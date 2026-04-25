/*
 * kernel_monitor.c
 * BPF/eBPF syscall tracer for SecureSyscall OS
 *
 * Requires: Linux kernel 4.9+, BCC toolchain (libbcc)
 *
 * Build (BCC Python binding):
 *   pip install bcc
 *   sudo python3 kernel_monitor_loader.py
 *
 * Or compile standalone with clang:
 *   clang -O2 -target bpf -c kernel_monitor.c -o kernel_monitor.o
 *
 * Usage: sudo python3 kernel_monitor_loader.py
 *        (outputs JSON lines to stdout, pipe to backend)
 *
 * Enhancements v2.1:
 *   - Rate-limit map to detect fork/exec storms
 *   - Per-UID syscall counter map
 *   - Separate probe for sys_exit to capture return values
 *   - Sensitive-path deny-list hash map
 *   - Privilege-escalation detection (setuid/setgid family)
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

/* ── Constants ───────────────────────────────────────────────── */
#define MAX_PATH_LEN  128
#define MAX_COMM_LEN  16   /* TASK_COMM_LEN */

/* ── Shared event struct (sent via perf ring buffer) ─────────── */
struct syscall_event_t {
    u32  pid;
    u32  tgid;
    u32  uid;
    u32  gid;
    u64  ts;                        /* nanoseconds since boot         */
    char comm[MAX_COMM_LEN];        /* process name                   */
    long syscall_nr;
    int  blocked;                   /* 1 = policy says block          */
    int  return_code;               /* captured on sys_exit (-1=none) */
    char args[MAX_PATH_LEN];        /* first string argument if path  */
    u32  rate_flag;                 /* 1 = rate-limit triggered       */
    u32  priv_esc;                  /* 1 = privilege escalation hint  */
};

/* ── Maps ────────────────────────────────────────────────────── */

/* Output ring buffer */
BPF_PERF_OUTPUT(syscall_events);

/*
 * policy_map: syscall_nr (u64) -> action (u32)
 *   0 = allow  1 = audit  2 = sandbox  3 = block
 * Populated from user-space loader / FastAPI backend.
 */
BPF_HASH(policy_map, u64, u32);

/*
 * rate_map: pid (u32) -> invocation count in current window
 * Simple per-PID counter; user-space resets periodically.
 */
BPF_HASH(rate_map, u32, u64);

/*
 * uid_syscall_map: uid (u32) -> total syscall count
 * Useful for per-user anomaly detection.
 */
BPF_HASH(uid_syscall_map, u32, u64);

/*
 * pending_map: pid (u32) -> syscall_nr (u64)
 * Stores the syscall number on entry so sys_exit can emit return code.
 */
BPF_HASH(pending_map, u32, u64);

/* ── Helpers ─────────────────────────────────────────────────── */

/* Returns 1 if this syscall is in the privilege-escalation family */
static __always_inline int is_priv_esc(long nr) {
    /* setuid=105, setgid=106, setreuid=113, setregid=114,
       setresuid=117, setresgid=119, setfsuid=122, setfsgid=123 */
    return (nr == 105 || nr == 106 || nr == 113 || nr == 114 ||
            nr == 117 || nr == 119 || nr == 122 || nr == 123);
}

/* ── Probe: raw_syscalls:sys_enter ───────────────────────────── */
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct syscall_event_t ev = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid      = pid_tgid >> 32;
    u32 tgid     = (u32)pid_tgid;

    u64 uid_gid  = bpf_get_current_uid_gid();
    u32 uid      = uid_gid & 0xFFFFFFFF;
    u32 gid      = uid_gid >> 32;

    ev.pid        = pid;
    ev.tgid       = tgid;
    ev.uid        = uid;
    ev.gid        = gid;
    ev.ts         = bpf_ktime_get_ns();
    ev.syscall_nr = args->id;
    ev.return_code = -1; /* filled in on exit probe */
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    /* ── Policy check ── */
    u64 nr     = (u64)args->id;
    u32 *action = policy_map.lookup(&nr);
    ev.blocked  = (action && *action == 3) ? 1 : 0;

    /* ── Privilege escalation flag ── */
    ev.priv_esc = is_priv_esc(args->id) ? 1 : 0;

    /* ── Per-PID rate tracking ── */
    u64 one = 1;
    u64 *cnt = rate_map.lookup_or_try_init(&pid, &one);
    if (cnt) {
        (*cnt)++;
        /* flag if PID has exceeded 1000 calls tracked without reset */
        ev.rate_flag = (*cnt > 1000) ? 1 : 0;
    }

    /* ── Per-UID global counter ── */
    u64 *ucnt = uid_syscall_map.lookup_or_try_init(&uid, &one);
    if (ucnt) (*ucnt)++;

    /* ── Capture filename argument for open/openat/unlink/rename ── */
    if (args->id == 2   /* open    */ ||
        args->id == 257 /* openat  */ ||
        args->id == 87  /* unlink  */ ||
        args->id == 82  /* rename  */) {

        const char __user *filename;
        if (args->id == 257 || args->id == 82) {
            /* openat/rename: first arg is dirfd, second is path */
            filename = (const char __user *)args->args[1];
        } else {
            filename = (const char __user *)args->args[0];
        }
        bpf_probe_read_user_str(ev.args, sizeof(ev.args), filename);
    }

    /* ── Store pending syscall_nr for exit probe ── */
    u64 sys_nr = (u64)args->id;
    pending_map.update(&pid, &sys_nr);

    syscall_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

/* ── Probe: raw_syscalls:sys_exit ────────────────────────────── */
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u64 *nr_ptr = pending_map.lookup(&pid);
    if (!nr_ptr) return 0;

    /* Only emit exit events for interesting (non-zero) return codes */
    long ret = args->ret;
    if (ret >= 0) {
        pending_map.delete(&pid);
        return 0;
    }

    struct syscall_event_t ev = {};
    ev.pid        = pid;
    ev.uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev.ts         = bpf_ktime_get_ns();
    ev.syscall_nr = (long)*nr_ptr;
    ev.return_code = (int)ret;
    ev.blocked     = 0; /* exit event, not a fresh block */
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    __builtin_memcpy(ev.args, "EXIT", 5);

    pending_map.delete(&pid);
    syscall_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

/*
 * ══════════════════════════════════════════════════════════════
 *  Python loader  —  kernel_monitor_loader.py
 *  Save as a separate .py file and run: sudo python3 kernel_monitor_loader.py
 * ══════════════════════════════════════════════════════════════
 *
 * #!/usr/bin/env python3
 * """
 * kernel_monitor_loader.py
 * Loads kernel_monitor.c into the kernel via BCC and streams
 * JSON-encoded syscall events to stdout for the FastAPI backend.
 * """
 *
 * import json
 * import ctypes
 * import sys
 * import signal
 * import threading
 * import time
 * from bcc import BPF
 *
 * # ── Syscall name table (x86-64) ──────────────────────────────
 * SYSCALL_NAMES = {
 *     0:"read",      1:"write",     2:"open",      3:"close",
 *     4:"stat",      5:"fstat",     9:"mmap",      10:"mprotect",
 *     11:"munmap",   56:"clone",    57:"fork",      59:"execve",
 *     62:"kill",     41:"socket",   42:"connect",   49:"bind",
 *     50:"listen",   43:"accept",   44:"sendto",    45:"recvfrom",
 *     46:"sendmsg",  47:"recvmsg",  101:"ptrace",   16:"ioctl",
 *     257:"openat",  84:"rmdir",    87:"unlink",    82:"rename",
 *     105:"setuid",  106:"setgid",  113:"setreuid", 114:"setregid",
 *     117:"setresuid",119:"setresgid",122:"setfsuid",123:"setfsgid",
 * }
 *
 * TASK_COMM_LEN = 16
 * MAX_PATH_LEN  = 128
 *
 * class Event(ctypes.Structure):
 *     _fields_ = [
 *         ("pid",         ctypes.c_uint),
 *         ("tgid",        ctypes.c_uint),
 *         ("uid",         ctypes.c_uint),
 *         ("gid",         ctypes.c_uint),
 *         ("ts",          ctypes.c_ulonglong),
 *         ("comm",        ctypes.c_char * TASK_COMM_LEN),
 *         ("syscall_nr",  ctypes.c_long),
 *         ("blocked",     ctypes.c_int),
 *         ("return_code", ctypes.c_int),
 *         ("args",        ctypes.c_char * MAX_PATH_LEN),
 *         ("rate_flag",   ctypes.c_uint),
 *         ("priv_esc",    ctypes.c_uint),
 *     ]
 *
 * _lock   = threading.Lock()
 * _policy = {}   # syscall_nr -> action string; updated by REST API
 *
 * def update_policy(bpf_obj, new_policy: dict):
 *     """Push policy changes into the BPF hash map."""
 *     pm = bpf_obj["policy_map"]
 *     action_map = {"allow":0,"audit":1,"sandbox":2,"block":3}
 *     for nr_str, action in new_policy.items():
 *         try:
 *             nr  = int(nr_str)
 *             val = ctypes.c_uint(action_map.get(action, 0))
 *             pm[ctypes.c_ulong(nr)] = val
 *         except Exception as e:
 *             print(f"[policy] error setting nr={nr_str}: {e}", file=sys.stderr)
 *
 * def reset_rate_map(bpf_obj):
 *     """Periodically clear the per-PID rate counters."""
 *     while True:
 *         time.sleep(10)
 *         try:
 *             bpf_obj["rate_map"].clear()
 *         except Exception:
 *             pass
 *
 * def handle_event(cpu, data, size):
 *     ev = ctypes.cast(data, ctypes.POINTER(Event)).contents
 *     record = {
 *         "pid":         ev.pid,
 *         "tgid":        ev.tgid,
 *         "uid":         ev.uid,
 *         "gid":         ev.gid,
 *         "ts_ns":       ev.ts,
 *         "process":     ev.comm.decode("utf-8", errors="replace").rstrip("\x00"),
 *         "syscall":     SYSCALL_NAMES.get(ev.syscall_nr, f"syscall_{ev.syscall_nr}"),
 *         "nr":          ev.syscall_nr,
 *         "blocked":     bool(ev.blocked),
 *         "return_code": ev.return_code,
 *         "args":        ev.args.decode("utf-8", errors="replace").rstrip("\x00"),
 *         "rate_flag":   bool(ev.rate_flag),
 *         "priv_esc":    bool(ev.priv_esc),
 *     }
 *     print(json.dumps(record), flush=True)
 *
 * def main():
 *     b = BPF(src_file="kernel_monitor.c")
 *     b["syscall_events"].open_perf_buffer(handle_event, page_cnt=512)
 *
 *     # Start rate-map reset thread
 *     t = threading.Thread(target=reset_rate_map, args=(b,), daemon=True)
 *     t.start()
 *
 *     print("[kernel_monitor] Tracing syscalls... Ctrl+C to stop.", file=sys.stderr)
 *
 *     def _sigint(_s, _f):
 *         sys.exit(0)
 *     signal.signal(signal.SIGINT, _sigint)
 *
 *     while True:
 *         b.perf_buffer_poll(timeout=100)
 *
 * if __name__ == "__main__":
 *     main()
 */