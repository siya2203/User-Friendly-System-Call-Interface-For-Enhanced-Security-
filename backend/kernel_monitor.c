#include <linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 syscall_id;
    char comm[TASK_COMM_LEN];
    char arg[160];
};

BPF_PERF_OUTPUT(syscall_events);

static int submit_event(struct pt_regs *ctx, u32 syscall_id, const char __user *arg) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.syscall_id = syscall_id;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    if (arg != 0) {
        bpf_probe_read_user_str(&data.arg, sizeof(data.arg), arg);
    }
    syscall_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__sys_open(struct pt_regs *ctx, const char __user *filename) {
    return submit_event(ctx, 2, filename);
}

int kprobe__sys_openat(struct pt_regs *ctx, int dfd, const char __user *filename) {
    return submit_event(ctx, 257, filename);
}

int kprobe__sys_execve(struct pt_regs *ctx, const char __user *filename) {
    return submit_event(ctx, 59, filename);
}

int kprobe__sys_ptrace(struct pt_regs *ctx) {
    return submit_event(ctx, 101, 0);
}

int kprobe__sys_mount(struct pt_regs *ctx, const char __user *dev_name) {
    return submit_event(ctx, 165, dev_name);
}
