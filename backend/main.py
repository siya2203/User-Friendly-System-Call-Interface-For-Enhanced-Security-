import asyncio
import hashlib
import json
import random
import shlex
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"

app = FastAPI(
    title="SecureSyscall OS API",
    description="User-friendly system call monitoring and security policy enforcement",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

syscall_log = deque(maxlen=600)
audit_trail = deque(maxlen=250)
blocked_count = 0
threat_score = 34
security_level = "enforcing"
started_at = time.time()


class PolicyUpdate(BaseModel):
    enabled: bool


class SyscallMode(BaseModel):
    status: str = Field(pattern="^(allowed|audited|sandboxed|blocked)$")


class SecurityLevelUpdate(BaseModel):
    level: str = Field(pattern="^(permissive|enforcing|strict)$")


class SandboxCommand(BaseModel):
    command: str = Field(min_length=1, max_length=160)
    profile: str = "minimal"
    timeout: int = Field(default=5, ge=1, le=120)


class ConnectionManager:
    def __init__(self):
        self.active_connections = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, payload: dict):
        disconnected = []
        for websocket in self.active_connections:
            try:
                await websocket.send_json(payload)
            except Exception:
                disconnected.append(websocket)
        for websocket in disconnected:
            self.disconnect(websocket)


manager = ConnectionManager()

SYSCALL_DEFINITIONS = [
    {"num": 0, "name": "read", "cat": "file", "status": "allowed"},
    {"num": 1, "name": "write", "cat": "file", "status": "allowed"},
    {"num": 2, "name": "open", "cat": "file", "status": "audited"},
    {"num": 3, "name": "close", "cat": "file", "status": "allowed"},
    {"num": 4, "name": "stat", "cat": "file", "status": "allowed"},
    {"num": 5, "name": "fstat", "cat": "file", "status": "allowed"},
    {"num": 8, "name": "lseek", "cat": "file", "status": "allowed"},
    {"num": 9, "name": "mmap", "cat": "mem", "status": "sandboxed"},
    {"num": 10, "name": "mprotect", "cat": "mem", "status": "blocked"},
    {"num": 11, "name": "munmap", "cat": "mem", "status": "allowed"},
    {"num": 12, "name": "brk", "cat": "mem", "status": "allowed"},
    {"num": 17, "name": "pread64", "cat": "file", "status": "allowed"},
    {"num": 39, "name": "getpid", "cat": "proc", "status": "allowed"},
    {"num": 41, "name": "socket", "cat": "net", "status": "audited"},
    {"num": 42, "name": "connect", "cat": "net", "status": "audited"},
    {"num": 44, "name": "sendto", "cat": "net", "status": "audited"},
    {"num": 45, "name": "recvfrom", "cat": "net", "status": "audited"},
    {"num": 56, "name": "clone", "cat": "proc", "status": "sandboxed"},
    {"num": 57, "name": "fork", "cat": "proc", "status": "sandboxed"},
    {"num": 59, "name": "execve", "cat": "proc", "status": "sandboxed"},
    {"num": 62, "name": "kill", "cat": "proc", "status": "audited"},
    {"num": 101, "name": "ptrace", "cat": "proc", "status": "blocked"},
    {"num": 105, "name": "setuid", "cat": "proc", "status": "audited"},
    {"num": 165, "name": "mount", "cat": "file", "status": "blocked"},
    {"num": 186, "name": "gettid", "cat": "proc", "status": "allowed"},
    {"num": 217, "name": "getdents", "cat": "file", "status": "allowed"},
    {"num": 257, "name": "openat", "cat": "file", "status": "audited"},
]

POLICIES_STATE = [
    {"name": "Deny ptrace from unprivileged processes", "desc": "Prevents process injection", "level": "CRITICAL", "on": True},
    {"name": "Block writable executable memory", "desc": "Stops W+X page mappings", "level": "CRITICAL", "on": True},
    {"name": "Restrict sensitive file reads", "desc": "Protects passwd and shadow paths", "level": "HIGH", "on": True},
    {"name": "Audit network socket activity", "desc": "Records outbound network attempts", "level": "MEDIUM", "on": True},
    {"name": "Sandbox risky process execution", "desc": "Runs execve activity in a jail", "level": "HIGH", "on": True},
    {"name": "Gate filesystem mounts", "desc": "Requires privileged mount capability", "level": "HIGH", "on": True},
    {"name": "Rate limit fork storms", "desc": "Detects fork bomb patterns", "level": "MEDIUM", "on": True},
    {"name": "Deny raw socket creation", "desc": "Blocks packet crafting", "level": "MEDIUM", "on": False},
    {"name": "Audit privilege changes", "desc": "Tracks setuid and setgid calls", "level": "MEDIUM", "on": True},
    {"name": "Block process memory writes", "desc": "Protects direct memory interfaces", "level": "HIGH", "on": True},
]

PROCESSES = [
    {"name": "nginx", "pid": 892},
    {"name": "sshd", "pid": 1882},
    {"name": "python3", "pid": 3302},
    {"name": "systemd", "pid": 1},
    {"name": "unknown", "pid": 4421},
    {"name": "gcc", "pid": 2110},
    {"name": "curl", "pid": 1102},
    {"name": "bash", "pid": 445},
]

ARGUMENTS = {
    "read": "fd={fd}, buf=0x{addr:x}, count={cnt}",
    "write": "fd={fd}, buf=0x{addr:x}, count={cnt}",
    "open": "/etc/passwd, O_RDONLY",
    "openat": "AT_FDCWD, /etc/shadow, O_RDONLY",
    "close": "fd={fd}",
    "stat": "/var/log/syslog",
    "fstat": "fd={fd}",
    "lseek": "fd={fd}, offset=0, SEEK_SET",
    "mmap": "addr=NULL, len={length}, PROT_READ|PROT_WRITE",
    "mprotect": "addr=0x{addr:x}, len=4096, PROT_EXEC|PROT_WRITE",
    "munmap": "addr=0x{addr:x}, len=4096",
    "brk": "addr=0x{addr:x}",
    "pread64": "fd={fd}, buf=0x{addr:x}, count={cnt}, offset=0",
    "getpid": "",
    "socket": "AF_INET, SOCK_STREAM, 0",
    "connect": "sockfd={fd}, addr=192.168.{a}.{b}:{port}",
    "sendto": "sockfd={fd}, buf=0x{addr:x}, len={cnt}",
    "recvfrom": "sockfd={fd}, buf=0x{addr:x}, len={cnt}",
    "clone": "flags=CLONE_VM|CLONE_FS",
    "fork": "",
    "execve": "/bin/sh, [\"/bin/sh\", \"-c\", \"...\"]",
    "kill": "pid={pid}, sig=SIGTERM",
    "ptrace": "PTRACE_ATTACH, target={pid}, addr=0x0",
    "setuid": "uid={pid}",
    "mount": "/dev/sdb1, /mnt/data, ext4",
    "gettid": "",
    "getdents": "fd={fd}, dirp=0x{addr:x}, count={cnt}",
}


def policy_for(name: str) -> str:
    mapping = {
        "ptrace": "P-01 ptrace deny",
        "mprotect": "P-02 memory execute deny",
        "open": "P-03 sensitive file gate",
        "openat": "P-03 sensitive file gate",
        "mount": "P-06 mount gate",
        "execve": "P-05 sandbox exec",
        "fork": "P-07 fork rate limit",
        "clone": "P-07 clone rate limit",
        "mmap": "P-05 memory sandbox",
        "socket": "P-09 network audit",
        "setuid": "P-10 privilege audit",
    }
    return mapping.get(name, "P-00 default policy")


def adjusted_status(status: str) -> str:
    if security_level == "permissive" and status in {"audited", "sandboxed"}:
        return "allowed"
    if security_level == "strict" and status == "audited":
        return "sandboxed"
    return status


def make_hash(entry: dict) -> str:
    raw = json.dumps(entry, sort_keys=True) + str(time.time_ns())
    return hashlib.sha256(raw.encode()).hexdigest()[:10]


def generate_syscall_event() -> dict:
    global blocked_count, threat_score
    definition = random.choice(SYSCALL_DEFINITIONS)
    process = random.choice(PROCESSES)
    name = definition["name"]
    action = adjusted_status(definition["status"])
    args = ARGUMENTS.get(name, "").format(
        fd=random.randint(3, 25),
        addr=random.randint(0x7F000000, 0x7FFFFFFF),
        cnt=random.choice([64, 128, 256, 512, 1024, 4096]),
        length=random.choice([4096, 8192, 65536]),
        pid=random.randint(100, 5000),
        a=random.randint(0, 255),
        b=random.randint(0, 255),
        port=random.choice([22, 80, 443, 3306, 8080]),
    )
    event = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "pid": str(process["pid"]),
        "process": process["name"],
        "call": f"{name}()",
        "args": args,
        "action": action,
        "cat": definition["cat"],
        "nr": definition["num"],
    }
    syscall_log.appendleft(event)
    if action == "blocked":
        blocked_count += 1
        threat_score = min(100, threat_score + random.randint(2, 5))
    elif action == "sandboxed":
        threat_score = min(100, threat_score + random.randint(0, 2))
    else:
        threat_score = max(0, threat_score - random.randint(0, 1))
    if action in {"blocked", "sandboxed", "audited"}:
        audit_trail.appendleft({
            "ts": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "pid": str(process["pid"]),
            "call": f"{name}()",
            "policy": policy_for(name),
            "decision": action.upper(),
            "hash": make_hash(event),
        })
    return event


def snapshot_categories() -> dict:
    counts = {"file": 0, "net": 0, "proc": 0, "mem": 0, "ipc": 0}
    for event in list(syscall_log)[:120]:
        counts[event["cat"]] = counts.get(event["cat"], 0) + 1
    total = sum(counts.values()) or 1
    return {key: round(value * 100 / total) for key, value in counts.items()}


def risk_for_process(pid: int) -> str:
    recent = [event for event in syscall_log if event["pid"] == str(pid)]
    blocked = sum(1 for event in recent if event["action"] == "blocked")
    sandboxed = sum(1 for event in recent if event["action"] == "sandboxed")
    if blocked >= 2 or sandboxed >= 4:
        return "high"
    if blocked == 1 or sandboxed >= 2:
        return "medium"
    return "low"


@app.get("/")
async def serve_frontend():
    return FileResponse(str(FRONTEND_DIR / "index.html"))


@app.get("/api/status")
async def get_status():
    return {
        "syscall_rate": random.randint(900, 1500),
        "blocked_total": blocked_count,
        "active_policies": sum(1 for policy in POLICIES_STATE if policy["on"]),
        "threat_score": threat_score,
        "security_level": security_level,
        "uptime_seconds": int(time.time() - started_at),
        "categories": snapshot_categories(),
    }


@app.get("/api/log")
async def get_log(action: Optional[str] = None, cat: Optional[str] = None, limit: int = 100):
    entries = list(syscall_log)
    if action and action != "all":
        entries = [entry for entry in entries if entry["action"] == action]
    if cat and cat != "all":
        entries = [entry for entry in entries if entry["cat"] == cat]
    return entries[: max(1, min(limit, 300))]


@app.get("/api/processes")
async def get_processes():
    result = []
    for process in PROCESSES:
        recent = [event for event in syscall_log if event["pid"] == str(process["pid"])]
        result.append({
            **process,
            "rate": min(100, 10 + len(recent) * 8 + random.randint(0, 20)),
            "count": 1000 + len(recent) * random.randint(40, 120),
            "risk": risk_for_process(process["pid"]),
        })
    return result


@app.get("/api/policies")
async def get_policies():
    return POLICIES_STATE


@app.put("/api/policies/{index}")
async def update_policy(index: int, update: PolicyUpdate):
    if index < 0 or index >= len(POLICIES_STATE):
        raise HTTPException(status_code=404, detail="Policy not found")
    POLICIES_STATE[index]["on"] = update.enabled
    return {"ok": True, "policy": POLICIES_STATE[index]}


@app.get("/api/syscalls")
async def get_syscall_definitions():
    return SYSCALL_DEFINITIONS


@app.put("/api/syscalls/{name}")
async def update_syscall_mode(name: str, update: SyscallMode):
    for syscall in SYSCALL_DEFINITIONS:
        if syscall["name"] == name:
            syscall["status"] = update.status
            return {"ok": True, "syscall": syscall}
    raise HTTPException(status_code=404, detail="Syscall not found")


@app.get("/api/audit")
async def get_audit(limit: int = 80):
    return list(audit_trail)[: max(1, min(limit, 200))]


@app.get("/api/threats")
async def get_threats():
    recent = list(audit_trail)[:80]
    return {
        "critical": sum(1 for entry in recent if entry["decision"] == "BLOCKED" and "ptrace" in entry["call"]),
        "high": sum(1 for entry in recent if entry["decision"] == "BLOCKED"),
        "medium": sum(1 for entry in recent if entry["decision"] == "SANDBOXED"),
        "resolved": max(4, len(recent) // 5),
        "score": threat_score,
        "items": recent[:6],
    }


@app.put("/api/security-level")
async def set_security_level(update: SecurityLevelUpdate):
    global security_level
    security_level = update.level
    return {"ok": True, "level": security_level}


@app.post("/api/sandbox/run")
async def run_sandbox(command: SandboxCommand):
    global blocked_count, threat_score
    text = command.command.strip()
    tokens = shlex.split(text, posix=False)
    root = tokens[0].lower() if tokens else ""
    denied = any(marker in text.lower() for marker in ["/etc/shadow", "sudo", "rm -rf", "format", "reg delete"])
    raw_network = root in {"ping", "tracert", "nmap"}
    action = "BLOCKED" if denied or raw_network else "SANDBOXED"
    if action == "BLOCKED":
        blocked_count += 1
        threat_score = min(100, threat_score + 4)
    lines = [{"cls": "t-prompt", "text": "secure$ "}, {"cls": "t-cmd", "text": text}]
    if denied:
        lines.extend([
            {"cls": "t-err", "text": "[SECCOMP] open or write syscall denied"},
            {"cls": "t-err", "text": "[POLICY P-03] Sensitive operation blocked"},
            {"cls": "t-warn", "text": "[AUDIT] Event logged and process terminated"},
            {"cls": "t-output", "text": "Process exit code: SIGKILL"},
        ])
    elif raw_network:
        lines.extend([
            {"cls": "t-warn", "text": "[SECCOMP] socket syscall inspected"},
            {"cls": "t-err", "text": "[POLICY P-08] Raw socket blocked"},
            {"cls": "t-output", "text": "Operation not permitted inside minimal profile"},
        ])
    elif root in {"ls", "dir"}:
        lines.extend([
            {"cls": "t-ok", "text": "[SECCOMP] execve allowed inside sandbox"},
            {"cls": "t-output", "text": "backend  frontend  requirements.txt"},
            {"cls": "t-ok", "text": "[SANDBOX] Completed with read-only filesystem access"},
        ])
    else:
        lines.extend([
            {"cls": "t-ok", "text": "[SECCOMP] Syscall profile accepted"},
            {"cls": "t-warn", "text": "[SANDBOX] Minimal jail active"},
            {"cls": "t-output", "text": "Command simulated successfully"},
            {"cls": "t-ok", "text": "[AUDIT] Completed with exit code 0"},
        ])
    audit_trail.appendleft({
        "ts": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "pid": str(random.randint(2000, 9000)),
        "call": "execve()",
        "policy": "P-05 sandbox exec",
        "decision": action,
        "hash": hashlib.sha256(text.encode()).hexdigest()[:10],
    })
    return {"action": action, "lines": lines}


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            events = [generate_syscall_event() for _ in range(random.randint(1, 3))]
            await websocket.send_json({
                "type": "syscall_events",
                "events": events,
                "stats": {
                    "rate": random.randint(900, 1500),
                    "blocked": blocked_count,
                    "threat_score": threat_score,
                    "categories": snapshot_categories(),
                },
            })
            await asyncio.sleep(0.8)
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.on_event("startup")
async def startup_event():
    for _ in range(45):
        generate_syscall_event()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
