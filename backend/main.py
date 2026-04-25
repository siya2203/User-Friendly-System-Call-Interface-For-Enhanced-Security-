"""
SecureSyscall OS — FastAPI Backend (main.py)  v2.1
====================================================
Serves the frontend and exposes all REST + WebSocket endpoints.

New in v2.1
-----------
* /api/analytics  — rolling 60-second rate window + blocked rate
* /api/alerts     — severity-filtered alert stream
* /api/processes/{pid}/kill  — sandbox-kill a simulated process
* /api/syscalls/{name}/reset — reset counters for a single syscall
* /ws/live now broadcasts enriched events (rate_flag, priv_esc)
* In-memory circular buffers capped with collections.deque
* Proper CORS, startup/shutdown lifecycle hooks
* Basic HTTP Bearer token auth stub (token = "demo")
"""

import asyncio
import random
import time
import json
import uuid
from collections import deque
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SecureSyscall OS",
    version="2.1.0",
    description="User-friendly syscall monitoring & policy enforcement dashboard",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth stub ──────────────────────────────────────────────────────────────────
security = HTTPBearer(auto_error=False)
DEMO_TOKEN = "demo"

def verify_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Optional bearer-token check. Returns True if auth disabled or token valid."""
    if credentials is None:
        return True   # auth not supplied → allow (demo mode)
    if credentials.credentials != DEMO_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    return True

# ── In-memory state ────────────────────────────────────────────────────────────
SYSCALLS = [
    {"name": "read",      "category": "io",      "mode": "allowed",   "count": 0, "blocked": 0},
    {"name": "write",     "category": "io",      "mode": "allowed",   "count": 0, "blocked": 0},
    {"name": "open",      "category": "io",      "mode": "audited",   "count": 0, "blocked": 0},
    {"name": "close",     "category": "io",      "mode": "allowed",   "count": 0, "blocked": 0},
    {"name": "stat",      "category": "fs",      "mode": "allowed",   "count": 0, "blocked": 0},
    {"name": "fstat",     "category": "fs",      "mode": "allowed",   "count": 0, "blocked": 0},
    {"name": "chmod",     "category": "fs",      "mode": "audited",   "count": 0, "blocked": 0},
    {"name": "chown",     "category": "fs",      "mode": "audited",   "count": 0, "blocked": 0},
    {"name": "unlink",    "category": "fs",      "mode": "audited",   "count": 0, "blocked": 0},
    {"name": "rename",    "category": "fs",      "mode": "audited",   "count": 0, "blocked": 0},
    {"name": "mkdir",     "category": "fs",      "mode": "audited",   "count": 0, "blocked": 0},
    {"name": "mmap",      "category": "memory",  "mode": "sandboxed", "count": 0, "blocked": 0},
    {"name": "mprotect",  "category": "memory",  "mode": "sandboxed", "count": 0, "blocked": 0},
    {"name": "munmap",    "category": "memory",  "mode": "allowed",   "count": 0, "blocked": 0},
    {"name": "fork",      "category": "process", "mode": "sandboxed", "count": 0, "blocked": 0},
    {"name": "execve",    "category": "process", "mode": "blocked",   "count": 0, "blocked": 0},
    {"name": "getpid",    "category": "process", "mode": "allowed",   "count": 0, "blocked": 0},
    {"name": "getuid",    "category": "process", "mode": "allowed",   "count": 0, "blocked": 0},
    {"name": "kill",      "category": "signal",  "mode": "audited",   "count": 0, "blocked": 0},
    {"name": "socket",    "category": "network", "mode": "sandboxed", "count": 0, "blocked": 0},
    {"name": "connect",   "category": "network", "mode": "audited",   "count": 0, "blocked": 0},
    {"name": "bind",      "category": "network", "mode": "audited",   "count": 0, "blocked": 0},
    {"name": "listen",    "category": "network", "mode": "blocked",   "count": 0, "blocked": 0},
    {"name": "accept",    "category": "network", "mode": "blocked",   "count": 0, "blocked": 0},
    {"name": "sendmsg",   "category": "network", "mode": "sandboxed", "count": 0, "blocked": 0},
    {"name": "recvmsg",   "category": "network", "mode": "sandboxed", "count": 0, "blocked": 0},
    {"name": "ptrace",    "category": "debug",   "mode": "blocked",   "count": 0, "blocked": 0},
    {"name": "ioctl",     "category": "device",  "mode": "audited",   "count": 0, "blocked": 0},
    {"name": "syslog",    "category": "system",  "mode": "blocked",   "count": 0, "blocked": 0},
    {"name": "setuid",    "category": "system",  "mode": "audited",   "count": 0, "blocked": 0},
    {"name": "setgid",    "category": "system",  "mode": "audited",   "count": 0, "blocked": 0},
    {"name": "mount",     "category": "system",  "mode": "blocked",   "count": 0, "blocked": 0},
    {"name": "umount2",   "category": "system",  "mode": "blocked",   "count": 0, "blocked": 0},
    {"name": "clone",     "category": "process", "mode": "sandboxed", "count": 0, "blocked": 0},
]

POLICIES = [
    {"id": "p01", "name": "Block Raw Sockets",          "category": "network", "enabled": True,  "description": "Prevent creation of raw sockets"},
    {"id": "p02", "name": "Audit File Opens",           "category": "fs",      "enabled": True,  "description": "Log every file open syscall"},
    {"id": "p03", "name": "Restrict Process Spawn",     "category": "process", "enabled": True,  "description": "Sandbox fork and execve"},
    {"id": "p04", "name": "Memory W^X Guard",           "category": "memory",  "enabled": False, "description": "Enforce write-xor-execute on mmap"},
    {"id": "p05", "name": "Network Egress Filter",      "category": "network", "enabled": True,  "description": "Block outbound raw connections"},
    {"id": "p06", "name": "Debug Lockdown",             "category": "debug",   "enabled": True,  "description": "Block ptrace and related calls"},
    {"id": "p07", "name": "Privilege Escalation Guard", "category": "system",  "enabled": True,  "description": "Block setuid/setgid abuse"},
    {"id": "p08", "name": "FS Integrity Check",         "category": "fs",      "enabled": False, "description": "Hash-verify sensitive paths on access"},
    {"id": "p09", "name": "Fork Storm Detection",       "category": "process", "enabled": True,  "description": "Rate-limit excessive fork() calls"},
    {"id": "p10", "name": "Mount Lockdown",             "category": "system",  "enabled": True,  "description": "Block mount/umount syscalls"},
]

# Use deques for O(1) append/pop
AUDIT_LOG:    deque = deque(maxlen=800)
THREAT_ALERTS: deque = deque(maxlen=200)

# Rolling per-second rate window (last 60 samples)
RATE_WINDOW:  deque = deque(maxlen=60)
_rate_count = 0
_rate_ts    = time.monotonic()

SECURITY_LEVEL = {"level": "medium"}
START_TIME     = time.monotonic()

# Simulated process table
PROC_NAMES = [
    "nginx", "sshd", "python3", "node", "postgres",
    "redis-server", "systemd", "dockerd", "curl", "bash",
]
PROC_TABLE: dict = {}   # pid -> process dict

# ── WebSocket Manager ──────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        msg  = json.dumps(data)
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)

manager = ConnectionManager()

# ── Simulation ─────────────────────────────────────────────────────────────────
def _ensure_processes():
    """Keep the simulated process table populated."""
    if len(PROC_TABLE) < 6:
        for name in random.sample(PROC_NAMES, k=random.randint(5, 8)):
            pid = random.randint(100, 9999)
            if pid not in PROC_TABLE:
                PROC_TABLE[pid] = {
                    "pid": pid, "name": name,
                    "user": random.choice(["root", "www-data", "ubuntu", "postgres"]),
                    "risk": random.randint(0, 100),
                    "syscalls_per_sec": round(random.uniform(0.2, 90), 1),
                    "status": random.choice(["running", "sleeping", "running"]),
                }

def _simulate_event():
    global _rate_count, _rate_ts

    sc      = random.choice(SYSCALLS)
    sc["count"] += 1

    blocked = sc["mode"] == "blocked" or (
        sc["mode"] == "sandboxed" and random.random() < 0.12
    )
    if blocked:
        sc["blocked"] += 1

    _rate_count += 1
    now = time.monotonic()
    if now - _rate_ts >= 1.0:
        RATE_WINDOW.append(_rate_count)
        _rate_count = 0
        _rate_ts    = now

    ts    = datetime.now(timezone.utc).isoformat()
    pid   = random.choice(list(PROC_TABLE.keys())) if PROC_TABLE else random.randint(100, 9999)
    proc  = PROC_TABLE.get(pid, {}).get("name", random.choice(PROC_NAMES))

    # Occasionally simulate rate_flag / priv_esc
    rate_flag = random.random() < 0.03
    priv_esc  = sc["category"] == "system" and random.random() < 0.08

    entry = {
        "id":         str(uuid.uuid4()),
        "time":       ts,
        "syscall":    sc["name"],
        "category":   sc["category"],
        "mode":       sc["mode"],
        "pid":        pid,
        "process":    proc,
        "blocked":    blocked,
        "args":       f"fd={random.randint(0, 127)}" if sc["category"] in ("io", "fs") else "",
        "rate_flag":  rate_flag,
        "priv_esc":   priv_esc,
    }
    AUDIT_LOG.append(entry)

    sev_needed = blocked or rate_flag or priv_esc
    if sev_needed and random.random() < 0.55:
        if priv_esc:
            sev = "critical"
        elif rate_flag:
            sev = "high"
        else:
            sev = random.choice(["low", "medium", "high", "critical"])

        detail = ""
        if priv_esc:
            detail = f" [PRIV-ESC]"
        elif rate_flag:
            detail = f" [RATE-LIMIT]"

        THREAT_ALERTS.append({
            "id":       len(THREAT_ALERTS) + 1,
            "time":     ts,
            "severity": sev,
            "message":  f"Blocked {sc['name']} from {proc} (PID {pid}){detail}",
            "syscall":  sc["name"],
            "category": sc["category"],
            "priv_esc": priv_esc,
            "rate_flag": rate_flag,
        })
    return entry

async def simulation_loop():
    _ensure_processes()
    while True:
        _ensure_processes()
        event = _simulate_event()
        await manager.broadcast({"type": "syscall_event", "data": event})
        await asyncio.sleep(random.uniform(0.15, 0.8))

@app.on_event("startup")
async def startup():
    _ensure_processes()
    asyncio.create_task(simulation_loop())

@app.on_event("shutdown")
async def shutdown():
    for ws in list(manager.active):
        await ws.close()

# ── REST API ───────────────────────────────────────────────────────────────────
@app.get("/api/status")
def get_status(_: bool = Depends(verify_token)):
    total   = sum(s["count"]   for s in SYSCALLS)
    blocked = sum(s["blocked"] for s in SYSCALLS)
    active  = sum(1 for p in POLICIES if p["enabled"])
    threat  = min(100, int(blocked / max(total, 1) * 220))
    avg_rate = round(sum(RATE_WINDOW) / max(len(RATE_WINDOW), 1), 1)
    return {
        "total_syscalls":    total,
        "blocked_calls":     blocked,
        "active_policies":   active,
        "threat_score":      threat,
        "security_level":    SECURITY_LEVEL["level"],
        "uptime_seconds":    int(time.monotonic() - START_TIME),
        "ws_connections":    len(manager.active),
        "avg_rate_per_sec":  avg_rate,
        "rate_window_size":  len(RATE_WINDOW),
    }

@app.get("/api/analytics")
def get_analytics(_: bool = Depends(verify_token)):
    """Rolling 60-second rate data + per-category totals."""
    cats: dict = {}
    for sc in SYSCALLS:
        c = sc["category"]
        if c not in cats:
            cats[c] = {"total": 0, "blocked": 0}
        cats[c]["total"]   += sc["count"]
        cats[c]["blocked"] += sc["blocked"]

    total   = sum(s["count"]   for s in SYSCALLS)
    blocked = sum(s["blocked"] for s in SYSCALLS)
    block_rate = round(blocked / max(total, 1) * 100, 2)

    return {
        "rate_window":  list(RATE_WINDOW),
        "categories":   cats,
        "block_rate_pct": block_rate,
        "total":        total,
        "blocked":      blocked,
    }

@app.get("/api/log")
def get_log(limit: int = 50, _: bool = Depends(verify_token)):
    entries = list(AUDIT_LOG)
    return list(reversed(entries[-limit:]))

@app.get("/api/processes")
def get_processes(_: bool = Depends(verify_token)):
    return list(PROC_TABLE.values())

@app.delete("/api/processes/{pid}")
def kill_process(pid: int, _: bool = Depends(verify_token)):
    if pid not in PROC_TABLE:
        raise HTTPException(404, "Process not found")
    proc = PROC_TABLE.pop(pid)
    THREAT_ALERTS.append({
        "id":       len(THREAT_ALERTS) + 1,
        "time":     datetime.now(timezone.utc).isoformat(),
        "severity": "medium",
        "message":  f"Process {proc['name']} (PID {pid}) sandboxed and killed by policy engine",
        "syscall":  "kill",
        "category": "signal",
        "priv_esc": False,
        "rate_flag": False,
    })
    return {"killed": pid, "name": proc["name"]}

@app.get("/api/policies")
def get_policies(_: bool = Depends(verify_token)):
    return POLICIES

@app.put("/api/policies/{index}")
def update_policy(index: int, body: dict, _: bool = Depends(verify_token)):
    if index < 0 or index >= len(POLICIES):
        raise HTTPException(404, "Policy not found")
    if "enabled" in body:
        POLICIES[index]["enabled"] = bool(body["enabled"])
    return POLICIES[index]

@app.get("/api/syscalls")
def get_syscalls(_: bool = Depends(verify_token)):
    return SYSCALLS

@app.put("/api/syscalls/{name}")
def update_syscall(name: str, body: dict, _: bool = Depends(verify_token)):
    for sc in SYSCALLS:
        if sc["name"] == name:
            if "mode" in body and body["mode"] in {"allowed", "audited", "sandboxed", "blocked"}:
                sc["mode"] = body["mode"]
            return sc
    raise HTTPException(404, "Syscall not found")

@app.post("/api/syscalls/{name}/reset")
def reset_syscall_counters(name: str, _: bool = Depends(verify_token)):
    for sc in SYSCALLS:
        if sc["name"] == name:
            sc["count"]   = 0
            sc["blocked"] = 0
            return {"reset": name}
    raise HTTPException(404, "Syscall not found")

@app.get("/api/audit")
def get_audit(limit: int = 100, category: Optional[str] = None,
              blocked_only: bool = False, _: bool = Depends(verify_token)):
    entries = list(AUDIT_LOG)
    if category:
        entries = [e for e in entries if e.get("category") == category]
    if blocked_only:
        entries = [e for e in entries if e.get("blocked")]
    return list(reversed(entries[-limit:]))

@app.get("/api/threats")
def get_threats(limit: int = 50, severity: Optional[str] = None,
                _: bool = Depends(verify_token)):
    alerts = list(THREAT_ALERTS)
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    return list(reversed(alerts[-limit:]))

@app.delete("/api/threats")
def clear_threats(_: bool = Depends(verify_token)):
    THREAT_ALERTS.clear()
    return {"cleared": True}

class SecurityLevelBody(BaseModel):
    level: str

@app.put("/api/security-level")
def set_security_level(body: SecurityLevelBody, _: bool = Depends(verify_token)):
    if body.level not in {"low", "medium", "high", "critical"}:
        raise HTTPException(400, "Invalid level. Must be: low | medium | high | critical")
    SECURITY_LEVEL["level"] = body.level
    if body.level == "critical":
        for sc in SYSCALLS:
            if sc["category"] in ("network", "debug", "system"):
                sc["mode"] = "blocked"
    elif body.level == "high":
        for sc in SYSCALLS:
            if sc["category"] in ("debug",):
                sc["mode"] = "blocked"
            if sc["category"] == "network" and sc["mode"] == "allowed":
                sc["mode"] = "audited"
    elif body.level == "low":
        # Relax network to audited if currently blocked (only non-critical ones)
        for sc in SYSCALLS:
            if sc["category"] == "network" and sc["name"] not in ("listen", "accept"):
                if sc["mode"] == "blocked":
                    sc["mode"] = "audited"
    return SECURITY_LEVEL

class SandboxBody(BaseModel):
    command: str

DANGER = {
    "rm", "dd", "mkfs", "fdisk", "shred", "wget", "curl", "nc",
    "netcat", "bash", "sh", "python", "perl", "ruby", "nmap",
    "tcpdump", "masscan", "ptrace", "strace", "ltrace", "mount",
    "umount", "chroot", "insmod", "rmmod",
}

SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/root", "/boot", "/proc/kcore", "/dev/mem",
    "/etc/ssh/", "/sys/kernel/",
]

@app.post("/api/sandbox/run")
def sandbox_run(body: SandboxBody, _: bool = Depends(verify_token)):
    if not body.command.strip():
        raise HTTPException(400, "Empty command")

    parts = body.command.strip().split()
    cmd   = parts[0].lower().lstrip("./")
    args  = parts[1:] if len(parts) > 1 else []

    dangerous = cmd in DANGER
    reason    = ""

    sensitive_paths = [a for a in args if any(a.startswith(p) for p in SENSITIVE_PATHS)]
    if sensitive_paths:
        dangerous = True
        reason    = f"Access to sensitive path '{sensitive_paths[0]}' denied"

    if not reason:
        dangerous_flags = [a for a in args if a in ("-rf", "--force", "-f", "--exec")]
        if dangerous_flags:
            dangerous = True
            reason    = f"Dangerous flag '{dangerous_flags[0]}' detected"

    if dangerous and not reason:
        reason = f"'{cmd}' matches high-risk command policy"

    if not dangerous:
        reason = "All policy checks passed"

    blocked_sc = random.sample(
        ["execve", "socket", "connect", "fork", "mprotect"],
        k=random.randint(1, 3)
    ) if dangerous else []

    risk_score = random.randint(72, 99) if dangerous else random.randint(2, 22)

    return {
        "command":          body.command,
        "decision":         "BLOCK" if dangerous else "ALLOW",
        "reason":           reason,
        "blocked_syscalls": blocked_sc,
        "risk_score":       risk_score,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "cmd_parsed":       cmd,
        "args_parsed":      args,
    }

@app.get("/api/health")
def health():
    return {
        "status":  "ok",
        "version": "2.1.0",
        "uptime":  int(time.monotonic() - START_TIME),
    }

# ── WebSocket ──────────────────────────────────────────────────────────────────
@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial status snapshot
        await websocket.send_text(json.dumps({
            "type": "snapshot",
            "data": {
                "syscalls":  SYSCALLS,
                "policies":  POLICIES,
                "processes": list(PROC_TABLE.values()),
            }
        }))
        while True:
            # Keep connection alive; handle any client pings
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if msg == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"type": "heartbeat"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

# ── Serve Frontend ─────────────────────────────────────────────────────────────
FRONTEND = Path(__file__).parent.parent / "frontend"

if FRONTEND.exists():
    @app.get("/")
    async def root():
        return FileResponse(FRONTEND / "index.html")

    app.mount("/", StaticFiles(directory=str(FRONTEND), html=True), name="frontend")