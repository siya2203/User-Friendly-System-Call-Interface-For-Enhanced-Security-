# User-Friendly System Call Interface For Enhanced Security

SecureSyscall OS is a teaching project for operating-system security. It provides a dashboard for monitoring simulated system calls, changing per-syscall policies, viewing process risk, checking audit trails, and running commands through a sandbox decision engine.

## Features

- FastAPI backend with REST endpoints and a live WebSocket syscall stream
- Dashboard for syscall rate, blocked calls, active policies, threat score, and category distribution
- Policy manager with live enable and disable controls
- Syscall filter table with allowed, audited, sandboxed, and blocked modes
- Sandbox runner that demonstrates seccomp-style command decisions
- Audit trail and threat alert views
- BPF C probe source for Linux kernel syscall tracing experiments
- C++ sandbox decision engine for command-line policy checks

## Run

```powershell
cd backend
..\venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000
```

If the virtual environment is missing dependencies:

```powershell
venv\Scripts\pip.exe install -r requirements.txt
```

## API

```text
GET  /api/status
GET  /api/log
GET  /api/processes
GET  /api/policies
PUT  /api/policies/{index}
GET  /api/syscalls
PUT  /api/syscalls/{name}
GET  /api/audit
GET  /api/threats
PUT  /api/security-level
POST /api/sandbox/run
WS   /ws/live
```

## Native Components

Build the C++ sandbox checker with a C++17 compiler:

```powershell
g++ backend\sandbox_enforcer.cpp -std=c++17 -o sandbox_enforcer.exe
.\sandbox_enforcer.exe open /etc/shadow
```

The BPF probe in `backend/kernel_monitor.c` is intended for Linux systems with BCC/eBPF support.
