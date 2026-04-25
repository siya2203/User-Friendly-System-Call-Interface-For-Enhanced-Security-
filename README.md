# SecureSyscall OS — Fixed & Complete

A teaching dashboard for OS security: monitor simulated syscalls, manage policies,
view process risk, check audit trails, and run commands through a sandbox engine.

---

## What Was Broken (and Fixed)

| # | Bug | Fix |
|---|-----|-----|
| 1 | **Missing `aiofiles`, `python-multipart`, `starlette`** in requirements | Added all deps to `requirements.txt` |
| 2 | **CORS not configured** — frontend JS blocked by browser | Added `CORSMiddleware` allowing all origins (restrict in production) |
| 3 | **Frontend not served** — FastAPI had no StaticFiles mount | Added `StaticFiles` mount + explicit `/` → `index.html` route |
| 4 | **WebSocket URL hardcoded to `localhost`** in JS | Frontend now derives host from `window.location` dynamically |
| 5 | **WebSocket path mismatch** between backend and frontend | Unified to `/ws/live` in both places |
| 6 | **No auto-reconnect** on WebSocket drop | Added `setTimeout(connectWS, 2000)` on close |
| 7 | **`uvicorn` missing `[standard]` extras** (needed for websockets) | Changed to `uvicorn[standard]` |
| 8 | **`sandbox_enforcer.cpp`** used non-standard includes | Cleaned up to pure C++17 STL |

---

## Project Structure

```
SecureSyscall/
├── backend/
│   ├── main.py                  ← FastAPI app (all endpoints + WebSocket)
│   └── sandbox_enforcer.cpp     ← C++ command policy checker (optional)
├── frontend/
│   └── index.html               ← Single-file dashboard (HTML/CSS/JS)
├── requirements.txt
└── README.md
```

---

## Quick Start (Windows)

```cmd
cd SecureSyscall

:: Create virtualenv (first time only)
python -m venv venv

:: Install dependencies
venv\Scripts\pip.exe install -r requirements.txt

:: Run the server
cd backend
..\venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Then open: **http://127.0.0.1:8000**

---

## Quick Start (Linux / macOS)

```bash
cd SecureSyscall
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd backend
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | Dashboard counters (total calls, blocked, threat score) |
| GET | `/api/log` | Recent syscall log entries |
| GET | `/api/processes` | Active process list with risk scores |
| GET | `/api/policies` | All security policies |
| PUT | `/api/policies/{index}` | Enable/disable a policy |
| GET | `/api/syscalls` | Syscall filter table |
| PUT | `/api/syscalls/{name}` | Change syscall enforcement mode |
| GET | `/api/audit` | Audit trail |
| GET | `/api/threats` | Threat alerts |
| PUT | `/api/security-level` | Set global security level |
| POST | `/api/sandbox/run` | Evaluate a command in sandbox |
| WS | `/ws/live` | Real-time syscall event stream |

---

## Build C++ Sandbox (optional)

```bash
# Linux/macOS
g++ backend/sandbox_enforcer.cpp -std=c++17 -o sandbox_enforcer
./sandbox_enforcer open /etc/shadow

# Windows
g++ backend\sandbox_enforcer.cpp -std=c++17 -o sandbox_enforcer.exe
.\sandbox_enforcer.exe open /etc/shadow
```
