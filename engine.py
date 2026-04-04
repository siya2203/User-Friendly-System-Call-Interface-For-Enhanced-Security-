from monitor import read_syscalls
from policy import check_syscall
from db import log_data, init_db
from anomaly import detect_anomaly

def run_engine():
    init_db()
    print("🛡️ Guard Engine Active: Monitoring system calls live...")
    
    # Process syscalls one by one as they come in from the live monitor
    for sc in read_syscalls():
        # 1. Check Hardcoded Policy
        status = check_syscall(sc)
        
        # 2. Check AI Anomaly Detection if the policy allowed it
        if status == "ALLOWED":
            ai_result = detect_anomaly(sc)
            if ai_result == -1:
                status = "SUSPICIOUS"

        log_data(sc, status)
        print(f"Event Captured: {sc} -> {status}")

if __name__ == "__main__":
    run_engine()