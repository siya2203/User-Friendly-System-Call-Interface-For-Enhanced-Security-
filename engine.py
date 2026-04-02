from monitor import read_syscalls
from policy import check_syscall
from db import log_data

def run_engine():
    syscalls = read_syscalls()

    for sc in syscalls:
        status = check_syscall(sc)
        log_data(sc, status)
        print(f"{sc} → {status}")

if __name__ == "__main__":
    run_engine()