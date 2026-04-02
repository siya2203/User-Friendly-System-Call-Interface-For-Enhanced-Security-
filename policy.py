BLOCKED = ["execve", "unlink"]

def check_syscall(syscall):
    if syscall in BLOCKED:
        return "DENIED"
    return "ALLOWED"