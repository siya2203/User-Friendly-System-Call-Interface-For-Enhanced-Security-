# List of high-risk system calls to block by default
BLOCKED = ["execve", "unlink", "rmdir", "ptrace"]

def check_syscall(syscall):
    """Checks if a syscall is in the manual blacklist."""
    if syscall in BLOCKED:
        return "DENIED"
    return "ALLOWED"