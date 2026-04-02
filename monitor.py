def read_syscalls():
    syscalls = []

    try:
        with open("trace.log", "r") as f:
            for line in f:
                if "(" in line:
                    syscall = line.split("(")[0].strip()
                    syscalls.append(syscall)
    except FileNotFoundError:
        print("trace.log not found. Run strace first.")

    return syscalls