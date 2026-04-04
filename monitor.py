import sys

def read_syscalls():
    """Reads syscalls live from the terminal input (stdin)"""
    try:
        # This allows the engine to process lines one-by-one as they arrive
        for line in sys.stdin:
            if "(" in line:
                syscall = line.split("(")[0].strip()
                yield syscall
    except EOFError:
        pass