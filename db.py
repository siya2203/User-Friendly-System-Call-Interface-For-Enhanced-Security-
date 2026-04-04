import sqlite3

def init_db():
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        syscall TEXT,
        status TEXT
    )
    """)
    conn.commit()
    conn.close()

def log_data(syscall, status):
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (syscall, status) VALUES (?, ?)", (syscall, status))
    conn.commit()
    conn.close()