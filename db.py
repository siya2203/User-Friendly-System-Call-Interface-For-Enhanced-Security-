import sqlite3

# connect to database
conn = sqlite3.connect("logs.db")
cursor = conn.cursor()

# create table
cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    syscall TEXT,
    status TEXT
)
""")

def log_data(syscall, status):
    cursor.execute("INSERT INTO logs (syscall, status) VALUES (?, ?)", (syscall, status))
    conn.commit()