from flask import Flask
import sqlite3
from datetime import datetime

app = Flask(__name__)

# -------------------------------
# 1. Initialize Database
# -------------------------------
def init_db():
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()

# Call this once when app starts
init_db()


# -------------------------------
# 2. Insert Sample Log (optional)
# -------------------------------
def insert_log(message):
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO logs (message, timestamp) VALUES (?, ?)",
        (message, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )

    conn.commit()
    conn.close()


# -------------------------------
# 3. Home Route
# -------------------------------
@app.route("/")
def home():
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM logs")
    logs = cursor.fetchall()

    conn.close()

    # Display logs in simple HTML
    html = "<h1>System Logs</h1>"

    if not logs:
        html += "<p>No logs available</p>"
    else:
        html += "<ul>"
        for log in logs:
            html += f"<li>{log[1]} | {log[2]}</li>"
        html += "</ul>"

    return html


# -------------------------------
# 4. Add Log Route (for testing)
# -------------------------------
@app.route("/add")
def add_log():
    insert_log("Test log added")
    return "Log added successfully! Go back to /"


# -------------------------------
# 5. Run App
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)