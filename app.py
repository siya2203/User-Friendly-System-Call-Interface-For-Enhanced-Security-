from flask import Flask, render_template_string
import sqlite3
from datetime import datetime

app = Flask(__name__)


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: sans-serif; background: #f0f2f5; padding: 30px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .DENIED { color: #e74c3c; font-weight: bold; }
        .SUSPICIOUS { color: #f39c12; font-weight: bold; }
        .ALLOWED { color: #2ecc71; }
    </style>
</head>
<body>
    <h1>🛡️ System Security Intelligence</h1>
    <div class="grid">
        <div class="card"><h3>Threat Distribution</h3><canvas id="pieChart"></canvas></div>
        <div class="card"><h3>Activity Volume</h3><canvas id="barChart"></canvas></div>
        <div class="card" style="grid-column: span 2;">
            <h3>Live Security Logs</h3>
            <table style="width:100%; text-align:left;">
                <tr><th>Syscall</th><th>Status</th></tr>
                {% for row in logs %}
                <tr><td>{{ row[1] }}</td><td class="{{ row[2] }}">{{ row[2] }}</td></tr>
                {% endfor %}
            </table>
        </div>
    </div>
    <script>
        const stats = {{ stats|tojson }};
        new Chart(document.getElementById('pieChart'), {
            type: 'pie',
            data: { labels: ['Allowed', 'Denied', 'Suspicious'], 
            datasets: [{ data: stats, backgroundColor: ['#2ecc71', '#e74c3c', '#f39c12'] }] }
        });
        new Chart(document.getElementById('barChart'), {
            type: 'bar',
            data: { labels: ['Allowed', 'Denied', 'Suspicious'], 
            datasets: [{ label: 'Call Count', data: stats, backgroundColor: '#3498db' }] }
        });
    </script>
</body>
</html>
"""

@app.route("/")
def home():
    conn = sqlite3.connect("logs.db")
    logs = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 10").fetchall()
    allowed = conn.execute("SELECT COUNT(*) FROM logs WHERE status='ALLOWED'").fetchone()[0]
    denied = conn.execute("SELECT COUNT(*) FROM logs WHERE status='DENIED'").fetchone()[0]
    suspicious = conn.execute("SELECT COUNT(*) FROM logs WHERE status='SUSPICIOUS'").fetchone()[0]
    conn.close()
    return render_template_string(HTML_TEMPLATE, logs=logs, stats=[allowed, denied, suspicious])
=======
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
>>>>>>> 2a9dcb7485b64b41a6ef8fd5798c430b3d096a5f

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