from flask import Flask
import sqlite3

app = Flask(__name__)

@app.route("/")
def home():
    conn = sqlite3.connect("logs.db")
    data = conn.execute("SELECT * FROM logs").fetchall()

    result = ""
    for row in data:
        result += f"{row}<br>"

    return result

if __name__ == "__main__":
    app.run(debug=True)