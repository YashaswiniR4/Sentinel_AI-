from flask import Flask, request
from datetime import datetime
import json
import os

app = Flask(__name__)

LOG_FILE = os.path.join("..", "logs", "http_logs.json")


def save_log(data):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    logs = []

    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as file:
                logs = json.load(file)
        except:
            logs = []

    logs.append(data)

    with open(LOG_FILE, "w") as file:
        json.dump(logs, file, indent=4)


@app.route("/", methods=["GET"])
def home():
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "ip": request.remote_addr,
        "protocol": "HTTP",
        "method": request.method,
        "request": request.path,
        "user_agent": request.headers.get("User-Agent")
    }

    save_log(log_data)

    return """
    <h1>Welcome</h1>
    <p>Server is running.</p>
    """


@app.route("/admin", methods=["GET", "POST"])
def admin():
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "ip": request.remote_addr,
        "protocol": "HTTP",
        "method": request.method,
        "request": request.path,
        "user_agent": request.headers.get("User-Agent")
    }

    save_log(log_data)

    return """
    <h1>Admin Login</h1>
    <form method="POST">
        Username: <input type="text" name="username"><br><br>
        Password: <input type="password" name="password"><br><br>
        <input type="submit" value="Login">
    </form>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "ip": request.remote_addr,
        "protocol": "HTTP",
        "method": request.method,
        "request": request.path,
        "user_agent": request.headers.get("User-Agent")
    }

    save_log(log_data)

    return """
    <h1>Login Page</h1>
    <p>This is a simulated login page for the honeypot.</p>
    """


@app.route("/test", methods=["GET"])
def test():
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "ip": request.remote_addr,
        "protocol": "HTTP",
        "method": request.method,
        "request": request.path,
        "user_agent": request.headers.get("User-Agent")
    }

    save_log(log_data)

    return """
    <h1>Test Endpoint</h1>
    <p>HTTP Honeypot is working.</p>
    """


if __name__ == "__main__":
    print("===================================")
    print("   HTTP HONEYPOT STARTED")
    print("   http://127.0.0.1:8080")
    print("===================================")

    app.run(host="127.0.0.1", port=8080, debug=False)