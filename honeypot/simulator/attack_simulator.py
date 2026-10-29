import json
import os
import random
import time
from datetime import datetime

LOG_FILE = os.path.join("..", "logs", "simulator_logs.json")


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


# Simulate SSH login activity
def simulate_ssh_activity():
    print("\n--- Simulating SSH Activity ---")

    test_ips = [
        "192.0.2.20",
        "192.0.2.30",
        "192.0.2.40"
    ]

    usernames = [
        "admin",
        "root",
        "test",
        "user"
    ]

    for i in range(5):
        ip = random.choice(test_ips)
        username = random.choice(usernames)

        log_data = {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "protocol": "SSH",
            "username": username,
            "login_success": False,
            "event": "login_attempt"
        }

        save_log(log_data)

        print(
            f"[SSH] Failed login from {ip} "
            f"using username: {username}"
        )

        time.sleep(0.5)


# Simulate HTTP activity
def simulate_http_activity():
    print("\n--- Simulating HTTP Activity ---")

    test_ips = [
        "192.0.2.20",
        "192.0.2.30",
        "192.0.2.50"
    ]

    endpoints = [
        "/",
        "/admin",
        "/login",
        "/test",
        "/config",
        "/backup"
    ]

    for i in range(6):
        ip = random.choice(test_ips)
        endpoint = random.choice(endpoints)

        log_data = {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "protocol": "HTTP",
            "method": "GET",
            "request": endpoint,
            "event": "http_request"
        }

        save_log(log_data)

        print(
            f"[HTTP] Request from {ip}: {endpoint}"
        )

        time.sleep(0.5)


if __name__ == "__main__":

    print("===================================")
    print("       ATTACK ACTIVITY SIMULATOR")
    print("===================================")

    simulate_ssh_activity()
    simulate_http_activity()

    print("\nSimulation completed.")
    print("Check:")
    print("honeypot/logs/simulator_logs.json")