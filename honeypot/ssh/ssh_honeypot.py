import json
import os
from datetime import datetime

LOG_FILE = os.path.join("..", "logs", "ssh_logs.json")


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


def simulate_login(ip, username, success=False):
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "protocol": "SSH",
        "username": username,
        "login_success": success,
        "event": "login_attempt"
    }

    save_log(log_data)

    print(f"[SSH] Login attempt from {ip} using username: {username}")


def simulate_command(ip, command):
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "protocol": "SSH",
        "command": command,
        "event": "command_activity"
    }

    save_log(log_data)

    print(f"[SSH] Command activity from {ip}: {command}")


if __name__ == "__main__":

    print("===================================")
    print("      SSH HONEYPOT SIMULATION")
    print("===================================")

    # Controlled local test data
    test_ip = "192.0.2.10"

    simulate_login(
        test_ip,
        "admin",
        False
    )

    simulate_login(
        test_ip,
        "root",
        False
    )

    simulate_login(
        test_ip,
        "test",
        False
    )

    simulate_command(
        test_ip,
        "whoami"
    )

    simulate_command(
        test_ip,
        "ls"
    )

    simulate_command(
        test_ip,
        "pwd"
    )

    print("\nSSH honeypot simulation completed.")
    print("Check honeypot/logs/ssh_logs.json")