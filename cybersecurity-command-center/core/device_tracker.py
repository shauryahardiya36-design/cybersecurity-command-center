import json
import os

DEVICE_FILE = "devices.json"


def load_devices():
    if not os.path.exists(DEVICE_FILE):
        return {}

    with open(DEVICE_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_devices(devices):
    with open(DEVICE_FILE, "w") as f:
        json.dump(devices, f, indent=2)


def compare_devices(old_devices, new_devices):
    alerts = []

    # New devices appeared
    for ip in new_devices:
        if ip not in old_devices:
            alerts.append(f"[NEW DEVICE] {ip}")

    # Devices disappeared
    for ip in old_devices:
        if ip not in new_devices:
            alerts.append(f"[DEVICE LOST] {ip}")

    # Port changes
    for ip in new_devices:
        if ip in old_devices:
            old_ports = set(old_devices.get(ip, []))
            new_ports = set(new_devices.get(ip, []))

            opened = new_ports - old_ports
            closed = old_ports - new_ports

            for port in opened:
                alerts.append(f"[PORT OPENED] {ip}:{port}")

            for port in closed:
                alerts.append(f"[PORT CLOSED] {ip}:{port}")

    return alerts
