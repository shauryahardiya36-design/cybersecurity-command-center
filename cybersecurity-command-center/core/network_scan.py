import subprocess

def scan_network(ips):
    alive = []

    for ip in ips:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "100", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                alive.append(ip)
        except Exception:
            pass

    return alive
