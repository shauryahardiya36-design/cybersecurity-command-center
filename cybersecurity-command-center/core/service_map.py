# Port -> (Service Name, Risk Level)

SERVICE_MAP = {
    21:  ("FTP", "HIGH"),
    22:  ("SSH", "MEDIUM"),
    23:  ("Telnet", "HIGH"),
    53:  ("DNS", "LOW"),
    80:  ("HTTP", "LOW"),
    443: ("HTTPS", "LOW"),
    445: ("SMB", "HIGH"),
    631: ("Printer (CUPS)", "MEDIUM"),
    8080: ("HTTP-Alt", "MEDIUM"),
    3389: ("RDP", "HIGH")
}

def describe_port(port):
    """
    Returns (service_name, risk_level)
    """
    return SERVICE_MAP.get(port, ("Unknown", "UNKNOWN"))
