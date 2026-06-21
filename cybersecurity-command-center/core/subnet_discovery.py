import socket
import ipaddress

def get_local_ip():
    """Get local IP safely (cross-platform)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

def get_local_subnet():
    """Return subnet in CIDR format like 192.168.1.0/24."""
    ip = get_local_ip()
    return ip.rsplit(".", 1)[0] + ".0/24"

def generate_ips(subnet):
    """Generate all IPs in a subnet."""
    net = ipaddress.ip_network(subnet, strict=False)
    return [str(ip) for ip in net.hosts()]
