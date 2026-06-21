import socket
import logging

logger = logging.getLogger(__name__)

def grab_banner(ip, port, timeout=2):
    """
    Grab banner from a target IP and port.
    
    Args:
        ip (str): Target IP address
        port (int): Target port
        timeout (int): Socket timeout in seconds
        
    Returns:
        str: Banner string or None if failed
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # HTTP needs a request to respond
            if port in (80, 8080, 8000, 443):
                request = b"HEAD / HTTP/1.1\r\nHost: %b\r\nConnection: close\r\n\r\n" % ip.encode()
                sock.sendall(request)

            banner = sock.recv(1024).decode(errors="ignore").strip()

            if banner:
                first_line = banner.split("\n")[0].strip()
                logger.debug(f"Banner grabbed from {ip}:{port} - {first_line}")
                return first_line
            
            logger.debug(f"No banner received from {ip}:{port}")
            return None

    except socket.timeout:
        logger.debug(f"Socket timeout on {ip}:{port}")
        return None
    except socket.error as e:
        logger.debug(f"Socket error on {ip}:{port} - {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error grabbing banner from {ip}:{port} - {e}")
        return None