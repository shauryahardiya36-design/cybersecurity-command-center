import subprocess
import logging
import platform

logger = logging.getLogger(__name__)

class NetworkBlocker:
    """Block IPs at the network level using system commands."""
    
    def __init__(self):
        self.os_type = platform.system()
        self.blocked_ips = []
    
    def block_ip(self, ip):
        """Block an IP using OS-specific commands."""
        if ip in self.blocked_ips:
            logger.info(f"{ip} already blocked")
            return True
        
        if self.os_type == "Darwin":  # macOS
            return self._block_ip_macos(ip)
        elif self.os_type == "Linux":
            return self._block_ip_linux(ip)
        elif self.os_type == "Windows":
            return self._block_ip_windows(ip)
        else:
            logger.error(f"Unsupported OS: {self.os_type}")
            return False
    
    def _block_ip_macos(self, ip):
        """Block IP on macOS using pfctl (requires sudo)."""
        try:
            # Add to pfctl blocklist
            cmd = f"sudo pfctl -t blocklist -T add {ip}"
            subprocess.run(cmd, shell=True, check=True)
            
            self.blocked_ips.append(ip)
            logger.critical(f"[BLOCKED] {ip} - Firewall rule added")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block {ip} on macOS: {e}")
            return False
    
    def _block_ip_linux(self, ip):
        """Block IP on Linux using iptables (requires sudo)."""
        try:
            # Block both incoming and outgoing traffic
            subprocess.run(f"sudo iptables -I INPUT -s {ip} -j DROP", shell=True, check=True)
            subprocess.run(f"sudo iptables -I OUTPUT -d {ip} -j DROP", shell=True, check=True)
            
            self.blocked_ips.append(ip)
            logger.critical(f"[BLOCKED] {ip} - iptables rule added")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block {ip} on Linux: {e}")
            return False
    
    def _block_ip_windows(self, ip):
        """Block IP on Windows using netsh (requires admin)."""
        try:
            cmd = f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}"
            subprocess.run(cmd, shell=True, check=True)
            
            self.blocked_ips.append(ip)
            logger.critical(f"[BLOCKED] {ip} - Windows Firewall rule added")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block {ip} on Windows: {e}")
            return False
    
    def unblock_ip(self, ip):
        """Unblock an IP."""
        if self.os_type == "Darwin":
            return self._unblock_ip_macos(ip)
        elif self.os_type == "Linux":
            return self._unblock_ip_linux(ip)
        elif self.os_type == "Windows":
            return self._unblock_ip_windows(ip)
    
    def _unblock_ip_macos(self, ip):
        """Unblock IP on macOS."""
        try:
            cmd = f"sudo pfctl -t blocklist -T delete {ip}"
            subprocess.run(cmd, shell=True, check=True)
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
            logger.info(f"[UNBLOCKED] {ip}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock {ip}: {e}")
            return False
    
    def _unblock_ip_linux(self, ip):
        """Unblock IP on Linux."""
        try:
            subprocess.run(f"sudo iptables -D INPUT -s {ip} -j DROP", shell=True, check=True)
            subprocess.run(f"sudo iptables -D OUTPUT -d {ip} -j DROP", shell=True, check=True)
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
            logger.info(f"[UNBLOCKED] {ip}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock {ip}: {e}")
            return False
    
    def _unblock_ip_windows(self, ip):
        """Unblock IP on Windows."""
        try:
            cmd = f"netsh advfirewall firewall delete rule name=\"Block {ip}\""
            subprocess.run(cmd, shell=True, check=True)
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
            logger.info(f"[UNBLOCKED] {ip}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock {ip}: {e}")
            return False


network_blocker = NetworkBlocker()