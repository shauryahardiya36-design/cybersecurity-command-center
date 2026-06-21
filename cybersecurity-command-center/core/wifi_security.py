import socket
import logging
from datetime import datetime, timedelta
from core.database import ScanDatabase
from core.network_blocker import network_blocker

logger = logging.getLogger(__name__)
db = ScanDatabase()

class WiFiSecurityMonitor:
    """Monitor and detect WiFi attacks like DNS spoofing."""
    
    def __init__(self):
        self.suspicious_ips_file = "data/suspicious_activity.json"
        self.known_dns_servers = {
            "8.8.8.8": "Google DNS",
            "8.8.4.4": "Google DNS",
            "1.1.1.1": "Cloudflare DNS",
            "1.0.0.1": "Cloudflare DNS",
            "9.9.9.9": "Quad9 DNS"
        }
    
    # =========================
    # DNS SPOOFING DETECTION
    # =========================
    
    def detect_dns_spoofing(self, ip, port=53):
        """
        Detect if an IP is running unauthorized DNS server.
        DNS servers should only be on known trusted devices.
        """
        if port != 53:
            return False, "Not DNS"
        
        # Check if this IP should have DNS
        whitelist = db.get_whitelist()
        if ip not in whitelist:
            # Unknown device on port 53 = potential DNS spoofing
            logger.warning(f"[DNS SPOOFING ALERT] Unauthorized DNS server detected on {ip}:{port}")
            return True, "Unauthorized DNS server detected"
        
        return False, "DNS server on whitelisted device"
    
    # =========================
    # ARP SPOOFING DETECTION
    # =========================
    
    def detect_arp_spoofing(self, ip, mac_address=None):
        """
        Detect ARP spoofing by monitoring MAC address changes.
        Same IP should always have same MAC address.
        """
        try:
            import json
            
            arp_cache_file = "data/arp_cache.json"
            
            try:
                with open(arp_cache_file, 'r') as f:
                    arp_cache = json.load(f)
            except FileNotFoundError:
                arp_cache = {}
            
            if ip in arp_cache:
                stored_mac = arp_cache[ip]["mac"]
                if mac_address and mac_address != stored_mac:
                    logger.warning(
                        f"[ARP SPOOFING ALERT] MAC address changed for {ip}! "
                        f"Was {stored_mac}, now {mac_address}"
                    )
                    return True, f"MAC spoofing detected: {stored_mac} → {mac_address}"
            
            # Update cache
            arp_cache[ip] = {
                "mac": mac_address,
                "last_seen": datetime.now().isoformat()
            }
            
            with open(arp_cache_file, 'w') as f:
                json.dump(arp_cache, f, indent=2)
            
            return False, "ARP verified"
        
        except Exception as e:
            logger.error(f"ARP check error: {e}")
            return False, str(e)
    
    # =========================
    # SUSPICIOUS PORT ACTIVITY
    # =========================
    
    def detect_suspicious_ports(self, ip, ports):
        """
        Detect suspicious port combinations that indicate attacks.
        """
        suspicious_combinations = [
            (53, 5353),      # DNS + mDNS (DNS hijacking)
            (67, 68),        # DHCP spoofing
            (443, 8443),     # HTTPS port duplication (man-in-the-middle)
        ]
        
        port_set = set(ports)
        alerts = []
        
        for combo in suspicious_combinations:
            if set(combo).issubset(port_set):
                logger.warning(
                    f"[SUSPICIOUS] {ip} running suspicious port combo: {combo}"
                )
                alerts.append(f"Suspicious ports detected: {combo}")
        
        return alerts
    
    # =========================
    # RATE LIMITING / DDoS
    # =========================
    
    def detect_port_scanning(self, ip, ports_found):
        """
        Detect if an IP is port scanning (many ports open = potential attacker).
        """
        try:
            import json
            
            scan_history_file = "data/scan_history.json"
            
            try:
                with open(scan_history_file, 'r') as f:
                    scan_history = json.load(f)
            except FileNotFoundError:
                scan_history = {}
            
            if ip not in scan_history:
                scan_history[ip] = []
            
            scan_history[ip].append({
                "timestamp": datetime.now().isoformat(),
                "ports_count": len(ports_found)
            })
            
            # Keep only last 10 scans
            scan_history[ip] = scan_history[ip][-10:]
            
            with open(scan_history_file, 'w') as f:
                json.dump(scan_history, f, indent=2)
            
            # If 3+ ports open on non-whitelisted device = suspicious
            if len(ports_found) >= 3:
                whitelist = db.get_whitelist()
                if ip not in whitelist:
                    logger.warning(
                        f"[PORT SCANNING] {ip} has {len(ports_found)} ports open - "
                        f"possible attacker scanning network"
                    )
                    return True, f"Too many open ports ({len(ports_found)})"
            
            return False, "Port count normal"
        
        except Exception as e:
            logger.error(f"Port scan detection error: {e}")
            return False, str(e)
    
    # =========================
    # THREAT RESPONSE
    # =========================
    
    def block_ip(self, ip, reason, severity="HIGH"):
        """
        Add IP to blacklist and block at network level.
        """
        db.add_blacklist(ip, reason=reason, severity=severity)
        logger.critical(f"[BLOCKED] {ip} - {reason}")
        
        # NEW: Actually block at network level
        network_blocker.block_ip(ip)
        
        # Log to system
        self._log_block_action(ip, reason)
        
        return True
    
    def _log_block_action(self, ip, reason):
        """Log blocking action for audit trail."""
        try:
            import json
            
            blocked_ips_file = "data/blocked_ips.json"
            
            try:
                with open(blocked_ips_file, 'r') as f:
                    blocked_ips = json.load(f)
            except FileNotFoundError:
                blocked_ips = []
            
            blocked_ips.append({
                "ip": ip,
                "reason": reason,
                "timestamp": datetime.now().isoformat()
            })
            
            with open(blocked_ips_file, 'w') as f:
                json.dump(blocked_ips, f, indent=2)
        
        except Exception as e:
            logger.error(f"Error logging block: {e}")
    
    def get_blocked_ips(self):
        """Get list of blocked IPs."""
        import json
        try:
            with open("data/blocked_ips.json", 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return []


# Initialize monitor
wifi_monitor = WiFiSecurityMonitor()