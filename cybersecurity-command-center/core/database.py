import json
import os
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ScanDatabase:
    """Manage scan results, whitelist, and blacklist."""
    
    def __init__(self, db_dir="data"):
        """Initialize database directory."""
        self.db_dir = db_dir
        self.results_file = os.path.join(db_dir, "scan_results.json")
        self.whitelist_file = os.path.join(db_dir, "whitelist.json")
        self.blacklist_file = os.path.join(db_dir, "blacklist.json")
        
        os.makedirs(db_dir, exist_ok=True)
        self._initialize_files()
    
    def _initialize_files(self):
        """Create default files if they don't exist."""
        if not os.path.exists(self.results_file):
            self._save_json(self.results_file, [])
        if not os.path.exists(self.whitelist_file):
            self._save_json(self.whitelist_file, {})
        if not os.path.exists(self.blacklist_file):
            self._save_json(self.blacklist_file, {})
    
    def _load_json(self, filepath):
        """Load JSON file safely."""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Error loading {filepath}: {e}")
            return [] if "results" in filepath else {}
    
    def _save_json(self, filepath, data):
        """Save JSON file safely."""
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved to {filepath}")
        except IOError as e:
            logger.error(f"Error saving {filepath}: {e}")
    
    # =========================
    # SCAN RESULTS
    # =========================
    
    def save_scan(self, ip, open_ports, alerts, banner_data=None):
        """Save scan results with timestamp."""
        results = self._load_json(self.results_file)
        
        scan_record = {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "open_ports": open_ports,
            "alerts": alerts,
            "banner_data": banner_data or {}
        }
        
        results.append(scan_record)
        self._save_json(self.results_file, results)
        logger.info(f"Scan result saved for {ip}")
    
    def get_scan_history(self, ip=None):
        """Retrieve scan history for an IP or all IPs."""
        results = self._load_json(self.results_file)
        
        if ip:
            return [r for r in results if r["ip"] == ip]
        return results
    
    def get_latest_scan(self, ip):
        """Get most recent scan for an IP."""
        history = self.get_scan_history(ip)
        return history[-1] if history else None
    
    # =========================
    # WHITELIST
    # =========================
    
    def add_whitelist(self, ip, reason=""):
        """Add IP to whitelist."""
        whitelist = self._load_json(self.whitelist_file)
        
        whitelist[ip] = {
            "added_at": datetime.now().isoformat(),
            "reason": reason
        }
        
        self._save_json(self.whitelist_file, whitelist)
        logger.info(f"Added {ip} to whitelist: {reason}")
    
    def is_whitelisted(self, ip):
        """Check if IP is whitelisted."""
        whitelist = self._load_json(self.whitelist_file)
        return ip in whitelist
    
    def remove_whitelist(self, ip):
        """Remove IP from whitelist."""
        whitelist = self._load_json(self.whitelist_file)
        
        if ip in whitelist:
            del whitelist[ip]
            self._save_json(self.whitelist_file, whitelist)
            logger.info(f"Removed {ip} from whitelist")
            return True
        return False
    
    def get_whitelist(self):
        """Get all whitelisted IPs."""
        return self._load_json(self.whitelist_file)
    
    # =========================
    # BLACKLIST
    # =========================
    
    def add_blacklist(self, ip, reason="", severity="MEDIUM"):
        """Add IP to blacklist with severity level."""
        blacklist = self._load_json(self.blacklist_file)
        
        blacklist[ip] = {
            "added_at": datetime.now().isoformat(),
            "reason": reason,
            "severity": severity  # LOW, MEDIUM, HIGH, CRITICAL
        }
        
        self._save_json(self.blacklist_file, blacklist)
        logger.warning(f"Added {ip} to blacklist ({severity}): {reason}")
    
    def is_blacklisted(self, ip):
        """Check if IP is blacklisted."""
        blacklist = self._load_json(self.blacklist_file)
        return ip in blacklist
    
    def remove_blacklist(self, ip):
        """Remove IP from blacklist."""
        blacklist = self._load_json(self.blacklist_file)
        
        if ip in blacklist:
            del blacklist[ip]
            self._save_json(self.blacklist_file, blacklist)
            logger.info(f"Removed {ip} from blacklist")
            return True
        return False
    
    def get_blacklist(self):
        """Get all blacklisted IPs."""
        return self._load_json(self.blacklist_file)
    
    # =========================
    # REPORTING
    # =========================
    
    def generate_report(self):
        """Generate summary report."""
        results = self._load_json(self.results_file)
        whitelist = self._load_json(self.whitelist_file)
        blacklist = self._load_json(self.blacklist_file)
        
        report = {
            "total_scans": len(results),
            "unique_ips_scanned": len(set(r["ip"] for r in results)),
            "total_alerts": sum(len(r["alerts"]) for r in results),
            "whitelisted_ips": len(whitelist),
            "blacklisted_ips": len(blacklist),
            "blacklist_by_severity": {
                "CRITICAL": len([b for b in blacklist.values() if b.get("severity") == "CRITICAL"]),
                "HIGH": len([b for b in blacklist.values() if b.get("severity") == "HIGH"]),
                "MEDIUM": len([b for b in blacklist.values() if b.get("severity") == "MEDIUM"]),
                "LOW": len([b for b in blacklist.values() if b.get("severity") == "LOW"])
            }
        }
        
        return report