import socket
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
from core.database import ScanDatabase
from core.banner_grab import grab_banner
from core.wifi_security import wifi_monitor
import os
from core.report_generator import report_generator

# =========================
# LOGGING SETUP
# =========================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# =========================
# DATABASE INITIALIZATION
# =========================
db = ScanDatabase()

# =========================
# CONFIG
# =========================

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389
]

PORT_RISK = {
    21: ("FTP", "HIGH"),
    22: ("SSH", "MEDIUM"),
    23: ("Telnet", "HIGH"),
    25: ("SMTP", "LOW"),
    53: ("DNS", "LOW"),
    80: ("HTTP", "LOW"),
    110: ("POP3", "MEDIUM"),
    139: ("NetBIOS", "MEDIUM"),
    143: ("IMAP", "LOW"),
    443: ("HTTPS", "LOW"),
    445: ("SMB", "HIGH"),
    3389: ("RDP", "HIGH"),
}

TIMEOUT = 0.5
MAX_WORKERS = 10


# =========================
# UTILITIES
# =========================

def is_valid_ip(ip):
    """Validate IP address format."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def check_port(ip, port):
    """Check if a single port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((ip, port)) == 0
        sock.close()
        return port if result else None
    except socket.error as e:
        logger.debug(f"Socket error on {ip}:{port} - {e}")
        return None


# =========================
# PORT SCANNER
# =========================

def scan_ports(ip, ports=COMMON_PORTS):
    """Scan multiple ports concurrently on target IP."""
    if not is_valid_ip(ip):
        logger.error(f"Invalid IP address: {ip}")
        return []

    open_ports = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_port, ip, port): port for port in ports}
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    
    return sorted(open_ports)


# =========================
# ANALYSIS / OUTPUT
# =========================

def analyze_ports(ip, open_ports):
    """Analyze open ports and return alerts."""
    alerts = []
    attack_type = None

    logger.info(f"Scanning {ip}")

    if not open_ports:
        logger.info(f"  {ip} - No exposed services (secure)")
        return alerts

    for port in open_ports:
        service, risk = PORT_RISK.get(port, ("Unknown", "UNKNOWN"))
        logger.info(f"  {port} ({service}) → {risk}")

        if risk in ("HIGH", "MEDIUM"):
            alerts.append({
                "ip": ip,
                "port": port,
                "service": service,
                "risk": risk
            })
    
    # Check for WiFi attacks
    is_spoofing, spoofing_msg = wifi_monitor.detect_dns_spoofing(ip)
    if is_spoofing:
        logger.critical(f"[ATTACK DETECTED] {ip}: {spoofing_msg}")
        attack_type = "DNS_SPOOFING"
        wifi_monitor.block_ip(ip, spoofing_msg, severity="CRITICAL")
        alerts.append({
            "ip": ip,
            "port": 53,
            "service": "DNS",
            "risk": "CRITICAL",
            "attack": "DNS Spoofing"
        })
    
    # Check for suspicious port combinations
    suspicious = wifi_monitor.detect_suspicious_ports(ip, open_ports)
    if suspicious:
        for alert_msg in suspicious:
            logger.warning(f"[ATTACK DETECTED] {ip}: {alert_msg}")
            attack_type = "SUSPICIOUS_PORTS"
            wifi_monitor.block_ip(ip, alert_msg, severity="HIGH")
    
    # Check for port scanning behavior
    is_scanning, scan_msg = wifi_monitor.detect_port_scanning(ip, open_ports)
    if is_scanning:
        logger.critical(f"[ATTACK DETECTED] {ip}: {scan_msg}")
        attack_type = "PORT_SCANNING"
        wifi_monitor.block_ip(ip, scan_msg, severity="HIGH")
        alerts.append({
            "ip": ip,
            "port": None,
            "service": "Network",
            "risk": "CRITICAL",
            "attack": "Port Scanning"
        })
    
    # Generate incident report if threats detected
    if alerts and attack_type:
        banner_data = {}
        for port in open_ports:
            banner = grab_banner(ip, port)
            if banner:
                banner_data[port] = banner
        
        report = report_generator.generate_incident_report(
            ip=ip,
            open_ports=open_ports,
            alerts=alerts,
            banner_data=banner_data,
            attack_type=attack_type
        )
        
        logger.info(f"Full incident report generated: {report['report_id']}")
        
        # Print report to console
        print_report(report)

    return alerts


def print_report(report):
    """Print detailed report to console."""
    print("\n" + "=" * 80)
    print("INCIDENT REPORT")
    print("=" * 80 + "\n")
    
    print(f"Report ID: {report['report_id']}")
    print(f"Timestamp: {report['timestamp']}\n")
    
    print("-" * 80)
    print("SUMMARY")
    print("-" * 80)
    print(f"{report['incident_summary']}\n")
    
    severity = report['severity_assessment']
    print(f"Severity: {severity['level']} ({severity['score']}/10)")
    print(f"{severity['description']}\n")
    
    print("-" * 80)
    print("DEVICE INFORMATION")
    print("-" * 80)
    device = report['device_information']
    print(f"IP Address: {device['ip_address']}")
    print(f"Status: {device['status']}")
    print(f"First Seen: {device['first_seen'] or 'Unknown'}")
    print(f"Scan Count: {device['scan_count']}\n")
    
    print("-" * 80)
    print("PORTS ACCESSED")
    print("-" * 80)
    for port_info in report['ports_accessed']:
        print(f"Port {port_info['port_number']}: {port_info['service']} ({port_info['risk_level']})")
        print(f"  {port_info['description']}")
        if port_info['banner']:
            print(f"  Banner: {port_info['banner']}")
    print()
    
    print("-" * 80)
    print("RESPONSE ACTIONS")
    print("-" * 80)
    for action in report['response_actions']['automatic_actions']:
        print(f"✓ {action.get('action')}")
        if 'result' in action:
            print(f"  {action['result']}")
    print()
    
    print("-" * 80)
    print("RECOMMENDATIONS")
    print("-" * 80)
    for rec in report['recommendations']:
        print(rec)
    
    print("\n" + "=" * 80 + "\n")


# =========================
# MAIN
# =========================

def main(targets=None):
    """Main entry point for port scanner."""
    if targets is None:
        targets = [
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3",
            "192.168.1.11",
            "192.168.1.14"
        ]

    logger.info("[ Cybersecurity Command Center ]")
    logger.info(f"Scan time: {datetime.now()}\n")

    all_alerts = []

    for ip in targets:
        # Check whitelist
        if db.is_whitelisted(ip):
            logger.info(f"[SKIP] {ip} is whitelisted")
            continue
        
        # Check blacklist
        if db.is_blacklisted(ip):
            blacklist = db.get_blacklist()
            bl_info = blacklist.get(ip, {})
            logger.warning(f"[BLACKLISTED] {ip} is on blacklist ({bl_info.get('severity', 'UNKNOWN')}): {bl_info.get('reason', '')}")
            continue

        open_ports = scan_ports(ip)
        alerts = analyze_ports(ip, open_ports)
        
        # Grab banners for open ports
        banner_data = {}
        for port in open_ports:
            banner = grab_banner(ip, port)
            if banner:
                banner_data[port] = banner
        
        # Save results to database
        db.save_scan(ip, open_ports, alerts, banner_data)
        all_alerts.extend(alerts)

    logger.info("\n[ ALERTS ]")
    if not all_alerts:
        logger.info("No high-risk exposed services detected ✔")
    else:
        for alert in all_alerts:
            logger.warning(
                f"[ALERT] {alert['ip']} exposes "
                f"{alert['service']} ({alert['port']}) → {alert['risk']} RISK"
            )
    
    # Print report
    logger.info("\n[ SCAN REPORT ]")
    report = db.generate_report()
    logger.info(f"Total scans: {report['total_scans']}")
    logger.info(f"Unique IPs scanned: {report['unique_ips_scanned']}")
    logger.info(f"Total alerts: {report['total_alerts']}")
    logger.info(f"Whitelisted IPs: {report['whitelisted_ips']}")
    logger.info(f"Blacklisted IPs: {report['blacklisted_ips']}")
    logger.info(f"Blacklist by severity:")
    for severity, count in report['blacklist_by_severity'].items():
        logger.info(f"  {severity}: {count}")


if __name__ == "__main__":
    main()