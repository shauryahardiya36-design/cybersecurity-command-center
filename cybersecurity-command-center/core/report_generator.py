import json
import os
import logging
from datetime import datetime
from core.database import ScanDatabase

logger = logging.getLogger(__name__)
db = ScanDatabase()

class ReportGenerator:
    """Generate comprehensive human-readable security reports."""
    
    def __init__(self):
        self.report_dir = "data/reports"
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_incident_report(self, ip, open_ports, alerts, banner_data, attack_type=None):
        """
        Generate comprehensive incident report for a detected threat.
        """
        timestamp = datetime.now()
        report = {
            "report_id": f"INC-{timestamp.strftime('%Y%m%d-%H%M%S')}",
            "timestamp": timestamp.isoformat(),
            "target_ip": ip,
            "incident_summary": self._generate_summary(ip, open_ports, alerts, attack_type),
            "threat_details": self._generate_threat_details(ip, open_ports, alerts, attack_type),
            "device_information": self._get_device_info(ip),
            "network_activity": self._get_network_activity(ip),
            "ports_accessed": self._analyze_ports(open_ports, banner_data),
            "banners_captured": banner_data or {},
            "response_actions": self._get_response_actions(ip),
            "severity_assessment": self._assess_severity(alerts),
            "recommendations": self._generate_recommendations(alerts, attack_type),
            "timeline": self._generate_timeline(ip, timestamp),
        }
        
        # Save report
        self._save_report(report)
        
        return report
    
    def _generate_summary(self, ip, open_ports, alerts, attack_type):
        """Generate human-readable summary."""
        alert_count = len(alerts)
        port_count = len(open_ports)
        
        if attack_type == "DNS_SPOOFING":
            summary = f"A DNS spoofing attack was detected from device {ip}. The attacker attempted to run an unauthorized DNS server on port 53, which could allow them to redirect network traffic and intercept sensitive data."
        elif attack_type == "ARP_SPOOFING":
            summary = f"An ARP spoofing attack was detected from device {ip}. The attacker changed their MAC address to impersonate a trusted device, attempting to intercept network traffic."
        elif attack_type == "PORT_SCANNING":
            summary = f"A port scanning attack was detected from device {ip}. The attacker probed {port_count} ports on your network, attempting to find vulnerabilities and gather information about your systems."
        elif attack_type == "DHCP_SPOOFING":
            summary = f"A DHCP spoofing attack was detected from device {ip}. The attacker attempted to run a rogue DHCP server to intercept and modify network configurations."
        else:
            summary = f"A security threat was detected from device {ip}. The device had {alert_count} high-risk services exposed across {port_count} open ports."
        
        return summary
    
    def _generate_threat_details(self, ip, open_ports, alerts, attack_type):
        """Generate detailed threat analysis."""
        details = {
            "attack_type": attack_type or "Unknown",
            "source_ip": ip,
            "ports_open": open_ports,
            "high_risk_alerts": [],
            "description": ""
        }
        
        for alert in alerts:
            if alert['risk'] in ("HIGH", "CRITICAL"):
                details['high_risk_alerts'].append({
                    "port": alert['port'],
                    "service": alert['service'],
                    "risk_level": alert['risk'],
                    "description": self._get_service_risk_description(alert['service'], alert['risk'])
                })
        
        if attack_type == "DNS_SPOOFING":
            details['description'] = (
                "DNS Spoofing is a critical attack where the attacker runs an unauthorized DNS server. "
                "This allows them to intercept DNS queries and redirect users to malicious sites, enabling phishing, "
                "malware distribution, and man-in-the-middle attacks."
            )
        elif attack_type == "ARP_SPOOFING":
            details['description'] = (
                "ARP Spoofing (Address Resolution Protocol) is a network attack where the attacker associates their "
                "MAC address with the IP address of a legitimate device (usually the gateway). This allows them to "
                "intercept all traffic intended for that device."
            )
        elif attack_type == "PORT_SCANNING":
            details['description'] = (
                "Port Scanning is reconnaissance activity where an attacker probes multiple ports to identify which "
                "services are running and potentially vulnerable. This is often a precursor to a more targeted attack."
            )
        elif attack_type == "DHCP_SPOOFING":
            details['description'] = (
                "DHCP Spoofing involves running a rogue DHCP server to assign malicious configurations to clients. "
                "This can redirect traffic through the attacker's machine or assign them as the default gateway."
            )
        
        return details
    
    def _get_device_info(self, ip):
        """Get information about the device."""
        whitelist = db.get_whitelist()
        blacklist = db.get_blacklist()
        
        device_info = {
            "ip_address": ip,
            "status": "Unknown",
            "first_seen": None,
            "last_scan": None,
            "scan_count": 0,
            "is_whitelisted": ip in whitelist,
            "is_blacklisted": ip in blacklist,
            "notes": ""
        }
        
        if ip in whitelist:
            device_info['status'] = "Whitelisted (Trusted)"
            device_info['notes'] = whitelist[ip].get('reason', '')
        elif ip in blacklist:
            device_info['status'] = "Blacklisted (Threat)"
            device_info['notes'] = blacklist[ip].get('reason', '')
        else:
            device_info['status'] = "Unknown (Unrecognized Device)"
        
        # Get scan history
        history = db.get_scan_history(ip)
        if history:
            device_info['first_seen'] = history[0]['timestamp']
            device_info['last_scan'] = history[-1]['timestamp']
            device_info['scan_count'] = len(history)
        
        return device_info
    
    def _get_network_activity(self, ip):
        """Get network activity for this IP."""
        history = db.get_scan_history(ip)
        
        activity = {
            "total_scans": len(history),
            "ports_history": [],
            "alert_history": []
        }
        
        for scan in history:
            activity['ports_history'].append({
                "timestamp": scan['timestamp'],
                "open_ports": scan['open_ports']
            })
            activity['alert_history'].extend(scan['alerts'])
        
        return activity
    
    def _analyze_ports(self, open_ports, banner_data):
        """Analyze all open ports with details."""
        from core.port_scan import PORT_RISK
        
        port_analysis = []
        
        for port in open_ports:
            service, risk = PORT_RISK.get(port, ("Unknown Service", "UNKNOWN"))
            banner = banner_data.get(port, "No banner captured") if banner_data else "No banner"
            
            port_info = {
                "port_number": port,
                "service": service,
                "risk_level": risk,
                "banner": banner,
                "description": self._get_port_description(port, service)
            }
            
            port_analysis.append(port_info)
        
        return port_analysis
    
    def _get_port_description(self, port, service):
        """Get detailed description of what each port does."""
        descriptions = {
            21: "FTP (File Transfer Protocol) - Unencrypted file transfer. HIGH RISK.",
            22: "SSH (Secure Shell) - Remote command execution. Could indicate compromise if unauthorized.",
            23: "Telnet - Unencrypted remote access. EXTREMELY HIGH RISK and should not be used.",
            25: "SMTP (Simple Mail Transfer Protocol) - Email service. Could be used for spam.",
            53: "DNS (Domain Name System) - Converts domain names to IPs. Unauthorized DNS = spoofing risk.",
            80: "HTTP (Web Server) - Unencrypted web traffic. Could expose sensitive data.",
            110: "POP3 (Post Office Protocol) - Email retrieval. Could expose email credentials.",
            139: "NetBIOS - Windows network sharing. Can leak file system information.",
            143: "IMAP (Internet Message Access Protocol) - Email access. Could expose email.",
            443: "HTTPS (Secure Web) - Encrypted web traffic. Generally safe if legitimate.",
            445: "SMB (Server Message Block) - Windows file/printer sharing. CRITICAL RISK for exposure.",
            3389: "RDP (Remote Desktop Protocol) - Remote desktop access. CRITICAL RISK if exposed."
        }
        
        return descriptions.get(port, f"Port {port} ({service}) - Purpose unknown")
    
    def _get_service_risk_description(self, service, risk_level):
        """Get why a service is risky."""
        risk_reasons = {
            "FTP": "File transfer without encryption - credentials can be stolen",
            "SSH": "Remote shell access - could lead to full system compromise",
            "Telnet": "Unencrypted remote access - all traffic visible to attackers",
            "SMTP": "Email service - could be used for spam or reconnaissance",
            "DNS": "If unauthorized, enables DNS spoofing and traffic interception",
            "HTTP": "Unencrypted web traffic - credentials and data exposed",
            "POP3": "Unencrypted email - credentials stolen, emails intercepted",
            "NetBIOS": "Windows file sharing - exposes file system structure",
            "IMAP": "Unencrypted email access - full email compromise possible",
            "HTTPS": "Encrypted web - generally safe if certificate is valid",
            "SMB": "File sharing - enables lateral movement and data theft",
            "RDP": "Remote desktop - full system access if credentials compromised"
        }
        
        return risk_reasons.get(service, f"{service} exposure detected")
    
    def _get_response_actions(self, ip):
        """Get what actions were taken."""
        blacklist = db.get_blacklist()
        
        actions = {
            "automatic_actions": [],
            "manual_review_required": False
        }
        
        if ip in blacklist:
            bl_entry = blacklist[ip]
            actions['automatic_actions'].append({
                "action": "IP Blacklisted",
                "timestamp": bl_entry.get('added_at'),
                "reason": bl_entry.get('reason'),
                "severity": bl_entry.get('severity')
            })
            actions['automatic_actions'].append({
                "action": "Firewall Rule Applied",
                "description": "Device was blocked at the network firewall level",
                "result": "Device can no longer communicate with your network"
            })
        else:
            actions['manual_review_required'] = True
        
        return actions
    
    def _assess_severity(self, alerts):
        """Assess overall severity of the incident."""
        if not alerts:
            return {"level": "LOW", "score": 1}
        
        critical_count = sum(1 for a in alerts if a.get('risk') == 'CRITICAL')
        high_count = sum(1 for a in alerts if a.get('risk') == 'HIGH')
        medium_count = sum(1 for a in alerts if a.get('risk') == 'MEDIUM')
        
        if critical_count > 0:
            severity = "CRITICAL"
            score = 10
            description = "Immediate action required. This is a severe threat to network security."
        elif high_count >= 2:
            severity = "HIGH"
            score = 8
            description = "Urgent attention needed. This device poses a significant security risk."
        elif high_count == 1:
            severity = "MEDIUM-HIGH"
            score = 6
            description = "Important. This device should be isolated and investigated."
        elif medium_count > 0:
            severity = "MEDIUM"
            score = 4
            description = "Notable. Monitor this device and consider isolation."
        else:
            severity = "LOW"
            score = 2
            description = "Minor concern. Continue monitoring."
        
        return {
            "level": severity,
            "score": score,
            "critical_alerts": critical_count,
            "high_alerts": high_count,
            "medium_alerts": medium_count,
            "description": description
        }
    
    def _generate_recommendations(self, alerts, attack_type):
        """Generate security recommendations."""
        recommendations = []
        
        if attack_type == "DNS_SPOOFING":
            recommendations = [
                "✓ IMMEDIATE: Block this device from the network",
                "✓ Verify your DNS settings (192.168.1.1 should be primary DNS)",
                "✓ Check if any other devices are set to use unusual DNS servers",
                "✓ Review router logs for unauthorized DHCP assignments",
                "✓ Consider changing your WiFi password",
                "✓ Update your router firmware to latest version"
            ]
        elif attack_type == "ARP_SPOOFING":
            recommendations = [
                "✓ IMMEDIATE: Isolate and remove the device from the network",
                "✓ Check for any unauthorized configuration changes",
                "✓ Monitor other devices for suspicious activity",
                "✓ Enable ARP binding on your router (if available)",
                "✓ Consider implementing Dynamic ARP Inspection (DAI)",
                "✓ Review network access logs for data exfiltration"
            ]
        elif attack_type == "PORT_SCANNING":
            recommendations = [
                "✓ IMMEDIATE: Block this device at the firewall",
                "✓ Determine if device is compromised (ransomware, botnet)",
                "✓ Isolate device and scan for malware",
                "✓ Review what data this device has accessed",
                "✓ Consider factory reset or complete OS reinstall",
                "✓ Enable intrusion detection on network perimeter"
            ]
        elif attack_type == "DHCP_SPOOFING":
            recommendations = [
                "✓ IMMEDIATE: Block this device from network",
                "✓ Check if any clients received unauthorized configurations",
                "✓ Restart your router to refresh DHCP leases",
                "✓ Enable DHCP snooping on your switch (if available)",
                "✓ Set DHCP reservation for critical devices",
                "✓ Review DHCP logs for suspicious activity"
            ]
        else:
            recommendations = [
                "✓ Block suspicious device from network",
                "✓ Investigate the source of the device",
                "✓ Review network access logs",
                "✓ Update firewall rules",
                "✓ Monitor for similar activity patterns",
                "✓ Consider security assessment of network"
            ]
        
        # Add general recommendations
        recommendations.extend([
            "✓ Enable network logging for future incidents",
            "✓ Schedule regular security scans",
            "✓ Keep all devices updated with latest security patches",
            "✓ Use strong WiFi password and WPA3 encryption if available"
        ])
        
        return recommendations
    
    def _generate_timeline(self, ip, incident_time):
        """Generate timeline of events."""
        history = db.get_scan_history(ip)
        
        timeline = []
        
        # Add historical scans
        for scan in history[:-1]:  # All but last scan
            timeline.append({
                "timestamp": scan['timestamp'],
                "event": f"Port scan detected: {len(scan['open_ports'])} ports open",
                "type": "OBSERVATION"
            })
        
        # Add current incident
        timeline.append({
            "timestamp": incident_time.isoformat(),
            "event": "Threat detected and blocked",
            "type": "INCIDENT"
        })
        
        return timeline
    
    def _save_report(self, report):
        """Save report to file."""
        filename = f"{self.report_dir}/report_{report['report_id']}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved: {filename}")
        
        # Also create human-readable text version
        self._create_text_report(report)
    
    def _create_text_report(self, report):
        """Create human-readable text version of report."""
        filename = f"{self.report_dir}/report_{report['report_id']}.txt"
        
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("CYBERSECURITY INCIDENT REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            # Header
            f.write(f"Report ID: {report['report_id']}\n")
            f.write(f"Timestamp: {report['timestamp']}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Summary
            f.write("-" * 80 + "\n")
            f.write("INCIDENT SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(f"{report['incident_summary']}\n\n")
            
            # Severity
            severity = report['severity_assessment']
            f.write(f"Severity Level: {severity['level']} (Score: {severity['score']}/10)\n")
            f.write(f"Description: {severity['description']}\n\n")
            
            # Device Information
            f.write("-" * 80 + "\n")
            f.write("DEVICE INFORMATION\n")
            f.write("-" * 80 + "\n")
            device = report['device_information']
            f.write(f"IP Address: {device['ip_address']}\n")
            f.write(f"Status: {device['status']}\n")
            f.write(f"Whitelisted: {'Yes' if device['is_whitelisted'] else 'No'}\n")
            f.write(f"Blacklisted: {'Yes' if device['is_blacklisted'] else 'No'}\n")
            f.write(f"First Seen: {device['first_seen'] or 'N/A'}\n")
            f.write(f"Last Scan: {device['last_scan'] or 'N/A'}\n")
            f.write(f"Scan Count: {device['scan_count']}\n")
            if device['notes']:
                f.write(f"Notes: {device['notes']}\n")
            f.write("\n")
            
            # Threat Details
            f.write("-" * 80 + "\n")
            f.write("THREAT ANALYSIS\n")
            f.write("-" * 80 + "\n")
            threat = report['threat_details']
            f.write(f"Attack Type: {threat['attack_type']}\n")
            f.write(f"Source IP: {threat['source_ip']}\n")
            f.write(f"Description: {threat['description']}\n\n")
            
            f.write(f"High-Risk Alerts: {len(threat['high_risk_alerts'])}\n")
            for alert in threat['high_risk_alerts']:
                f.write(f"  • Port {alert['port']} ({alert['service']}) - {alert['risk_level']}\n")
                f.write(f"    {alert['description']}\n")
            f.write("\n")
            
            # Ports Accessed
            f.write("-" * 80 + "\n")
            f.write("PORTS ACCESSED\n")
            f.write("-" * 80 + "\n")
            for port_info in report['ports_accessed']:
                f.write(f"Port {port_info['port_number']}: {port_info['service']} ({port_info['risk_level']})\n")
                f.write(f"  {port_info['description']}\n")
                if port_info['banner'] and port_info['banner'] != "No banner":
                    f.write(f"  Banner: {port_info['banner']}\n")
                f.write("\n")
            
            # Response Actions
            f.write("-" * 80 + "\n")
            f.write("RESPONSE ACTIONS TAKEN\n")
            f.write("-" * 80 + "\n")
            actions = report['response_actions']
            if actions['automatic_actions']:
                for action in actions['automatic_actions']:
                    f.write(f"✓ {action.get('action')}\n")
                    if 'description' in action:
                        f.write(f"  {action['description']}\n")
                    if 'result' in action:
                        f.write(f"  Result: {action['result']}\n")
            if actions['manual_review_required']:
                f.write("⚠ MANUAL REVIEW REQUIRED\n")
            f.write("\n")
            
            # Recommendations
            f.write("-" * 80 + "\n")
            f.write("RECOMMENDATIONS\n")
            f.write("-" * 80 + "\n")
            for rec in report['recommendations']:
                f.write(f"{rec}\n")
            f.write("\n")
            
            f.write("=" * 80 + "\n")
        
        logger.info(f"Text report saved: {filename}")


report_generator = ReportGenerator()