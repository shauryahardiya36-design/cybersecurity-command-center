# Cybersecurity Command Center (CCC)

A comprehensive Python-based network security monitoring and threat detection system for local area networks. This tool provides real-time network scanning, threat detection, automated response capabilities, and detailed security reporting.

This tool is made for security purposes only. Misuse of this tool could be dangerous and potentially lead to legal consequences.

Project Created By: Shaurya Hardiya

ALL RIGHTS RESERVED.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Installation & Setup](#installation--setup)
- [Core Components](#core-components)
- [CLI Commands](#cli-commands)
- [Usage Workflows](#usage-workflows)
- [Threat Detection System](#threat-detection-system)
- [Scheduled Monitoring](#scheduled-monitoring)
- [Database Structure](#database-structure)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

The Cybersecurity Command Center is a network security orchestration tool designed to provide comprehensive visibility and control over local network infrastructure. It combines automated network reconnaissance, intelligent threat detection, and incident response capabilities into a unified platform.

**Primary Use Cases:**
- Network perimeter monitoring and continuous surveillance
- Detection of network-based attacks (DNS spoofing, ARP spoofing, DHCP spoofing)
- Device inventory and OS fingerprinting
- Automated threat response and IP blocking
- Security incident reporting and forensics
- Network change tracking and alerting

**Target Environment:** Local Area Networks (LANs) with typical home/small office setups

---

## ✨ Key Features

### 🔍 Network Reconnaissance
- **Automated Subnet Discovery**: Automatically identifies local network subnet (CIDR notation)
- **Active Host Detection**: Performs ICMP ping sweeps to identify live devices
- **Port Scanning**: Concurrent port scanning of common service ports with configurable timeouts
- **Service Identification**: Maps ports to services and risk levels with accuracy
- **Banner Grabbing**: Retrieves service banners for version detection and vulnerability identification
- **OS Fingerprinting**: Identifies operating systems based on port signatures
- **Device Classification**: Categorizes devices (NAS, Printers, IoT, Servers, etc.) from banner analysis

### 🛡️ Threat Detection
- **DNS Spoofing Detection**: Identifies unauthorized DNS servers running on unknown devices
- **ARP Spoofing Detection**: Monitors MAC address changes to detect address resolution protocol attacks
- **DHCP Spoofing Detection**: Detects rogue DHCP servers attempting to distribute malicious configurations
- **Port Activity Monitoring**: Identifies suspicious port combinations indicating active attacks
- **Device Change Tracking**: Alerts on new devices, disappearing devices, and port state changes
- **High-Risk Service Detection**: Flags dangerous services (FTP, Telnet, SMB, RDP) with severity levels

### 📊 Device Management
- **Whitelisting System**: Mark trusted devices to reduce false positives
- **Blacklisting System**: Track known malicious or suspicious IPs with severity ratings
- **Device Baseline Tracking**: Maintains historical snapshot of discovered devices and ports
- **Change Alerting**: Generates alerts for device and port state changes since last scan
- **Persistent Device History**: JSON-based storage of all discovered devices and configurations

### ⚡ Automated Response
- **Network Blocking**: Cross-platform IP blocking (macOS pfctl, Linux iptables, Windows netsh)
- **Firewall Integration**: Adds permanent firewall rules to block malicious IPs
- **Conditional Threat Response**: Automatic blocking for high-severity threats when enabled
- **Unblock Management**: Safe removal of firewall rules for false positives
- **Response Logging**: Detailed audit trail of all blocking actions

### 📋 Reporting & Forensics
- **Incident Report Generation**: Comprehensive multi-section incident reports
- **Threat Analysis**: Detailed threat descriptions and attack methodologies
- **Severity Assessment**: Risk scoring and severity classification
- **Timeline Reconstruction**: Chronological timeline of network events
- **Response Recommendations**: Automated suggestions for remediation
- **Report Persistence**: Timestamped reports stored for historical analysis

### 🗄️ Data Management
- **Scan Result History**: Complete log of all network scans with timestamps
- **ARP Cache Tracking**: Historical MAC address associations for each IP
- **Whitelist/Blacklist Management**: Persistent lists with timestamps and reasoning
- **JSON Storage**: Human-readable JSON format for all data
- **Integrity Preservation**: Automatic file initialization and error handling

### ⏰ Scheduling & Automation
- **One-time Scans**: Manual execution of network scans on demand
- **Interval-based Scanning**: Configurable recurring scans (e.g., every 15-30 minutes)
- **Daily Scheduled Scans**: Time-based scheduling for deep scans
- **Background Processing**: Daemon mode for continuous monitoring
- **Startup Execution**: Immediate scan on application launch
- **Multiple Schedule Chains**: Support for concurrent interval, hourly, and daily schedules

### 🖥️ Command-Line Interface
- **Comprehensive CLI**: Complete command suite for all operations
- **Intuitive Subcommands**: Organized command structure for whitelist, blacklist, reports, wifi, scheduler
- **Status Checking**: Real-time visibility into current security state
- **Interactive Feedback**: Clear success/error messages with actionable guidance
- **Argument Validation**: Input validation and helpful error messages

---

## 🏗️ Architecture

### Directory Structure

```
cybersecurity-command-center/
├── ccc.py                          # Main orchestration entry point
├── cli.py                          # Command-line interface
├── run_scheduler.py                # Background scheduler runner
├── setup_continuous_monitoring.py  # Multi-schedule setup utility
├── whitelist_trusted_devices.py    # Interactive whitelist setup
│
├── core/                           # Core functionality modules
│   ├── __init__.py
│   ├── database.py                 # Persistent JSON data storage
│   ├── scheduler.py                # Scheduled task execution
│   ├── network_scan.py             # ICMP ping-based host discovery
│   ├── port_scan.py                # Concurrent port scanning engine
│   ├── subnet_discovery.py         # Local network detection
│   ├── banner_grab.py              # Service banner extraction
│   ├── device_tracker.py           # Device baseline comparison
│   ├── device_fingerprint.py       # OS and device type identification
│   ├── service_map.py              # Port-to-service mapping
│   ├── wifi_security.py            # WiFi attack detection (DNS, ARP, DHCP)
│   ├── network_blocker.py          # Cross-platform IP blocking
│   └── report_generator.py         # Incident report creation
│
├── data/                           # Data storage directory
│   ├── scan_results.json           # Historical scan data
│   ├── whitelist.json              # Trusted device list
│   ├── blacklist.json              # Malicious device list
│   ├── arp_cache.json              # MAC address tracking (auto-generated)
│   ├── suspicious_activity.json    # Threat data (auto-generated)
│   └── reports/                    # Generated incident reports
│
├── logs/                           # Application logs
│   ├── ccc.log                     # Main application log
│   └── scheduler.log               # Scheduler activity log
│
└── README.md                       # This file
```

### Data Flow

```
1. Subnet Discovery
   ↓
2. Network Scan (ICMP Ping)
   ↓
3. Port Scanning (Concurrent)
   ↓
4. Banner Grabbing & OS Fingerprinting
   ↓
5. Device Comparison & Change Detection
   ↓
6. Threat Detection (DNS, ARP, DHCP spoofing)
   ↓
7. Alert Generation & Optional Blocking
   ↓
8. Report Generation & Logging
```

### Concurrency Model

- **Port Scanning**: Uses `ThreadPoolExecutor` with configurable worker threads (default 10)
- **Timeout Handling**: Individual socket timeouts (0.5s) prevent hanging on unresponsive ports
- **Scheduler**: Background thread for continuous scanning without blocking main process

---

## 🚀 Installation & Setup

### Prerequisites

```
Python 3.7+
pip or conda for package management
macOS, Linux, or Windows (platform detection automatic)
sudo/admin privileges for network blocking (optional)
```

### Step 1: Clone/Download

```bash
cd cybersecurity-command-center
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

Or manually install required packages:

```bash
pip install schedule  # For task scheduling
```

### Step 3: Set Up Data Directories

```bash
mkdir -p data/reports logs
chmod 755 data logs
```

### Step 4: Initial Whitelist Setup

Mark your trusted devices to reduce false positives:

```bash
python3 whitelist_trusted_devices.py
```

This prompts you to enter trusted device IPs with descriptive reasons.

### Step 5: Verify Installation

```bash
python3 cli.py whitelist list
```

If successful, should display your whitelisted devices.

---

## 🔧 Core Components

### 1. **network_scan.py** - Host Discovery
**Purpose:** Identify active devices on the network via ICMP ping

**Key Functions:**
- `scan_network(ips)` - Pings multiple IPs and returns alive hosts
- Uses subprocess `ping` command with 1 packet, 100ms timeout
- Cross-platform compatible (uses different flags for macOS/Linux)

**Output:** List of IP addresses that respond to ping

**Example:**
```python
from core.subnet_discovery import get_local_subnet, generate_ips
from core.network_scan import scan_network

subnet = get_local_subnet()  # "192.168.1.0/24"
ips = generate_ips(subnet)
alive_devices = scan_network(ips)  # ["192.168.1.1", "192.168.1.5", ...]
```

---

### 2. **port_scan.py** - Service Detection
**Purpose:** Identify open ports and running services on discovered hosts

**Key Components:**

| Function | Purpose |
|----------|---------|
| `check_port(ip, port)` | Tests single port with TCP connection |
| `scan_ports(ip, ports)` | Concurrent scan of multiple ports |
| `is_valid_ip(ip)` | Validates IP address format |

**Port Configuration:**
```python
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
PORT_RISK = {
    21: ("FTP", "HIGH"),
    22: ("SSH", "MEDIUM"),
    445: ("SMB", "HIGH"),
    # ... etc
}
```

**Concurrency:** Default 10 worker threads, 0.5s timeout per port

**Output:** Sorted list of open ports

**Example:**
```python
from core.port_scan import scan_ports

ports = scan_ports("192.168.1.5")  # [22, 80, 443]
```

---

### 3. **banner_grab.py** - Service Identification
**Purpose:** Extract service banners for version detection

**Key Function:**
- `grab_banner(ip, port, timeout=2)` - Connects and retrieves service banner

**Capabilities:**
- HTTP/HTTPS special handling (sends HEAD request)
- Timeout handling for unresponsive services
- Error-safe decoding with `errors="ignore"`
- Returns first line of response

**Output:** Banner string or None

**Example:**
```python
from core.banner_grab import grab_banner

banner = grab_banner("192.168.1.5", 22)  # "SSH-2.0-OpenSSH_7.4"
```

---

### 4. **device_fingerprint.py** - OS Detection
**Purpose:** Identify operating system and device type

**Key Functions:**

| Method | Purpose |
|--------|---------|
| `identify_os(open_ports, banners)` | Guess OS from port signatures |
| `identify_device_type(banners)` | Classify device (NAS, Printer, IoT, Server) |

**OS Signatures:**
```python
"Windows": [135, 139, 445, 3389]      # RPC, NetBIOS, SMB, RDP
"Linux": [22, 80, 443, 3306]          # SSH, HTTP, HTTPS, MySQL
"macOS": [22, 80, 443, 5900]          # SSH, HTTP, HTTPS, VNC
"iOS/Android": [5353, 5900]           # mDNS, VNC
```

**Output:** OS name or device type string

**Example:**
```python
from core.device_fingerprint import DeviceFingerprinter

os_type = DeviceFingerprinter.identify_os([22, 80, 443], {})  # "Linux"
device = DeviceFingerprinter.identify_device_type({"22": "SSH-2.0-OpenSSH"})  # "Server"
```

---

### 5. **wifi_security.py** - Attack Detection
**Purpose:** Detect network attacks (DNS spoofing, ARP spoofing, DHCP spoofing)

**Key Methods:**

| Attack Type | Detection Method | Risk |
|------------|-----------------|------|
| **DNS Spoofing** | Detects unauthorized DNS on port 53 | CRITICAL |
| **ARP Spoofing** | Monitors MAC address changes for IPs | CRITICAL |
| **DHCP Spoofing** | Detects port 67/68 on untrusted devices | CRITICAL |
| **Port Combinations** | Flags suspicious port patterns | HIGH |

**Key Functions:**
```python
wifi_monitor = WiFiSecurityMonitor()

# DNS Spoofing
is_attack, msg = wifi_monitor.detect_dns_spoofing("192.168.1.10", 53)

# ARP Spoofing
is_attack, msg = wifi_monitor.detect_arp_spoofing("192.168.1.10", "aa:bb:cc:dd:ee:ff")

# Suspicious Ports
attacks = wifi_monitor.detect_suspicious_ports("192.168.1.10", [53, 5353])
```

**Output:** Boolean and descriptive message

---

### 6. **network_blocker.py** - Firewall Integration
**Purpose:** Block malicious IPs at the OS level

**Platform Support:**

| OS | Method | Command |
|---|--------|---------|
| **macOS** | pfctl | `pfctl -t blocklist -T add/delete <IP>` |
| **Linux** | iptables | `iptables -I INPUT/OUTPUT -s/-d <IP> -j DROP` |
| **Windows** | netsh | `netsh advfirewall firewall add rule` |

**Key Methods:**
```python
blocker = NetworkBlocker()

# Block an IP
blocker.block_ip("192.168.1.100")  # Returns True/False

# Unblock an IP
blocker.unblock_ip("192.168.1.100")
```

**Requirements:**
- Requires `sudo` on macOS/Linux
- Requires admin on Windows
- Changes are persistent across reboots

---

### 7. **device_tracker.py** - Change Detection
**Purpose:** Compare scans and detect network changes

**Key Functions:**

| Function | Purpose |
|----------|---------|
| `load_devices()` | Load previous scan baseline |
| `save_devices(devices)` | Save current scan as new baseline |
| `compare_devices(old, new)` | Generate alerts for changes |

**Alert Types:**
```
[NEW DEVICE] 192.168.1.50          # Previously unknown device appeared
[DEVICE LOST] 192.168.1.20         # Known device disappeared
[PORT OPENED] 192.168.1.30:8080    # New port opened on known device
[PORT CLOSED] 192.168.1.30:443     # Port closed on known device
```

**Example:**
```python
from core.device_tracker import load_devices, save_devices, compare_devices

old_devices = load_devices()
new_devices = {
    "192.168.1.1": [53, 80, 443],
    "192.168.1.5": [22, 80],
}
alerts = compare_devices(old_devices, new_devices)
save_devices(new_devices)
```

---

### 8. **database.py** - Data Persistence
**Purpose:** Centralized JSON-based data storage

**Key Methods:**

| Method | Purpose |
|--------|---------|
| `save_scan(ip, open_ports, alerts, banner_data)` | Store scan result |
| `get_scan_history(ip=None)` | Retrieve historical scans |
| `get_latest_scan(ip)` | Get most recent scan |
| `add_whitelist(ip, reason)` | Add trusted device |
| `remove_whitelist(ip)` | Remove from whitelist |
| `get_whitelist()` | Retrieve all trusted devices |
| `add_blacklist(ip, reason, severity)` | Add malicious device |
| `remove_blacklist(ip)` | Remove from blacklist |
| `get_blacklist()` | Retrieve all blacklisted devices |

**Data Format:**

**scan_results.json:**
```json
[
  {
    "timestamp": "2024-01-15T14:32:00",
    "ip": "192.168.1.50",
    "open_ports": [22, 80, 443],
    "alerts": ["[NEW DEVICE] 192.168.1.50"],
    "banner_data": {"22": "SSH-2.0-OpenSSH_8.0"}
  }
]
```

**whitelist.json:**
```json
{
  "192.168.1.1": {
    "reason": "Home router",
    "added_at": "2024-01-15T10:00:00"
  },
  "192.168.1.5": {
    "reason": "Main workstation",
    "added_at": "2024-01-15T10:05:00"
  }
}
```

**blacklist.json:**
```json
{
  "192.168.1.100": {
    "reason": "Ransomware detected",
    "severity": "CRITICAL",
    "added_at": "2024-01-15T14:30:00"
  }
}
```

---

### 9. **report_generator.py** - Incident Reports
**Purpose:** Generate comprehensive human-readable security reports

**Key Methods:**

| Method | Purpose |
|--------|---------|
| `generate_incident_report(...)` | Create full incident report |
| `_generate_summary(...)` | Human-readable incident summary |
| `_generate_threat_details(...)` | Detailed threat analysis |
| `_assess_severity(alerts)` | Risk scoring (LOW/MEDIUM/HIGH/CRITICAL) |
| `_generate_recommendations(...)` | Remediation suggestions |

**Report Sections:**
1. **Report Metadata** - ID, timestamp, target IP
2. **Incident Summary** - Plain English description of threat
3. **Threat Details** - Technical analysis with attack type
4. **Device Information** - OS, device type, services
5. **Network Activity** - Historical activity for IP
6. **Ports Accessed** - Detailed port analysis
7. **Banners Captured** - Service version information
8. **Response Actions** - Recommended or taken actions
9. **Severity Assessment** - Risk classification
10. **Recommendations** - Mitigation steps
11. **Timeline** - Chronological event sequence

**Example Report Output:**
```
Report ID: INC-20240115-143200
Timestamp: 2024-01-15T14:32:00.000000

INCIDENT SUMMARY
A DNS spoofing attack was detected from device 192.168.1.50. The attacker 
attempted to run an unauthorized DNS server on port 53, which could allow 
them to redirect network traffic and intercept sensitive data.

THREAT DETAILS
Attack Type: DNS_SPOOFING
Source IP: 192.168.1.50
Ports Open: [53, 5353]

HIGH RISK ALERTS:
- Port 53 (DNS) - HIGH
  Unauthorized DNS server on untrusted device

SEVERITY: CRITICAL
RECOMMENDATIONS:
1. Block IP immediately: 192.168.1.50
2. Disconnect suspicious device from network
3. Inspect connected device for compromise
4. Review DNS query logs for malicious redirects
```

---

### 10. **scheduler.py** - Task Automation
**Purpose:** Schedule and execute recurring network scans

**Key Methods:**

| Method | Purpose |
|--------|---------|
| `schedule_every_minutes(interval)` | Recurring interval-based scans |
| `schedule_every_hours(interval)` | Hourly recurring scans |
| `schedule_daily(hour, minute)` | Daily scheduled scan at time |
| `schedule_on_startup()` | Execute scan immediately |
| `start(background=True)` | Start scheduler (threaded or blocking) |

**Features:**
- Background thread execution
- Graceful error handling with detailed logging
- Supports multiple concurrent schedules
- Keyboard interrupt handling

**Example:**
```python
from core.scheduler import scheduler

# Setup multiple schedules
scheduler.schedule_on_startup()
scheduler.schedule_every_minutes(15)
scheduler.schedule_every_hours(2)
scheduler.schedule_daily(hour=2, minute=0)

# Start scheduler
scheduler.start(background=True)  # Run in background
# or
scheduler.start(background=False) # Block until Ctrl+C
```

---

## 💻 CLI Commands

The command-line interface provides complete control over the system. All commands follow the format:

```bash
python3 cli.py <command> <subcommand> [options]
```

### **Whitelist Commands**

Manage trusted devices to reduce false positives.

```bash
# Add device to whitelist
python3 cli.py whitelist add 192.168.1.1 --reason "Home router"

# List all whitelisted devices
python3 cli.py whitelist list

# Remove device from whitelist
python3 cli.py whitelist remove 192.168.1.1
```

**Output Example:**
```
[ WHITELIST ]

  192.168.1.1
    Reason: Home router
    Added: 2024-01-15T10:00:00

  192.168.1.5
    Reason: Main workstation
    Added: 2024-01-15T10:05:00
```

---

### **Blacklist Commands**

Track and manage known malicious devices.

```bash
# Add device to blacklist with severity
python3 cli.py blacklist add 192.168.1.100 --reason "Ransomware detected" --severity CRITICAL

# List all blacklisted devices
python3 cli.py blacklist list

# Remove from blacklist
python3 cli.py blacklist remove 192.168.1.100
```

**Severity Levels:** LOW, MEDIUM, HIGH, CRITICAL

**Output Example:**
```
[ BLACKLIST ]

  192.168.1.100 [CRITICAL]
    Reason: Ransomware detected
    Added: 2024-01-15T14:30:00

  192.168.1.200 [HIGH]
    Reason: Port scanning detected
    Added: 2024-01-14T09:15:00
```

---

### **Report Commands**

View and manage generated incident reports.

```bash
# List all reports
python3 cli.py report list

# View specific report
python3 cli.py report view INC-20240115-143200
```

**Output Example:**
```
[ REPORTS ]

  INC-20240115-143200
    Timestamp: 2024-01-15 14:32:00
    Target: 192.168.1.50
    Type: DNS_SPOOFING
    Severity: CRITICAL

  INC-20240114-021500
    Timestamp: 2024-01-14 02:15:00
    Target: 192.168.1.75
    Type: ARP_SPOOFING
    Severity: HIGH
```

---

### **WiFi Security Commands**

Monitor and manage WiFi security threats.

```bash
# List currently blocked IPs
python3 cli.py wifi blocked

# View detected threats
python3 cli.py wifi threats

# Unblock an IP (if false positive)
python3 cli.py wifi unblock 192.168.1.100
```

**Output Example:**
```
[ CURRENTLY BLOCKED ]

  192.168.1.100
    Reason: DNS spoofing detected
    Blocked at: 2024-01-15T14:32:00

[ DETECTED THREATS ]

  192.168.1.50
    Type: DNS_SPOOFING
    Risk: CRITICAL
    Status: BLOCKED
    Port: 53
```

---

### **Scheduler Commands**

Manage automated scanning schedules.

```bash
# Start scheduler with multiple schedules
python3 cli.py scheduler start --now --interval 15

# Add daily scan
python3 cli.py scheduler add-daily --hour 2 --minute 0

# Add hourly scan
python3 cli.py scheduler add-hourly --interval 1

# Add minute-based scan
python3 cli.py scheduler add-minutes --interval 30

# Check scheduler status
python3 cli.py scheduler status

# Stop scheduler
python3 cli.py scheduler stop
```

---

## 📖 Usage Workflows

### **Workflow 1: Initial Network Setup**

Step-by-step guide for first-time setup.

```bash
# 1. Setup whitelist with trusted devices
python3 whitelist_trusted_devices.py
# Follow prompts to add home router, workstations, printers, etc.

# 2. Run initial scan (identify all devices)
python3 -c "from core.port_scan import main; main()"

# 3. Review scan results
python3 cli.py report list

# 4. Verify no false alerts
python3 cli.py whitelist list
# If new trusted device found, add it:
python3 cli.py whitelist add 192.168.1.30 --reason "Guest laptop"

# 5. Setup continuous monitoring
python3 setup_continuous_monitoring.py
```

---

### **Workflow 2: Quick Threat Investigation**

When you suspect a security threat.

```bash
# 1. Run immediate scan
python3 -c "from core.port_scan import main; main()"

# 2. Check recent reports
python3 cli.py report list

# 3. View detailed threat report
python3 cli.py report view <REPORT_ID>

# 4. Check if device is already flagged
python3 cli.py blacklist list
python3 cli.py wifi threats

# 5. If legitimate threat found:
python3 cli.py blacklist add 192.168.1.XX --reason "Explanation" --severity CRITICAL

# 6. If false positive:
python3 cli.py whitelist add 192.168.1.XX --reason "Reason"
```

---

### **Workflow 3: Active Threat Response**

Automatic response when threat is detected.

```bash
# 1. Identify malicious IP
python3 cli.py wifi threats

# 2. Review threat details
python3 cli.py report view <REPORT_ID>

# 3. Block the IP (requires sudo)
sudo python3 -c "from core.network_blocker import network_blocker; network_blocker.block_ip('192.168.1.100')"

# 4. Verify block is active
python3 cli.py wifi blocked

# 5. Log incident for reference
python3 cli.py blacklist add 192.168.1.100 --reason "DNS spoofing attack detected" --severity CRITICAL

# 6. Keep device blocked (firewall rule is permanent)
```

---

### **Workflow 4: Continuous Monitoring Setup**

Configure system for 24/7 monitoring.

```bash
# 1. Setup initial whitelist
python3 whitelist_trusted_devices.py

# 2. Configure multi-schedule monitoring
python3 setup_continuous_monitoring.py

# 3. Verify schedules are active
python3 cli.py scheduler status

# 4. Check logs for activity
tail -f logs/scheduler.log

# 5. Review reports periodically
python3 cli.py report list
python3 cli.py report view <REPORT_ID>
```

---

### **Workflow 5: False Positive Recovery**

When a legitimate device is mistakenly blocked.

```bash
# 1. Identify blocked IP
python3 cli.py wifi blocked

# 2. Unblock the IP
python3 cli.py wifi unblock 192.168.1.XX

# 3. Add to whitelist (prevent future blocks)
python3 cli.py whitelist add 192.168.1.XX --reason "Legitimate device - false positive"

# 4. Remove from blacklist if present
python3 cli.py blacklist remove 192.168.1.XX

# 5. Verify normal operation
python3 cli.py whitelist list
python3 cli.py wifi blocked
```

---

## 🚨 Threat Detection System

### **DNS Spoofing Attack**

**What it is:**
A network attack where unauthorized DNS server is running on a device that shouldn't have DNS.

**How it works:**
1. Attacker runs DNS server on port 53
2. Attacker's device is not on whitelist
3. System flags as unauthorized DNS
4. Can redirect all DNS queries to malicious server

**Detection:**
```python
wifi_monitor.detect_dns_spoofing(ip, port=53)
```

**Indicators:**
- Port 53 (DNS) on untrusted device
- mDNS (port 5353) running simultaneously
- Device not in whitelist

**Severity:** 🔴 **CRITICAL**

**Response:**
```bash
python3 cli.py blacklist add <IP> --severity CRITICAL
sudo python3 -c "from core.network_blocker import network_blocker; network_blocker.block_ip('<IP>')"
```

---

### **ARP Spoofing Attack**

**What it is:**
Address Resolution Protocol attack where attacker changes their MAC address to impersonate another device.

**How it works:**
1. Attacker sends ARP responses with their MAC for legitimate IP
2. Victims send traffic to attacker instead of real device
3. Attacker can intercept or modify traffic
4. System detects MAC address change for same IP

**Detection:**
```python
wifi_monitor.detect_arp_spoofing(ip, mac_address)
```

**Indicators:**
- MAC address changes for same IP
- Alerts in: `data/arp_cache.json`
- Different MAC in ARP table than stored

**Severity:** 🔴 **CRITICAL**

**Response:**
```bash
python3 cli.py blacklist add <IP> --severity CRITICAL
```

---

### **DHCP Spoofing Attack**

**What it is:**
Rogue DHCP server distributing malicious network configurations.

**How it works:**
1. Attacker runs DHCP server (ports 67/68)
2. Clients request network configuration
3. Rogue server assigns attacker as gateway/DNS
4. All traffic routed through attacker

**Detection:**
- Ports 67/68 (DHCP) on untrusted device
- Combination with DNS spoofing

**Severity:** 🔴 **CRITICAL**

---

### **Suspicious Port Combinations**

**What it is:**
Multiple attack vectors running simultaneously on same device.

**Examples:**
```python
(53, 5353)      # DNS + mDNS = DNS hijacking
(67, 68)        # DHCP spoofing
(443, 8443)     # HTTPS duplication = man-in-the-middle
```

**Severity:** 🟠 **HIGH**

---

### **Device Change Alerts**

**What it is:**
Unexpected changes in network topology or device state.

**Alert Types:**

| Alert | Meaning | Risk |
|-------|---------|------|
| `[NEW DEVICE]` | Unfamiliar IP appeared | MEDIUM |
| `[DEVICE LOST]` | Known device disappeared | LOW |
| `[PORT OPENED]` | New service on device | VARIES |
| `[PORT CLOSED]` | Service stopped | LOW |

---

## ⏰ Scheduled Monitoring

### **Setup Continuous Monitoring**

```bash
python3 setup_continuous_monitoring.py
```

This configures:
- **Immediate Scan**: On startup
- **Quick Scans**: Every 15 minutes (lightweight)
- **Full Scans**: Every 2 hours
- **Deep Scans**: Daily at 2:00 AM

### **Manual Scheduler Control**

```bash
# Start background scheduler
python3 run_scheduler.py

# In another terminal, configure schedules
python3 cli.py scheduler add-minutes --interval 15
python3 cli.py scheduler add-daily --hour 2 --minute 0

# Check status
python3 cli.py scheduler status
```

### **Log File Monitoring**

```bash
# Watch scheduler logs in real-time
tail -f logs/scheduler.log

# Search for specific events
grep "CRITICAL" logs/scheduler.log
grep "threat" logs/ccc.log
```

---

## 🗄️ Database Structure

### **File Locations**

```
data/
├── scan_results.json       # All historical scans
├── whitelist.json          # Trusted devices
├── blacklist.json          # Malicious devices
├── arp_cache.json          # MAC address history (auto-generated)
├── suspicious_activity.json # Threat tracking (auto-generated)
└── reports/
    ├── report_INC-20240115-143200.txt
    └── report_INC-20240114-021500.txt
```

### **Accessing Raw Data**

```bash
# View scan history
cat data/scan_results.json | jq '.'

# Filter scans for specific IP
cat data/scan_results.json | jq '.[] | select(.ip=="192.168.1.50")'

# View whitelist
cat data/whitelist.json

# View blacklist
cat data/blacklist.json

# View ARP cache
cat data/arp_cache.json

# List reports
ls -la data/reports/
```

### **Data Backup**

```bash
# Backup all data
cp -r data/ data_backup_$(date +%Y%m%d_%H%M%S)

# Backup logs
cp -r logs/ logs_backup_$(date +%Y%m%d_%H%M%S)

# Full system backup
tar -czf ccc_backup_$(date +%Y%m%d_%H%M%S).tar.gz data/ logs/
```

---

## 🔒 Security Considerations

### **Privilege Requirements**

| Operation | Privilege Level | Command |
|-----------|-----------------|---------|
| Network scanning (ICMP ping) | User | `python3 ccc.py` |
| Port scanning | User | `python3 -c "from core.port_scan import main; main()"` |
| Banner grabbing | User | Included in port_scan |
| Automatic threat blocking | **Admin/Sudo** | `sudo python3 ccc.py` |
| Firewall rule management | **Admin/Sudo** | `sudo python3 cli.py` |

### **Network Impact**

- **ICMP Ping**: Minimal impact, single packet per host
- **Port Scanning**: 0.5s timeout per port, concurrent with 10 workers
- **Banner Grabbing**: TCP connections only to open ports
- **Load**: Typically <5% CPU, <10MB memory

### **Data Privacy**

- All data stored locally in `data/` directory
- No external API calls or cloud uploads
- Sensitive data (IP addresses, services) not encrypted at rest
- Log files contain detailed network information

### **Protection Against Script Abuse**

```bash
# Use rate limiting for scanning
# Modify TIMEOUT in core/port_scan.py to increase (slower, safer)

# Only run with sudo when absolutely necessary
# Avoid blocking trusted devices

# Maintain whitelist to prevent false positives
python3 cli.py whitelist list

# Regular review of blacklist
python3 cli.py blacklist list
```

### **Firewall Rule Management**

**Important:** Firewall rules are **permanent** across reboots

```bash
# macOS - view pfctl rules
sudo pfctl -t blocklist -T show

# Linux - view iptables rules
sudo iptables -L -v

# Windows - view firewall rules
netsh advfirewall firewall show rule name all
```

---

## 🛠️ Troubleshooting

### **Issue: "Permission denied" when blocking IPs**

**Cause:** Network blocking requires admin/sudo privileges

**Solution:**
```bash
# Run with sudo
sudo python3 cli.py wifi unblock 192.168.1.100

# Or use sudo for blocking operations
sudo python3 -c "from core.network_blocker import network_blocker; network_blocker.block_ip('192.168.1.100')"
```

---

### **Issue: No devices detected in scan**

**Cause:** 
- Devices are offline
- Network configuration issue
- Firewall blocking ICMP

**Debug:**
```bash
# Test connectivity to gateway
ping -c 1 $(python3 -c "from core.subnet_discovery import get_local_ip; print(get_local_ip())")

# Manual IP test
ping -c 1 192.168.1.1

# Check detected subnet
python3 -c "from core.subnet_discovery import get_local_subnet; print(get_local_subnet())"

# List all generated IPs
python3 -c "from core.subnet_discovery import get_local_subnet, generate_ips; ips = generate_ips(get_local_subnet()); print(f'Generated {len(ips)} IPs')"
```

---

### **Issue: Port scanning is slow**

**Cause:** 
- Timeout too high
- Too few worker threads
- Network latency

**Solution:**
```bash
# Reduce timeout in core/port_scan.py
TIMEOUT = 0.2  # instead of 0.5

# Increase worker threads
MAX_WORKERS = 20  # instead of 10

# Reduce port list
COMMON_PORTS = [22, 80, 443, 445]  # instead of all ports
```

---

### **Issue: False positives - legitimate devices flagged as threats**

**Solution:** Build comprehensive whitelist
```bash
# Add all your devices to whitelist
python3 cli.py whitelist add 192.168.1.1 --reason "Router"
python3 cli.py whitelist add 192.168.1.5 --reason "Primary workstation"
python3 cli.py whitelist add 192.168.1.10 --reason "Smart TV"

# View current whitelist
python3 cli.py whitelist list

# If device is incorrectly flagged, add it
python3 cli.py whitelist add 192.168.1.XX --reason "Reason for false positive"
```

---

### **Issue: Scheduler not running scans**

**Debug:**
```bash
# Check if scheduler is running
ps aux | grep scheduler

# View scheduler logs
tail -f logs/scheduler.log

# Test manual scan
python3 -c "from core.port_scan import main; main()"

# Restart scheduler
pkill -f scheduler
python3 run_scheduler.py
```

---

### **Issue: Too many files in reports directory**

**Cleanup:**
```bash
# Archive old reports
mkdir reports_archive_$(date +%Y%m%d)
mv data/reports/* reports_archive_$(date +%Y%m%d)/

# Or delete reports older than 30 days
find data/reports -mtime +30 -delete
```

---

### **Issue: Database file corruption**

**Recovery:**
```bash
# Reset databases to empty state
python3 -c "from core.database import ScanDatabase; db = ScanDatabase(); print('Database reinitialized')"

# Restore from backup (if available)
cp data_backup_YYYYMMDD_HHMMSS/* data/

# Manual data recovery
cat data/scan_results.json | jq '.' > data/scan_results_recovered.json
```

---

## 📝 Advanced Usage

### **Custom Port Lists**

```bash
# Modify core/port_scan.py
COMMON_PORTS = [21, 22, 80, 443, 8080, 8443, 3389, 5900]
```

### **Extended Timeout**

```bash
# For slow networks, increase timeout in core/port_scan.py
TIMEOUT = 2.0  # More patient, slower scans
```

### **Network Blocking Dry Run**

```python
# Test without actually blocking
from core.network_blocker import network_blocker

# Don't run block_ip(), just log the action
print(f"Would block: 192.168.1.100")
```

### **Custom Report Format**

Edit `core/report_generator.py` to customize report sections, formatting, or recommendations.

---

## 📊 Performance Metrics

### **Typical Scan Performance**

| Operation | Time | Notes |
|-----------|------|-------|
| Subnet discovery | <1s | Automatic IP calculation |
| Network scan (20 hosts) | 5-10s | ICMP ping, 1 packet each |
| Port scan (20 hosts × 12 ports) | 20-30s | Concurrent with 10 workers |
| Banner grabbing (20 services) | 10-20s | Timeout handling included |
| Full scan cycle | 40-60s | Complete reconnaissance |
| Report generation | 1-2s | JSON serialization |

### **Resource Usage**

| Metric | Typical | Peak |
|--------|---------|------|
| CPU | <5% | 15% (port scanning) |
| Memory | 20MB | 50MB (concurrent threads) |
| Disk (per scan) | 10KB | 50KB (large scan) |
| Network | <1Mbps | 5Mbps (port scanning) |

---

## 🤝 Contributing

To extend or modify the system:

1. **Add new threat detection**: Edit `core/wifi_security.py`
2. **Custom reports**: Modify `core/report_generator.py`
3. **Database storage**: Extend `core/database.py`
4. **Additional checks**: Create new module in `core/`

---

## 📄 License

This project is provided as-is for educational and personal security use.

---

## 🆘 Support

For issues or questions:

1. Check troubleshooting section above
2. Review log files: `tail -f logs/ccc.log`
3. Test individual components manually
4. Check file permissions and sudo access

---

## ⚠️ Disclaimer

**Security Warning:**
- This tool should only be used on networks you own or have explicit permission to monitor
- Unauthorized network scanning may be illegal in your jurisdiction
- Always maintain comprehensive whitelists to prevent false positives
- Test in controlled environments before production use
- Author assumes no responsibility for misuse or damage

---

**Last Updated:** January 2024  
**Version:** 1.0  
**Python:** 3.7+  
**Status:** Active Development

---
## Author & Credits
* **Lead Developer / Sole Creator:** Shaurya Hardiya
* This project was designed, coded, and maintained entirely by me. No external co-founders or co-developers were involved in the creation of this codebase.
