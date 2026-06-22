# cybersecurity-command-center
# Cybersecurity Command Center (CCC)

A modular, stateful Network Security Monitor and Intrusion Detection tool written in Python. CCC is designed to discover active assets on a local subnet, map open ports, grab low-level service banners, and enforce network policy via whitelisting and blacklisting operations.

The architecture establishes a known baseline of your network and triggers active warnings or mitigation protocols when unauthorized anomalies or high-risk exposures are detected.

---

## 🚀 Key Features

*   **Stateful Subnet Monitoring:** Scans local subnets and systematically tracks state changes against a JSON database baseline to flag rogue devices immediately.
*   **Low-Level Banner Grabbing:** Interrogates target sockets directly utilizing raw protocol headers (`HEAD / HTTP/1.1`) to identify service versions and software footprints.
*   **Automated Risk Assessment:** Maps active ports against a known vulnerability database to immediately isolate and alert on `HIGH` or `CRITICAL` risk exposures.
*   **Flexible Operational Orchestration:** Dual-interface execution allowing for granular control via an administrative CLI panel or automated background task scheduling.

---

## 📂 Architecture & Module Breakdown

The project follows a decoupled, modular design to ensure scalability and clean separation of concerns:

*   `ccc.py`: The core automation pipeline. Manages network discovery, port auditing, banner parsing, and differential state analysis.
*   `cli.py`: Administrative Command Line Interface managing database states, whitelist permissions, and threat mitigation viewing.
*   `run_scheduler.py` & `setup_continuous_monitoring.py`: Script engines configured to run lightweight, detailed, or deep assessments on customizable interval loops (e.g., every 15 minutes, 2 hours, or daily).
*   `core/`: Internal logic package handling raw socket networking, JSON state storage, scheduling workers, and blocking logic.

---
## Author & Credits
* **Lead Developer / Sole Creator:** Shaurya Hardiya
* This project was designed, coded, and maintained entirely by me. No external co-founders or co-developers were involved in the creation of this codebase.
