import argparse
import logging
import time
import os
import json
from core.database import ScanDatabase
from core.wifi_security import wifi_monitor
from core.network_blocker import network_blocker
from core.scheduler import scheduler

logger = logging.getLogger(__name__)

db = ScanDatabase()

def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Command Center CLI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Whitelist commands
    whitelist_parser = subparsers.add_parser("whitelist", help="Manage whitelist")
    whitelist_parser.add_argument("action", choices=["add", "remove", "list"])
    whitelist_parser.add_argument("ip", nargs="?")
    whitelist_parser.add_argument("--reason", default="")
    
    # Blacklist commands
    blacklist_parser = subparsers.add_parser("blacklist", help="Manage blacklist")
    blacklist_parser.add_argument("action", choices=["add", "remove", "list"])
    blacklist_parser.add_argument("ip", nargs="?")
    blacklist_parser.add_argument("--reason", default="")
    blacklist_parser.add_argument("--severity", default="MEDIUM", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    
    # Report viewing
    report_parser = subparsers.add_parser("report", help="View and manage reports")
    report_parser.add_argument("action", choices=["list", "view"], nargs="?", default="list")
    report_parser.add_argument("report_id", nargs="?")
    
    # WiFi security commands
    wifi_parser = subparsers.add_parser("wifi", help="WiFi security management")
    wifi_parser.add_argument("action", choices=["blocked", "threats", "unblock"])
    wifi_parser.add_argument("ip", nargs="?")
    
    # Scheduler commands
    scheduler_parser = subparsers.add_parser("scheduler", help="Manage scheduled scans")
    scheduler_parser.add_argument("action", choices=["start", "stop", "status", "add-daily", "add-hourly", "add-minutes"])
    scheduler_parser.add_argument("--hour", type=int, default=2)
    scheduler_parser.add_argument("--minute", type=int, default=0)
    scheduler_parser.add_argument("--interval", type=int, default=30)
    scheduler_parser.add_argument("--now", action="store_true", help="Run scan now on startup")
    
    args = parser.parse_args()
    
    # Whitelist commands
    if args.command == "whitelist":
        if args.action == "add":
            if not args.ip:
                print("Error: IP address required for add action")
                return
            db.add_whitelist(args.ip, args.reason)
            print(f"✓ Added {args.ip} to whitelist")
        
        elif args.action == "remove":
            if not args.ip:
                print("Error: IP address required for remove action")
                return
            db.remove_whitelist(args.ip)
            print(f"✓ Removed {args.ip} from whitelist")
        
        elif args.action == "list":
            whitelist = db.get_whitelist()
            if not whitelist:
                print("Whitelist is empty")
                return
            
            print("[ WHITELIST ]\n")
            for ip, info in whitelist.items():
                reason = info.get('reason', 'No reason')
                added_at = info.get('added_at', 'N/A')
                print(f"  {ip}")
                print(f"    Reason: {reason}")
                print(f"    Added: {added_at}\n")
    
    # Blacklist commands
    elif args.command == "blacklist":
        if args.action == "add":
            if not args.ip:
                print("Error: IP address required for add action")
                return
            db.add_blacklist(args.ip, args.reason, args.severity)
            print(f"✓ Added {args.ip} to blacklist [{args.severity}]")
        
        elif args.action == "remove":
            if not args.ip:
                print("Error: IP address required for remove action")
                return
            db.remove_blacklist(args.ip)
            print(f"✓ Removed {args.ip} from blacklist")
        
        elif args.action == "list":
            blacklist = db.get_blacklist()
            if not blacklist:
                print("Blacklist is empty")
                return
            
            print("[ BLACKLIST ]\n")
            for ip, info in blacklist.items():
                severity = info.get('severity', 'UNKNOWN')
                reason = info.get('reason', 'No reason')
                added_at = info.get('added_at', 'N/A')
                print(f"  {ip} [{severity}]")
                print(f"    Reason: {reason}")
                print(f"    Added: {added_at}\n")
    
    # Report commands
    elif args.command == "report":
        if args.action == "list":
            reports_dir = "data/reports"
            if os.path.exists(reports_dir):
                reports = [f for f in os.listdir(reports_dir) if f.endswith('.json')]
                
                if not reports:
                    print("No reports found")
                    return
                
                print("[ AVAILABLE REPORTS ]\n")
                for report_file in sorted(reports):
                    report_id = report_file.replace('report_', '').replace('.json', '')
                    print(f"  {report_id}")
                
                print(f"\nTotal: {len(reports)} reports")
            else:
                print("No reports directory found")
        
        elif args.action == "view":
            if not args.report_id:
                print("Error: report_id required for view action")
                return
            
            report_file = f"data/reports/report_{args.report_id}.json"
            try:
                with open(report_file, 'r') as f:
                    report = json.load(f)
                
                # Pretty print the report
                print("\n" + "="*80)
                print(report['incident_summary'])
                print("="*80 + "\n")
                print(json.dumps(report, indent=2))
            
            except FileNotFoundError:
                print(f"Report not found: {args.report_id}")
                return
            
            except json.JSONDecodeError:
                print(f"Error reading report file: {args.report_id}")
                return
    
    # WiFi security commands
    elif args.command == "wifi":
        if args.action == "blocked":
            blocked = wifi_monitor.get_blocked_ips()
            
            if not blocked:
                print("No blocked IPs")
                return
            
            print("[ BLOCKED IPs ]\n")
            for entry in blocked:
                ip = entry.get('ip', 'N/A')
                reason = entry.get('reason', 'Unknown')
                timestamp = entry.get('timestamp', 'N/A')
                print(f"  {ip}")
                print(f"    Reason: {reason}")
                print(f"    Blocked: {timestamp}\n")
        
        elif args.action == "threats":
            blacklist = db.get_blacklist()
            
            if not blacklist:
                print("No threats detected")
                return
            
            threats = {ip: info for ip, info in blacklist.items() 
                      if info.get("severity") in ("CRITICAL", "HIGH")}
            
            if not threats:
                print("No high/critical threats")
                return
            
            print("[ ACTIVE THREATS ]\n")
            for ip, info in threats.items():
                severity = info.get('severity', 'UNKNOWN')
                reason = info.get('reason', 'Unknown')
                print(f"  {ip} [{severity}]")
                print(f"    {reason}\n")
        
        elif args.action == "unblock":
            if not args.ip:
                print("Error: IP address required for unblock action")
                return
            
            network_blocker.unblock_ip(args.ip)
            db.remove_blacklist(args.ip)
            print(f"✓ Unblocked {args.ip}")
    
    # Scheduler commands
    elif args.command == "scheduler":
        if args.action == "start":
            print("Starting scheduler...")
            
            # Configure scheduler
            if args.now:
                print("Running initial scan...")
                scheduler.schedule_on_startup()
            
            scheduler.schedule_every_minutes(args.interval)
            print(f"✓ Scheduler configured to run every {args.interval} minutes")
            print("Press Ctrl+C to stop\n")
            
            scheduler.start(background=False)
        
        elif args.action == "stop":
            scheduler.stop()
            print("✓ Scheduler stopped")
        
        elif args.action == "status":
            jobs = scheduler.get_scheduled_jobs()
            
            if not jobs:
                print("No scheduled jobs")
                return
            
            print("[ SCHEDULED JOBS ]\n")
            for i, job in enumerate(jobs, 1):
                print(f"Job {i}:")
                print(f"  Interval: {job['interval']} {job['unit']}")
                if job['at_time'] != "N/A":
                    print(f"  At time: {job['at_time']}")
                print(f"  Next run: {job['next_run']}\n")
        
        elif args.action == "add-daily":
            scheduler.schedule_daily(args.hour, args.minute)
            print(f"✓ Added daily scan at {args.hour:02d}:{args.minute:02d}")
        
        elif args.action == "add-hourly":
            scheduler.schedule_every_hours(args.interval)
            print(f"✓ Added hourly scan every {args.interval} hours")
        
        elif args.action == "add-minutes":
            scheduler.schedule_every_minutes(args.interval)
            print(f"✓ Added scan every {args.interval} minutes")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()