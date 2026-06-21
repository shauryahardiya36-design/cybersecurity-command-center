import argparse
import time
import logging
from core.scheduler import scheduler
from core.subnet_discovery import get_local_subnet, generate_ips
from core.network_scan import scan_network
from core.port_scan import scan_ports
from core.device_tracker import load_devices, save_devices, compare_devices
from core.service_map import describe_port
from core.banner_grab import grab_banner

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ccc.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def main(schedule_enabled=False):
    """
    Main scan function.
    If schedule_enabled=True, runs in scheduler mode.
    """
    # Load previous devices
    old_devices = load_devices()

    # Scan subnet
    subnet = get_local_subnet()
    logger.info(f"[+] Local subnet: {subnet}")

    ips = generate_ips(subnet)
    alive_devices = scan_network(ips)

    # Scan ports for each alive device
    new_devices = {}
    for ip in alive_devices:
        ports = scan_ports(ip)
        new_devices[ip] = ports

    # Compare with previous scan
    alerts = compare_devices(old_devices, new_devices)

    # Save current scan as new baseline
    save_devices(new_devices)

    # Print results
    logger.info(f"[+] Devices found: {len(alive_devices)}")
    for ip in alive_devices:
        ports = new_devices[ip]
        logger.info(f" - {ip}")

        if not ports:
            logger.info("    No exposed services")
        else:
            for port in ports:
                service, risk = describe_port(port)
                banner = grab_banner(ip, port)

                logger.info(f"    {port} ({service}) → {risk}")

                if banner:
                    logger.info(f"      Banner: {banner}")

                if risk == "HIGH":
                    logger.warning("      [!] HIGH RISK SERVICE DETECTED")

    # Print alerts
    if alerts:
        logger.warning("\n[ ALERTS ]")
        for alert in alerts:
            logger.warning(alert)
    else:
        logger.info("\n[No changes detected]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cybersecurity Command Center")
    parser.add_argument("--schedule", action="store_true", help="Run in scheduler mode")
    parser.add_argument("--interval", type=int, default=30, help="Scan interval in minutes")
    parser.add_argument("--daily", action="store_true", help="Add daily scan")
    parser.add_argument("--hour", type=int, default=2, help="Hour for daily scan (0-23)")
    parser.add_argument("--minute", type=int, default=0, help="Minute for daily scan")
    
    args = parser.parse_args()
    
    if args.schedule:
        logger.info("Starting in scheduler mode...")
        scheduler.schedule_on_startup()
        scheduler.schedule_every_minutes(args.interval)
        
        if args.daily:
            scheduler.schedule_daily(args.hour, args.minute)
        
        scheduler.start(background=False)
    else:
        main()