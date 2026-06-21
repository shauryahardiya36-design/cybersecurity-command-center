#!/usr/bin/env python3
"""
Standalone scheduler script - Run in background for automatic scans
Usage: python3 run_scheduler.py
"""

import logging
import time
from core.scheduler import scheduler

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/scheduler.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def main():
    logger.info("="*80)
    logger.info("CYBERSECURITY COMMAND CENTER - SCHEDULER")
    logger.info("="*80)
    logger.info("")
    
    # Configure scheduling
    scheduler.schedule_on_startup()  # Run immediately first time
    scheduler.schedule_every_minutes(30)  # Then every 30 minutes
    scheduler.schedule_daily(hour=2, minute=0)  # Also run daily at 2 AM
    
    logger.info("Starting scheduler...")
    logger.info("Press Ctrl+C to stop\n")
    
    try:
        scheduler.start(background=False)
    except KeyboardInterrupt:
        logger.info("\n[!] Shutting down scheduler...")
        scheduler.stop()
        logger.info("Scheduler stopped cleanly")


if __name__ == "__main__":
    main()