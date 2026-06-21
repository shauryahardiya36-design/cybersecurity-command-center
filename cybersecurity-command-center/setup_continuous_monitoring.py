#!/usr/bin/env python3
"""
Setup continuous network monitoring with multiple schedules
"""

import logging
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scheduler import scheduler

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/scheduler.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def setup_continuous_monitoring():
    """
    Setup multiple monitoring schedules:
    - Quick scan every 15 minutes (lightweight)
    - Full scan every 2 hours
    - Deep scan daily at 2 AM
    """
    
    logger.info("="*80)
    logger.info("SETTING UP CONTINUOUS NETWORK MONITORING")
    logger.info("="*80)
    logger.info("")
    
    try:
        # Run initial scan immediately
        logger.info("Running initial scan...")
        scheduler.schedule_on_startup()
        
        # Quick scan every 15 minutes
        logger.info("✓ Setting up quick scans every 15 minutes")
        scheduler.schedule_every_minutes(15)
        
        # Detailed scan every 2 hours
        logger.info("✓ Setting up detailed scans every 2 hours")
        scheduler.schedule_every_hours(2)
        
        # Deep scan daily at 2 AM
        logger.info("✓ Setting up deep scan daily at 02:00 AM")
        scheduler.schedule_daily(hour=2, minute=0)
        
        logger.info("")
        logger.info("Starting continuous monitoring...")
        logger.info("Press Ctrl+C to stop\n")
        
        scheduler.start(background=False)
    
    except Exception as e:
        logger.error(f"Error during setup: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    try:
        setup_continuous_monitoring()
    except KeyboardInterrupt:
        logger.info("\n[!] Monitoring stopped by user")
        scheduler.stop()
        print("\n✓ Scheduler cleaned up and stopped")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)