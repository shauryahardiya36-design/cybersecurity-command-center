import schedule
import time
import logging
import threading
from datetime import datetime
from core.port_scan import main as run_scan

logger = logging.getLogger(__name__)

class ScanScheduler:
    """Schedule automatic network scans."""
    
    def __init__(self):
        self.is_running = False
        self.scheduler_thread = None
    
    def schedule_every_minutes(self, interval_minutes=30):
        """Schedule scans every N minutes."""
        schedule.every(interval_minutes).minutes.do(self._run_scheduled_scan)
        logger.info(f"✓ Scheduled scans every {interval_minutes} minutes")
        return self
    
    def schedule_every_hours(self, interval_hours=1):
        """Schedule scans every N hours."""
        schedule.every(interval_hours).hours.do(self._run_scheduled_scan)
        logger.info(f"✓ Scheduled scans every {interval_hours} hours")
        return self
    
    def schedule_daily(self, hour=2, minute=0):
        """Schedule daily scan at specific time (24-hour format)."""
        time_str = f"{hour:02d}:{minute:02d}"
        schedule.every().day.at(time_str).do(self._run_scheduled_scan)
        logger.info(f"✓ Scheduled daily scan at {time_str}")
        return self
    
    def schedule_on_startup(self):
        """Run scan immediately on startup."""
        self._run_scheduled_scan()
        return self
    
    def _run_scheduled_scan(self):
        """Run scan with logging and error handling."""
        logger.info(f"")
        logger.info(f"{'='*80}")
        logger.info(f"[SCHEDULED SCAN] Starting at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"{'='*80}")
        
        try:
            run_scan()
            logger.info(f"[SCHEDULED SCAN] Completed successfully at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception as e:
            logger.error(f"[SCHEDULED SCAN] Failed: {e}", exc_info=True)
        
        logger.info(f"{'='*80}\n")
    
    def start(self, background=True):
        """Start the scheduler (in thread if background=True)."""
        if self.is_running:
            logger.warning("Scheduler is already running")
            return
        
        self.is_running = True
        
        if background:
            self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
            self.scheduler_thread.start()
            logger.info("✓ Scheduler started in background")
        else:
            logger.info("Starting scheduler (blocking mode - press Ctrl+C to stop)")
            self._run_scheduler()
    
    def _run_scheduler(self):
        """Main scheduler loop."""
        logger.info("Scheduler loop started")
        
        while self.is_running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except KeyboardInterrupt:
                logger.info("Scheduler interrupted by user")
                self.stop()
                break
            except Exception as e:
                logger.error(f"Scheduler error: {e}", exc_info=True)
                time.sleep(60)
    
    def stop(self):
        """Stop the scheduler."""
        self.is_running = False
        schedule.clear()
        logger.info("✓ Scheduler stopped")
    
    def get_scheduled_jobs(self):
        """Get list of scheduled jobs."""
        jobs = schedule.jobs
        
        if not jobs:
            return []
        
        job_list = []
        for job in jobs:
            job_list.append({
                "interval": str(job.interval),
                "unit": job.unit,
                "at_time": str(job.at_time) if hasattr(job, 'at_time') else "N/A",
                "next_run": str(job.next_run)
            })
        
        return job_list


scheduler = ScanScheduler()