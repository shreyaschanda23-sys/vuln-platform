"""Recurring scan scheduler using APScheduler. Runs in-process alongside
FastAPI (started on app startup) and triggers the same Celery pipeline
used for manual scans."""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from api.deps import SessionLocal
from models.scan import Scan, ScanStatus
from services.orchestrator import start_scan_pipeline
from utils.logger import get_logger

logger = get_logger(__name__)

scheduler = BackgroundScheduler()

CRON_MAP = {
    "daily": {"hour": 0, "minute": 0},
    "weekly": {"day_of_week": "mon", "hour": 0, "minute": 0},
    "monthly": {"day": 1, "hour": 0, "minute": 0},
}


def _run_scheduled_scan(domain_id: int, scanners: list[str] | None):
    db = SessionLocal()
    try:
        scan = Scan(domain_id=domain_id, status=ScanStatus.pending, scanners=scanners)
        db.add(scan)
        db.commit()
        db.refresh(scan)
        start_scan_pipeline(scan.id, scanners)
        logger.info(f"Scheduled scan {scan.id} started for domain {domain_id}")
    finally:
        db.close()


def add_recurring_scan(domain_id: int, frequency: str, scanners: list[str] | None = None) -> str:
    """frequency: 'daily' | 'weekly' | 'monthly'"""
    if frequency not in CRON_MAP:
        raise ValueError(f"Invalid frequency: {frequency}")

    job_id = f"domain-{domain_id}-{frequency}"
    scheduler.add_job(
        _run_scheduled_scan,
        trigger=CronTrigger(**CRON_MAP[frequency]),
        args=[domain_id, scanners],
        id=job_id,
        replace_existing=True,
    )
    logger.info(f"Scheduled {frequency} scan for domain {domain_id}")
    return job_id


def remove_recurring_scan(job_id: str):
    scheduler.remove_job(job_id)


def list_scheduled_jobs() -> list[dict]:
    return [
        {"id": job.id, "next_run": str(job.next_run_time)}
        for job in scheduler.get_jobs()
    ]


def start_scheduler():
    scheduler.start()