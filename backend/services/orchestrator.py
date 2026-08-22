"""Chains all scan stage tasks into one pipeline via Celery."""
from celery import chain

from worker.tasks import (
    asset_discovery_task,
    port_scan_task,
    live_hosts_task,
    crawl_task,
    vuln_scan_task,
    deep_scan_task,
    post_processing_task,
    mark_scan_failed_task,
)
from api.deps import SessionLocal
from models.scan import Scan, ScanStatus
from models.domain import Domain
from utils.logger import get_logger

logger = get_logger(__name__)


def start_scan_pipeline(scan_id: int, scanners: list[str] | None = None) -> str:
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        domain = db.query(Domain).filter(Domain.id == scan.domain_id).first()
        if not domain:
            raise ValueError(f"Domain {scan.domain_id} not found")

        pipeline = chain(
            asset_discovery_task.si(scan_id, domain.name, scanners),
            port_scan_task.si(scan_id, domain.name, scanners),
            live_hosts_task.si(scan_id, domain.name, scanners),
            crawl_task.si(scan_id, scanners),
            vuln_scan_task.si(scan_id, scanners),
            deep_scan_task.si(scan_id, scanners),
            post_processing_task.si(scan_id),
        )

        # link_error ensures a crash anywhere in the chain marks the scan
        # failed instead of leaving it stuck in "running" indefinitely.
        result = pipeline.apply_async(
            link_error=mark_scan_failed_task.s(scan_id)
        )

        scan.status = ScanStatus.running
        db.commit()
        logger.info(f"Started pipeline for scan {scan_id}, task_id={result.id}")
        return result.id
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()