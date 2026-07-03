"""One Celery task per pipeline stage. Each task pulls the scan/domain
from DB, runs the relevant scanner(s), persists results, and updates
Scan.current_stage. Orchestrator chains these together."""
import asyncio
from celery import shared_task
from sqlalchemy.orm import Session

from worker.celery import celery_app
from api.deps import SessionLocal
from models.scan import Scan, ScanStage, ScanStatus
from models.asset import Subdomain, Port, Endpoint
from models.finding import Finding
from utils.logger import get_logger

from scanners import (
    SubfinderScanner, AmassScanner, MasscanScanner, NmapScanner,
    HttpxScanner, KatanaScanner, NucleiScanner,
)

logger = get_logger(__name__)


def _get_db() -> Session:
    return SessionLocal()


def _run_async(coro):
    """Celery tasks are sync; scanners are async. Bridge the two."""
    return asyncio.run(coro)


def _set_stage(db: Session, scan: Scan, stage: ScanStage):
    scan.current_stage = stage
    scan.status = ScanStatus.running
    db.commit()


@celery_app.task(name="worker.tasks.asset_discovery")
def asset_discovery_task(scan_id: int, domain_name: str):
    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        _set_stage(db, scan, ScanStage.asset_discovery)

        subfinder_result = _run_async(SubfinderScanner().run(domain_name))
        amass_result = _run_async(AmassScanner().run(domain_name))

        seen = set()
        for r in (subfinder_result, amass_result):
            for item in r.parsed:
                name = item.get("name")
                if name and name.endswith(domain_name) and name not in seen:
                    seen.add(name)
                    db.add(Subdomain(domain_id=scan.domain_id, scan_id=scan.id, name=name))
        db.commit()
        logger.info(f"Scan {scan_id}: discovered {len(seen)} subdomains")
        return {"count": len(seen)}
    finally:
        db.close()


@celery_app.task(name="worker.tasks.port_scan")
def port_scan_task(scan_id: int, domain_name: str):
    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        _set_stage(db, scan, ScanStage.port_scan)

        result = _run_async(MasscanScanner().run(domain_name, ports="1-1000"))
        for item in result.parsed:
            db.add(Port(
                scan_id=scan.id,
                host=item["host"],
                port_number=item["port_number"],
                protocol=item.get("protocol", "tcp"),
                state=item.get("state", "open"),
            ))
        db.commit()

        nmap_result = _run_async(NmapScanner().run(domain_name))
        for item in nmap_result.parsed:
            existing = db.query(Port).filter(
                Port.scan_id == scan.id,
                Port.host == item["host"],
                Port.port_number == item["port_number"],
            ).first()
            if existing:
                existing.service = item.get("service")
                existing.version = item.get("version")
            else:
                db.add(Port(scan_id=scan.id, **item))
        db.commit()
        logger.info(f"Scan {scan_id}: port scan complete")
        return {"count": len(result.parsed)}
    finally:
        db.close()


@celery_app.task(name="worker.tasks.live_hosts")
def live_hosts_task(scan_id: int, domain_name: str):
    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        _set_stage(db, scan, ScanStage.live_hosts)

        subdomains = db.query(Subdomain).filter(Subdomain.scan_id == scan.id).all()
        targets = [s.name for s in subdomains] or [domain_name]

        live_count = 0
        for target in targets:
            result = _run_async(HttpxScanner().run(target))
            for item in result.parsed:
                db.add(Endpoint(
                    scan_id=scan.id,
                    url=item["url"],
                    status_code=item.get("status_code"),
                    title=item.get("title"),
                    tech_stack=item.get("tech_stack"),
                    is_live=True,
                ))
                live_count += 1
        db.commit()
        logger.info(f"Scan {scan_id}: {live_count} live endpoints")
        return {"count": live_count}
    finally:
        db.close()


@celery_app.task(name="worker.tasks.crawl")
def crawl_task(scan_id: int):
    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        _set_stage(db, scan, ScanStage.crawl)

        endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan.id, Endpoint.is_live == True).all()
        crawled = 0
        for ep in endpoints:
            result = _run_async(KatanaScanner().run(ep.url))
            for item in result.parsed:
                url = item.get("url")
                if url and not db.query(Endpoint).filter(Endpoint.scan_id == scan.id, Endpoint.url == url).first():
                    db.add(Endpoint(scan_id=scan.id, url=url, is_live=True))
                    crawled += 1
        db.commit()
        logger.info(f"Scan {scan_id}: crawled {crawled} new endpoints")
        return {"count": crawled}
    finally:
        db.close()


@celery_app.task(name="worker.tasks.vuln_scan")
def vuln_scan_task(scan_id: int):
    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        _set_stage(db, scan, ScanStage.vuln_scan)

        endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan.id, Endpoint.is_live == True).all()
        found = 0
        for ep in endpoints:
            result = _run_async(NucleiScanner().run(ep.url))
            for item in result.parsed:
                db.add(Finding(
                    scan_id=scan.id,
                    cve_id=item.get("cve_id"),
                    template_id=item.get("template_id"),
                    severity=item.get("severity") or "info",
                    host=item.get("host") or ep.url,
                    endpoint=item.get("endpoint"),
                    description=item.get("description"),
                    evidence=item.get("evidence"),
                ))
                found += 1
        db.commit()
        logger.info(f"Scan {scan_id}: {found} raw findings")
        return {"count": found}
    finally:
        db.close()


@celery_app.task(name="worker.tasks.post_processing")
def post_processing_task(scan_id: int):
    """Dedup -> enrich -> validate -> score, then mark scan complete."""
    from utils.dedup import dedup_within_scan
    from services.enrichment import enrich_scan_findings
    from services.validator import validate_scan_findings
    from services.scoring import score_scan_findings
    from datetime import datetime

    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()

        _set_stage(db, scan, ScanStage.enrichment)
        dedup_within_scan(scan_id, db)
        enrich_scan_findings(scan_id, db)

        _set_stage(db, scan, ScanStage.validation)
        validate_scan_findings(scan_id, db)

        _set_stage(db, scan, ScanStage.scoring)
        score_scan_findings(scan_id, db)

        scan.current_stage = ScanStage.complete
        scan.status = ScanStatus.complete
        scan.finished_at = datetime.utcnow()
        db.commit()
        logger.info(f"Scan {scan_id}: complete")
        return {"status": "complete"}
    except Exception as e:
        scan.status = ScanStatus.failed
        scan.error_message = str(e)
        db.commit()
        logger.error(f"Scan {scan_id}: failed - {e}")
        raise
    finally:
        db.close()