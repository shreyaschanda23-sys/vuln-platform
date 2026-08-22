"""One Celery task per pipeline stage. Each task pulls the scan/domain
from DB, runs the relevant scanner(s), persists results, and updates
Scan.current_stage. Orchestrator chains these together."""
import asyncio
import json
from datetime import datetime
from urllib.parse import urlparse
from sqlalchemy.orm import Session
import redis as sync_redis

from worker.celery import celery_app
from api.deps import SessionLocal
from app.config import settings
from models.scan import Scan, ScanStage, ScanStatus
from models.asset import Subdomain, Port, Endpoint
from models.finding import Finding
from utils.logger import get_logger
from services.asset_discovery import persist_subdomains, extract_emails_from_text

from scanners import (
    SubfinderScanner, AmassScanner, MasscanScanner, NmapScanner,
    HttpxScanner, KatanaScanner, NucleiScanner,
)

logger = get_logger(__name__)

_redis_client = sync_redis.from_url(settings.redis_url)

_NUCLEI_BATCH_SIZE = 5


def _get_db() -> Session:
    return SessionLocal()


def _run_async(coro):
    return asyncio.run(coro)


def _run_async_gather(*coros):
    """Run multiple coroutines concurrently in one event loop.
    Exceptions in individual scanners are captured, not raised, so one
    failing tool doesn't kill results from the others."""
    async def _gather():
        return await asyncio.gather(*coros, return_exceptions=True)
    return asyncio.run(_gather())


def _broadcast(scan: Scan):
    """Publish scan progress to Redis. The FastAPI process subscribes to
    this channel and fans out to its own local WebSocket connections —
    Celery workers have no WebSocket connections of their own, so this
    Redis hop is required to bridge the two processes."""
    try:
        _redis_client.publish(
            f"scan_progress:{scan.id}",
            json.dumps({
                "scan_id": scan.id,
                "status": scan.status.value,
                "current_stage": scan.current_stage.value if scan.current_stage else None,
            })
        )
    except Exception:
        pass


def _set_stage(db: Session, scan: Scan, stage: ScanStage):
    scan.current_stage = stage
    scan.status = ScanStatus.running
    db.commit()
    _broadcast(scan)


def _is_in_scope(url: str, domain_name: str) -> bool:
    """
    Only allow URLs whose host is the target domain or a subdomain of it.
    Prevents the crawler/scanner from touching third-party URLs incidentally
    picked up from JS string literals, external links, CDN references, or
    example/placeholder URLs embedded in bundled code (e.g. README examples
    baked into a JS library, github.com links, etc).
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    host = parsed.hostname
    if not host:
        return False

    host = host.lower()
    domain_name = domain_name.lower()

    return host == domain_name or host.endswith(f".{domain_name}")


# Path fragments that indicate a URL was reconstructed from a string literal
# inside JS/sourcemap code rather than being a real discoverable endpoint,
# based on patterns observed from katana/linkfinder false positives.
_SUSPICIOUS_PATH_MARKERS = (
    "/node_modules/",
    "/src/node/",
    "importAnalysisBuild",
    "spa-github-pages",
)


def _is_valid_url(url: str) -> bool:
    """
    Reject structurally malformed or clearly-not-a-real-endpoint URLs before
    they're persisted as Endpoint rows or handed to a vuln scanner. Catches
    patterns seen from katana/linkfinder extracting string literals out of
    JS/sourcemaps rather than real discoverable paths:
      - doubled adjacent path segments (/assets/assets/...)
      - truncated single-character path components (/assets/g)
      - known build-tool/library-internal path fragments
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    path = parsed.path
    if not path:
        return True  # bare domain root is fine

    segments = [s for s in path.split("/") if s]

    # Doubled adjacent segments: /assets/assets/foo
    for i in range(len(segments) - 1):
        if segments[i] == segments[i + 1]:
            return False

    # Truncated trailing component: single/double-char with no extension,
    # e.g. /assets/g — real asset filenames are essentially never this short
    if segments:
        last = segments[-1]
        if len(last) <= 2 and "." not in last:
            return False

    lowered = url.lower()
    if any(marker.lower() in lowered for marker in _SUSPICIOUS_PATH_MARKERS):
        return False

    return True


_SKIP_EXTENSIONS = {
    ".js", ".css", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".webm", ".mp3",
    ".pdf", ".zip",
}


def _is_static_asset(url: str) -> bool:
    """
    Skip nuclei scanning for static asset files (bundled JS/CSS, images,
    fonts, etc). These have no server-side logic, injection points, or
    version-fingerprintable behavior that nuclei's default severity-based
    templates can meaningfully check — scanning them wastes significant
    time (observed ~2 min/file) for effectively zero real coverage.
    """
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    return any(path.endswith(ext) for ext in _SKIP_EXTENSIONS)


@celery_app.task(name="worker.tasks.asset_discovery")
def asset_discovery_task(scan_id: int, domain_name: str, scanners: list[str] | None = None):
    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        _set_stage(db, scan, ScanStage.asset_discovery)

        use_all = scanners is None

        coros = []
        labels = []
        if use_all or "subfinder" in scanners:
            coros.append(SubfinderScanner().run(domain_name))
            labels.append("subfinder")
        if use_all or "amass" in scanners:
            coros.append(AmassScanner().run(domain_name))
            labels.append("amass")

        raw_results = _run_async_gather(*coros) if coros else []

        results = []
        for label, r in zip(labels, raw_results):
            if isinstance(r, Exception):
                logger.warning(f"Scan {scan_id}: {label} failed - {r}")
                continue
            results.append(r)

        names = set()
        for r in results:
            for item in r.parsed:
                name = item.get("name")
                if name and name.endswith(domain_name):
                    names.add(name)

        new_count = persist_subdomains(scan.domain_id, scan.id, names, db)
        logger.info(f"Scan {scan_id}: discovered {new_count} new subdomains")
        return {"count": new_count}
    finally:
        db.close()


@celery_app.task(name="worker.tasks.port_scan")
def port_scan_task(scan_id: int, domain_name: str, scanners: list[str] | None = None):
    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        _set_stage(db, scan, ScanStage.port_scan)
        use_all = scanners is None
        count = 0

        if use_all or "masscan" in scanners:
            result = _run_async(MasscanScanner().run(domain_name, ports="1-1000"))
            for item in result.parsed:
                db.add(Port(scan_id=scan.id, host=item["host"], port_number=item["port_number"],
                             protocol=item.get("protocol", "tcp"), state=item.get("state", "open")))
            count = len(result.parsed)
            db.commit()

        if use_all or "nmap" in scanners:
            nmap_result = _run_async(NmapScanner().run(domain_name))
            for item in nmap_result.parsed:
                item = {k: v for k, v in item.items() if k != "os"}
                existing = db.query(Port).filter(
                    Port.scan_id == scan.id, Port.host == item["host"], Port.port_number == item["port_number"]
                ).first()
                if existing:
                    existing.service = item.get("service")
                    existing.version = item.get("version")
                else:
                    db.add(Port(scan_id=scan.id, **item))
            db.commit()
        logger.info(f"Scan {scan_id}: port scan complete")
        return {"count": count}
    finally:
        db.close()


@celery_app.task(name="worker.tasks.live_hosts")
def live_hosts_task(scan_id: int, domain_name: str, scanners: list[str] | None = None):
    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        _set_stage(db, scan, ScanStage.live_hosts)

        if scanners is not None and "httpx" not in scanners:
            logger.info(f"Scan {scan_id}: httpx skipped by selection")
            return {"count": 0}

        subdomains = db.query(Subdomain).filter(Subdomain.scan_id == scan.id).all()
        targets = [s.name for s in subdomains] or [domain_name]

        live_count = 0
        emails_found = set()
        for target in targets:
            result = _run_async(HttpxScanner().run(target))
            for item in result.parsed:
                db.add(Endpoint(scan_id=scan.id, url=item["url"], status_code=item.get("status_code"),
                                 title=item.get("title"), tech_stack=item.get("tech_stack"), is_live=True))
                live_count += 1
                if item.get("body"):
                    emails_found.update(extract_emails_from_text(item["body"]))

        scan.emails_found = list(emails_found)
        db.commit()
        logger.info(f"Scan {scan_id}: {live_count} live endpoints, {len(emails_found)} emails")
        return {"count": live_count}
    finally:
        db.close()


@celery_app.task(name="worker.tasks.crawl")
def crawl_task(scan_id: int, scanners: list[str] | None = None):
    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        _set_stage(db, scan, ScanStage.crawl)

        if scanners is not None and "katana" not in scanners:
            logger.info(f"Scan {scan_id}: katana skipped by selection")
            return {"count": 0}

        if not scan.domain:
            logger.warning(f"Scan {scan_id}: no domain associated, skipping crawl")
            db.commit()
            return {"count": 0}

        domain_name = scan.domain.name
        endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan.id, Endpoint.is_live == True).all()
        crawled = 0
        skipped_out_of_scope = 0
        skipped_invalid = 0

        for ep in endpoints:
            result = _run_async(KatanaScanner().run(ep.url))
            for item in result.parsed:
                url = item.get("url")
                if not url:
                    continue

                if not _is_in_scope(url, domain_name):
                    skipped_out_of_scope += 1
                    continue

                if not _is_valid_url(url):
                    skipped_invalid += 1
                    continue

                if not db.query(Endpoint).filter(Endpoint.scan_id == scan.id, Endpoint.url == url).first():
                    db.add(Endpoint(scan_id=scan.id, url=url, is_live=True))
                    crawled += 1

        db.commit()
        logger.info(
            f"Scan {scan_id}: crawled {crawled} new endpoints "
            f"({skipped_out_of_scope} out-of-scope, {skipped_invalid} malformed skipped)"
        )
        return {"count": crawled}
    finally:
        db.close()


@celery_app.task(name="worker.tasks.vuln_scan")
def vuln_scan_task(scan_id: int, scanners: list[str] | None = None):
    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        _set_stage(db, scan, ScanStage.vuln_scan)

        if scanners is not None and "nuclei" not in scanners:
            logger.info(f"Scan {scan_id}: nuclei skipped by selection")
            return {"count": 0}

        domain_name = scan.domain.name if scan.domain else None
        endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan.id, Endpoint.is_live == True).all()

        targets = []
        skipped_scope = 0
        skipped_asset = 0
        for ep in endpoints:
            if domain_name and not _is_in_scope(ep.url, domain_name):
                skipped_scope += 1
                continue
            if not _is_valid_url(ep.url):
                skipped_scope += 1
                continue
            if _is_static_asset(ep.url):
                skipped_asset += 1
                continue
            targets.append(ep)

        if skipped_scope or skipped_asset:
            logger.info(
                f"Scan {scan_id}: vuln_scan skipping {skipped_scope} out-of-scope/invalid, "
                f"{skipped_asset} static assets"
            )

        found = 0

        # Process endpoints in small concurrent batches rather than fully
        # sequential (slow, ~3-6 min/endpoint observed) or fully parallel
        # (risks overloading VM CPU/network with many simultaneous nuclei
        # processes, each loading its own full template set into memory).
        for i in range(0, len(targets), _NUCLEI_BATCH_SIZE):
            batch = targets[i:i + _NUCLEI_BATCH_SIZE]
            coros = [NucleiScanner().run(ep.url) for ep in batch]
            raw_results = _run_async_gather(*coros)

            for ep, result in zip(batch, raw_results):
                if isinstance(result, Exception):
                    logger.warning(f"Scan {scan_id}: nuclei failed on {ep.url} - {result}")
                    continue
                for item in result.parsed:
                    db.add(Finding(scan_id=scan.id, cve_id=item.get("cve_id"), template_id=item.get("template_id"),
                                    severity=item.get("severity") or "info", host=item.get("host") or ep.url,
                                    endpoint=item.get("endpoint"), description=item.get("description"),
                                    evidence=item.get("evidence")))
                    found += 1

            batch_end = min(i + _NUCLEI_BATCH_SIZE, len(targets))
            logger.info(f"Scan {scan_id}: nuclei batch complete ({batch_end}/{len(targets)} endpoints)")

        db.commit()
        logger.info(f"Scan {scan_id}: {found} raw findings")
        return {"count": found}
    finally:
        db.close()


@celery_app.task(name="worker.tasks.deep_scan")
def deep_scan_task(scan_id: int, scanners: list[str] | None = None):
    from scanners import FfufScanner, SqlmapScanner, DalfoxScanner, TrufflehogScanner, GowitnessScanner

    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        _set_stage(db, scan, ScanStage.vuln_scan)

        if scanners is None:
            logger.info(f"Scan {scan_id}: deep scan skipped (opt-in only)")
            return {"count": 0}

        endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan.id, Endpoint.is_live == True).all()
        found = 0

        jobs = []  # list of (kind, endpoint_or_none, coro)

        if "ffuf" in scanners:
            for ep in endpoints[:5]:
                jobs.append(("ffuf", ep, FfufScanner().run(ep.url)))

        if "sqlmap" in scanners:
            for ep in endpoints[:5]:
                jobs.append(("sqlmap", ep, SqlmapScanner().run(ep.url)))

        if "dalfox" in scanners:
            for ep in endpoints[:5]:
                jobs.append(("dalfox", ep, DalfoxScanner().run(ep.url)))

        if "trufflehog" in scanners and scan.domain and scan.domain.name:
            jobs.append(("trufflehog", None, TrufflehogScanner().run(f"https://{scan.domain.name}")))

        if "gowitness" in scanners:
            for ep in endpoints[:10]:
                jobs.append(("gowitness", ep, GowitnessScanner().run(ep.url)))

        if not jobs:
            db.commit()
            return {"count": 0}

        coros = [j[2] for j in jobs]
        raw_results = _run_async_gather(*coros)

        for (kind, ep, _), result in zip(jobs, raw_results):
            if isinstance(result, Exception):
                logger.warning(f"Scan {scan_id}: {kind} failed on {ep.url if ep else scan.domain.name} - {result}")
                continue

            if kind == "ffuf":
                for item in result.parsed:
                    if not db.query(Endpoint).filter(Endpoint.scan_id == scan.id, Endpoint.url == item["url"]).first():
                        db.add(Endpoint(scan_id=scan.id, url=item["url"], status_code=item.get("status_code"), is_live=True))

            elif kind == "sqlmap":
                for item in result.parsed:
                    db.add(Finding(scan_id=scan.id, template_id=item.get("template_id"), severity=item.get("severity", "high"),
                                    host=ep.url, description=item.get("description"), evidence=item.get("evidence")))
                    found += 1

            elif kind == "dalfox":
                for item in result.parsed:
                    db.add(Finding(scan_id=scan.id, template_id=item.get("template_id"), severity=item.get("severity", "high"),
                                    host=ep.url, endpoint=item.get("endpoint"), description=item.get("description"),
                                    evidence=item.get("evidence")))
                    found += 1

            elif kind == "trufflehog":
                for item in result.parsed:
                    db.add(Finding(scan_id=scan.id, template_id=item.get("template_id"), severity=item.get("severity", "high"),
                                    host=scan.domain.name, endpoint=item.get("endpoint"), description=item.get("description"),
                                    evidence=item.get("evidence")))
                    found += 1

            # gowitness has no parsed findings/endpoints to persist — screenshot side effect only

        db.commit()
        logger.info(f"Scan {scan_id}: deep scan found {found} additional findings")
        return {"count": found}
    finally:
        db.close()


@celery_app.task(name="worker.tasks.post_processing")
def post_processing_task(scan_id: int):
    from utils.dedup import dedup_within_scan
    from services.enrichment import enrich_scan_findings
    from services.validator import validate_scan_findings
    from services.scoring import score_scan_findings

    db = _get_db()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    try:
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
        _broadcast(scan)
        logger.info(f"Scan {scan_id}: complete")
        return {"status": "complete"}
    except Exception as e:
        scan.status = ScanStatus.failed
        scan.error_message = str(e)
        db.commit()
        _broadcast(scan)
        logger.error(f"Scan {scan_id}: failed - {e}")
        raise
    finally:
        db.close()


@celery_app.task(name="worker.tasks.mark_scan_failed")
def mark_scan_failed_task(request, exc, traceback, scan_id: int):
    """Celery error callback: fires if any task in the pipeline chain
    raises unhandled, so the scan doesn't sit stuck in 'running' forever
    with no record of what went wrong."""
    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.failed
            scan.error_message = str(exc)
            scan.finished_at = datetime.utcnow()
            db.commit()
            _broadcast(scan)
            logger.error(f"Scan {scan_id} failed: {exc}")
    finally:
        db.close()