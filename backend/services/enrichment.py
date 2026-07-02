"""
Enrichment service: pulls CVSS (NVD), EPSS (FIRST.org), and KEV status (CISA)
for a given CVE and writes them onto a Finding.
"""
import time
import httpx
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from app.config import settings
from models.finding import Finding
from utils.logger import get_logger

logger = get_logger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# NVD rate limits: 5 req/30s without a key, 50 req/30s with one.
_NVD_DELAY = 0.6 if settings.nvd_api_key else 6.0

_kev_cache: dict | None = None
_kev_cache_time: datetime | None = None
_KEV_CACHE_TTL = timedelta(hours=6)


class EnrichmentError(Exception):
    pass


def _nvd_headers() -> dict:
    return {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}


def fetch_cvss(cve_id: str, client: httpx.Client) -> float | None:
    """Fetch CVSS base score for a CVE from NVD. Prefers v3.1 -> v3.0 -> v2."""
    try:
        resp = client.get(
            NVD_BASE_URL,
            params={"cveId": cve_id},
            headers=_nvd_headers(),
            timeout=15.0,
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        metrics = vulns[0]["cve"].get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                return float(metrics[key][0]["cvssData"]["baseScore"])
        return None
    except httpx.HTTPError as e:
        logger.warning(f"NVD lookup failed for {cve_id}: {e}")
        return None
    finally:
        time.sleep(_NVD_DELAY)


def fetch_epss(cve_id: str, client: httpx.Client) -> float | None:
    """Fetch EPSS probability score (0-1) for a CVE."""
    try:
        resp = client.get(EPSS_BASE_URL, params={"cve": cve_id}, timeout=15.0)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        if not data:
            return None
        return float(data[0]["epss"])
    except httpx.HTTPError as e:
        logger.warning(f"EPSS lookup failed for {cve_id}: {e}")
        return None


def _load_kev_catalog(client: httpx.Client) -> set[str]:
    """Load and cache the CISA KEV catalog. Refreshes every 6 hours."""
    global _kev_cache, _kev_cache_time
    now = datetime.utcnow()
    if _kev_cache is not None and _kev_cache_time and now - _kev_cache_time < _KEV_CACHE_TTL:
        return _kev_cache

    try:
        resp = client.get(KEV_FEED_URL, timeout=20.0)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        _kev_cache = {v["cveID"] for v in vulns}
        _kev_cache_time = now
    except httpx.HTTPError as e:
        logger.warning(f"KEV catalog fetch failed: {e}")
        _kev_cache = _kev_cache or set()

    return _kev_cache


def is_in_kev(cve_id: str, client: httpx.Client) -> bool:
    return cve_id in _load_kev_catalog(client)


def enrich_finding(finding: Finding, client: httpx.Client) -> Finding:
    """Enrich a single finding in-place with CVSS, EPSS, and KEV status."""
    if not finding.cve_id:
        return finding

    if finding.cvss_score is None:
        finding.cvss_score = fetch_cvss(finding.cve_id, client)

    if finding.epss_score is None:
        finding.epss_score = fetch_epss(finding.cve_id, client)

    finding.kev_status = is_in_kev(finding.cve_id, client)

    return finding


def enrich_scan_findings(scan_id: int, db: Session) -> int:
    """Enrich every un-enriched finding belonging to a scan. Returns count enriched."""
    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id, Finding.cve_id.isnot(None))
        .all()
    )

    count = 0
    with httpx.Client() as client:
        for finding in findings:
            enrich_finding(finding, client)
            count += 1
            if count % 10 == 0:
                db.commit()  # checkpoint periodically for long scans

    db.commit()
    logger.info(f"Enriched {count} findings for scan {scan_id}")
    return count
