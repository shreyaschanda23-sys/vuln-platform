"""
Scoring service: combines CVSS severity, EPSS exploitation probability, and
CISA KEV status into a single 0-100 risk_score per finding.
"""
from sqlalchemy.orm import Session

from models.finding import Finding
from utils.logger import get_logger

logger = get_logger(__name__)

# Weights: CVSS is the baseline severity signal, EPSS captures real-world
# exploitation likelihood, and KEV is a hard override since it means CISA
# has confirmed active exploitation.
_CVSS_WEIGHT = 0.5
_EPSS_WEIGHT = 0.3
_EXPOSURE_WEIGHT = 0.2
_KEV_FLOOR = 90.0  # KEV-listed findings never score below this


def _cvss_component(finding: Finding) -> float:
    """Normalize CVSS (0-10) to 0-100."""
    if finding.cvss_score is None:
        # No CVSS data — fall back to severity string if present.
        fallback = {"critical": 9.5, "high": 8.0, "medium": 5.0, "low": 2.5}
        return fallback.get((finding.severity or "").lower(), 3.0) * 10
    return finding.cvss_score * 10


def _epss_component(finding: Finding) -> float:
    """EPSS is already 0-1 probability; scale to 0-100."""
    if finding.epss_score is None:
        return 0.0
    return finding.epss_score * 100


def _exposure_component(finding: Finding) -> float:
    """
    Simple exposure heuristic: internet-facing endpoint findings score
    higher than internal-only port findings. Extend this once asset
    criticality / network zone data exists.
    """
    if finding.endpoint:
        return 100.0  # web-facing
    if finding.port:
        return 60.0   # network service
    return 40.0


def calculate_risk_score(finding: Finding) -> float:
    """Compute a 0-100 risk score for a single finding."""
    if finding.is_false_positive:
        return 0.0

    score = (
        _cvss_component(finding) * _CVSS_WEIGHT
        + _epss_component(finding) * _EPSS_WEIGHT
        + _exposure_component(finding) * _EXPOSURE_WEIGHT
    )

    if finding.kev_status:
        score = max(score, _KEV_FLOOR)

    return round(min(score, 100.0), 2)


def score_finding(finding: Finding) -> Finding:
    finding.risk_score = calculate_risk_score(finding)
    return finding


def score_scan_findings(scan_id: int, db: Session) -> int:
    """Score every finding for a scan. Returns count scored."""
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    for finding in findings:
        score_finding(finding)

    db.commit()
    logger.info(f"Scored {len(findings)} findings for scan {scan_id}")
    return len(findings)