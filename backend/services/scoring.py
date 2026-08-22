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

_SEVERITY_FALLBACK = {"critical": 9.5, "high": 8.0, "medium": 5.0, "low": 2.5, "info": 0.0, "informational": 0.0}


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(value, hi))


def _cvss_component(finding: Finding) -> float:
    """Normalize CVSS (0-10) to 0-100. Clamps out-of-range/bad data."""
    if finding.cvss_score is None:
        sev = (finding.severity or "").lower()
        if sev and sev not in _SEVERITY_FALLBACK:
            logger.warning(f"Finding {finding.id}: unrecognized severity '{finding.severity}', defaulting to low")
        fallback = _SEVERITY_FALLBACK.get(sev, 2.5)
        return fallback * 10
    cvss = _clamp(finding.cvss_score, 0.0, 10.0)
    if cvss != finding.cvss_score:
        logger.warning(f"Finding {finding.id}: cvss_score {finding.cvss_score} out of range, clamped to {cvss}")
    return cvss * 10


def _epss_component(finding: Finding) -> float:
    """EPSS is a 0-1 probability; scale to 0-100. Clamps bad API data."""
    if finding.epss_score is None:
        return 0.0
    epss = _clamp(finding.epss_score, 0.0, 1.0)
    if epss != finding.epss_score:
        logger.warning(f"Finding {finding.id}: epss_score {finding.epss_score} out of range, clamped to {epss}")
    return epss * 100


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

    return round(_clamp(score, 0.0, 100.0), 2)


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