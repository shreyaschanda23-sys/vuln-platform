"""
Validator service: flags likely false positives before findings are scored,
so noisy scanner output doesn't inflate risk numbers or clutter reports.
"""
import re
from sqlalchemy.orm import Session

from models.finding import Finding
from utils.logger import get_logger

logger = get_logger(__name__)

# Generic/templated evidence patterns that nuclei/other scanners emit even
# when the underlying condition wasn't really confirmed.
_WEAK_EVIDENCE_PATTERNS = [
    re.compile(r"^\s*$"),                       # empty evidence
    re.compile(r"potential", re.IGNORECASE),
    re.compile(r"possible(?:ly)?", re.IGNORECASE),
    re.compile(r"generic detection", re.IGNORECASE),
]

# Status codes that usually mean "the probe didn't actually land" rather
# than confirming a real vulnerable endpoint.
_INVALID_STATUS_CODES = {0, 404, 403, 401, 501, 502, 503}

# Template IDs known to be prone to false positives (tune this list as you
# observe FPs from real scans).
_NOISY_TEMPLATE_IDS = {
    "generic-detection",
    "waf-detect",
    "tech-detect",
}


def _has_weak_evidence(finding: Finding) -> bool:
    if not finding.evidence:
        return True
    return any(p.search(finding.evidence) for p in _WEAK_EVIDENCE_PATTERNS)


def _endpoint_status_invalid(finding: Finding) -> bool:
    # Only applies if we captured a status code on the endpoint some other
    # way; findings without one are neither confirmed nor denied here.
    return False  # placeholder hook — wire up once endpoint join is available


def _template_is_noisy(finding: Finding) -> bool:
    return bool(finding.template_id) and finding.template_id in _NOISY_TEMPLATE_IDS


def validate_finding(finding: Finding) -> bool:
    """
    Returns True if the finding looks legitimate, False if it should be
    flagged as a likely false positive. Sets finding.is_false_positive
    in-place either way.
    """
    reasons = []

    if _has_weak_evidence(finding):
        reasons.append("weak_evidence")

    if _template_is_noisy(finding):
        reasons.append("noisy_template")

    # CVE-backed findings with no CVSS at all after enrichment attempts are
    # suspicious — likely a bad CVE ID from the scanner template.
    if finding.cve_id and finding.cvss_score is None:
        reasons.append("unresolvable_cve")

    is_fp = len(reasons) >= 2  # require multiple weak signals, not just one
    finding.is_false_positive = is_fp

    if is_fp:
        logger.info(f"Finding {finding.id} flagged as false positive: {reasons}")

    return not is_fp


def validate_scan_findings(scan_id: int, db: Session) -> tuple[int, int]:
    """Validate all findings for a scan. Returns (total, flagged_as_fp)."""
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    flagged = 0
    for finding in findings:
        if not validate_finding(finding):
            flagged += 1

    db.commit()
    logger.info(f"Validated {len(findings)} findings for scan {scan_id}, {flagged} flagged as FP")
    return len(findings), flagged