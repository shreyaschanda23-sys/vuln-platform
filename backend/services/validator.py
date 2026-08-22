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
# when the underlying condition wasn't really confirmed. NOTE: deliberately
# excludes "possible"/"potential" alone since sqlmap uses that vocabulary
# for CONFIRMED findings (e.g. "possible time-based blind SQL injection").
_WEAK_EVIDENCE_PATTERNS = [
    re.compile(r"^\s*$"),                          # empty evidence
    re.compile(r"generic detection", re.IGNORECASE),
    re.compile(r"unconfirmed", re.IGNORECASE),
    re.compile(r"heuristic match only", re.IGNORECASE),
]

_WEAK_EVIDENCE_PATTERNS_NON_SQLMAP = _WEAK_EVIDENCE_PATTERNS + [
    re.compile(r"\bpossible\b", re.IGNORECASE),
    re.compile(r"\bpotential\b", re.IGNORECASE),
]

_INVALID_STATUS_CODES = {0, 404, 403, 401, 501, 502, 503}

_NOISY_TEMPLATE_IDS = {
    "generic-detection",
    "waf-detect",
    "tech-detect",
}

# sqlmap_scanner.py sets template_id to this exact static string on every
# finding — not a prefix convention.
_SQLMAP_TEMPLATE_ID = "sqlmap-sqli"


def _has_weak_evidence(finding: Finding) -> bool:
    if not finding.evidence:
        return True
    is_sqlmap = finding.template_id == _SQLMAP_TEMPLATE_ID
    patterns = _WEAK_EVIDENCE_PATTERNS if is_sqlmap else _WEAK_EVIDENCE_PATTERNS_NON_SQLMAP
    return any(p.search(finding.evidence) for p in patterns)


def _endpoint_status_invalid(finding: Finding, endpoint_status: int | None) -> bool:
    if endpoint_status is None:
        return False
    return endpoint_status in _INVALID_STATUS_CODES


def _template_is_noisy(finding: Finding) -> bool:
    return bool(finding.template_id) and finding.template_id in _NOISY_TEMPLATE_IDS


def validate_finding(finding: Finding, *, enrichment_complete: bool = True, endpoint_status: int | None = None) -> bool:
    reasons = []

    if _has_weak_evidence(finding):
        reasons.append("weak_evidence")

    if _template_is_noisy(finding):
        reasons.append("noisy_template")

    if _endpoint_status_invalid(finding, endpoint_status):
        reasons.append("invalid_endpoint_status")

    if enrichment_complete and finding.cve_id and finding.cvss_score is None:
        reasons.append("unresolvable_cve")

    is_fp = len(reasons) >= 2
    finding.is_false_positive = is_fp

    if is_fp:
        logger.info(f"Finding {finding.id} flagged as false positive: {reasons}")

    return not is_fp


def validate_scan_findings(scan_id: int, db: Session, *, enrichment_complete: bool = True) -> tuple[int, int]:
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    flagged = 0
    for finding in findings:
        if not validate_finding(finding, enrichment_complete=enrichment_complete):
            flagged += 1

    db.commit()
    logger.info(f"Validated {len(findings)} findings for scan {scan_id}, {flagged} flagged as FP")
    return len(findings), flagged