"""
Deduplication: prevents the same underlying vulnerability from being
recorded multiple times across scanner tools or repeated scan runs.
"""
from sqlalchemy.orm import Session
from sqlalchemy import and_

from models.finding import Finding
from utils.logger import get_logger

logger = get_logger(__name__)


def _finding_key(finding: Finding) -> tuple:
    """
    Identity key for a finding: same host + port + endpoint + cve/template
    is considered the same underlying issue, even if reported by different
    tools or in different scan stages.

    When neither cve_id nor template_id is set (e.g. some sqlmap/dalfox
    results), fall back to including description so two distinct
    vulnerabilities on the same endpoint don't collide into one key.
    """
    identifier = finding.cve_id or finding.template_id
    if identifier is None:
        identifier = ("desc", (finding.description or "")[:200])
    return (
        finding.host,
        finding.port,
        finding.endpoint,
        identifier,
    )


def dedup_within_scan(scan_id: int, db: Session) -> int:
    """
    Remove duplicate findings within a single scan (e.g. nuclei firing the
    same template twice, or two tools flagging the same CVE on the same
    host). Keeps the first occurrence, deletes the rest. Returns count removed.
    """
    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.id.asc())
        .all()
    )

    seen: set[tuple] = set()
    to_delete = []

    for finding in findings:
        key = _finding_key(finding)
        if key in seen:
            to_delete.append(finding)
        else:
            seen.add(key)

    for finding in to_delete:
        db.delete(finding)

    if to_delete:
        db.commit()
        logger.info(f"Removed {len(to_delete)} duplicate findings in scan {scan_id}")

    return len(to_delete)


def find_persistent_finding(finding: Finding, domain_id: int, db: Session) -> Finding | None:
    """
    Given a newly discovered finding, check if an equivalent finding exists
    on a previous scan of the same domain (used by the diff engine in
    Phase 7, but the lookup lives here since it's dedup logic).

    Checks candidates in discovered_at order (most recent first) and
    returns the first one whose full key actually matches — rather than
    grabbing the single most-recent host/port/endpoint match and hoping
    its cve/template also lines up.
    """
    from models.scan import Scan  # local import to avoid circular import

    key = _finding_key(finding)

    candidates = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            and_(
                Scan.domain_id == domain_id,
                Scan.id != finding.scan_id,
                Finding.host == key[0],
                Finding.port == key[1],
                Finding.endpoint == key[2],
            )
        )
        .order_by(Finding.discovered_at.desc())
        .all()
    )

    for candidate in candidates:
        if _finding_key(candidate) == key:
            return candidate

    return None