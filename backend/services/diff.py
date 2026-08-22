"""Compares findings between the latest scan and the previous scan of the
same domain to surface new, resolved, and persistent vulnerabilities."""
from dataclasses import dataclass, field
from sqlalchemy.orm import Session

from models.scan import Scan, ScanStatus
from models.finding import Finding
from utils.dedup import _finding_key  # reuse the single source of truth for identity keys


@dataclass
class ScanDiff:
    new: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    persistent: list[Finding] = field(default_factory=list)


def get_previous_scan(scan: Scan, db: Session) -> Scan | None:
    return (
        db.query(Scan)
        .filter(Scan.domain_id == scan.domain_id, Scan.id != scan.id, Scan.status == ScanStatus.complete)
        .filter(Scan.started_at < scan.started_at)
        .order_by(Scan.started_at.desc())
        .first()
    )


def diff_scans(current_scan_id: int, db: Session) -> ScanDiff:
    """Diff the current scan against the immediately preceding completed
    scan for the same domain. Returns empty diff if there's no prior scan."""
    current_scan = db.query(Scan).filter(Scan.id == current_scan_id).first()
    if not current_scan:
        return ScanDiff()

    previous_scan = get_previous_scan(current_scan, db)
    if not previous_scan:
        return ScanDiff(new=db.query(Finding).filter(Finding.scan_id == current_scan_id).all())

    current_findings = db.query(Finding).filter(Finding.scan_id == current_scan_id).all()
    previous_findings = db.query(Finding).filter(Finding.scan_id == previous_scan.id).all()

    current_keys = {_finding_key(f): f for f in current_findings}
    previous_keys = {_finding_key(f): f for f in previous_findings}

    new = [f for k, f in current_keys.items() if k not in previous_keys]
    resolved = [f for k, f in previous_keys.items() if k not in current_keys]
    persistent = [f for k, f in current_keys.items() if k in previous_keys]

    return ScanDiff(new=new, resolved=resolved, persistent=persistent)