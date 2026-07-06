from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from api.deps import get_db, get_current_user, require_role
from api.schemas import ScanCreate, ScanResponse
from models.scan import Scan, ScanStatus
from models.domain import Domain
from models.user import User, UserRole
from services.orchestrator import start_scan_pipeline
from services.diff import diff_scans
from worker.celery import celery_app

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _with_domain_name(scan: Scan, db: Session) -> Scan:
    scan.domain_name = db.query(Domain.name).filter(Domain.id == scan.domain_id).scalar()
    return scan


@router.get("", response_model=list[ScanResponse])
def list_scans(
    domain_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Scan)
    if domain_id is not None:
        query = query.filter(Scan.domain_id == domain_id)
    scans = query.order_by(Scan.started_at.desc()).all()
    return [_with_domain_name(s, db) for s in scans]


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
):
    domain = db.query(Domain).filter(Domain.id == payload.domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    scan = Scan(domain_id=domain.id, status=ScanStatus.pending, scanners=payload.scanners)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    start_scan_pipeline(scan.id, payload.scanners)

    return _with_domain_name(scan, db)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _with_domain_name(scan, db)


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in (ScanStatus.complete, ScanStatus.failed):
        raise HTTPException(status_code=400, detail="Scan already finished")

    if scan.task_id:
        celery_app.control.revoke(scan.task_id, terminate=True)

    scan.status = ScanStatus.failed
    scan.error_message = "Cancelled by user"
    db.commit()
    db.refresh(scan)
    return _with_domain_name(scan, db)


@router.get("/{scan_id}/diff")
def get_scan_diff(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    diff = diff_scans(scan_id, db)

    def _serialize(f):
        return {
            "id": f.id, "cve_id": f.cve_id, "severity": f.severity,
            "host": f.host, "endpoint": f.endpoint, "description": f.description,
        }

    return {
        "new": [_serialize(f) for f in diff.new],
        "resolved": [_serialize(f) for f in diff.resolved],
        "persistent": [_serialize(f) for f in diff.persistent],
    }