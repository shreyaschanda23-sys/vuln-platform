from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from api.deps import get_db, get_current_user, require_role
from api.schemas import ScanCreate, ScanResponse
from models.scan import Scan, ScanStatus
from models.domain import Domain
from models.user import User, UserRole

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("", response_model=list[ScanResponse])
def list_scans(
    domain_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Scan)
    if domain_id is not None:
        query = query.filter(Scan.domain_id == domain_id)
    return query.order_by(Scan.started_at.desc()).all()


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
):
    domain = db.query(Domain).filter(Domain.id == payload.domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    scan = Scan(domain_id=domain.id, status=ScanStatus.pending)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Hook point for Phase 3's Celery orchestrator, e.g.:
    # from worker.tasks import run_scan_pipeline
    # run_scan_pipeline.delay(scan.id)

    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


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

    scan.status = ScanStatus.failed
    scan.error_message = "Cancelled by user"
    db.commit()
    db.refresh(scan)
    return scan