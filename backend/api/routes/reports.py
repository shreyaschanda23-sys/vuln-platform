from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.deps import get_db, get_current_user
from models.scan import Scan
from models.user import User

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{scan_id}/status")
def report_status(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Reports depend on services/reporter.py, which is built in Phase 8.
    This endpoint exists now so the frontend has a stable contract to
    build against; it returns 501 until that service is implemented."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    raise HTTPException(
        status_code=501,
        detail="Report generation not yet implemented (Phase 8)",
    )