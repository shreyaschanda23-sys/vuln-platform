from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import get_db, get_current_user, require_role
from models.domain import Domain
from models.user import User, UserRole
from services.scheduler import add_recurring_scan, remove_recurring_scan, list_scheduled_jobs

router = APIRouter(prefix="/api/scheduler", tags=["scheduler"])


class ScheduleRequest(BaseModel):
    domain_id: int
    frequency: str  # daily | weekly | monthly
    scanners: list[str] | None = None


@router.get("")
def list_jobs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return list_scheduled_jobs()


@router.post("")
def create_schedule(
    payload: ScheduleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
):
    domain = db.query(Domain).filter(Domain.id == payload.domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    try:
        job_id = add_recurring_scan(payload.domain_id, payload.frequency, payload.scanners)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"job_id": job_id}


@router.delete("/{job_id}")
def delete_schedule(
    job_id: str,
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
):
    remove_recurring_scan(job_id)
    return {"status": "removed"}