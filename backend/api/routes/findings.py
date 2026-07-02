from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.deps import get_db, get_current_user
from api.schemas import FindingResponse, FindingUpdate, PaginatedFindings
from models.finding import Finding
from models.user import User

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=PaginatedFindings)
def list_findings(
    scan_id: int | None = None,
    domain_id: int | None = None,
    severity: str | None = None,
    is_resolved: bool | None = None,
    is_false_positive: bool | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Finding)

    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)

    if domain_id is not None:
        from models.scan import Scan
        query = query.join(Scan, Finding.scan_id == Scan.id).filter(Scan.domain_id == domain_id)

    if severity is not None:
        query = query.filter(Finding.severity == severity)

    if is_resolved is not None:
        query = query.filter(Finding.is_resolved == is_resolved)

    if is_false_positive is not None:
        query = query.filter(Finding.is_false_positive == is_false_positive)

    total = query.count()
    items = (
        query.order_by(Finding.risk_score.desc().nullslast())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return PaginatedFindings(total=total, limit=limit, offset=offset, items=items)


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding(
    finding_id: int,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if payload.is_false_positive is not None:
        finding.is_false_positive = payload.is_false_positive
    if payload.is_resolved is not None:
        finding.is_resolved = payload.is_resolved

    db.commit()
    db.refresh(finding)
    return finding