from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from urllib.parse import urlparse

from api.deps import get_db, get_current_user, require_role
from api.schemas import DomainCreate, DomainResponse
from models.domain import Domain
from models.user import User, UserRole
from models.asset import Subdomain, Port, Endpoint
from models.scan import Scan

router = APIRouter(prefix="/api/domains", tags=["domains"])


def normalize_domain(name: str) -> str:
    name = name.strip()
    if "://" in name:
        name = urlparse(name).netloc or name
    return name.rstrip("/")


@router.get("", response_model=list[DomainResponse])
def list_domains(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return db.query(Domain).order_by(Domain.created_at.desc()).all()


@router.post("", response_model=DomainResponse, status_code=status.HTTP_201_CREATED)
def create_domain(
    payload: DomainCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.analyst)),
):
    domain = Domain(name=normalize_domain(payload.name), description=payload.description)
    db.add(domain)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Domain already exists")
    db.refresh(domain)
    return domain


@router.get("/{domain_id}", response_model=DomainResponse)
def get_domain(
    domain_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    return domain


@router.get("/{domain_id}/assets")
def get_domain_assets(
    domain_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    latest_scan = (
        db.query(Scan).filter(Scan.domain_id == domain_id)
        .order_by(Scan.started_at.desc()).first()
    )
    if not latest_scan:
        return {"subdomains": [], "ports": [], "endpoints": []}

    subdomains = db.query(Subdomain).filter(Subdomain.scan_id == latest_scan.id).all()
    ports = db.query(Port).filter(Port.scan_id == latest_scan.id).all()
    endpoints = db.query(Endpoint).filter(Endpoint.scan_id == latest_scan.id).all()

    return {
        "subdomains": [{"name": s.name, "ip_address": s.ip_address} for s in subdomains],
        "ports": [{"host": p.host, "port": p.port_number, "service": p.service} for p in ports],
        "endpoints": [{"url": e.url, "status_code": e.status_code, "title": e.title} for e in endpoints],
    }


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_domain(
    domain_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    db.delete(domain)
    db.commit()