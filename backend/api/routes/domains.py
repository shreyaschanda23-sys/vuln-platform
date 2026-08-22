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
from models.finding import Finding
import whois
import dns.resolver

router = APIRouter(prefix="/api/domains", tags=["domains"])


def normalize_domain(name: str) -> str:
    name = name.strip()
    if "://" in name:
        name = urlparse(name).netloc or name
    return name.rstrip("/")


def get_dns_records(domain_name: str) -> dict:
    records = {}
    for rtype in ("A", "AAAA", "MX", "TXT", "NS"):
        try:
            answers = dns.resolver.resolve(domain_name, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []
    return records


def get_whois_info(domain_name: str) -> dict:
    try:
        w = whois.whois(domain_name)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "org": w.org,
            "name_servers": w.name_servers,
        }
    except Exception:
        return {}


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
        return {"subdomains": [], "ports": [], "endpoints": [], "technologies": [], "dns": {}, "whois": {}}

    subdomains = db.query(Subdomain).filter(Subdomain.scan_id == latest_scan.id).all()
    ports = db.query(Port).filter(Port.scan_id == latest_scan.id).all()
    endpoints = db.query(Endpoint).filter(Endpoint.scan_id == latest_scan.id).all()

    tech_set = set()
    for e in endpoints:
        if e.tech_stack:
            tech_set.update(e.tech_stack.split(","))

    finding_counts = {}
    findings = db.query(Finding).filter(Finding.scan_id == latest_scan.id).all()
    for f in findings:
        finding_counts[f.severity] = finding_counts.get(f.severity, 0) + 1

    return {
        "subdomains": [{"name": s.name, "ip_address": s.ip_address} for s in subdomains],
        "ports": [{"host": p.host, "port": p.port_number, "service": p.service, "version": p.version} for p in ports],
        "endpoints": [{"url": e.url, "status_code": e.status_code, "title": e.title} for e in endpoints],
        "technologies": list(tech_set),
        "dns": get_dns_records(domain.name),
        "whois": get_whois_info(domain.name),
        "vulnerability_counts": finding_counts,
        "emails": latest_scan.emails_found or [],
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