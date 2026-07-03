"""Resolves subdomains to IPs and dedupes before persistence.
Called by worker.tasks.asset_discovery_task after subfinder/amass run."""
import socket
from sqlalchemy.orm import Session
from models.asset import Subdomain
from utils.logger import get_logger

logger = get_logger(__name__)


def resolve_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def persist_subdomains(domain_id: int, scan_id: int, names: set[str], db: Session) -> int:
    """Resolve IPs and insert new subdomains, skipping ones already recorded for this domain."""
    existing = {
        s.name for s in db.query(Subdomain.name).filter(Subdomain.domain_id == domain_id)
    }

    new_count = 0
    for name in names:
        if name in existing:
            continue
        ip = resolve_ip(name)
        db.add(Subdomain(domain_id=domain_id, scan_id=scan_id, name=name, ip_address=ip))
        existing.add(name)
        new_count += 1

    db.commit()
    logger.info(f"Persisted {new_count} new subdomains for domain {domain_id}")
    return new_count