"""Resolves subdomains to IPs and dedupes before persistence.
Called by worker.tasks.asset_discovery_task after subfinder/amass run."""
import re
import socket
from sqlalchemy.orm import Session
from models.asset import Subdomain
from utils.logger import get_logger

logger = get_logger(__name__)

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

_DNS_TIMEOUT_SECONDS = 3.0


def extract_emails_from_text(text: str) -> set[str]:
    return set(EMAIL_RE.findall(text))


def resolve_ip(hostname: str) -> str | None:
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(_DNS_TIMEOUT_SECONDS)
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.timeout, UnicodeError, OSError) as e:
        logger.debug(f"DNS resolution failed for {hostname}: {e}")
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def persist_subdomains(domain_id: int, scan_id: int, names: set[str], db: Session) -> int:
    """Resolve IPs and insert new subdomains, skipping ones already recorded
    for this domain across ALL scans (not just the current one). This is
    what prevents recurring scans from re-inserting duplicate subdomain
    rows every run."""
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
    logger.info(f"Persisted {new_count} new subdomains for domain {domain_id} (out of {len(names)} discovered)")
    return new_count