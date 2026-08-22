from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from .user import Base
import enum


class ScanStatus(str, enum.Enum):
    pending  = "pending"
    running  = "running"
    complete = "complete"
    failed   = "failed"


class ScanStage(str, enum.Enum):
    asset_discovery = "asset_discovery"
    recon           = "recon"
    port_scan       = "port_scan"
    live_hosts      = "live_hosts"
    crawl           = "crawl"
    vuln_scan       = "vuln_scan"
    validation      = "validation"
    enrichment      = "enrichment"
    scoring         = "scoring"
    complete        = "complete"


class Scan(Base):
    __tablename__ = "scans"

    id            = Column(Integer, primary_key=True, index=True)
    domain_id     = Column(Integer, ForeignKey("domains.id"), nullable=False)
    status        = Column(Enum(ScanStatus), default=ScanStatus.pending)
    current_stage = Column(Enum(ScanStage), nullable=True)
    started_at    = Column(DateTime, default=datetime.utcnow)
    finished_at   = Column(DateTime, nullable=True)
    error_message = Column(String, nullable=True)
    scanners      = Column(JSON, nullable=True)   # already exists in DB — now declared on the model
    task_id       = Column(String, nullable=True) # NEW
    emails_found  = Column(JSON, nullable=True)   # NEW

    domain   = relationship("Domain", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")