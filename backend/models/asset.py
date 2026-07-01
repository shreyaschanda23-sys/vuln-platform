from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from .user import Base


class Subdomain(Base):
    __tablename__ = "subdomains"

    id            = Column(Integer, primary_key=True, index=True)
    domain_id     = Column(Integer, ForeignKey("domains.id"), nullable=False)
    scan_id       = Column(Integer, ForeignKey("scans.id"), nullable=False)
    name          = Column(String, nullable=False)
    ip_address    = Column(String, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    domain = relationship("Domain", back_populates="assets")


class Port(Base):
    __tablename__ = "ports"

    id          = Column(Integer, primary_key=True, index=True)
    scan_id     = Column(Integer, ForeignKey("scans.id"), nullable=False)
    host        = Column(String, nullable=False)
    port_number = Column(Integer, nullable=False)
    protocol    = Column(String, default="tcp")
    service     = Column(String, nullable=True)
    version     = Column(String, nullable=True)
    state       = Column(String, default="open")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id              = Column(Integer, primary_key=True, index=True)
    scan_id         = Column(Integer, ForeignKey("scans.id"), nullable=False)
    url             = Column(String, nullable=False)
    status_code     = Column(Integer, nullable=True)
    title           = Column(String, nullable=True)
    tech_stack      = Column(String, nullable=True)
    is_live         = Column(Boolean, default=True)
    screenshot_path = Column(String, nullable=True)

