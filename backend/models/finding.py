from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .user import Base


class Finding(Base):
    __tablename__ = "findings"

    id                   = Column(Integer, primary_key=True, index=True)
    scan_id              = Column(Integer, ForeignKey("scans.id"), nullable=False)
    cve_id               = Column(String, nullable=True, index=True)
    template_id          = Column(String, nullable=True)
    severity             = Column(String, nullable=False)
    cvss_score           = Column(Float, nullable=True)
    epss_score           = Column(Float, nullable=True)
    kev_status           = Column(Boolean, default=False)
    risk_score           = Column(Float, nullable=True)
    host                 = Column(String, nullable=False)
    port                 = Column(Integer, nullable=True)
    endpoint             = Column(String, nullable=True)
    evidence             = Column(String, nullable=True)
    description          = Column(String, nullable=True)
    patch_recommendation = Column(String, nullable=True)
    fix_version          = Column(String, nullable=True)
    is_false_positive    = Column(Boolean, default=False)
    is_resolved          = Column(Boolean, default=False)
    discovered_at        = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
