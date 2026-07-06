from pydantic import BaseModel, EmailStr
from datetime import datetime
from models.user import UserRole
from models.scan import ScanStatus, ScanStage


# ---- Auth ----
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: int
    email: str
    role: UserRole
    is_active: bool

    class Config:
        from_attributes = True


# ---- Domains ----
class DomainCreate(BaseModel):
    name: str
    description: str | None = None


class DomainResponse(BaseModel):
    id: int
    name: str
    description: str | None
    is_active: bool
    created_at: datetime
    last_scanned_at: datetime | None

    class Config:
        from_attributes = True


# ---- Scans ----
class ScanCreate(BaseModel):
    domain_id: int
    scanners: list[str] | None = None  # None = run all


class ScanResponse(BaseModel):
    id: int
    domain_id: int
    domain_name: str
    status: ScanStatus
    current_stage: ScanStage | None
    started_at: datetime
    finished_at: datetime | None
    error_message: str | None

    class Config:
        from_attributes = True


# ---- Findings ----
class FindingResponse(BaseModel):
    id: int
    scan_id: int
    cve_id: str | None
    template_id: str | None
    severity: str
    cvss_score: float | None
    epss_score: float | None
    kev_status: bool
    risk_score: float | None
    host: str
    port: int | None
    endpoint: str | None
    evidence: str | None
    description: str | None
    patch_recommendation: str | None
    fix_version: str | None
    is_false_positive: bool
    is_resolved: bool
    discovered_at: datetime

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    is_false_positive: bool | None = None
    is_resolved: bool | None = None


class PaginatedFindings(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[FindingResponse]