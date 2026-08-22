"""Shared pytest fixtures: in-memory SQLite DB, isolated per test."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models.user import Base
from models.domain import Domain
from models.scan import Scan, ScanStatus
from models.finding import Finding


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def domain(db_session):
    d = Domain(name="example-test.com")
    db_session.add(d)
    db_session.commit()
    db_session.refresh(d)
    return d


@pytest.fixture
def scan_factory(db_session, domain):
    def _make(status=ScanStatus.complete, started_at=None):
        s = Scan(domain_id=domain.id, status=status)
        if started_at:
            s.started_at = started_at
        db_session.add(s)
        db_session.commit()
        db_session.refresh(s)
        return s
    return _make


@pytest.fixture
def finding_factory(db_session):
    def _make(scan_id, **kwargs):
        defaults = dict(
            scan_id=scan_id, host="1.2.3.4", severity="medium",
            is_false_positive=False, is_resolved=False,
        )
        defaults.update(kwargs)
        f = Finding(**defaults)
        db_session.add(f)
        db_session.commit()
        db_session.refresh(f)
        return f
    return _make