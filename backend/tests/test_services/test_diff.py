from datetime import datetime, timedelta
from services.diff import diff_scans


def test_first_scan_has_no_previous_all_new(db_session, scan_factory, finding_factory):
    scan = scan_factory(started_at=datetime.utcnow())
    finding_factory(scan.id, host="1.2.3.4", cve_id="CVE-2024-0001")

    result = diff_scans(scan.id, db_session)
    assert len(result.new) == 1
    assert len(result.resolved) == 0
    assert len(result.persistent) == 0


def test_detects_new_and_resolved(db_session, scan_factory, finding_factory):
    old_scan = scan_factory(started_at=datetime.utcnow() - timedelta(days=1))
    finding_factory(old_scan.id, host="1.2.3.4", cve_id="CVE-2024-0001")

    new_scan = scan_factory(started_at=datetime.utcnow())
    finding_factory(new_scan.id, host="1.2.3.4", cve_id="CVE-2024-0002")

    result = diff_scans(new_scan.id, db_session)
    assert len(result.new) == 1
    assert result.new[0].cve_id == "CVE-2024-0002"
    assert len(result.resolved) == 1
    assert result.resolved[0].cve_id == "CVE-2024-0001"


def test_detects_persistent_findings(db_session, scan_factory, finding_factory):
    old_scan = scan_factory(started_at=datetime.utcnow() - timedelta(days=1))
    finding_factory(old_scan.id, host="1.2.3.4", port=443, cve_id="CVE-2024-0001")

    new_scan = scan_factory(started_at=datetime.utcnow())
    finding_factory(new_scan.id, host="1.2.3.4", port=443, cve_id="CVE-2024-0001")

    result = diff_scans(new_scan.id, db_session)
    assert len(result.persistent) == 1
    assert len(result.new) == 0
    assert len(result.resolved) == 0