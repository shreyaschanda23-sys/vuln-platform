from utils.dedup import dedup_within_scan


def test_removes_exact_duplicates(db_session, scan_factory, finding_factory):
    scan = scan_factory()
    finding_factory(scan.id, host="1.2.3.4", port=443, endpoint=None, cve_id="CVE-2024-0001")
    finding_factory(scan.id, host="1.2.3.4", port=443, endpoint=None, cve_id="CVE-2024-0001")

    removed = dedup_within_scan(scan.id, db_session)
    assert removed == 1


def test_keeps_distinct_findings(db_session, scan_factory, finding_factory):
    scan = scan_factory()
    finding_factory(scan.id, host="1.2.3.4", port=443, cve_id="CVE-2024-0001")
    finding_factory(scan.id, host="1.2.3.4", port=8443, cve_id="CVE-2024-0002")

    removed = dedup_within_scan(scan.id, db_session)
    assert removed == 0


def test_dedup_is_idempotent(db_session, scan_factory, finding_factory):
    scan = scan_factory()
    finding_factory(scan.id, host="1.2.3.4", port=443, cve_id="CVE-2024-0001")
    finding_factory(scan.id, host="1.2.3.4", port=443, cve_id="CVE-2024-0001")

    dedup_within_scan(scan.id, db_session)
    second_pass_removed = dedup_within_scan(scan.id, db_session)
    assert second_pass_removed == 0