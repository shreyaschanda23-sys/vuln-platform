from services.validator import validate_finding
from models.finding import Finding


def test_flags_weak_evidence_and_unresolved_cve():
    f = Finding(host="1.2.3.4", severity="medium", evidence="", cve_id="CVE-2024-9999", cvss_score=None)
    assert validate_finding(f) is False
    assert f.is_false_positive is True


def test_valid_finding_passes():
    f = Finding(host="1.2.3.4", severity="high", evidence="Confirmed via response reflection", cve_id="CVE-2024-0001", cvss_score=8.5, template_id="real-template")
    assert validate_finding(f) is True
    assert f.is_false_positive is False


def test_noisy_template_alone_not_enough_to_flag():
    f = Finding(host="1.2.3.4", severity="low", evidence="Confirmed via multiple payloads and timing", template_id="tech-detect")
    # only one weak signal (noisy template) — needs 2+ to flag
    assert validate_finding(f) is True