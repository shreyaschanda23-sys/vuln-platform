from services.scoring import calculate_risk_score
from models.finding import Finding


def _finding(**kwargs):
    defaults = dict(
        cvss_score=None, epss_score=None, kev_status=False,
        severity="medium", endpoint=None, port=None, is_false_positive=False,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def test_false_positive_scores_zero():
    f = _finding(cvss_score=9.0, is_false_positive=True)
    assert calculate_risk_score(f) == 0.0


def test_kev_enforces_floor():
    f = _finding(cvss_score=2.0, epss_score=0.01, kev_status=True)
    assert calculate_risk_score(f) >= 90.0


def test_higher_cvss_scores_higher():
    low = _finding(cvss_score=2.0)
    high = _finding(cvss_score=9.5)
    assert calculate_risk_score(high) > calculate_risk_score(low)


def test_web_endpoint_scores_higher_than_port_only():
    web = _finding(cvss_score=5.0, endpoint="/login")
    port_only = _finding(cvss_score=5.0, port=443)
    assert calculate_risk_score(web) > calculate_risk_score(port_only)


def test_missing_cvss_falls_back_to_severity():
    f = _finding(cvss_score=None, severity="critical")
    assert calculate_risk_score(f) > 0


def test_score_never_exceeds_100():
    f = _finding(cvss_score=10.0, epss_score=1.0, kev_status=True, endpoint="/x")
    assert calculate_risk_score(f) <= 100.0