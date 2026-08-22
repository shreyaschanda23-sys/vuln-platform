from scanners.nuclei_scanner import NucleiScanner
from utils.subprocess import CommandResult


def _result(stdout: str) -> CommandResult:
    return CommandResult(command="nuclei", returncode=0, stdout=stdout, stderr="")


def test_parses_finding_with_cve():
    scanner = NucleiScanner()
    stdout = (
        '{"template-id":"CVE-2023-0001","host":"https://example.com",'
        '"matched-at":"https://example.com/login",'
        '"info":{"severity":"high","description":"Test vuln",'
        '"classification":{"cve-id":["CVE-2023-0001"]}}}\n'
    )
    parsed = scanner.parse_output(_result(stdout))
    assert len(parsed) == 1
    assert parsed[0]["severity"] == "high"
    assert parsed[0]["host"] == "https://example.com"


def test_parses_finding_without_cve():
    scanner = NucleiScanner()
    stdout = '{"template-id":"tech-detect","host":"https://example.com","info":{"severity":"info","description":"Tech detected"}}\n'
    parsed = scanner.parse_output(_result(stdout))
    assert len(parsed) == 1
    assert parsed[0]["cve_id"] is None


def test_empty_output_returns_empty_list():
    scanner = NucleiScanner()
    parsed = scanner.parse_output(_result(""))
    assert parsed == []
