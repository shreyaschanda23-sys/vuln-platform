from scanners.masscan import MasscanScanner
from utils.subprocess import CommandResult


def _result(stdout: str) -> CommandResult:
    return CommandResult(command="masscan", returncode=0, stdout=stdout, stderr="")


def test_parses_masscan_json():
    scanner = MasscanScanner()
    stdout = '[{"ip":"1.2.3.4","ports":[{"port":443,"proto":"tcp","status":"open"}]}]'
    parsed = scanner.parse_output(_result(stdout))
    assert len(parsed) == 1
    assert parsed[0]["host"] == "1.2.3.4"
    assert parsed[0]["port_number"] == 443


def test_empty_result_no_crash():
    scanner = MasscanScanner()
    parsed = scanner.parse_output(_result(""))
    assert parsed == []


def test_bracket_only_output_no_crash():
    scanner = MasscanScanner()
    parsed = scanner.parse_output(_result("[]"))
    assert parsed == []


def test_resolves_hostname_to_ip():
    scanner = MasscanScanner()
    args = scanner.build_args("scanme.nmap.org")
    # first non-flag arg after 'sudo masscan' should be resolved to an IP, not the raw hostname
    assert "scanme.nmap.org" not in args
