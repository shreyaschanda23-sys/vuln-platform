from scanners.subfinder import SubfinderScanner
from utils.subprocess import CommandResult


def _result(stdout: str) -> CommandResult:
    return CommandResult(command="subfinder", returncode=0, stdout=stdout, stderr="")


def test_parses_jsonl_output():
    scanner = SubfinderScanner()
    stdout = (
        '{"host":"mail.example.com","source":"crtsh"}\n'
        '{"host":"www.example.com","source":"dns"}\n'
    )
    parsed = scanner.parse_output(_result(stdout))
    assert len(parsed) == 2
    assert parsed[0]["name"] == "mail.example.com"
    assert parsed[0]["source"] == "crtsh"


def test_skips_entries_without_host():
    scanner = SubfinderScanner()
    stdout = '{"source":"crtsh"}\n{"host":"valid.example.com","source":"dns"}\n'
    parsed = scanner.parse_output(_result(stdout))
    assert len(parsed) == 1
    assert parsed[0]["name"] == "valid.example.com"


def test_empty_output_returns_empty_list():
    scanner = SubfinderScanner()
    parsed = scanner.parse_output(_result(""))
    assert parsed == []