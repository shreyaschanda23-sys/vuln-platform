from scanners.nmap import NmapScanner
from utils.subprocess import CommandResult

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def _result(stdout: str) -> CommandResult:
    return CommandResult(command="nmap", returncode=0, stdout=stdout, stderr="")


def test_parses_open_ports():
    scanner = NmapScanner()
    parsed = scanner.parse_output(_result(SAMPLE_XML))
    assert len(parsed) == 2
    assert parsed[0]["host"] == "192.168.1.1"
    assert parsed[0]["port_number"] == 80
    assert parsed[0]["service"] == "http"


def test_malformed_xml_returns_empty_list():
    scanner = NmapScanner()
    parsed = scanner.parse_output(_result("<not valid xml"))
    assert parsed == []


def test_empty_xml_returns_empty_list():
    scanner = NmapScanner()
    parsed = scanner.parse_output(_result("<nmaprun></nmaprun>"))
    assert parsed == []