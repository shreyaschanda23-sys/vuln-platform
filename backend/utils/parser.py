"""
Output parsers for recon tool formats. Each scanner wrapper picks the
relevant function(s) here rather than parsing raw text inline.
"""
import json
import xml.etree.ElementTree as ET
from utils.logger import get_logger

logger = get_logger(__name__)


def parse_jsonl(raw: str) -> list[dict]:
    """Parse newline-delimited JSON (subfinder -oJ, httpx -json, nuclei -jsonl, etc.)."""
    results = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            logger.warning(f"Skipping malformed JSON line: {line[:100]}")
    return results


def parse_lines(raw: str) -> list[str]:
    """Plain newline-delimited text output (subfinder default, amass default)."""
    return [line.strip() for line in raw.strip().splitlines() if line.strip()]


def parse_nmap_xml(raw: str) -> list[dict]:
    """Parse nmap -oX output into a list of {host, port, protocol, service, version, state}."""
    results = []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        logger.error(f"Failed to parse nmap XML: {e}")
        return results

    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        host = addr_el.get("addr") if addr_el is not None else None
        if not host:
            continue

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            service_el = port_el.find("service")

            results.append({
                "host": host,
                "port_number": int(port_el.get("portid")),
                "protocol": port_el.get("protocol", "tcp"),
                "state": state_el.get("state") if state_el is not None else "unknown",
                "service": service_el.get("name") if service_el is not None else None,
                "version": service_el.get("product") if service_el is not None else None,
            })

    return results


def parse_masscan_json(raw: str) -> list[dict]:
    """Parse masscan -oJ output into {host, port_number, protocol}."""
    results = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse masscan JSON: {e}")
        return results

    for entry in data:
        host = entry.get("ip")
        for port_info in entry.get("ports", []):
            results.append({
                "host": host,
                "port_number": port_info.get("port"),
                "protocol": port_info.get("proto", "tcp"),
                "state": port_info.get("status", "open"),
            })

    return results