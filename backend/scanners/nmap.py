import xml.etree.ElementTree as ET
from scanners.base import BaseScannerWrapper
from utils.logger import get_logger

logger = get_logger(__name__)


class NmapScanner(BaseScannerWrapper):
    """
    Wrapper for nmap — port scanning and service detection.
    """
    tool_name = "nmap"
    timeout = 600  # 10 minutes for deep scans

    def scan(self, target: str, **kwargs) -> list[dict]:
        """
        Run nmap service scan against a target.
        Returns list of open ports with service info.
        """
        output_file = f"/tmp/nmap_{target.replace('.', '_')}.xml"

        command = [
            "nmap",
            "-sV",          # service version detection
            "-sC",          # default scripts
            "--open",       # only show open ports
            "-T4",          # aggressive timing
            "-oX", output_file,  # XML output
            target
        ]

        logger.info(f"Starting nmap scan on {target}")
        stdout, stderr, returncode = self.run(command)

        return self.parse_xml(output_file, target)

    def parse_xml(self, xml_file: str, target: str) -> list[dict]:
        """Parse nmap XML output into structured port data."""
        ports = []
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host in root.findall("host"):
                # get IP address
                address = host.find("address")
                ip = address.get("addr", target) if address is not None else target

                # get hostname
                hostnames = host.find("hostnames")
                hostname = ""
                if hostnames is not None:
                    hn = hostnames.find("hostname")
                    if hn is not None:
                        hostname = hn.get("name", "")

                # get ports
                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue

                for port in ports_elem.findall("port"):
                    state_elem = port.find("state")
                    if state_elem is None:
                        continue
                    if state_elem.get("state") != "open":
                        continue

                    service_elem = port.find("service")
                    service = ""
                    version = ""
                    if service_elem is not None:
                        service = service_elem.get("name", "")
                        product = service_elem.get("product", "")
                        ver = service_elem.get("version", "")
                        version = f"{product} {ver}".strip()

                    ports.append({
                        "host": ip,
                        "hostname": hostname,
                        "port_number": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", "tcp"),
                        "state": state_elem.get("state", "open"),
                        "service": service,
                        "version": version,
                        "tool": "nmap"
                    })

        except FileNotFoundError:
            logger.error(f"nmap XML output not found: {xml_file}")
        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML: {e}")

        logger.info(f"nmap found {len(ports)} open ports on {target}")
        return ports
