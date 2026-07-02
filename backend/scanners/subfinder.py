from scanners.base import BaseScannerWrapper
from utils.logger import get_logger

logger = get_logger(__name__)


class SubfinderScanner(BaseScannerWrapper):
    """
    Wrapper for subfinder — passive subdomain enumeration.
    https://github.com/projectdiscovery/subfinder
    """
    tool_name = "subfinder"
    timeout = 120

    def scan(self, target: str, **kwargs) -> list[dict]:
        """
        Run subfinder against a domain.
        Returns list of subdomains found.
        """
        command = [
            "subfinder",
            "-d", target,
            "-json",
            "-silent"
        ]

        logger.info(f"Starting subfinder scan on {target}")
        stdout, stderr, returncode = self.run(command)

        if returncode != 0 and not stdout:
            logger.error(f"subfinder failed: {stderr}")
            return []

        results = self.parse_json_lines(stdout)

        subdomains = []
        for item in results:
            subdomains.append({
                "host": item.get("host", ""),
                "source": item.get("source", "subfinder"),
                "ip": item.get("ip", ""),
                "tool": "subfinder"
            })

        logger.info(f"subfinder found {len(subdomains)} subdomains for {target}")
        return subdomains
