from scanners.base import BaseScannerWrapper
from utils.logger import get_logger

logger = get_logger(__name__)


class KatanaScanner(BaseScannerWrapper):
    """
    Wrapper for katana — web crawling and endpoint discovery.
    https://github.com/projectdiscovery/katana
    """
    tool_name = "katana"
    timeout = 180

    def scan(self, target: str, **kwargs) -> list[dict]:
        """
        Crawl a target URL and extract endpoints.
        Returns list of discovered URLs.
        """
        depth = kwargs.get("depth", 3)

        command = [
            "katana",
            "-u", target,
            "-json",
            "-silent",
            "-depth", str(depth),
            "-js-crawl",
            "-no-color"
        ]

        logger.info(f"Starting katana crawl on {target}")
        stdout, stderr, returncode = self.run(command)

        if not stdout:
            return []

        results = self.parse_json_lines(stdout)

        endpoints = []
        for item in results:
            endpoints.append({
                "url": item.get("endpoint", ""),
                "source": item.get("source", ""),
                "tool": "katana"
            })

        logger.info(f"katana found {len(endpoints)} endpoints on {target}")
        return endpoints
