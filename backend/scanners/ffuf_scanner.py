from scanners.base import BaseScannerWrapper
from utils.logger import get_logger

logger = get_logger(__name__)


class FfufScanner(BaseScannerWrapper):
    """
    Wrapper for ffuf — directory and path bruteforcing.
    """
    tool_name = "ffuf"
    timeout = 300

    def scan(self, target: str, **kwargs) -> list[dict]:
        """
        Run ffuf directory bruteforce on a target.
        Returns list of discovered paths.
        """
        wordlist = kwargs.get(
            "wordlist",
            "/usr/share/wordlists/dirb/common.txt"
        )

        url = target.rstrip("/") + "/FUZZ"

        command = [
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-json",
            "-silent",
            "-mc", "200,201,204,301,302,403"
        ]

        logger.info(f"Starting ffuf scan on {target}")
        stdout, stderr, returncode = self.run(command)

        if not stdout:
            return []

        data = self.parse_json(stdout)
        results = data.get("results", [])

        endpoints = []
        for item in results:
            endpoints.append({
                "url": item.get("url", ""),
                "status_code": item.get("status", 0),
                "length": item.get("length", 0),
                "tool": "ffuf"
            })

        logger.info(f"ffuf found {len(endpoints)} paths on {target}")
        return endpoints
