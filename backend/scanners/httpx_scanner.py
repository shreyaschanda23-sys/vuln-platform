from scanners.base import BaseScannerWrapper
from utils.logger import get_logger

logger = get_logger(__name__)


class HttpxScanner(BaseScannerWrapper):
    """
    Wrapper for httpx — HTTP probing and tech detection.
    https://github.com/projectdiscovery/httpx
    """
    tool_name = "httpx"
    timeout = 120

    def is_installed(self) -> bool:
        """Override to check Go bin path."""
        import subprocess
        for path in ["httpx", "/home/whyyy/go/bin/httpx"]:
            try:
                result = subprocess.run(
                    [path, "-version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    self._httpx_path = path
                    return True
            except Exception:
                continue
        return False

    def scan(self, target: str, **kwargs) -> list[dict]:
        """
        Probe a list of URLs or a single target with httpx.
        Returns list of live endpoints with metadata.
        """
        httpx_path = getattr(self, '_httpx_path', '/home/whyyy/go/bin/httpx')

        command = [
            httpx_path,
            "-u", target,
            "-json",
            "-silent",
            "-title",
            "-tech-detect",
            "-status-code",
            "-follow-redirects"
        ]

        logger.info(f"Starting httpx probe on {target}")
        stdout, stderr, returncode = self.run(command)

        if not stdout:
            return []

        results = self.parse_json_lines(stdout)

        endpoints = []
        for item in results:
            endpoints.append({
                "url": item.get("url", ""),
                "status_code": item.get("status_code", 0),
                "title": item.get("title", ""),
                "tech_stack": ", ".join(item.get("tech", [])),
                "is_live": True,
                "tool": "httpx"
            })

        logger.info(f"httpx found {len(endpoints)} live endpoints")
        return endpoints
