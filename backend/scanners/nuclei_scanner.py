from scanners.base import BaseScannerWrapper
from utils.logger import get_logger

logger = get_logger(__name__)


class NucleiScanner(BaseScannerWrapper):
    """
    Wrapper for nuclei — vulnerability scanning with templates.
    https://github.com/projectdiscovery/nuclei
    """
    tool_name = "nuclei"
    timeout = 600

    def scan(self, target: str, **kwargs) -> list[dict]:
        """
        Run nuclei against a target URL or list of URLs.
        Returns list of vulnerabilities found.
        """
        severity = kwargs.get("severity", "low,medium,high,critical")
        templates = kwargs.get("templates", None)

        command = [
            "nuclei",
            "-u", target,
            "-json",
            "-silent",
            "-severity", severity,
            "-no-interactsh"
        ]

        if templates:
            command.extend(["-t", templates])

        logger.info(f"Starting nuclei scan on {target}")
        stdout, stderr, returncode = self.run(command)

        if not stdout:
            return []

        results = self.parse_json_lines(stdout)

        findings = []
        for item in results:
            info = item.get("info", {})
            findings.append({
                "template_id": item.get("template-id", ""),
                "cve_id": item.get("template-id", "") if "CVE" in item.get("template-id", "").upper() else None,
                "severity": info.get("severity", "unknown"),
                "name": info.get("name", ""),
                "description": info.get("description", ""),
                "host": item.get("host", ""),
                "matched_at": item.get("matched-at", ""),
                "evidence": item.get("extracted-results", ""),
                "tool": "nuclei"
            })

        logger.info(f"nuclei found {len(findings)} vulnerabilities on {target}")
        return findings
