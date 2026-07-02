from scanners.base import BaseScannerWrapper
from utils.logger import get_logger

logger = get_logger(__name__)


class SqlmapScanner(BaseScannerWrapper):
    """
    Wrapper for sqlmap — SQL injection detection.
    """
    tool_name = "sqlmap"
    timeout = 300

    def scan(self, target: str, **kwargs) -> list[dict]:
        """
        Run sqlmap against a target URL.
        Returns list of SQL injection findings.
        """
        command = [
            "sqlmap",
            "-u", target,
            "--batch",
            "--output-dir=/tmp/sqlmap",
            "--forms",
            "--level=2",
            "--risk=1",
            "--json-output=/tmp/sqlmap_output.json",
            "--quiet"
        ]

        logger.info(f"Starting sqlmap scan on {target}")
        stdout, stderr, returncode = self.run(command)

        findings = []
        if "injectable" in stdout.lower() or "vulnerable" in stdout.lower():
            findings.append({
                "host": target,
                "severity": "high",
                "template_id": "sqli-detected",
                "description": "SQL injection vulnerability detected by sqlmap",
                "evidence": stdout[:500],
                "tool": "sqlmap"
            })

        logger.info(f"sqlmap found {len(findings)} SQLi issues on {target}")
        return findings
