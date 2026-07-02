"""sqlmap wrapper — SQL injection detection."""
from scanners.base import BaseScannerWrapper
from utils.subprocess import CommandResult


class SqlmapScanner(BaseScannerWrapper):
    binary_name = "sqlmap"
    default_timeout = 600

    def build_args(self, target: str, **kwargs) -> list[str]:
        return [
            self.binary_name,
            "-u", target,
            "--batch",
            "--random-agent",
            "--level", str(kwargs.get("level", 1)),
            "--risk", str(kwargs.get("risk", 1)),
            "--output-dir", "/tmp/sqlmap",
        ]

    def parse_output(self, result: CommandResult) -> list[dict]:
        vulnerable = "sqlmap identified the following injection point" in result.stdout \
            or "Parameter:" in result.stdout

        if not vulnerable:
            return []

        params = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Parameter:"):
                params.append(line.replace("Parameter:", "").strip())

        return [{
            "template_id": "sqlmap-sqli",
            "severity": "high",
            "evidence": ", ".join(params) if params else "SQL injection confirmed",
            "description": "SQL injection vulnerability detected by sqlmap",
        }]