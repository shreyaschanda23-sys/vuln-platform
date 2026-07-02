"""Dalfox wrapper — XSS scanning."""
from scanners.base import BaseScannerWrapper
from utils.parser import parse_jsonl
from utils.subprocess import CommandResult


class DalfoxScanner(BaseScannerWrapper):
    binary_name = "dalfox"
    default_timeout = 300

    def build_args(self, target: str, **kwargs) -> list[str]:
        return [self.binary_name, "url", target, "--format", "json", "--silence"]

    def parse_output(self, result: CommandResult) -> list[dict]:
        entries = parse_jsonl(result.stdout)
        return [
            {
                "template_id": "dalfox-xss",
                "severity": "high",
                "endpoint": e.get("data"),
                "evidence": e.get("evidence") or e.get("param"),
                "description": f"XSS detected via {e.get('type', 'unknown')}",
            }
            for e in entries
        ]