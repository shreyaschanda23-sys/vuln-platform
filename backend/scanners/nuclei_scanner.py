"""Nuclei wrapper — CVE/misconfig template-based vulnerability scanning."""
from scanners.base import BaseScannerWrapper
from utils.parser import parse_jsonl
from utils.subprocess import CommandResult


class NucleiScanner(BaseScannerWrapper):
    binary_name = "nuclei"
    default_timeout = 900

    def build_args(self, target: str, **kwargs) -> list[str]:
        severity = kwargs.get("severity", "critical,high,medium,low")
        args = [
            self.binary_name,
            "-u", target,
            "-jsonl",
            "-silent",
            "-severity", severity,
        ]
        tags = kwargs.get("tags")
        if tags:
            args += ["-tags", tags]
        return args

    def parse_output(self, result: CommandResult) -> list[dict]:
        entries = parse_jsonl(result.stdout)
        findings = []
        for e in entries:
            info = e.get("info", {})
            findings.append({
                "template_id": e.get("template-id"),
                "severity": info.get("severity"),
                "host": e.get("host"),
                "endpoint": e.get("matched-at"),
                "description": info.get("description"),
                "cve_id": (info.get("classification") or {}).get("cve-id", [None])[0]
                    if isinstance((info.get("classification") or {}).get("cve-id"), list)
                    else (info.get("classification") or {}).get("cve-id"),
                "evidence": e.get("extracted-results") and ",".join(e["extracted-results"]),
            })
        return findings