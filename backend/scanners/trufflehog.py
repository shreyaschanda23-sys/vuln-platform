"""TruffleHog wrapper — secret detection in repos/filesystems."""
import json
from scanners.base import BaseScannerWrapper
from utils.subprocess import CommandResult


class TrufflehogScanner(BaseScannerWrapper):
    binary_name = "trufflehog"
    default_timeout = 300

    def build_args(self, target: str, **kwargs) -> list[str]:
        source_type = kwargs.get("source_type", "git")
        return [
            self.binary_name,
            source_type,
            target,
            "--json",
            "--no-update",
        ]

    def parse_output(self, result: CommandResult) -> list[dict]:
        findings = []
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            detector = entry.get("DetectorName", "unknown")
            findings.append({
                "template_id": f"trufflehog-{detector}",
                "severity": "high",
                "description": f"Exposed secret detected: {detector}",
                "evidence": entry.get("Raw", "")[:200],
                "endpoint": entry.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file"),
            })
        return findings
    