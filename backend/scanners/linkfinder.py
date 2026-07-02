"""LinkFinder wrapper — extracts endpoints from JS files."""
import re
from scanners.base import BaseScannerWrapper
from utils.subprocess import CommandResult


class LinkFinderScanner(BaseScannerWrapper):
    binary_name = "linkfinder"
    default_timeout = 120

    def build_args(self, target: str, **kwargs) -> list[str]:
        return [
            self.binary_name,
            "-i", target,
            "-o", "cli",
        ]

    def parse_output(self, result: CommandResult) -> list[dict]:
        endpoints = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("[") and re.match(r"^[/\w].*", line):
                endpoints.add(line)
        return [{"url": e} for e in endpoints]