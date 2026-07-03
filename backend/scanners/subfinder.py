"""Subfinder wrapper — passive subdomain enumeration."""
from scanners.base import BaseScannerWrapper
from utils.parser import parse_jsonl
from utils.subprocess import CommandResult


class SubfinderScanner(BaseScannerWrapper):
    binary_name = "subfinder"
    default_timeout = 180

    def build_args(self, target: str, **kwargs) -> list[str]:
        return [
            self.binary_name,
            "-d", target,
            "-json",
            "-silent",
        ]

    def parse_output(self, result: CommandResult) -> list[dict]:
        entries = parse_jsonl(result.stdout)
        return [
            {"name": e.get("host"), "source": e.get("source")}
            for e in entries
            if e.get("host")
        ]
