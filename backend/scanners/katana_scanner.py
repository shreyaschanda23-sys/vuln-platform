"""Katana wrapper — web crawler for endpoint discovery."""
from scanners.base import BaseScannerWrapper
from utils.parser import parse_lines
from utils.subprocess import CommandResult


class KatanaScanner(BaseScannerWrapper):
    binary_name = "katana"
    default_timeout = 300

    def build_args(self, target: str, **kwargs) -> list[str]:
        depth = kwargs.get("depth", "3")
        return [
            self.binary_name,
            "-u", target,
            "-d", depth,
            "-silent",
            "-jc",
        ]

    def parse_output(self, result: CommandResult) -> list[dict]:
        urls = parse_lines(result.stdout)
        return [{"url": u} for u in urls]