"""Amass wrapper — passive/active subdomain enumeration."""
from scanners.base import BaseScannerWrapper
from utils.parser import parse_lines
from utils.subprocess import CommandResult


class AmassScanner(BaseScannerWrapper):
    binary_name = "amass"
    default_timeout = 300

    def build_args(self, target: str, **kwargs) -> list[str]:
        mode = kwargs.get("mode", "enum")
        args = [self.binary_name, mode, "-passive", "-d", target, "-silent"]
        if kwargs.get("active"):
            args.remove("-passive")
        return args

    def parse_output(self, result: CommandResult) -> list[dict]:
        names = parse_lines(result.stdout)
        return [{"name": n, "source": "amass"} for n in names]