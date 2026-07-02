"""Masscan wrapper — fast port scanning."""
from scanners.base import BaseScannerWrapper
from utils.parser import parse_masscan_json
from utils.subprocess import CommandResult


class MasscanScanner(BaseScannerWrapper):
    binary_name = "masscan"
    default_timeout = 300

    def build_args(self, target: str, **kwargs) -> list[str]:
        ports = kwargs.get("ports", "1-65535")
        rate = kwargs.get("rate", "1000")
        return [
            "sudo", self.binary_name,
            target,
            "-p", ports,
            "--rate", rate,
            "-oJ", "-",
        ]

    def parse_output(self, result: CommandResult) -> list[dict]:
        return parse_masscan_json(result.stdout)