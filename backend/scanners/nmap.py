"""Nmap wrapper — service/version detection port scanning."""
import os
from scanners.base import BaseScannerWrapper
from utils.parser import parse_nmap_xml
from utils.subprocess import CommandResult

_RUNNING_IN_DOCKER = os.environ.get("RUNNING_IN_DOCKER", "").lower() in ("1", "true")


class NmapScanner(BaseScannerWrapper):
    binary_name = "nmap"
    default_timeout = 300

    def build_args(self, target: str, **kwargs) -> list[str]:
        base_args = [self.binary_name, "-sV", "-sC", "-O", "--open", "-T4", "-oX", "-", target]

        if _RUNNING_IN_DOCKER:
            return base_args
        return ["sudo", "-n"] + base_args

    def parse_output(self, result: CommandResult) -> list[dict]:
        return parse_nmap_xml(result.stdout)