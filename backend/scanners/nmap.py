"""Nmap wrapper — service/version detection on discovered ports."""
from scanners.base import BaseScannerWrapper
from utils.parser import parse_nmap_xml
from utils.subprocess import CommandResult


class NmapScanner(BaseScannerWrapper):
    binary_name = "nmap"
    default_timeout = 600

    def build_args(self, target: str, **kwargs) -> list[str]:
        ports = kwargs.get("ports", "")
        args = [self.binary_name, "-sV", "-sC", "--open", "-T4", "-oX", "-"]
        if ports:
            args += ["-p", ports]
        args.append(target)
        return args

    def parse_output(self, result: CommandResult) -> list[dict]:
        return parse_nmap_xml(result.stdout)