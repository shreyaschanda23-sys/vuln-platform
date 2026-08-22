"""Masscan wrapper — fast port scanning."""
import os
import socket
from scanners.base import BaseScannerWrapper
from utils.parser import parse_masscan_json
from utils.subprocess import CommandResult

# Inside Docker, the worker container runs as root with NET_RAW/NET_ADMIN
# capabilities, so masscan doesn't need sudo at all. On the bare VM, it
# still needs "sudo -n" with the NOPASSWD sudoers rule we configured.
_RUNNING_IN_DOCKER = os.environ.get("RUNNING_IN_DOCKER", "").lower() in ("1", "true")


class MasscanScanner(BaseScannerWrapper):
    binary_name = "masscan"
    default_timeout = 300

    def build_args(self, target: str, **kwargs) -> list[str]:
        ports = kwargs.get("ports", "1-65535")
        rate = kwargs.get("rate", "1000")
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            ip = target

        base_args = [self.binary_name, ip, "-p", ports, "--rate", rate, "-oJ", "-"]

        if _RUNNING_IN_DOCKER:
            return base_args
        return ["sudo", "-n"] + base_args

    def parse_output(self, result: CommandResult) -> list[dict]:
        return parse_masscan_json(result.stdout)