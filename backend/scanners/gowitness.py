"""Gowitness wrapper — screenshot capture for live hosts."""
import os
from scanners.base import BaseScannerWrapper
from utils.subprocess import CommandResult


class GowitnessScanner(BaseScannerWrapper):
    binary_name = "gowitness"
    default_timeout = 120

    def build_args(self, target: str, **kwargs) -> list[str]:
        out_dir = kwargs.get("out_dir", "/tmp/screenshots")
        os.makedirs(out_dir, exist_ok=True)
        return [
            self.binary_name, "single",
            "-u", target,
            "--screenshot-path", out_dir,
        ]

    def parse_output(self, result: CommandResult) -> list[dict]:
        return [{"success": result.ok}]