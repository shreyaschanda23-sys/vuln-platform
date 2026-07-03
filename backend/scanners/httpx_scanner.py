"""httpx wrapper — live host probing and tech detection."""
from scanners.base import BaseScannerWrapper
from utils.parser import parse_jsonl
from utils.subprocess import CommandResult


class HttpxScanner(BaseScannerWrapper):
    binary_name = "/home/whyyy/go/bin/httpx"
    default_timeout = 180

    def build_args(self, target: str, **kwargs) -> list[str]:
        return [
            self.binary_name,
            "-u", target,
            "-json",
            "-silent",
            "-title",
            "-tech-detect",
            "-status-code",
            "-follow-redirects",
        ]

    def parse_output(self, result: CommandResult) -> list[dict]:
        entries = parse_jsonl(result.stdout)
        return [
            {
                "url": e.get("url"),
                "status_code": e.get("status_code"),
                "title": e.get("title"),
                "tech_stack": ",".join(e.get("tech", [])) if e.get("tech") else None,
                "is_live": True,
            }
            for e in entries if e.get("url")
        ]