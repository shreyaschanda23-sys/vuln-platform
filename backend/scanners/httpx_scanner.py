"""httpx wrapper — live host probing and tech detection."""
import os
from scanners.base import BaseScannerWrapper
from utils.parser import parse_jsonl
from utils.subprocess import CommandResult

# On the bare VM, the Go-built httpx binary lives at a fixed user path.
# Inside Docker, it's installed to the root user's Go bin dir instead
# (see Dockerfile.worker). HTTPX_GO_BINARY lets either environment
# override this; falls back to the VM path if unset, so nothing breaks
# for existing bare-VM usage.
_DEFAULT_VM_PATH = "/home/whyyy/go/bin/httpx"


class HttpxScanner(BaseScannerWrapper):
    binary_name = os.environ.get("HTTPX_GO_BINARY", _DEFAULT_VM_PATH)
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
            "-body-preview", "5000",
        ]

    def parse_output(self, result: CommandResult) -> list[dict]:
        entries = parse_jsonl(result.stdout)
        return [
            {
                "url": e.get("url"),
                "status_code": e.get("status_code"),
                "title": e.get("title"),
                "tech_stack": ",".join(e.get("tech", [])) if e.get("tech") else None,
                "body": e.get("body_preview", ""),
                "is_live": True,
            }
            for e in entries if e.get("url")
        ]