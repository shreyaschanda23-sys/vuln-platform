"""ffuf wrapper — directory/file fuzzing."""
from scanners.base import BaseScannerWrapper
from utils.parser import parse_jsonl
from utils.subprocess import CommandResult


class FfufScanner(BaseScannerWrapper):
    binary_name = "ffuf"
    default_timeout = 300

    def build_args(self, target: str, **kwargs) -> list[str]:
        wordlist = kwargs.get(
            "wordlist", "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
        )
        url = target.rstrip("/") + "/FUZZ"
        return [
            self.binary_name,
            "-u", url,
            "-w", wordlist,
            "-mc", "200,204,301,302,307,401,403",
            "-json",
            "-s",
        ]

    def parse_output(self, result: CommandResult) -> list[dict]:
        entries = parse_jsonl(result.stdout)
        return [
            {
                "url": e.get("url"),
                "status_code": e.get("status"),
                "length": e.get("length"),
            }
            for e in entries if e.get("url")
        ]