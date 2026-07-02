import subprocess
import json
import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseScannerWrapper(ABC):
    """
    Base class for all scanner tool wrappers.
    Every scanner (nmap, nuclei, httpx, etc.) inherits from this.
    """
    tool_name: str = ""
    timeout: int = 300  # 5 minutes default timeout

    def is_installed(self) -> bool:
        """Check if the tool is installed and available."""
        try:
            result = subprocess.run(
                ["which", self.tool_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def run(self, command: list[str]) -> tuple[str, str, int]:
        """
        Safely run a subprocess command.
        Returns: (stdout, stderr, returncode)
        """
        if not self.is_installed():
            raise RuntimeError(f"Tool '{self.tool_name}' is not installed.")

        logger.info(f"Running: {' '.join(command)}")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            if result.returncode != 0:
                logger.warning(
                    f"{self.tool_name} exited with code {result.returncode}: "
                    f"{result.stderr[:200]}"
                )
            return result.stdout, result.stderr, result.returncode

        except subprocess.TimeoutExpired:
            logger.error(f"{self.tool_name} timed out after {self.timeout}s")
            raise
        except Exception as e:
            logger.error(f"{self.tool_name} failed: {e}")
            raise

    def parse_json_lines(self, output: str) -> list[dict]:
        """
        Parse newline-delimited JSON output.
        Most ProjectDiscovery tools output one JSON object per line.
        """
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                logger.debug(f"Skipping non-JSON line: {line[:100]}")
        return results

    def parse_json(self, output: str) -> dict | list:
        """Parse standard JSON output."""
        try:
            return json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")
            return {}

    @abstractmethod
    def scan(self, target: str, **kwargs) -> list[dict]:
        """
        Run the scan against a target.
        Must be implemented by every scanner subclass.
        Returns a list of findings/results as dicts.
        """
        pass
