"""
Abstract base class every scanner wrapper implements. Keeps the interface
consistent so the orchestrator (Phase 3) can call any scanner uniformly.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from utils.subprocess import run_command, CommandResult
from utils.logger import get_logger


@dataclass
class ScanResult:
    tool: str
    success: bool
    raw_output: str
    parsed: list[dict] = field(default_factory=list)
    error: str | None = None


class BaseScannerWrapper(ABC):
    """
    Subclasses implement `binary_name`, `build_args`, and `parse_output`.
    `run()` ties them together with the safe subprocess runner.
    """

    binary_name: str = ""
    default_timeout: int = 300

    def __init__(self):
        self.logger = get_logger(self.__class__.__name__)
        if not self.binary_name:
            raise NotImplementedError("Subclasses must set binary_name")

    @abstractmethod
    def build_args(self, target: str, **kwargs) -> list[str]:
        """Build the argv list for this tool given a target and options."""
        raise NotImplementedError

    @abstractmethod
    def parse_output(self, result: CommandResult) -> list[dict]:
        """Turn raw stdout into a list of structured dicts."""
        raise NotImplementedError

    async def run(self, target: str, timeout: int | None = None, **kwargs) -> ScanResult:
        args = self.build_args(target, **kwargs)
        result = await run_command(args, timeout=timeout or self.default_timeout)

        if result.timed_out:
            return ScanResult(
                tool=self.binary_name,
                success=False,
                raw_output=result.stdout,
                error="timeout",
            )

        if not result.ok:
            self.logger.warning(f"{self.binary_name} exited {result.returncode}: {result.stderr[:200]}")

        try:
            parsed = self.parse_output(result)
        except Exception as e:
            self.logger.error(f"Failed to parse {self.binary_name} output: {e}")
            return ScanResult(
                tool=self.binary_name,
                success=False,
                raw_output=result.stdout,
                error=f"parse_error: {e}",
            )

        return ScanResult(
            tool=self.binary_name,
            success=result.ok,
            raw_output=result.stdout,
            parsed=parsed,
        )