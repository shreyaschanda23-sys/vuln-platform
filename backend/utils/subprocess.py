"""
Safe subprocess runner for invoking recon/scan tools. Enforces timeouts,
captures stdout/stderr, and never raises on non-zero exit — callers check
the returned result instead, since scanners routinely exit non-zero on
things like "no results found."
"""
import asyncio
import shlex
from dataclasses import dataclass

from utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_TIMEOUT = 300  # seconds


@dataclass
class CommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


async def run_command(
    args: list[str],
    timeout: int = DEFAULT_TIMEOUT,
    cwd: str | None = None,
) -> CommandResult:
    """
    Run a command given as an argv list (never a shell string — avoids
    shell injection entirely since args are passed directly to exec).
    """
    cmd_str = " ".join(shlex.quote(a) for a in args)
    logger.info(f"Running: {cmd_str}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
    except FileNotFoundError:
        logger.error(f"Binary not found: {args[0]}")
        return CommandResult(command=cmd_str, returncode=127, stdout="", stderr=f"{args[0]}: command not found")

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.warning(f"Timed out after {timeout}s: {cmd_str}")
        return CommandResult(command=cmd_str, returncode=-1, stdout="", stderr="timeout", timed_out=True)

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode != 0:
        logger.warning(f"Non-zero exit ({proc.returncode}): {cmd_str}")

    return CommandResult(command=cmd_str, returncode=proc.returncode, stdout=stdout, stderr=stderr)