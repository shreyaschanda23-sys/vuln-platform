import subprocess
from utils.logger import get_logger

logger = get_logger(__name__)


def run_command(
    command: list[str],
    timeout: int = 300,
    cwd: str = None
) -> tuple[str, str, int]:
    """
    Safe subprocess runner with timeout and logging.
    Returns: (stdout, stderr, returncode)
    """
    logger.info(f"Executing: {' '.join(command)}")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd
        )
        return result.stdout, result.stderr, result.returncode

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {' '.join(command)}")
        raise

    except FileNotFoundError:
        logger.error(f"Command not found: {command[0]}")
        raise

    except Exception as e:
        logger.error(f"Command failed: {e}")
        raise


def is_tool_installed(tool_name: str) -> bool:
    """Check if a CLI tool is available on the system."""
    try:
        result = subprocess.run(
            ["which", tool_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False
