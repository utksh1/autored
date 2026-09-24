"""AutoRed subprocess runner — async, with timeout + stdout/stderr capture.

Every external CLI tool in autored/tools/ goes through this runner.
Never use os.system or shell=True.
"""
from __future__ import annotations

import asyncio
import time
from pydantic import BaseModel, Field

from autored.logging import get_logger

log = get_logger("subprocess")


class SubprocessResult(BaseModel):
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    duration_sec: float = 0.0
    command: str = ""


async def run_subprocess(cmd: list[str], timeout: int = 600) -> SubprocessResult:
    """Run a command, return captured output. Raises TimeoutError on timeout.

    cmd: list of args (already split via shlex.split — never pass shell=True).

    The runner intentionally does NOT have an outer `except Exception` log +
    re-raise. Non-timeout failures (e.g. FileNotFoundError for a missing
    binary) propagate naturally to the calling tool wrapper, which is the
    right place to log with engagement context. The previous outer
    except-Exception block re-logged timeouts as `subprocess_error`,
    producing confusing double-logging on the timeout path.
    """
    cmd_str = " ".join(cmd)
    log.info("subprocess_start", cmd=cmd_str, timeout=timeout)
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()
        raise TimeoutError(
            f"command '{cmd_str}' timed out after {timeout}s"
        )
    duration = time.monotonic() - started
    result = SubprocessResult(
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
        returncode=proc.returncode or 0,
        duration_sec=duration,
        command=cmd_str,
    )
    log.info(
        "subprocess_done",
        cmd=cmd_str,
        returncode=result.returncode,
        duration_sec=duration,
    )
    return result
