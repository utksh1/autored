import asyncio
from datetime import datetime
from pydantic import BaseModel
from autored.logging import get_logger

log = get_logger("subprocess")

class SubprocessResult(BaseModel):
    stdout: str
    stderr: str
    returncode: int
    duration_sec: float
    command: str

async def run_subprocess(cmd: list[str], timeout: int = 600) -> SubprocessResult:
    """Run a subprocess async with hard timeout. Raises TimeoutError on timeout."""
    start = datetime.utcnow()
    cmd_str = " ".join(cmd)
    log.info("subprocess_start", cmd=cmd_str, timeout=timeout)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        duration = (datetime.utcnow() - start).total_seconds()

        result = SubprocessResult(
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            returncode=proc.returncode if proc.returncode is not None else -1,
            duration_sec=duration,
            command=cmd_str,
        )
        log.info("subprocess_done", cmd=cmd_str, returncode=result.returncode, duration=duration)
        return result
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        duration = (datetime.utcnow() - start).total_seconds()
        log.error("subprocess_timeout", cmd=cmd_str, timeout=timeout, duration=duration)
        raise TimeoutError(f"Command timed out after {timeout}s: {cmd_str}")
