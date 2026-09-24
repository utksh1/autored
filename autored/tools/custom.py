"""AutoRed custom command tool — Phase 3, Task 6.

The escape hatch for the LLM-driven orchestrator: when none of sqlmap /
hydra / metasploit / searchsploit fits the engagement, the operator (or
the orchestrator under explicit HitL approval) can run an arbitrary
command through this tool.

Security contract: the ``command`` string is split via ``shlex.split``
into a ``list[str]`` and passed to ``run_subprocess``, which calls
``asyncio.create_subprocess_exec`` (NEVER ``shell=True``). A malicious
``command`` value cannot escape the argv list into a shell context —
shell metacharacters (``&&``, ``|``, ``;``, ``>``) become inert argv
elements rather than operators. The brief's docstring notes that the
command must have been approved at a HitL gate before this tool is
invoked; the tool itself does not enforce approval, it just executes
the already-vetted string.

Decorator order note (Ruling 1 in the SDD ledger): ``@tool`` is applied
OUTERMOST and ``@roe_guard`` INNER. The opposite order produces a
StructuredTool that is not callable via ``.ainvoke({...})`` at runtime —
see Batch A review.
"""
from __future__ import annotations

import shlex

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.custom")


class CustomResult(BaseModel):
    """Result envelope for ``custom_command``.

    ``success`` is derived from ``returncode == 0`` at the call site (not
    via a Pydantic validator) so callers can override it for commands
    that return non-zero on success (e.g., ``grep -c``).
    """

    command: str
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    success: bool = False
    raw_output_path: str = ""
    duration_sec: float = 0.0


@tool
@roe_guard(allowed_categories=["exploit"])
async def custom_command(
    command: str,
    engagement_id: str = "",
) -> CustomResult:
    """Execute an arbitrary approved command.

    This is the escape hatch for exploits that don't fit
    sqlmap/hydra/metasploit. The command must have been approved at a HitL
    gate before this tool is called.

    Args:
        command: Full command string to execute (already approved by
            operator). Split via ``shlex.split`` and run via
            ``create_subprocess_exec`` — NEVER ``shell=True``.
        engagement_id: Current engagement ID for RoE check + raw artefact
            storage.

    Returns:
        ``CustomResult`` with captured stdout/stderr/returncode and the
        derived ``success`` flag.
    """
    cmd_list = shlex.split(command)
    log.info("custom_command_start", command=command, cmd_list=cmd_list)

    result = await run_subprocess(cmd_list, timeout=600)
    raw_path = await _save_raw(
        "custom", command, result.stdout, result.stderr, engagement_id
    )

    log.info(
        "custom_command_done",
        command=command,
        returncode=result.returncode,
        duration=result.duration_sec,
    )
    return CustomResult(
        command=command,
        stdout=result.stdout,
        stderr=result.stderr,
        returncode=result.returncode,
        success=result.returncode == 0,
        raw_output_path=raw_path,
        duration_sec=result.duration_sec,
    )
