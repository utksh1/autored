"""Unit tests for the Phase 6 foothold session manager."""
from datetime import datetime

from autored.foothold_session import (
    FootholdSessionManager,
    _find_credentials_for_host,
    foothold_session_context,
    get_installed,
    uninstall,
)
from autored.models import Foothold, Secret
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _state() -> EngagementState:
    return EngagementState(
        engagement_id="e1", target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=_roe(),
    )


def _foothold(access_type: str = "ssh", username: str = "root") -> Foothold:
    return Foothold(
        id="f-1", host_ip="10.0.0.5", username=username, context="user",
        method="ssh_brute", access_type=access_type,
        evidence_path="evidence/f1.txt",
        established_at=datetime.utcnow(), hypothesis_rank=1,
    )


def test_find_credentials_prefers_password_and_parses_username():
    state = _state()
    state.harvested_secrets = [
        Secret(host_ip="10.0.0.5", secret_type="password",
               secret_value="Passw0rd!", source="mimikatz:wdigest/administrator"),
        Secret(host_ip="10.0.0.5", secret_type="hash",
               secret_value="8a4f6d9c2b7e1f3a5d8c4b6e2f0a1d3c",
               source="mimikatz:kerberos/administrator"),
        Secret(host_ip="10.0.0.9", secret_type="password",
               secret_value="OTHERHOST", source="mimikatz:wdigest/other"),
    ]
    bundle = _find_credentials_for_host(state, "10.0.0.5")
    assert bundle.password == "Passw0rd!"
    assert bundle.nthash == "8a4f6d9c2b7e1f3a5d8c4b6e2f0a1d3c"
    assert bundle.username == "administrator"  # parsed from source, not the OTHERHOST secret


def test_find_credentials_falls_back_to_foothold_username():
    state = _state()
    state.footholds = [_foothold(access_type="winrm", username="bob")]
    state.harvested_secrets = [
        Secret(host_ip="10.0.0.5", secret_type="hash",
               secret_value="a" * 32, source="sam_dump"),  # no slash in source
    ]
    bundle = _find_credentials_for_host(state, "10.0.0.5")
    assert bundle.username == "bob"
    assert bundle.nthash == "a" * 32
    assert bundle.password == ""


async def test_execute_ssh_uses_sshpass(monkeypatch):
    from autored.subprocess_runner import SubprocessResult

    calls = {}

    async def fake_run_subprocess(cmd, timeout=300):
        calls["cmd"] = cmd
        calls["timeout"] = timeout
        return SubprocessResult(
            stdout="uid=0(root)", stderr="", returncode=0,
            duration_sec=0.5, command="sshpass",
        )

    import autored.foothold_session as fs
    monkeypatch.setattr(fs, "run_subprocess", fake_run_subprocess)

    state = _state()
    state.footholds = [_foothold(access_type="ssh", username="root")]
    state.harvested_secrets = [
        Secret(host_ip="10.0.0.5", secret_type="password",
               secret_value="hunter2", source="brute_force"),
    ]
    mgr = FootholdSessionManager(state)
    result = await mgr.execute(_foothold(access_type="ssh", username="root"), "id")
    assert result.success is True
    assert result.stdout == "uid=0(root)"
    assert calls["cmd"][:2] == ["sshpass", "-p"]
    assert "hunter2" in calls["cmd"]
    assert "root@10.0.0.5" in calls["cmd"]


async def test_execute_windows_uses_impacket_wmiexec(monkeypatch):
    """``FootholdSessionManager.execute`` for winrm/rpc dispatches through
    ``impacket_wmiexec.ainvoke({...})`` with the resolved credential bundle.

    The patched fake is a ``MagicMock`` whose ``ainvoke`` is an async function
    that takes the args dict the production code passes against the real
    langchain ``StructuredTool`` — same shape, just without touching the
    real impacket binary / SMB stack.
    """
    from unittest.mock import MagicMock

    from autored.tools.impacket_remote import ImpacketRemoteResult

    async def fake_ainvoke(args, **kwargs):
        return ImpacketRemoteResult(
            host_ip=args["target"], method="wmiexec",
            command_executed=args["command"],
            output="goaad\\administrator", success=True,
            raw_output_path="raw/x.out", duration_sec=1.2,
        )

    fake_wmiexec = MagicMock()
    fake_wmiexec.ainvoke = fake_ainvoke

    import autored.foothold_session as fs
    monkeypatch.setattr(fs, "impacket_wmiexec", fake_wmiexec)

    state = _state()
    state.harvested_secrets = [
        Secret(host_ip="10.0.0.5", secret_type="hash",
               secret_value="8a" * 16, source="mimikatz:kerberos/administrator"),
    ]
    mgr = FootholdSessionManager(state)
    result = await mgr.execute(_foothold(access_type="winrm", username="administrator"), "whoami")
    assert result.success is True
    assert result.stdout == "goaad\\administrator"


async def test_execute_no_transport_for_shell_footholds():
    state = _state()
    mgr = FootholdSessionManager(state)
    result = await mgr.execute(_foothold(access_type="webshell"), "id")
    assert result.success is False
    assert "no transport" in result.stderr


async def test_session_context_installs_and_uninstalls():
    state = _state()
    try:
        with foothold_session_context(state):
            assert get_installed() is not None
            assert get_installed().state.engagement_id == "e1"
        assert get_installed() is None  # uninstalled on clean exit
    finally:
        uninstall()


async def test_session_context_uninstalls_on_exception():
    state = _state()
    try:
        try:
            with foothold_session_context(state):
                assert get_installed() is not None
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        assert get_installed() is None  # uninstalled even on exception
    finally:
        uninstall()


def test_find_foothold_by_id():
    state = _state()
    f = _foothold()
    state.footholds = [f]
    mgr = FootholdSessionManager(state)
    assert mgr.find_foothold("f-1") is f
    assert mgr.find_foothold("nope") is None
