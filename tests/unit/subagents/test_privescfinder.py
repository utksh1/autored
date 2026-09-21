# tests/unit/subagents/test_privescfinder.py
import pytest
from unittest.mock import AsyncMock, patch

from autored.models.postex import PrivescCandidate
from autored.subagents.privescfinder import (
    privescfinder_subagent,
    PrivescFinderOutput,
)


@pytest.mark.asyncio
async def test_privescfinder_uses_llm_to_analyze_enum_results():
    """PrivescFinder calls the LLM with enum results and parses the candidates."""
    fake_response = type(
        "MockResp",
        (),
        {"content": """```json
        {
          "candidates": [
            {
              "host_ip": "10.10.10.5",
              "technique": "sudo find",
              "category": "misconfig",
              "details": "sudo find with NOPASSWD allows root shell via -exec",
              "confidence": 0.95,
              "exploit_command": "sudo find . -exec /bin/sh +"
            },
            {
              "host_ip": "10.10.10.5",
              "technique": "CVE-2021-4034 (PwnKit)",
              "category": "kernel",
              "details": "Polkit pkexec local privilege escalation",
              "confidence": 0.9,
              "exploit_command": "./cve-2021-4034"
            }
          ]
        }
        ```"""},
    )()

    enum_results = [
        {
            "host_ip": "10.10.10.5",
            "os_type": "linux",
            "suid_binaries": ["/usr/bin/find"],
            "sudo_entries": ["(ALL) NOPASSWD: /usr/bin/find"],
            "cves": ["CVE-2021-4034"],
        },
    ]

    with patch("autored.subagents.privescfinder.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=fake_response)
        mock_get_model.return_value = mock_model

        result = await privescfinder_subagent.ainvoke({
            "enum_results": enum_results,
            "engagement_id": "test-eng",
        })

    assert isinstance(result, PrivescFinderOutput)
    assert len(result.candidates) == 2
    assert isinstance(result.candidates[0], PrivescCandidate)
    assert result.candidates[0].technique == "sudo find"
    assert result.candidates[0].category == "misconfig"
    assert result.candidates[0].confidence == 0.95
    assert result.candidates[1].category == "kernel"
    # get_model must have been called with the plan_postex task slot
    mock_get_model.assert_called_once_with("plan_postex")
