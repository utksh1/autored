"""Tests for the custom command tool wrapper (Phase 3, Task 6).

This is the Phase 3 escape hatch — the LLM-driven orchestrator calls it
when none of sqlmap/hydra/metasploit fits. The contract is simple: take a
shell-looking command string, split it with ``shlex.split`` (NEVER
``shell=True``), run it through the shared ``run_subprocess`` (which uses
``asyncio.create_subprocess_exec`` under the hood), persist raw output
through the same ``_save_raw`` helper every other tool uses, and return a
``CustomResult``.

The brief's Step 1 test only covers the ``CustomResult`` Pydantic model.
We add two integration tests on top of it:

- ``test_custom_command_shlex_split`` — captures the ``cmd`` list passed
  to ``run_subprocess`` and asserts it's a ``list[str]`` (NOT a shell
  string) and that shlex splits args correctly (the brief's no-injection
  contract is regression-caught here, not just in the docstring).

- ``test_custom_command_ainvoke_works_with_roe_guard`` — the standard
  Ruling-1 integration test that exercises the full decorator stack via
  ``.ainvoke({...})``.
"""
from __future__ import annotations

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.custom import CustomResult, custom_command


def test_custom_result_model():
    """Brief Step 1: ``CustomResult`` Pydantic model accepts the documented
    fields and surfaces ``success`` derived from returncode."""
    r = CustomResult(
        command="whoami",
        stdout="root\n",
        stderr="",
        returncode=0,
        success=True,
    )
    assert r.success is True
    assert r.stdout == "root\n"


@pytest.mark.asyncio
async def test_custom_command_shlex_split(sandbox_roe_yaml, monkeypatch):
    """Brief-style unit test: ``shlex.split`` is used, NOT ``shell=True``.

    Captures the ``cmd`` list passed to ``run_subprocess`` and asserts:
    - it is a ``list[str]`` (each token is a separate argv entry)
    - the tokens match the expected shlex split (quoted args survive as
      single tokens, e.g., ``"hello world"`` → ``["hello world"]``)

    This is the regression catcher for the no-injection contract documented
    in the brief's docstring: the LLM-driven orchestrator can hand the
    tool any command string, but ``shlex.split`` + ``create_subprocess_exec``
    (NOT ``shell=True``) means a malicious ``command`` value cannot escape
    the argv list into a shell context.
    """
    # Register a RoE for the test engagement (the @roe_guard wrapper
    # raises RoEViolation without one, before run_subprocess is reached).
    roe = load_roe(sandbox_roe_yaml)
    register_roe("custom-shlex", roe)

    captured_cmd: list[list[str]] = []

    async def fake_run_subprocess(cmd, timeout=600):
        captured_cmd.append(cmd)
        return SubprocessResult(
            stdout="root\n",
            stderr="",
            returncode=0,
            duration_sec=0.1,
            command=" ".join(cmd),
        )

    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.custom.run_subprocess", fake_run_subprocess)
    monkeypatch.setattr("autored.tools.custom._save_raw", fake_save_raw)

    result = await custom_command.ainvoke(
        {
            "command": 'echo "hello world" && whoami',
            "engagement_id": "custom-shlex",
        }
    )

    # shlex.split tokenises shell-like strings into argv entries without
    # invoking a shell. ``"hello world"`` survives as one quoted token,
    # and the ``&&`` is just another arg (it would only be a shell operator
    # if we used ``shell=True``, which we deliberately do not).
    assert captured_cmd, "run_subprocess was never called"
    cmd_list = captured_cmd[0]
    assert isinstance(cmd_list, list)
    assert all(isinstance(tok, str) for tok in cmd_list)
    assert cmd_list[0] == "echo"
    assert "hello world" in cmd_list  # the quoted arg is a single token
    assert "&&" in cmd_list  # shell operator is just an argv element here

    # success derived from returncode == 0
    assert isinstance(result, CustomResult)
    assert result.success is True
    assert result.stdout == "root\n"
    assert result.returncode == 0
    assert result.command == 'echo "hello world" && whoami'


@pytest.mark.asyncio
async def test_custom_command_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via ``.ainvoke()``.

    Regression catcher for the decorator-stacking bug (Ruling 1 in the SDD
    ledger): ``@tool`` must be applied OUTERMOST and ``@roe_guard`` INNER,
    or the resulting StructuredTool is not callable via ``.ainvoke({...})``.

    Note: ``_save_raw`` is imported into ``custom``'s namespace via
    ``from autored.tools.nmap import _save_raw``, so the patch target must
    be ``autored.tools.custom._save_raw`` to intercept the call from
    inside ``custom_command``.
    """
    # 1. Register a RoE for the test engagement.
    roe = load_roe(sandbox_roe_yaml)
    register_roe("custom-int", roe)

    # 2. Mock run_subprocess to return a controlled stdout.
    async def fake_run_subprocess(cmd, timeout=600):
        return SubprocessResult(
            stdout="root\n",
            stderr="",
            returncode=0,
            duration_sec=0.05,
            command=" ".join(cmd),
        )

    monkeypatch.setattr("autored.tools.custom.run_subprocess", fake_run_subprocess)

    # 3. Mock _save_raw to a no-op so the test doesn't touch disk.
    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.custom._save_raw", fake_save_raw)

    # 4. Call the tool via .ainvoke({...}).
    result = await custom_command.ainvoke(
        {
            "command": "whoami",
            "engagement_id": "custom-int",
        }
    )

    # 5. Assert the returned object is the right Pydantic model with the
    #    expected fields populated.
    assert isinstance(result, CustomResult)
    assert result.command == "whoami"
    assert result.stdout == "root\n"
    assert result.stderr == ""
    assert result.returncode == 0
    assert result.success is True
    assert result.duration_sec == 0.05
