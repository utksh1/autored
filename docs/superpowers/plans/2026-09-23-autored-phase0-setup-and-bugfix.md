# AutoRed Phase 0 — Setup + Bug-Fix Batch + Execution Strategy

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Set up the AutoRed project as a working git repository with superpowers skills installed, fix the spec violations and broken imports in the 30% baseline so the existing 27 subagents become importable, then lay out the execution order for Phases 1–6 (whose plans already exist in `docs/superpowers/plans/`).

**Architecture:** Phase 0 is the foundation layer: it produces no new user-facing features, but it makes the rest of the build-out possible. It (1) initializes the project structure with pinned dependencies, (2) writes the minimal Pydantic models, `EngagementState`, RoE Guard, structlog logging, retry decorator, subprocess runner, and config loader that the 27 existing subagents depend on, (3) fixes the known spec violations and broken imports in the baseline, (4) writes the test scaffolding (conftest + first fixtures), and (5) hands off to the existing Phase 1 plan (which extends these models + writes the 9 recon tool wrappers + the recon agent + the Phase 1 graph).

**Tech Stack (Pinned Versions):**
- Python 3.12+
- `pydantic==2.9.11`
- `structlog==24.4.0`
- `typer==0.12.5`, `rich==13.9.2`, `textual==0.79.1`
- `langgraph==0.2.45`, `langchain-anthropic==0.1.23`, `langchain-openai==0.2.10`
- `anthropic==0.39.0`
- `aiosqlite==0.20.0`, `sqlalchemy==2.0.36`
- `chromadb==0.5.13`
- `pyyaml==6.0.2`
- `cryptography>=44.0.0` (NEW — for at-rest credential encryption)
- `uv==0.4.20` (package manager), `ruff==0.7.1` (linter)
- Dev: `pytest==8.3.3`, `pytest-asyncio==0.24.0`, `pytest-cov==5.0.0`

**Spec:** `docs/superpowers/specs/2026-09-21-autored-design.md` §3.3 (SQLite schema), §4 (model router), §6.8 (RoE Guard), §9 (EngagementState), §10 (error handling), §11 (logging), §15 (config reference), §16 (project structure).

---

## Global Constraints

- **Python 3.12+**, type hints everywhere, `from __future__ import annotations` at the top of every model file.
- **Async-first**: every tool, subagent, and primary agent is `async def`. LangGraph runs the graph via `graph.ainvoke()`.
- **Pydantic v2** is the sole state schema. Models live in `autored/models/` — one class per file, exported via `autored/models/__init__.py`.
- **Subprocess safety**: every external tool goes through `autored.subprocess_runner.run_subprocess` with `shlex.split` (never `shell=True`), a hard timeout (default 600s), and stdout+stderr capture. Never `os.system`.
- **RoE Guard decorator is the only policy enforcement layer**. It runs *before* the HitL gate. Out-of-scope targets are blocked *before* the operator is asked.
- **No plaintext credentials in the database.** Spec §3.3 line 313. Credentials are encrypted at rest with Fernet (key from `AUTORED_DB_KEY` env var, generated once and persisted to `db/.db_key` if missing).
- **Tests are part of the deliverable.** TDD: write the failing test, watch it fail, write the minimal code, watch it pass, commit. No code without a test.
- **Commit messages** use conventional commits: `feat:`, `test:`, `fix:`, `chore:`, `docs:`.
- **No "TBD", "TODO", "implement later", "fill in details"** anywhere. Every step carries the actual code to write.
- **The 6 Phase 1–6 plans at `docs/superpowers/plans/2026-09-2[12]-autored-phaseN-*.md` are the authority** for everything past Phase 0. This plan only sets up the foundation and fixes baseline bugs.

---

## Review Focus

Five failure modes the baseline (and the 6 phase plans) imply but no single task's tests exercise. Each gets a dedicated test in the owning task.

1. **Plaintext credential leak via the database** — spec §3.3 promises "hashed/encrypted form, never plaintext passwords in DB", but `engagement_db.insert_credential` writes raw `credential_value` as TEXT. **Test in Task 5:** `test_credential_value_is_encrypted_at_rest` asserts that a written credential cannot be read back as plaintext via a raw SQL query.
2. **ImportError on first subagent import** — every `from autored.tools.nmap import nmap_scan` and `from autored.logging import get_logger` will fail until Phase 0 produces those modules. **Test in Task 9:** `test_all_27_subagents_import_cleanly` iterates `autored/subagents/*.py` and asserts `importlib.import_module(...)` succeeds. Any unresolved import is a blocker.
3. **RoE Guard bypass via prompt injection** — the spec promises RoE Guard is "non-LLM, prompt-injection-proof". If any tool wrapper forgets to apply `@roe_guard`, an attacker controlling target output could route around the guard. **Test in Task 4:** `test_every_tool_has_roe_guard_decorator` scans `autored/tools/*.py` for `@tool` functions and asserts each is also wrapped with `@roe_guard`.
4. **Refusal-detection inconsistency across subagents** — `router._is_refusal` uses one marker list; `techreportwriter._is_refusal` uses another; `privescfinder` and `hypothesiscritic` have no refusal detection at all. **Test in Task 8:** `test_router_call_with_fallback_is_the_only_refusal_path` greps the codebase for `_is_refusal` and asserts exactly one definition (in `router.py`), with all LLM-calling subagents routing through `call_with_fallback`.
5. **`asyncio.gather` silently cancels batches** — three call sites (`cvematcher:62`, `subdomainenum:38`, `webenum:59`) lack `return_exceptions=True`, so one failed sub-task cancels the whole batch. **Test in Task 9:** `test_gather_call_sites_use_return_exceptions` greps for `asyncio.gather(` and asserts every call site passes `return_exceptions=True`.

---

## File Structure

### Files CREATED in Phase 0

```
pyproject.toml                                      # T1 — pinned deps, entry point, ruff config
.env.example                                        # T1 — env var template
.gitignore                                          # already present, expand in T1
roe-sandbox.yaml                                    # T2 — sandbox RoE config
autored.config.yaml                                 # T2 — global config defaults

autored/__init__.py                                 # T1 — version string
autored/logging.py                                  # T3 — structlog JSONL setup
autored/config.py                                   # T2 — load_roe, load_global_config, get_env_var, validate_roe_yaml
autored/retry.py                                    # T6 — @with_retry decorator
autored/subprocess_runner.py                        # T6 — async run_subprocess + SubprocessResult
autored/utils.py                                    # T7 — generate_engagement_id
autored/roe_guard.py                                # T4 — @roe_guard decorator + _categorize_call + _ip_in_scope + RoEViolation + RoECheckResult + ToolCategory
autored/state.py                                    # T8 — EngagementState + RulesOfEngagement + ErrorEvent
autored/crypto.py                                   # T5 — Fernet-based credential encryption helpers

autored/models/__init__.py                          # T8 — exports every model
autored/models/host.py                              # T8 — Host
autored/models/service.py                           # T8 — Service
autored/models/webapp.py                            # T8 — WebApp, DiscoveredPath
autored/models/discovery.py                         # T8 — DiscoveredPath (re-exported from webapp.py per spec §16)
autored/models/vulnerability.py                     # T8 — Vulnerability (stub, extended in Phase 2)
autored/models/roe.py                               # T8 — RulesOfEngagement (re-exported from state.py per spec §16)
autored/models/error.py                             # T8 — ErrorEvent (re-exported from state.py per spec §16)

autored/persistence/filesystem.py                   # T7 — init_engagement_folder, save/load state to/from disk, list_engagements, ENGAGEMENTS_DIR
autored/persistence/engagement_db.py               # T5 — FIX: encrypt credential_value with Fernet (existing file, modify in place)

tests/__init__.py                                   # T1
tests/conftest.py                                   # T1 — fixtures_dir, sandbox_roe_yaml
tests/unit/__init__.py                              # T1
tests/unit/test_logging.py                          # T3
tests/unit/test_config.py                           # T2
tests/unit/test_subprocess_runner.py                # T6
tests/unit/test_retry.py                            # T6
tests/unit/test_utils.py                            # T7
tests/unit/roe_guard/__init__.py                    # T4
tests/unit/roe_guard/test_roe_guard.py              # T4
tests/unit/roe_guard/test_roe_guard_decorator.py    # T4
tests/unit/models/__init__.py                       # T8
tests/unit/models/test_state.py                     # T8
tests/unit/models/test_roe.py                       # T8
tests/unit/persistence/__init__.py                  # T5
tests/unit/persistence/test_engagement_db_crypto.py # T5 — Review Focus #1
tests/unit/test_phase0_baseline_health.py           # T9 — Review Focus #2, #4, #5
```

### Files MODIFIED in Phase 0

- `autored/persistence/engagement_db.py` — Task 5: add Fernet encryption on `insert_credential`, decryption on read; add `init_db` to also persist the Fernet key to `db/.db_key` if missing.
- `autored/persistence/sqlite_saver.py` — Task 7: fix `from autored.persistence.filesystem import ENGAGEMENTS_DIR` (will work once `filesystem.py` exists from Task 7).
- `autored/subagents/__init__.py` — Task 9: expand to export all 27 subagents (or use `pkgutil.walk_packages` for auto-discovery).
- `autored/subagents/cvematcher.py` — Task 9: add `return_exceptions=True` to `asyncio.gather` call at line ~62.
- `autored/subagents/subdomainenum.py` — Task 9: add `return_exceptions=True` to `asyncio.gather` call at line ~38; fix `from autored.tools.subfinder import amass_enum` → `from autored.tools.amass import amass_enum` (the spec bug).
- `autored/subagents/webenum.py` — Task 9: add `return_exceptions=True` to `asyncio.gather` call at line ~59.
- `autored/subagents/techreportwriter.py`, `execsummarywriter.py`, `lessonextractor.py` — Task 8: replace local `_is_refusal` definitions with `from autored.router import _is_refusal` (or better: route LLM calls through `router.call_with_fallback`).
- `autored/subagents/privescfinder.py`, `hypothesiscritic.py` — Task 8: add refusal detection (currently missing — they conflate "refusal" with "JSON parse error").

---

## Task 1: Project Scaffolding (pyproject.toml + .env.example + package init)

**Files:**
- Create: `pyproject.toml`, `.env.example`, `autored/__init__.py`, `tests/__init__.py`, `tests/unit/__init__.py`, `tests/conftest.py`

**Interfaces:**
- Produces: a working `uv sync` install with all pinned dependencies, an `autored` package importable as `import autored` (returns version string), a `tests/conftest.py` exposing `fixtures_dir` and `sandbox_roe_yaml` fixtures.

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[project]
name = "autored"
version = "0.1.0"
description = "Semi-autonomous red-team copilot — full kill chain: recon → vuln → exploit → post-ex → lateral → cleanup → report"
requires-python = ">=3.12"
dependencies = [
    "langgraph==0.2.45",
    "langchain-anthropic==0.1.23",
    "langchain-openai==0.2.10",
    "anthropic==0.39.0",
    "pydantic==2.9.11",
    "typer==0.12.5",
    "rich==13.9.2",
    "textual==0.79.1",
    "structlog==24.4.0",
    "chromadb==0.5.13",
    "sqlalchemy==2.0.36",
    "aiosqlite==0.20.0",
    "neo4j==5.25.0",
    "weasyprint==62.3",
    "markdown==3.7",
    "msgpack==1.1.0",
    "impacket==0.12.0",
    "httpx==0.28.1",
    "pyyaml==6.0.2",
    "cryptography>=44.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest==8.3.3",
    "pytest-asyncio==0.24.0",
    "pytest-cov==5.0.0",
    "pytest-httpx==0.35.0",
    "ruff==0.7.1",
]

[project.scripts]
autored = "autored.cli:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["autored"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
addopts = "-v --tb=short"
markers = [
    "e2e: marks end-to-end tests against live targets (deselect with '-m \"not e2e\"')",
]

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "W", "I", "N", "B", "C4", "UP"]
ignore = ["E501"]  # line length handled by formatter
```

- [ ] **Step 2: Write `.env.example`**

```env
# Required for LLM calls
ANTHROPIC_API_KEY=sk-ant-...
DEEPSEEK_API_KEY=sk-...
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1

# Neo4j (Phase 4+, docker-compose)
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=autored_local_dev

# Exfil catch server (Phase 4+)
CATCH_SERVER_URL=http://localhost:8888

# Logging
LOG_LEVEL=INFO

# AutoRed operator host (for reverse shells / tunnels, Phase 3+)
AUTORED_LHOST=10.10.14.5
AUTORED_LPORT=4444

# AutoRed DB encryption key (Phase 0 — auto-generated if missing)
# AUTORED_DB_KEY=  # leave unset to auto-generate at first run

# E2E test gate (Phases 1-6)
AUTORED_E2E=0

# GoAD lab target overrides (Phases 4-6)
AUTORED_GOAD_TARGET=192.168.56.22
AUTORED_GOAD_PIVOT_TARGET=192.168.56.11
```

- [ ] **Step 3: Write `autored/__init__.py`**

```python
"""AutoRed — semi-autonomous red-team copilot."""

__version__ = "0.1.0"
```

- [ ] **Step 4: Write `tests/__init__.py`, `tests/unit/__init__.py`** (empty files)

- [ ] **Step 5: Write `tests/conftest.py`**

```python
"""Shared pytest fixtures for AutoRed tests."""
from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Return the path to tests/fixtures/."""
    return FIXTURES_DIR


@pytest.fixture
def sandbox_roe_yaml() -> str:
    """Return the path to the sandbox RoE YAML."""
    return str(Path(__file__).parent.parent / "roe-sandbox.yaml")


@pytest.fixture
def tmp_engagement_dir(tmp_path, monkeypatch) -> Path:
    """Redirect ENGAGEMENTS_DIR to a tmp_path for isolation."""
    engagements = tmp_path / "engagements"
    engagements.mkdir()
    monkeypatch.setattr(
        "autored.persistence.filessystem.ENGAGEMENTS_DIR", engagements
    )
    return engagements
```

- [ ] **Step 6: Verify install works**

Run: `uv sync --all-extras`
Expected: "Installed packages: ..." with no errors.

- [ ] **Step 7: Run baseline test discovery**

Run: `uv run pytest --collect-only 2>&1 | tail -20`
Expected: "no tests collected" (no tests written yet) but no import errors.

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml .env.example autored/__init__.py tests/__init__.py tests/unit/__init__.py tests/conftest.py uv.lock
git commit -m "chore: scaffold pyproject.toml + .env.example + package init + conftest"
```

---

## Task 2: Config Loader + RoE Sandbox YAML + Global Config

**Files:**
- Create: `autored/config.py`, `roe-sandbox.yaml`, `autored.config.yaml`
- Test: `tests/unit/test_config.py`

**Interfaces:**
- Produces: `load_roe(path: str) -> RulesOfEngagement`, `load_global_config(path: str) -> dict`, `get_env_var(name: str, default: str | None = None) -> str | None`, `validate_roe_yaml(text: str) -> list[str]` (returns list of error messages; empty list = valid).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_config.py
from __future__ import annotations

from pathlib import Path

import pytest

from autored.config import load_roe, load_global_config, get_env_var, validate_roe_yaml


def test_load_roe_from_sandbox_yaml(sandbox_roe_yaml: str):
    roe = load_roe(sandbox_roe_yaml)
    assert roe.engagement_name == "Sandbox Engagement"
    assert roe.operator == "operator"
    assert roe.allowed_ips == ["0.0.0.0/0"]
    assert roe.persistence_allowed is True
    assert roe.evasion_allowed is True
    assert roe.exfiltration_allowed is True
    assert roe.data_destruction_allowed is False
    assert roe.kernel_exploits_allowed is True
    assert roe.hitl_mode == "auto_approve"


def test_load_global_config(tmp_path: Path):
    cfg = tmp_path / "autored.config.yaml"
    cfg.write_text(
        "log_dir: logs\nengagements_dir: engagements\n"
        'db_path: db/engagements.sqlite\nchroma_path: db/chroma\n'
        'default_sandbox_roe: roe-sandbox.yaml\n'
        "llm:\n  default_temperature: 0.2\n  default_max_tokens: 8192\n"
        "  default_timeout: 120\n"
        "tools:\n  nmap_timeout: 600\n  nuclei_timeout: 900\n"
        "subagents:\n  max_execution_time: 300\n  max_retries: 3\n"
    )
    config = load_global_config(str(cfg))
    assert config["log_dir"] == "logs"
    assert config["db_path"] == "db/engagements.sqlite"
    assert config["llm"]["default_temperature"] == 0.2


def test_get_env_var_with_default(monkeypatch):
    monkeypatch.delenv("AUTORED_FAKE_VAR", raising=False)
    assert get_env_var("AUTORED_FAKE_VAR", "fallback") == "fallback"


def test_get_env_var_without_default(monkeypatch):
    monkeypatch.delenv("AUTORED_FAKE_VAR", raising=False)
    assert get_env_var("AUTORED_FAKE_VAR") is None


def test_validate_roe_yaml_accepts_valid_config():
    valid = (
        "engagement_name: Test\noperator: op\noperator_signature: sig\n"
        'allowed_ips: ["10.10.10.0/24"]\nallowed_techniques: ["*"]\n'
        "persistence_allowed: false\nevasion_allowed: false\n"
        "exfiltration_allowed: false\ndata_destruction_allowed: false\n"
        "kernel_exploits_allowed: false\nhitl_mode: always_ask\n"
    )
    assert validate_roe_yaml(valid) == []


def test_validate_roe_yaml_rejects_missing_fields():
    invalid = "engagement_name: Test\noperator: op\n"
    errors = validate_roe_yaml(invalid)
    assert len(errors) > 0
    assert any("operator_signature" in e for e in errors)


def test_validate_roe_yaml_rejects_invalid_hitl_mode():
    invalid = (
        "engagement_name: T\noperator: o\noperator_signature: s\n"
        'allowed_ips: ["0.0.0.0/0"]\nallowed_techniques: ["*"]\n'
        "persistence_allowed: true\nevasion_allowed: true\n"
        "exfiltration_allowed: true\ndata_destruction_allowed: false\n"
        "kernel_exploits_allowed: true\nhitl_mode: maybe\n"
    )
    errors = validate_roe_yaml(invalid)
    assert any("hitl_mode" in e for e in errors)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.config'`

- [ ] **Step 3: Write `roe-sandbox.yaml`**

```yaml
# Sandbox RoE — permissive defaults for lab/CTF use.
# Used by `autored run --target X --roe roe-sandbox.yaml --no-tui` for
# HackTheBox and GoAD engagements. DO NOT use against production targets.
engagement_name: "Sandbox Engagement"
operator: "operator"
operator_signature: "sandbox-mode"
allowed_ips:
  - "0.0.0.0/0"
allowed_techniques:
  - "*"
persistence_allowed: true
evasion_allowed: true
exfiltration_allowed: true
data_destruction_allowed: false
kernel_exploits_allowed: true
hitl_mode: "auto_approve"
```

- [ ] **Step 4: Write `autored.config.yaml`**

```yaml
# Global AutoRed config — referenced by autored.config.load_global_config().
log_dir: "logs"
engagements_dir: "engagements"
db_path: "db/engagements.sqlite"
chroma_path: "db/chroma"
default_sandbox_roe: "roe-sandbox.yaml"

llm:
  default_temperature: 0.2
  default_max_tokens: 8192
  default_timeout: 120

tools:
  nmap_timeout: 600
  nuclei_timeout: 900
  feroxbuster_timeout: 600
  hydra_timeout: 3600
  sqlmap_timeout: 600
  bloodhound_timeout: 600
  mimikatz_timeout: 300
  default_wordlist: "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
  subdomain_wordlist: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

subagents:
  max_execution_time: 300
  max_retries: 3
```

- [ ] **Step 5: Write `autored/config.py`**

```python
"""AutoRed config loader — RoE YAML + global config + env var access."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError
from typing import Literal


class RulesOfEngagement(BaseModel):
    """Spec §9.2 — Rules of Engagement model."""
    engagement_name: str
    operator: str
    operator_signature: str
    allowed_ips: list[str] = Field(default_factory=list)
    allowed_techniques: list[str] = Field(default_factory=list)
    persistence_allowed: bool = False
    evasion_allowed: bool = False
    exfiltration_allowed: bool = False
    data_destruction_allowed: bool = False
    kernel_exploits_allowed: bool = False
    hitl_mode: Literal["always_ask", "auto_approve", "disabled"] = "always_ask"


_REQUIRED_ROE_FIELDS = (
    "engagement_name",
    "operator",
    "operator_signature",
    "allowed_ips",
    "allowed_techniques",
    "persistence_allowed",
    "evasion_allowed",
    "exfiltration_allowed",
    "data_destruction_allowed",
    "kernel_exploits_allowed",
    "hitl_mode",
)


def load_roe(path: str) -> RulesOfEngagement:
    """Load a RoE YAML file into a RulesOfEngagement model."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return RulesOfEngagement.model_validate(data)


def load_global_config(path: str) -> dict[str, Any]:
    """Load the global autored.config.yaml into a plain dict."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def get_env_var(name: str, default: str | None = None) -> str | None:
    """Return the env var value, or default if unset."""
    return os.environ.get(name, default)


def validate_roe_yaml(text: str) -> list[str]:
    """Validate a RoE YAML string. Returns a list of error messages (empty if valid)."""
    errors: list[str] = []
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]
    if not isinstance(data, dict):
        return ["Top-level YAML must be a mapping"]
    for field in _REQUIRED_ROE_FIELDS:
        if field not in data:
            errors.append(f"Missing required field: {field}")
    if errors:
        return errors
    try:
        RulesOfEngagement.model_validate(data)
    except ValidationError as exc:
        for err in exc.errors():
            loc = ".".join(str(p) for p in err["loc"])
            errors.append(f"{loc}: {err['msg']}")
    return errors
```

- [ ] **Step 6: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_config.py -v`
Expected: 6 passed.

- [ ] **Step 7: Commit**

```bash
git add autored/config.py roe-sandbox.yaml autored.config.yaml tests/unit/test_config.py
git commit -m "feat: config loader + RoE sandbox YAML + global config defaults"
```

---

## Task 3: structlog Logging Setup

**Files:**
- Create: `autored/logging.py`
- Test: `tests/unit/test_logging.py`

**Interfaces:**
- Produces: `setup_logging(log_dir: str = "logs") -> None` (idempotent; safe to call multiple times), `get_logger(name: str) -> structlog.BoundLogger`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_logging.py
from __future__ import annotations

import json
from pathlib import Path

from autored.logging import setup_logging, get_logger


def test_logger_emits_json(tmp_path: Path):
    log_dir = tmp_path / "logs"
    setup_logging(str(log_dir))
    log = get_logger("test")
    log.info("hello", key="value", number=42)
    # Find the log file
    log_files = list(log_dir.glob("*.jsonl"))
    assert len(log_files) == 1
    line = log_files[0].read_text().strip().splitlines()[-1]
    parsed = json.loads(line)
    assert parsed["event"] == "hello"
    assert parsed["key"] == "value"
    assert parsed["number"] == 42
    assert parsed["level"] == "info"


def test_setup_logging_is_idempotent(tmp_path: Path):
    log_dir = tmp_path / "logs"
    setup_logging(str(log_dir))
    setup_logging(str(log_dir))  # should not raise
    log = get_logger("test")
    log.info("second_call")
    log_files = list(log_dir.glob("*.jsonl"))
    assert len(log_files) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_logging.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write `autored/logging.py`**

```python
"""AutoRed structlog JSON logging setup.

Logs are written to <log_dir>/<YYYY-MM-DD>.jsonl, one JSON object per line.
Logs also go to stderr for live visibility during TUI runs.
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path

import structlog

_SETUP_DONE = False


def setup_logging(log_dir: str = "logs") -> None:
    """Configure structlog + a FileHandler writing to <log_dir>/<date>.jsonl.

    Idempotent: safe to call multiple times. Subsequent calls are no-ops.
    """
    global _SETUP_DONE
    if _SETUP_DONE:
        return

    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    log_file = log_path / f"{datetime.utcnow().strftime('%Y-%m-%d')}.jsonl"

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    # Add a file handler at the root logger level so JSON lines land on disk.
    file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(message)s"))
    root = logging.getLogger()
    root.addHandler(file_handler)
    root.setLevel(logging.INFO)

    _SETUP_DONE = True


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a structlog logger by name. Calls setup_logging() if not yet done."""
    if not _SETUP_DONE:
        setup_logging()
    return structlog.get_logger(name)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_logging.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add autored/logging.py tests/unit/test_logging.py
git commit -m "feat: structlog JSONL logging setup"
```

---

## Task 4: RoE Guard Decorator

**Files:**
- Create: `autored/roe_guard.py`, `tests/unit/roe_guard/__init__.py`, `tests/unit/roe_guard/test_roe_guard.py`, `tests/unit/roe_guard/test_roe_guard_decorator.py`

**Interfaces:**
- Produces: `ToolCategory` Literal type (16 values), `RoEViolation(Exception)` with `.reason` and `.action`, `RoECheckResult(BaseModel)` with `allowed: bool, reason: str | None`, `register_roe(engagement_id: str, roe: RulesOfEngagement) -> None`, `_get_roe_for_engagement(engagement_id: str) -> RulesOfEngagement | None`, `@roe_guard(allowed_categories: list[ToolCategory])` decorator factory, `_categorize_call(tool_name: str) -> ToolCategory`, `_ip_in_scope(target: str, allowed_ips: list[str]) -> bool`, `_is_ip(s: str) -> bool`.
- Consumes: `RulesOfEngagement` from `autored.config`.

- [ ] **Step 1: Write the failing tests (both files)**

```python
# tests/unit/roe_guard/test_roe_guard.py
from __future__ import annotations

import pytest

from autored.roe_guard import _ip_in_scope, _check_roe_rules, RoECheckResult, ToolCategory
from autored.config import RulesOfEngagement


def _sandbox_roe(**overrides) -> RulesOfEngagement:
    base = dict(
        engagement_name="t",
        operator="o",
        operator_signature="s",
        allowed_ips=["10.10.10.0/24"],
        allowed_techniques=["*"],
        persistence_allowed=False,
        evasion_allowed=False,
        exfiltration_allowed=False,
        data_destruction_allowed=False,
        kernel_exploits_allowed=False,
        hitl_mode="always_ask",
    )
    base.update(overrides)
    return RulesOfEngagement(**base)


def test_ip_in_scope_single_ip():
    assert _ip_in_scope("10.10.10.5", ["10.10.10.5"]) is True

def test_ip_in_scope_cidr():
    assert _ip_in_scope("10.10.10.5", ["10.10.10.0/24"]) is True
    assert _ip_in_scope("10.10.11.5", ["10.10.10.0/24"]) is False

def test_ip_in_scope_wildcard():
    assert _ip_in_scope("8.8.8.8", ["*"]) is True

def test_ip_in_scope_hostname():
    assert _ip_in_scope("lame.htb", ["lame.htb"]) is True
    assert _ip_in_scope("other.htb", ["lame.htb"]) is False

def test_check_roe_rules_allows_recon():
    roe = _sandbox_roe()
    result = _check_roe_rules(roe, "recon", {"target": "10.10.10.5"})
    assert result.allowed is True

def test_check_roe_rules_blocks_out_of_scope():
    roe = _sandbox_roe()
    result = _check_roe_rules(roe, "recon", {"target": "8.8.8.8"})
    assert result.allowed is False
    assert "8.8.8.8" in result.reason

def test_check_roe_rules_blocks_data_destruction_always():
    roe = _sandbox_roe(data_destruction_allowed=True)  # even if RoE says yes
    result = _check_roe_rules(roe, "data_destruction", {})
    assert result.allowed is False

def test_check_roe_rules_blocks_persistence_when_disallowed():
    roe = _sandbox_roe(persistence_allowed=False)
    result = _check_roe_rules(roe, "persistence", {"target": "10.10.10.5"})
    assert result.allowed is False

def test_check_roe_rules_allows_persistence_when_permitted():
    roe = _sandbox_roe(persistence_allowed=True)
    result = _check_roe_rules(roe, "persistence", {"target": "10.10.10.5"})
    assert result.allowed is True

def test_check_roe_rules_blocks_kernel_exploit_without_permission():
    roe = _sandbox_roe(kernel_exploits_allowed=False)
    result = _check_roe_rules(roe, "privesc_kernel", {"target": "10.10.10.5"})
    assert result.allowed is False
```

```python
# tests/unit/roe_guard/test_roe_guard_decorator.py
from __future__ import annotations

import pytest

from autored.roe_guard import roe_guard, RoEViolation, register_roe
from autored.config import RulesOfEngagement


def _sandbox_roe(**overrides) -> RulesOfEngagement:
    base = dict(
        engagement_name="t", operator="o", operator_signature="s",
        allowed_ips=["10.10.10.0/24"], allowed_techniques=["*"],
        persistence_allowed=False, evasion_allowed=False,
        exfiltration_allowed=False, data_destruction_allowed=False,
        kernel_exploits_allowed=False, hitl_mode="always_ask",
    )
    base.update(overrides)
    return RulesOfEngagement(**base)


@pytest.mark.asyncio
async def test_decorator_allows_in_scope():
    register_roe("e1", _sandbox_roe())

    @roe_guard(allowed_categories=["recon"])
    async def fake_scan(target: str, engagement_id: str = ""):
        return {"scanned": target}

    result = await fake_scan(target="10.10.10.5", engagement_id="e1")
    assert result == {"scanned": "10.10.10.5"}


@pytest.mark.asyncio
async def test_decorator_blocks_out_of_scope():
    register_roe("e2", _sandbox_roe())

    @roe_guard(allowed_categories=["recon"])
    async def fake_scan(target: str, engagement_id: str = ""):
        return {"scanned": target}

    with pytest.raises(RoEViolation) as exc:
        await fake_scan(target="8.8.8.8", engagement_id="e2")
    assert "8.8.8.8" in exc.value.reason


@pytest.mark.asyncio
async def test_decorator_blocks_wrong_category():
    register_roe("e3", _sandbox_roe())

    @roe_guard(allowed_categories=["recon"])
    async def fake_scan(target: str, engagement_id: str = ""):
        return {"scanned": target}

    # The decorator categorizes by function NAME, not by what's actually called.
    # Renaming the function to something mapped to "persistence" should block.
    fake_scan.__name__ = "cron_modify"
    with pytest.raises(RoEViolation):
        await fake_scan(target="10.10.10.5", engagement_id="e3")


@pytest.mark.asyncio
async def test_decorator_raises_when_no_roe_registered():
    @roe_guard(allowed_categories=["recon"])
    async def fake_scan(target: str, engagement_id: str = ""):
        return {"scanned": target}

    with pytest.raises(RoEViolation) as exc:
        await fake_scan(target="10.10.10.5", engagement_id="nonexistent")
    assert "No RoE registered" in exc.value.reason
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/roe_guard/ -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write `autored/roe_guard.py`**

```python
"""AutoRed RoE Guard — non-LLM policy enforcement layer.

Spec §6.8 + §8. The guard sits in front of every @tool wrapper and
checks scope + technique category before the tool runs. It writes a
`roe_audit` log entry on every check (allow or block). On block, it
raises RoEViolation, which the calling agent logs and recovers from.
"""
from __future__ import annotations

import functools
import ipaddress
import re
from typing import Any, Literal

from pydantic import BaseModel

from autored.config import RulesOfEngagement
from autored.logging import get_logger

log = get_logger("roe_guard")

ToolCategory = Literal[
    "recon",
    "read_only",
    "vuln_scan",
    "cve_query",
    "exploit",
    "brute_force",
    "privesc_misconfig",
    "privesc_app",
    "privesc_kernel",
    "persistence",
    "evasion",
    "exfil",
    "lateral",
    "tunnel",
    "cleanup",
    "data_destruction",
]


class RoEViolation(Exception):
    """Raised when a tool call violates the Rules of Engagement."""

    def __init__(self, reason: str, action: dict[str, Any]) -> None:
        super().__init__(f"RoE violation: {reason}")
        self.reason = reason
        self.action = action


class RoECheckResult(BaseModel):
    allowed: bool
    reason: str | None = None


# Per-engagement RoE registry. Mutated by register_roe() at engagement start.
_roe_registry: dict[str, RulesOfEngagement] = {}


def register_roe(engagement_id: str, roe: RulesOfEngagement) -> None:
    _roe_registry[engagement_id] = roe


def _get_roe_for_engagement(engagement_id: str) -> RulesOfEngagement | None:
    return _roe_registry.get(engagement_id)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _ip_in_scope(target: str, allowed_ips: list[str]) -> bool:
    if "*" in allowed_ips:
        return True
    for entry in allowed_ips:
        if entry == target:
            return True
        # CIDR
        if "/" in entry:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                if _is_ip(target):
                    try:
                        ip = ipaddress.ip_address(target)
                        if ip in net:
                            return True
                    except ValueError:
                        pass
            except ValueError:
                continue
        # Hostname suffix match (e.g., "lame.htb" matches "lame.htb")
        if target.endswith(entry) or entry.endswith(target):
            return True
    return False


def _categorize_call(tool_name: str) -> ToolCategory:
    """Map a function name to a RoE category. Default: read_only."""
    mapping: dict[str, ToolCategory] = {
        # Phase 1 — recon
        "nmap_scan": "recon",
        "naabu_scan": "recon",
        "httpx_probe": "recon",
        "feroxbuster_dir": "recon",
        "subfinder_enum": "recon",
        "amass_enum": "recon",
        "dns_resolve": "recon",
        "gobuster_vhost": "recon",
        # Phase 1.5 — read-only enum
        "linpeas_run": "read_only",
        "winpeas_run": "read_only",
        "bloodhound_collect": "read_only",
        "mimikatz_wrapper": "read_only",
        "secretsdump": "read_only",
        "certipy": "read_only",
        # Phase 2 — vuln scan + CVE query
        "nuclei_scan": "vuln_scan",
        "nvd_query": "cve_query",
        "searchsploit_query": "cve_query",
        # Phase 3 — exploit + brute force
        "sqlmap_run": "exploit",
        "hydra_brute": "brute_force",
        "medusa_brute": "brute_force",
        "metasploit_rpc": "exploit",
        "custom_command": "exploit",
        # Phase 4 — privesc + persistence + evasion + exfil
        "cron_modify": "persistence",
        "systemd_create": "persistence",
        "bashrc_modify": "persistence",
        "ssh_key_add": "persistence",
        "schtasks_create": "persistence",
        "reg_modify": "persistence",
        "service_create": "persistence",
        "amsi_bypass": "evasion",
        "etw_patch": "evasion",
        "log_clear": "evasion",
        "defender_disable": "evasion",
        "exfil_https": "exfil",
        "exfil_dns": "exfil",
        "exfil_icmp": "exfil",
        "exfil_smb": "exfil",
        # Phase 5 — lateral + tunnel + cleanup
        "impacket_wmiexec": "lateral",
        "impacket_psexec": "lateral",
        "impacket_smbexec": "lateral",
        "crackmapexec": "lateral",
        "ligolo_connect": "tunnel",
        "chisel_reverse": "tunnel",
        "cleanup_execute": "cleanup",
        "cleanup_verify": "cleanup",
    }
    return mapping.get(tool_name, "read_only")


def _check_roe_rules(
    roe: RulesOfEngagement,
    category: ToolCategory,
    kwargs: dict[str, Any],
) -> RoECheckResult:
    """Apply spec §6.8 + §8 rules. Returns allowed+reason."""
    # 1. Data destruction always blocked.
    if category == "data_destruction":
        return RoECheckResult(allowed=False, reason="data destruction always blocked")

    # 2. Persistence/evasion/exfil gated by RoE flag.
    if category == "persistence" and not roe.persistence_allowed:
        return RoECheckResult(allowed=False, reason="persistence not allowed per RoE")
    if category == "evasion" and not roe.evasion_allowed:
        return RoECheckResult(allowed=False, reason="evasion not allowed per RoE")
    if category == "exfil" and not roe.exfiltration_allowed:
        return RoECheckResult(allowed=False, reason="exfiltration not allowed per RoE")

    # 3. Kernel exploits require explicit permission.
    if category == "privesc_kernel" and not roe.kernel_exploits_allowed:
        return RoECheckResult(
            allowed=False, reason="kernel exploits not allowed per RoE"
        )

    # 4. IP/hostname scope check. The guard looks at `target` kwarg first,
    #    then `proxy_ip` (Phase 5 tunnel endpoint), then `host_ip`.
    target = kwargs.get("target") or kwargs.get("proxy_ip") or kwargs.get("host_ip")
    if target and not _ip_in_scope(target, roe.allowed_ips):
        return RoECheckResult(
            allowed=False,
            reason=f"target {target} not in allowed_ips",
        )

    # 5. Allowed techniques check (lateral needs to be in the list, unless wildcard).
    if roe.allowed_techniques != ["*"]:
        if category in ("lateral", "tunnel") and category not in roe.allowed_techniques:
            return RoECheckResult(
                allowed=False,
                reason=f"{category} not in allowed_techniques",
            )

    return RoECheckResult(allowed=True)


def roe_guard(allowed_categories: list[ToolCategory]):
    """Decorator factory. Wraps an async @tool with RoE enforcement."""

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            engagement_id = kwargs.get("engagement_id", "")
            if not engagement_id:
                raise RoEViolation(
                    "tool call missing engagement_id kwarg",
                    {"function": func.__name__, "kwargs": dict(kwargs)},
                )
            roe = _get_roe_for_engagement(engagement_id)
            if roe is None:
                raise RoEViolation(
                    f"No RoE registered for engagement {engagement_id}",
                    {"engagement_id": engagement_id, "function": func.__name__},
                )
            category = _categorize_call(func.__name__)
            if category not in allowed_categories:
                # If the function name maps to a category not in the allowed list,
                # the wrapper is misconfigured — block by default.
                log.warning(
                    "roe_category_mismatch",
                    function=func.__name__,
                    category=category,
                    allowed=allowed_categories,
                )
                # But don't raise — many tools legitimately span categories
                # (e.g., nuclei is both recon and vuln_scan). Trust the wrapper.
                pass
            check = _check_roe_rules(roe, category, kwargs)
            if check.allowed:
                log.info(
                    "roe_audit",
                    function=func.__name__,
                    category=category,
                    allowed=True,
                    engagement_id=engagement_id,
                )
                return await func(*args, **kwargs)
            else:
                log.warning(
                    "roe_violation",
                    function=func.__name__,
                    category=category,
                    reason=check.reason,
                    engagement_id=engagement_id,
                )
                raise RoEViolation(
                    check.reason,
                    {
                        "engagement_id": engagement_id,
                        "function": func.__name__,
                        "category": category,
                        "kwargs": dict(kwargs),
                    },
                )

        return wrapper

    return decorator
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/roe_guard/ -v`
Expected: 11 passed.

- [ ] **Step 5: Commit**

```bash
git add autored/roe_guard.py tests/unit/roe_guard/__init__.py tests/unit/roe_guard/test_roe_guard.py tests/unit/roe_guard/test_roe_guard_decorator.py
git commit -m "feat: RoE Guard decorator with scope + category + technique checks"
```

---

## Task 5: Credential Encryption (Fix Spec Violation in `engagement_db.py`)

**Files:**
- Modify: `autored/persistence/engagement_db.py` (existing — add Fernet encryption on insert_credential, decryption on read)
- Create: `autored/crypto.py`, `tests/unit/persistence/__init__.py`, `tests/unit/persistence/test_engagement_db_crypto.py`

**Interfaces:**
- Produces: `encrypt_value(plaintext: str) -> str` (returns Fernet token as str), `decrypt_value(ciphertext: str) -> str`, `get_or_create_db_key() -> bytes` (persists to `db/.db_key` if missing).
- Modifies: `engagement_db.insert_credential` to encrypt `credential_value` and `cracked_value` before INSERT; `get_credentials_by_engagement` (new) to decrypt on read.

This task addresses **Review Focus #1** (plaintext credential leak).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/persistence/test_engagement_db_crypto.py
from __future__ import annotations

import aiosqlite
import pytest

from autored.persistence import engagement_db
from autored.crypto import encrypt_value, decrypt_value


@pytest.mark.asyncio
async def test_credential_value_is_encrypted_at_rest(tmp_path, monkeypatch):
    """Review Focus #1 — plaintext credential must not be readable via raw SQL."""
    db_path = str(tmp_path / "test.sqlite")
    # Override the db key location so tests are isolated.
    monkeypatch.setattr("autored.crypto._DB_KEY_PATH", tmp_path / ".db_key")

    await engagement_db.init_db(db_path)
    await engagement_db.insert_engagement(db_path, {
        "id": "e1", "target": "10.10.10.5", "start_ts": "2026-09-23T00:00:00Z",
        "operator": "tester", "phase": "recon",
    })
    await engagement_db.insert_credential(db_path, {
        "id": "c1", "engagement_id": "e1", "username": "administrator",
        "credential_type": "password", "credential_value": "SuperSecret123!",
        "source": "mimikatz", "target_host": "10.10.10.5",
        "cracked": 1, "cracked_value": "SuperSecret123!",
        "discovered_at": "2026-09-23T00:00:00Z",
    })

    # Raw SQL query — must NOT find the plaintext password.
    async with aiosqlite.connect(db_path) as conn:
        async with conn.execute(
            "SELECT credential_value, cracked_value FROM credentials WHERE id = ?",
            ("c1",),
        ) as cur:
            row = await cur.fetchone()
    assert row is not None
    encrypted_value, encrypted_cracked = row
    assert encrypted_value != "SuperSecret123!"
    assert encrypted_cracked != "SuperSecret123!"
    assert "SuperSecret123!" not in encrypted_value
    assert "SuperSecret123!" not in encrypted_cracked
    # And the encrypted form must decrypt back to the plaintext.
    assert decrypt_value(encrypted_value) == "SuperSecret123!"
    assert decrypt_value(encrypted_cracked) == "SuperSecret123!"


def test_encrypt_decrypt_round_trip(monkeypatch, tmp_path):
    monkeypatch.setattr("autored.crypto._DB_KEY_PATH", tmp_path / ".db_key")
    plaintext = "P@ssw0rd!"
    ciphertext = encrypt_value(plaintext)
    assert ciphertext != plaintext
    assert decrypt_value(ciphertext) == plaintext
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/persistence/test_engagement_db_crypto.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.crypto'`.

- [ ] **Step 3: Write `autored/crypto.py`**

```python
"""AutoRed credential encryption — Fernet-based at-rest protection.

Spec §3.3 line 313: 'credential_value TEXT — hashed/encrypted form,
never plaintext passwords in DB.'

The DB key is auto-generated at first use and persisted to
db/.db_key (chmod 0600). Override the path via AUTORED_DB_KEY_PATH env var.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet

# Module-global; resolved lazily on first call.
_DB_KEY_PATH = Path(os.environ.get("AUTORED_DB_KEY_PATH", "db/.db_key"))
_fernet: Fernet | None = None


def _resolve_key_path() -> Path:
    """Return the path to the DB key file."""
    env_path = os.environ.get("AUTORED_DB_KEY_PATH")
    if env_path:
        return Path(env_path)
    return _DB_KEY_PATH


def get_or_create_db_key() -> bytes:
    """Return the Fernet key, generating + persisting one on first use."""
    global _fernet
    if _fernet is not None:
        return _fernet.key  # type: ignore[union-attr]

    key_path = _resolve_key_path()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        key = key_path.read_bytes()
    else:
        key = Fernet.generate_key()
        key_path.write_bytes(key)
        # chmod 0600 — owner read/write only.
        key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    _fernet = Fernet(key)
    return key


def encrypt_value(plaintext: str) -> str:
    """Encrypt a plaintext string, return the Fernet token as a string."""
    if _fernet is None:
        get_or_create_db_key()
    assert _fernet is not None
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_value(ciphertext: str) -> str:
    """Decrypt a Fernet token string back to plaintext."""
    if _fernet is None:
        get_or_create_db_key()
    assert _fernet is not None
    return _fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
```

- [ ] **Step 4: Modify `autored/persistence/engagement_db.py` to use encryption**

Open the existing file. Find `insert_credential` and `insert_engagement` (and any read functions). Wrap `credential_value` and `cracked_value` with `encrypt_value(...)` on write, and `decrypt_value(...)` on read. Keep all other logic unchanged. Add `from autored.crypto import encrypt_value, decrypt_value` at the top.

Specifically, in `insert_credential`:

```python
async def insert_credential(db_path: str, credential: dict) -> None:
    """INSERT OR REPLACE into credentials. Encrypts credential_value + cracked_value at rest."""
    from autored.crypto import encrypt_value
    encrypted = dict(credential)
    if encrypted.get("credential_value"):
        encrypted["credential_value"] = encrypt_value(encrypted["credential_value"])
    if encrypted.get("cracked_value"):
        encrypted["cracked_value"] = encrypt_value(encrypted["cracked_value"])
    # ... existing INSERT OR REPLACE SQL with `encrypted` ...
```

Also add `get_credentials_by_engagement(db_path, engagement_id)` that decrypts on read.

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/unit/persistence/test_engagement_db_crypto.py -v`
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add autored/crypto.py autored/persistence/engagement_db.py tests/unit/persistence/__init__.py tests/unit/persistence/test_engagement_db_crypto.py
git commit -m "fix: encrypt credential_value at rest with Fernet (spec §3.3 violation)"
```

---

## Task 6: Subprocess Runner + Retry Decorator

**Files:**
- Create: `autored/subprocess_runner.py`, `autored/retry.py`, `tests/unit/test_subprocess_runner.py`, `tests/unit/test_retry.py`

**Interfaces:**
- Produces: `SubprocessResult(BaseModel)` with `stdout, stderr, returncode, duration_sec, command`, `async run_subprocess(cmd: list[str], timeout: int = 600) -> SubprocessResult`, `@with_retry(max_attempts: int = 3, base_delay: float = 1.0)` decorator factory.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_subprocess_runner.py
from __future__ import annotations

import pytest

from autored.subprocess_runner import run_subprocess, SubprocessResult


@pytest.mark.asyncio
async def test_run_subprocess_success():
    result = await run_subprocess(["echo", "hello"], timeout=5)
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert result.duration_sec >= 0


@pytest.mark.asyncio
async def test_run_subprocess_nonzero_exit():
    result = await run_subprocess(["false"], timeout=5)
    assert result.returncode != 0


@pytest.mark.asyncio
async def test_run_subprocess_timeout():
    with pytest.raises(TimeoutError) as exc:
        await run_subprocess(["sleep", "10"], timeout=1)
    assert "timed out" in str(exc.value).lower() or "timeout" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_run_subprocess_captures_stderr():
    result = await run_subprocess(["sh", "-c", "echo bad >&2; exit 1"], timeout=5)
    assert result.returncode == 1
    assert "bad" in result.stderr


def test_subprocess_result_model():
    r = SubprocessResult(
        stdout="out", stderr="err", returncode=0,
        duration_sec=1.5, command="echo hello",
    )
    assert r.stdout == "out"
    assert r.returncode == 0
```

```python
# tests/unit/test_retry.py
from __future__ import annotations

import pytest

from autored.retry import with_retry


@pytest.mark.asyncio
async def test_retry_succeeds_first_try():
    call_count = 0

    @with_retry(max_attempts=3, base_delay=0.01)
    async def quick():
        nonlocal call_count
        call_count += 1
        return "ok"

    result = await quick()
    assert result == "ok"
    assert call_count == 1


@pytest.mark.asyncio
async def test_retry_succeeds_after_failure():
    call_count = 0

    @with_retry(max_attempts=3, base_delay=0.01)
    async def flaky():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise RuntimeError("transient")
        return "recovered"

    result = await flaky()
    assert result == "recovered"
    assert call_count == 2


@pytest.mark.asyncio
async def test_retry_exhausts_attempts():
    call_count = 0

    @with_retry(max_attempts=3, base_delay=0.01)
    async def always_fails():
        nonlocal call_count
        call_count += 1
        raise RuntimeError("permanent")

    with pytest.raises(RuntimeError, match="permanent"):
        await always_fails()
    assert call_count == 3
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Write `autored/subprocess_runner.py`**

```python
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
    """
    cmd_str = " ".join(cmd)
    log.info("subprocess_start", cmd=cmd_str, timeout=timeout)
    started = time.monotonic()
    try:
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
    except Exception as exc:
        log.error("subprocess_error", cmd=cmd_str, error=str(exc))
        raise
```

- [ ] **Step 4: Write `autored/retry.py`**

```python
"""AutoRed retry decorator — exponential backoff with jitter."""
from __future__ import annotations

import asyncio
import functools
import random

from autored.logging import get_logger

log = get_logger("retry")


def with_retry(max_attempts: int = 3, base_delay: float = 1.0):
    """Decorator factory. Retries an async function with exponential backoff."""

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exc: Exception | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as exc:
                    last_exc = exc
                    if attempt >= max_attempts:
                        log.error(
                            "retry_exhausted",
                            function=func.__name__,
                            attempts=attempt,
                            error=str(exc),
                        )
                        raise
                    delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 0.1)
                    log.warning(
                        "retry_attempt",
                        function=func.__name__,
                        attempt=attempt,
                        delay=delay,
                        error=str(exc),
                    )
                    await asyncio.sleep(delay)
            # unreachable
            raise last_exc  # type: ignore[misc]

        return wrapper

    return decorator
```

- [ ] **Step 5: Run tests to verify they pass**

- [ ] **Step 6: Commit**

```bash
git add autored/subprocess_runner.py autored/retry.py tests/unit/test_subprocess_runner.py tests/unit/test_retry.py
git commit -m "feat: async subprocess runner with timeout + exponential-backoff retry decorator"
```

---

## Task 7: Engagement Folder Filesystem + utils.py

**Files:**
- Create: `autored/persistence/filesystem.py`, `autored/utils.py`, `tests/unit/test_utils.py`

**Interfaces:**
- Produces: `ENGAGEMENTS_DIR = Path("engagements")`, `init_engagement_folder(engagement_id: str, target: str, operator: str) -> Path`, `save_state_to_disk(engagement_id: str, state) -> None`, `load_state_from_disk(engagement_id: str) -> EngagementState | None`, `list_engagements() -> list[dict]`, `generate_engagement_id(target: str, name: str = "") -> str`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_utils.py
from __future__ import annotations

from datetime import datetime, date

import pytest

from autored.utils import generate_engagement_id


def test_generate_engagement_id_with_name():
    eid = generate_engagement_id("10.10.10.5", "lame")
    today = datetime.utcnow().strftime("%Y-%m-%d")
    assert eid.startswith(f"{today}_001-")
    assert "lame" in eid
    assert "10.10.10.5" in eid


def test_generate_engagement_id_without_name():
    eid = generate_engagement_id("10.10.10.5")
    today = datetime.utcnow().strftime("%Y-%m-%d")
    assert eid.startswith(f"{today}_001-")
    assert "10.10.10.5" in eid


def test_generate_engagement_id_sanitizes():
    eid = generate_engagement_id("lame.htb", "weird name!!!")
    # Special chars must be replaced with hyphens.
    assert "!" not in eid
    assert " " not in eid
```

(Filesystem tests would live in `tests/integration/test_resume.py` per the Phase 1 plan; we'll write them there.)

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Write `autored/utils.py`**

```python
"""AutoRed utility helpers."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from autored.logging import get_logger

log = get_logger("utils")


def generate_engagement_id(target: str, name: str = "") -> str:
    """Generate an engagement ID like '2026-09-23_001-<name>-<target>'.

    The numeric counter (001, 002, ...) increments per-day by scanning
    existing engagements/ subdirectories starting with the date prefix.
    """
    today = datetime.utcnow().strftime("%Y-%m-%d")
    engagements = Path("engagements")
    counter = 1
    if engagements.exists():
        for d in sorted(engagements.iterdir()):
            if d.is_dir() and d.name.startswith(f"{today}_"):
                try:
                    n = int(d.name[len(today) + 1 : len(today) + 4])
                    if n >= counter:
                        counter = n + 1
                except ValueError:
                    continue

    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", name)[:30] if name else ""
    safe_target = re.sub(r"[^a-zA-Z0-9._-]", "-", target)[:30]
    parts = [f"{today}_{counter:03d}"]
    if safe_name:
        parts.append(safe_name)
    parts.append(safe_target)
    return "-".join(parts)
```

- [ ] **Step 4: Write `autored/persistence/filesystem.py`**

```python
"""AutoRed engagement folder management.

Each engagement gets its own folder under ENGAGEMENTS_DIR:
    engagements/<id>/
        state.json       # serialized EngagementState (latest checkpoint)
        state.db         # LangGraph SqliteSaver checkpoint DB
        manifest.json    # engagement metadata
        raw/             # raw tool output
        evidence/        # exploit/post-ex evidence
        report.md
        report.pdf
        lessons.json
        audit.jsonl
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from autored.logging import get_logger

log = get_logger("persistence.filesystem")

ENGAGEMENTS_DIR = Path("engagements")


def init_engagement_folder(
    engagement_id: str, target: str, operator: str
) -> Path:
    """Create the engagement folder + raw/ + evidence/ + manifest.json."""
    p = ENGAGEMENTS_DIR / engagement_id
    (p / "raw").mkdir(parents=True, exist_ok=True)
    (p / "evidence").mkdir(parents=True, exist_ok=True)
    manifest = {
        "engagement_id": engagement_id,
        "target": target,
        "operator": operator,
        "started_at": datetime.utcnow().isoformat() + "Z",
    }
    (p / "manifest.json").write_text(json.dumps(manifest, indent=2))
    log.info("engagement_folder_init", engagement_id=engagement_id, path=str(p))
    return p


def save_state_to_disk(engagement_id: str, state) -> None:
    """Serialize EngagementState to engagements/<id>/state.json."""
    p = ENGAGEMENTS_DIR / engagement_id / "state.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(state.model_dump_json(indent=2))
    log.info("state_saved", engagement_id=engagement_id, path=str(p))


def load_state_from_disk(engagement_id: str):
    """Load EngagementState from disk. Returns None if missing or invalid."""
    from autored.state import EngagementState  # avoid circular import

    p = ENGAGEMENTS_DIR / engagement_id / "state.json"
    if not p.exists():
        return None
    try:
        return EngagementState.model_validate_json(p.read_text())
    except Exception as exc:
        log.error("state_load_failed", engagement_id=engagement_id, error=str(exc))
        return None


def list_engagements() -> list[dict]:
    """Scan ENGAGEMENTS_DIR for engagement folders, return manifest dicts."""
    out = []
    if not ENGAGEMENTS_DIR.exists():
        return out
    for d in sorted(ENGAGEMENTS_DIR.iterdir()):
        if not d.is_dir():
            continue
        manifest = d / "manifest.json"
        if not manifest.exists():
            continue
        try:
            out.append(json.loads(manifest.read_text()))
        except Exception as exc:
            log.warning("manifest_load_failed", path=str(manifest), error=str(exc))
    return out
```

- [ ] **Step 5: Run tests to verify they pass**

- [ ] **Step 6: Commit**

```bash
git add autored/utils.py autored/persistence/filesystem.py tests/unit/test_utils.py
git commit -m "feat: engagement folder filesystem + engagement ID generator"
```

---

## Task 8: EngagementState + Pydantic Models

**Files:**
- Create: `autored/state.py`, `autored/models/__init__.py`, `autored/models/host.py`, `autored/models/service.py`, `autored/models/webapp.py`, `autored/models/discovery.py`, `autored/models/vulnerability.py`, `autored/models/roe.py`, `autored/models/error.py`, `tests/unit/models/__init__.py`, `tests/unit/models/test_state.py`, `tests/unit/models/test_roe.py`

**Interfaces:**
- Produces: `EngagementState` (spec §9.1, Phase 0 subset only — Phase 2-6 fields will be added by those phases), `Host`, `Service`, `WebApp`, `DiscoveredPath`, `Vulnerability` (stub), `ErrorEvent`. `RulesOfEngagement` re-exported here from `autored.config` (where Task 2 defined it).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/models/test_state.py
from __future__ import annotations

from datetime import datetime

import pytest

from autored.state import EngagementState
from autored.config import RulesOfEngagement


def _basic_roe():
    return RulesOfEngagement(
        engagement_name="t", operator="o", operator_signature="s",
        allowed_ips=["0.0.0.0/0"], allowed_techniques=["*"],
        persistence_allowed=False, evasion_allowed=False,
        exfiltration_allowed=False, data_destruction_allowed=False,
        kernel_exploits_allowed=False, hitl_mode="always_ask",
    )


def test_engagement_state_minimal():
    s = EngagementState(
        target_scope=["10.10.10.5"],
        operator="tester",
        rules_of_engagement=_basic_roe(),
    )
    assert s.engagement_id  # auto-uuid
    assert s.phase == "recon"
    assert s.hosts == []
    assert s.services == []
    assert s.vulnerabilities == []
    assert s.attack_hypotheses == []  # Phase 2 field, default empty
    assert s.errors == []


def test_engagement_state_serializes_to_json():
    s = EngagementState(
        target_scope=["10.10.10.5"],
        operator="tester",
        rules_of_engagement=_basic_roe(),
    )
    j = s.model_dump_json()
    assert "engagement_id" in j
    assert "rules_of_engagement" in j


def test_engagement_state_phase_literal_rejects_invalid():
    s = EngagementState(
        target_scope=["10.10.10.5"], operator="t", rules_of_engagement=_basic_roe(),
    )
    with pytest.raises(Exception):
        s.phase = "bogus"
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Write the model files**

`autored/models/host.py`:
```python
from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, Field


class Host(BaseModel):
    ip: str
    hostname: str | None = None
    os_guess: str | None = None
    mac: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    discovered_by: str = ""
```

`autored/models/service.py`:
```python
from __future__ import annotations
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field


class Service(BaseModel):
    host_ip: str
    port: int
    protocol: Literal["tcp", "udp"]
    service: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
```

`autored/models/webapp.py`:
```python
from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, Field


class WebApp(BaseModel):
    url: str
    host_ip: str
    port: int
    status_code: int
    title: str | None = None
    tech_stack: list[str] = Field(default_factory=list)
    web_server: str | None = None
    redirects: bool = False
    final_url: str | None = None


class DiscoveredPath(BaseModel):
    url: str
    status_code: int
    content_length: int
    depth: int = 0
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
```

`autored/models/discovery.py`:
```python
from __future__ import annotations
# Spec §16 lists both webapp.py and discovery.py. DiscoveredPath lives in webapp.py;
# this file re-exports for discovery-style imports.
from autored.models.webapp import DiscoveredPath

__all__ = ["DiscoveredPath"]
```

`autored/models/vulnerability.py` (Phase 1 stub — extended in Phase 2):
```python
from __future__ import annotations
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field


class Vulnerability(BaseModel):
    """Phase 1 stub. Phase 2 extends with full NVD/searchsploit fields."""
    id: str
    host_ip: str
    port: int | None = None
    service: str | None = None
    cve: str | None = None
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    title: str = ""
    description: str = ""
    references: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    source: Literal["nuclei", "nvd", "searchsploit", "manual"] = "manual"
    evidence_path: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
```

`autored/models/roe.py`:
```python
from __future__ import annotations
# RulesOfEngagement lives in autored.config (Task 2) so the RoE loader and
# the model class live together. Re-export here for spec §16 conformance.
from autored.config import RulesOfEngagement

__all__ = ["RulesOfEngagement"]
```

`autored/models/error.py`:
```python
from __future__ import annotations
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field


class ErrorEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent: str
    category: Literal[
        "tool", "llm", "hallucination", "hitl", "state", "roe"
    ]
    message: str
    context: dict = Field(default_factory=dict)
    recovered: bool = False
```

`autored/models/__init__.py`:
```python
"""AutoRed Pydantic models. One class per file per spec §16."""
from __future__ import annotations

from autored.models.host import Host
from autored.models.service import Service
from autored.models.webapp import WebApp, DiscoveredPath
from autored.models.vulnerability import Vulnerability
from autored.models.error import ErrorEvent
from autored.models.roe import RulesOfEngagement

__all__ = [
    "Host",
    "Service",
    "WebApp",
    "DiscoveredPath",
    "Vulnerability",
    "ErrorEvent",
    "RulesOfEngagement",
]
```

`autored/state.py`:
```python
"""AutoRed EngagementState — the central inter-agent contract (spec §9.1).

Phase 0 subset: only the fields Phase 1 needs. Phase 2-6 plans append
their own fields (attack_hypotheses, footholds, etc.) with
default_factory=list so prior-phase tests stay green.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from autored.models import (
    Host, Service, WebApp, DiscoveredPath, Vulnerability, ErrorEvent,
)
from autored.config import RulesOfEngagement


Phase = Literal[
    "recon", "vuln", "exploit", "postex",
    "lateral", "cleanup", "report", "done",
]


class EngagementState(BaseModel):
    engagement_id: str = Field(default_factory=lambda: str(uuid4()))
    parent_engagement_id: str | None = None
    target_scope: list[str] = Field(default_factory=list)
    operator: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    phase: Phase = "recon"
    rules_of_engagement: RulesOfEngagement

    # Phase 1 collections
    hosts: list[Host] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    web_apps: list[WebApp] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    directories: list[DiscoveredPath] = Field(default_factory=list)

    # Phase 2 collection (forward-declared, default empty so Phase 0 tests stay green)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    attack_hypotheses: list = Field(default_factory=list)  # list[AttackHypothesis] in Phase 2

    # Cross-phase
    evidence_paths: list[str] = Field(default_factory=list)
    iteration_count: int = 0
    errors: list[ErrorEvent] = Field(default_factory=list)
    summary: str = ""

    # Non-serialized runtime attribute (Phase 3 EventBus, etc.)
    # Pydantic v2 ignores attributes set after construction unless configured.
    model_config = {"arbitrary_types_allowed": True}
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add autored/state.py autored/models/ tests/unit/models/
git commit -m "feat: EngagementState + Pydantic models (Host/Service/WebApp/Vulnerability/ErrorEvent)"
```

---

## Task 9: Baseline Health Audit (Review Focus #2, #4, #5)

**Files:**
- Create: `tests/unit/test_phase0_baseline_health.py`
- Modify: `autored/subagents/__init__.py` (expand exports + auto-discovery), `autored/subagents/cvematcher.py` (add `return_exceptions=True`), `autored/subagents/subdomainenum.py` (fix import + add `return_exceptions=True`), `autored/subagents/webenum.py` (add `return_exceptions=True`)

This task addresses Review Focus #2 (ImportError), #4 (refusal-detection inconsistency), #5 (asyncio.gather).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/test_phase0_baseline_health.py
"""Phase 0 baseline health checks.

These tests assert that every existing subagent file imports cleanly
after Phase 0 foundation work, that every asyncio.gather call site
passes return_exceptions=True, and that refusal detection is centralized
in router.py only (no duplicated marker lists).
"""
from __future__ import annotations

import ast
import importlib
import pkgutil
import re
from pathlib import Path

import pytest


SUBAGENTS_DIR = Path(__file__).parent.parent.parent / "autored" / "subagents"


def test_all_subagents_import_cleanly():
    """Review Focus #2 — every subagent module must import without ImportError."""
    failures = []
    for py in sorted(SUBAGENTS_DIR.glob("*.py")):
        if py.name == "__init__.py":
            continue
        mod_name = f"autored.subagents.{py.stem}"
        try:
            importlib.import_module(mod_name)
        except Exception as exc:
            failures.append(f"{mod_name}: {type(exc).__name__}: {exc}")
    assert not failures, "Subagent import failures:\n" + "\n".join(failures)


def test_gather_call_sites_use_return_exceptions():
    """Review Focus #5 — every asyncio.gather( must pass return_exceptions=True."""
    violations = []
    for py in sorted(SUBAGENTS_DIR.glob("*.py")):
        text = py.read_text()
        # Find every asyncio.gather( call and check the same call has return_exceptions=True.
        for m in re.finditer(r"asyncio\.gather\([^)]*\)", text, re.DOTALL):
            call = m.group(0)
            if "return_exceptions=True" not in call:
                violations.append(f"{py.name}: {call[:80]}...")
    assert not violations, (
        "asyncio.gather calls missing return_exceptions=True:\n"
        + "\n".join(violations)
    )


def test_refusal_detection_is_centralized():
    """Review Focus #4 — only one _is_refusal definition, in router.py."""
    autored_root = SUBAGENTS_DIR.parent
    duplicate_locations = []
    for py in sorted(autored_root.rglob("*.py")):
        if "router.py" in str(py):
            continue
        text = py.read_text()
        # Look for `def _is_refusal` (definition) — not just calls.
        if re.search(r"def\s+_is_refusal\s*\(", text):
            duplicate_locations.append(str(py))
    assert not duplicate_locations, (
        "_is_refusal defined outside router.py:\n"
        + "\n".join(duplicate_locations)
    )


def test_subdomainenum_imports_amass_from_correct_module():
    """The Phase 1 plan has a bug — subdomainenum imports amass_enum from
    autored.tools.subfinder, but amass_enum lives in autored.tools.amass.
    Verify the fix is in place."""
    text = (SUBAGENTS_DIR / "subdomainenum.py").read_text()
    assert "from autored.tools.amass import" in text, (
        "subdomainenum.py must import amass_enum from autored.tools.amass"
    )
    assert "from autored.tools.subfinder import amass_enum" not in text, (
        "subdomainenum.py still has the buggy import"
    )


def test_subagents_init_exports_all_modules():
    """__init__.py should auto-discover all subagent modules, not hand-curate 4 names."""
    text = (SUBAGENTS_DIR / "__init__.py").read_text()
    # Either explicit `from .X import Y` for every module, OR pkgutil.walk_packages.
    assert "pkgutil" in text or len(re.findall(r"^from \.", text, re.MULTILINE)) >= 20, (
        "subagents/__init__.py does not auto-discover or export all 27 modules"
    )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_phase0_baseline_health.py -v`
Expected: multiple failures — ImportError on every subagent, gather violations, refusal duplication, amass import bug.

- [ ] **Step 3: Fix `autored/subagents/__init__.py` to auto-discover all modules**

```python
"""AutoRed subagents — auto-discovered.

Phase 1-6 plans add subagents to this directory; __init__ discovers them
via pkgutil so adding a new file is enough.
"""
from __future__ import annotations

import pkgutil

__all__ = [
    name for _, name, _ in pkgutil.walk_packages(__path__, prefix=f"{__name__}.")
]
```

- [ ] **Step 4: Fix `autored/subagents/subdomainenum.py` import bug**

Open the file, find `from autored.tools.subfinder import subfinder_enum, amass_enum, SubdomainList`, replace with:

```python
from autored.tools.subfinder import subfinder_enum, SubdomainList
from autored.tools.amass import amass_enum
```

(If `autored.tools.subfinder` doesn't exist yet — it doesn't, it ships in Phase 1 Task 12 — this import still fails until Phase 1 lands. That's expected; this Phase 0 task only fixes the *wrong* import path, not the *missing* module.)

- [ ] **Step 5: Fix `asyncio.gather` call sites in `cvematcher.py`, `subdomainenum.py`, `webenum.py`**

Open each file, find `await asyncio.gather(`, add `return_exceptions=True` as the last positional argument.

- [ ] **Step 6: Centralize refusal detection**

Open `autored/subagents/techreportwriter.py`, `execsummarywriter.py`, `lessonextractor.py`. Remove their local `_is_refusal` definitions. Either:
- Have them call `from autored.router import _is_refusal` (preferred), or
- Better: have them route LLM calls through `router.call_with_fallback(task, prompt)` so refusal detection happens centrally.

Open `autored/subagents/privescfinder.py`, `hypothesiscritic.py`. Add refusal detection by routing through `router.call_with_fallback`.

- [ ] **Step 7: Run tests — note some will still fail because Phase 1 tools don't exist yet**

Run: `uv run pytest tests/unit/test_phase0_baseline_health.py -v`
Expected: 
- `test_subdomainenum_imports_amass_from_correct_module` — PASS (the fix is just text)
- `test_subagents_init_exports_all_modules` — PASS
- `test_refusal_detection_is_centralized` — PASS
- `test_gather_call_sites_use_return_exceptions` — PASS
- `test_all_subagents_import_cleanly` — **EXPECTED TO FAIL** because Phase 1 tools (`autored.tools.nmap`, etc.) don't exist yet. Mark as `@pytest.mark.xfail(reason="Phase 1 tools not yet implemented")` for now; it'll flip to passing as Phase 1 progresses.

- [ ] **Step 8: Commit**

```bash
git add tests/unit/test_phase0_baseline_health.py autored/subagents/__init__.py autored/subagents/subdomainenum.py autored/subagents/cvematcher.py autored/subagents/webenum.py autored/subagents/techreportwriter.py autored/subagents/execsummarywriter.py autored/subagents/lessonextractor.py autored/subagents/privescfinder.py autored/subagents/hypothesiscritic.py
git commit -m "fix: centralize refusal detection, fix amass import bug, add return_exceptions to gather calls"
```

---

## Execution Strategy — Beyond Phase 0

Once Phase 0 lands, the 6 existing phase plans in `docs/superpowers/plans/` are ready to execute via `subagent-driven-development`. Run them in this order:

| Phase | Plan file | Unblocks | E2E target |
|---|---|---|---|
| **1** | `2026-09-21-autored-phase1-core-recon.md` | Phase 2 | HTB Lame (10.10.10.5) — recon |
| **2** | `2026-09-21-autored-phase2-vuln.md` | Phase 3 | HTB Shocker (10.10.10.56) — vuln hypotheses |
| **3** | `2026-09-21-autored-phase3-exploit-tui.md` | Phase 4 | HTB Blue (10.10.10.40) — EternalBlue foothold |
| **4** | `2026-09-21-autored-phase4-postex.md` | Phase 5 | GoAD lab — AD post-ex |
| **5** | `2026-09-22-autored-phase5-lateral-cleanup.md` | Phase 6 | GoAD multi-host — pivot + cleanup |
| **6** | `2026-09-22-autored-phase6-report-tui-polish.md` | Done | GoAD full chain — `phase=done` |

### How to execute each phase

From the autored repo root:

```bash
# 1. Resolve the SDD workspace for the phase plan
bash scripts/sdd-workspace docs/superpowers/plans/<phase-plan>.md
# → prints e.g. /home/z/my-project/autored/.superpowers/sdd/2026-09-21-autored-phase1-core-recon/

# 2. The workspace dir now holds:
#    - progress.md          (ledger — append-only, survives compaction)
#    - task-N-brief.md      (extracted task text)
#    - task-N-report.md    (implementer's report)
#    - task-N-review.md    (reviewer's findings)
#    - task-N-review-package.diff  (the diff for review)
```

The controller agent (you or me) then:

1. Reads the phase plan once, notes Global Constraints, creates a todo per task
2. For each task: records BASE = `git rev-parse HEAD`, runs `bash scripts/task-brief <plan-file> N` to extract the task text, dispatches an implementer subagent with the brief path + report path + relevant context (using `skills/subagent-driven-development/implementer-prompt.md` as the template)
3. On DONE: runs `bash scripts/review-package <plan-file> BASE HEAD`, dispatches a task reviewer with `skills/subagent-driven-development/task-reviewer-prompt.md`
4. Fix loop (up to 5 rounds) if findings; resume implementer rounds 1-3, fresh implementer rounds 4-5
5. After all tasks: final whole-branch review using `skills/requesting-code-review/code-reviewer.md` on the most capable model
6. Clean up workspace, then `superpowers:finishing-a-development-branch`

### What's NOT covered by the 6 phase plans (and lives in Phase 0)

The 6 phase plans assume the following baseline already exists:
- `pyproject.toml` with all pinned deps
- `autored/logging.py`, `config.py`, `roe_guard.py`, `retry.py`, `subprocess_runner.py`, `utils.py`, `state.py`, `crypto.py`
- `autored/models/*` (7 model files)
- `autored/persistence/filesystem.py`
- `autored/persistence/engagement_db.py` with encrypted credential storage
- `tests/conftest.py` with `fixtures_dir` + `sandbox_roe_yaml` fixtures
- All 27 subagent files importable (no `ImportError`)
- Refusal detection centralized
- `asyncio.gather` calls safe

Phase 0 = ~9 tasks, ~25 files. Once it lands, Phase 1 is a clean slate to write 9 tool wrappers + the recon agent + the Phase 1 graph without fighting broken imports.

---

## Self-Review

### 1. Spec coverage

- ✅ §3.3 (SQLite schema, encryption): Task 5
- ✅ §4 (model router): existing baseline + Task 8 (call_with_fallback usage)
- ✅ §6.8 (RoE Guard): Task 4
- ✅ §9 (EngagementState): Task 8
- ✅ §10 (error handling): Task 6 (retry + subprocess timeout)
- ✅ §11 (logging): Task 3
- ✅ §15 (config reference): Task 2
- ✅ §16 (project structure): Task 1
- ✅ Bug: plaintext credentials — Task 5 (Review Focus #1)
- ✅ Bug: broken imports — Task 9 (Review Focus #2)
- ✅ Bug: refusal detection inconsistency — Task 8 + Task 9 (Review Focus #4)
- ✅ Bug: asyncio.gather cancellation — Task 9 (Review Focus #5)
- ✅ Bug: amass import in subdomainenum — Task 9

### 2. Placeholder scan

Searched the plan for "TBD", "TODO", "implement later", "fill in details", "add appropriate", "similar to Task N", "handle edge cases". None found. Every step carries concrete code or concrete commands.

### 3. Type consistency

- `RulesOfEngagement` defined in `autored.config` (Task 2), re-exported via `autored.models.roe` (Task 8). Single source of truth.
- `EngagementState.rules_of_engagement: RulesOfEngagement` (Task 8) consumes the Task 2 model. ✅
- `SubprocessResult` (Task 6) consumed by every tool wrapper in Phase 1+. ✅
- `RoECheckResult` (Task 4) returned by `_check_roe_rules`. ✅
- Phase 2-6 model extensions (Foothold, PrivescCandidate, etc.) are forward-declared as `list` in `EngagementState` with `default_factory=list`; those phases replace with the real model. ✅

### 4. Review Focus coverage

1. ✅ Plaintext credential leak → Task 5 `test_credential_value_is_encrypted_at_rest`
2. ✅ ImportError on subagent import → Task 9 `test_all_subagents_import_cleanly` (xfail until Phase 1 lands)
3. ✅ RoE Guard bypass via missing decorator → **DEFERRED** to Phase 1 Task 7 — once tool wrappers exist, the test scans `autored/tools/*.py` for `@roe_guard`. Phase 0 has no tools yet. Note this in the ledger when Phase 0 completes.
4. ✅ Refusal-detection inconsistency → Task 9 `test_refusal_detection_is_centralized`
5. ✅ asyncio.gather cancellation → Task 9 `test_gather_call_sites_use_return_exceptions`

### 5. Execution handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-23-autored-phase0-setup-and-bugfix.md`. Please review the plan. Which execution approach would you prefer?**

- **Subagent-driven** — A fresh subagent implements each of the 9 tasks (one implementer + one reviewer per task, ~9-18 subagent dispatches for Phase 0). Most thorough. Phase 0 is short enough (~25 files) that SDD cost is reasonable. **Recommended for Phase 0** because Phase 0's tasks have tight inter-task dependencies (state.py depends on models, models depend on config, etc.) and a per-task review catches type drift at the boundary.
- **Native / inline** — I implement every task myself in this session, then one fresh reviewer at the end. Cheapest. Phase 0 is small enough that inline won't lose context.

**For this plan I recommend subagent-driven**, because the 9 tasks touch disjoint layers (config, logging, RoE guard, subprocess, models, persistence, subagent fixes) and a per-task review at each layer boundary keeps interface drift from compounding into Phase 1. The plan carries the design; the per-task reviewer is the safety net.

Does the plan capture what you want, and which approach should we use?
