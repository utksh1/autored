# AutoRed — Autonomous Red Team Copilot

> **Status:** Pre-alpha. Foundation phase (Phase 0) in progress. 27 of ~195 files
> exist as the subagent library layer from a prior attempt; the rest of the
> framework (state, graph, RoE Guard, CLI, tools, agents, TUI, reporting,
> tests) is being built out using the superpowers SDD workflow.

AutoRed is a semi-autonomous red-team copilot that runs the full kill chain —
recon → vuln → exploit → post-ex → lateral → cleanup → report — against
sandboxed targets, with human-in-the-loop gates configurable to auto-approve
in sandbox mode.

## Repository Layout

```
autored/                          # The Python package
  autored/                        # Source code (subagents/, tools/, agents/, ...)
  docs/superpowers/               # Design + per-phase implementation plans
  skills/                         # Superpowers skill library (vendored)
  hooks/                          # Superpowers session hooks
  scripts/                        # Superpowers bash scripts (sdd-workspace, task-brief, review-package)
  tests/                          # Test suite (target: 300+ tests across 6 phases)
  pyproject.toml                  # Pinned dependencies (created in Phase 1)
  README.md                       # This file
```

## Documentation

- **Authoritative design:** [`docs/superpowers/specs/2026-09-21-autored-design.md`](docs/superpowers/specs/2026-09-21-autored-design.md)
- **Phase plans:** [`docs/superpowers/plans/`](docs/superpowers/plans/) — Phases 1–6 (each in superpowers format)
- **Phase 0 meta-plan:** [`docs/superpowers/plans/2026-09-23-autored-phase0-setup-and-bugfix.md`](docs/superpowers/plans/2026-09-23-autored-phase0-setup-and-bugfix.md)

## Execution Approach

Per the design spec, all implementation uses the superpowers
`subagent-driven-development` skill: a fresh implementer subagent per task,
a task reviewer after each, and a final whole-branch review per phase.

To execute a phase:

```bash
# From the autored repo root
bash scripts/sdd-workspace docs/superpowers/plans/2026-09-21-autored-phase1-core-recon.md
# → prints the workspace path; ledger, briefs, reports live there
```

Then a controller agent (you, or me on request) dispatches one implementer
per task using `skills/subagent-driven-development/implementer-prompt.md` as
the template, followed by a task reviewer using
`skills/subagent-driven-development/task-reviewer-prompt.md`. Five fix
rounds maximum per task; the breaker triggers an adjudication in the
ledger.

## E2E Tests

E2E tests run against live targets (HackTheBox). They are **skipped by default**
and require an explicit opt-in via `AUTORED_E2E=1`. The Phase 1 E2E test
(`tests/e2e/test_phase1_lame.py`) runs the full Phase 1 graph — real LLM, real
`nmap` / `naabu` / `httpx` / `nuclei` / `feroxbuster` / `subfinder` / `amass` /
`dnsx` / `gobuster` subprocesses — against HTB Lame (`10.10.10.5`).

### Prerequisites

- **HackTheBox VPN connected** (`sudo openvpn user.ovpn`)
- **`ANTHROPIC_API_KEY`** set (Claude Sonnet 4.5 powers `plan_recon`)
- **CLI tools installed and on `PATH`**: `nmap`, `naabu`, `httpx`, `nuclei`,
  `feroxbuster`, `subfinder`, `amass`, `dnsx`, `gobuster`
- **`AUTORED_E2E=1`** env var (the gate)

### Run

```bash
# 1. Connect to HackTheBox VPN
sudo openvpn user.ovpn

# 2. Verify target is reachable
ping 10.10.10.5

# 3. Set env vars
export ANTHROPIC_API_KEY=sk-ant-...
export AUTORED_E2E=1

# 4. Run E2E test
uv run pytest tests/e2e/test_phase1_lame.py -v -s
```

### Expected runtime

5-15 minutes against HTB Lame (the box is intentionally slow to scan).
The test passes if all of the following hold:

- `nmap` discovers the canonical Lame open ports **21** (FTP — vsftpd 2.3.4),
  **22** (SSH — OpenSSH 4.7p1), and **445** (SMB — Samba 3.0.20).
- All dispatched tools (`naabu`, `httpx`, `nuclei`, `feroxbuster`, `dnsx`)
  execute without raising.
- The Phase 1 graph terminates with `state.phase` in `{"vuln", "done"}`.
- At least 1 host (`10.10.10.5`) is recorded in `state.hosts`.

The final state is saved to `engagements/<id>/state.json` for inspection.

### Phase 2 E2E Test (Shocker)

Phase 2 adds the Vuln Agent (CVE correlation + self-critique + cross-engagement
memory). The Phase 2 E2E test (`tests/e2e/test_phase2_shocker.py`) runs the
full Phase 2 graph — recon **and** vuln — against HTB Shocker
(`10.10.10.56`). Same skip-by-default gate as Phase 1; the Phase 1
prerequisites carry over and add a second API key.

#### Prerequisites (in addition to Phase 1)

- **`DEEPSEEK_API_KEY`** set (DeepSeek powers the `second_opinion` slot used
  by the `hypothesiscritic` sub-agent's self-critique loop).
- **`searchsploit`** CLI installed and on `PATH` (ExploitDB offline mirror —
  the `exploitfinder` sub-agent wraps it).
- **HTB Shocker reachable** (`ping 10.10.10.56` after VPN connects).

#### Run

```bash
# 1. Connect to HackTheBox VPN
sudo openvpn user.ovpn

# 2. Verify Shocker is reachable
ping 10.10.10.56

# 3. Set env vars (both API keys + the E2E gate)
export ANTHROPIC_API_KEY=sk-ant-...
export DEEPSEEK_API_KEY=sk-...
export AUTORED_E2E=1

# 4. Run Phase 2 E2E test
uv run pytest tests/e2e/test_phase2_shocker.py -v -s
```

#### Expected runtime & pass criteria

10-15 minutes against HTB Shocker. The test passes if all of the following
hold:

- Recon discovers port 80 (Apache httpd 2.2.22 — the Shellshock surface).
- The Vuln Agent produces at least 1 attack hypothesis.
- At least one hypothesis references Shellshock (`CVE-2014-6271`) — via
  `h.cve` or `h.technique`.
- The Phase 2 graph terminates with `state.phase` in `{"done", "exploit"}`.

The final state (including the ranked `attack_hypotheses` list) is saved to
`engagements/<id>/state.json` for inspection.

### Phase 3 E2E Test (Blue)

Phase 3 adds the Exploit Agent (HitL gates + LLM-planned dispatch +
verified footholds via Metasploit / sqlmap / hydra / custom commands).
The Phase 3 E2E test (`tests/e2e/test_phase3_blue.py`) runs the full
Phase 3 graph — recon **and** vuln **and** exploit — against HTB Blue
(`10.10.10.40`), the canonical EternalBlue (MS17-010) box. Same skip-by-
default gate as Phases 1 + 2; the Phase 1 + 2 prerequisites carry over
and add the Metasploit RPC daemon.

#### Prerequisites (in addition to Phase 2)

- **Metasploit RPC daemon running** on `127.0.0.1:55553` with password
  `msf`:

  ```bash
  msfrpcd -P msf -p 55553 -a 127.0.0.1
  ```

  The `msfagent` sub-agent connects to this daemon to dispatch the
  `exploit/windows/smb/ms17_010_eternalblue` module against the target.
- **A reachable reverse-handler port** on the operator's HTB VPN IP.
  The LLM-generated exploit plan includes `lhost=<vpn-ip>` and
  `lport=4444`; the meterpreter `reverse_tcp` payload dials back to
  this address. Verify the VPN IP with `ip addr show tun0` and ensure
  port 4444 is open on the operator's host for the callback.
- **HTB Blue reachable** (`ping 10.10.10.40` after VPN connects).

#### Run

```bash
# 1. Connect to HackTheBox VPN
sudo openvpn user.ovpn

# 2. Verify Blue is reachable
ping 10.10.10.40

# 3. Start msfrpcd (in a separate terminal)
msfrpcd -P msf -p 55553 -a 127.0.0.1

# 4. Set env vars (both API keys + the E2E gate)
export ANTHROPIC_API_KEY=sk-ant-...
export DEEPSEEK_API_KEY=sk-...
export AUTORED_E2E=1

# 5. Run Phase 3 E2E test
uv run pytest tests/e2e/test_phase3_blue.py -v -s
```

#### Expected runtime & pass criteria

15-20 minutes against HTB Blue (recon ~5min, vuln ~5min,
exploit ~5-10min including msfrpcd module dispatch + payload delivery +
meterpreter callback). The test passes if all of the following hold:

- Recon discovers port 445 (SMB — Microsoft Windows 7 / Server 2008 R2,
  the canonical EternalBlue surface).
- The Vuln Agent produces at least 1 attack hypothesis.
- At least one hypothesis references EternalBlue / MS17-010 /
  `CVE-2017-0144` via `h.cve` or `h.technique`.
- The Exploit Agent records at least 1 verified `Foothold` whose
  `method` field references EternalBlue / MS17-010.
- The Phase 3 graph terminates with `state.phase == "done"` (the
  report stub ran after the exploit node).

The final state (including the verified `footholds` list with
`host_ip`, `method`, `access_type`, and `hypothesis_rank`) is saved to
`engagements/<id>/state.json` for inspection.

### Phase 4 E2E Test (GoAD)

Phase 4 adds the Post-Ex Agent (enumeration → BloodHound → privesc →
persistence → evasion → exfiltration on each verified foothold, with RoE
hard-blocks and HitL soft-gates). The Phase 4 E2E test
(`tests/e2e/test_phase4_goad.py`) runs the full Phase 4 graph — recon
**and** vuln **and** exploit **and** postex — against a self-hosted GoAD
(Game Of Active Directory) multi-VM AD lab. Same skip-by-default gate as
Phases 1-3; the Phase 1 + 2 + 3 prerequisites carry over and add the
GoAD lab + impacket + bloodhound-python + Neo4j.

GoAD is preferred over HTB for Phase 4 because post-ex activities —
especially BloodHound collection and AD-trust lateral movement — need a
real multi-VM AD environment to exercise against. HTB single-VM boxes
don't surface the AD trust graph.

#### Prerequisites (in addition to Phase 3)

- **GoAD lab deployed and running locally** (VirtualBox + Vagrant).
  See <https://github.com/Orange-Cyberdefense/GOAD> for setup. The
  default GoAD subnet is `192.168.56.0/24`; the DC is typically
  `192.168.56.10` and member servers `.11/.12/.13`. Override the
  target IP for non-default GoAD deployments via `AUTORED_GOAD_TARGET`.
- **HackTheBox VPN NOT required** (GoAD is self-hosted). The operator
  must instead be on the GoAD host-only network
  (`ping 192.168.56.10` succeeds from the operator's host).
- **`impacket` installed** (`pip install impacket`) — powers the
  `secretsdump.py` remote-hash-dump used by the CredHarvester sub-agent
  against Windows targets with credentials.
- **`bloodhound-python` installed** (`pip install bloodhound-python`) —
  powers the BloodHound data collector that maps the AD trust graph
  from harvested credentials.
- **Neo4j running** for BloodHound ingestion (the Phase 4
  `bloodhound_collect` tool ingests the JSON via Neo4j). Start it with
  `docker-compose neo4j up -d` from the AutoRed repo root.

#### Run

```bash
# 1. Deploy + start the GoAD lab (see upstream GOAD README)
cd GOAD && vagrant up

# 2. Verify GoAD DC is reachable
ping 192.168.56.10

# 3. Start msfrpcd (in a separate terminal)
msfrpcd -P msf -p 55553 -a 127.0.0.1

# 4. Start Neo4j (in another terminal)
docker-compose neo4j up -d

# 5. Set env vars (both API keys + the E2E gate)
export ANTHROPIC_API_KEY=sk-ant-...
export DEEPSEEK_API_KEY=sk-...
export AUTORED_E2E=1

# 6. (Optional) override the default GoAD target IP
export AUTORED_GOAD_TARGET=192.168.56.10

# 7. Run Phase 4 E2E test
uv run pytest tests/e2e/test_phase4_goad.py -v -s
```

#### Expected runtime & pass criteria

30-60 minutes against GoAD (recon ~5min, vuln ~5min, exploit ~5-10min
for the initial foothold, then post-ex ~15-30min covering WindowsEnum
+ mimikatz + BloodHound + persistence + evasion + exfil on the
foothold). The test passes if all of the following hold:

- Recon discovers at least 1 Windows host on the GoAD subnet.
- The Vuln Agent produces at least 1 attack hypothesis.
- The Exploit Agent records at least 1 verified `Foothold` whose
  `access_type` indicates a Windows session (`winrm` / `shell` with
  `method` referencing a Windows exploit like MS17-010 or a
  credential-based foothold).
- The Post-Ex Agent records at least 1 `local_users` entry (WindowsEnum
  surfaced local accounts).
- The Post-Ex Agent records at least 1 `harvested_secrets` entry
  (mimikatz dumped NTLM hashes or plaintext passwords).
- The Post-Ex Agent records at least 1 `persistence_artifacts` entry
  (persistence is permitted by the sandbox RoE + `auto_approve`
  short-circuits the HitL gate — a `scheduled_task` or `registry_run`
  implant is established on the foothold).
- Every `PersistenceArtifact` carries a non-empty `removal_command`
  (Phase 5 Cleanup Agent walks the list and runs them verbatim).
- The Phase 4 graph terminates with `state.phase == "done"` (the
  report stub ran after the postex node).

The final state (including the populated `local_users`,
`harvested_secrets`, `privesc_attempts`, `persistence_artifacts`,
`evasion_actions`, and `exfiltration_proof` lists) is saved to
`engagements/<id>/state.json` for inspection.

### Phase 5 E2E Test (GoAD, Multi-Host)

Phase 5 adds the Lateral Agent (pivot + sub-engagement recursion) and
the Cleanup Agent (artifact removal + verification re-scan). The
Phase 5 E2E test (`tests/e2e/test_phase5_goad_multihost.py`) runs the
full chain — recon → vuln → exploit → post-ex → lateral → cleanup —
against **two** GoAD hosts and asserts the engagement pivots onto the
second host, spawns a linked sub-engagement, and leaves zero artifacts
behind. Same skip-by-default gate as Phases 1-4; the Phase 4
prerequisites carry over and add a second reachable GoAD VM plus the
pivot + cleanup CLI tools.

#### Prerequisites (in addition to Phase 4)

- **A second reachable GoAD VM** — the test pivots from the primary
  target (default `192.168.56.22` / SRV02) to a second host (default
  `192.168.56.11`). Override with `AUTORED_GOAD_TARGET` and
  `AUTORED_GOAD_PIVOT_TARGET`. Verify both are reachable:
  `ping 192.168.56.22 && ping 192.168.56.11`.
- **`crackmapexec` on your `$PATH`** (Kali default; if you only have
  `netexec`, symlink it:
  `ln -s $(which netexec) /usr/local/bin/crackmapexec`). Powers the
  PivotExecutor sub-agent's credential validation spray against the
  pivot target.
- **`impacket` installed** (already required for Phase 4's
  secretsdump) — also powers the PivotExecutor's
  `wmiexec` / `psexec` / `smbexec` remote-exec channels and the
  Cleanup Agent's `impacket_wmiexec` transport for removal commands.
- **`chisel` and `ligolo-ng` on `$PATH`** — the TunnelSetup
  sub-agent's two backed tools. Only invoked when a pivot needs a
  tunnel (the pivot target sits on a subnet the AutoRed host can't
  route to), but install them ahead of time so a non-routable pivot
  target doesn't crash the run.
- **`sshpass` on `$PATH`** — the cleanup tool's `ssh` transport for
  Linux targets. Only used if a Linux host appears in the scope, but
  install it ahead of time.
- **`AUTORED_LHOST` set** to the operator's VirtualBox host-only IP
  (default `192.168.56.1`) — the chisel reverse SOCKS tunnel dials
  back to this address when a pivot needs a tunnel.
- **Working domain credentials are NOT pre-seeded** — the chain
  harvests them itself: exploit → foothold → post-ex secretsdump →
  administrator hash → pivot.

#### Run

```bash
# 1. Bring up GoAD (two+ VMs), verify both targets are reachable
ping 192.168.56.22 && ping 192.168.56.11

# 2. Start msfrpcd (see Phase 3 section)
msfrpcd -P msf -p 55553 -a 127.0.0.1 -U msf -L

# 3. Start Neo4j (Phase 4 BloodHound ingestion — see Phase 4 section)
docker-compose neo4j up -d

# 4. Set env vars (both API keys + the E2E gate + LHOST + the two targets)
export ANTHROPIC_API_KEY=sk-ant-...
export DEEPSEEK_API_KEY=sk-...
export AUTORED_E2E=1
export AUTORED_LHOST=192.168.56.1
export AUTORED_GOAD_TARGET=192.168.56.22
export AUTORED_GOAD_PIVOT_TARGET=192.168.56.11

# 5. Run (60-90 minutes — two hosts + a sub-engagement)
uv run pytest tests/e2e/test_phase5_goad_multihost.py -v -s
```

#### Expected runtime & pass criteria

60-90 minutes against GoAD (recon ~5min, vuln ~5min, exploit ~5-10min
for the initial foothold, post-ex ~15-30min covering WindowsEnum +
mimikatz + BloodHound + persistence + evasion + exfil on the primary
foothold, lateral pivot ~1-5min, sub-engagement ~20-30min running the
full Phase 4 chain against the pivot target, cleanup ~5-10min for
artifact removal + verification re-scan across both hosts). The test
passes if all of the spec §13.5 ship criteria hold:

- Recon discovers ≥ 2 hosts (both scope targets).
- The Exploit Agent records ≥ 1 foothold on the primary target.
- The Lateral Agent executes ≥ 1 **successful** pivot onto the
  second host (harvested administrator hash via wmiexec pass-the-hash).
- A sub-engagement runs against the pivot target and its `state.json`
  is persisted under `engagements/<sub_id>/state.json` and linked
  from the parent state's `sub_engagements` list.
- The Cleanup Agent removes and **verifies** every persistence
  artifact (zero unverified cleanups — Review Focus #5).
- The Phase 5 graph terminates with `state.phase == "done"`.

The final state (including the populated `pivots`, `movement_paths`,
`sub_engagements`, and `cleanup_results` lists) is saved to
`engagements/<id>/state.json` for inspection.

#### Troubleshooting

- **`no lateral pivot was executed`** — either both hosts got direct
  footholds in the exploit phase (leaving no un-footholded pivot
  target — re-run, or pin the Vuln Agent toward the weaker host), or
  post-ex failed to harvest a username-bearing credential (check
  `harvested_secrets` in `state.json` — secrets need
  `secretsdump:.../<username>`-style sources for the Lateral Agent's
  username parser to pick them up).
- **`pivot success=False`** — crackmapexec / wmiexec auth failed: the
  harvested hash doesn't have admin rights on the pivot target. Try a
  different pivot target VM (GoAD's multi-DC trust graph usually has
  one DC the domain admin hash can pivot onto cleanly).
- **unverified cleanups** — inspect `cleanup_results` in `state.json`:
  each unverified entry carries the exact verify command and the
  output; run it manually against the target host to see what
  remains (typically a scheduled task whose name didn't match the
  removal regex, or a registry Run key under a different hive).

### Phase 6 E2E Test (GoAD, Full Chain)

Phase 6 closes the kill chain: the Report Agent runs after Cleanup and
produces the engagement's deliverables (markdown + PDF + lessons) plus
the cross-engagement memory rows. The Phase 6 E2E test
(`tests/e2e/test_phase6_fullchain.py`) runs the full Phase 6 graph —
recon → vuln → exploit → post-ex → lateral → cleanup → **report** —
against the canonical GoAD primary (`192.168.56.22` by default) and
asserts the spec §13.6 ship criteria: the chain reaches `phase="done"`,
deliverables exist and are non-empty, no harvested secret value appears
verbatim in the report text, the SQLite `engagements` table has exactly
one row for the engagement, and every cleanup result is verified. Same
skip-by-default gate as Phases 1-5; the Phase 1-5 prerequisites carry
over with no additions.

#### Run

```bash
# 1. Bring up GoAD, verify target is reachable
ping 192.168.56.22

# 2. Start msfrpcd (see Phase 3 section)
msfrpcd -P msf -p 55553 -a 127.0.0.1 -U msf -L

# 3. Start Neo4j (see Phase 4 section)
docker-compose neo4j up -d

# 4. Set env vars (both API keys + the E2E gate + LHOST + the target)
export ANTHROPIC_API_KEY=sk-ant-...
export DEEPSEEK_API_KEY=sk-...
export AUTORED_E2E=1
export AUTORED_LHOST=192.168.56.1
export AUTORED_GOAD_TARGET=192.168.56.22

# 5. Run (60-120 minutes — full chain + report generation)
uv run pytest tests/e2e/test_phase6_fullchain.py -v -s
```

#### Expected runtime & pass criteria

60-120 minutes against GoAD (the Phase 5 runtime plus ~30-60s of LLM
time for the report's executive summary + technical report). The test
passes if all of the spec §13.6 ship criteria hold:

- The chain terminates with `state.phase == "done"`.
- `state.footholds` is non-empty.
- `state.report_paths` is not `None` and `report.md` exists & is
  non-empty.
- `lessons.json` exists.
- If `report_paths.pdf_path` is not `None`, the file starts with the
  `%PDF-` magic bytes (skipped when WeasyPrint is unavailable —
  graceful degradation).
- No `secret.secret_value` from `state.harvested_secrets` appears
  verbatim in the report text (live redaction re-check).
- The SQLite `db/engagements.sqlite` `engagements` table has exactly
  one row for the engagement id.
- Every `cleanup_results` entry has `verified == True` (Phase 5
  regression).
- Every `sub_engagements` entry has its `state.json` persisted at
  `sub_state_path`.

The final state (including `report_paths`, `lessons`,
`mitre_mappings`) is saved to `engagements/<id>/state.json` for
inspection; the deliverables land in `engagements/<id>/`.

## Phase 6 — Report Agent, Full TUI, Cross-Engagement Memory

The full kill chain now closes itself: `recon → vuln → exploit →
post-ex → lateral → cleanup → report`, ending in generated
deliverables. The Report Agent runs after Cleanup, assembles the
executive summary + technical report + MITRE ATT&CK matrix, renders
the PDF (when WeasyPrint is available), and writes the cross-engagement
memory rows (SQLite + Chroma) — so the next engagement's Vuln Agent
has prior findings to query when ranking hypotheses.

### Reports

Every engagement produces, under `engagements/<id>/`:

- `report.md` — executive summary + technical report + MITRE ATT&CK
  matrix. The technical report attributes each finding to the phase
  that surfaced it; harvested secrets are redacted (only the
  `secret_type` + `source` appear, never the value).
- `report.pdf` — WeasyPrint render of the markdown. Requires system
  Pango/Cairo; degrades gracefully to markdown-only when unavailable
  (`report_paths.pdf_path` is `None`, the CLI / TUI opens
  `report.md` directly).
- `lessons.json` — extracted lessons (`Lesson` rows: category, body,
  optional MITRE technique id), also persisted to cross-engagement
  memory at report time.

Regenerate the deliverables for any engagement (re-runs the four
report sub-agents + PDF render + memory write):

```bash
autored report <engagement_id>
```

### Cross-engagement memory

Findings, credentials (sha256-hashed — **never** plaintext, spec §3.3),
and lessons are written to `db/engagements.sqlite` (engagements /
findings / credentials / lessons tables) and `db/chroma` (finding
embeddings + technique pattern collections) at report time, by
`persist_engagement_memory`. The Vuln Agent queries this memory when
ranking hypotheses — run engagements against similar targets and it
gets smarter (the Phase 2 `query_similar_findings` read-side finally
has data to find). Memory writes never raise — partial failures
(SQLite up, Chroma down) are logged and the engagement still
completes.

### TUI keybindings (full set)

| Key | Action            | | Key | Action            |
|-----|-------------------|---|-----|-------------------|
| `q` | Quit              | | `f` | Findings table    |
| `d` | Dashboard         | | `s` | State inspector   |
| `e` | Engagements list  | | `v` | Evidence viewer   |
| `l` | Log viewer        | | `g` | Attack graph      |
| `r` | RoE editor        | | `?` / `h` | Help       |

Launch the TUI alongside an orchestration:

```bash
autored run --target 192.168.56.22 --roe roe-sandbox.yaml --tui
```

The orchestrator runs as a background task inside the app; HitL gates
pop the approval modal (auto-approve in sandbox mode still shows in
the activity log, so the operator can audit what was auto-approved
after the fact). The eight Phase 6 screens — EngagementList,
EvidenceViewer, StateInspector, FindingsTable, LogViewer, RoEEditor,
AttackGraph, Help — are all reachable via the keybindings above.
`AgentDetailScreen` is descoped (StateInspector covers agent-state
browsing; documented deviation, spec §13.6 ship list wins over §17.3's
screen inventory).

### CLI (complete)

```bash
autored run --target <ip> --roe <yaml> [--tui|--no-tui]  # full kill chain
autored resume <id>        # checkpoint-resume, state.json fallback
autored report <id>        # regenerate deliverables (md + pdf + lessons)
autored state <id>         # state summary table
autored engagements        # SQLite-backed list (filesystem fallback)
autored roe-wizard         # interactive RoE generator
```

`autored engagements` reads from `db/engagements.sqlite` when it has
rows, falls back to the filesystem scan of `engagements/<id>/manifest.json`
when SQLite is unavailable (spec §14.2). `autored resume` rehydrates
from the LangGraph SQLite checkpointer first, then from
`engagements/<id>/state.json` if the checkpointer is missing or
corrupt.

### Recording a demo (spec §13.6 "demo video" follow-up)

```bash
# Option 1: asciinema (terminal recording, ASCII)
pipx install asciinema
asciinema rec autored-demo.cast --command "autored run --target 192.168.56.22 --roe roe-sandbox.yaml --tui"
asciinema upload autored-demo.cast
# Convert to GIF for embedding: agg autored-demo.cast demo.gif

# Option 2: vhs (deterministic tape with typed pacing — better for
# reproducible demos in CI)
brew install vhs   # or: go install github.com/charmbracelet/vhs@latest
vhs demo.tape      # writes demo.gif from the typed commands
```

A `demo.tape` with typed pacing (`Type "autored run ..."`, `Enter`,
`Sleep 5s`, snapshot) is the recommended approach for the spec §13.6
"demo video" follow-up — it's reproducible and doesn't capture the
operator's keystroke timing.

## License

MIT — see [LICENSE](LICENSE).
