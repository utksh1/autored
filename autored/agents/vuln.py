"""AutoRed Vuln Agent — LangGraph node (Phase 2, Task 9).

Synthesizes attack hypotheses from recon findings + NVD CVE matches +
ExploitDB search results + cross-engagement Chroma memory. The
synthesis step uses the routed Sonnet model
(``get_model("synthesize_findings")`` via ``router.call_with_fallback``)
and is then self-critiqued by the HypothesisCritic sub-agent
(``get_model("second_opinion")`` = DeepSeek). The critique loop runs at
most 3 iterations; convergence is when DeepSeek returns no critique OR
returns "sound" verdicts for every hypothesis. On non-convergence the
loop ships the last-revised best version rather than stalling the
engagement (the ``for...else`` clause logs a warning).

Flow
----
1. ``cvematcher_subagent`` queries NVD for each service with product+version.
2. ``exploitfinder_subagent`` queries ExploitDB for each unique
   product+version surfaced by the CVE matcher.
3. ``ChromaStore.query_similar_findings`` returns cross-engagement
   memory hits (gracefully degrades to ``[]`` on any error).
4. ``router.call_with_fallback("synthesize_findings", prompt)`` runs
   Sonnet to produce 3-5 ranked ``AttackHypothesis`` objects.
5. Self-critique loop (max 3 iterations):
   - ``hypothesiscritic_subagent`` (DeepSeek) returns per-hypothesis
     verdicts (sound / needs_revision / discard).
   - Convergence: critique empty OR all verdicts "sound".
   - On non-convergence, Sonnet revises via ``VULN_REVISION_PROMPT``.
6. Sort by rank, advance phase to ``"exploit"``.
"""

from __future__ import annotations

import asyncio
import json

from langchain_core.runnables import RunnableConfig

from autored.logging import get_logger
from autored.models import AttackHypothesis, ErrorEvent, Vulnerability
from autored.persistence.chroma_store import ChromaStore
from autored.router import call_with_fallback
from autored.state import EngagementState
from autored.subagents import cvematcher as _cvematcher_mod
from autored.subagents import exploitfinder as _exploitfinder_mod
from autored.subagents import hypothesiscritic as _hypothesiscritic_mod

log = get_logger("agents.vuln")

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
      "risks": ["may crash SMB service", "high detection likelihood"],
      "command_preview": "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.10.5; run'"
    }}
  ]
}}

Rules:
- Cite real CVEs only. If you're unsure, say so in confidence.
- Use real Metasploit module paths if you reference Metasploit.
- Rank by (exploitability × impact × confidence), highest first
- If no viable hypotheses, return {{"hypotheses": []}} and explain why in rationale
- Return ONLY the JSON, no markdown, no explanation
"""

VULN_REVISION_PROMPT = """You are the Vuln Agent revising your attack hypotheses based on critique.

Original hypotheses:
{hypotheses_json}

Critique from senior reviewer:
{critique_json}

For each hypothesis that received "needs_revision" or "discard":
- Fix the issues identified
- If "discard", remove it
- If "needs_revision", fix and keep the same rank
- If "sound", leave unchanged

Return the revised hypotheses in the same JSON schema as before:
{{
  "hypotheses": [...]
}}

Return ONLY the JSON, no markdown.
"""

# Max self-critique iterations before we ship the best version anyway.
_MAX_CRITIQUE_ITERATIONS = 3


async def vuln_node(
    state: EngagementState, config: RunnableConfig
) -> dict:
    """LangGraph node: runs the Vuln Agent.

    Returns a state-shaped dict with the keys:
    - ``vulnerabilities``: prior vulnerabilities + NVD/searchsploit-derived ones.
    - ``attack_hypotheses``: ranked ``AttackHypothesis`` objects.
    - ``phase``: ``"exploit"`` (advances the engagement).
    - ``iteration_count``: prior count + 1 (one vuln-node pass).

    ``config`` is accepted for I1 (Phase 3 fix wave) consistency with
    the other Phase 1-3 nodes (recon, exploit, report). Vuln doesn't
    currently consume the EventBus — synthesis + critique have no HitL
    gate — but the signature stays uniform so Phase 4+ nodes can adopt
    the same pattern without back-filling signatures.
    """
    log.info("vuln_start", engagement_id=state.engagement_id)

    # Step 1: CVEMatcher queries NVD for each service in parallel.
    services_dicts = [s.model_dump() for s in state.services]
    cve_output = await _cvematcher_mod.cvematcher_subagent.ainvoke(
        {
            "services": services_dicts,
            "engagement_id": state.engagement_id,
        }
    )
    cve_matches = cve_output.cve_matches
    log.info("vuln_cve_matches", count=len(cve_matches))

    # Step 2: ExploitFinder queries ExploitDB for each unique product+version
    # surfaced by the CVE matcher (parallel). Empty unique_queries short-
    # circuits the gather so we don't construct an empty coroutine list.
    unique_queries = list(
        {f"{m.product} {m.version}" for m in cve_matches if m.product and m.version}
    )
    if unique_queries:
        exploit_outputs = await asyncio.gather(
            *[
                _exploitfinder_mod.exploitfinder_subagent.ainvoke(
                    {
                        "query": q,
                        "engagement_id": state.engagement_id,
                    }
                )
                for q in unique_queries
            ]
        )
    else:
        exploit_outputs = []
    log.info("vuln_exploit_searches", queries=len(unique_queries))

    # Step 3: Query Chroma for cross-engagement similar past findings.
    # Gracefully degrade to [] on any failure — Chroma is a memory
    # enhancement, not a hard dependency.
    try:
        chroma = ChromaStore()
        query_text = " ".join(
            f"{s.product} {s.version}" for s in state.services if s.product and s.version
        )
        chroma_results = (
            await chroma.query_similar_findings(text=query_text, top_k=5) if query_text else []
        )
    except Exception as e:
        log.warning("vuln_chroma_query_failed", error=str(e))
        chroma_results = []

    # Step 4: Sonnet generates 3-5 ranked hypotheses. Per Phase 1 R1, route
    # through call_with_fallback so refusal detection + DeepSeek fallback
    # are centralized. Returns the response content as a str directly (no
    # .content access at the call site).
    #
    # I1 (Phase 2 final review): wrap call_with_fallback in try/except so a
    # Sonnet transport outage (network error, 429, 500) degrades to empty
    # hypotheses + an ErrorEvent, symmetric with NVD's graceful [] on 5xx.
    # The engagement continues to the exploit phase, which handles empty
    # hypotheses gracefully per the Phase 3 plan.
    prompt = VULN_HYPOTHESES_PROMPT.format(
        hosts_summary=_summarize_hosts(state.hosts),
        services_summary=_summarize_services(state.services),
        web_apps_summary=_summarize_web_apps(state.web_apps),
        nuclei_findings=_summarize_nuclei(state.vulnerabilities),
        cve_matches=_summarize_cve_matches(cve_matches),
        chroma_results=_summarize_chroma(chroma_results),
    )
    try:
        content = await call_with_fallback("synthesize_findings", prompt)
    except Exception as exc:
        log.warning("vuln_synthesis_failed", error=str(exc))
        return {
            "vulnerabilities": state.vulnerabilities,
            "attack_hypotheses": [],
            "phase": "exploit",
            "iteration_count": state.iteration_count + 1,
            "errors": state.errors
            + [
                ErrorEvent(
                    agent="vuln",
                    category="llm",
                    message=f"LLM synthesis failed: {exc}",
                    recovered=False,
                )
            ],
        }
    hypotheses = _parse_hypotheses(content)
    log.info("vuln_hypotheses_generated", count=len(hypotheses))

    # Step 5: Self-critique loop (max 3 iterations). Convergence is when
    # DeepSeek returns no critique OR all verdicts are "sound". On
    # non-convergence, the for...else clause logs a warning and we ship
    # the last-revised best version rather than stalling the engagement.
    for iteration in range(_MAX_CRITIQUE_ITERATIONS):
        if not hypotheses:
            # Nothing left to critique — either the LLM returned [] or a
            # revision discarded everything. Break out so we don't burn
            # the remaining iterations on no-op critique calls.
            break
        critique_output = await _hypothesiscritic_mod.hypothesiscritic_subagent.ainvoke(
            {
                "hypotheses": [h.model_dump() for h in hypotheses],
                "engagement_id": state.engagement_id,
            }
        )
        critique = critique_output.critique
        if not critique or all(c.get("verdict") == "sound" for c in critique):
            log.info("vuln_critique_converged", iteration=iteration + 1)
            break
        # Revise hypotheses based on critique (discards removed, fixes
        # applied). I1 (Phase 2 final review): _revise_hypotheses wraps
        # its own call_with_fallback in try/except and returns the input
        # list unchanged on a transport failure, so a mid-iteration Sonnet
        # outage degrades to "no revision this round" rather than crashing
        # the loop.
        hypotheses = await _revise_hypotheses(hypotheses, critique)
        log.info(
            "vuln_hypotheses_revised",
            iteration=iteration + 1,
            count=len(hypotheses),
        )
    else:
        # Loop completed without break — persistent non-convergence.
        # Ship the last-revised best version anyway so the engagement
        # progresses to the Exploit Agent.
        log.warning(
            "vuln_critique_non_convergence",
            shipped_best=True,
            iterations=_MAX_CRITIQUE_ITERATIONS,
        )

    # Step 6: Sort by rank (1 = highest priority first).
    hypotheses.sort(key=lambda h: h.rank)

    log.info("vuln_done", hypotheses_count=len(hypotheses))

    return {
        "vulnerabilities": state.vulnerabilities + _extract_vulns(cve_matches, exploit_outputs),
        "attack_hypotheses": hypotheses,
        "phase": "exploit",
        "iteration_count": state.iteration_count + 1,
    }


def _parse_hypotheses(content: str) -> list[AttackHypothesis]:
    """Parse LLM hypothesis JSON. Strips markdown code fences first.

    Returns ``[]`` on any parse failure (rather than raising) so the
    vuln_node's self-critique loop short-circuits cleanly on an
    unparseable Sonnet response.
    """
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        log.error("vuln_hypotheses_parse_failed", error=str(e), content=content[:500])
        return []
    raw = data.get("hypotheses", []) if isinstance(data, dict) else []
    if not isinstance(raw, list):
        log.error("vuln_hypotheses_unexpected_shape", payload_type=type(raw).__name__)
        return []
    out: list[AttackHypothesis] = []
    for h in raw:
        try:
            out.append(AttackHypothesis.model_validate(h))
        except Exception as e:
            log.error(
                "vuln_hypothesis_validation_failed",
                error=str(e),
                hypothesis=str(h)[:200],
            )
    return out


async def _revise_hypotheses(
    hypotheses: list[AttackHypothesis], critique: list[dict]
) -> list[AttackHypothesis]:
    """Send hypotheses + critique back to Sonnet for revision.

    Uses the same routed model + fallback path as the initial synthesis
    step (``call_with_fallback("synthesize_findings", ...)``) so refusal
    detection + DeepSeek fallback apply uniformly.

    I1 (Phase 2 final review): on a Sonnet transport outage (network
    error, 429, 500) the call raises and is caught here — we log a
    warning and return the input ``hypotheses`` unchanged so the
    self-critique loop in ``vuln_node`` keeps its existing list rather
    than crashing mid-iteration. The next loop iteration will re-critique
    the (unchanged) list; if Sonnet stays down, the loop runs out and
    the for...else clause ships the unchanged list as the best version.
    """
    prompt = VULN_REVISION_PROMPT.format(
        hypotheses_json=json.dumps([h.model_dump() for h in hypotheses], indent=2),
        critique_json=json.dumps(critique, indent=2),
    )
    try:
        content = await call_with_fallback("synthesize_findings", prompt)
    except Exception as exc:
        log.warning("vuln_revision_failed", error=str(exc), iteration_hypotheses=len(hypotheses))
        return hypotheses
    return _parse_hypotheses(content)


def _summarize_hosts(hosts) -> str:
    return "\n".join(f"- {h.ip} ({h.hostname or 'no hostname'})" for h in hosts) or "None"


def _summarize_services(services) -> str:
    return (
        "\n".join(
            f"- {s.host_ip}:{s.port} {s.service} {s.product or ''} {s.version or ''}"
            for s in services
        )
        or "None"
    )


def _summarize_web_apps(web_apps) -> str:
    return (
        "\n".join(
            f"- {w.url} (status {w.status_code}, tech: {', '.join(w.tech_stack)})" for w in web_apps
        )
        or "None"
    )


def _summarize_nuclei(vulns) -> str:
    return (
        "\n".join(
            f"- [{v.severity}] {v.title} ({v.cve or 'no CVE'})"
            for v in vulns
            if v.source == "nuclei"
        )
        or "None"
    )


def _summarize_cve_matches(matches) -> str:
    lines = []
    for m in matches:
        for cve in m.cves:
            lines.append(
                f"- {m.host_ip}:{m.port} {m.product} {m.version} → "
                f"{cve.cve_id} (CVSS {cve.cvss_score})"
            )
    return "\n".join(lines) or "None"


def _summarize_chroma(results) -> str:
    if not results:
        return "No similar past findings."
    lines = []
    for r in results[:3]:
        meta = r.get("metadata", {}) if isinstance(r, dict) else {}
        doc = r.get("document", "") if isinstance(r, dict) else str(r)
        lines.append(f"- Past finding: {str(doc)[:100]} (CVE: {meta.get('cve', 'unknown')})")
    return "\n".join(lines)


def _extract_vulns(cve_matches, exploit_outputs) -> list[Vulnerability]:
    """Convert CVE matches + exploit search results into Vulnerability records.

    CVE matches become NVD-sourced vulnerabilities keyed by host+port+cve.
    ExploitDB hits become searchsploit-sourced vulnerabilities with empty
    host_ip (the search wasn't host-specific — the Exploit Agent will
    re-scope them against the live target).
    """
    severity_map = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
    }
    vulns: list[Vulnerability] = []
    for match in cve_matches:
        for cve in match.cves:
            vulns.append(
                Vulnerability(
                    host_ip=match.host_ip,
                    port=match.port,
                    service=match.service,
                    cve=cve.cve_id,
                    severity=severity_map.get((cve.severity or "").upper(), "info"),
                    title=(cve.description[:100] if cve.description else cve.cve_id),
                    description=cve.description,
                    references=list(cve.references) if cve.references else [],
                    cvss_score=cve.cvss_score,
                    source="nvd",
                )
            )
    for eo in exploit_outputs:
        for exp in eo.exploits:
            vulns.append(
                Vulnerability(
                    host_ip="",  # exploit search isn't host-specific
                    title=exp.title,
                    description=f"ExploitDB {exp.edb_id}: {exp.title} ({exp.type})",
                    references=[f"https://www.exploit-db.com/exploits/{exp.edb_id}"],
                    source="searchsploit",
                )
            )
    return vulns
