"""Vuln Agent — LangGraph node that turns recon findings into ranked attack hypotheses.

The agent runs a five-stage pipeline:

  1. **CVE correlation** — call ``cvematcher_subagent`` once with every
     service dict; it queries NVD in parallel internally and returns one
     :class:`CveMatch` per service that actually has CVEs.
  2. **Exploit search** — for each unique ``product version`` string that
     appeared in a CVE match, call ``exploitfinder_subagent`` (which
     wraps ``searchsploit``) in parallel. ExploitDB hits become
     :class:`Vulnerability` records (source="searchsploit") and feed the
     Sonnet synthesis prompt as additional context.
  3. **Cross-engagement memory** — query the Chroma ``findings_collection``
     for similar past engagements. Results go into the prompt as *context*,
     not as authoritative — the spec explicitly warns against blindly
     trusting them, so they are summarised alongside the live recon
     findings rather than treated as ground truth.
  4. **Synthesis** — call Sonnet (``synthesize_findings`` slot) with
     ``VULN_HYPOTHESES_PROMPT`` populated from the summaries. Parse the
     JSON response into :class:`AttackHypothesis` objects (markdown code
     fences are stripped defensively).
  5. **Self-critique loop (max 3 iterations)** — alternate
     Sonnet (synthesis) → DeepSeek (critique) → Sonnet (revision) →
     DeepSeek (re-critique). If DeepSeek returns ``sound`` for every
     hypothesis, the loop converges and exits early. If it persists in
     saying ``needs_revision`` / ``discard`` for all three iterations
     the best (last) version is shipped anyway with a non-convergence
     warning logged — never loop forever.

Why we import sub-agent *modules* (not their @tool names)
-------------------------------------------------------
Tests patch the sub-agent @tool objects at their canonical location,
e.g. ``patch("autored.subagents.cvematcher.cvematcher_subagent")``. For
that patch to take effect, ``vuln_node`` must look up the tool via the
module attribute path at *call* time
(``_cvematcher_mod.cvematcher_subagent.ainvoke(...)``) rather than via
a name imported into this module's globals (which would be a frozen
reference to the original tool instance). Same pattern as
``autored/agents/recon.py``.

``ChromaStore`` is imported and instantiated directly inside
``vuln_node`` — tests patch ``autored.agents.vuln.ChromaStore`` to swap
in a MagicMock. The instantiation is wrapped in a try/except so a
Chroma init failure (e.g. permissions on ``db/chroma``) downgrades to
"no cross-engagement context" rather than crashing the whole agent.
"""

import asyncio
import json

from autored.state import EngagementState
from autored.router import get_model
# Import the sub-agent MODULES so test patches on
# `autored.subagents.<x>.<tool_name>` propagate through at call time.
from autored.subagents import (
    cvematcher as _cvematcher_mod,
    exploitfinder as _exploitfinder_mod,
    hypothesiscritic as _hypothesiscritic_mod,
)
from autored.models import Vulnerability, AttackHypothesis
from autored.persistence.chroma_store import ChromaStore
from autored.logging import get_logger

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


async def vuln_node(state: EngagementState) -> dict:
    """LangGraph node: runs the Vuln Agent."""
    log.info("vuln_start", engagement_id=state.engagement_id)

    # Step 1: Query CVEMatcher for each service (parallel internally)
    services_dicts = [s.model_dump() for s in state.services]
    cve_output = await _cvematcher_mod.cvematcher_subagent.ainvoke({
        "services": services_dicts,
        "engagement_id": state.engagement_id,
    })
    # The @tool may return either a CVEMatcherOutput instance (when called
    # directly) or its dict form (depending on the LangChain version /
    # patch surface). Handle both defensively.
    if hasattr(cve_output, "cve_matches"):
        cve_matches = cve_output.cve_matches
    elif isinstance(cve_output, dict):
        cve_matches = cve_output.get("cve_matches", [])
    else:
        cve_matches = []
    log.info("vuln_cve_matches", count=len(cve_matches))

    # Step 2: Query ExploitFinder for each unique product+version (parallel)
    unique_queries = list({
        f"{m.product} {m.version}"
        for m in cve_matches
        if getattr(m, "product", None) and getattr(m, "version", None)
    })
    if unique_queries:
        exploit_outputs = await asyncio.gather(*[
            _exploitfinder_mod.exploitfinder_subagent.ainvoke({
                "query": q,
                "engagement_id": state.engagement_id,
            }) for q in unique_queries
        ])
    else:
        exploit_outputs = []
    log.info("vuln_exploit_searches", queries=len(unique_queries))

    # Step 3: Query Chroma for similar past findings
    try:
        chroma = ChromaStore()
        # Build query text from current services
        query_text = " ".join(
            f"{s.product} {s.version}"
            for s in state.services
            if s.product and s.version
        )
        if query_text:
            chroma_results = await chroma.query_similar_findings(text=query_text, top_k=5)
        else:
            chroma_results = []
    except Exception as e:
        log.warning("vuln_chroma_query_failed", error=str(e))
        chroma_results = []

    # Step 4: Sonnet generates hypotheses
    model = get_model("synthesize_findings")
    prompt = VULN_HYPOTHESES_PROMPT.format(
        hosts_summary=_summarize_hosts(state.hosts),
        services_summary=_summarize_services(state.services),
        web_apps_summary=_summarize_web_apps(state.web_apps),
        nuclei_findings=_summarize_nuclei(state.vulnerabilities),
        cve_matches=_summarize_cve_matches(cve_matches),
        chroma_results=_summarize_chroma(chroma_results),
    )
    response = await model.ainvoke(prompt)
    hypotheses = _parse_hypotheses(response.content)
    log.info("vuln_hypotheses_generated", count=len(hypotheses))

    # Step 5: Self-critique loop (max 3 iterations)
    # Sonnet → DeepSeek (critique) → Sonnet (revision) → DeepSeek ...
    # Breaks early if DeepSeek returns "sound" for every hypothesis.
    # Ships the best (last) version after 3 iterations even without
    # convergence so the pipeline never stalls.
    for iteration in range(3):
        if not hypotheses:
            break  # nothing to critique — exit before calling DeepSeek
        critique_output = await _hypothesiscritic_mod.hypothesiscritic_subagent.ainvoke({
            "hypotheses": [h.model_dump() for h in hypotheses],
            "engagement_id": state.engagement_id,
        })
        critique = (
            critique_output.critique
            if hasattr(critique_output, "critique")
            else critique_output.get("critique", [])
            if isinstance(critique_output, dict)
            else []
        )
        if not critique or all(c.get("verdict") == "sound" for c in critique):
            log.info("vuln_critique_converged", iteration=iteration + 1)
            break
        # Revise hypotheses based on critique
        hypotheses = await _revise_hypotheses(model, hypotheses, critique)
        log.info("vuln_hypotheses_revised", iteration=iteration + 1, count=len(hypotheses))
    else:
        log.warning("vuln_critique_non_convergence", shipped_best=True)

    # Step 6: Sort by rank
    hypotheses.sort(key=lambda h: h.rank)

    log.info("vuln_done", hypotheses_count=len(hypotheses))

    return {
        "vulnerabilities": state.vulnerabilities + _extract_vulns(cve_matches, exploit_outputs),
        "attack_hypotheses": hypotheses,
        "phase": "exploit",
        "iteration_count": state.iteration_count + 1,
    }


def _parse_hypotheses(content: str) -> list[AttackHypothesis]:
    """Parse LLM hypothesis response. Handles markdown code fences.

    Returns an empty list on any parse failure — the self-critique loop
    short-circuits on empty hypotheses so a Sonnet parse failure degrades
    to "no viable path" rather than crashing the agent.
    """
    text = content.strip()
    # Strip markdown code fences if present (LLMs often wrap JSON in
    # ```json ... ``` even when told not to).
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop the opening fence (e.g. "```json" or "```").
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    try:
        data = json.loads(text)
        raw = data.get("hypotheses", []) if isinstance(data, dict) else []
        return [AttackHypothesis.model_validate(h) for h in raw]
    except Exception as e:
        log.error("vuln_hypotheses_parse_failed", error=str(e), content=content[:500])
        return []


async def _revise_hypotheses(
    model,
    hypotheses: list[AttackHypothesis],
    critique: list[dict],
) -> list[AttackHypothesis]:
    """Send hypotheses + critique back to Sonnet for revision."""
    prompt = VULN_REVISION_PROMPT.format(
        hypotheses_json=json.dumps([h.model_dump() for h in hypotheses], indent=2),
        critique_json=json.dumps(critique, indent=2),
    )
    response = await model.ainvoke(prompt)
    return _parse_hypotheses(response.content)


def _summarize_hosts(hosts) -> str:
    return "\n".join(
        f"- {h.ip} ({h.hostname or 'no hostname'})" for h in hosts
    ) or "None"


def _summarize_services(services) -> str:
    return "\n".join(
        f"- {s.host_ip}:{s.port} {s.service} {s.product or ''} {s.version or ''}"
        for s in services
    ) or "None"


def _summarize_web_apps(web_apps) -> str:
    return "\n".join(
        f"- {w.url} (status {w.status_code}, tech: {', '.join(w.tech_stack)})"
        for w in web_apps
    ) or "None"


def _summarize_nuclei(vulns) -> str:
    return "\n".join(
        f"- [{v.severity}] {v.title} ({v.cve or 'no CVE'})"
        for v in vulns
        if v.source == "nuclei"
    ) or "None"


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
        document = r.get("document", "") if isinstance(r, dict) else str(r)
        lines.append(
            f"- Past finding: {document[:100]} (CVE: {meta.get('cve', 'unknown')})"
        )
    return "\n".join(lines)


def _extract_vulns(cve_matches, exploit_outputs) -> list[Vulnerability]:
    """Convert CVE matches and exploit search results into Vulnerability records."""
    vulns: list[Vulnerability] = []
    severity_map = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
    }
    for match in cve_matches:
        for cve in match.cves:
            vulns.append(Vulnerability(
                host_ip=match.host_ip,
                port=match.port,
                service=match.service,
                cve=cve.cve_id,
                severity=severity_map.get((cve.severity or "").upper(), "info"),
                title=(cve.description[:100] if cve.description else cve.cve_id),
                description=cve.description,
                references=cve.references,
                cvss_score=cve.cvss_score,
                source="nvd",
            ))
    for eo in exploit_outputs:
        # ExploitFinderOutput may arrive as a Pydantic instance or a dict
        # depending on how the @tool was invoked / patched.
        exploits = (
            eo.exploits
            if hasattr(eo, "exploits")
            else eo.get("exploits", [])
            if isinstance(eo, dict)
            else []
        )
        for exp in exploits:
            edb_id = getattr(exp, "edb_id", None) or (exp.get("edb_id", "") if isinstance(exp, dict) else "")
            title = getattr(exp, "title", None) or (exp.get("title", "") if isinstance(exp, dict) else "")
            exp_type = getattr(exp, "type", None) or (exp.get("type", "") if isinstance(exp, dict) else "")
            vulns.append(Vulnerability(
                host_ip="",  # exploit search isn't host-specific
                title=title,
                description=f"ExploitDB {edb_id}: {title} ({exp_type})",
                references=[f"https://www.exploit-db.com/exploits/{edb_id}"],
                source="searchsploit",
            ))
    return vulns
