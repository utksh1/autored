"""AutoRed Recon Agent — LangGraph node + plan executor.

Phase 1, Task 22. This module is the heart of Phase 1: it owns the
LLM-driven recon planning loop and dispatches to the five Phase 1
sub-agents (``portscan``, ``webenum``, ``subdomainenum``, ``dnsenum``,
``vhostenum``).

Flow
----
1. ``recon_node(state)`` prompts the routed model for a JSON plan.
2. ``_parse_plan_response`` strips markdown fences and parses JSON.
3. ``_execute_plan`` walks the dependency graph (``depends_on``) and
   runs each ready batch in parallel via ``asyncio.gather``.
4. ``_dispatch_subagent`` looks up the right sub-agent function *lazily*
   (via ``from autored.subagents.X import Y_subagent`` inside the
   function body) so tests can patch the module-level reference with
   ``unittest.mock.patch("autored.subagents.X.X_subagent")``.
5. The returned ``Pydantic`` models are ``model_dump()``-ed and the
   flat dict is merged back into ``EngagementState`` shape via the
   ``_extract_*`` helpers.
"""
from __future__ import annotations

import asyncio
import json
from urllib.parse import urlparse

from langchain_core.runnables import RunnableConfig

from autored.logging import get_logger
from autored.models import DiscoveredPath, Host, Service, WebApp
from autored.router import call_with_fallback
from autored.state import EngagementState

log = get_logger("agents.recon")


RECON_PLAN_PROMPT = """You are the Recon Agent in AutoRed, a red team automation system.
Your job is to plan read-only reconnaissance against a target.

You have these sub-agents available:
- portscan: runs naabu + nmap. args: target (str), scan_type (str: "quick"|"full"|"service")
- webenum: runs httpx + feroxbuster + nuclei. args: url (str)
- subdomainenum: runs subfinder + amass. args: domain (str)
- dnsenum: runs dnsx. args: hostname (str)
- vhostenum: runs gobuster vhost. args: url (str)

Target scope: {target_scope}
Engagement ID: {engagement_id}

Produce a JSON recon plan with this exact schema:
{{
  "steps": [
    {{
      "subagent": "portscan" | "webenum" | "subdomainenum" | "dnsenum" | "vhostenum",
      "args": {{"target": "...", "scan_type": "quick"}},
      "depends_on": [step_index, ...]
    }}
  ]
}}

Rules:
- All steps must reference a real sub-agent from the list above
- Steps with no dependencies can run in parallel
- Do NOT plan any exploitation. Recon only.
- For IP targets, plan portscan with scan_type="service"
- For domain targets, plan subdomainenum + dnsenum first, then portscan per discovered host
- For HTTP services, plan webenum
- Return ONLY the JSON, no markdown, no explanation
"""


async def recon_node(
    state: EngagementState, config: RunnableConfig
) -> dict:
    """LangGraph node: runs Recon Agent.

    1. Prompt the routed LLM for a JSON plan.
    2. Execute the plan in dependency-ordered parallel batches.
    3. Merge sub-agent outputs back into EngagementState-shaped dict
       (``hosts``, ``services``, ``web_apps``, ``subdomains``,
       ``directories``) and advance the phase to ``"vuln"``.

    ``config`` is accepted for I1 (Phase 3 fix wave) consistency with
    the other Phase 1-3 nodes — the EventBus pattern (``config.
    configurable.event_bus``) is established on ``exploit_node`` and
    Phase 4+ nodes (postex/lateral/cleanup) will consume it too. The
    Recon Agent doesn't currently need the bus (recon is read-only, no
    HitL gate) but the signature is uniform across nodes so future
    additions don't break existing tests.
    """
    log.info("recon_start", engagement_id=state.engagement_id, target=state.target_scope)

    prompt = RECON_PLAN_PROMPT.format(
        target_scope=state.target_scope,
        engagement_id=state.engagement_id,
    )

    # Step 1: Get plan from LLM via router.call_with_fallback so refusal
    # detection + DeepSeek fallback is centralized (spec §4.3).
    # ``call_with_fallback`` returns the response text (a ``str``), not a
    # message object, so there's no ``.content`` access at this call site.
    content = await call_with_fallback("plan_recon", prompt)
    plan = _parse_plan_response(content)
    log.info("recon_plan_received", steps=len(plan.get("steps", [])))

    # Step 2: Execute plan, respecting dependencies
    results = await _execute_plan(plan, state)

    # Step 3: Merge results into state-shaped dict
    new_hosts = _extract_hosts(results)
    new_services = _extract_services(results)
    new_web_apps = _extract_web_apps(results)
    new_subdomains = _extract_subdomains(results)
    new_directories = _extract_directories(results)

    log.info(
        "recon_done",
        hosts=len(new_hosts), services=len(new_services),
        web_apps=len(new_web_apps),
    )

    return {
        "hosts": state.hosts + new_hosts,
        "services": state.services + new_services,
        "web_apps": state.web_apps + new_web_apps,
        "subdomains": state.subdomains + new_subdomains,
        "directories": state.directories + new_directories,
        "phase": "vuln",
        "iteration_count": state.iteration_count + 1,
    }


def _parse_plan_response(content: str) -> dict:
    """Parse LLM response into plan dict. Handles markdown code fences."""
    text = content.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.splitlines()
        # Remove first line (opening fence, possibly with language tag)
        lines = lines[1:]
        # Remove trailing closing fence if present
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        log.error("recon_plan_parse_failed", error=str(e), content=content[:500])
        return {"steps": []}


async def _execute_plan(plan: dict, state: EngagementState) -> list[dict]:
    """Execute recon plan, respecting step dependencies.

    Each iteration computes the set of step indices whose
    ``depends_on`` list is fully satisfied by already-completed steps,
    then runs that batch in parallel via ``asyncio.gather``. A step
    whose sub-agent raises is recorded as ``{"error": str(e)}`` rather
    than failing the whole plan — the extractors treat ``error`` dicts
    as empty.
    """
    steps = plan.get("steps", [])
    results: list[dict | None] = [None] * len(steps)
    pending = set(range(len(steps)))

    while pending:
        ready = [
            i for i in pending
            if all(
                results[dep] is not None
                for dep in steps[i].get("depends_on", [])
            )
        ]
        if not ready:
            log.error("recon_plan_deadlock", pending=list(pending))
            break

        async def run_step(idx: int) -> tuple[int, dict]:
            step = steps[idx]
            log.info("recon_step_start", step=idx, subagent=step["subagent"])
            try:
                result = await _dispatch_subagent(step, state)
                return idx, result
            except Exception as e:
                log.error(
                    "recon_step_failed",
                    step=idx, subagent=step["subagent"], error=str(e),
                )
                return idx, {"error": str(e)}

        step_results = await asyncio.gather(*[run_step(i) for i in ready])
        for idx, result in step_results:
            results[idx] = result
            pending.discard(idx)

    return [r for r in results if r is not None]


async def _dispatch_subagent(step: dict, state: EngagementState) -> dict:
    """Call the right sub-agent based on ``step["subagent"]``.

    Sub-agents are imported lazily inside this function so tests can
    patch the module-level reference, e.g.::

        with patch("autored.subagents.portscan.portscan_subagent") as mock:
            mock.ainvoke = AsyncMock(return_value=fake_portscan)

    A top-level ``from autored.subagents.portscan import portscan_subagent``
    would bind the name at module-load time and the patch would never
    be seen.
    """
    subagent = step["subagent"]
    args = dict(step.get("args", {}))
    args["engagement_id"] = state.engagement_id

    if subagent == "portscan":
        from autored.subagents.portscan import portscan_subagent
        result = await portscan_subagent.ainvoke(args)
    elif subagent == "webenum":
        from autored.subagents.webenum import webenum_subagent
        result = await webenum_subagent.ainvoke(args)
    elif subagent == "subdomainenum":
        from autored.subagents.subdomainenum import subdomainenum_subagent
        result = await subdomainenum_subagent.ainvoke(args)
    elif subagent == "dnsenum":
        from autored.subagents.dnsenum import dnsenum_subagent
        result = await dnsenum_subagent.ainvoke(args)
    elif subagent == "vhostenum":
        from autored.subagents.vhostenum import vhostenum_subagent
        result = await vhostenum_subagent.ainvoke(args)
    else:
        raise ValueError(f"Unknown subagent: {subagent}")

    return result.model_dump() if hasattr(result, "model_dump") else result.__dict__


def _extract_hosts(results: list[dict]) -> list[Host]:
    """Pull ``Host`` objects out of ``PortScanOutput.deep_scan.hosts``.

    Dedupes by IP so a portscan + a dnsenum that both surface the same
    IP don't double-count.
    """
    hosts: list[Host] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        deep = r.get("deep_scan")
        if deep and isinstance(deep, dict):
            for h in deep.get("hosts", []):
                hosts.append(Host(
                    ip=h["ip"],
                    hostname=h.get("hostname"),
                    mac=h.get("mac"),
                    os_guess=h.get("os_guess"),
                    discovered_by="nmap",
                ))
    seen: set[str] = set()
    unique: list[Host] = []
    for h in hosts:
        if h.ip not in seen:
            seen.add(h.ip)
            unique.append(h)
    return unique


def _extract_services(results: list[dict]) -> list[Service]:
    """Pull ``Service`` objects out of every open port in deep_scan.hosts.

    Dedupes by ``(host_ip, port, protocol)`` so a port reported by both
    naabu and nmap (or by two sub-agent calls against the same host)
    doesn't produce two ``Service`` rows for the same endpoint. The
    first-seen wins; in practice nmap's service-detection result is the
    richer one and is the one that lands first because portscan's
    ``deep_scan`` is the structured source we walk here.
    """
    deduped: dict[tuple[str, int, str], Service] = {}
    for r in results:
        if not isinstance(r, dict):
            continue
        deep = r.get("deep_scan")
        if deep and isinstance(deep, dict):
            for h in deep.get("hosts", []):
                for p in h.get("ports", []):
                    if p.get("state") == "open":
                        key = (h["ip"], p["port"], p["protocol"])
                        if key in deduped:
                            continue
                        deduped[key] = Service(
                            host_ip=h["ip"],
                            port=p["port"],
                            protocol=p["protocol"],
                            service=p.get("service"),
                            product=p.get("product"),
                            version=p.get("version"),
                        )
    return list(deduped.values())


def _extract_web_apps(results: list[dict]) -> list[WebApp]:
    """Pull ``WebApp`` objects out of ``WebEnumOutput.httpx_results``.

    Each ``WebApp`` is linkable back to its ``Host`` via ``host_ip`` +
    ``port``. We extract both from the httpx result's ``url`` field via
    ``urllib.parse.urlparse`` (``hostname`` and ``port`` attributes).
    When the URL doesn't parse cleanly (malformed, empty, or IP-less),
    we fall back to ``host_ip=""`` and ``port=0`` so a bad URL doesn't
    explode the whole extraction — Phase 2's Vuln Agent can skip orphan
    WebApps by checking for empty ``host_ip``.
    """
    web_apps: list[WebApp] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        httpx_results = r.get("httpx_results", [])
        for hr in httpx_results:
            url = hr.get("url", "")
            parsed = urlparse(url)
            host_ip = parsed.hostname or ""
            # When the URL parses to a real hostname, default the port to
            # the scheme's standard (443 for https, 80 for http/anything
            # else). When the URL doesn't parse cleanly (no hostname AND
            # no scheme), preserve the pre-fix orphan behaviour:
            # ``host_ip=""`` + ``port=0`` — Phase 2's Vuln Agent skips
            # these by checking for empty ``host_ip``.
            if host_ip:
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
            else:
                port = parsed.port or 0
            web_apps.append(WebApp(
                url=url,
                host_ip=host_ip,
                port=port,
                status_code=hr["status_code"],
                title=hr.get("title"),
                tech_stack=hr.get("tech_stack", []),
                web_server=hr.get("web_server"),
                redirects=hr.get("redirects", False),
                final_url=hr.get("final_url"),
            ))
    return web_apps


def _extract_subdomains(results: list[dict]) -> list[str]:
    """Pull subdomain strings out of ``SubdomainList.subdomains``."""
    subs: list[str] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        if "subdomains" in r:
            subs.extend(r["subdomains"])
    return list(set(subs))  # dedupe


def _extract_directories(results: list[dict]) -> list[DiscoveredPath]:
    """Pull ``DiscoveredPath`` objects out of ``WebEnumOutput.directories``."""
    dirs: list[DiscoveredPath] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        for d in r.get("directories", []):
            dirs.append(DiscoveredPath(
                url=d["url"],
                status_code=d["status_code"],
                content_length=d.get("content_length", 0),
            ))
    return dirs
