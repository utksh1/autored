"""Recon Agent — LangGraph node that plans and runs read-only recon.

The agent:
  1. Calls ``get_model("plan_recon")`` to get an LLM.
  2. Sends RECON_PLAN_PROMPT populated with the target scope.
  3. Parses a JSON plan from the LLM response (handles markdown fences).
  4. Executes plan steps respecting ``depends_on`` (parallel via
     ``asyncio.gather`` when no deps).
  5. Dispatches each step to the right sub-agent based on ``step.subagent``.
  6. Merges results into the state-shaped dict
     (hosts, services, web_apps, subdomains, directories).
  7. Returns a dict with the updated fields and ``phase="vuln"``.

Why we import sub-agent *modules* (not their @tool names)
-------------------------------------------------------
Tests patch the sub-agent @tool objects at their canonical location,
e.g. ``patch("autored.subagents.portscan.portscan_subagent")``. For that
patch to take effect, ``recon_node`` must look up the tool via the module
attribute path at *call* time (``portscan.portscan_subagent.ainvoke(...)``)
rather than via a name imported into this module's globals (which would
be a frozen reference to the original tool instance).
"""

import asyncio
import json

from autored.state import EngagementState
from autored.router import get_model
# Import the sub-agent MODULES so test patches on
# `autored.subagents.<x>.<tool_name>` take effect at call time via
# module attribute lookup.
from autored.subagents import (
    portscan as _portscan_mod,
    webenum as _webenum_mod,
    subdomainenum as _subdomainenum_mod,
    dnsenum as _dnsenum_mod,
    vhostenum as _vhostenum_mod,
)
from autored.models import Host, Service, WebApp, DiscoveredPath
from autored.logging import get_logger

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


async def recon_node(state: EngagementState) -> dict:
    """LangGraph node: runs the Recon Agent."""
    log.info("recon_start", engagement_id=state.engagement_id, target=state.target_scope)

    model = get_model("plan_recon")
    prompt = RECON_PLAN_PROMPT.format(
        target_scope=state.target_scope,
        engagement_id=state.engagement_id,
    )

    # Step 1: Get plan from LLM
    response = await model.ainvoke(prompt)
    plan = _parse_plan_response(response.content)
    log.info("recon_plan_received", steps=len(plan.get("steps", [])))

    # Step 2: Execute plan, respecting dependencies
    results = await _execute_plan(plan, state)

    # Step 3: Merge results into state-shaped dict
    new_hosts = _extract_hosts(results, state)
    new_services = _extract_services(results)
    new_web_apps = _extract_web_apps(results)
    new_subdomains = _extract_subdomains(results)
    new_directories = _extract_directories(results)

    log.info(
        "recon_done",
        hosts=len(new_hosts),
        services=len(new_services),
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
        # Remove first and last line (fences)
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        log.error("recon_plan_parse_failed", error=str(e), content=content[:500])
        return {"steps": []}


async def _execute_plan(plan: dict, state: EngagementState) -> list[dict]:
    """Execute recon plan, respecting step dependencies."""
    results: list[dict | None] = [None] * len(plan.get("steps", []))
    pending = set(range(len(results)))

    while pending:
        ready = [
            i
            for i in pending
            if all(
                results[dep] is not None
                for dep in plan["steps"][i].get("depends_on", [])
            )
        ]
        if not ready:
            log.error("recon_plan_deadlock", pending=list(pending))
            break

        async def run_step(idx: int) -> tuple[int, dict]:
            step = plan["steps"][idx]
            log.info("recon_step_start", step=idx, subagent=step["subagent"])
            try:
                result = await _dispatch_subagent(step, state)
                return idx, result
            except Exception as e:
                log.error(
                    "recon_step_failed",
                    step=idx,
                    subagent=step["subagent"],
                    error=str(e),
                )
                return idx, {"error": str(e)}

        step_results = await asyncio.gather(*[run_step(i) for i in ready])
        for idx, result in step_results:
            results[idx] = result
            pending.discard(idx)

    return [r for r in results if r is not None]


async def _dispatch_subagent(step: dict, state: EngagementState) -> dict:
    """Call the right sub-agent based on step.subagent.

    Looks up the @tool object via its module attribute path
    (e.g. ``_portscan_mod.portscan_subagent``) rather than via a local
    name binding so that test patches on
    ``autored.subagents.<x>.<tool_name>`` propagate through.
    """
    subagent = step["subagent"]
    args = dict(step.get("args", {}))
    args["engagement_id"] = state.engagement_id

    if subagent == "portscan":
        result = await _portscan_mod.portscan_subagent.ainvoke(args)
    elif subagent == "webenum":
        result = await _webenum_mod.webenum_subagent.ainvoke(args)
    elif subagent == "subdomainenum":
        result = await _subdomainenum_mod.subdomainenum_subagent.ainvoke(args)
    elif subagent == "dnsenum":
        result = await _dnsenum_mod.dnsenum_subagent.ainvoke(args)
    elif subagent == "vhostenum":
        result = await _vhostenum_mod.vhostenum_subagent.ainvoke(args)
    else:
        raise ValueError(f"Unknown subagent: {subagent}")

    return result.model_dump() if hasattr(result, "model_dump") else result.__dict__


def _extract_hosts(results: list[dict], state: EngagementState) -> list[Host]:
    hosts = []
    for r in results:
        # PortScanOutput has deep_scan.hosts
        deep = r.get("deep_scan") if isinstance(r, dict) else None
        if deep and isinstance(deep, dict):
            for h in deep.get("hosts", []):
                hosts.append(
                    Host(
                        ip=h["ip"],
                        hostname=h.get("hostname"),
                        mac=h.get("mac"),
                        os_guess=h.get("os_guess"),
                        discovered_by="nmap",
                    )
                )
    # Dedupe by IP
    seen: set[str] = set()
    unique: list[Host] = []
    for h in hosts:
        if h.ip not in seen:
            seen.add(h.ip)
            unique.append(h)
    return unique


def _extract_services(results: list[dict]) -> list[Service]:
    services = []
    for r in results:
        deep = r.get("deep_scan") if isinstance(r, dict) else None
        if deep and isinstance(deep, dict):
            for h in deep.get("hosts", []):
                for p in h.get("ports", []):
                    if p.get("state") == "open":
                        services.append(
                            Service(
                                host_ip=h["ip"],
                                port=p["port"],
                                protocol=p["protocol"],
                                service=p.get("service"),
                                product=p.get("product"),
                                version=p.get("version"),
                            )
                        )
    return services


def _extract_web_apps(results: list[dict]) -> list[WebApp]:
    web_apps = []
    for r in results:
        if not isinstance(r, dict):
            continue
        httpx_results = r.get("httpx_results", [])
        for hr in httpx_results:
            web_apps.append(
                WebApp(
                    url=hr["url"],
                    host_ip="",  # filled by caller
                    port=0,  # filled by caller
                    status_code=hr["status_code"],
                    title=hr.get("title"),
                    tech_stack=hr.get("tech_stack", []),
                    web_server=hr.get("web_server"),
                    redirects=hr.get("redirects", False),
                    final_url=hr.get("final_url"),
                )
            )
    return web_apps


def _extract_subdomains(results: list[dict]) -> list[str]:
    subs = []
    for r in results:
        if not isinstance(r, dict):
            continue
        if "subdomains" in r:
            subs.extend(r["subdomains"])
    return list(set(subs))  # dedupe


def _extract_directories(results: list[dict]) -> list[DiscoveredPath]:
    dirs = []
    for r in results:
        if not isinstance(r, dict):
            continue
        for d in r.get("directories", []):
            dirs.append(
                DiscoveredPath(
                    url=d["url"],
                    status_code=d["status_code"],
                    content_length=d.get("content_length", 0),
                )
            )
    return dirs
