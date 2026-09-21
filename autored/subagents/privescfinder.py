"""PrivescFinder sub-agent.

LLM-driven analysis of the enumeration output produced by LinuxEnum /
WindowsEnum. The Post-Ex Agent (Phase 4 Task 11) collects the
per-foothold enum outputs and asks the LLM (router slot
``plan_postex`` — Sonnet 4.5) to identify privilege-escalation
candidates from the SUID binaries / sudo entries / modifiable
services / autologon credentials / unattended files that the
enumeration surfaced.

The LLM is asked to return JSON in the shape::

    {"candidates": [ {host_ip, technique, category, details,
                      confidence, exploit_command,
                      removal_command?}, ... ]}

The response is parsed defensively: markdown code fences are stripped
before ``json.loads``, malformed JSON yields an empty candidate list,
and any candidate that fails Pydantic validation is dropped (and
logged) rather than crashing the sub-agent. This matches the
HypothesisCritic sub-agent's defensive-parse pattern.
"""
import json

from langchain_core.tools import tool
from pydantic import BaseModel, Field, ValidationError

from autored.logging import get_logger
from autored.models.postex import PrivescCandidate
from autored.router import get_model

log = get_logger("subagents.privescfinder")

PRIVESC_FINDER_PROMPT = """You are a senior red teamer analysing enumeration output
to identify privilege-escalation paths. For each foothold, look at the
SUID binaries, sudo entries, modifiable services, autologon credentials,
unattended files, scheduled tasks, and CVEs surfaced by linpeas/winpeas.

Enumeration results:
{enum_results_json}

For each privesc candidate you identify, return:
- host_ip: the foothold's IP
- technique: a short name (e.g., "sudo find", "CVE-2021-4034 PwnKit",
  "modifiable service VulnSvc", "autologon credential reuse")
- category: one of "misconfig", "app_system", or "kernel"
- details: 1-2 sentences explaining the path
- confidence: 0.0 - 1.0
- exploit_command: the exact shell command to trigger the privesc
- removal_command (optional): how to undo the change if applicable

Return JSON:
{{
  "candidates": [
    {{
      "host_ip": "10.10.10.5",
      "technique": "sudo find",
      "category": "misconfig",
      "details": "sudo find with NOPASSWD allows root shell via -exec",
      "confidence": 0.95,
      "exploit_command": "sudo find . -exec /bin/sh \\;"
    }}
  ]
}}

Return ONLY the JSON, no markdown, no explanation.
"""


class PrivescFinderOutput(BaseModel):
    candidates: list[PrivescCandidate] = Field(default_factory=list)


def _parse_candidates_response(content: str) -> list[dict]:
    """Parse the LLM response into a list of candidate dicts.

    Strips markdown code fences before ``json.loads`` and returns
    ``[]`` on any decode failure — same graceful-degradation contract
    as the HypothesisCritic sub-agent's ``_parse_critique_response``.
    """
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:]  # drop the opening fence
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        log.error("privesc_parse_failed", error=str(e), content=content[:500])
        return []
    if not isinstance(data, dict):
        log.error("privesc_unexpected_shape", payload_type=type(data).__name__)
        return []
    candidates = data.get("candidates", [])
    if not isinstance(candidates, list):
        log.error("privesc_candidates_not_list", type=type(candidates).__name__)
        return []
    return candidates


@tool
async def privescfinder_subagent(
    enum_results: list[dict],
    engagement_id: str = "",
) -> PrivescFinderOutput:
    """Use the LLM to identify privesc candidates from enum output.

    Args:
        enum_results: List of per-foothold enum result dicts (each
            carries host_ip, os_type, and the parsed linpeas / winpeas
            findings).
        engagement_id: Current engagement ID.

    Returns:
        PrivescFinderOutput with a list of validated PrivescCandidate
        records. Malformed candidates are dropped (and logged) rather
        than crashing the sub-agent.
    """
    log.info("privescfinder_start", enum_count=len(enum_results))
    if not enum_results:
        return PrivescFinderOutput(candidates=[])

    model = get_model("plan_postex")  # Claude Sonnet 4.5
    prompt = PRIVESC_FINDER_PROMPT.format(
        enum_results_json=json.dumps(enum_results, indent=2, default=str),
    )
    response = await model.ainvoke(prompt)
    raw_candidates = _parse_candidates_response(response.content)

    candidates: list[PrivescCandidate] = []
    for raw in raw_candidates:
        if not isinstance(raw, dict):
            continue
        try:
            candidates.append(PrivescCandidate(**raw))
        except ValidationError as e:
            log.warning(
                "privesc_candidate_dropped",
                reason=str(e),
                raw=raw,
            )

    log.info(
        "privescfinder_done",
        raw=len(raw_candidates),
        valid=len(candidates),
    )
    return PrivescFinderOutput(candidates=candidates)
