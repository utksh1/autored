"""HypothesisCritic sub-agent.

Calls DeepSeek (via the router's ``second_opinion`` slot) to critique a list
of attack hypotheses produced by the Vuln Agent's Sonnet synthesis step.
DeepSeek is asked to look for the classic failure modes — hallucinated CVEs,
CVE/version mismatches, wrong Metasploit module paths, understated risk,
overstated confidence — and return a per-hypothesis verdict of ``sound``,
``needs_revision``, or ``discard``.

The DeepSeek response is parsed defensively: markdown code fences are
stripped before ``json.loads``, and any decode failure (or absence of a
``critique`` key) yields an empty list rather than an exception. The Vuln
Agent's self-critique loop treats an empty critique as "DeepSeek had nothing
to say, treat all hypotheses as still under review" — graceful degradation
when the second-opinion model returns prose instead of JSON.
"""
import json

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.router import get_model

log = get_logger("subagents.hypothesiscritic")

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

Return ONLY the JSON, no markdown, no explanation.
"""


class CritiqueOutput(BaseModel):
    critique: list[dict] = Field(default_factory=list)


def _parse_critique_response(content: str) -> list[dict]:
    """Parse LLM critique response. Handles markdown code fences.

    Returns an empty list on any parse failure — the caller (Vuln Agent
    self-critique loop) treats "no critique" as "DeepSeek had nothing
    actionable to say" rather than as an error.
    """
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop the opening fence (e.g. "```json" or "```").
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        log.error("critique_parse_failed", error=str(e), content=content[:500])
        return []
    if not isinstance(data, dict):
        log.error("critique_unexpected_shape", payload_type=type(data).__name__)
        return []
    critique = data.get("critique", [])
    if not isinstance(critique, list):
        log.error("critique_not_list", type=type(critique).__name__)
        return []
    return critique


@tool
async def hypothesiscritic_subagent(
    hypotheses: list[dict],
    engagement_id: str = "",
) -> CritiqueOutput:
    """Critique a list of attack hypotheses using DeepSeek (second-opinion model).

    Args:
        hypotheses: List of hypothesis dicts (rank, target, technique, cve, etc.)
        engagement_id: Current engagement ID

    Returns:
        CritiqueOutput with per-hypothesis verdict (sound/needs_revision/discard).
    """
    log.info("hypothesiscritic_start", hypotheses_count=len(hypotheses))
    if not hypotheses:
        return CritiqueOutput(critique=[])

    model = get_model("second_opinion")  # DeepSeek
    prompt = VULN_CRITIQUE_PROMPT.format(
        hypotheses_json=json.dumps(hypotheses, indent=2),
    )
    response = await model.ainvoke(prompt)
    critique = _parse_critique_response(response.content)

    log.info("hypothesiscritic_done", verdicts=[c.get("verdict") for c in critique])
    return CritiqueOutput(critique=critique)
