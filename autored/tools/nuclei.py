import json
from datetime import datetime
from pathlib import Path
from typing import Literal

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw

log = get_logger("tools.nuclei")


class NucleiResult(BaseModel):
    template_id: str
    template_url: str = ""
    matched_at: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    type: str = ""
    description: str = ""
    reference: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    cve: str | None = None
    extracted_data: dict = Field(default_factory=dict)


class NucleiOutput(BaseModel):
    target: str
    results: list[NucleiResult] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


def _build_nuclei_cmd(target: str, templates: list[str]) -> list[str]:
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent"]
    for t in templates:
        cmd.extend(["-t", t])
    return cmd


def _parse_nuclei_jsonl(text: str) -> list[NucleiResult]:
    results = []
    for line in text.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            # Coerce severity to literal
            severity = data.get("severity", "info").lower()
            if severity not in ("info", "low", "medium", "high", "critical"):
                severity = "info"
            results.append(NucleiResult(
                template_id=data.get("template-id", data.get("templateID", "")),
                template_url=data.get("template-url", data.get("templateURL", "")),
                matched_at=data.get("matched-at", data.get("matched", "")),
                severity=severity,
                type=data.get("type", ""),
                description=data.get("description", data.get("info", {}).get("description", "")),
                reference=data.get("reference", []),
                cvss_score=data.get("cvss-score") or data.get("classification", {}).get("cvss-score"),
                cve=data.get("cve") or (data.get("classification", {}).get("cve-id", [""])[0] if data.get("classification", {}).get("cve-id") else None),
                extracted_data=data.get("extracted", {}),
            ))
        except (json.JSONDecodeError, KeyError) as e:
            log.warning("nuclei_parse_line_failed", line=line, error=str(e))
    return results


@tool
@roe_guard(allowed_categories=["vuln_scan", "recon"])
async def nuclei_scan(
    target: str,
    templates: list[str] | None = None,
    engagement_id: str = "",
) -> NucleiOutput:
    """Run nuclei vulnerability scanner.

    Args:
        target: URL or host to scan
        templates: List of template directories (e.g., ["cves/", "vulnerabilities/"])
                   Defaults to common templates
        engagement_id: Current engagement ID

    Returns:
        NucleiOutput with list of NucleiResult
    """
    if templates is None:
        templates = ["cves/", "vulnerabilities/", "misconfiguration/", "exposures/"]

    cmd = _build_nuclei_cmd(target, templates)
    log.info("nuclei_start", target=target, templates=templates)

    result = await run_subprocess(cmd, timeout=900)
    raw_path = await _save_raw("nuclei", target, result.stdout, result.stderr, engagement_id)

    results = _parse_nuclei_jsonl(result.stdout)
    log.info("nuclei_done", target=target, findings=len(results), duration=result.duration_sec)

    return NucleiOutput(
        target=target,
        results=results,
        raw_output_path=raw_path,
        command=result.command,
        duration_sec=result.duration_sec,
    )
