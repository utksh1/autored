from langchain_core.tools import tool

from autored.logging import get_logger
from autored.tools.hydra import hydra_brute, BruteResult

log = get_logger("subagents.bruteagent")


@tool
async def bruteagent_subagent(
    target: str,
    service: str,
    usernames_file: str,
    passwords_file: str,
    engagement_id: str = "",
) -> BruteResult:
    """Run brute-force attack via hydra.

    Args:
        target: Target IP or hostname
        service: Service to attack (ssh, ftp, etc.)
        usernames_file: Path to usernames wordlist
        passwords_file: Path to passwords wordlist
        engagement_id: Current engagement ID

    Returns:
        BruteResult with found credentials.
    """
    log.info("bruteagent_start", target=target, service=service)
    result = await hydra_brute.ainvoke({
        "target": target, "service": service,
        "usernames_file": usernames_file, "passwords_file": passwords_file,
        "engagement_id": engagement_id,
    })
    log.info("bruteagent_done", target=target, success=result.success)
    return result
