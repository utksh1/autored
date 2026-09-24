"""AutoRed tool wrappers (Phase 1+)."""
from autored.tools.cleanup import (
    CleanupExecutionResult,
    CleanupVerificationResult,
    cleanup_execute,
    cleanup_verify,
)
from autored.tools.crackmapexec import CrackmapexecResult, crackmapexec
from autored.tools.impacket_remote import (
    ImpacketRemoteResult,
    impacket_psexec,
    impacket_smbexec,
    impacket_wmiexec,
)
from autored.tools.nmap import NmapHost, NmapPort, NmapResult, nmap_scan
from autored.tools.tunnel import (
    TunnelResult,
    chisel_reverse,
    ligolo_connect,
)

__all__ = [
    "nmap_scan",
    "NmapResult",
    "NmapHost",
    "NmapPort",
    # Phase 5 — lateral movement
    "impacket_wmiexec",
    "impacket_psexec",
    "impacket_smbexec",
    "ImpacketRemoteResult",
    "crackmapexec",
    "CrackmapexecResult",
    # Phase 5 — tunnels
    "ligolo_connect",
    "chisel_reverse",
    "TunnelResult",
    # Phase 5 — cleanup
    "cleanup_execute",
    "cleanup_verify",
    "CleanupExecutionResult",
    "CleanupVerificationResult",
]
