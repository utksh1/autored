"""MITREMapper sub-agent — maps engagement activity to ATT&CK technique IDs.

Rules-based by design (Phase 6 plan): the embedded ``MITRE_TECHNIQUES``
index is the only source of technique IDs this module may emit. An LLM
recalling technique IDs invents plausible-looking nonexistent ones; a
keyword table over structured state is deterministic and auditable —
the same reasoning that made the RoE Guard non-LLM (spec §2.4).

Spec reference: §7.4 (Report sub-agents), §13.6.
"""
import json

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.models.report import MitreMapping

log = get_logger("subagents.mitremapper")

# technique_id -> (technique_name, tactic)
MITRE_TECHNIQUES: dict[str, tuple[str, str]] = {
    # Discovery
    "T1046": ("Network Service Discovery", "discovery"),
    "T1046.002": ("Network Service Discovery: Network Share Discovery", "discovery"),
    "T1087.002": ("Account Discovery: Domain Account", "discovery"),
    "T1018": ("Remote System Discovery", "discovery"),
    "T1482": ("Domain Trust Discovery", "discovery"),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "reconnaissance"),
    # Initial access / execution
    "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1203": ("Exploitation for Client Execution", "execution"),
    "T1210": ("Exploitation of Remote Services", "lateral-movement"),
    "T1110": ("Brute Force", "credential-access"),
    # Privilege escalation
    "T1068": ("Exploitation for Privilege Escalation", "privilege-escalation"),
    "T1548": ("Abuse Elevation Control Mechanism", "privilege-escalation"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "privilege-escalation"),
    # Persistence
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "persistence"),
    "T1053.003": ("Scheduled Task/Job: Cron", "persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "persistence"),
    "T1060": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "persistence"),
    "T1546.003": ("Event Triggered Execution: WMI Event Subscription", "persistence"),
    "T1546.004": ("Event Triggered Execution: Unix Shell Configuration Modification", "persistence"),
    "T1574.001": ("Hijack Execution Flow: DLL Search Order Hijacking", "persistence"),
    # Credential access
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "credential-access"),
    "T1003.002": ("OS Credential Dumping: Security Account Manager", "credential-access"),
    "T1003.003": ("OS Credential Dumping: NTDS", "credential-access"),
    "T1552": ("Unsecured Credentials", "credential-access"),
    # Defense evasion
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "defense-evasion"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "defense-evasion"),
    "T1055": ("Process Injection", "defense-evasion"),
    # Collection / exfiltration
    "T1041": ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1048": ("Exfiltration Over Alternative Protocol", "exfiltration"),
    "T1048.003": ("Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol", "exfiltration"),
    # Lateral movement
    "T1047": ("Windows Management Instrumentation", "lateral-movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "lateral-movement"),
    "T1021.004": ("Remote Services: SSH", "lateral-movement"),
    "T1021.006": ("Remote Services: Windows Remote Management", "lateral-movement"),
    "T1550": ("Use Alternate Authentication Material", "lateral-movement"),
    "T1090.001": ("Proxy: Internal Proxy", "command-and-control"),
}

# Keyword rules: state collection -> (match key within record, {value or substring: technique_id})
_FOOTHOLD_METHOD_RULES = {
    "ms17_010": "T1210", "eternalblue": "T1210", "smb": "T1210",
    "sqli": "T1190", "sqlmap": "T1190", "web": "T1190",
    "ssh_brute": "T1110", "brute": "T1110", "hydra": "T1110",
    "msf": "T1203", "client": "T1203",
}
_PRIVESC_RULES = {
    "kernel": "T1068", "dirty_pipe": "T1068", "dirty_cow": "T1068",
    "sudo": "T1548.003", "suid": "T1548",
    "service": "T1543.003", "polkit": "T1068",
}
_PERSISTENCE_RULES = {
    "scheduled_task": "T1053.005", "cron": "T1053.003",
    "systemd": "T1543.002", "service": "T1543.003",
    "registry_run": "T1060", "ssh_authorized_keys": "T1098.004",
    "wmi_subscription": "T1546.003", "bashrc": "T1546.004",
    "dll_hijack": "T1574.001",
}
_EVASION_RULES = {
    "amsi_bypass": "T1562.001", "etw_patch": "T1562.001",
    "defender_disable": "T1562.001", "log_clear": "T1070.001",
    "process_injection": "T1055",
}
_EXFIL_RULES = {"https": "T1041", "dns": "T1048.003", "icmp": "T1048", "smb": "T1021.002"}
_PIVOT_RULES = {
    "wmiexec": "T1047", "psexec": "T1021.002", "smbexec": "T1021.002",
    "ssh": "T1021.004", "winrm": "T1021.006",
    "crackmapexec": "T1550", "certipy": "T1550",
}
_TUNNEL_RULES = {"ligolo": "T1090.001", "chisel": "T1090.001", "proxychains": "T1090.001"}
_CRED_METHOD_RULES = {
    "mimikatz": "T1003.001", "lsass": "T1003.001",
    "secretsdump": "T1003.003", "ntds": "T1003.003",
    "sam_dump": "T1003.002",
}


class MitreMapperOutput(BaseModel):
    mappings: list[MitreMapping] = Field(default_factory=list)


def _match(rule_key: str, rules: dict[str, str], source: str, tactic_source: str,
           detail: str, out: list[MitreMapping]) -> None:
    """Add a mapping if rule_key matches; never emit IDs outside the index."""
    key = rule_key.lower()
    for pattern, technique_id in rules.items():
        if pattern in key or pattern in rule_key.lower():
            if technique_id in MITRE_TECHNIQUES:
                name, tactic = MITRE_TECHNIQUES[technique_id]
                out.append(MitreMapping(
                    technique_id=technique_id, technique_name=name,
                    tactic=tactic, source=tactic_source, detail=detail,
                ))
            return  # first matching pattern wins — one technique per record


def _map_records(records: dict) -> list[MitreMapping]:
    """Map serialized engagement records to ATT&CK mappings (pure function)."""
    out: list[MitreMapping] = []

    if records.get("recon_hosts"):
        name, tactic = MITRE_TECHNIQUES["T1046"]
        out.append(MitreMapping(technique_id="T1046", technique_name=name, tactic=tactic,
                                source="recon", detail=f"{records['recon_hosts']} hosts scanned"))
    if records.get("vuln_scans"):
        name, tactic = MITRE_TECHNIQUES["T1595.002"]
        out.append(MitreMapping(technique_id="T1595.002", technique_name=name, tactic=tactic,
                                source="vuln", detail=f"{records['vuln_scans']} vulnerability scans"))

    for foothold in records.get("footholds", []):
        _match(foothold.get("method", ""), _FOOTHOLD_METHOD_RULES, foothold.get("method", ""),
               "foothold", f"{foothold.get('method')} on {foothold.get('host_ip')}", out)

    for attempt in records.get("privesc_attempts", []):
        if not attempt.get("success"):
            continue
        _match(attempt.get("technique", ""), _PRIVESC_RULES, attempt.get("technique", ""),
               "privesc", f"{attempt.get('technique')} ({attempt.get('category')})", out)

    for artifact in records.get("persistence_artifacts", []):
        _match(artifact.get("method", ""), _PERSISTENCE_RULES, artifact.get("method", ""),
               "persistence", f"{artifact.get('method')} on {artifact.get('host_ip')}", out)

    for action in records.get("evasion_actions", []):
        _match(action.get("technique", ""), _EVASION_RULES, action.get("technique", ""),
               "evasion", action.get("technique", ""), out)

    for proof in records.get("exfiltration_proof", []):
        _match(proof.get("method", ""), _EXFIL_RULES, proof.get("method", ""),
               "exfiltration", proof.get("method", ""), out)

    for pivot in records.get("pivots", []):
        if not pivot.get("success"):
            continue
        _match(pivot.get("method", ""), _PIVOT_RULES, pivot.get("method", ""),
               "pivot", f"{pivot.get('method')} to {pivot.get('target_host')}", out)

    for tunnel in records.get("tunnels", []):
        _match(tunnel.get("tool", ""), _TUNNEL_RULES, tunnel.get("tool", ""),
               "tunnel", tunnel.get("tool", ""), out)

    for method in records.get("cred_methods", []):
        _match(method, _CRED_METHOD_RULES, method, "credential-access", method, out)

    if records.get("bloodhound"):
        name, tactic = MITRE_TECHNIQUES["T1482"]
        out.append(MitreMapping(technique_id="T1482", technique_name=name, tactic=tactic,
                                source="postex", detail="BloodHound domain collection"))

    # Deduplicate on (technique_id, source) — repeated artifacts collapse to one row.
    seen: set[tuple[str, str]] = set()
    deduped: list[MitreMapping] = []
    for mapping in out:
        key = (mapping.technique_id, mapping.source)
        if key not in seen:
            seen.add(key)
            deduped.append(mapping)
    return deduped


@tool
async def mitremapper_subagent(engagement_records: str, engagement_id: str = "") -> MitreMapperOutput:
    """Map engagement activity to MITRE ATT&CK technique IDs.

    Rules-based: only technique IDs from the embedded index are ever
    emitted; unmapped activity is skipped (never guessed).

    Args:
        engagement_records: JSON string produced by the Report Agent's
            engagement summary builder.
        engagement_id: Current engagement ID.

    Returns:
        MitreMapperOutput with deduplicated MitreMapping rows.
    """
    log.info("mitremapper_start", engagement_id=engagement_id)
    records = json.loads(engagement_records) if isinstance(engagement_records, str) else engagement_records
    mappings = _map_records(records)
    log.info("mitremapper_done", engagement_id=engagement_id, mappings=len(mappings))
    return MitreMapperOutput(mappings=mappings)
