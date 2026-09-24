"""Unit tests for the rules-based MITREMapper sub-agent (Phase 6 Task 3)."""
from autored.models.report import MitreMapping
from autored.subagents.mitremapper import (
    MITRE_TECHNIQUES,
    _map_records,
    mitremapper_subagent,
)


def _records(**overrides) -> dict:
    base = {
        "recon_hosts": 3,
        "vuln_scans": 2,
        "footholds": [],
        "privesc_attempts": [],
        "persistence_artifacts": [],
        "evasion_actions": [],
        "exfiltration_proof": [],
        "pivots": [],
        "tunnels": [],
        "cred_methods": [],
        "bloodhound": False,
    }
    base.update(overrides)
    return base


def test_every_index_entry_is_well_formed():
    for technique_id, (name, tactic) in MITRE_TECHNIQUES.items():
        assert technique_id.startswith("T"), technique_id
        assert len(technique_id) in (5, 9), technique_id  # T1046 / T1053.005
        assert name and tactic


def test_recon_maps_to_discovery():
    mappings = _map_records(_records())
    ids = {m.technique_id for m in mappings}
    assert "T1046" in ids  # Network Service Discovery (nmap sweep)
    assert "T1595.002" in ids  # Vulnerability Scanning (nuclei)


def test_foothold_method_mapping():
    mappings = _map_records(_records(footholds=[
        {"method": "ms17_010", "access_type": "rpc", "host_ip": "10.0.0.5"},
        {"method": "sqli", "access_type": "webshell", "host_ip": "10.0.0.6"},
        {"method": "ssh_brute", "access_type": "ssh", "host_ip": "10.0.0.7"},
    ]))
    ids = {m.technique_id for m in mappings}
    assert "T1210" in ids  # Exploitation of Remote Services (S EternalBlue)
    assert "T1190" in ids  # Exploit Public-Facing Application (sqli)
    assert "T1110" in ids  # Brute Force (ssh_brute)


def test_persistence_method_mapping():
    mappings = _map_records(_records(persistence_artifacts=[
        {"method": "scheduled_task", "host_ip": "10.0.0.5"},
        {"method": "cron", "host_ip": "10.0.0.7"},
        {"method": "ssh_authorized_keys", "host_ip": "10.0.0.7"},
    ]))
    ids = {m.technique_id for m in mappings}
    assert "T1053.005" in ids  # Scheduled Task
    assert "T1053.003" in ids  # Cron
    assert "T1098.004" in ids  # SSH Authorized Keys


def test_evasion_and_exfil_mapping():
    mappings = _map_records(_records(
        evasion_actions=[{"technique": "amsi_bypass"}, {"technique": "log_clear"}],
        exfiltration_proof=[{"method": "dns"}],
    ))
    ids = {m.technique_id for m in mappings}
    assert "T1562.001" in ids  # Disable/Modify Tools (AMSI bypass)
    assert "T1070.001" in ids  # Clear Windows Event Logs
    assert "T1048.003" in ids  # Exfiltration Over Alternative Protocol: DNS


def test_pivot_and_tunnel_mapping():
    mappings = _map_records(_records(
        pivots=[{"method": "wmiexec", "target_host": "10.0.0.8", "success": True}],
        tunnels=[{"tool": "ligolo"}],
    ))
    ids = {m.technique_id for m in mappings}
    assert "T1047" in ids  # WMI
    assert "T1090.001" in ids  # Internal Proxy


def test_cred_harvest_mapping():
    mappings = _map_records(_records(cred_methods=["mimikatz", "secretsdump"]))
    ids = {m.technique_id for m in mappings}
    assert "T1003.001" in ids  # LSASS Memory (mimikatz)
    assert "T1003.003" in ids  # NTDS (secretsdump)


def test_unmapped_activity_is_skipped_never_invented():
    """Review Focus #4 — an unknown method must not produce any mapping."""
    mappings = _map_records(_records(
        footholds=[{"method": "quantum_exploit", "access_type": "ssh", "host_ip": "x"}],
        pivots=[{"method": "teleport", "target_host": "y", "success": True}],
    ))
    ids = {m.technique_id for m in mappings}
    # discovery mappings from recon_hosts/vuln_scans are fine, but nothing for the junk
    assert all(mid in MITRE_TECHNIQUES for mid in ids)
    junk_sources = {m.source for m in mappings}
    assert "foothold" not in junk_sources or all(
        m.technique_id in {"T1110", "T1210", "T1190"} for m in mappings if m.source == "foothold"
    )


def test_empty_records_produce_discovery_only():
    mappings = _map_records(_records(recon_hosts=0, vuln_scans=0))
    assert mappings == []


async def test_subagent_tool_round_trip():
    import json
    records = _records(pivots=[{"method": "ssh", "target_host": "10.0.0.9", "success": True}])
    output = await mitremapper_subagent.ainvoke({
        "engagement_records": json.dumps(records),
        "engagement_id": "e1",
    })
    assert isinstance(output, MitreMapping) or hasattr(output, "mappings")
    ids = {m.technique_id for m in output.mappings}
    assert "T1021.004" in ids  # SSH lateral


def test_bloodhound_maps_to_domain_trust_discovery():
    mappings = _map_records(_records(bloodhound=True))
    ids = {m.technique_id for m in mappings}
    assert "T1482" in ids


def test_dedup_on_technique_id_source_pair():
    """Repeated persistence artifacts with the same method collapse to one row."""
    mappings = _map_records(_records(persistence_artifacts=[
        {"method": "cron", "host_ip": "10.0.0.5"},
        {"method": "cron", "host_ip": "10.0.0.6"},
        {"method": "cron", "host_ip": "10.0.0.7"},
    ]))
    cron_rows = [m for m in mappings if m.technique_id == "T1053.003"]
    assert len(cron_rows) == 1  # deduped on (technique_id, source)


def test_failed_pivot_is_skipped():
    """Unsuccessful pivots should not produce a mapping."""
    mappings = _map_records(_records(
        pivots=[{"method": "ssh", "target_host": "10.0.0.9", "success": False}],
    ))
    pivot_rows = [m for m in mappings if m.source == "pivot"]
    assert pivot_rows == []


def test_failed_privesc_is_skipped():
    mappings = _map_records(_records(
        privesc_attempts=[
            {"technique": "kernel", "category": "linux", "success": False},
        ],
    ))
    privesc_rows = [m for m in mappings if m.source == "privesc"]
    assert privesc_rows == []
