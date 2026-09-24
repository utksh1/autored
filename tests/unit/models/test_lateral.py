"""Unit tests for Phase 5 lateral-movement models (spec §9.2)."""
from datetime import datetime

import pytest
from pydantic import ValidationError

from autored.models.lateral import (
    MovementPath,
    PivotCandidate,
    PivotRecord,
    SubEngagementRef,
    TunnelConfig,
)


def test_pivot_candidate_fields():
    c = PivotCandidate(
        credential_id="s-1",
        username="administrator",
        cred_type="hash",
        secret_value="31d6cfe0d16ae931b73c59d7e0c089c0",
        source_host="192.168.56.22",
        target_host="192.168.56.11",
        method="wmiexec",
        confidence=0.8,
    )
    assert c.method == "wmiexec"
    assert c.cred_type == "hash"
    assert c.confidence == 0.8


def test_pivot_candidate_rejects_unknown_method():
    with pytest.raises(ValidationError):
        PivotCandidate(
            credential_id="s-1", username="u", cred_type="password",
            secret_value="p", source_host="10.0.0.1", target_host="10.0.0.2",
            method="rpd", confidence=0.5,
        )


def test_pivot_record_defaults():
    r = PivotRecord(target_host="10.0.0.2", method="psexec", credentials_used=["s-1"])
    assert r.id  # uuid default factory
    assert r.success is False
    assert r.new_foothold_id is None
    assert isinstance(r.timestamp, datetime)
    assert r.needs_tunnel is False


def test_tunnel_config_has_teardown_command():
    """Spec §9.2 TunnelConfig + the Phase-5 teardown_command addition.

    The Cleanup Agent (spec §6.6) removes tunnels — without a recorded
    teardown command there is nothing to run, so the field is mandatory.
    """
    t = TunnelConfig(
        tool="chisel",
        proxy_endpoint="10.10.14.5:1080",
        local_port=1080,
        target_network="192.168.56.0/24",
        teardown_command="pkill -f 'chisel client 10.10.14.5:1080'",
    )
    assert t.teardown_command.startswith("pkill")
    assert t.tool == "chisel"
    assert isinstance(t.established_at, datetime)


def test_tunnel_config_rejects_unknown_tool():
    with pytest.raises(ValidationError):
        TunnelConfig(
            tool="openvpn", proxy_endpoint="x:1", local_port=1,
            target_network="10.0.0.0/8", teardown_command="",
        )


def test_sub_engagement_ref_status_literal():
    ref = SubEngagementRef(
        sub_id="eng_sub_01", target_host="10.0.0.2", pivot_method="wmiexec",
        status="completed", summary="pwned", sub_state_path="engagements/eng_sub_01/state.json",
    )
    assert ref.status == "completed"
    with pytest.raises(ValidationError):
        SubEngagementRef(
            sub_id="x", target_host="t", pivot_method="m", status="paused",
            summary="", sub_state_path="",
        )


def test_movement_path_fields():
    m = MovementPath(
        from_host="10.0.0.1", to_host="10.0.0.2",
        method="wmiexec", credential_used="s-1",
    )
    assert isinstance(m.timestamp, datetime)
