"""Unit tests for the Foothold model (Phase 3 T1)."""
from __future__ import annotations

from datetime import datetime

import pytest

from autored.models.foothold import Foothold


def test_foothold_minimal():
    f = Foothold(
        id="foothold-001",
        host_ip="10.10.10.40",
        username="SYSTEM",
        context="system",
        method="ms17_010",
        access_type="shell",
        evidence_path="engagements/test/evidence/msf_session_001.txt",
        established_at=datetime.utcnow(),
        hypothesis_rank=1,
    )
    assert f.host_ip == "10.10.10.40"
    assert f.context == "system"
    assert f.access_type == "shell"
    assert f.method == "ms17_010"


def test_foothold_rejects_invalid_context():
    with pytest.raises(Exception):
        Foothold(
            id="x", host_ip="x", username="x",
            context="invalid",  # must be user/root/system/service_account
            method="x", access_type="shell",
            evidence_path="x", established_at=datetime.utcnow(),
            hypothesis_rank=1,
        )


def test_foothold_rejects_invalid_access_type():
    with pytest.raises(Exception):
        Foothold(
            id="x", host_ip="x", username="x",
            context="root",
            method="x", access_type="invalid",  # must be shell/webshell/rpc/ssh/winrm
            evidence_path="x", established_at=datetime.utcnow(),
            hypothesis_rank=1,
        )


def test_foothold_round_trip_json():
    f = Foothold(
        id="f1", host_ip="10.10.10.40", username="www-data",
        context="user", method="sqli", access_type="webshell",
        evidence_path="/tmp/evidence.txt",
        established_at=datetime(2026, 9, 21, 12, 0, 0),
        hypothesis_rank=2,
    )
    restored = Foothold.model_validate_json(f.model_dump_json())
    assert restored == f
