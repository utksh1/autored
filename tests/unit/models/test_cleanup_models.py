"""Unit tests for Phase 5 cleanup models (spec §9.2 + plan additions)."""
from datetime import datetime

import pytest
from pydantic import ValidationError

from autored.models.cleanup import CleanupPlan, CleanupResult, HostCleanupPlan


def test_cleanup_result_fields():
    r = CleanupResult(
        artifact_id="a-1", host_ip="10.0.0.1",
        removal_command="schtasks /delete /tn AutoRedUpdate /f",
        success=True, verified=True,
    )
    assert r.error is None
    assert isinstance(r.timestamp, datetime)


def test_host_cleanup_plan_defaults():
    p = HostCleanupPlan(host_ip="10.0.0.1", artifact_ids=["a-1"])
    assert p.removal_commands == []
    assert p.tunnel_teardowns == []
    assert p.temp_files == []
    assert p.username == ""


def test_cleanup_plan_groups_by_host():
    plan = CleanupPlan(
        by_host=[
            HostCleanupPlan(host_ip="10.0.0.1", artifact_ids=["a-1"], removal_commands=["cmd1"]),
            HostCleanupPlan(host_ip="10.0.0.2", artifact_ids=["a-2"], removal_commands=["cmd2"]),
        ],
        total_actions=2,
    )
    assert {h.host_ip for h in plan.by_host} == {"10.0.0.1", "10.0.0.2"}
    assert plan.total_actions == 2
