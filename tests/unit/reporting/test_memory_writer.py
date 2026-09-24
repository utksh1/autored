"""Unit tests for the cross-engagement memory writer (Phase 6 Task 8)."""
import hashlib
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import aiosqlite

from autored.models import Secret, Vulnerability
from autored.models.report import Lesson, MitreMapping
from autored.models.roe import RulesOfEngagement
from autored.persistence.engagement_db import get_credentials_by_engagement
from autored.state import EngagementState
from autored.reporting.memory_writer import persist_engagement_memory

PLAINTEXT = "hunter2hunter2"


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _state() -> EngagementState:
    state = EngagementState(
        engagement_id="mem-e1", target_scope=["10.0.0.5"],
        operator="tester", rules_of_engagement=_roe(),
        parent_engagement_id=None,
    )
    state.vulnerabilities = [
        Vulnerability(
            id="v-1", host_ip="10.0.0.5", port=445, service="smb",
            cve="CVE-2017-0144", severity="critical", title="EternalBlue",
            description="RCE in SMBv1", references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
            cvss_score=9.8, source="nvd", evidence_path="evidence/v1.txt",
            discovered_at=datetime.utcnow(),
        ),
    ]
    state.harvested_secrets = [
        Secret(host_ip="10.0.0.5", secret_type="password",
               secret_value=PLAINTEXT, source="mimikatz:wdigest/administrator"),
    ]
    state.lessons = [Lesson(category="technique_worked", body="ms17_010 worked",
                            mitre_technique_id="T1210")]
    state.mitre_mappings = [MitreMapping(
        technique_id="T1210", technique_name="Exploitation of Remote Services",
        tactic="lateral-movement", source="foothold", detail="ms17_010 on 10.0.0.5",
    )]
    # The memory writer runs at report time, so the report node will have
    # advanced state.phase to "report" before calling persist_engagement_memory.
    state.phase = "report"
    state.summary = "full chain achieved"
    state.report_paths = None
    return state


def _chroma() -> MagicMock:
    chroma = MagicMock()
    chroma.upsert_finding = AsyncMock()
    chroma.upsert_technique = AsyncMock()
    return chroma


async def test_persists_all_rows_to_sqlite(tmp_path):
    db_path = str(tmp_path / "engagements.sqlite")
    state = _state()
    result = await persist_engagement_memory(state, db_path=db_path, chroma=_chroma())

    assert result.engagement_written is True
    assert result.findings_written == 1
    assert result.credentials_written == 1
    assert result.lessons_written == 1
    assert result.db_error is None

    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        eng = await (await db.execute(
            "SELECT * FROM engagements WHERE id = ?", ("mem-e1",))).fetchone()
        assert eng["target"] == "10.0.0.5"
        assert eng["operator"] == "tester"
        assert eng["phase"] == "report"
        assert eng["summary"] == "full chain achieved"

        finding = await (await db.execute(
            "SELECT * FROM findings WHERE id = ?", ("v-1",))).fetchone()
        assert finding["cve"] == "CVE-2017-0144"
        assert finding["severity"] == "critical"
        assert finding["status"] == "open"  # no foothold on 10.0.0.5 in this state


async def test_credential_value_is_hashed_never_plaintext(tmp_path, monkeypatch):
    """Review Focus #2 — the DB never stores plaintext secret material.

    The memory writer hashes the secret with SHA-256 before handing the row
    to ``insert_credential`` (spec §3.3 "hashed/encrypted form").
    ``insert_credential`` then Fernet-encrypts that hash at rest. We read
    back via the decrypting accessor to confirm the round-trip yields the
    hash (not the plaintext) — so the DB never stores plaintext either
    before or after Fernet.
    """
    monkeypatch.setattr("autored.crypto._DB_KEY_PATH", tmp_path / ".db_key")
    db_path = str(tmp_path / "engagements.sqlite")
    state = _state()
    await persist_engagement_memory(state, db_path=db_path, chroma=_chroma())

    creds = await get_credentials_by_engagement(db_path, "mem-e1")
    assert len(creds) == 1
    cred = creds[0]
    expected_hash = hashlib.sha256(PLAINTEXT.encode()).hexdigest()
    assert cred["credential_value"] == expected_hash
    assert cred["credential_value"] != PLAINTEXT
    assert cred["username"] == "administrator"  # parsed from source
    assert cred["credential_type"] == "password"

    # And a raw SQL read must NOT expose the plaintext or the bare hash —
    # only the Fernet ciphertext is on disk.
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        raw = await (await db.execute(
            "SELECT credential_value FROM credentials WHERE engagement_id = ?",
            ("mem-e1",),
        )).fetchone()
        assert raw["credential_value"] != PLAINTEXT
        assert raw["credential_value"] != expected_hash


async def test_finding_status_is_exploited_when_foothold_exists(tmp_path):
    from autored.models import Foothold

    db_path = str(tmp_path / "engagements.sqlite")
    state = _state()
    state.footholds = [Foothold(
        id="f-1", host_ip="10.0.0.5", username="system", context="system",
        method="ms17_010", access_type="rpc", evidence_path="e.txt",
        established_at=datetime.utcnow(), hypothesis_rank=1,
    )]
    await persist_engagement_memory(state, db_path=db_path, chroma=_chroma())

    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        finding = await (await db.execute(
            "SELECT status FROM findings WHERE id = ?", ("v-1",))).fetchone()
        assert finding["status"] == "exploited"


async def test_chroma_upserts_findings_and_techniques(tmp_path):
    db_path = str(tmp_path / "engagements.sqlite")
    chroma = _chroma()
    state = _state()
    result = await persist_engagement_memory(state, db_path=db_path, chroma=chroma)

    assert result.chroma_findings_upserted == 1
    assert result.chroma_techniques_upserted >= 1
    chroma.upsert_finding.assert_awaited_once()
    args = chroma.upsert_finding.await_args
    assert "CVE-2017-0144" in args.args[1]
    assert args.args[2]["engagement_id"] == "mem-e1"
    chroma.upsert_technique.assert_awaited()
    technique_doc = chroma.upsert_technique.await_args.args[1]
    assert "T1210" in technique_doc


async def test_sqlite_failure_is_isolated_from_chroma(tmp_path, monkeypatch):
    """A DB failure must not block Chroma writes or raise to the caller."""
    import autored.reporting.memory_writer as mw

    async def _boom(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(mw, "insert_engagement", _boom)
    chroma = _chroma()
    result = await persist_engagement_memory(
        _state(), db_path=str(tmp_path / "x.sqlite"), chroma=chroma)

    assert result.engagement_written is False
    assert result.db_error is not None
    assert result.chroma_findings_upserted == 1  # chroma still ran


async def test_chroma_failure_is_isolated(tmp_path):
    db_path = str(tmp_path / "engagements.sqlite")
    chroma = _chroma()
    chroma.upsert_finding = AsyncMock(side_effect=RuntimeError("chroma locked"))
    result = await persist_engagement_memory(_state(), db_path=db_path, chroma=chroma)

    assert result.chroma_error is not None
    assert result.engagement_written is True  # sqlite still ran


async def test_chroma_none_skips_vector_store_without_error(tmp_path):
    """chroma=None (renderer-free environments) is a legal call."""
    result = await persist_engagement_memory(
        _state(), db_path=str(tmp_path / "x.sqlite"), chroma=None)
    assert result.chroma_findings_upserted == 0
    assert result.chroma_error is None
