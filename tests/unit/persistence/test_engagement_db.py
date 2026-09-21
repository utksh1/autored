import pytest
from datetime import datetime
from autored.persistence.engagement_db import (
    init_db, insert_engagement, insert_finding, insert_lesson,
    get_findings_by_cve, get_findings_by_engagement, list_engagements_with_findings,
)

@pytest.fixture
async def db(tmp_path):
    db_path = str(tmp_path / "test.sqlite")
    await init_db(db_path)
    return db_path

@pytest.mark.asyncio
async def test_init_db_creates_tables(db):
    # If init_db succeeded without error, tables exist
    # Verify by inserting a row
    await insert_engagement(db, {
        "id": "test-eng-001",
        "target": "10.10.10.5",
        "start_ts": datetime.utcnow().isoformat(),
        "end_ts": None,
        "summary": None,
        "report_path": None,
        "operator": "test",
        "phase": "recon",
        "parent_engagement_id": None,
    })

@pytest.mark.asyncio
async def test_insert_and_query_finding(db):
    await insert_engagement(db, {
        "id": "test-eng-001", "target": "10.10.10.5",
        "start_ts": datetime.utcnow().isoformat(), "end_ts": None,
        "summary": None, "report_path": None, "operator": "test",
        "phase": "done", "parent_engagement_id": None,
    })
    await insert_finding(db, {
        "id": "finding-001", "engagement_id": "test-eng-001",
        "host": "10.10.10.5", "port": 80, "service": "http",
        "cve": "CVE-2014-6271", "severity": "critical",
        "status": "confirmed", "evidence_path": None,
        "discovered_at": datetime.utcnow().isoformat(),
    })

    findings = await get_findings_by_cve(db, "CVE-2014-6271")
    assert len(findings) == 1
    assert findings[0]["host"] == "10.10.10.5"
    assert findings[0]["cve"] == "CVE-2014-6271"

    eng_findings = await get_findings_by_engagement(db, "test-eng-001")
    assert len(eng_findings) == 1

@pytest.mark.asyncio
async def test_insert_lesson(db):
    await insert_engagement(db, {
        "id": "test-eng-001", "target": "10.10.10.5",
        "start_ts": datetime.utcnow().isoformat(), "end_ts": None,
        "summary": None, "report_path": None, "operator": "test",
        "phase": "done", "parent_engagement_id": None,
    })
    await insert_lesson(db, {
        "id": "lesson-001", "engagement_id": "test-eng-001",
        "category": "cve_exploited", "body": "Shellshock via cgi-bin worked",
        "mitre_technique_id": "T1059.004",
        "created_at": datetime.utcnow().isoformat(),
    })

@pytest.mark.asyncio
async def test_list_engagements_with_findings(db):
    await insert_engagement(db, {
        "id": "eng-a", "target": "10.10.10.5",
        "start_ts": datetime.utcnow().isoformat(), "end_ts": None,
        "summary": None, "report_path": None, "operator": "test",
        "phase": "done", "parent_engagement_id": None,
    })
    await insert_engagement(db, {
        "id": "eng-b", "target": "10.10.10.56",
        "start_ts": datetime.utcnow().isoformat(), "end_ts": None,
        "summary": None, "report_path": None, "operator": "test",
        "phase": "done", "parent_engagement_id": None,
    })
    engs = await list_engagements_with_findings(db)
    assert len(engs) == 2
    assert {e["id"] for e in engs} == {"eng-a", "eng-b"}
