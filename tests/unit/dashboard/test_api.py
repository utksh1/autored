"""Dashboard REST API tests (engagements, state, roe)."""
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState


@pytest.fixture()
def engagement_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """One engagement on disk under a temp root the API reads from."""
    monkeypatch.chdir(tmp_path)
    eng = tmp_path / "engagements" / "eng_test_01"
    (eng / "evidence").mkdir(parents=True)
    roe = RulesOfEngagement(
        engagement_name="t", operator="op", operator_signature="s",
        allowed_ips=["0.0.0.0/0"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, kernel_exploits_allowed=True,
    )
    state = EngagementState(
        engagement_id="eng_test_01", target_scope=["10.0.0.1"],
        operator="op", rules_of_engagement=roe,
    )
    state.phase = "recon"
    (eng / "state.json").write_text(state.model_dump_json())
    (eng / "manifest.json").write_text(
        '{"engagement_id": "eng_test_01", "target": "10.0.0.1", '
        '"operator": "op", "started_at": "2026-09-27T00:00:00"}'
    )
    return eng


@pytest.fixture()
def client():
    from autored.dashboard.api import create_app

    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


@pytest.mark.asyncio
async def test_engagement_list_from_filesystem(engagement_dir, client):
    # SQLite (db/engagements.sqlite) doesn't exist under tmp_path → fallback
    resp = await client.get("/api/engagements")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["engagement_id"] == "eng_test_01"
    assert rows[0]["target"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_engagement_state_endpoint(engagement_dir, client):
    resp = await client.get("/api/engagements/eng_test_01/state")
    assert resp.status_code == 200
    body = resp.json()
    assert body["phase"] == "recon"
    assert "pending_hitl_gates" in body
    assert body["harvested_secrets"] == []


@pytest.mark.asyncio
async def test_state_unknown_engagement_404(engagement_dir, client):
    resp = await client.get("/api/engagements/eng_nope/state")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_roe_endpoint(engagement_dir, client):
    resp = await client.get("/api/engagements/eng_test_01/roe")
    assert resp.status_code == 200
    assert resp.json()["operator"] == "op"
    assert resp.json()["engagement_name"] == "t"


@pytest.mark.asyncio
async def test_evidence_serves_file(engagement_dir, client):
    (engagement_dir / "evidence" / "nmap.txt").write_text("PORT STATE\n21 open")
    resp = await client.get("/api/engagements/eng_test_01/evidence/nmap.txt")
    assert resp.status_code == 200
    assert "21 open" in resp.text


@pytest.mark.asyncio
async def test_evidence_rejects_traversal(engagement_dir, client):
    # httpx normalizes literal "../" segments client-side (they never reach
    # the app), so the traversal is sent percent-encoded; the server decodes
    # it back to "../" before the path jail sees it.
    resp = await client.get(
        "/api/engagements/eng_test_01/evidence/%2e%2e/%2e%2e/state.json"
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "path escapes evidence jail"


@pytest.mark.asyncio
async def test_evidence_rejects_symlink_escape(engagement_dir, client):
    outside = engagement_dir.parent / "outside.txt"
    outside.write_text("secret")
    link = engagement_dir / "evidence" / "leak.txt"
    link.symlink_to(outside)
    resp = await client.get("/api/engagements/eng_test_01/evidence/leak.txt")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_evidence_missing_file_404(engagement_dir, client):
    resp = await client.get("/api/engagements/eng_test_01/evidence/nope.txt")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_root_falls_back_without_build(engagement_dir, client):
    # dist/ doesn't exist in the repo checkout → instruction page
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "npm --prefix frontend run build" in resp.text


@pytest.mark.asyncio
async def test_root_serves_spa_when_built(engagement_dir, tmp_path, monkeypatch):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html>SPA</html>")
    monkeypatch.setattr("autored.dashboard.api.FRONTEND_DIST", dist)
    # The app must be built AFTER the monkeypatch: create_app() snapshots
    # FRONTEND_DIST.is_dir() at creation time, and the shared `client`
    # fixture builds it before this test body runs (the fallback text
    # contains "SPA", so reusing it here would pass without ever
    # exercising the StaticFiles mount).
    from autored.dashboard.api import create_app

    async with AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://test"
    ) as client:
        resp = await client.get("/")
    assert "SPA" in resp.text


@pytest.mark.asyncio
async def test_state_rejects_invalid_engagement_id(engagement_dir, client):
    # `..` as the engagement id would shift every jail-style lookup one
    # level up (the same vector the evidence jail guards) — reject with 400.
    resp = await client.get("/api/engagements/%2e%2e/state")
    assert resp.status_code == 400
    assert resp.json()["detail"] == "invalid engagement id"


@pytest.mark.asyncio
async def test_roe_rejects_invalid_engagement_id(engagement_dir, client):
    resp = await client.get("/api/engagements/%2e%2e/roe")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_spa_serves_deep_links_and_keeps_api_precedence(
    engagement_dir, tmp_path, monkeypatch
):
    # Browser refresh on a client-side route must serve index.html, while
    # /api/* keeps JSON precedence (and unknown /api paths still 404).
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html>SPA</html>")
    monkeypatch.setattr("autored.dashboard.api.FRONTEND_DIST", dist)
    from autored.dashboard.api import create_app

    async with AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://test"
    ) as deep_client:
        resp = await deep_client.get("/engagements/eng_test_01")
        assert resp.status_code == 200
        assert "SPA" in resp.text
        api_resp = await deep_client.get("/api/engagements")
        assert api_resp.status_code == 200
        assert isinstance(api_resp.json(), list)
        missing = await deep_client.get("/api/nonexistent")
        assert missing.status_code == 404
        assert missing.json()["detail"] == "Not Found"
