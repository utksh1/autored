# tests/unit/persistence/test_neo4j_store.py
"""Unit tests for Neo4jStore — all Docker interaction is mocked (no real Docker needed).

The Neo4jStore class manages a Neo4j container via docker-compose. It uses
``asyncio.create_subprocess_exec`` for all docker commands, so tests mock that
function (and the returned process object's ``communicate`` coroutine) to avoid
spawning real subprocesses.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from autored.persistence.neo4j_store import Neo4jStore


def _make_proc(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> MagicMock:
    """Build a fake asyncio subprocess whose ``communicate`` is awaitable."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    return proc


def test_store_init():
    store = Neo4jStore(uri="bolt://localhost:7687", user="neo4j", password="test")
    assert store.uri == "bolt://localhost:7687"
    assert store.user == "neo4j"
    assert store.password == "test"


@pytest.mark.asyncio
async def test_start_docker_compose(tmp_path, monkeypatch):
    """Verify start() runs `docker compose -f docker-compose.neo4j.yml up -d`."""
    store = Neo4jStore()
    proc_mock = _make_proc(returncode=0, stdout=b"", stderr=b"")
    with patch(
        "autored.persistence.neo4j_store.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc_mock),
    ) as mock_exec:
        await store.start()
        assert mock_exec.called
        # First positional arg should be the program name
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "docker"
        assert "compose" in cmd
        assert "up" in cmd
        # Should reference the compose file
        assert "docker-compose.neo4j.yml" in cmd


@pytest.mark.asyncio
async def test_is_running():
    """is_running() returns True when `docker ps` output contains 'neo4j'."""
    store = Neo4jStore()
    proc_mock = _make_proc(returncode=0, stdout=b"neo4j\n", stderr=b"")
    with patch(
        "autored.persistence.neo4j_store.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc_mock),
    ):
        assert await store.is_running() is True


@pytest.mark.asyncio
async def test_is_running_false_when_not_running():
    """is_running() returns False when docker ps output is empty."""
    store = Neo4jStore()
    proc_mock = _make_proc(returncode=0, stdout=b"", stderr=b"")
    with patch(
        "autored.persistence.neo4j_store.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc_mock),
    ):
        assert await store.is_running() is False


@pytest.mark.asyncio
async def test_upload_bloodhound_data():
    """upload_bloodhound_data returns True on success (returncode 0)."""
    store = Neo4jStore()
    proc_mock = _make_proc(returncode=0, stdout=b" uploaded", stderr=b"")
    with patch(
        "autored.persistence.neo4j_store.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc_mock),
    ) as mock_exec:
        result = await store.upload_bloodhound_data("/tmp/data.json")
        assert result is True
        # Should have invoked docker exec ... neo4j-admin import
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "docker"
        assert "exec" in cmd
        assert "/tmp/data.json" in cmd


@pytest.mark.asyncio
async def test_upload_bloodhound_data_failure():
    """upload_bloodhound_data returns False when neo4j-admin import fails."""
    store = Neo4jStore()
    proc_mock = _make_proc(returncode=1, stdout=b"", stderr=b"boom")
    with patch(
        "autored.persistence.neo4j_store.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc_mock),
    ):
        result = await store.upload_bloodhound_data("/tmp/data.json")
        assert result is False


@pytest.mark.asyncio
async def test_stop_runs_docker_compose_down():
    """stop() runs `docker compose ... down`."""
    store = Neo4jStore()
    proc_mock = _make_proc(returncode=0)
    with patch(
        "autored.persistence.neo4j_store.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc_mock),
    ) as mock_exec:
        await store.stop()
        cmd = mock_exec.call_args[0]
        assert cmd[0] == "docker"
        assert "compose" in cmd
        assert "down" in cmd


@pytest.mark.asyncio
async def test_query_shortest_path_returns_empty_stub():
    """query_shortest_path is a stub returning [] until Phase 5 driver wiring."""
    store = Neo4jStore()
    result = await store.query_shortest_path("USER-A@DOMAIN", "DOMAIN-ADMIN")
    assert result == []
