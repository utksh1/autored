"""Unit tests for Neo4jStore (Phase 4 T2).

Tests mock ``subprocess.run`` so no real Docker daemon is required.
Covers the four scenarios required by the Phase 4 T2 brief:
  * ``test_store_init`` — construction parameters are stored.
  * ``test_start_docker_compose`` — ``start()`` invokes ``docker compose up -d``.
  * ``test_is_running`` — ``is_running()`` returns True when ``docker ps``
    reports the ``neo4j`` container in its stdout.
  * ``test_upload_bloodhound_data`` — successful ``neo4j-admin`` import returns True.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from autored.persistence.neo4j_store import Neo4jStore


def test_store_init():
    store = Neo4jStore(uri="bolt://localhost:7687", user="neo4j", password="test")
    assert store.uri == "bolt://localhost:7687"
    assert store.user == "neo4j"


@pytest.mark.asyncio
async def test_start_docker_compose(tmp_path, monkeypatch):
    """Verify start() runs docker compose up."""
    store = Neo4jStore()
    with patch("autored.persistence.neo4j_store.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        await store.start()
        assert mock_run.called
        # Verify docker compose command
        cmd = mock_run.call_args[0][0]
        assert "docker" in cmd
        assert "compose" in cmd or "up" in str(mock_run.call_args)


@pytest.mark.asyncio
async def test_is_running():
    store = Neo4jStore()
    with patch("autored.persistence.neo4j_store.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="neo4j-neo4j-1\n", stderr="")
        assert await store.is_running() is True


@pytest.mark.asyncio
async def test_upload_bloodhound_data():
    store = Neo4jStore()
    with patch("autored.persistence.neo4j_store.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=" uploaded", stderr="")
        result = await store.upload_bloodhound_data("/tmp/data.json")
        assert result is True
