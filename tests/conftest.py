"""Shared pytest fixtures for AutoRed tests."""
from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Return the path to tests/fixtures/."""
    return FIXTURES_DIR


@pytest.fixture
def sandbox_roe_yaml() -> str:
    """Return the path to the sandbox RoE YAML."""
    return str(Path(__file__).parent.parent / "roe-sandbox.yaml")


@pytest.fixture
def tmp_engagement_dir(tmp_path, monkeypatch) -> Path:
    """Redirect ENGAGEMENTS_DIR to a tmp_path for isolation."""
    engagements = tmp_path / "engagements"
    engagements.mkdir()
    monkeypatch.setattr(
        "autored.persistence.filesystem.ENGAGEMENTS_DIR", engagements
    )
    return engagements
