# tests/unit/test_utils.py
from __future__ import annotations

from datetime import datetime

from autored.utils import generate_engagement_id


def test_generate_engagement_id_with_name(tmp_path, monkeypatch):
    # Isolate from any real engagements/ dir at the repo root.
    monkeypatch.chdir(tmp_path)
    eid = generate_engagement_id("10.10.10.5", "lame")
    today = datetime.utcnow().strftime("%Y-%m-%d")
    assert eid.startswith(f"{today}_001-")
    assert "lame" in eid
    assert "10.10.10.5" in eid


def test_generate_engagement_id_without_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eid = generate_engagement_id("10.10.10.5")
    today = datetime.utcnow().strftime("%Y-%m-%d")
    assert eid.startswith(f"{today}_001-")
    assert "10.10.10.5" in eid


def test_generate_engagement_id_sanitizes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eid = generate_engagement_id("lame.htb", "weird name!!!")
    # Special chars must be replaced with hyphens.
    assert "!" not in eid
    assert " " not in eid
