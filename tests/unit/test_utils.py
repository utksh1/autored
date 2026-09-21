"""Unit tests for autored.utils.generate_engagement_id (Task 24).

Verifies the engagement ID format ``YYYY-MM-DD_NNN-<name>-<target>``:
  * Date prefix is today (year-prefixed).
  * Sequence counter increments per engagement created today.
  * Name and target are sanitised (no spaces, no special chars).
  * Name is optional.
"""

from pathlib import Path

from autored.utils import generate_engagement_id


def test_generate_engagement_id_with_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eid = generate_engagement_id("10.10.10.5", "lame-test")
    assert eid.startswith("20")  # year prefix
    assert "001" in eid  # sequence
    assert "lame-test" in eid
    assert "10.10.10.5" in eid


def test_generate_engagement_id_without_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eid = generate_engagement_id("10.10.10.5", "")
    assert "10.10.10.5" in eid
    # No empty middle segment
    assert "--" not in eid


def test_generate_engagement_id_sanitizes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eid = generate_engagement_id("10.10.10.5", "Lame Test!!")
    assert "!" not in eid
    assert " " not in eid


def test_generate_engagement_id_increments_sequence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    first = generate_engagement_id("10.10.10.5", "first")
    # Simulate that the first engagement folder was created
    (Path("engagements") / first).mkdir(parents=True)
    second = generate_engagement_id("10.10.10.6", "second")
    assert "002" in second
    assert "001" in first
