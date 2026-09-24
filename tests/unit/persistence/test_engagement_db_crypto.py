from __future__ import annotations

import aiosqlite
import pytest

from autored.persistence import engagement_db
from autored.crypto import encrypt_value, decrypt_value


@pytest.mark.asyncio
async def test_credential_value_is_encrypted_at_rest(tmp_path, monkeypatch):
    """Review Focus #1 — plaintext credential must not be readable via raw SQL."""
    db_path = str(tmp_path / "test.sqlite")
    # Override the db key location so tests are isolated.
    monkeypatch.setattr("autored.crypto._DB_KEY_PATH", tmp_path / ".db_key")

    await engagement_db.init_db(db_path)
    await engagement_db.insert_engagement(db_path, {
        "id": "e1", "target": "10.10.10.5", "start_ts": "2026-09-23T00:00:00Z",
        "end_ts": None, "summary": None, "report_path": None,
        "operator": "tester", "phase": "recon", "parent_engagement_id": None,
    })
    await engagement_db.insert_credential(db_path, {
        "id": "c1", "engagement_id": "e1", "username": "administrator",
        "credential_type": "password", "credential_value": "SuperSecret123!",
        "source": "mimikatz", "target_host": "10.10.10.5",
        "cracked": 1, "cracked_value": "SuperSecret123!",
        "discovered_at": "2026-09-23T00:00:00Z",
    })

    # Raw SQL query — must NOT find the plaintext password.
    async with aiosqlite.connect(db_path) as conn:
        async with conn.execute(
            "SELECT credential_value, cracked_value FROM credentials WHERE id = ?",
            ("c1",),
        ) as cur:
            row = await cur.fetchone()
    assert row is not None
    encrypted_value, encrypted_cracked = row
    assert encrypted_value != "SuperSecret123!"
    assert encrypted_cracked != "SuperSecret123!"
    assert "SuperSecret123!" not in encrypted_value
    assert "SuperSecret123!" not in encrypted_cracked
    # And the encrypted form must decrypt back to the plaintext.
    assert decrypt_value(encrypted_value) == "SuperSecret123!"
    assert decrypt_value(encrypted_cracked) == "SuperSecret123!"


def test_encrypt_decrypt_round_trip(monkeypatch, tmp_path):
    monkeypatch.setattr("autored.crypto._DB_KEY_PATH", tmp_path / ".db_key")
    plaintext = "P@ssw0rd!"
    ciphertext = encrypt_value(plaintext)
    assert ciphertext != plaintext
    assert decrypt_value(ciphertext) == plaintext


def test_db_key_path_change_invalidates_cache(monkeypatch, tmp_path):
    """Fix I4 — `_fernet` cache must invalidate when `_DB_KEY_PATH` changes.

    Without the fix, the module-global `_fernet` is set once on first call and
    never rebuilt, so the second call below would silently keep using the
    key from `key1` and `key2` would never be written.
    """
    from autored import crypto

    key1 = tmp_path / "key1"
    key2 = tmp_path / "key2"

    monkeypatch.setattr("autored.crypto._DB_KEY_PATH", key1)
    crypto.encrypt_value("a")  # initializes `_fernet` from key1
    assert key1.exists(), "key1 file should have been created on first call"
    key1_bytes = key1.read_bytes()

    monkeypatch.setattr("autored.crypto._DB_KEY_PATH", key2)
    crypto.encrypt_value("b")  # cache must be invalidated; rebuild from key2
    assert key2.exists(), (
        "key2 file should have been created after path change — if missing, "
        "the `_fernet` cache was not invalidated"
    )
    key2_bytes = key2.read_bytes()

    # The two key files must differ — proves the cache was invalidated
    # (otherwise both calls would have used key1 and key2 would not exist).
    assert key1_bytes != key2_bytes
