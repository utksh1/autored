"""AutoRed credential encryption — Fernet-based at-rest protection.

Spec §3.3 line 313: 'credential_value TEXT — hashed/encrypted form,
never plaintext passwords in DB.'

The DB key is auto-generated at first use and persisted to
db/.db_key (chmod 0600). Override the path via AUTORED_DB_KEY_PATH env var.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet

# Module-global; resolved lazily on first call.
_DB_KEY_PATH = Path(os.environ.get("AUTORED_DB_KEY_PATH", "db/.db_key"))
_fernet: Fernet | None = None
# Raw key bytes for the cached `_fernet`. Tracked separately because
# `Fernet` instances don't expose their key as a public attribute (the
# original code's `_fernet.key` was a latent AttributeError, masked
# because encrypt/decrypt only called get_or_create_db_key() when
# `_fernet is None`).
_db_key: bytes | None = None
# Last path the cached `_fernet` was built from. When `_resolve_key_path()`
# returns a different path (e.g. a test does monkeypatch.setattr on
# `_DB_KEY_PATH`), the cache must be invalidated — otherwise encrypt/decrypt
# silently keeps using the old key.
_last_key_path: Path | None = None


def _resolve_key_path() -> Path:
    """Return the path to the DB key file."""
    env_path = os.environ.get("AUTORED_DB_KEY_PATH")
    if env_path:
        return Path(env_path)
    return _DB_KEY_PATH


def get_or_create_db_key() -> bytes:
    """Return the Fernet key, generating + persisting one on first use.

    Cache invalidation: if the resolved key path differs from the one the
    cached `_fernet` was built from (e.g. a test redirected `_DB_KEY_PATH`
    via monkeypatch.setattr, or the env var changed), the cache is dropped
    and a new Fernet instance is built from the new path's key.
    """
    global _fernet, _db_key, _last_key_path
    key_path = _resolve_key_path()
    if _fernet is not None and _last_key_path == key_path:
        # Cache hit — return the stored key bytes.
        assert _db_key is not None
        return _db_key

    # Either first call OR key path changed — re-initialize.
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        key = key_path.read_bytes()
    else:
        key = Fernet.generate_key()
        key_path.write_bytes(key)
        # chmod 0600 — owner read/write only.
        key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    _fernet = Fernet(key)
    _db_key = key
    _last_key_path = key_path
    return key


def encrypt_value(plaintext: str) -> str:
    """Encrypt a plaintext string, return the Fernet token as a string."""
    # Always call get_or_create_db_key() so the cache-invalidation check
    # runs (cheap no-op when `_last_key_path` already equals the resolved
    # path; rebuilds the Fernet instance when the path has changed).
    get_or_create_db_key()
    assert _fernet is not None
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_value(ciphertext: str) -> str:
    """Decrypt a Fernet token string back to plaintext."""
    # See comment in encrypt_value — always re-validate the cache.
    get_or_create_db_key()
    assert _fernet is not None
    return _fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
