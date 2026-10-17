"""Token hashing + verification — PBKDF2-HMAC-SHA256 per ADR #002.

Also: token generation (cryptographically random, high entropy), token resolution
via registry.db, and last-used debouncing.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Optional

from apps.octo.auth.config import (
    PBKDF2_ITERATIONS,
    PBKDF2_KEY_BYTES,
    PBKDF2_SALT_BYTES,
    TOKEN_PLAINTEXT_BYTES,
    TOKEN_PREFIX_CHARS,
)

HASH_ALGO = "pbkdf2_sha256"


def generate_token() -> str:
    """Return a fresh base64url-encoded bearer token (no padding)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(TOKEN_PLAINTEXT_BYTES)).rstrip(b"=").decode()


def token_prefix(plaintext: str) -> str:
    return plaintext[:TOKEN_PREFIX_CHARS]


def hash_token(plaintext: str) -> str:
    """Return storage-format hash. See ADR #002."""
    salt = os.urandom(PBKDF2_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(
        "sha256", plaintext.encode(), salt, PBKDF2_ITERATIONS, dklen=PBKDF2_KEY_BYTES
    )
    return (
        f"{HASH_ALGO}${PBKDF2_ITERATIONS}"
        f"${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"
    )


def verify_token(plaintext: str, stored: str) -> bool:
    """Constant-time PBKDF2 verification."""
    try:
        algo, iters_s, salt_b64, dk_b64 = stored.split("$")
    except ValueError:
        return False
    if algo != HASH_ALGO:
        return False
    try:
        iters = int(iters_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
    except (ValueError, base64.binascii.Error):
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", plaintext.encode(), salt, iters, dklen=len(expected)
    )
    return hmac.compare_digest(actual, expected)


@dataclass(frozen=True)
class TokenResolution:
    """Result of resolving a bearer token against registry.db."""
    slug: str
    token_id: int
    kind: str          # 'buoy' | 'service' | 'admin'
    label: str
    source_instance_id: Optional[str] = None
    """Set on service-kind tokens that are bound to a specific source
    instance (per Phase F.4b). NULL for buoy / admin / unbound-service
    tokens. The router for /api/v1/ingest/<slug>/<source_type>/alerts
    requires this to be set and matches it against the registered source
    instance."""


class AuthError(Exception):
    """Raised on any auth failure. Do not leak which check failed to the caller."""


def resolve_client_token(registry_db: sqlite3.Connection, plaintext: str) -> TokenResolution:
    """Resolve a bearer presented on ingestion endpoints → TokenResolution.

    Raises AuthError on any failure. Caller decides what to log + surface to API caller.
    """
    prefix = token_prefix(plaintext)
    rows = registry_db.execute(
        """
        SELECT id, slug, token_hash, kind, label, revoked_at,
               source_instance_id
          FROM client_tokens
         WHERE token_prefix = ?
        """,
        (prefix,),
    ).fetchall()
    if not rows:
        raise AuthError("no token with that prefix")

    for row in rows:
        if row["revoked_at"] is not None:
            continue
        if verify_token(plaintext, row["token_hash"]):
            return TokenResolution(
                slug=row["slug"],
                token_id=row["id"],
                kind=row["kind"],
                label=row["label"],
                source_instance_id=row["source_instance_id"],
            )
    raise AuthError("token did not verify")


def resolve_admin_token(registry_db: sqlite3.Connection, plaintext: str):
    """Resolve an admin bearer → operator row (dict-like). Raises AuthError."""
    prefix = token_prefix(plaintext)
    rows = registry_db.execute(
        """
        SELECT id, username, email, token_hash, disabled_at
          FROM operators
         WHERE token_prefix = ?
        """,
        (prefix,),
    ).fetchall()
    if not rows:
        raise AuthError("no operator token with that prefix")
    for row in rows:
        if row["disabled_at"] is not None:
            continue
        if verify_token(plaintext, row["token_hash"]):
            return row
    raise AuthError("operator token did not verify")


# ---------------------------------------------------------------------------
# Last-used debounce (spec §7.1). Keep in memory; flush on interval or shutdown.
#
# The interval is measured from a token's last WRITE, not from its previous
# use. Comparing each use with the one before it (as this did) never let a
# token used more often than the interval through again: a buoy heartbeating
# every 60 s had its last_used_at frozen at the first write after start —
# and on the ingest path, where the flush empties the samples, every request
# wrote instead.
# ---------------------------------------------------------------------------

_LAST_USED_DEBOUNCE_SEC = 5 * 60
_last_used_lock = threading.Lock()
# The newest use not yet written, per token.
_pending_last_used: dict[int, tuple[float, str | None]] = {}
# When each token's row was last written (or a write claimed): the anchor.
_last_used_written: dict[int, float] = {}
# The newest use per token, written or not — liveness readers in this process
# (source health) see it without waiting for the next write.
_last_used_seen: dict[int, float] = {}


def note_token_used(token_id: int, source_ip: Optional[str] = None) -> bool:
    """Record a use; return True when the caller should flush it now — the
    token's first use since start, or `_LAST_USED_DEBOUNCE_SEC` since its
    last write. A True answer claims the write, so a burst of concurrent
    uses costs one."""
    now = time.time()
    with _last_used_lock:
        _pending_last_used[token_id] = (now, source_ip)
        if now > _last_used_seen.get(token_id, 0.0):
            _last_used_seen[token_id] = now
        written = _last_used_written.get(token_id)
        if written is not None and now - written < _LAST_USED_DEBOUNCE_SEC:
            return False
        _last_used_written[token_id] = now
        return True


def last_use_seen(token_id: int) -> Optional[float]:
    """Epoch seconds of the newest use of `token_id` in this process (None
    when unused since start). Its row's last_used_at may lag by up to
    `_LAST_USED_DEBOUNCE_SEC`."""
    with _last_used_lock:
        return _last_used_seen.get(token_id)


def flush_last_used(registry_db: sqlite3.Connection) -> int:
    """Flush pending last-used samples; return number of rows written.

    Every pending token is written, due or not, and its debounce restarts
    from now. Lost samples on crash are acceptable — this is liveness, not
    auth.
    """
    with _last_used_lock:
        if not _pending_last_used:
            return 0
        rows = list(_pending_last_used.items())
        _pending_last_used.clear()
        now = time.time()
        for token_id, _ in rows:
            _last_used_written[token_id] = max(now, _last_used_written.get(token_id, 0.0))
    count = 0
    with registry_db:
        for token_id, (ts, ip) in rows:
            registry_db.execute(
                """
                UPDATE client_tokens
                   SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', ?, 'unixepoch'),
                       last_used_ip = ?
                 WHERE id = ?
                """,
                (ts, ip, token_id),
            )
            count += 1
    return count
