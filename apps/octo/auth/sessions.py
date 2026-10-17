"""Console session lifecycle — issue, validate, refresh, revoke.

Sessions are first-party (cookie-based), stored in `registry.db::sessions`.
Two expiry boundaries:

  - `expires_at`     — absolute, 24h from issue. Hard cap.
  - `idle_expires_at` — rolling, 8h from `last_active_at`. Touched on
                        successful validate so an actively-used session
                        stays alive. An idle session times out independently
                        of the absolute expiry.

The cookie value is a 256-bit URL-safe random string. We do NOT store the
plaintext cookie hashed — it IS the row primary key. Stealing the cookie
== having the session, same as bearer-token-in-header. Defense layers
(httpOnly, Secure, SameSite, short idle expiry, IP/UA recording) live at
the cookie/middleware layer, not the storage layer.

A session row is "valid" iff:
  - revoked_at IS NULL
  - now < expires_at
  - now < idle_expires_at

`validate_session()` returns None if any of those fail.
"""
from __future__ import annotations

import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from apps.octo.db import connect, transaction
from apps.octo import paths

SESSION_BYTES = 32                         # 256-bit; URL-safe → 43 chars
ABSOLUTE_LIFETIME = timedelta(hours=24)
IDLE_LIFETIME = timedelta(hours=8)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse(iso: str) -> datetime:
    # SQLite stores trailing 'Z'; Python's fromisoformat doesn't accept that
    # before 3.11. Use a tolerant parse.
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    return datetime.fromisoformat(iso)


@dataclass(frozen=True)
class SessionInfo:
    id: str
    operator_id: int
    issued_at: datetime
    last_active_at: datetime
    expires_at: datetime
    idle_expires_at: datetime
    auth_method: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    revoked_at: Optional[datetime]
    revoked_by: Optional[int]
    # Step-up auth state — populated when the operator has re-authed
    # for a sensitive surface (e.g., /search). All NULL on a fresh
    # session. See migrations 009/010 + apps/octo/auth/step_up.py.
    step_up_auth_granted_at: Optional[datetime] = None
    step_up_auth_until: Optional[datetime] = None
    step_up_auth_ip_prefix: Optional[str] = None


def generate_session_id() -> str:
    return secrets.token_urlsafe(SESSION_BYTES)


def issue_session(
    *,
    operator_id: int,
    auth_method: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> str:
    """Insert a new session row; return the cookie value (session id).

    `auth_method` must be one of: 'password+totp', 'passkey', 'magic-link',
    'bootstrap'.
    """
    # `bootstrap` covers both the factory-default first-login path AND
    # the password-only-because-MFA-not-yet-enrolled path. In every
    # case, the operator is in initial-setup state and the setup_gate
    # middleware confines the session to the setup flow until
    # must_change_password=0 AND mfa_enabled=1.
    if auth_method not in {"password+totp", "passkey", "magic-link", "bootstrap"}:
        raise ValueError(f"invalid auth_method: {auth_method!r}")
    sid = generate_session_id()
    now = _now()
    expires = now + ABSOLUTE_LIFETIME
    idle_expires = now + IDLE_LIFETIME
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                """
                INSERT INTO sessions
                    (id, operator_id, issued_at, last_active_at,
                     expires_at, idle_expires_at, auth_method,
                     ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (sid, operator_id, _iso(now), _iso(now),
                 _iso(expires), _iso(idle_expires), auth_method,
                 ip_address, user_agent),
            )
    finally:
        reg.close()
    return sid


def _row_to_info(row: sqlite3.Row) -> SessionInfo:
    # Step-up columns may not exist in pre-migration-009 databases; tolerate
    # missing keys so older test fixtures don't break.
    keys = row.keys() if hasattr(row, "keys") else []
    granted_raw = row["step_up_auth_granted_at"] if "step_up_auth_granted_at" in keys else None
    until_raw = row["step_up_auth_until"] if "step_up_auth_until" in keys else None
    ip_prefix = row["step_up_auth_ip_prefix"] if "step_up_auth_ip_prefix" in keys else None
    return SessionInfo(
        id=row["id"],
        operator_id=row["operator_id"],
        issued_at=_parse(row["issued_at"]),
        last_active_at=_parse(row["last_active_at"]),
        expires_at=_parse(row["expires_at"]),
        idle_expires_at=_parse(row["idle_expires_at"]),
        auth_method=row["auth_method"],
        ip_address=row["ip_address"],
        user_agent=row["user_agent"],
        revoked_at=_parse(row["revoked_at"]) if row["revoked_at"] else None,
        revoked_by=row["revoked_by"],
        step_up_auth_granted_at=_parse(granted_raw) if granted_raw else None,
        step_up_auth_until=_parse(until_raw) if until_raw else None,
        step_up_auth_ip_prefix=ip_prefix,
    )


def validate_session(session_id: str) -> Optional[SessionInfo]:
    """Return SessionInfo if the session is valid; otherwise None.

    Side-effect: on a valid session, touches `last_active_at` and bumps
    `idle_expires_at` (rolling 8h). The absolute `expires_at` is never
    extended.
    """
    if not session_id:
        return None
    reg = connect(paths.registry_db_path())
    try:
        row = reg.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if row is None:
            return None
        if row["revoked_at"] is not None:
            return None
        now = _now()
        try:
            expires = _parse(row["expires_at"])
            idle_expires = _parse(row["idle_expires_at"])
        except ValueError:
            return None
        if now >= expires or now >= idle_expires:
            return None
        # Touch — rolling idle expiry
        new_last_active = _iso(now)
        new_idle_expires = _iso(now + IDLE_LIFETIME)
        with transaction(reg):
            reg.execute(
                "UPDATE sessions SET last_active_at = ?, idle_expires_at = ? "
                "WHERE id = ?",
                (new_last_active, new_idle_expires, session_id),
            )
        # Re-read to return the post-touch state
        row = reg.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
    finally:
        reg.close()
    return _row_to_info(row)


def revoke_session(
    session_id: str,
    *,
    revoked_by: Optional[int] = None,
) -> bool:
    """Mark a session revoked; return True if it was found and not already revoked."""
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            cur = reg.execute(
                "UPDATE sessions SET revoked_at = ?, revoked_by = ? "
                "WHERE id = ? AND revoked_at IS NULL",
                (_iso(_now()), revoked_by, session_id),
            )
            return cur.rowcount > 0
    finally:
        reg.close()


def revoke_all_for_operator(
    operator_id: int,
    *,
    revoked_by: Optional[int] = None,
    except_session_id: Optional[str] = None,
) -> int:
    """Revoke every active session for an operator; return count revoked.

    Used after password change, MFA reset, admin lockout. Pass
    `except_session_id` to keep the caller's own session alive (e.g., when
    the operator changes their own password from the Settings page).
    """
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            if except_session_id:
                cur = reg.execute(
                    "UPDATE sessions SET revoked_at = ?, revoked_by = ? "
                    "WHERE operator_id = ? AND revoked_at IS NULL "
                    "AND id != ?",
                    (_iso(_now()), revoked_by, operator_id, except_session_id),
                )
            else:
                cur = reg.execute(
                    "UPDATE sessions SET revoked_at = ?, revoked_by = ? "
                    "WHERE operator_id = ? AND revoked_at IS NULL",
                    (_iso(_now()), revoked_by, operator_id),
                )
            return cur.rowcount
    finally:
        reg.close()


def list_sessions_for_operator(operator_id: int) -> list[SessionInfo]:
    """List all sessions (active + expired + revoked) for an operator,
    most recently issued first. Used by the Settings UI."""
    reg = connect(paths.registry_db_path())
    try:
        rows = reg.execute(
            "SELECT * FROM sessions WHERE operator_id = ? "
            "ORDER BY issued_at DESC",
            (operator_id,),
        ).fetchall()
    finally:
        reg.close()
    return [_row_to_info(r) for r in rows]
