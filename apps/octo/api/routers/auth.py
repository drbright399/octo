"""Athena Console auth endpoints — Phase G.1.

Surface:

  POST   /api/v1/auth/password/begin            → verify password, return TOTP challenge
  POST   /api/v1/auth/password/totp             → verify TOTP, issue session
  POST   /api/v1/auth/magic-link/request        → super_admin issues a magic link
  POST   /api/v1/auth/magic-link/verify         → consume a magic link, issue session
  POST   /api/v1/auth/passkey/register/begin    → (authed) generate registration challenge
  POST   /api/v1/auth/passkey/register/complete → (authed) verify attestation, store credential
  POST   /api/v1/auth/passkey/begin             → generate authentication challenge
  POST   /api/v1/auth/passkey/complete          → verify assertion, issue session
  POST   /api/v1/auth/logout                    → revoke current session
  GET    /api/v1/auth/sessions                  → list current operator's sessions
  DELETE /api/v1/auth/sessions/{id}             → revoke a specific session

Identity model
--------------

These endpoints establish *Athena Console* identity (session-cookie-based),
distinct from OCTO admin bearer tokens. An operator may hold both:

  - admin bearer token  → CLI / automation (existing, unchanged)
  - Console session     → browser UI (new, this surface)

Lockout model
-------------

`failed_login_count` increments on wrong password OR wrong TOTP. After 5
failures, `locked_until = now + 15min` is set and `/password/begin` returns
`AUTH_LOCKED` (423) without distinguishing wrong-password from no-such-user.
Successful login resets the counter to 0.

Challenge model
---------------

Between `/password/begin` and `/password/totp`, the server issues a stateless
Fernet-encrypted challenge token (5min TTL). Token holds `{operator_id,
auth_method}`. Fernet provides timestamp-based expiry + tamper detection +
no DB write per login. Multi-worker-safe via key derived from the shared
MFA key.

Audit chain
-----------

Every auth event is hash-chain-logged (action labels: `auth_login_attempt`,
`auth_login_success`, `auth_login_lockout`, `auth_logout`, `auth_session_revoke`).
Failed attempts log even when the attacker is unknown — the audit trail must
show every probe.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Cookie, Depends, Header, Request, Response
from pydantic import BaseModel, Field
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from apps.octo import paths
from apps.octo.auth import audit, bootstrap, crypto, email_sender, sessions
from apps.octo.auth import core as core_auth
from apps.octo.api.errors import APIError
from apps.octo.auth.config import ATHENA_RP_NAME, athena_origin, athena_rp_id
from apps.octo.db import connect, transaction


router = APIRouter(prefix="/auth", tags=["auth"])

CHALLENGE_TTL_SECONDS = 300                  # 5 minutes
LOCKOUT_THRESHOLD = 5                        # failures before lockout
LOCKOUT_DURATION = timedelta(minutes=15)
SESSION_COOKIE_NAME = "athena_session"
WEBAUTHN_CHALLENGE_COOKIE = "athena_webauthn_challenge"
WEBAUTHN_CHALLENGE_TTL = 300                 # 5 minutes for WebAuthn ceremonies


def _cookie_secure() -> bool:
    """Whether to set the `Secure` flag on session cookies.

    Default True — production runs HTTPS-only behind a reverse proxy.
    Local dev runs over HTTP at http://localhost:5173, which browsers
    refuse to store `Secure` cookies for; the dev startup script sets
    `OCTO_COOKIE_SECURE=0` to opt out. Never set this to false in any
    deployment that handles real credentials.
    """
    import os
    return os.environ.get("OCTO_COOKIE_SECURE", "1") not in (
        "0", "false", "no", "False",
    )


# ---------------------------------------------------------------------------
# Pydantic models — request + response shapes
# ---------------------------------------------------------------------------

class LoginPasswordRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=512)


class LoginPasswordBeginResponse(BaseModel):
    """Two-shape response:
      - operator has MFA enrolled → `requires_totp=true`, `challenge_id`
        set; caller posts /password/totp to finalize.
      - operator has NOT enrolled MFA → `requires_totp=false`,
        `challenge_id` blank, and a session cookie has already been set
        on this response. Caller redirects to / — the setup_gate
        middleware will force them onto /login/setup until they
        complete MFA enrollment.
    Path 2 is the only way a brand-new operator (just got a temp
    password from the admin, no MFA yet) can sign in to reach the
    enrollment wizard.
    """
    challenge_id: str = ""
    requires_totp: bool = True


class LoginTOTPRequest(BaseModel):
    challenge_id: str
    # 6-digit TOTP, or a single-use backup code (XXXX-XXXX-XXXX)
    totp_code: str = Field(min_length=6, max_length=16)


class LoginCompleteResponse(BaseModel):
    operator_id: int
    username: str
    email: str
    role: list[str]
    scope_slugs: list[str]
    ai_access_enabled: bool


class SessionEntry(BaseModel):
    id: str                                  # truncated for display safety
    issued_at: str
    last_active_at: str
    expires_at: str
    auth_method: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    is_current: bool                         # True if this is the caller's session


class SessionListResponse(BaseModel):
    sessions: list[SessionEntry]


class LogoutResponse(BaseModel):
    revoked: bool


# ---------------------------------------------------------------------------
# Challenge token (stateless, Fernet-encrypted)
# ---------------------------------------------------------------------------

def _mfa_subkey_fernet(purpose: bytes) -> Fernet:
    """A Fernet keyed by a purpose-bound subkey of the MFA master key:
    SHA-256(master key || purpose label).

    What is hashed is the 32-byte MFA master key (`crypto.load_mfa_key`,
    minted by `Fernet.generate_key()` from the OS CSPRNG) — never a password
    or anything a person chose. With 256 bits of uniform entropy there is
    nothing to brute-force, so a fast hash is the right tool here; a password
    KDF (argon2 / scrypt / PBKDF2 — operator passwords go through
    `core.hash_token`, PBKDF2) would only add its cost to every sign-in. The
    label is a domain separator: a login challenge and a pending-enrolment
    token are sealed under different keys, so neither can be replayed as the
    other.

    Deterministic so multi-worker setups all sign + verify with the same key.
    Changing the derivation (or the label) invalidates every token in flight.
    """
    _, mfa_key_b64 = crypto.load_mfa_key()
    master_key = base64.urlsafe_b64decode(mfa_key_b64)
    derived = hashlib.sha256(master_key + purpose).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def _challenge_fernet() -> Fernet:
    """The login-challenge Fernet (see `_mfa_subkey_fernet`).

    Key rotation is intentional: rotating the MFA key invalidates pending
    challenges (which is fine — challenges are 5min-lived).
    """
    return _mfa_subkey_fernet(b"auth-challenge-v1")


def _issue_challenge(operator_id: int) -> str:
    f = _challenge_fernet()
    payload = json.dumps({"op": operator_id, "iat": int(time.time())}).encode()
    return f.encrypt(payload).decode()


def _verify_challenge(token: str) -> int:
    """Return operator_id. A genuine-but-expired challenge raises
    AUTH_CHALLENGE_EXPIRED so the UI can say "timed out, enter your password
    again" instead of "wrong code" — an operator who takes >5 min to find
    their authenticator was otherwise told their (correct) code was wrong,
    indefinitely. Reveals nothing: the holder already knows when the token
    was issued. Anything else raises AUTH_TOTP_INVALID."""
    f = _challenge_fernet()
    try:
        raw = f.decrypt(token.encode(), ttl=CHALLENGE_TTL_SECONDS)
    except InvalidToken:
        try:
            f.decrypt(token.encode())          # authentic, just too old?
        except InvalidToken:
            raise APIError("AUTH_TOTP_INVALID", "challenge token invalid")
        raise APIError("AUTH_CHALLENGE_EXPIRED")
    try:
        data = json.loads(raw.decode())
        return int(data["op"])
    except (json.JSONDecodeError, KeyError, ValueError):
        raise APIError("AUTH_TOTP_INVALID", "challenge token malformed")


# ---------------------------------------------------------------------------
# Lockout / failed-login bookkeeping
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _is_locked(row: sqlite3.Row) -> bool:
    locked_until = row["locked_until"]
    if not locked_until:
        return False
    try:
        # Tolerant parse (SQLite stores trailing Z)
        s = locked_until[:-1] + "+00:00" if locked_until.endswith("Z") else locked_until
        until = datetime.fromisoformat(s)
    except ValueError:
        return False
    return datetime.now(timezone.utc) < until


def _bump_failed_login(reg: sqlite3.Connection, operator_id: int) -> int:
    """Atomic increment of failed_login_count; sets locked_until on threshold.

    Single UPDATE statement → atomic on its own. Commits immediately (no
    `with transaction()` wrapper) so the bump persists even if the caller
    raises an APIError afterward (which would otherwise trigger a rollback).
    Returns the post-bump failed_login_count.
    """
    until = datetime.now(timezone.utc) + LOCKOUT_DURATION
    until_iso = until.strftime("%Y-%m-%dT%H:%M:%S.") + f"{until.microsecond // 1000:03d}Z"
    reg.execute(
        """
        UPDATE operators
           SET failed_login_count = failed_login_count + 1,
               locked_until = CASE
                   WHEN failed_login_count + 1 >= ? THEN ?
                   ELSE locked_until
               END
         WHERE id = ?
        """,
        (LOCKOUT_THRESHOLD, until_iso, operator_id),
    )
    reg.commit()
    return reg.execute(
        "SELECT failed_login_count FROM operators WHERE id = ?",
        (operator_id,),
    ).fetchone()[0]


def _reset_login_posture(
    reg: sqlite3.Connection,
    operator_id: int,
    *,
    also_stamp_mfa_verified: bool = False,
) -> None:
    """Successful login: zero the counter, clear lockout, stamp last_login_at.

    Optionally also stamps last_mfa_verified_at in the same UPDATE so the
    success path of password+TOTP commits atomically. Commits immediately.
    """
    now = _now_iso()
    if also_stamp_mfa_verified:
        reg.execute(
            "UPDATE operators SET failed_login_count = 0, locked_until = NULL, "
            "last_login_at = ?, last_mfa_verified_at = ? WHERE id = ?",
            (now, now, operator_id),
        )
    else:
        reg.execute(
            "UPDATE operators SET failed_login_count = 0, locked_until = NULL, "
            "last_login_at = ? WHERE id = ?",
            (now, operator_id),
        )
    reg.commit()


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------

def _audit_append(action: str, *, actor: str, target_id: Optional[str],
                  before: Optional[dict], after: Optional[dict],
                  reason: Optional[str], request_id: str) -> None:
    """Append a single audit row for an auth event. Failure to audit is fatal —
    we never let an auth event slip through without a chain entry.
    """
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=actor,
            actor_kind="human" if actor != "system" else "system",
            action=action,
            target_kind="operator",
            target_id=target_id,
            client_slug="global",
            before_state=before,
            after_state=after,
            reason=reason,
            request_id=request_id,
        ))
    finally:
        g_audit.close()


# ---------------------------------------------------------------------------
# Session-cookie identity dep (used by protected endpoints below)
# ---------------------------------------------------------------------------

def session_identity(
    athena_session: Optional[str] = Cookie(default=None),
) -> sessions.SessionInfo:
    """FastAPI dep: validate the session cookie, return SessionInfo.

    Raises APIError(AUTH_SESSION_INVALID) if the cookie is missing/expired/
    revoked. Touches `last_active_at` (rolling idle expiry) on success.
    """
    if not athena_session:
        raise APIError("AUTH_SESSION_INVALID", "no session cookie")
    info = sessions.validate_session(athena_session)
    if info is None:
        raise APIError("AUTH_SESSION_INVALID")
    return info


# ---------------------------------------------------------------------------
# /me — session-cookie analog of /api/v1/whoami (which is bearer-only)
# ---------------------------------------------------------------------------
#
# Used by the Athena Console's session middleware to validate an inbound
# request and resolve the operator. Unlike `whoami`, this is COOKIE-authed,
# not bearer-authed — Console session cookies don't have a corresponding
# bearer surface. Returns the same identity shape as the login endpoints
# return (LoginCompleteResponse) so downstream code can treat all three
# auth methods uniformly.

class MeResponse(BaseModel):
    operator_id:           int
    username:              str
    email:                 str
    display_name:          Optional[str] = None  # what Athena calls the user when set
    role:                  list[str]
    scope_slugs:           list[str]
    ai_access_enabled:     bool
    auth_method:           str        # how this session was issued
    session_expires_at:    str        # ISO; absolute (24h) cap
    # Account state — the SPA reads these to gate forced-setup + render
    # the Account panel live (instead of hardcoded fixtures).
    must_change_password:  bool       # operator hasn't set a password yet, or admin forced rotation
    mfa_enabled:           bool       # operator has TOTP enrolled
    backup_codes_remaining: int       # count of unconsumed backup codes (0 if none generated)
    needs_setup:           bool       # convenience: must_change_password OR not mfa_enabled


@router.get("/me", response_model=MeResponse)
def me(info: sessions.SessionInfo = Depends(session_identity)) -> MeResponse:
    """Return the current operator's identity. Reads from the session cookie
    (set by /password/totp, /magic-link/verify, or /passkey/complete)."""
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        op = reg.execute(
            """
            SELECT id, username, email, ai_access_enabled, ai_access_expires_at,
                   must_change_password, mfa_enabled, display_name
              FROM operators WHERE id = ?
            """,
            (info.operator_id,),
        ).fetchone()
        if op is None:
            raise APIError("AUTH_SESSION_INVALID", "session resolves to deleted operator")
        role_rows = reg.execute(
            "SELECT role_name, scope_slugs FROM operator_roles "
            "WHERE operator_id = ?",
            (op["id"],),
        ).fetchall()
        # Count unconsumed backup codes across the operator's active set.
        # Each active backup_code_sets row holds an encrypted JSON blob with
        # a `consumed` array; we count = hashes - consumed. Hard-decoding
        # every operator-me hit on the active set is acceptable cost (one
        # Fernet decrypt per /me) and keeps the source of truth in one place.
        active_set = reg.execute(
            "SELECT codes_enc FROM backup_code_sets "
            "WHERE operator_id = ? AND revoked_at IS NULL "
            "ORDER BY id DESC LIMIT 1",
            (op["id"],),
        ).fetchone()
    finally:
        reg.close()

    backup_codes_remaining = 0
    if active_set is not None:
        try:
            payload = crypto.decode_backup_code_set(active_set["codes_enc"])
            total = len(payload.get("hashes", []))
            consumed = len(payload.get("consumed", []))
            backup_codes_remaining = max(0, total - consumed)
        except Exception:
            # Encrypted blob unreadable — surface 0 rather than 500
            backup_codes_remaining = 0

    roles_list = sorted({r["role_name"] for r in role_rows})
    scope: set[str] = set()
    for r in role_rows:
        for s in json.loads(r["scope_slugs"]):
            scope.add(s)

    ai_enabled = bool(op["ai_access_enabled"])
    if ai_enabled and op["ai_access_expires_at"]:
        try:
            exp_s = op["ai_access_expires_at"]
            exp_s = exp_s[:-1] + "+00:00" if exp_s.endswith("Z") else exp_s
            if datetime.fromisoformat(exp_s) < datetime.now(timezone.utc):
                ai_enabled = False
        except ValueError:
            ai_enabled = False

    must_change = bool(op["must_change_password"])
    mfa_enabled = bool(op["mfa_enabled"])
    return MeResponse(
        operator_id=op["id"],
        username=op["username"],
        email=op["email"],
        display_name=op["display_name"],
        role=roles_list,
        scope_slugs=sorted(scope),
        ai_access_enabled=ai_enabled,
        auth_method=info.auth_method,
        session_expires_at=info.expires_at.isoformat(),
        must_change_password=must_change,
        mfa_enabled=mfa_enabled,
        backup_codes_remaining=backup_codes_remaining,
        needs_setup=must_change or not mfa_enabled,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/password/begin", response_model=LoginPasswordBeginResponse)
def password_begin(
    req: LoginPasswordRequest,
    request: Request,
    response: Response,
) -> LoginPasswordBeginResponse:
    """Verify username + password. Two possible outcomes:

    1. Operator has MFA enrolled → return a 5-min challenge token; caller
       posts /password/totp next.
    2. Operator does NOT have MFA enrolled → issue a session immediately
       with auth_method='password-no-mfa'. The setup_gate middleware
       confines that session to the setup flow until MFA is enrolled.
       This is the password path that lets an operator who HAS a password
       but no MFA yet (admin-issued reset, or a setup wizard abandoned
       between set-password and TOTP) get back to `/login/setup`.

    An operator with no password at all (`password_hash IS NULL` — the
    factory super_admin before setup, invited operators) can never pass
    here, whatever is submitted; their only door is the single-use
    initial-setup magic link.

    Failures (no such user / wrong password / locked) all return
    AUTH_PASSWORD_INVALID with a generic message. Locked accounts return
    AUTH_LOCKED to give the user a clear retry affordance.
    """
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    reg = connect(paths.registry_db_path())
    try:
        # No `with transaction()` wrapper here — every state-change path
        # (failed-login bump) needs to commit BEFORE we raise an APIError,
        # else `transaction()`'s exception-rollback would undo it. Each
        # write is single-statement and atomic on its own.
        row = reg.execute(
            """
            SELECT id, username, email, password_hash, mfa_enabled,
                   failed_login_count, locked_until, disabled_at
              FROM operators
             WHERE username = ?
            """,
            (req.username,),
        ).fetchone()
        if row is None:
            _audit_append(
                "auth_login_attempt",
                actor=f"unknown:{req.username}",
                target_id=None,
                before=None,
                after={"outcome": "no_such_user", "ip": ip},
                reason="login attempt against unknown username",
                request_id=request_id,
            )
            raise APIError("AUTH_PASSWORD_INVALID")
        if row["disabled_at"] is not None:
            _audit_append(
                "auth_login_attempt",
                actor=row["username"], target_id=str(row["id"]),
                before=None,
                after={"outcome": "disabled", "ip": ip},
                reason="login attempt against disabled operator",
                request_id=request_id,
            )
            raise APIError("AUTH_OPERATOR_DISABLED")
        if _is_locked(row):
            _audit_append(
                "auth_login_attempt",
                actor=row["username"], target_id=str(row["id"]),
                before=None,
                after={"outcome": "locked", "ip": ip},
                reason="login attempt against locked operator",
                request_id=request_id,
            )
            raise APIError("AUTH_LOCKED")
        if not row["password_hash"]:
            # No password set — passkey-only or magic-link-only operator.
            # Generic failure to avoid disclosing which auth method is enabled.
            raise APIError("AUTH_PASSWORD_INVALID")
        if not core_auth.verify_token(req.password, row["password_hash"]):
            count = _bump_failed_login(reg, row["id"])
            _audit_append(
                "auth_login_attempt",
                actor=row["username"], target_id=str(row["id"]),
                before=None,
                after={"outcome": "wrong_password", "ip": ip,
                       "failed_count": count},
                reason="password did not verify",
                request_id=request_id,
            )
            if count >= LOCKOUT_THRESHOLD:
                _audit_append(
                    "auth_login_lockout",
                    actor="system", target_id=str(row["id"]),
                    before={"failed_count": count - 1},
                    after={"failed_count": count,
                           "lockout_minutes": int(LOCKOUT_DURATION.total_seconds() // 60)},
                    reason=f"{LOCKOUT_THRESHOLD} consecutive failed logins",
                    request_id=request_id,
                )
            raise APIError("AUTH_PASSWORD_INVALID")
        if not row["mfa_enabled"]:
            # Password is correct + operator has no MFA factor. This is
            # the brand-new-operator path: admin set a temp password, no
            # TOTP enrolled yet. Issue a session bound to the setup flow.
            # The setup_gate middleware will reject every non-setup path
            # until MFA is enrolled + must_change_password clears.
            _reset_login_posture(reg, row["id"], also_stamp_mfa_verified=False)
        else:
            # Password verified, MFA enrolled — issue challenge.
            challenge = _issue_challenge(row["id"])
            _audit_append(
                "auth_login_password_ok",
                actor=row["username"], target_id=str(row["id"]),
                before=None,
                after={"outcome": "challenge_issued", "ip": ip},
                reason=None,
                request_id=request_id,
            )
            return LoginPasswordBeginResponse(
                challenge_id=challenge, requires_totp=True,
            )

        # --- password-no-mfa path: issue session immediately ---
        op_username = row["username"]
        op_id = row["id"]
    finally:
        reg.close()

    # auth_method='bootstrap' is the catch-all for "operator is in
    # initial-setup state" — here, a verified password with no MFA yet.
    # (There is no factory-default password: the factory super_admin has
    # a NULL hash until its owner sets one, so it cannot reach this line
    # before then.) The setup_gate middleware confines the session to
    # setup endpoints.
    sid = sessions.issue_session(
        operator_id=op_id,
        auth_method="bootstrap",
        ip_address=ip,
        user_agent=user_agent,
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=sid,
        max_age=int(sessions.ABSOLUTE_LIFETIME.total_seconds()),
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        path="/",
    )
    _audit_append(
        "auth_login_success",
        actor=op_username, target_id=str(op_id),
        before=None,
        after={"auth_method": "bootstrap",
               "subkind": "password-only-pending-mfa",
               "ip": ip, "session_issued": True,
               "note": "session confined to setup flow until MFA enrolled"},
        reason="password-only sign-in for operator pending MFA enrollment",
        request_id=request_id,
    )
    return LoginPasswordBeginResponse(challenge_id="", requires_totp=False)


def _consume_backup_code(
    reg: sqlite3.Connection, operator_id: int, username: str,
    presented: str, ip: Optional[str], request_id: str,
) -> bool:
    """Burn one backup code from the operator's active set. True on match."""
    code = presented.upper().replace(" ", "")
    if "-" not in code and len(code) == 12:
        code = f"{code[0:4]}-{code[4:8]}-{code[8:12]}"
    active = reg.execute(
        "SELECT id, codes_enc FROM backup_code_sets "
        "WHERE operator_id = ? AND revoked_at IS NULL "
        "ORDER BY id DESC LIMIT 1",
        (operator_id,),
    ).fetchone()
    if active is None:
        return False
    try:
        matched, new_blob = crypto.consume_backup_code(active["codes_enc"], code)
    except (InvalidToken, ValueError, KeyError):
        return False
    if not matched:
        return False
    reg.execute(
        "UPDATE backup_code_sets SET codes_enc = ? WHERE id = ?",
        (new_blob, active["id"]),
    )
    reg.commit()
    payload = crypto.decode_backup_code_set(new_blob)
    remaining = len(payload.get("hashes", [])) - len(payload.get("consumed", []))
    _audit_append(
        "auth_login_backup_code_used",
        actor=username, target_id=str(operator_id),
        before=None,
        after={"outcome": "success", "ip": ip,
               "backup_codes_remaining": max(0, remaining)},
        reason="backup code accepted in place of TOTP",
        request_id=request_id,
    )
    return True


@router.post("/password/totp", response_model=LoginCompleteResponse)
def password_totp(req: LoginTOTPRequest, request: Request, response: Response) -> LoginCompleteResponse:
    """Verify TOTP code against the challenge. On success, issue a session
    cookie and return operator identity.

    The challenge token is stateless — its 5min TTL is enforced by Fernet,
    and a malformed/expired token returns AUTH_TOTP_INVALID without revealing
    operator_id.
    """
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    operator_id = _verify_challenge(req.challenge_id)

    reg = connect(paths.registry_db_path())
    try:
        # See note in password_begin — same transaction-vs-raise discipline.
        row = reg.execute(
            """
            SELECT id, username, email, mfa_secret_enc, mfa_enabled,
                   failed_login_count, locked_until, disabled_at,
                   ai_access_enabled, ai_access_expires_at
              FROM operators
             WHERE id = ?
            """,
            (operator_id,),
        ).fetchone()
        if row is None or row["disabled_at"] is not None:
            raise APIError("AUTH_TOTP_INVALID")
        if _is_locked(row):
            raise APIError("AUTH_LOCKED")
        if not row["mfa_enabled"] or not row["mfa_secret_enc"]:
            raise APIError("AUTH_MFA_NOT_ENROLLED")
        try:
            secret_b32 = crypto.decrypt_at_rest(row["mfa_secret_enc"]).decode()
        except (InvalidToken, ValueError):
            # Encrypted secret can't be decrypted — operator is unusable
            # without admin intervention. Don't reveal this to attacker.
            raise APIError("AUTH_TOTP_INVALID")
        totp = pyotp.TOTP(secret_b32)
        presented = req.totp_code.strip()
        if presented.isdigit():
            second_factor_ok = totp.verify(presented, valid_window=1)
        else:
            # Not a TOTP shape → single-use backup code. The wizard has always
            # promised these as the lost-authenticator fallback; until now no
            # login path accepted one. A miss takes the same failed-login /
            # lockout path as a wrong TOTP.
            second_factor_ok = _consume_backup_code(
                reg, row["id"], row["username"], presented, ip, request_id,
            )
        if not second_factor_ok:
            count = _bump_failed_login(reg, row["id"])
            _audit_append(
                "auth_login_attempt",
                actor=row["username"], target_id=str(row["id"]),
                before=None,
                after={"outcome": "wrong_totp", "ip": ip,
                       "failed_count": count},
                reason="TOTP did not verify",
                request_id=request_id,
            )
            if count >= LOCKOUT_THRESHOLD:
                _audit_append(
                    "auth_login_lockout",
                    actor="system", target_id=str(row["id"]),
                    before={"failed_count": count - 1},
                    after={"failed_count": count,
                           "lockout_minutes": int(LOCKOUT_DURATION.total_seconds() // 60)},
                    reason=f"{LOCKOUT_THRESHOLD} consecutive failed logins",
                    request_id=request_id,
                )
            raise APIError("AUTH_TOTP_INVALID")
        # Success — single-statement reset that also stamps last_mfa_verified_at
        _reset_login_posture(reg, row["id"], also_stamp_mfa_verified=True)
        # Collect roles + scope_slugs (across all role assignments)
        role_rows = reg.execute(
            "SELECT role_name, scope_slugs FROM operator_roles WHERE operator_id = ?",
            (row["id"],),
        ).fetchall()
        roles: list[str] = sorted({r["role_name"] for r in role_rows})
        scope: set[str] = set()
        for r in role_rows:
            for s in json.loads(r["scope_slugs"]):
                scope.add(s)
    finally:
        reg.close()

    # Issue session OUTSIDE the registry transaction (sessions module opens
    # its own connection). Session insert has its own atomicity.
    sid = sessions.issue_session(
        operator_id=row["id"],
        auth_method="password+totp",
        ip_address=ip,
        user_agent=user_agent,
    )

    # AI-access flag: enabled = (column is 1) AND (no expiry OR expiry > now)
    ai_enabled = bool(row["ai_access_enabled"])
    if ai_enabled and row["ai_access_expires_at"]:
        try:
            exp_s = row["ai_access_expires_at"]
            exp_s = exp_s[:-1] + "+00:00" if exp_s.endswith("Z") else exp_s
            if datetime.fromisoformat(exp_s) < datetime.now(timezone.utc):
                ai_enabled = False
        except ValueError:
            ai_enabled = False

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=sid,
        max_age=int(sessions.ABSOLUTE_LIFETIME.total_seconds()),
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        path="/",
    )

    _audit_append(
        "auth_login_success",
        actor=row["username"], target_id=str(row["id"]),
        before=None,
        after={"auth_method": "password+totp", "ip": ip,
               "session_issued": True},
        reason=None,
        request_id=request_id,
    )

    return LoginCompleteResponse(
        operator_id=row["id"],
        username=row["username"],
        email=row["email"],
        role=roles,
        scope_slugs=sorted(scope),
        ai_access_enabled=ai_enabled,
    )


@router.post("/logout", response_model=LogoutResponse)
def logout(
    response: Response,
    info: sessions.SessionInfo = Depends(session_identity),
) -> LogoutResponse:
    """Revoke the current session, clear the cookie."""
    request_id = str(uuid.uuid4())
    revoked = sessions.revoke_session(info.id, revoked_by=info.operator_id)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    _audit_append(
        "auth_logout",
        actor=str(info.operator_id), target_id=str(info.operator_id),
        before={"session_id_prefix": info.id[:8]},
        after={"revoked": revoked},
        reason="self-logout",
        request_id=request_id,
    )
    return LogoutResponse(revoked=revoked)


@router.get("/sessions", response_model=SessionListResponse)
def list_sessions(
    info: sessions.SessionInfo = Depends(session_identity),
) -> SessionListResponse:
    """List the operator's CURRENTLY-ACTIVE sessions (the UI calls this
    a "live" panel — revoked + expired rows are filtered out).

    Audit + forensic-style "every session ever issued" listings belong
    on a separate endpoint (history) — this one feeds the Settings UI
    and needs to reflect only what's actually live, or the list grows
    unbounded across every sign-in.
    """
    now = datetime.now(timezone.utc)
    rows = sessions.list_sessions_for_operator(info.operator_id)
    out: list[SessionEntry] = []
    for r in rows:
        if r.revoked_at is not None:
            continue
        # `expires_at` is the absolute 24h cap. We don't filter on idle
        # here — idle-expired sessions are still recoverable until the
        # idle counter is checked on a real request, and surfacing them
        # in the panel lets the operator revoke them explicitly.
        if r.expires_at < now:
            continue
        out.append(SessionEntry(
            id=r.id[:12] + "…",
            issued_at=r.issued_at.isoformat(),
            last_active_at=r.last_active_at.isoformat(),
            expires_at=r.expires_at.isoformat(),
            auth_method=r.auth_method,
            ip_address=r.ip_address,
            user_agent=r.user_agent,
            is_current=(r.id == info.id),
        ))
    return SessionListResponse(sessions=out)


# ---------------------------------------------------------------------------
# Magic-link endpoints
# ---------------------------------------------------------------------------

class MagicLinkRequest(BaseModel):
    """super_admin requesting a magic link for another operator (or self)."""
    target_username: str = Field(min_length=1, max_length=64)
    purpose: str = Field(default="re-auth")               # 're-auth' | 'passkey-recovery'
    reason: str = Field(min_length=1, max_length=200)     # audit reason


class MagicLinkRequestResponse(BaseModel):
    """The plaintext token is returned exactly once. The caller (super_admin)
    is responsible for delivering it to the target operator via a secure
    channel (vault drop, encrypted message). The plaintext is NEVER persisted
    server-side — only its PBKDF2 hash."""
    token: str
    expires_at: str
    purpose: str
    target_operator_id: int
    target_username: str


class MagicLinkVerifyRequest(BaseModel):
    token: str = Field(min_length=16, max_length=512)


# Magic-link TTLs by purpose (per proposal §3.1).
#
# `password-reset` was tightened 2026-05-11 from 1 hour → 10 minutes. An
# AI-driven security platform makes the reset link a high-value target:
# anyone urgent enough to reset on the move has 10 minutes to click; any
# longer window is unjustifiable attack surface (mailbox compromise,
# stale-link exposure, shoulder-surfing). The body-text + email copy
# below repeats the new window so users aren't surprised.
MAGIC_LINK_TTL: dict[str, timedelta] = {
    "initial-setup":     timedelta(hours=24),    # bootstrap path
    "re-auth":           timedelta(minutes=15),
    "passkey-recovery":  timedelta(minutes=15),
    "password-reset":    timedelta(minutes=10),  # tightened 2026-05-11
}


# ---------------------------------------------------------------------------
# Forgot-password / reset — Pydantic shapes
# ---------------------------------------------------------------------------

class PasswordForgotRequest(BaseModel):
    """Self-service password reset request. Caller submits either a
    username OR an email; the server resolves either to the same operator
    row. Anti-enumeration: the response is identical regardless of
    whether the input matches an operator."""
    identifier: str = Field(min_length=1, max_length=255)


class PasswordForgotResponse(BaseModel):
    """Always returned with the same 202 + body shape regardless of
    whether the identifier matched. Anti-enumeration."""
    accepted: bool = True
    message: str = (
        "If an account matches that identifier, an email has been sent "
        "with reset instructions. The link expires in 10 minutes."
    )


class PasswordResetRequest(BaseModel):
    token: str = Field(min_length=16, max_length=512)
    new_password: str = Field(min_length=12, max_length=512)


class PasswordResetResponse(BaseModel):
    operator_id: int
    username: str


def _admin_session_super_admin(
    info: sessions.SessionInfo = Depends(session_identity),
) -> sessions.SessionInfo:
    """Dep that requires the caller's session-bound operator to hold the
    super_admin role. Used to gate magic-link issuance."""
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        roles = [r["role_name"] for r in reg.execute(
            "SELECT role_name FROM operator_roles WHERE operator_id = ?",
            (info.operator_id,),
        ).fetchall()]
    finally:
        reg.close()
    if "super_admin" not in roles:
        raise APIError("ISOLATION_VIOLATION",
                        "magic-link issuance requires super_admin role")
    return info


@router.post("/magic-link/request", response_model=MagicLinkRequestResponse)
def magic_link_request(
    body: MagicLinkRequest,
    request: Request,
    issuer: sessions.SessionInfo = Depends(_admin_session_super_admin),
) -> MagicLinkRequestResponse:
    """Issue a single-use magic link for `target_username`. Caller must be a
    super_admin. The plaintext token is returned ONCE in the response body —
    the caller is responsible for vaulting and delivering to the target.

    Purposes accepted:
      - 're-auth'           — short re-auth (15 min)
      - 'passkey-recovery'  — fallback when passkey is lost (15 min)

    'initial-setup' is reserved for the bootstrap script; the API surface
    refuses it to keep the human + automation paths disjoint.
    """
    request_id = str(uuid.uuid4())
    if body.purpose not in {"re-auth", "passkey-recovery"}:
        raise APIError("VALIDATION_FAILED",
                        f"purpose {body.purpose!r} not permitted via API "
                        "('initial-setup' is bootstrap-only)")
    ttl = MAGIC_LINK_TTL[body.purpose]

    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            target = reg.execute(
                "SELECT id, username, disabled_at FROM operators WHERE username = ?",
                (body.target_username,),
            ).fetchone()
            if target is None:
                raise APIError("AUTH_OPERATOR_NOT_FOUND")
            if target["disabled_at"] is not None:
                raise APIError("AUTH_OPERATOR_DISABLED")

            plaintext = secrets.token_urlsafe(32)        # 256-bit, ~43 chars
            token_hash = core_auth.hash_token(plaintext)
            now = datetime.now(timezone.utc)
            expires = now + ttl
            now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
            exp_iso = expires.strftime("%Y-%m-%dT%H:%M:%S.") + f"{expires.microsecond // 1000:03d}Z"
            reg.execute(
                """
                INSERT INTO magic_link_tokens
                    (token_hash, operator_id, issued_at, expires_at, purpose)
                VALUES (?, ?, ?, ?, ?)
                """,
                (token_hash, target["id"], now_iso, exp_iso, body.purpose),
            )
    finally:
        reg.close()

    _audit_append(
        "auth_magic_link_issue",
        actor=str(issuer.operator_id),
        target_id=str(target["id"]),
        before=None,
        after={"purpose": body.purpose,
               "target_username": target["username"],
               "expires_at": exp_iso},
        reason=body.reason,
        request_id=request_id,
    )

    return MagicLinkRequestResponse(
        token=plaintext,
        expires_at=exp_iso,
        purpose=body.purpose,
        target_operator_id=target["id"],
        target_username=target["username"],
    )


@router.post("/magic-link/verify", response_model=LoginCompleteResponse)
def magic_link_verify(
    body: MagicLinkVerifyRequest,
    request: Request,
    response: Response,
) -> LoginCompleteResponse:
    """Consume a magic link, issue a session.

    Single-use: on first successful verification the row's `used_at` is
    stamped; subsequent presentations of the same token return
    AUTH_MAGIC_LINK_USED.
    """
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    presented = body.token

    reg = connect(paths.registry_db_path())
    try:
        # No `with transaction()` — same discipline as password endpoints.
        # Single-row state changes are atomic on their own; we use
        # compare-and-swap on the `mark used` UPDATE to handle concurrent
        # presentations of the same token.
        now = datetime.now(timezone.utc)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
        rows = reg.execute(
            "SELECT id, token_hash, operator_id, expires_at, purpose, used_at "
            "FROM magic_link_tokens WHERE used_at IS NULL"
        ).fetchall()
        matched = None
        for row in rows:
            if core_auth.verify_token(presented, row["token_hash"]):
                matched = row
                break
        if matched is None:
            _audit_append(
                "auth_magic_link_verify",
                actor="unknown", target_id=None,
                before=None,
                after={"outcome": "no_match", "ip": ip},
                reason="presented token did not match any unused row",
                request_id=request_id,
            )
            raise APIError("AUTH_MAGIC_LINK_INVALID")
        # Expiry check
        try:
            exp_s = matched["expires_at"]
            exp_s = exp_s[:-1] + "+00:00" if exp_s.endswith("Z") else exp_s
            if datetime.fromisoformat(exp_s) < now:
                _audit_append(
                    "auth_magic_link_verify",
                    actor=str(matched["operator_id"]),
                    target_id=str(matched["operator_id"]),
                    before=None,
                    after={"outcome": "expired",
                           "expires_at": matched["expires_at"], "ip": ip},
                    reason="token expired before verify",
                    request_id=request_id,
                )
                raise APIError("AUTH_MAGIC_LINK_INVALID")
        except ValueError:
            raise APIError("AUTH_MAGIC_LINK_INVALID")
        # Compare-and-swap: only one caller can flip used_at IS NULL → used_at = now.
        cur = reg.execute(
            "UPDATE magic_link_tokens SET used_at = ? "
            "WHERE id = ? AND used_at IS NULL",
            (now_iso, matched["id"]),
        )
        reg.commit()
        if cur.rowcount == 0:
            # Lost the race against a concurrent verify of the same token.
            raise APIError("AUTH_MAGIC_LINK_USED")
        # Resolve operator
        op = reg.execute(
            """
            SELECT id, username, email, disabled_at,
                   ai_access_enabled, ai_access_expires_at
              FROM operators WHERE id = ?
            """,
            (matched["operator_id"],),
        ).fetchone()
        if op is None or op["disabled_at"] is not None:
            # Token already burned by the CAS above — operator can re-request.
            raise APIError("AUTH_OPERATOR_DISABLED")
        _reset_login_posture(reg, op["id"])
        role_rows = reg.execute(
            "SELECT role_name, scope_slugs FROM operator_roles "
            "WHERE operator_id = ?",
            (op["id"],),
        ).fetchall()
        roles_list: list[str] = sorted({r["role_name"] for r in role_rows})
        scope: set[str] = set()
        for r in role_rows:
            for s in json.loads(r["scope_slugs"]):
                scope.add(s)
    finally:
        reg.close()

    sid = sessions.issue_session(
        operator_id=op["id"],
        auth_method="magic-link",
        ip_address=ip,
        user_agent=user_agent,
    )

    ai_enabled = bool(op["ai_access_enabled"])
    if ai_enabled and op["ai_access_expires_at"]:
        try:
            exp_s = op["ai_access_expires_at"]
            exp_s = exp_s[:-1] + "+00:00" if exp_s.endswith("Z") else exp_s
            if datetime.fromisoformat(exp_s) < datetime.now(timezone.utc):
                ai_enabled = False
        except ValueError:
            ai_enabled = False

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=sid,
        max_age=int(sessions.ABSOLUTE_LIFETIME.total_seconds()),
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        path="/",
    )

    _audit_append(
        "auth_magic_link_verify",
        actor=str(op["id"]),
        target_id=str(op["id"]),
        before=None,
        after={"outcome": "success",
               "purpose": matched["purpose"],
               "session_issued": True,
               "ip": ip},
        reason=None,
        request_id=request_id,
    )

    return LoginCompleteResponse(
        operator_id=op["id"],
        username=op["username"],
        email=op["email"],
        role=roles_list,
        scope_slugs=sorted(scope),
        ai_access_enabled=ai_enabled,
    )


# ---------------------------------------------------------------------------
# Passkey (WebAuthn) endpoints
# ---------------------------------------------------------------------------
#
# Ceremony state — the challenge generated by /begin must round-trip through
# the browser and arrive verbatim at /complete. We carry the original
# challenge in an HttpOnly Fernet-encrypted cookie scoped to the passkey
# path. This is multi-worker-safe (key derived from MFA key, same on all
# workers), survives restarts, and never lands in the DB.
#
# user_handle — bound at registration, returned by the authenticator in the
# assertion. We pack the operator_id as 8-byte big-endian; on /complete we
# look up the credential_id (which the authenticator returns alongside) and
# resolve the operator from there. Both paths agree.

class PasskeyRegisterBeginRequest(BaseModel):
    label: Optional[str] = Field(default=None, max_length=80)


class PasskeyRegisterBeginResponse(BaseModel):
    publicKey: dict           # PublicKeyCredentialCreationOptions per WebAuthn spec


class PasskeyRegisterCompleteRequest(BaseModel):
    credential: dict          # navigator.credentials.create() raw JSON
    label: Optional[str] = Field(default=None, max_length=80)


class PasskeyRegisterCompleteResponse(BaseModel):
    credential_id: str        # base64url, no padding
    label: Optional[str]


class PasskeyAuthBeginResponse(BaseModel):
    publicKey: dict


class PasskeyCompleteRequest(BaseModel):
    credential: dict          # navigator.credentials.get() raw JSON


def _operator_id_to_user_handle(op_id: int) -> bytes:
    return op_id.to_bytes(8, "big")


def _stash_webauthn_challenge(
    response: Response,
    *,
    challenge: bytes,
    operator_id: Optional[int],
    intent: str,
) -> None:
    """Stash a WebAuthn challenge in an HttpOnly cookie for the next /complete."""
    f = _challenge_fernet()
    payload = json.dumps({
        "challenge": base64.urlsafe_b64encode(challenge).decode(),
        "operator_id": operator_id,
        "intent": intent,
        "iat": int(time.time()),
    }).encode()
    encrypted = f.encrypt(payload).decode()
    response.set_cookie(
        key=WEBAUTHN_CHALLENGE_COOKIE,
        value=encrypted,
        max_age=WEBAUTHN_CHALLENGE_TTL,
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        path="/api/v1/auth/passkey",
    )


def _read_webauthn_challenge(
    cookie_value: Optional[str],
    expected_intent: str,
) -> tuple[bytes, Optional[int]]:
    """Decrypt + parse the challenge cookie. Returns (challenge_bytes, op_id_or_None).

    Raises APIError(AUTH_PASSKEY_INVALID) for any failure: missing cookie,
    expired cookie, tampered cookie, intent mismatch.
    """
    if not cookie_value:
        raise APIError("AUTH_PASSKEY_INVALID", "no passkey challenge cookie")
    f = _challenge_fernet()
    try:
        raw = f.decrypt(cookie_value.encode(), ttl=WEBAUTHN_CHALLENGE_TTL)
    except InvalidToken:
        raise APIError("AUTH_PASSKEY_INVALID",
                        "passkey challenge expired or tampered")
    try:
        data = json.loads(raw.decode())
        if data.get("intent") != expected_intent:
            raise APIError("AUTH_PASSKEY_INVALID", "challenge intent mismatch")
        return base64.urlsafe_b64decode(data["challenge"]), data.get("operator_id")
    except (json.JSONDecodeError, KeyError, ValueError):
        raise APIError("AUTH_PASSKEY_INVALID", "challenge cookie malformed")


# ---------------------------------------------------------------------------
# Forgot-password / reset (self-service, email-driven)
# ---------------------------------------------------------------------------
#
# Two endpoints, both unauthenticated by design:
#
#   POST /api/v1/auth/password/forgot   → always 202; if identifier resolves
#                                         to an operator, generate a
#                                         password-reset magic link and email
#                                         it. Anti-enumeration: same response
#                                         + similar timing on miss vs hit.
#
#   POST /api/v1/auth/password/reset    → consume token, set new password,
#                                         clear lockout, revoke all sessions.
#
# Reuses `magic_link_tokens` with new `purpose = 'password-reset'` (1h TTL).
# Reset clears `failed_login_count` + `locked_until` so users who locked
# themselves out via password attempts can recover via this flow without an
# admin intervening (which is the whole point of self-service).

# Constant-time-ish artificial delay budget for the forgot endpoint, so a
# miss takes about as long as a hit (which has the email-send latency).
_FORGOT_HIT_DELAY_BUDGET_S = 0.30


@router.post("/password/forgot", response_model=PasswordForgotResponse)
def password_forgot(
    body: PasswordForgotRequest,
    request: Request,
) -> PasswordForgotResponse:
    """Email a password-reset link to the operator matching `identifier`
    (username or email). Returns 202 + identical body regardless of
    whether a match exists."""
    request_id = str(uuid.uuid4())
    started = time.monotonic()
    ip = request.client.host if request.client else None
    identifier_hash = hashlib.sha256(body.identifier.lower().encode()).hexdigest()[:16]

    reg = connect(paths.registry_db_path())
    try:
        ident = body.identifier.strip()
        # Match either username or email (case-insensitive on email).
        target = reg.execute(
            """
            SELECT id, username, email, disabled_at, password_hash, mfa_enabled
              FROM operators
             WHERE username = ? OR LOWER(email) = LOWER(?)
            """,
            (ident, ident),
        ).fetchone()

        # Self-service reset is refused (indistinguishably from a miss) for:
        #   - a never-activated account (no password AND no MFA — e.g. the
        #     factory super_admin before/after a host-side reset). There is
        #     no password to have forgotten; the only way in is its
        #     initial-setup magic link. Otherwise an anonymous caller could
        #     mint a reset token that, once redeemed, turns /password/begin
        #     into a no-MFA door to the account.
        #   - any account still on the factory placeholder email, which is
        #     undeliverable by design (and must not become deliverable by
        #     someone standing up an `athena.local` mail domain).
        ineligible = target is not None and (
            (not target["password_hash"] and not target["mfa_enabled"])
            or (target["email"] or "").lower()
                == bootstrap.FACTORY_SUPER_ADMIN_EMAIL.lower()
        )

        if target is None or target["disabled_at"] is not None or ineligible:
            _audit_append(
                "auth_password_reset_request",
                actor="unknown", target_id=None,
                before=None,
                after={"outcome": "not_eligible" if ineligible else "no_match",
                       "ip": ip,
                       "identifier_hash": identifier_hash},
                reason=("self-service password reset refused (account not "
                        "eligible: never activated, or placeholder email)"
                        if ineligible else
                        "self-service password reset (no matching operator)"),
                request_id=request_id,
            )
            # Pad timing so attackers can't enumerate by latency.
            elapsed = time.monotonic() - started
            if elapsed < _FORGOT_HIT_DELAY_BUDGET_S:
                time.sleep(_FORGOT_HIT_DELAY_BUDGET_S - elapsed)
            return PasswordForgotResponse()

        # Match found — issue token and email it.
        plaintext = secrets.token_urlsafe(32)
        token_hash = core_auth.hash_token(plaintext)
        now = datetime.now(timezone.utc)
        expires = now + MAGIC_LINK_TTL["password-reset"]
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
        exp_iso = expires.strftime("%Y-%m-%dT%H:%M:%S.") + f"{expires.microsecond // 1000:03d}Z"
        reg.execute(
            """
            INSERT INTO magic_link_tokens
                (token_hash, operator_id, issued_at, expires_at, purpose)
            VALUES (?, ?, ?, ?, ?)
            """,
            (token_hash, target["id"], now_iso, exp_iso, "password-reset"),
        )
        reg.commit()

        reset_url = (
            athena_origin().rstrip("/")
            + "/login/reset?token="
            + plaintext
        )
        subject = "Athena Console — password reset"
        body_text = (
            f"Hello {target['username']},\n\n"
            "A password reset was requested for your Athena Console account.\n\n"
            f"To set a new password, open this link within 10 minutes:\n\n"
            f"  {reset_url}\n\n"
            "If you did not request this, you can ignore this email — "
            "the link will expire on its own and your existing password "
            "stays unchanged.\n\n"
            "Athena Console\n"
        )
        sent = email_sender.send_email(
            to=target["email"],
            subject=subject,
            body_text=body_text,
        )

        _audit_append(
            "auth_password_reset_request",
            actor=str(target["id"]),
            target_id=str(target["id"]),
            before=None,
            after={"outcome": "issued",
                   "email_sent": sent,
                   "expires_at": exp_iso,
                   "ip": ip,
                   "identifier_hash": identifier_hash},
            reason="self-service password reset (matched operator)",
            request_id=request_id,
        )
    finally:
        reg.close()

    return PasswordForgotResponse()


@router.post("/password/reset", response_model=PasswordResetResponse)
def password_reset(
    body: PasswordResetRequest,
    request: Request,
) -> PasswordResetResponse:
    """Consume a password-reset token, set a new password, clear lockout,
    and revoke all active sessions for the operator (per OWASP — a
    forgotten password may indicate compromise)."""
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else None
    presented = body.token

    reg = connect(paths.registry_db_path())
    try:
        now = datetime.now(timezone.utc)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
        rows = reg.execute(
            "SELECT id, token_hash, operator_id, expires_at, purpose, used_at "
            "FROM magic_link_tokens WHERE used_at IS NULL"
        ).fetchall()
        matched = None
        for row in rows:
            if core_auth.verify_token(presented, row["token_hash"]):
                matched = row
                break
        if matched is None or matched["purpose"] != "password-reset":
            _audit_append(
                "auth_password_reset_complete",
                actor="unknown", target_id=None,
                before=None,
                after={"outcome": "no_match", "ip": ip},
                reason="presented reset token did not match",
                request_id=request_id,
            )
            raise APIError("AUTH_MAGIC_LINK_INVALID")

        # Expiry
        try:
            exp_s = matched["expires_at"]
            exp_s = exp_s[:-1] + "+00:00" if exp_s.endswith("Z") else exp_s
            if datetime.fromisoformat(exp_s) < now:
                _audit_append(
                    "auth_password_reset_complete",
                    actor=str(matched["operator_id"]),
                    target_id=str(matched["operator_id"]),
                    before=None,
                    after={"outcome": "expired", "ip": ip},
                    reason="reset token expired before completion",
                    request_id=request_id,
                )
                raise APIError("AUTH_MAGIC_LINK_INVALID")
        except ValueError:
            raise APIError("AUTH_MAGIC_LINK_INVALID")

        # Compare-and-swap: only one caller can consume the token.
        cur = reg.execute(
            "UPDATE magic_link_tokens SET used_at = ? "
            "WHERE id = ? AND used_at IS NULL",
            (now_iso, matched["id"]),
        )
        reg.commit()
        if cur.rowcount == 0:
            raise APIError("AUTH_MAGIC_LINK_USED")

        # Resolve operator (must still exist + be enabled).
        op = reg.execute(
            "SELECT id, username, email, disabled_at FROM operators WHERE id = ?",
            (matched["operator_id"],),
        ).fetchone()
        if op is None or op["disabled_at"] is not None:
            raise APIError("AUTH_OPERATOR_DISABLED")

        # Update password + clear lockout. Single UPDATE — atomic.
        new_hash = core_auth.hash_token(body.new_password)
        reg.execute(
            """
            UPDATE operators
               SET password_hash = ?,
                   password_changed_at = ?,
                   must_change_password = 0,
                   failed_login_count = 0,
                   locked_until = NULL
             WHERE id = ?
            """,
            (new_hash, now_iso, op["id"]),
        )
        reg.commit()

        # Revoke all active sessions for this operator (OWASP: forgotten
        # password may indicate compromise; assume all current sessions
        # are suspect). revoked_by is the operator-id FK — no human actor
        # for self-service resets, so leave it NULL. The audit row
        # ("auth_password_reset_complete" below) records the reason.
        sessions.revoke_all_for_operator(
            operator_id=op["id"],
            revoked_by=None,
            except_session_id=None,
        )

        _audit_append(
            "auth_password_reset_complete",
            actor=str(op["id"]),
            target_id=str(op["id"]),
            before=None,
            after={"outcome": "success", "ip": ip},
            reason="self-service password reset completed",
            request_id=request_id,
        )

        return PasswordResetResponse(
            operator_id=op["id"],
            username=op["username"],
        )
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# Session-authed password change (in-app "change password" path)
#
# Distinct from /password/reset (which consumes a magic-link token):
#   - /password/reset  → no session, requires emailed token, used for forgot-
#                        password and admin-issued resets.
#   - /password/change → cookie-authed, used by the operator themselves from
#                        Settings → Account, AND by the forced-setup flow
#                        when must_change_password=1.
#
# The current_password check is bypassed when must_change_password=1 (the
# initial-setup case where the operator has no password yet, or an admin
# forced rotation). In all OTHER cases current_password must verify.
# ---------------------------------------------------------------------------

class PasswordChangeRequest(BaseModel):
    current_password: Optional[str] = None
    new_password: str = Field(min_length=12, max_length=512)


class PasswordChangeResponse(BaseModel):
    operator_id: int
    must_change_password: bool = False  # always False after success


@router.post("/password/change", response_model=PasswordChangeResponse)
def password_change(
    body: PasswordChangeRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> PasswordChangeResponse:
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else "?"
    reg = connect(paths.registry_db_path())
    try:
        op = reg.execute(
            "SELECT id, username, password_hash, must_change_password "
            "FROM operators WHERE id = ?",
            (info.operator_id,),
        ).fetchone()
        if op is None:
            raise APIError("AUTH_SESSION_INVALID", "session resolves to deleted operator")

        must_change = bool(op["must_change_password"])
        # If the operator HAS a password and isn't in forced-change state,
        # they must prove they know it. If they're in forced-change state
        # (initial setup OR admin-rotation-pending) the current_password
        # check is bypassed — the session itself is the auth.
        if op["password_hash"] is not None and not must_change:
            if not body.current_password or not core_auth.verify_token(
                body.current_password, op["password_hash"],
            ):
                _audit_append(
                    "auth_password_change",
                    actor=str(op["id"]),
                    target_id=str(op["id"]),
                    before=None,
                    after={"outcome": "current_password_mismatch", "ip": ip},
                    reason="current password did not verify",
                    request_id=request_id,
                )
                raise APIError("AUTH_PASSWORD_INVALID")

        # Don't let the new password match the old (cheap protection
        # against a no-op rotation that satisfies must_change_password).
        if op["password_hash"] is not None and core_auth.verify_token(
            body.new_password, op["password_hash"],
        ):
            raise APIError(
                "VALIDATION_FAILED",
                "new password must differ from the current password",
            )

        new_hash = core_auth.hash_token(body.new_password)
        now = datetime.now(timezone.utc)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
        with transaction(reg):
            reg.execute(
                """
                UPDATE operators
                   SET password_hash = ?,
                       password_changed_at = ?,
                       must_change_password = 0,
                       failed_login_count = 0,
                       locked_until = NULL
                 WHERE id = ?
                """,
                (new_hash, now_iso, op["id"]),
            )
    finally:
        reg.close()

    # Revoke every OTHER session for this operator. The current session
    # stays alive so the operator doesn't get bounced back to /login mid-
    # setup. If you want a hard sign-out-everywhere you do that separately.
    sessions.revoke_all_for_operator(
        operator_id=info.operator_id,
        revoked_by=info.operator_id,
        # SessionInfo exposes the session id as `.id`, not `.session_id`.
        except_session_id=info.id,
    )

    _audit_append(
        "auth_password_change",
        actor=str(info.operator_id),
        target_id=str(info.operator_id),
        before=None,
        after={
            "outcome": "success",
            "was_forced_initial": must_change,
            "ip": ip,
        },
        reason=("initial password set" if must_change else "self-service password change"),
        request_id=request_id,
    )

    return PasswordChangeResponse(
        operator_id=info.operator_id,
        must_change_password=False,
    )


# ---------------------------------------------------------------------------
# Profile update (session-authed)
#
# Self-service update of display_name + email. display_name change is
# low-stakes (alters only the UI greeting). email change is sensitive
# because the new email receives future password-reset links — so it
# requires current_password proof. Both fields are independent; the
# operator can update either or both in one call.
# ---------------------------------------------------------------------------

class ProfileUpdateRequest(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=80)
    email: Optional[str] = Field(
        default=None, min_length=3, max_length=254,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
    )
    # Required only when changing email. Ignored otherwise.
    current_password: Optional[str] = None


class ProfileUpdateResponse(BaseModel):
    operator_id: int
    display_name: Optional[str] = None
    email: str


@router.patch("/me/profile", response_model=ProfileUpdateResponse)
def update_profile(
    body: ProfileUpdateRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> ProfileUpdateResponse:
    """Update display_name and/or email on the caller's own operator row.

    `display_name`: any string ≤80 chars, or null to clear. No password
    proof required — it's UI-only metadata.

    `email`: must look like an email (regex matches /admin/operators
    create). Requires `current_password` to verify the caller really
    holds this account. Reason: email is the destination for future
    password-reset links; an attacker with a stolen session could
    redirect resets without this gate.
    """
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else "?"
    if body.display_name is None and body.email is None:
        raise APIError(
            "VALIDATION_FAILED",
            "provide display_name and/or email to update",
        )

    reg = connect(paths.registry_db_path())
    try:
        op = reg.execute(
            "SELECT id, username, email, password_hash, display_name "
            "FROM operators WHERE id = ?",
            (info.operator_id,),
        ).fetchone()
        if op is None:
            raise APIError("AUTH_SESSION_INVALID", "session resolves to deleted operator")

        new_email = op["email"]
        new_display_name = op["display_name"]
        email_changed = False

        if body.email is not None and body.email != op["email"]:
            # Email change requires current_password proof.
            if not body.current_password or op["password_hash"] is None:
                raise APIError(
                    "AUTH_PASSWORD_INVALID",
                    "current_password required to change email",
                )
            if not core_auth.verify_token(body.current_password, op["password_hash"]):
                _audit_append(
                    "auth_profile_update",
                    actor=str(info.operator_id),
                    target_id=str(info.operator_id),
                    before=None,
                    after={"outcome": "email_change_password_mismatch", "ip": ip},
                    reason="current password did not verify for email change",
                    request_id=request_id,
                )
                raise APIError("AUTH_PASSWORD_INVALID")
            new_email = body.email
            email_changed = True

        if body.display_name is not None:
            # Empty string clears the display name; whitespace-only is
            # treated the same so a stray space doesn't lock in an
            # invisible value.
            trimmed = body.display_name.strip()
            new_display_name = trimmed if trimmed else None

        with transaction(reg):
            reg.execute(
                "UPDATE operators SET email = ?, display_name = ? "
                "WHERE id = ?",
                (new_email, new_display_name, info.operator_id),
            )
    finally:
        reg.close()

    _audit_append(
        "auth_profile_update",
        actor=str(info.operator_id),
        target_id=str(info.operator_id),
        before=None,
        after={
            "outcome": "success",
            "email_changed": email_changed,
            "display_name_changed": (
                body.display_name is not None
                and (body.display_name.strip() or None) != op["display_name"]
            ),
            "ip": ip,
        },
        reason="self-service profile update",
        request_id=request_id,
    )

    return ProfileUpdateResponse(
        operator_id=info.operator_id,
        display_name=new_display_name,
        email=new_email,
    )


# ---------------------------------------------------------------------------
# Backup-codes regenerate (session-authed)
# ---------------------------------------------------------------------------

class BackupCodesRegenerateRequest(BaseModel):
    # current_password proof prevents an attacker who has the session
    # cookie from silently rotating codes — a regen attempt without
    # password verification would mean the attacker can steal fresh
    # offline fallbacks without the operator's knowledge.
    current_password: str = Field(min_length=1)


class BackupCodesRegenerateResponse(BaseModel):
    backup_codes: list[str]


@router.post(
    "/backup-codes/regenerate",
    response_model=BackupCodesRegenerateResponse,
)
def backup_codes_regenerate(
    body: BackupCodesRegenerateRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> BackupCodesRegenerateResponse:
    """Rotate the operator's backup-code set without touching their TOTP
    secret. Old set is revoked; the fresh 8-code set is returned ONCE.
    Requires current_password proof.
    """
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else "?"
    reg = connect(paths.registry_db_path())
    try:
        op = reg.execute(
            "SELECT id, username, password_hash, mfa_enabled "
            "FROM operators WHERE id = ?",
            (info.operator_id,),
        ).fetchone()
        if op is None:
            raise APIError("AUTH_SESSION_INVALID", "session resolves to deleted operator")
        if op["password_hash"] is None or not core_auth.verify_token(
            body.current_password, op["password_hash"],
        ):
            _audit_append(
                "auth_backup_codes_regenerate",
                actor=str(info.operator_id),
                target_id=str(info.operator_id),
                before=None,
                after={"outcome": "password_mismatch", "ip": ip},
                reason="current password did not verify",
                request_id=request_id,
            )
            raise APIError("AUTH_PASSWORD_INVALID")
        if not op["mfa_enabled"]:
            # Regen-without-MFA-enrolled is meaningless — operator should
            # enroll TOTP first (which auto-issues a backup-code set).
            raise APIError(
                "AUTH_MFA_NOT_ENROLLED",
                "enroll TOTP before generating backup codes",
            )

        plaintext_codes = crypto.generate_backup_codes()
        codes_enc = crypto.encode_backup_code_set(plaintext_codes)
        now = datetime.now(timezone.utc)
        now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"

        with transaction(reg):
            reg.execute(
                "UPDATE backup_code_sets SET revoked_at = ?, revoke_reason = 'rotated' "
                "WHERE operator_id = ? AND revoked_at IS NULL",
                (now_iso, info.operator_id),
            )
            reg.execute(
                "INSERT INTO backup_code_sets (operator_id, codes_enc, generated_by) "
                "VALUES (?, ?, ?)",
                (info.operator_id, codes_enc, info.operator_id),
            )
    finally:
        reg.close()

    _audit_append(
        "auth_backup_codes_regenerate",
        actor=str(info.operator_id),
        target_id=str(info.operator_id),
        before=None,
        after={
            "outcome": "success",
            "code_count": len(plaintext_codes),
            "ip": ip,
        },
        reason="self-service backup-code rotation",
        request_id=request_id,
    )
    return BackupCodesRegenerateResponse(backup_codes=plaintext_codes)


# ---------------------------------------------------------------------------
# TOTP enrollment (session-authed)
#
# Two-step ceremony so an abandoned enrollment never touches the operator's
# real `mfa_secret_enc`:
#   begin    → generate secret, return secret + otpauth URI + a stateless
#              Fernet-wrapped `pending_token` carrying (operator_id, secret,
#              issued_at). TTL 10 minutes (same posture as auth challenges).
#   complete → operator submits TOTP code + pending_token. We unwrap, verify
#              the code against the pending secret, then commit it to
#              `operators.mfa_secret_enc`, set `mfa_enabled = 1`, generate
#              backup codes, return plaintext codes ONCE.
#
# Used by the forced-setup wizard on first login AND by the future
# "Reset TOTP" affordance on Settings → Account.
# ---------------------------------------------------------------------------

TOTP_ENROLL_TTL_SECONDS = 600    # 10 minutes


class TotpEnrollBeginResponse(BaseModel):
    pending_token: str       # opaque, pass back at /complete
    secret_b32: str          # for manual entry into authenticator
    otpauth_uri: str         # for QR rendering


class TotpEnrollCompleteRequest(BaseModel):
    pending_token: str
    totp_code: str = Field(min_length=6, max_length=8)


class TotpEnrollCompleteResponse(BaseModel):
    operator_id: int
    backup_codes: list[str]  # plaintext, shown ONCE — operator stores offline


def _totp_pending_fernet() -> Fernet:
    """Derived from the MFA key + a different domain separator so pending
    enrollment tokens don't collide with login challenge tokens (see
    `_mfa_subkey_fernet`)."""
    return _mfa_subkey_fernet(b"totp-enroll-v1")


def _issue_totp_pending_token(operator_id: int, secret_b32: str) -> str:
    f = _totp_pending_fernet()
    payload = json.dumps({
        "op": operator_id,
        "secret": secret_b32,
        "iat": int(time.time()),
    }).encode()
    return f.encrypt(payload).decode()


def _verify_totp_pending_token(token: str, operator_id: int) -> str:
    """Return the secret_b32; raise on mismatch / expiry."""
    f = _totp_pending_fernet()
    try:
        raw = f.decrypt(token.encode(), ttl=TOTP_ENROLL_TTL_SECONDS)
    except InvalidToken:
        raise APIError("AUTH_TOTP_INVALID", "enrollment token invalid or expired")
    try:
        data = json.loads(raw.decode())
        if int(data["op"]) != operator_id:
            # Wrong operator binding — refuse silently (don't tell attacker
            # which operator the token was bound to).
            raise APIError("AUTH_TOTP_INVALID")
        return str(data["secret"])
    except (json.JSONDecodeError, KeyError, ValueError):
        raise APIError("AUTH_TOTP_INVALID", "enrollment token malformed")


@router.post("/totp/enroll/begin", response_model=TotpEnrollBeginResponse)
def totp_enroll_begin(
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> TotpEnrollBeginResponse:
    """Generate a fresh TOTP secret + pending token. The secret is NOT
    persisted until /complete succeeds — abandoning the flow leaves the
    operator's existing MFA state untouched."""
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else "?"
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        op = reg.execute(
            "SELECT id, username, password_hash FROM operators WHERE id = ?",
            (info.operator_id,),
        ).fetchone()
    finally:
        reg.close()
    if op is None:
        raise APIError("AUTH_SESSION_INVALID", "session resolves to deleted operator")
    if op["password_hash"] is None:
        # Password first. TOTP-then-lost-session on a password-less account
        # has no way back in except a destructive reset (the magic link is
        # spent, /password/begin has nothing to verify, forgot-password
        # refuses never-activated accounts). Password-then-lost-session
        # resumes cleanly via /password/begin's setup-bound session.
        raise APIError("AUTH_PASSWORD_REQUIRED_FIRST")

    secret_b32 = pyotp.random_base32()
    pending_token = _issue_totp_pending_token(info.operator_id, secret_b32)
    otpauth_uri = pyotp.TOTP(secret_b32).provisioning_uri(
        name=op["username"], issuer_name=ATHENA_RP_NAME,
    )
    _audit_append(
        "auth_totp_enroll_begin",
        actor=str(info.operator_id),
        target_id=str(info.operator_id),
        before=None,
        after={"ip": ip},
        reason="totp enrollment initiated",
        request_id=request_id,
    )
    return TotpEnrollBeginResponse(
        pending_token=pending_token,
        secret_b32=secret_b32,
        otpauth_uri=otpauth_uri,
    )


@router.post("/totp/enroll/complete", response_model=TotpEnrollCompleteResponse)
def totp_enroll_complete(
    body: TotpEnrollCompleteRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> TotpEnrollCompleteResponse:
    """Verify the TOTP code against the pending secret. On success: commit
    the secret as `operators.mfa_secret_enc`, set `mfa_enabled=1`, generate
    + return a fresh backup-code set."""
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else "?"
    secret_b32 = _verify_totp_pending_token(body.pending_token, info.operator_id)
    totp = pyotp.TOTP(secret_b32)
    if not totp.verify(body.totp_code, valid_window=1):
        _audit_append(
            "auth_totp_enroll_complete",
            actor=str(info.operator_id),
            target_id=str(info.operator_id),
            before=None,
            after={"outcome": "code_mismatch", "ip": ip},
            reason="enrollment TOTP code did not verify",
            request_id=request_id,
        )
        raise APIError("AUTH_TOTP_INVALID")

    # Generate backup codes BEFORE persisting the secret so partial state
    # never leaves an operator with TOTP enabled but no backup codes.
    plaintext_codes = crypto.generate_backup_codes()
    codes_enc = crypto.encode_backup_code_set(plaintext_codes)
    secret_enc = crypto.encrypt_at_rest(secret_b32.encode())
    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"

    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            # Revoke any previously-active set (e.g. operator is rotating
            # their TOTP). Then insert the fresh active set.
            reg.execute(
                "UPDATE backup_code_sets SET revoked_at = ?, revoke_reason = 'rotated' "
                "WHERE operator_id = ? AND revoked_at IS NULL",
                (now_iso, info.operator_id),
            )
            reg.execute(
                "INSERT INTO backup_code_sets (operator_id, codes_enc, generated_by) "
                "VALUES (?, ?, ?)",
                (info.operator_id, codes_enc, info.operator_id),
            )
            reg.execute(
                "UPDATE operators SET mfa_enabled = 1, mfa_secret_enc = ?, "
                "last_mfa_verified_at = ? WHERE id = ?",
                (secret_enc, now_iso, info.operator_id),
            )
    finally:
        reg.close()

    _audit_append(
        "auth_totp_enroll_complete",
        actor=str(info.operator_id),
        target_id=str(info.operator_id),
        before=None,
        after={"outcome": "success", "ip": ip, "backup_code_count": len(plaintext_codes)},
        reason="totp enrolled + backup codes issued",
        request_id=request_id,
    )
    return TotpEnrollCompleteResponse(
        operator_id=info.operator_id,
        backup_codes=plaintext_codes,
    )


@router.post("/passkey/register/begin", response_model=PasskeyRegisterBeginResponse)
def passkey_register_begin(
    body: PasskeyRegisterBeginRequest,
    response: Response,
    info: sessions.SessionInfo = Depends(session_identity),
) -> PasskeyRegisterBeginResponse:
    """Generate registration options for binding a new passkey to the
    current operator's account. Excludes already-registered credentials so
    the same authenticator can't double-register."""
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        op = reg.execute(
            "SELECT username, email FROM operators WHERE id = ?",
            (info.operator_id,),
        ).fetchone()
        existing = reg.execute(
            "SELECT credential_id FROM webauthn_credentials "
            "WHERE operator_id = ? AND revoked_at IS NULL",
            (info.operator_id,),
        ).fetchall()
    finally:
        reg.close()
    if op is None:
        raise APIError("AUTH_OPERATOR_NOT_FOUND")

    exclude_creds = [
        PublicKeyCredentialDescriptor(id=bytes(r["credential_id"]))
        for r in existing
    ]

    opts = generate_registration_options(
        rp_id=athena_rp_id(),
        rp_name=ATHENA_RP_NAME,
        user_id=_operator_id_to_user_handle(info.operator_id),
        user_name=op["username"],
        user_display_name=op["email"],
        exclude_credentials=exclude_creds,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    _stash_webauthn_challenge(
        response,
        challenge=opts.challenge,
        operator_id=info.operator_id,
        intent="register",
    )

    return PasskeyRegisterBeginResponse(publicKey=json.loads(options_to_json(opts)))


@router.post(
    "/passkey/register/complete",
    response_model=PasskeyRegisterCompleteResponse,
)
def passkey_register_complete(
    body: PasskeyRegisterCompleteRequest,
    response: Response,
    athena_webauthn_challenge: Optional[str] = Cookie(default=None),
    info: sessions.SessionInfo = Depends(session_identity),
) -> PasskeyRegisterCompleteResponse:
    """Verify the registration attestation and store the credential."""
    request_id = str(uuid.uuid4())
    challenge_bytes, op_id_in_cookie = _read_webauthn_challenge(
        athena_webauthn_challenge, expected_intent="register",
    )
    if op_id_in_cookie != info.operator_id:
        raise APIError("AUTH_PASSKEY_INVALID",
                        "challenge bound to different operator than current session")

    try:
        verification = verify_registration_response(
            credential=body.credential,
            expected_challenge=challenge_bytes,
            expected_origin=athena_origin(),
            expected_rp_id=athena_rp_id(),
        )
    except Exception as exc:
        _audit_append(
            "auth_passkey_register",
            actor=str(info.operator_id), target_id=str(info.operator_id),
            before=None,
            after={"outcome": "verification_failed", "error": str(exc)[:200]},
            reason="WebAuthn registration verification failed",
            request_id=request_id,
        )
        raise APIError("AUTH_PASSKEY_INVALID")

    transports_json: Optional[str] = None
    if isinstance(body.credential.get("response"), dict):
        t = body.credential["response"].get("transports")
        if isinstance(t, list):
            transports_json = json.dumps(t)

    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                """
                INSERT INTO webauthn_credentials
                    (operator_id, credential_id, public_key, sign_count,
                     label, transports, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (info.operator_id,
                 verification.credential_id,
                 verification.credential_public_key,
                 verification.sign_count,
                 body.label,
                 transports_json,
                 _now_iso()),
            )
    finally:
        reg.close()

    response.delete_cookie(WEBAUTHN_CHALLENGE_COOKIE, path="/api/v1/auth/passkey")

    cred_b64 = base64.urlsafe_b64encode(verification.credential_id).decode().rstrip("=")
    _audit_append(
        "auth_passkey_register",
        actor=str(info.operator_id), target_id=str(info.operator_id),
        before=None,
        after={"outcome": "success",
               "credential_id_prefix": cred_b64[:12],
               "label": body.label},
        reason=None,
        request_id=request_id,
    )

    return PasskeyRegisterCompleteResponse(credential_id=cred_b64, label=body.label)


@router.post("/passkey/begin", response_model=PasskeyAuthBeginResponse)
def passkey_begin(response: Response) -> PasskeyAuthBeginResponse:
    """Generate authentication options. No allow-list — relies on
    discoverable credentials so the user picks from their device's passkey
    chooser. The user_handle in the assertion identifies the operator on
    /complete."""
    opts = generate_authentication_options(
        rp_id=athena_rp_id(),
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    _stash_webauthn_challenge(
        response,
        challenge=opts.challenge,
        operator_id=None,
        intent="auth",
    )
    return PasskeyAuthBeginResponse(publicKey=json.loads(options_to_json(opts)))


@router.post("/passkey/complete", response_model=LoginCompleteResponse)
def passkey_complete(
    body: PasskeyCompleteRequest,
    request: Request,
    response: Response,
    athena_webauthn_challenge: Optional[str] = Cookie(default=None),
) -> LoginCompleteResponse:
    """Verify the authentication assertion and issue a session.

    Operator is identified by the credential_id in the assertion (looked up
    in webauthn_credentials). Sign-count is bumped in DB on success;
    sign-count regression is treated as a cloned-authenticator signal and
    fails the assertion (the webauthn lib enforces this).
    """
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    challenge_bytes, _ = _read_webauthn_challenge(
        athena_webauthn_challenge, expected_intent="auth",
    )

    cred_b64 = body.credential.get("rawId") or body.credential.get("id")
    if not cred_b64:
        raise APIError("AUTH_PASSKEY_INVALID", "credential ID missing from assertion")
    try:
        cred_id_bytes = base64.urlsafe_b64decode(cred_b64 + "=" * (-len(cred_b64) % 4))
    except Exception:
        raise APIError("AUTH_PASSKEY_INVALID", "credential ID malformed")

    reg = connect(paths.registry_db_path())
    try:
        cred_row = reg.execute(
            "SELECT id, operator_id, public_key, sign_count, revoked_at "
            "FROM webauthn_credentials WHERE credential_id = ?",
            (cred_id_bytes,),
        ).fetchone()
        if cred_row is None or cred_row["revoked_at"] is not None:
            _audit_append(
                "auth_passkey_assert",
                actor="unknown", target_id=None,
                before=None,
                after={"outcome": "unknown_or_revoked_credential", "ip": ip},
                reason="presented credential_id not in webauthn_credentials",
                request_id=request_id,
            )
            raise APIError("AUTH_PASSKEY_INVALID")

        try:
            verification = verify_authentication_response(
                credential=body.credential,
                expected_challenge=challenge_bytes,
                expected_origin=athena_origin(),
                expected_rp_id=athena_rp_id(),
                credential_public_key=bytes(cred_row["public_key"]),
                credential_current_sign_count=cred_row["sign_count"],
            )
        except Exception as exc:
            _audit_append(
                "auth_passkey_assert",
                actor=str(cred_row["operator_id"]),
                target_id=str(cred_row["operator_id"]),
                before=None,
                after={"outcome": "verification_failed",
                       "error": str(exc)[:200], "ip": ip},
                reason="WebAuthn assertion verification failed",
                request_id=request_id,
            )
            raise APIError("AUTH_PASSKEY_INVALID")

        # No `with transaction()` — same discipline as password endpoints.
        reg.execute(
            "UPDATE webauthn_credentials "
            "SET sign_count = ?, last_used_at = ? WHERE id = ?",
            (verification.new_sign_count, _now_iso(), cred_row["id"]),
        )
        reg.commit()
        op = reg.execute(
            """
            SELECT id, username, email, disabled_at,
                   ai_access_enabled, ai_access_expires_at
              FROM operators WHERE id = ?
            """,
            (cred_row["operator_id"],),
        ).fetchone()
        if op is None or op["disabled_at"] is not None:
            raise APIError("AUTH_OPERATOR_DISABLED")
        _reset_login_posture(reg, op["id"])
        role_rows = reg.execute(
            "SELECT role_name, scope_slugs FROM operator_roles "
            "WHERE operator_id = ?",
            (op["id"],),
        ).fetchall()
        roles_list = sorted({r["role_name"] for r in role_rows})
        scope: set[str] = set()
        for r in role_rows:
            for s in json.loads(r["scope_slugs"]):
                scope.add(s)
    finally:
        reg.close()

    sid = sessions.issue_session(
        operator_id=op["id"],
        auth_method="passkey",
        ip_address=ip,
        user_agent=user_agent,
    )

    ai_enabled = bool(op["ai_access_enabled"])
    if ai_enabled and op["ai_access_expires_at"]:
        try:
            exp_s = op["ai_access_expires_at"]
            exp_s = exp_s[:-1] + "+00:00" if exp_s.endswith("Z") else exp_s
            if datetime.fromisoformat(exp_s) < datetime.now(timezone.utc):
                ai_enabled = False
        except ValueError:
            ai_enabled = False

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=sid,
        max_age=int(sessions.ABSOLUTE_LIFETIME.total_seconds()),
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        path="/",
    )
    response.delete_cookie(WEBAUTHN_CHALLENGE_COOKIE, path="/api/v1/auth/passkey")

    _audit_append(
        "auth_passkey_assert",
        actor=str(op["id"]), target_id=str(op["id"]),
        before=None,
        after={"outcome": "success",
               "credential_id_prefix": (cred_b64 if isinstance(cred_b64, str) else cred_b64.decode())[:12],
               "session_issued": True, "ip": ip},
        reason=None,
        request_id=request_id,
    )

    return LoginCompleteResponse(
        operator_id=op["id"],
        username=op["username"],
        email=op["email"],
        role=roles_list,
        scope_slugs=sorted(scope),
        ai_access_enabled=ai_enabled,
    )


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

class RevokeOthersResponse(BaseModel):
    revoked_count: int


@router.post("/sessions/revoke-others", response_model=RevokeOthersResponse)
def revoke_other_sessions(
    info: sessions.SessionInfo = Depends(session_identity),
) -> RevokeOthersResponse:
    """Revoke every active session for this operator EXCEPT the caller's
    current one. Used by the "Sign out everywhere else" affordance on
    Settings → Account.

    To revoke the current session too, the caller follows up with the
    normal /auth/logout call (or just lets the cookie expire).
    """
    request_id = str(uuid.uuid4())
    count = sessions.revoke_all_for_operator(
        operator_id=info.operator_id,
        revoked_by=info.operator_id,
        except_session_id=info.id,
    )
    _audit_append(
        "auth_session_revoke_others",
        actor=str(info.operator_id),
        target_id=str(info.operator_id),
        before=None,
        after={"revoked_count": count, "kept_session_prefix": info.id[:8]},
        reason="operator signed out every other session",
        request_id=request_id,
    )
    return RevokeOthersResponse(revoked_count=count)


@router.delete("/sessions/{session_id_prefix}")
def revoke_session(
    session_id_prefix: str,
    info: sessions.SessionInfo = Depends(session_identity),
) -> LogoutResponse:
    """Revoke a session by its 12-char prefix (matches what /sessions returns).

    Operators can only revoke their own sessions. Revoking the prefix-matching
    session of another operator returns 404 — the prefix space is per-operator
    so an attacker can't enumerate other operators' sessions.
    """
    request_id = str(uuid.uuid4())
    own = [r for r in sessions.list_sessions_for_operator(info.operator_id)
           if r.id.startswith(session_id_prefix.rstrip("…"))]
    if not own:
        raise APIError("NOT_FOUND", f"no session with prefix {session_id_prefix!r}")
    if len(own) > 1:
        raise APIError("CONFLICT", "ambiguous session prefix; provide more chars")
    target = own[0]
    revoked = sessions.revoke_session(target.id, revoked_by=info.operator_id)
    _audit_append(
        "auth_session_revoke",
        actor=str(info.operator_id), target_id=str(info.operator_id),
        before={"session_id_prefix": target.id[:8],
                "issued_at": target.issued_at.isoformat()},
        after={"revoked": revoked},
        reason="manual revoke from settings",
        request_id=request_id,
    )
    return LogoutResponse(revoked=revoked)
