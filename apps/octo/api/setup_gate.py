"""Setup-gate middleware.

When a session resolves to an operator whose `must_change_password=1`
OR `mfa_enabled=0`, only a small allowlist of endpoints is reachable:

  - /healthz                                        — meta
  - /api/v1/auth/me                                 — read identity
  - /api/v1/auth/logout                             — bail out
  - /api/v1/auth/password/change                    — set initial password
  - /api/v1/auth/totp/enroll/begin                  — start TOTP enroll
  - /api/v1/auth/totp/enroll/complete               — finish TOTP enroll
  - /api/v1/auth/sessions and /sessions/{id} DELETE — session housekeeping
  - /api/v1/dev/login                               — dev auto-login

Every other admin/data endpoint returns 403 SETUP_REQUIRED. This is the
backend half of the forced-setup flow — the SPA's redirect-to-setup is
the UX, this is the security floor.

NOTE: rate-limit middleware should sit BEFORE this so spammers don't
exploit the cheap check. exception_handlers stay outermost.
"""
from __future__ import annotations

import logging
import sqlite3

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from apps.octo import paths
from apps.octo.db import connect

logger = logging.getLogger(__name__)

# Paths reachable mid-setup. Exact-match OR prefix-match (trailing /).
_ALLOWLIST_EXACT: set[str] = {
    "/healthz",
    "/readyz",
    "/api/v1/auth/me",
    "/api/v1/auth/me/profile",
    "/api/v1/auth/logout",
    "/api/v1/auth/password/change",
    "/api/v1/auth/totp/enroll/begin",
    "/api/v1/auth/totp/enroll/complete",
    "/api/v1/auth/backup-codes/regenerate",
    "/api/v1/auth/sessions",
    "/api/v1/auth/sessions/revoke-others",
}
# Paths whose prefix is allowed (DELETE /api/v1/auth/sessions/{id}, dev/login)
_ALLOWLIST_PREFIX: tuple[str, ...] = (
    "/api/v1/auth/sessions/",
    "/api/v1/dev/",
)
# Paths that bypass session resolution entirely (login flow itself,
# unauthenticated endpoints). Anything starting with these is just passed
# through — the route's own auth dep decides.
_BYPASS_PREFIX: tuple[str, ...] = (
    "/api/v1/auth/password/begin",
    "/api/v1/auth/password/totp",
    "/api/v1/auth/password/forgot",
    "/api/v1/auth/password/reset",
    "/api/v1/auth/magic-link/",
    # Passkey SIGN-IN only. The bare "/passkey/" prefix also matched the
    # session-authed /passkey/register/* routes, letting a setup-confined
    # session plant a passkey before finishing setup (a persistence
    # primitive for anyone briefly holding a setup link).
    "/api/v1/auth/passkey/begin",
    "/api/v1/auth/passkey/complete",
)


def _path_allowed_mid_setup(path: str) -> bool:
    if path in _ALLOWLIST_EXACT:
        return True
    return any(path.startswith(p) for p in _ALLOWLIST_PREFIX)


def _path_bypass(path: str) -> bool:
    return any(path.startswith(p) for p in _BYPASS_PREFIX)


def _operator_needs_setup(operator_id: int) -> bool:
    """Read must_change_password + mfa_enabled. Returns True if EITHER
    flag indicates setup is incomplete."""
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        row = reg.execute(
            "SELECT must_change_password, mfa_enabled "
            "FROM operators WHERE id = ?",
            (operator_id,),
        ).fetchone()
    finally:
        reg.close()
    if row is None:
        return False
    return bool(row["must_change_password"]) or not bool(row["mfa_enabled"])


def install_setup_gate_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def setup_gate(request: Request, call_next):
        path = request.url.path
        # Bypass paths and explicitly-allowed paths don't need a setup check.
        if _path_bypass(path) or _path_allowed_mid_setup(path):
            return await call_next(request)

        # We only gate on cookie-authed sessions. Bearer tokens (admin,
        # buoy, service) aren't subject to operator-side setup flows.
        sid = request.cookies.get("athena_session")
        if not sid:
            return await call_next(request)

        # Resolve operator from session. Cheap path: a SQLite lookup by id.
        from apps.octo.auth import sessions
        info = sessions.validate_session(sid)
        if info is None:
            return await call_next(request)

        if _operator_needs_setup(info.operator_id):
            return JSONResponse(
                status_code=403,
                content={
                    "code": "SETUP_REQUIRED",
                    "message": (
                        "Account setup is incomplete. Finish setting a "
                        "password and enrolling MFA before continuing."
                    ),
                    "request_id": "setup-gate",
                },
            )
        return await call_next(request)
