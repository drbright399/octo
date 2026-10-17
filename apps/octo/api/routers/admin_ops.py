"""Admin-tier operator management.

Endpoints:

    GET    /api/v1/admin/operators              list operators in this bundle
    POST   /api/v1/admin/operators              create operator (pending state)
    POST   /api/v1/admin/operators/{id}/disable disable operator
    POST   /api/v1/admin/operators/{id}/enable  re-enable a disabled operator
    POST   /api/v1/admin/operators/{id}/role    grant/revoke a role

Tier rules (per the one-bundle-per-MSP design + the role matrix):

  - admin can create + disable + grant roles ≤ admin
    (analyst, viewer, admin — but NOT super_admin)
  - super_admin can do everything admin can plus:
        * create/disable super_admin operators
        * grant the super_admin role
        * cannot disable themselves
        * cannot disable the LAST super_admin (refuses with VALIDATION_FAILED)

  - Created operators land in the same "pending activation" shape used by
    `bootstrap.stage_pending_super_admin` — the caller (admin/super_admin)
    follows up by issuing a magic link via `/api/v1/auth/magic-link/request`.
    No password is set at creation time. This keeps the "AI/admin never
    sees the user's plaintext password" invariant.

  - Viewers are CLIENT users. A viewer role row (invite, grant, scope edit)
    takes only an explicit list of ACTIVE tenants, none still carrying its
    auto-create placeholder name or slug (which names a vendor); '*' and []
    are refused (422), and so is revoking the higher role of an operator
    whose remaining viewer row says '*' or nothing. analyst+ keep the ['*']
    default.

  - All actions are audit-logged with the caller's identity.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.auth import audit, operators as ops_mod, sessions
from apps.octo.auth import core as core_auth
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import (
    ROLE_TIER,
    get_operator_roles,
    operator_max_tier,
    session_admin_plus,
)
from apps.octo.auth.config import athena_origin
from apps.octo.db import connect, transaction


router = APIRouter(prefix="/admin/operators", tags=["admin-operators"])


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class OperatorListEntry(BaseModel):
    """One row in the operator listing. Excludes any credential material."""
    id: int
    username: str
    email: str
    roles: list[str]
    scope_slugs: list[str]
    mfa_enabled: bool
    must_change_password: bool
    disabled_at: Optional[str]
    last_login_at: Optional[str]
    created_at: str
    # Slice 7f — feature flags surfaced for the Settings → Operators UI.
    # is_factory is read-only; l2_llm_granted toggles via the dedicated
    # /admin/operators/{id}/llm-grant endpoint with the tier rule.
    is_factory: bool = False
    l2_llm_granted: bool = False


class OperatorListResponse(BaseModel):
    operators: list[OperatorListEntry]


class CreateOperatorBody(BaseModel):
    username: str = Field(min_length=1, max_length=64,
                            pattern=r"^[A-Za-z0-9._-]+$")
    email: str = Field(min_length=3, max_length=254,
                         pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    role: str = Field(description="One of: super_admin, admin, analyst, viewer")
    scope_slugs: list[str] = Field(default_factory=lambda: ["*"])
    reason: Optional[str] = None


class CreateOperatorResponse(BaseModel):
    operator_id: int
    username: str
    email: str
    role: str
    state: str
    activation_path: str
    magic_link_url: str
    magic_link_expires_at: str


class GrantRoleBody(BaseModel):
    role: str
    scope_slugs: list[str] = Field(default_factory=lambda: ["*"])
    reason: Optional[str] = None


class RevokeRoleBody(BaseModel):
    role: str
    reason: Optional[str] = None


class DisableOperatorBody(BaseModel):
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _audit(action: str, *, actor: int, target_id: int, after: dict,
           reason: str, request_id: str) -> None:
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=str(actor),
            actor_kind="human",
            action=action,
            target_kind="operator",
            target_id=str(target_id),
            client_slug="global",
            after_state=after,
            reason=reason,
            request_id=request_id,
        ))
    finally:
        g_audit.close()


def _enforce_tier_rule(caller_id: int, target_role: str) -> None:
    """Raise ISOLATION_VIOLATION if caller cannot grant/manage `target_role`.

    Rule: caller's max tier must be ≥ target role's tier. So:
      - admin (tier 3) can manage analyst (2), viewer (1), admin (3). NOT super_admin (4).
      - super_admin (tier 4) can manage anything.
    """
    if target_role not in ROLE_TIER:
        raise APIError("VALIDATION_FAILED",
                        f"unknown role {target_role!r}")
    caller_tier = operator_max_tier(caller_id)
    target_tier = ROLE_TIER[target_role]
    if caller_tier < target_tier:
        raise APIError(
            "ISOLATION_VIOLATION",
            f"caller tier insufficient to manage role {target_role!r} "
            f"(need ≥ tier {target_tier}, have {caller_tier})",
        )


def _count_active_super_admins() -> int:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return reg.execute(
            "SELECT COUNT(*) FROM operator_roles r "
            "JOIN operators o ON o.id = r.operator_id "
            "WHERE r.role_name = 'super_admin' AND o.disabled_at IS NULL",
        ).fetchone()[0]
    finally:
        reg.close()


def _operator_is_super_admin(op_id: int) -> bool:
    return "super_admin" in get_operator_roles(op_id)


_VIEWER_SCOPE_RULE = (
    "A viewer is a client user: scope them to the specific tenant(s) they "
    "belong to. '*' (every tenant) and an empty scope are refused for viewers."
)


# More than this in one viewer's scope is not one client's user.
MAX_VIEWER_TENANTS = 200


def _listed(slugs: list[str]) -> str:
    return ", ".join(repr(s[:64]) for s in slugs[:5]) + (" …" if len(slugs) > 5 else "")


def _viewer_scope(scope_slugs: list[str]) -> list[str]:
    """The scope a viewer row may hold: a non-empty list of concrete slugs of
    ACTIVE tenants none of which still carries its auto-create placeholder
    (a name or slug naming the vendor that created it — a client user must
    never learn which vendors the MSP runs). Deduplicated and sorted;
    VALIDATION_FAILED (422) otherwise. Viewers are CLIENT users: the invite
    default ['*'] would show one customer every tenant's data."""
    from apps.octo.instances.tenant_autocreate import placeholder_parts

    wanted = sorted(set(scope_slugs))
    if not wanted or "*" in wanted:
        raise APIError("VALIDATION_FAILED", _VIEWER_SCOPE_RULE)
    if len(wanted) > MAX_VIEWER_TENANTS:
        raise APIError(
            "VALIDATION_FAILED", f"a viewer can be scoped to at most {MAX_VIEWER_TENANTS} tenants",
        )
    malformed = [s for s in wanted if not paths.SLUG_RE.match(s)]
    if malformed:
        raise APIError("VALIDATION_FAILED", f"not a tenant slug: {_listed(malformed)}")
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        marks = ",".join("?" * len(wanted))
        status = {
            r["slug"]: r["status"]
            for r in reg.execute(
                f"SELECT slug, status FROM clients WHERE slug IN ({marks})", wanted,
            ).fetchall()
        }
        placeholders = placeholder_parts(reg, wanted)
    finally:
        reg.close()
    unknown = [s for s in wanted if s not in status]
    if unknown:
        raise APIError("VALIDATION_FAILED", f"no such tenant: {_listed(unknown)}")
    inactive = [s for s in wanted if status[s] != "active"]
    if inactive:
        raise APIError(
            "VALIDATION_FAILED",
            f"a viewer can only be scoped to ACTIVE tenants — not active: {_listed(inactive)}",
        )
    named = [s for s in wanted if "name" in placeholders.get(s, ())]
    if named:
        raise APIError(
            "VALIDATION_FAILED",
            f"tenant {_listed(named)} still has the placeholder name it was "
            "auto-created with, which names the vendor that created it. Rename "
            "it under Settings → Tenants before inviting client users.",
        )
    slugged = [s for s in wanted if "slug" in placeholders.get(s, ())]
    if slugged:
        raise APIError(
            "VALIDATION_FAILED",
            f"tenant {_listed(slugged)} has a placeholder slug made from the "
            "vendor's name, and a slug can't be renamed. Create the tenant under "
            "a proper slug — with the same compliance tags, so one super admin "
            "may merge into it — and merge this one into it (Settings → "
            "Tenants), then invite client users to that one.",
        )
    return wanted


def _refuse_revoke_leaving_wildcard_viewer(operator_id: int, role: str) -> None:
    """Revoking the operator's higher roles must not leave a viewer (a client
    user) whose viewer row still says '*' or nothing — a row written before
    viewers had to be scoped, or under a higher role's defaults."""
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        rows = reg.execute(
            "SELECT role_name, scope_slugs FROM operator_roles "
            "WHERE operator_id = ? AND role_name != ?",
            (operator_id, role),
        ).fetchall()
    finally:
        reg.close()
    remaining = {r["role_name"]: r["scope_slugs"] for r in rows}
    if not remaining or max(ROLE_TIER.get(n, 0) for n in remaining) != ROLE_TIER["viewer"]:
        return
    try:
        scope = json.loads(remaining.get("viewer") or "[]") or []
    except (TypeError, ValueError):
        scope = []
    if not scope or "*" in scope:
        raise APIError(
            "VALIDATION_FAILED",
            f"revoking {role!r} would leave a viewer (a client user) scoped to "
            f"{'every tenant' if scope else 'no tenant'}. Under Operators: revoke "
            f"'viewer' first, grant 'viewer' again with the specific tenant(s), then "
            f"revoke {role!r} — or revoke 'viewer' too.",
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=OperatorListResponse)
def list_operators(
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> OperatorListResponse:
    """List operators visible to the caller. Within a bundle, every operator
    in the bundle is visible to admin+; the listing excludes credential
    material entirely."""
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        # is_factory + l2_llm_granted (migrations 026 + 027) may be
        # absent on a pre-migration DB; use COALESCE-style fallback
        # via try/except so this listing works on every bundle age.
        try:
            rows = reg.execute(
                "SELECT id, username, email, mfa_enabled, must_change_password, "
                "       disabled_at, last_login_at, created_at, "
                "       is_factory, l2_llm_granted "
                "FROM operators WHERE removed_at IS NULL ORDER BY id ASC"
            ).fetchall()
            has_llm_fields = True
        except sqlite3.OperationalError:
            rows = reg.execute(
                "SELECT id, username, email, mfa_enabled, must_change_password, "
                "       disabled_at, last_login_at, created_at "
                "FROM operators ORDER BY id ASC"
            ).fetchall()
            has_llm_fields = False
        out: list[OperatorListEntry] = []
        for row in rows:
            role_rows = reg.execute(
                "SELECT role_name, scope_slugs FROM operator_roles "
                "WHERE operator_id = ?",
                (row["id"],),
            ).fetchall()
            roles = sorted({r["role_name"] for r in role_rows})
            scopes = []
            for r in role_rows:
                try:
                    parsed = json.loads(r["scope_slugs"]) or []
                except (TypeError, ValueError):
                    parsed = []
                scopes.extend(parsed)
            out.append(OperatorListEntry(
                id=row["id"],
                username=row["username"],
                email=row["email"],
                roles=roles,
                scope_slugs=sorted(set(scopes)),
                mfa_enabled=bool(row["mfa_enabled"]),
                must_change_password=bool(row["must_change_password"]),
                disabled_at=row["disabled_at"],
                last_login_at=row["last_login_at"],
                created_at=row["created_at"],
                is_factory=bool(row["is_factory"]) if has_llm_fields else False,
                l2_llm_granted=bool(row["l2_llm_granted"]) if has_llm_fields else False,
            ))
    finally:
        reg.close()
    return OperatorListResponse(operators=out)


def _refuse_duplicate_operator(
    username: str, email: str, *, exclude_operator_id: int | None = None,
) -> None:
    """Usernames and emails are UNIQUE — and a DISABLED account keeps both.
    Without this check the INSERT raised IntegrityError → an unhandled 500 →
    the console's generic "Create failed", with nothing telling the admin
    that a disabled account was holding the address. The caller is admin+
    and can already list operators, so naming the conflicting account
    discloses nothing new."""
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        rows = reg.execute(
            "SELECT id, username, email, disabled_at FROM operators "
            "WHERE (lower(username) = lower(?) OR lower(email) = lower(?))",
            (username, email),
        ).fetchall()
    finally:
        reg.close()
    for row in rows:
        if exclude_operator_id is not None and row["id"] == exclude_operator_id:
            continue
        field = "username" if row["username"].lower() == username.lower() else "email"
        state = "a DISABLED account" if row["disabled_at"] else "an active account"
        raise APIError(
            "OPERATOR_EXISTS",
            f"That {field} already belongs to {state} ('{row['username']}'). "
            f"Usernames and emails must be unique — disabled accounts keep "
            f"theirs. Change that account's {field} first, or use a different one.",
        )


@router.post("", response_model=CreateOperatorResponse)
def create_operator(
    body: CreateOperatorBody,
    request: Request,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> CreateOperatorResponse:
    """Create a pending operator. The new operator has no password and no
    MFA factor — activation is via a follow-up magic-link issuance.

    Tier rule: caller cannot grant a role above their own tier (admin
    cannot create super_admin).

    Scope: a viewer (client user) needs an explicit list of active,
    properly named tenants (`_viewer_scope`); analyst+ keep the default
    ['*'], and an empty list still means ['*'] for them."""
    request_id = str(uuid.uuid4())
    _enforce_tier_rule(caller.operator_id, body.role)
    scope = (
        _viewer_scope(body.scope_slugs) if body.role == "viewer"
        else (body.scope_slugs or ["*"])
    )
    _refuse_duplicate_operator(body.username, body.email)

    op = ops_mod.create_operator(
        username=body.username,
        email=body.email,
        # Use the role the admin actually picked, not a hardcoded
        # "admin". The earlier code created a stray admin role on
        # every operator that the second INSERT OR IGNORE below
        # then layered onto — making every analyst look like an
        # admin in /auth/me. Fixed 2026-05-11.
        role=body.role,
        scope_slugs=scope,
        actor=str(caller.operator_id),
        reason=body.reason or "admin_ops.create_operator",
    )
    op_id = op["operator_id"]

    # Issue an initial-setup magic link in the SAME transaction so the
    # operator can be activated by following the link. 24h TTL — same
    # contract as bootstrap.provision_super_admin's link.
    magic_token_plain = secrets.token_urlsafe(32)
    magic_token_hash = core_auth.hash_token(magic_token_plain)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=24)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    exp_iso = expires.strftime("%Y-%m-%dT%H:%M:%S.") + f"{expires.microsecond // 1000:03d}Z"

    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                "INSERT OR IGNORE INTO operator_roles "
                "(operator_id, role_name, scope_slugs) VALUES (?, ?, ?)",
                (op_id, body.role, json.dumps(scope)),
            )
            reg.execute(
                "INSERT INTO magic_link_tokens "
                "(token_hash, operator_id, issued_at, expires_at, purpose) "
                "VALUES (?, ?, ?, ?, ?)",
                (magic_token_hash, op_id, now_iso, exp_iso, "initial-setup"),
            )
            # Invited operators have no password yet. Without this flag the
            # wizard skipped straight to TOTP and they finished onboarding
            # with password_hash NULL — unable to sign in again once the
            # session ended (the invite link is single-use).
            reg.execute(
                "UPDATE operators SET must_change_password = 1 "
                "WHERE id = ? AND password_hash IS NULL",
                (op_id,),
            )
    finally:
        reg.close()

    magic_url = (
        athena_origin().rstrip("/")
        + "/login/magic?token="
        + urllib.parse.quote(magic_token_plain, safe="")
    )

    _audit(
        "admin_ops_create_operator",
        actor=caller.operator_id, target_id=op_id,
        after={
            "username": body.username,
            "email": body.email,
            "role": body.role,
            "scope_slugs": scope,
            "state": "pending",
            "magic_link_expires_at": exp_iso,
        },
        reason=body.reason or "admin_ops.create_operator",
        request_id=request_id,
    )

    return CreateOperatorResponse(
        operator_id=op_id,
        username=body.username,
        email=body.email,
        role=body.role,
        state="pending",
        activation_path=(
            "deliver the magic_link_url to the new operator via your "
            "out-of-band channel; they redeem it to set their password + TOTP"
        ),
        magic_link_url=magic_url,
        magic_link_expires_at=exp_iso,
    )


def _load_operator_or_404(op_id: int) -> dict:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute(
            "SELECT id, username, email, disabled_at FROM operators WHERE id = ?",
            (op_id,),
        ).fetchone()
    finally:
        reg.close()
    if row is None:
        raise APIError("AUTH_OPERATOR_NOT_FOUND",
                        f"no operator with id {op_id}")
    return dict(row)


@router.post("/{operator_id}/disable")
def disable_operator(
    operator_id: int,
    body: DisableOperatorBody,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> dict:
    """Disable an operator. Tier rule: caller must hold a role ≥ target's
    highest role. A super_admin caller cannot disable themselves, and cannot
    disable the LAST active super_admin."""
    request_id = str(uuid.uuid4())
    target = _load_operator_or_404(operator_id)
    if target["disabled_at"] is not None:
        # Already disabled — return idempotently.
        return {"operator_id": operator_id, "state": "already-disabled"}

    if operator_id == caller.operator_id:
        raise APIError("VALIDATION_FAILED",
                        "operators cannot disable their own account")

    target_roles = get_operator_roles(operator_id)
    if target_roles:
        # Tier check: caller must be ≥ target's highest tier
        target_tier = max(ROLE_TIER.get(r, 0) for r in target_roles)
        if operator_max_tier(caller.operator_id) < target_tier:
            raise APIError(
                "ISOLATION_VIOLATION",
                "caller tier insufficient to disable this operator",
            )

    if "super_admin" in target_roles:
        if _count_active_super_admins() <= 1:
            raise APIError(
                "VALIDATION_FAILED",
                "cannot disable the last active super_admin",
            )

    now = audit._now_iso() if hasattr(audit, "_now_iso") else None
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            from datetime import datetime, timezone
            now_iso = (datetime.now(timezone.utc)
                       .strftime("%Y-%m-%dT%H:%M:%S.")
                       + f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z")
            reg.execute(
                "UPDATE operators SET disabled_at = ? WHERE id = ?",
                (now_iso, operator_id),
            )
    finally:
        reg.close()

    # Revoke active sessions for the disabled operator.
    sessions.revoke_all_for_operator(
        operator_id=operator_id,
        revoked_by=caller.operator_id,
        except_session_id=None,
    )

    _audit(
        "admin_ops_disable_operator",
        actor=caller.operator_id, target_id=operator_id,
        after={
            "username": target["username"],
            "disabled_at": now_iso,
            "sessions_revoked": True,
        },
        reason=body.reason or "admin_ops.disable_operator",
        request_id=request_id,
    )

    return {"operator_id": operator_id, "state": "disabled",
            "disabled_at": now_iso}


@router.post("/{operator_id}/enable")
def enable_operator(
    operator_id: int,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> dict:
    """Re-enable a previously-disabled operator. Tier rule same as disable:
    caller must hold a role ≥ target's highest role."""
    request_id = str(uuid.uuid4())
    target = _load_operator_or_404(operator_id)
    if target["disabled_at"] is None:
        return {"operator_id": operator_id, "state": "already-enabled"}

    target_roles = get_operator_roles(operator_id)
    if target_roles:
        target_tier = max(ROLE_TIER.get(r, 0) for r in target_roles)
        if operator_max_tier(caller.operator_id) < target_tier:
            raise APIError(
                "ISOLATION_VIOLATION",
                "caller tier insufficient to enable this operator",
            )

    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                "UPDATE operators SET disabled_at = NULL WHERE id = ?",
                (operator_id,),
            )
    finally:
        reg.close()

    _audit(
        "admin_ops_enable_operator",
        actor=caller.operator_id, target_id=operator_id,
        after={"username": target["username"]},
        reason="admin_ops.enable_operator",
        request_id=request_id,
    )
    return {"operator_id": operator_id, "state": "enabled"}


class RemoveOperatorBody(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


def _operator_has_history(reg: sqlite3.Connection, operator_id: int) -> bool:
    """True if the account was ever USED. Audit rows name the actor by id and
    some tables reference operators(id) with no ON DELETE rule, so an account
    with history must be retired (tombstoned), never deleted."""
    row = reg.execute(
        "SELECT last_login_at, password_hash FROM operators WHERE id = ?",
        (operator_id,),
    ).fetchone()
    if row["last_login_at"] is not None or row["password_hash"] is not None:
        return True
    for table, column in (("sessions", "operator_id"),
                          ("buoy_notes", "author_id"),
                          ("buoy_commands", "requested_by"),
                          ("adapter_instances", "configured_by_operator_id")):
        try:
            if reg.execute(f"SELECT 1 FROM {table} WHERE {column} = ? LIMIT 1",
                           (operator_id,)).fetchone():
                return True
        except sqlite3.OperationalError:      # table absent on this bundle age
            continue
    return False


@router.post("/{operator_id}/remove")
def remove_operator(
    operator_id: int,
    body: RemoveOperatorBody,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> dict:
    """Remove an operator from the console.

    - never-used account (never signed in, no password, nothing references
      it) → the row is DELETED — the mistyped-invite case
    - account with history → RETIRED: sessions, MFA, passkeys, backup codes,
      outstanding links and roles are revoked, the UNIQUE username + email are
      freed for reuse, the row is hidden from the list — and KEPT, so every
      audit entry that names this operator id still resolves to an identity.

    Guards: not yourself, not the factory account, not the last active
    super_admin; tier rule as disable. `reason` is required and audited."""
    request_id = str(uuid.uuid4())
    target = _load_operator_or_404(operator_id)

    if operator_id == caller.operator_id:
        raise APIError("VALIDATION_FAILED",
                        "operators cannot remove their own account")

    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        flags = reg.execute(
            "SELECT is_factory, removed_at FROM operators WHERE id = ?",
            (operator_id,),
        ).fetchone()
    finally:
        reg.close()
    if flags["removed_at"] is not None:
        return {"operator_id": operator_id, "state": "already-removed"}
    if flags["is_factory"]:
        raise APIError(
            "VALIDATION_FAILED",
            "the factory account cannot be removed — it is the break-glass "
            "recovery path for this platform (disable it instead)",
        )

    target_roles = get_operator_roles(operator_id)
    if target_roles:
        target_tier = max(ROLE_TIER.get(r, 0) for r in target_roles)
        if operator_max_tier(caller.operator_id) < target_tier:
            raise APIError(
                "ISOLATION_VIOLATION",
                "caller tier insufficient to remove this operator",
            )
    if ("super_admin" in target_roles and target["disabled_at"] is None
            and _count_active_super_admins() <= 1):
        raise APIError("VALIDATION_FAILED",
                        "cannot remove the last active super_admin")

    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"

    reg = connect(paths.registry_db_path())
    try:
        retired = _operator_has_history(reg, operator_id)
        with transaction(reg):
            if not retired:
                reg.execute("DELETE FROM operators WHERE id = ?", (operator_id,))
            else:
                # Free the UNIQUE fields; ".invalid" is reserved and never routes.
                reg.execute(
                    "UPDATE operators SET "
                    "  removed_at = ?, removed_by = ?, removed_reason = ?, "
                    "  disabled_at = COALESCE(disabled_at, ?), "
                    "  username = ?, email = ?, "
                    "  password_hash = NULL, must_change_password = 0, "
                    "  mfa_enabled = 0, mfa_secret_enc = NULL, "
                    "  token_hash = ?, token_prefix = 'removed' "
                    "WHERE id = ?",
                    (now_iso, caller.operator_id, body.reason, now_iso,
                     f"removed-{operator_id}-{target['username']}"[:120],
                     f"removed-{operator_id}@removed.invalid",
                     core_auth.hash_token(secrets.token_urlsafe(32)),
                     operator_id),
                )
                reg.execute("DELETE FROM operator_roles WHERE operator_id = ?",
                            (operator_id,))
                reg.execute(
                    "UPDATE magic_link_tokens SET used_at = ? "
                    "WHERE operator_id = ? AND used_at IS NULL",
                    (now_iso, operator_id),
                )
                reg.execute(
                    "UPDATE backup_code_sets SET revoked_at = ?, revoked_by = ?, "
                    "revoke_reason = 'operator-disabled' "
                    "WHERE operator_id = ? AND revoked_at IS NULL",
                    (now_iso, caller.operator_id, operator_id),
                )
                reg.execute(
                    "UPDATE webauthn_credentials SET revoked_at = ? "
                    "WHERE operator_id = ? AND revoked_at IS NULL",
                    (now_iso, operator_id),
                )
    finally:
        reg.close()

    sessions_revoked = 0
    if retired:
        sessions_revoked = sessions.revoke_all_for_operator(
            operator_id, revoked_by=caller.operator_id)

    _audit(
        "admin_ops_remove_operator",
        actor=caller.operator_id, target_id=operator_id,
        after={"username": target["username"], "email": target["email"],
               "mode": "retired" if retired else "deleted",
               "roles_revoked": sorted(target_roles),
               "sessions_revoked": sessions_revoked},
        reason=body.reason,
        request_id=request_id,
    )
    return {"operator_id": operator_id,
            "state": "retired" if retired else "deleted"}


class UpdateOperatorEmailBody(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    reason: Optional[str] = Field(default=None, max_length=500)


@router.post("/{operator_id}/email")
def update_operator_email(
    operator_id: int,
    body: UpdateOperatorEmailBody,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> dict:
    """Change an operator's email. Exists because a DISABLED account keeps its
    (unique) email and cannot sign in to change it itself — without this route
    a disabled account blocked that address forever. Works on enabled and
    disabled accounts. Tier rule same as enable/disable. Does NOT sign the
    operator out and does NOT trigger any email: password resets go to the NEW
    address from now on, so the change is audited with both values."""
    request_id = str(uuid.uuid4())
    target = _load_operator_or_404(operator_id)

    if operator_id == caller.operator_id:
        # Your OWN email changes through Account settings, which demands the
        # current password: a stolen session must not be able to redirect
        # password-reset mail. This admin route has no such gate, so it must
        # never apply to the caller (same rule as admin password reset).
        raise APIError("VALIDATION_FAILED",
                        "use Account settings to change your own email")

    target_roles = get_operator_roles(operator_id)
    if target_roles:
        target_tier = max(ROLE_TIER.get(r, 0) for r in target_roles)
        if operator_max_tier(caller.operator_id) < target_tier:
            raise APIError(
                "ISOLATION_VIOLATION",
                "caller tier insufficient to edit this operator",
            )

    new_email = body.email.strip()
    if new_email.lower() == (target["email"] or "").lower():
        return {"operator_id": operator_id, "state": "unchanged"}
    _refuse_duplicate_operator(
        target["username"], new_email, exclude_operator_id=operator_id,
    )

    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                "UPDATE operators SET email = ? WHERE id = ?",
                (new_email, operator_id),
            )
    finally:
        reg.close()

    _audit(
        "admin_ops_update_operator_email",
        actor=caller.operator_id, target_id=operator_id,
        after={"username": target["username"], "old_email": target["email"],
               "new_email": new_email},
        reason=body.reason or "admin_ops.update_operator_email",
        request_id=request_id,
    )
    return {"operator_id": operator_id, "state": "updated", "email": new_email}


@router.post("/{operator_id}/role/grant")
def grant_role(
    operator_id: int,
    body: GrantRoleBody,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> dict:
    """Grant a role to an operator — or, for a role they hold, replace its
    tenant scope (how the console's scope editor saves). Tier rule: caller
    cannot grant a role above their own tier. Operators cannot self-grant
    any role. A viewer row takes only an explicit list of active, properly
    named tenants (`_viewer_scope`): an existing viewer is never widened to
    '*'."""
    request_id = str(uuid.uuid4())
    if operator_id == caller.operator_id:
        raise APIError("VALIDATION_FAILED",
                        "operators cannot grant roles to themselves")
    _load_operator_or_404(operator_id)
    _enforce_tier_rule(caller.operator_id, body.role)
    scope = _viewer_scope(body.scope_slugs) if body.role == "viewer" else body.scope_slugs

    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                "INSERT INTO operator_roles "
                "(operator_id, role_name, scope_slugs) VALUES (?, ?, ?) "
                "ON CONFLICT(operator_id, role_name) "
                "DO UPDATE SET scope_slugs = excluded.scope_slugs",
                (operator_id, body.role, json.dumps(scope)),
            )
    finally:
        reg.close()

    _audit(
        "admin_ops_grant_role",
        actor=caller.operator_id, target_id=operator_id,
        after={"role": body.role, "scope_slugs": scope},
        reason=body.reason or "admin_ops.grant_role",
        request_id=request_id,
    )
    return {"operator_id": operator_id, "granted": body.role,
            "scope_slugs": scope}


@router.post("/{operator_id}/role/revoke")
def revoke_role(
    operator_id: int,
    body: RevokeRoleBody,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> dict:
    """Revoke a role. Tier rule same as grant. Refuses to revoke the last
    super_admin's super_admin role (would lock the bundle out)."""
    request_id = str(uuid.uuid4())
    if operator_id == caller.operator_id:
        raise APIError("VALIDATION_FAILED",
                        "operators cannot revoke their own roles")
    _load_operator_or_404(operator_id)
    _enforce_tier_rule(caller.operator_id, body.role)

    if body.role == "super_admin":
        # Must keep at least one active super_admin
        if _count_active_super_admins() <= 1 and \
                _operator_is_super_admin(operator_id):
            raise APIError(
                "VALIDATION_FAILED",
                "cannot revoke super_admin from the last super_admin operator",
            )
    _refuse_revoke_leaving_wildcard_viewer(operator_id, body.role)

    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            cur = reg.execute(
                "DELETE FROM operator_roles WHERE operator_id = ? AND role_name = ?",
                (operator_id, body.role),
            )
            removed = cur.rowcount
    finally:
        reg.close()

    _audit(
        "admin_ops_revoke_role",
        actor=caller.operator_id, target_id=operator_id,
        after={"role": body.role, "removed": removed},
        reason=body.reason or "admin_ops.revoke_role",
        request_id=request_id,
    )
    return {"operator_id": operator_id, "revoked": body.role,
            "removed": removed}


# ---------------------------------------------------------------------------
# Admin-driven password reset
# ---------------------------------------------------------------------------
#
# An admin / super_admin issues a fresh password-reset magic link for
# another operator. The endpoint returns the URL so the admin can hand it
# off out-of-band (DM, ticket, etc.) — no email is sent. Side effects on
# the target operator:
#
#   - `must_change_password = 1`         (forces the setup gate on next sign-in)
#   - `password_hash = NULL`             (old password no longer usable —
#                                         the magic link is the only path back in)
#   - `failed_login_count = 0, locked_until = NULL` (clear any lockout state)
#   - every active session revoked       (no stale cookies stay valid)
#
# Tier rule: caller can reset operators at tiers ≤ their own. An admin
# cannot reset a super_admin's password.
# ---------------------------------------------------------------------------

class ResetPasswordBody(BaseModel):
    """Two modes:
      - `new_password` provided → admin sets a known temporary password.
        Target keeps must_change_password=1 so they're forced to pick
        their own on next sign-in.
      - `new_password` omitted    → server issues a one-time magic-link
        URL that the target consumes via /login/reset.
    Either way: target's existing sessions are revoked and the prior
    password is invalidated.
    """
    new_password: Optional[str] = Field(default=None, min_length=12, max_length=512)
    reason: Optional[str] = None


class ResetPasswordResponse(BaseModel):
    operator_id: int
    username: str
    # Populated when admin set a temporary password directly:
    temporary_password_set: bool = False
    # Populated when the server issued a magic-link:
    magic_link_url: Optional[str] = None
    magic_link_expires_at: Optional[str] = None


def _operator_max_role(op_id: int) -> str:
    """Return the highest-tier role name held by an operator, or '' if none."""
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        rows = reg.execute(
            "SELECT role_name FROM operator_roles WHERE operator_id = ?",
            (op_id,),
        ).fetchall()
    finally:
        reg.close()
    best = ""
    best_tier = 0
    for r in rows:
        t = ROLE_TIER.get(r["role_name"], 0)
        if t > best_tier:
            best_tier = t
            best = r["role_name"]
    return best


@router.post(
    "/{operator_id}/reset-password",
    response_model=ResetPasswordResponse,
)
def reset_operator_password(
    operator_id: int,
    body: ResetPasswordBody,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> ResetPasswordResponse:
    """Generate a fresh password-reset magic-link for another operator,
    clear their current password + revoke sessions, return the URL.
    """
    request_id = str(uuid.uuid4())
    if operator_id == caller.operator_id:
        # Self-reset doesn't make sense via the admin endpoint — use
        # the in-app /password/change or /password/forgot flows.
        raise APIError(
            "VALIDATION_FAILED",
            "use /auth/password/change to reset your own password",
        )
    target = _load_operator_or_404(operator_id)
    # Tier rule: caller must be ≥ target's max tier.
    target_role = _operator_max_role(operator_id)
    if target_role:
        _enforce_tier_rule(caller.operator_id, target_role)

    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"

    if body.new_password is not None:
        # ---- Mode A: admin sets a known temporary password. ----
        # Target is FORCED to change it on next sign-in via the
        # setup_gate middleware (must_change_password=1 stays set).
        # The admin can hand the temp password to the user out-of-band;
        # since the user must rotate it immediately, the admin's window
        # of plaintext knowledge is bounded by next-login.
        new_hash = core_auth.hash_token(body.new_password)
        reg = connect(paths.registry_db_path())
        try:
            with transaction(reg):
                reg.execute(
                    """
                    UPDATE operators
                       SET password_hash = ?,
                           must_change_password = 1,
                           failed_login_count = 0,
                           locked_until = NULL,
                           password_changed_at = ?
                     WHERE id = ?
                    """,
                    (new_hash, now_iso, operator_id),
                )
        finally:
            reg.close()

        # Revoke every active session for the target operator.
        sessions.revoke_all_for_operator(
            operator_id=operator_id,
            revoked_by=caller.operator_id,
            except_session_id=None,
        )

        _audit(
            "admin_ops_reset_password",
            actor=caller.operator_id,
            target_id=operator_id,
            after={
                "outcome": "temp_password_set",
                "target_role": target_role,
                # NEVER log the plaintext or hash — only that one was set.
                "method": "admin_set_temporary",
            },
            reason=body.reason or "admin_ops.reset_password",
            request_id=request_id,
        )
        return ResetPasswordResponse(
            operator_id=operator_id,
            username=target["username"],
            temporary_password_set=True,
        )

    # ---- Mode B: server issues a magic-link the admin hands off. ----
    plaintext = secrets.token_urlsafe(32)
    token_hash = core_auth.hash_token(plaintext)
    # Mirror the auth.py MAGIC_LINK_TTL["password-reset"] window.
    expires = now + timedelta(minutes=10)
    exp_iso = expires.strftime("%Y-%m-%dT%H:%M:%S.") + f"{expires.microsecond // 1000:03d}Z"

    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                """
                UPDATE operators
                   SET password_hash = NULL,
                       must_change_password = 1,
                       failed_login_count = 0,
                       locked_until = NULL,
                       password_changed_at = ?
                 WHERE id = ?
                """,
                (now_iso, operator_id),
            )
            reg.execute(
                "INSERT INTO magic_link_tokens "
                "(token_hash, operator_id, issued_at, expires_at, purpose) "
                "VALUES (?, ?, ?, ?, ?)",
                (token_hash, operator_id, now_iso, exp_iso, "password-reset"),
            )
    finally:
        reg.close()

    sessions.revoke_all_for_operator(
        operator_id=operator_id,
        revoked_by=caller.operator_id,
        except_session_id=None,
    )

    magic_url = (
        athena_origin().rstrip("/")
        + "/login/reset?token="
        + urllib.parse.quote(plaintext, safe="")
    )

    _audit(
        "admin_ops_reset_password",
        actor=caller.operator_id,
        target_id=operator_id,
        after={
            "outcome": "magic_link_issued",
            "expires_at": exp_iso,
            "target_role": target_role,
            "method": "magic_link",
        },
        reason=body.reason or "admin_ops.reset_password",
        request_id=request_id,
    )
    return ResetPasswordResponse(
        operator_id=operator_id,
        username=target["username"],
        magic_link_url=magic_url,
        magic_link_expires_at=exp_iso,
    )
