"""Role-tier helpers + FastAPI dependencies for the per-bundle role taxonomy.

Bundle role tiers (ordered low → high):

    viewer    1   read-only within scope_slugs
    analyst   2   investigate + AI engagement within scope_slugs
    admin     3   MSP daily-ops top tier — manage operators ≤ admin, clients,
                  integrations, all data within the bundle
    super_admin 4 MSP customer's break-glass + factory account — manage all
                  operators including admin, plus system-level config

Per the per-MSP-bundle architecture (Option 2), `super_admin` here means the
MSP customer's own top tier, NOT the federation operator. Federation lives
in a separate service.

Usage in a router:

    from apps.octo.api.role_gates import session_at_least, session_admin_plus

    @router.post("/admin/operators")
    def create_operator(
        body: CreateOperatorBody,
        caller: sessions.SessionInfo = Depends(session_admin_plus),
    ): ...

The dependency raises `ISOLATION_VIOLATION` (403) if the caller's max
role tier is below the required minimum.
"""
from __future__ import annotations

from fastapi import Depends

from apps.octo import paths
from apps.octo.auth import sessions
from apps.octo.api.errors import APIError
from apps.octo.api.routers.auth import session_identity
from apps.octo.db import connect


# Tier ranking. Higher number = more privilege.
ROLE_TIER: dict[str, int] = {
    "viewer":      1,
    "analyst":     2,
    "admin":       3,
    "super_admin": 4,
}


def get_operator_roles(operator_id: int) -> set[str]:
    """Return the set of role names assigned to an operator. Empty set if
    the operator has no role rows (effectively no Console access)."""
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        rows = reg.execute(
            "SELECT role_name FROM operator_roles WHERE operator_id = ?",
            (operator_id,),
        ).fetchall()
    finally:
        reg.close()
    return {r["role_name"] for r in rows}


def operator_max_tier(operator_id: int) -> int:
    """Return the highest role tier held by the operator. Returns 0 if no
    roles or only unknown role names — treat 0 as "no Console privileges"."""
    roles = get_operator_roles(operator_id)
    return max((ROLE_TIER.get(r, 0) for r in roles), default=0)


def resolve_caller_scope(operator_id: int) -> list[str]:
    """The tenants an operator may READ: the union of `scope_slugs` across
    their role rows. `*` collapses to ['*']; otherwise the concrete slugs,
    sorted — ACTIVE tenants only.

    A concrete scope is a client user's (viewers are client users). Once
    their tenant is offboarded, archived or disabled its data is no longer
    theirs to read, so the slug drops out here — on every scoped read, in
    every router — without waiting for anyone to edit the operator. Empty
    list = the operator can see no client. The ONE resolver every scoped
    route goes through (dashboard, search, tickets, buoy, agent feeds…); a
    router-local copy that forgot the status filter is how a viewer scoped
    to an offboarded tenant kept reading its buoy command history."""
    import json

    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        rows = reg.execute(
            "SELECT scope_slugs FROM operator_roles WHERE operator_id = ?",
            (operator_id,),
        ).fetchall()
        scope: set[str] = set()
        for r in rows:
            try:
                parsed = json.loads(r["scope_slugs"]) or []
            except (TypeError, ValueError):
                continue
            for s in parsed:
                scope.add(s)
        if "*" in scope:
            return ["*"]
        if not scope:
            return []
        marks = ",".join("?" * len(scope))
        active = reg.execute(
            f"SELECT slug FROM clients WHERE status = 'active' AND slug IN ({marks})",
            sorted(scope),
        ).fetchall()
    finally:
        reg.close()
    return sorted(r["slug"] for r in active)


def session_at_least(min_role: str):
    """Build a FastAPI dependency that gates the route on caller's max
    role tier ≥ `min_role`. Returns `sessions.SessionInfo` on success,
    raises `ISOLATION_VIOLATION` on insufficient privilege."""
    if min_role not in ROLE_TIER:
        raise ValueError(f"unknown role name {min_role!r}")
    required_tier = ROLE_TIER[min_role]

    def _dep(
        info: sessions.SessionInfo = Depends(session_identity),
    ) -> sessions.SessionInfo:
        if operator_max_tier(info.operator_id) < required_tier:
            raise APIError(
                "ISOLATION_VIOLATION",
                f"this action requires at least the {min_role!r} role",
            )
        return info

    _dep.__name__ = f"session_at_least_{min_role}"
    return _dep


def operator_is_factory(operator_id: int) -> bool:
    """Return True iff this operator is the bundle's factory super_admin.

    Reads operators.is_factory (added by migration 026). Tolerates the
    pre-migration schema (returns False) so a bundle that hasn't yet
    auto-migrated doesn't grant factory privileges by accident.
    """
    import sqlite3

    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        try:
            row = reg.execute(
                "SELECT is_factory FROM operators WHERE id = ?",
                (operator_id,),
            ).fetchone()
        except sqlite3.OperationalError:
            # Column doesn't exist yet → no operator can be factory
            # until migration 026 lands. Safe default.
            return False
    finally:
        reg.close()
    if row is None:
        return False
    val = row[0] if not hasattr(row, "keys") else row["is_factory"]
    return bool(val)


def session_factory():
    """FastAPI dependency that gates the route on caller being the
    factory super_admin (operators.is_factory = 1).

    This is STRICTLY narrower than session_at_least("super_admin") —
    a bundle may have multiple super_admins, but exactly ONE factory
    super_admin. Used for actions that should never be runnable by
    a normal super_admin: L2 LLM model add/swap/delete, future
    factory-recovery flows, dual-control unlock seeds.
    """
    def _dep(
        info: sessions.SessionInfo = Depends(session_identity),
    ) -> sessions.SessionInfo:
        # Caller must also be at least super_admin tier — defense in
        # depth in case is_factory ever drifts from the role grant.
        if operator_max_tier(info.operator_id) < ROLE_TIER["super_admin"]:
            raise APIError(
                "ISOLATION_VIOLATION",
                "this action requires the factory super_admin",
            )
        if not operator_is_factory(info.operator_id):
            raise APIError(
                "ISOLATION_VIOLATION",
                "this action requires the factory super_admin "
                "(other super_admins are insufficient)",
            )
        return info

    _dep.__name__ = "session_factory"
    return _dep


# Convenience aliases for the most-used gates. Each is a fresh closure so
# FastAPI can introspect the dep without aliasing collisions.
session_super_admin = session_at_least("super_admin")
session_admin_plus  = session_at_least("admin")
session_analyst_plus = session_at_least("analyst")
session_viewer_plus = session_at_least("viewer")
