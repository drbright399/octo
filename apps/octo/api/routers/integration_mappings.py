"""Tenant-mapping editor — `/api/v1/integrations/{vendor_slug}/{instance_id}/mappings/tenants`.

The generic per-instance tenant map (migration 030, `instances/tenant_map.py`):
maps a source's vendor tenant ids (Datto siteUid, Wazuh agent group, RocketCyber
customerId, …) → OCTO client slugs, establishing cross-source client identity so
events from every tool land under one client. The Integrations wizard's
tenant-mapping step calls these; the future master-directory auto-matcher will
pre-fill them (match_source != 'manual').

GET returns the current mappings, each with the status and display name of
the client it points at; PUT bulk-replaces the EDITABLE ones. admin+ gated.

FROZEN rows. When a tenant is offboarded (or merged, archived, disabled) its
mappings are deliberately KEPT, pointing at the departed slug, so the site's
traffic is held in quarantine as 'offboarded-tenant' instead of auto-creating
a look-alike tenant (`admin_tenants._apply_offboard`). Such a row is not the
mapping panel's to edit: it is lifecycle state, and the only way to re-point
it is a human routing the site's held events under Quarantine. So PUT
MERGES rather than replaces where frozen rows are concerned — the decision
of record, made so a frozen row can never be lost by accident:
  - a frozen row the body OMITS is kept verbatim (a client that loads the
    map, edits the active rows and saves cannot delete it);
  - a frozen row the body carries UNCHANGED (same id → same slug; a naive
    GET → PUT round-trip, or the panel sending it back) is accepted and the
    STORED row is kept verbatim — label and match_source included, so a
    round-trip cannot rewrite an auto-created row as 'manual';
  - a body row that names a frozen site but a DIFFERENT client is refused
    (409) with the route to take: re-pointing is a quarantine decision.
The body therefore describes the active map only; the audit row's after
state is the effective map (active rows + frozen rows).

PUT validation is deliberately PERMISSIVE about what a vendor tenant id looks
like — most vendors cannot list their tenants, and an id the vendor will only
start sending tomorrow is legitimate — and it never contacts a vendor. It
refuses only input that cannot work whatever the vendor is: a blank or
whitespace-padded id (routing is an exact match), a duplicate id, a client
that does not exist (its events would be dropped), an unknown match_source,
and — the same-name rule (2026-10-01) — any NEW row that is not 'manual':
a name match or other suggestion becomes a mapping only when an operator
confirms that row (saved as 'manual'); a stored non-manual row may only be
sent back unchanged (it stays "unconfirmed" until someone confirms it).
Whether an id matches a REAL vendor tenant is the mapping panel's job
(`POST /admin/adapters/instances/{id}/vendor-tenants`), where a human confirms.
The replace is audited (who / which instance / before → after).
"""

from __future__ import annotations

import sqlite3
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Path, Request
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import session_admin_plus
from apps.octo.auth import audit, sessions
from apps.octo.db import connect
from apps.octo.instances import tenant_map
from apps.octo.instances.vendor_tenants import MAX_ID_CHARS, MAX_LABEL_CHARS

router = APIRouter(prefix="/integrations", tags=["integration-mappings"])

# The values migration 030 documents for `match_source`.
MATCH_SOURCES = ("manual", "auto-domain", "auto-name", "directory")
MAX_MAPPINGS = 10_000


class TenantMappingIn(BaseModel):
    vendor_tenant_id: str
    octo_client_slug: str
    vendor_tenant_label: str | None = None
    match_source: str = "manual"


class TenantMappingOut(BaseModel):
    vendor_tenant_id: str
    octo_client_slug: str
    vendor_tenant_label: str | None = None
    match_source: str
    # The client's lifecycle status: active | disabled | offboarded | archived
    # ('missing' only if its row is gone, which no flow leaves behind).
    # Anything but 'active' = a FROZEN row (see the module docstring): the
    # panel renders it read-only and this route keeps it whatever PUT sends.
    client_status: str
    client_display_name: str
    # Server-computed (`mapping_review.unconfirmed`): a mapping still to
    # re-review — made from a NAME by an earlier version, never the mapping
    # an instance wrote for a tenant it auto-created itself. The panel's
    # "unconfirmed" banner reads THIS, never match_source alone.
    needs_review: bool = False


class SetTenantMappingsRequest(BaseModel):
    mappings: list[TenantMappingIn] = Field(
        default_factory=list, max_length=MAX_MAPPINGS,
    )


class TenantMappingsResponse(BaseModel):
    vendor_slug: str
    instance_id: int
    mappings: list[TenantMappingOut]


ClientIndex = dict[str, tuple[str, str]]   # slug → (display_name, status)


def _client_index() -> ClientIndex:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return {
            r["slug"]: (r["display_name"], r["status"])
            for r in reg.execute("SELECT slug, display_name, status FROM clients").fetchall()
        }
    finally:
        reg.close()


def _is_frozen(m: tenant_map.TenantMapping, clients: ClientIndex) -> bool:
    return clients.get(m.octo_client_slug, ("", "missing"))[1] != "active"


def _stored_mappings(instance_id: int) -> list[tenant_map.TenantMapping]:
    try:
        return tenant_map.get_mappings(instance_id)
    except sqlite3.OperationalError:  # tenant-map migration not applied yet
        return []


def _review_ids(instance_id: int) -> set[tuple[str, str]]:
    """(vendor tenant id, client slug) of this instance's mappings still to
    re-review."""
    from apps.octo.instances import mapping_review

    try:
        return {(m.vendor_tenant_id, m.client_slug)
                for m in mapping_review.unconfirmed(instance_id=instance_id)}
    except sqlite3.Error:
        return set()


def _out(m: tenant_map.TenantMapping, clients: ClientIndex,
         review: Optional[set[tuple[str, str]]] = None) -> TenantMappingOut:
    display_name, status = clients.get(m.octo_client_slug, (m.octo_client_slug, "missing"))
    return TenantMappingOut(
        vendor_tenant_id=m.vendor_tenant_id,
        octo_client_slug=m.octo_client_slug,
        vendor_tenant_label=m.vendor_tenant_label,
        match_source=m.match_source,
        client_status=status,
        client_display_name=display_name,
        needs_review=(m.vendor_tenant_id, m.octo_client_slug) in (review or set()),
    )


def _shown(value: str) -> str:
    """An operator-typed value, bounded, for an error message."""
    return repr(value if len(value) <= 64 else value[:63] + "…")


def _validated(
    body: SetTenantMappingsRequest, vendor_slug: str, instance_id: int,
    *, clients: ClientIndex, stored: list[tenant_map.TenantMapping],
) -> list[tenant_map.TenantMapping]:
    """Refuse what can never work (see the module docstring); local reads
    only. Returns the rows to store: the body's editable rows exactly as
    sent (a blank label becomes NULL) PLUS every frozen row of `stored`,
    verbatim — the merge rule the module docstring documents."""
    from apps.octo.client_provisioning import _SLUG_RE
    from apps.octo.instances.manager import get_instance

    record = get_instance(instance_id)
    if record is None or record.vendor_slug != vendor_slug:
        raise APIError(
            "NOT_FOUND", f"no {vendor_slug} adapter instance with id {instance_id}",
        )
    if record.disabled_at is not None:
        raise APIError(
            "CONFLICT",
            f"adapter instance {instance_id} is disabled; its mappings can no "
            "longer be changed",
        )

    frozen = {m.vendor_tenant_id: m for m in stored if _is_frozen(m, clients)}
    stored_by_id = {m.vendor_tenant_id: m for m in stored}
    seen: set[str] = set()
    out: list[tenant_map.TenantMapping] = []
    for n, m in enumerate(body.mappings, start=1):
        tid = m.vendor_tenant_id
        held = frozen.get(tid)
        if held is not None:
            # Sent back as it is → the stored row stands (re-added below).
            # Pointed elsewhere → not this route's decision to make.
            if m.octo_client_slug == held.octo_client_slug:
                continue
            raise APIError(
                "CONFLICT",
                f"mapping {n}: {_shown(tid)} is frozen to {held.octo_client_slug!r}, "
                f"a tenant that is {clients.get(held.octo_client_slug, ('', 'missing'))[1]}. "
                "Its traffic is held in quarantine; to point the site at another "
                "tenant, route its held events under Quarantine.",
            )
        if not tid.strip():
            raise APIError("VALIDATION_FAILED", f"mapping {n}: vendor_tenant_id is blank")
        if tid != tid.strip() or not tid.isprintable():
            raise APIError(
                "VALIDATION_FAILED",
                f"mapping {n}: vendor_tenant_id {_shown(tid)} has leading/trailing "
                "whitespace or control characters — routing is an exact match, "
                "so it could never match an event",
            )
        if len(tid) > MAX_ID_CHARS:
            raise APIError(
                "VALIDATION_FAILED",
                f"mapping {n}: vendor_tenant_id is longer than {MAX_ID_CHARS} characters",
            )
        if tid in seen:
            raise APIError(
                "VALIDATION_FAILED",
                f"mapping {n}: duplicate vendor_tenant_id {_shown(tid)} — one "
                "vendor tenant maps to exactly one client",
            )
        seen.add(tid)
        slug = m.octo_client_slug
        if not _SLUG_RE.match(slug):
            raise APIError(
                "VALIDATION_FAILED",
                f"mapping {n}: octo_client_slug {_shown(slug)} is not a client slug",
            )
        if slug not in clients:
            raise APIError(
                "VALIDATION_FAILED",
                f"mapping {n}: client {_shown(slug)} does not exist — events "
                "mapped to it would be dropped. Create the client first.",
            )
        if m.match_source != "manual":
            # A mapping made by a NAME is never created through this route
            # (the same-name rule, 2026-10-01): a suggestion becomes a
            # mapping only when an operator confirms its row, and that is
            # their decision — 'manual'. A stored non-manual row sent back
            # UNCHANGED (same site → same client, same source) is kept as it
            # is: it stays listed as unconfirmed until someone confirms it.
            kept = stored_by_id.get(tid)
            unchanged = (kept is not None and kept.octo_client_slug == slug
                         and kept.match_source == m.match_source)
            if not unchanged:
                if m.match_source not in MATCH_SOURCES:
                    raise APIError(
                        "VALIDATION_FAILED",
                        f"mapping {n}: match_source must be one of {', '.join(MATCH_SOURCES)}",
                    )
                raise APIError(
                    "VALIDATION_FAILED",
                    f"mapping {n}: {_shown(tid)} → {_shown(slug)} cannot be saved as "
                    f"{m.match_source!r} — Athena never stores a mapping made from a name "
                    "or a suggestion by itself. Confirm the row and save it as 'manual' "
                    "(your decision).",
                )
        label = (m.vendor_tenant_label or "").strip()
        if len(label) > MAX_LABEL_CHARS or not label.isprintable():
            raise APIError(
                "VALIDATION_FAILED",
                f"mapping {n}: vendor_tenant_label must be at most "
                f"{MAX_LABEL_CHARS} printable characters",
            )
        out.append(tenant_map.TenantMapping(
            vendor_tenant_id=tid,
            octo_client_slug=slug,
            vendor_tenant_label=label or None,
            match_source=m.match_source,
        ))
    # Frozen rows ride along verbatim, whether or not the body carried them.
    out.extend(frozen[tid] for tid in sorted(frozen))
    return out


def _audit_replace(
    *,
    operator_id: int,
    vendor_slug: str,
    instance_id: int,
    before: list[tenant_map.TenantMapping],
    after: list[tenant_map.TenantMapping],
) -> None:
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=str(operator_id),
            actor_kind="human",
            action="adapter_tenant_map_replace",
            target_kind="adapter_instance",
            target_id=str(instance_id),
            client_slug="global",
            before_state={
                "vendor_slug": vendor_slug,
                "mappings": {m.vendor_tenant_id: m.octo_client_slug for m in before},
            },
            after_state={
                "vendor_slug": vendor_slug,
                "mappings": {m.vendor_tenant_id: m.octo_client_slug for m in after},
            },
            reason="tenant mapping bulk-replace via admin API",
            request_id=str(uuid.uuid4()),
        ))
    finally:
        g_audit.close()


@router.get(
    "/{vendor_slug}/{instance_id}/mappings/tenants",
    response_model=TenantMappingsResponse,
)
def get_tenant_mappings(
    vendor_slug: str = Path(...),
    instance_id: int = Path(...),
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> TenantMappingsResponse:
    clients = _client_index()
    review = _review_ids(instance_id)
    return TenantMappingsResponse(
        vendor_slug=vendor_slug,
        instance_id=instance_id,
        mappings=[_out(m, clients, review) for m in tenant_map.get_mappings(instance_id)],
    )


@router.put(
    "/{vendor_slug}/{instance_id}/mappings/tenants",
    response_model=TenantMappingsResponse,
)
def put_tenant_mappings(
    body: SetTenantMappingsRequest,
    request: Request,
    vendor_slug: str = Path(...),
    instance_id: int = Path(...),
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> TenantMappingsResponse:
    clients = _client_index()
    before = _stored_mappings(instance_id)
    # Merge, not replace, for frozen rows: `mappings` is the body's active
    # rows plus every frozen stored row verbatim (module docstring).
    mappings = _validated(body, vendor_slug, instance_id, clients=clients, stored=before)
    # Audit FIRST (failure to audit is fatal, so nothing changes unaudited).
    _audit_replace(
        operator_id=caller.operator_id,
        vendor_slug=vendor_slug,
        instance_id=instance_id,
        before=before,
        after=mappings,
    )
    tenant_map.set_mappings(instance_id, mappings, operator_id=caller.operator_id)
    # A poller that waits for the operator's mapping before its first import
    # (RocketCyber) starts it now rather than at its next interval. Best
    # effort: `nudge` never raises, and an adapter without `poll_now` ignores it.
    manager = getattr(request.app.state, "instance_manager", None)
    if manager is not None:
        manager.nudge(instance_id)
    review = _review_ids(instance_id)
    return TenantMappingsResponse(
        vendor_slug=vendor_slug,
        instance_id=instance_id,
        mappings=[_out(m, clients, review) for m in tenant_map.get_mappings(instance_id)],
    )
