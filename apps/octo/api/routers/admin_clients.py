"""GET /api/v1/admin/clients — list every client slug + display name
registered in this bundle.

The "clients" table holds the MSP's own customers (`acme-corp`,
`globex`, etc.). This list drives the tenant-scope picker in the
Operators UI: when an admin grants a role with constrained scope, the
SPA needs to know what slugs are valid.

Admin+ tier gated. Read-only. Returns active clients only by default;
pass `?include_disabled=1` to also surface offboarded/archived rows
(useful for audit views, not for the scope picker). `placeholder_name` /
`placeholder_slug` flag an auto-created tenant whose name or slug is still
the vendor-named placeholder: a viewer (client user) can't be scoped to it.
"""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from apps.octo import paths
from apps.octo.api.role_gates import session_admin_plus
from apps.octo.auth import sessions
from apps.octo.db import connect
from apps.octo.instances.tenant_autocreate import placeholder_parts


router = APIRouter(prefix="/admin/clients", tags=["admin-clients"])


class ClientEntry(BaseModel):
    slug: str
    display_name: str
    status: str
    # Still the auto-create placeholder ("<vendor> site …"): no viewer may be
    # scoped here until it is renamed (name) / merged away (slug).
    placeholder_name: bool = False
    placeholder_slug: bool = False


class ClientListResponse(BaseModel):
    clients: list[ClientEntry]


class CreateClientRequest(BaseModel):
    slug: str
    display_name: str


@router.get("", response_model=ClientListResponse)
def list_clients(
    include_disabled: int = Query(default=0),
    _caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> ClientListResponse:
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        if include_disabled:
            rows = reg.execute(
                "SELECT slug, display_name, status FROM clients "
                "ORDER BY display_name COLLATE NOCASE",
            ).fetchall()
        else:
            rows = reg.execute(
                "SELECT slug, display_name, status FROM clients "
                "WHERE status = 'active' "
                "ORDER BY display_name COLLATE NOCASE",
            ).fetchall()
        placeholders = placeholder_parts(reg, [r["slug"] for r in rows])
    finally:
        reg.close()
    return ClientListResponse(
        clients=[
            ClientEntry(
                slug=r["slug"],
                display_name=r["display_name"],
                status=r["status"],
                placeholder_name="name" in placeholders.get(r["slug"], ()),
                placeholder_slug="slug" in placeholders.get(r["slug"], ()),
            )
            for r in rows
        ],
    )


@router.post("", response_model=ClientEntry, status_code=201)
def create_client(
    body: CreateClientRequest,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> ClientEntry:
    """Provision a new client: register the row + create its per-client
    events.db / indicators.db so telemetry can land for it. admin+ gated.

    The same audited path as POST /admin/tenants: the row is born
    'unclassified' and therefore PENDING review (a kind is set under
    Settings → Tenants), and a `tenant_create` audit row precedes it —
    every tenant creation is audited, whichever door it came through."""
    from apps.octo.api.routers.admin_tenants import create_manual_tenant

    slug = create_manual_tenant(
        body.slug, body.display_name, kind="unclassified", flags=[], ai_policy="none",
        operator_id=caller.operator_id, reason="client created via admin API (legacy route)",
    )
    return ClientEntry(
        slug=slug,
        display_name=" ".join(body.display_name.split()),
        status="active",
    )
