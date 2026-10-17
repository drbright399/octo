"""Autotask mapping endpoints (P4-b1).

Backs the Settings → Integrations → Autotask page (P4-b2). Lets a
super_admin manage the operator ↔ Autotask Resource map AND the
tenant ↔ Autotask Company map per adapter instance.

  GET  /api/v1/integrations/autotask/{instance_id}/mappings/operators
  PUT  /api/v1/integrations/autotask/{instance_id}/mappings/operators
  GET  /api/v1/integrations/autotask/{instance_id}/mappings/companies
  PUT  /api/v1/integrations/autotask/{instance_id}/mappings/companies

  (These were `/mappings/tenants` until 2026-10-05. That path is the GENERIC
  mapping editor's — apps/octo/api/routers/integration_mappings.py — and this
  router, registered first, swallowed the generic panel's Autotask saves with
  a 422. The generic editor writes `adapter_tenant_map`; the Autotask poller
  reads both stores.)

PUTs are bulk replace — the UI sends the full intended state and
this router diff-applies (insert/update/delete) so the operator can
edit the table in one shot.

The picklist cache itself is read by P4-c1's outbound push path; it's
populated by a refresh worker that lands with that slice. No UI for
the picklist cache yet — it's an internal translation table.

Every write is audit-logged with the operator + before/after state.
"""
from __future__ import annotations

import sqlite3
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.adapters.autotask.client import (
    AutotaskAuthError,
    AutotaskClient,
    AutotaskClientError,
    AutotaskConfig,
    AutotaskZoneError,
    resolve_zone,
)
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import session_super_admin
from apps.octo.api.routers.auth import _audit_append
from apps.octo.auth import sessions
from apps.octo.credentials import vault as credentials_vault
from apps.octo.db import connect, transaction
from apps.octo.instances import manager as instance_manager


router = APIRouter(
    prefix="/integrations/autotask",
    tags=["integrations-autotask"],
)


# ---------------------------------------------------------------------------
# Operator ↔ Autotask Resource map
# ---------------------------------------------------------------------------

class OperatorMapping(BaseModel):
    operator_id: int
    autotask_resource_id: int
    autotask_resource_email: Optional[str] = None
    autotask_resource_name: Optional[str] = None
    updated_at: Optional[str] = None
    updated_by_operator_id: Optional[int] = None


class OperatorMappingsResponse(BaseModel):
    instance_id: int
    mappings: list[OperatorMapping]


class OperatorMappingPut(BaseModel):
    """Single mapping row in a bulk PUT body. Operator_id + resource_id
    are required; the email + name are optional display hints."""
    operator_id: int
    autotask_resource_id: int
    autotask_resource_email: Optional[str] = Field(default=None, max_length=320)
    autotask_resource_name: Optional[str] = Field(default=None, max_length=200)


class OperatorMappingsPutRequest(BaseModel):
    mappings: list[OperatorMappingPut]


@router.get(
    "/{instance_id}/mappings/operators",
    response_model=OperatorMappingsResponse,
)
def get_operator_mappings(
    instance_id: int,
    request: Request,
    info: sessions.SessionInfo = Depends(session_super_admin),
) -> OperatorMappingsResponse:
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        rows = reg.execute(
            "SELECT operator_id, autotask_resource_id, "
            "       autotask_resource_email, autotask_resource_name, "
            "       updated_at, updated_by_operator_id "
            "  FROM autotask_operator_resource_map "
            " WHERE adapter_instance_id = ? "
            " ORDER BY operator_id",
            (instance_id,),
        ).fetchall()
    finally:
        reg.close()
    return OperatorMappingsResponse(
        instance_id=instance_id,
        mappings=[OperatorMapping(**dict(r)) for r in rows],
    )


@router.put(
    "/{instance_id}/mappings/operators",
    response_model=OperatorMappingsResponse,
)
def put_operator_mappings(
    instance_id: int,
    body: OperatorMappingsPutRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(session_super_admin),
) -> OperatorMappingsResponse:
    """Bulk-replace operator mappings for an instance. The body is the
    DESIRED state; rows not present are deleted, rows present are
    upserted. Audit-logged with the full before + after."""
    # Reject duplicates inside the request
    seen_ops: set[int] = set()
    for m in body.mappings:
        if m.operator_id in seen_ops:
            raise APIError(
                "VALIDATION_FAILED",
                f"duplicate operator_id {m.operator_id} in request",
            )
        seen_ops.add(m.operator_id)

    request_id = str(uuid.uuid4())
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        # Snapshot before-state for audit
        before_rows = reg.execute(
            "SELECT operator_id, autotask_resource_id "
            "  FROM autotask_operator_resource_map "
            " WHERE adapter_instance_id = ?",
            (instance_id,),
        ).fetchall()
        before_state = {r["operator_id"]: r["autotask_resource_id"]
                        for r in before_rows}

        # Replace the entire instance's mapping set
        reg.execute(
            "DELETE FROM autotask_operator_resource_map "
            " WHERE adapter_instance_id = ?", (instance_id,),
        )
        for m in body.mappings:
            reg.execute(
                "INSERT INTO autotask_operator_resource_map "
                "(adapter_instance_id, operator_id, autotask_resource_id, "
                " autotask_resource_email, autotask_resource_name, "
                " updated_by_operator_id) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (instance_id, m.operator_id, m.autotask_resource_id,
                 m.autotask_resource_email, m.autotask_resource_name,
                 info.operator_id),
            )
        reg.commit()

        after_rows = reg.execute(
            "SELECT operator_id, autotask_resource_id, "
            "       autotask_resource_email, autotask_resource_name, "
            "       updated_at, updated_by_operator_id "
            "  FROM autotask_operator_resource_map "
            " WHERE adapter_instance_id = ? "
            " ORDER BY operator_id",
            (instance_id,),
        ).fetchall()
        after_state = {r["operator_id"]: r["autotask_resource_id"]
                       for r in after_rows}
    finally:
        reg.close()

    _audit_append(
        "integrations.autotask.operator_map_replace",
        actor=f"operator:{info.operator_id}",
        target_id=f"adapter_instance:{instance_id}",
        before={"mappings": before_state},
        after={"mappings": after_state, "session_id_prefix": info.id[:8]},
        reason="Autotask operator mapping bulk-replace",
        request_id=request_id,
    )

    return OperatorMappingsResponse(
        instance_id=instance_id,
        mappings=[OperatorMapping(**dict(r)) for r in after_rows],
    )


# ---------------------------------------------------------------------------
# Tenant ↔ Autotask Company map
# ---------------------------------------------------------------------------

class TenantMapping(BaseModel):
    tenant_slug: str
    autotask_company_id: int
    autotask_company_name: Optional[str] = None
    autotask_homepage_url: Optional[str] = None
    updated_at: Optional[str] = None
    updated_by_operator_id: Optional[int] = None


class TenantMappingsResponse(BaseModel):
    instance_id: int
    mappings: list[TenantMapping]


class TenantMappingPut(BaseModel):
    tenant_slug: str = Field(min_length=1, max_length=120)
    autotask_company_id: int
    autotask_company_name: Optional[str] = Field(default=None, max_length=200)
    autotask_homepage_url: Optional[str] = Field(default=None, max_length=500)


class TenantMappingsPutRequest(BaseModel):
    mappings: list[TenantMappingPut]


@router.get(
    "/{instance_id}/mappings/companies",
    response_model=TenantMappingsResponse,
)
def get_tenant_mappings(
    instance_id: int,
    request: Request,
    info: sessions.SessionInfo = Depends(session_super_admin),
) -> TenantMappingsResponse:
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        rows = reg.execute(
            "SELECT tenant_slug, autotask_company_id, "
            "       autotask_company_name, autotask_homepage_url, "
            "       updated_at, updated_by_operator_id "
            "  FROM autotask_tenant_company_map "
            " WHERE adapter_instance_id = ? "
            " ORDER BY tenant_slug",
            (instance_id,),
        ).fetchall()
    finally:
        reg.close()
    return TenantMappingsResponse(
        instance_id=instance_id,
        mappings=[TenantMapping(**dict(r)) for r in rows],
    )


@router.put(
    "/{instance_id}/mappings/companies",
    response_model=TenantMappingsResponse,
)
def put_tenant_mappings(
    instance_id: int,
    body: TenantMappingsPutRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(session_super_admin),
) -> TenantMappingsResponse:
    """Bulk-replace tenant mappings — same shape as the operator
    endpoint above."""
    seen_slugs: set[str] = set()
    for m in body.mappings:
        if m.tenant_slug in seen_slugs:
            raise APIError(
                "VALIDATION_FAILED",
                f"duplicate tenant_slug {m.tenant_slug!r} in request",
            )
        seen_slugs.add(m.tenant_slug)
        # Light URL validation — we don't want to bake a regex but
        # 'http' prefix check filters the most common operator
        # typos. Detail validation happens at click-through time.
        if m.autotask_homepage_url is not None:
            if not (m.autotask_homepage_url.startswith("http://")
                    or m.autotask_homepage_url.startswith("https://")):
                raise APIError(
                    "VALIDATION_FAILED",
                    f"autotask_homepage_url for tenant {m.tenant_slug!r} "
                    "must start with http:// or https://",
                )

    request_id = str(uuid.uuid4())
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        before_rows = reg.execute(
            "SELECT tenant_slug, autotask_company_id "
            "  FROM autotask_tenant_company_map "
            " WHERE adapter_instance_id = ?",
            (instance_id,),
        ).fetchall()
        before_state = {r["tenant_slug"]: r["autotask_company_id"]
                        for r in before_rows}

        # One transaction: a reader (the daily location proposals) never
        # sees the map half-saved — empty, or missing the rows not yet
        # re-inserted.
        with transaction(reg):
            reg.execute(
                "DELETE FROM autotask_tenant_company_map "
                " WHERE adapter_instance_id = ?", (instance_id,),
            )
            for m in body.mappings:
                reg.execute(
                    "INSERT INTO autotask_tenant_company_map "
                    "(adapter_instance_id, tenant_slug, autotask_company_id, "
                    " autotask_company_name, autotask_homepage_url, "
                    " updated_by_operator_id) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (instance_id, m.tenant_slug, m.autotask_company_id,
                     m.autotask_company_name, m.autotask_homepage_url,
                     info.operator_id),
                )

        after_rows = reg.execute(
            "SELECT tenant_slug, autotask_company_id, "
            "       autotask_company_name, autotask_homepage_url, "
            "       updated_at, updated_by_operator_id "
            "  FROM autotask_tenant_company_map "
            " WHERE adapter_instance_id = ? "
            " ORDER BY tenant_slug",
            (instance_id,),
        ).fetchall()
        after_state = {r["tenant_slug"]: r["autotask_company_id"]
                       for r in after_rows}
    finally:
        reg.close()

    _audit_append(
        "integrations.autotask.tenant_map_replace",
        actor=f"operator:{info.operator_id}",
        target_id=f"adapter_instance:{instance_id}",
        before={"mappings": before_state},
        after={"mappings": after_state, "session_id_prefix": info.id[:8]},
        reason="Autotask tenant mapping bulk-replace",
        request_id=request_id,
    )

    return TenantMappingsResponse(
        instance_id=instance_id,
        mappings=[TenantMapping(**dict(r)) for r in after_rows],
    )


# ---------------------------------------------------------------------------
# Proxy: fetch Autotask companies + resources for the mapping UI dropdowns
# ---------------------------------------------------------------------------

def _build_client_for_instance(instance_id: int) -> AutotaskClient:
    """Resolve the configured instance → AutotaskClient with creds
    loaded from the bundle vault + zone re-resolved."""
    record = instance_manager.get_instance(instance_id)
    if record is None or record.vendor_slug != "autotask":
        raise APIError(
            "VALIDATION_FAILED",
            f"adapter_instance {instance_id} is not a configured Autotask integration",
        )
    try:
        creds = credentials_vault.load(record.cred_ref)
    except Exception as e:
        raise APIError(
            "VALIDATION_FAILED",
            f"failed to load credentials for instance {instance_id}: {e}",
        )

    username = (creds.get("AUTOTASK_USERNAME") or "").strip()
    secret = creds.get("AUTOTASK_SECRET") or ""
    integration_code = (creds.get("AUTOTASK_INTEGRATION_CODE") or "").strip()
    zone_url = (creds.get("AUTOTASK_ZONE_URL") or "").strip()
    if not zone_url:
        # Re-resolve on the fly. Cheap (unauthenticated) and avoids
        # caching the zone-URL ourselves; the credentials vault is
        # the source of truth.
        zone_url = resolve_zone(username)

    cfg = AutotaskConfig(
        username=username,
        secret=secret,
        integration_code=integration_code,
        zone_url=zone_url,
    )
    return AutotaskClient(cfg)


class AutotaskCompanyOption(BaseModel):
    id: int
    name: Optional[str] = None


class AutotaskCompaniesResponse(BaseModel):
    items: list[AutotaskCompanyOption]


@router.get(
    "/{instance_id}/companies",
    response_model=AutotaskCompaniesResponse,
)
def list_autotask_companies(
    instance_id: int,
    request: Request,
    info: sessions.SessionInfo = Depends(session_super_admin),
) -> AutotaskCompaniesResponse:
    """Proxy `/V1.0/Companies/query` against this instance's
    Autotask integration. Returns up to 500 companies for the
    mapping-UI dropdown. Auth failures surface as 401; everything
    else is wrapped with operator-actionable detail."""
    client = _build_client_for_instance(instance_id)
    try:
        envelope = client._query("Companies", {  # noqa: SLF001 — intentional
            "filter": [{"op": "gte", "field": "id", "value": 0}],
            "MaxRecords": 500,
        })
    except (AutotaskAuthError, AutotaskClientError, AutotaskZoneError) as e:
        # Any Autotask-side failure surfaces as VALIDATION_FAILED with
        # the detail message intact. The UI shows "Connection error:
        # <detail>" — operator's path is to revisit the integration
        # settings, not retry indefinitely. 422 matches the
        # adapter-bedrock convention for "stored config no longer
        # works against the live vendor."
        raise APIError("VALIDATION_FAILED", str(e))

    items: list[AutotaskCompanyOption] = []
    raw_items = envelope.get("items") if isinstance(envelope, dict) else None
    if isinstance(raw_items, list):
        for r in raw_items:
            if not isinstance(r, dict):
                continue
            rid = r.get("id")
            if isinstance(rid, int):
                items.append(AutotaskCompanyOption(
                    id=rid,
                    name=r.get("companyName"),
                ))
    items.sort(key=lambda c: (c.name or "").lower())
    return AutotaskCompaniesResponse(items=items)


class AutotaskResourceOption(BaseModel):
    id: int
    email: Optional[str] = None
    name: Optional[str] = None


class AutotaskResourcesResponse(BaseModel):
    items: list[AutotaskResourceOption]


@router.get(
    "/{instance_id}/resources",
    response_model=AutotaskResourcesResponse,
)
def list_autotask_resources(
    instance_id: int,
    request: Request,
    info: sessions.SessionInfo = Depends(session_super_admin),
) -> AutotaskResourcesResponse:
    """Proxy `/V1.0/Resources/query` for the operator-mapping UI's
    Autotask Resource picker."""
    client = _build_client_for_instance(instance_id)
    try:
        envelope = client._query("Resources", {  # noqa: SLF001 — intentional
            "filter": [{"op": "gte", "field": "id", "value": 0}],
            "MaxRecords": 500,
        })
    except (AutotaskAuthError, AutotaskClientError, AutotaskZoneError) as e:
        # Any Autotask-side failure surfaces as VALIDATION_FAILED with
        # the detail message intact. The UI shows "Connection error:
        # <detail>" — operator's path is to revisit the integration
        # settings, not retry indefinitely. 422 matches the
        # adapter-bedrock convention for "stored config no longer
        # works against the live vendor."
        raise APIError("VALIDATION_FAILED", str(e))

    items: list[AutotaskResourceOption] = []
    raw_items = envelope.get("items") if isinstance(envelope, dict) else None
    if isinstance(raw_items, list):
        for r in raw_items:
            if not isinstance(r, dict):
                continue
            rid = r.get("id")
            if not isinstance(rid, int):
                continue
            # Autotask Resources have `firstName` + `lastName`; surface
            # a single `name` field in "Last, First" format to match
            # Autotask's own UI convention.
            first = (r.get("firstName") or "").strip()
            last = (r.get("lastName") or "").strip()
            display = f"{last}, {first}" if last or first else None
            items.append(AutotaskResourceOption(
                id=rid,
                email=r.get("email"),
                name=display,
            ))
    items.sort(key=lambda r: (r.name or "").lower())
    return AutotaskResourcesResponse(items=items)
