"""Ingestion endpoints — client-token bearer auth (ADR-0003 fresh build).

POST /api/v1/ingest/{slug}/events                — generic event ingest
                                                   (buoy-forwarder v2)
POST /api/v1/ingest/{slug}/{source_type}/alerts  — source-native alert ingest
                                                   (wazuh-octo-shim)

Ports the legacy ingestion surface onto bedrock so the bundle serves
ingest natively and the legacy service is never ported
(ADR-0003). Wire-compatible with the deployed buoy-forwarder v2 and
wazuh-octo-shim: callers change only host + token.

Auth: ``Authorization: Bearer <client-token>`` resolved against
``registry.client_tokens`` (`apps.octo.auth.core.resolve_client_token`,
PBKDF2). A small TTL cache keyed by token digest avoids the legacy design's
per-request 600k-iteration PBKDF2 burn (~0.3 s CPU per request at 3 req/s =
~a full core); the trade is that revoking a token takes effect up to
``_TOKEN_CACHE_TTL_SEC`` late on a hot token — acceptable for machine
ingest tokens (revocation is paired with stopping the sender).

Deltas from the legacy pipeline, documented per the ADR keep/toss review:
  - guard sanitization is NOT yet ported (legacy `octo_admin.guard`) —
    tracked as a fresh-build follow-up;
  - incident auto-open on high/critical is NOT yet ported (bedrock incidents
    flow via the triage worker instead);
  - `/ingest/{slug}/indicators` is NOT ported (zero live callers — all
    tenant indicators.db rows are empty since 2026-04).
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, Request

from apps.octo import paths
from apps.octo.adapters.wazuh import WazuhSourceAdapter
from apps.octo.api.errors import APIError
from apps.octo.api.models import (
    EventIngest,
    IngestResult,
    SourceAlertIngest,
    SourceIngestResult,
)
from apps.octo.auth import core as auth_core
from apps.octo.ingest import SqliteIngestSink
from apps.octo.ingest.tiering import TELEMETRY
from apps.octo.instances import freshness
from shared_adapter_contract.types import CanonicalEvent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])

_MAX_BODY_BYTES = 1_000_000  # 1 MB — single events/alerts are small JSON.

# Idempotency for the alerts path. Dedup key = (source, payload_sha256,
# stored vendor timestamp) at ANY age: payload_sha256 covers the whole raw
# envelope (vendor id + timestamp included), so only a byte-identical
# replay — shim retry, cursor replay after an outage/cutover — collapses.
# The guard itself lives in SqliteIngestSink so every writer shares it.

# ---------------------------------------------------------------------------
# Token resolution + TTL cache
# ---------------------------------------------------------------------------

_TOKEN_CACHE_TTL_SEC = 300
_TOKEN_CACHE_MAX = 512
_token_cache: dict[str, tuple[float, auth_core.TokenResolution]] = {}


def _cache_get(digest: str) -> Optional[auth_core.TokenResolution]:
    hit = _token_cache.get(digest)
    if hit is None:
        return None
    ts, res = hit
    if time.monotonic() - ts > _TOKEN_CACHE_TTL_SEC:
        _token_cache.pop(digest, None)
        return None
    return res


def _cache_put(digest: str, res: auth_core.TokenResolution) -> None:
    if len(_token_cache) >= _TOKEN_CACHE_MAX:
        # Drop expired entries first; if still over, drop oldest.
        now = time.monotonic()
        for key, (ts, _) in list(_token_cache.items()):
            if now - ts > _TOKEN_CACHE_TTL_SEC:
                _token_cache.pop(key, None)
        while len(_token_cache) >= _TOKEN_CACHE_MAX:
            oldest = min(_token_cache, key=lambda k: _token_cache[k][0])
            _token_cache.pop(oldest, None)
    _token_cache[digest] = (time.monotonic(), res)


def _registry_conn(read_only: bool = True) -> sqlite3.Connection:
    db_path = paths.registry_db_path()
    if read_only:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    else:
        conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def ingest_identity(
    slug: str, request: Request
) -> auth_core.TokenResolution:
    """Resolve + authorize the bearer for `{slug}` ingestion.

    Mirrors legacy semantics exactly:
      401 AUTH_MISSING / AUTH_INVALID — absent or unresolvable bearer
      403 ISOLATION_VIOLATION        — token slug ≠ URL slug
      404 CLIENT_NOT_FOUND           — unknown OR offboarded/archived
                                       (existence not leaked to stale bearers)
      423 CLIENT_DISABLED            — client ingestion paused
      413 PAYLOAD_TOO_LARGE          — body over 1 MB
    """
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > _MAX_BODY_BYTES:
                raise APIError("PAYLOAD_TOO_LARGE")
        except ValueError:
            raise APIError("VALIDATION_FAILED", "bad content-length")

    authz = request.headers.get("authorization", "")
    if not authz.startswith("Bearer ") or len(authz) <= len("Bearer "):
        raise APIError("AUTH_MISSING")
    plaintext = authz[len("Bearer "):].strip()

    digest = hashlib.sha256(plaintext.encode()).hexdigest()
    resolution = _cache_get(digest)
    if resolution is None:
        reg = _registry_conn(read_only=True)
        try:
            resolution = auth_core.resolve_client_token(reg, plaintext)
        except auth_core.AuthError:
            raise APIError("AUTH_INVALID")
        finally:
            reg.close()
        _cache_put(digest, resolution)

    if resolution.slug != slug:
        raise APIError("ISOLATION_VIOLATION")

    # Client lifecycle gates — read fresh every request (cheap indexed read;
    # disabling/offboarding a client must take effect immediately even for
    # cache-hot tokens).
    reg = _registry_conn(read_only=True)
    try:
        row = reg.execute(
            "SELECT status FROM clients WHERE slug = ?", (slug,)
        ).fetchone()
    finally:
        reg.close()
    if row is None or row["status"] in ("offboarded", "archived"):
        raise APIError("CLIENT_NOT_FOUND")
    if row["status"] == "disabled":
        raise APIError("CLIENT_DISABLED")

    # Liveness bookkeeping (debounced — one write per token per 5 min).
    # The body is not validated yet: this request may still be refused, so
    # source health compares it with the token's last ACCEPTED post.
    freshness.record_token_request(resolution.token_id)
    try:
        client_ip = request.client.host if request.client else None
        if auth_core.note_token_used(resolution.token_id, client_ip):
            reg_w = _registry_conn(read_only=False)
            try:
                auth_core.flush_last_used(reg_w)
            finally:
                reg_w.close()
    except Exception:  # noqa: BLE001 — liveness, never auth-fatal
        logger.debug("last-used flush failed", exc_info=True)

    return resolution


# ---------------------------------------------------------------------------
# Source-native alert normalizers
# ---------------------------------------------------------------------------

_wazuh_adapter = WazuhSourceAdapter()

_NORMALIZERS: dict[str, Callable[[dict[str, Any]], CanonicalEvent]] = {
    "wazuh": _wazuh_adapter.extract_event,
}

_EVENT_TYPE_BY_SOURCE: dict[str, str] = {
    "wazuh": "wazuh.alert",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ingest_source_label(label: Optional[str], fallback: str) -> str:
    """`events.source` for a post by a token labelled `label` (source health
    reads a token's stored events back by it after a restart)."""
    return f"buoy:{label or fallback}"


def _source_label(resolution: auth_core.TokenResolution, fallback: str) -> str:
    return ingest_source_label(resolution.label, fallback)


def _utcnow_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post(
    "/{slug}/events", response_model=IngestResult, status_code=202
)
def post_event(
    slug: str,
    body: EventIngest,
    identity: auth_core.TokenResolution = Depends(ingest_identity),
) -> IngestResult:
    """Generic event ingest — the buoy-forwarder v2 contract.

    No idempotency dedup on this path (matches legacy): telemetry events
    may legitimately repeat, and forwarders do not replay.

    Tiering (migration 036): answered DNS and TLS / HTTP / flow metadata are
    stored in the tenant's telemetry.db (`tier: "telemetry"`, the row id in
    `telemetry_id`); everything else — alerts, blocked DNS, honeypot hits,
    unknown types — in events.db as before (`tier: "signal"`, `event_id`).
    """
    data = body.data
    if body.event_type.startswith("opencanary."):
        # A decoy's tried SECRET is never stored (Tier Black R6): a person
        # may have typed a REAL password into it. The forwarder sends its
        # length only; an older forwarder's value is redacted here.
        from apps.octo.threat.evaluators import redact_canary_secrets

        data = redact_canary_secrets(data)
    payload = {
        "event_type": body.event_type,
        "severity": body.severity,
        **data,
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    sha = hashlib.sha256(canonical.encode()).hexdigest()
    source = _source_label(identity, "forwarder")

    idem_key = body.data.get("_idempotency_key")
    event = CanonicalEvent(
        vendor_event_id=str(idem_key) if idem_key else sha[:16],
        received_at=_utcnow_iso(),
        severity=body.severity,
        indicator=None,
        indicator_type=None,
        source_host=body.source_host,
        summary=body.event_type,
        payload=payload,
        payload_sha256=sha,
    )

    try:
        # dedup=False: received_at here is OUR receive clock, not a vendor
        # timestamp, and identical telemetry may legitimately repeat.
        # The sink files the event as a signal (events.db) or as telemetry
        # (telemetry.db) — `apps.octo.ingest.tiering`; a telemetry-store
        # failure falls back to events.db, so this request never fails for
        # the telemetry store's sake.
        outcome = SqliteIngestSink().ingest(
            slug, source, event, event_type=body.event_type, dedup=False
        )
    except FileNotFoundError:
        raise APIError("CLIENT_NOT_FOUND", "client not provisioned")
    telemetry = outcome.tier == TELEMETRY
    # Telemetry is traffic like any other: source health must see the buoy.
    freshness.record_event(slug=slug)
    freshness.record_token_post(
        identity.token_id, slug=slug,
        stored_event_id=None if telemetry else outcome.event_id,
        stored_telemetry_id=outcome.event_id if telemetry else None,
    )

    return IngestResult(
        ok=True,
        slug=slug,
        event_id=None if telemetry else outcome.event_id,
        telemetry_id=outcome.event_id if telemetry else None,
        tier=outcome.tier,
    )


@router.post(
    "/{slug}/{source_type}/alerts",
    response_model=SourceIngestResult,
    status_code=202,
)
def post_source_alert(
    slug: str,
    source_type: str,
    body: SourceAlertIngest,
    identity: auth_core.TokenResolution = Depends(ingest_identity),
) -> SourceIngestResult:
    """Source-native alert ingest — the wazuh-octo-shim contract.

    The registered normalizer maps the vendor envelope onto a
    CanonicalEvent; (source, payload_sha256, vendor timestamp) is the
    idempotency key at any age, so shim retries and cursor replays return
    ``idempotent=true`` without a duplicate row.
    """
    normalize = _NORMALIZERS.get(source_type)
    if normalize is None:
        raise APIError(
            "VALIDATION_FAILED", f"unsupported source_type {source_type!r}"
        )

    try:
        event = normalize(body.payload)
    except Exception as exc:  # noqa: BLE001 — vendor schema drift → 422
        raise APIError("VALIDATION_FAILED", f"payload rejected: {exc}")

    source = _source_label(identity, source_type)

    # Idempotency is the sink's guard (shared with the pollers and webhooks);
    # a replay comes back as duplicate=True carrying the existing row id.
    try:
        outcome = SqliteIngestSink().ingest(
            slug,
            source,
            event,
            event_type=_EVENT_TYPE_BY_SOURCE.get(source_type, "alert"),
        )
    except FileNotFoundError:
        raise APIError("CLIENT_NOT_FOUND", "client not provisioned")
    if not outcome.duplicate:
        # Tenant feed freshness (receive clock) for the source-health view.
        freshness.record_event(slug=slug)
    # The token's last ACCEPTED post — a replay counts (the sender works).
    # Its last_used_at (ingest_identity) is set before the body is even
    # validated, so it can't tell a working shim from a refused one. A new
    # row's id marks it as this process's (a replay's row is older).
    telemetry = outcome.tier == TELEMETRY
    new_id = None if outcome.duplicate else outcome.event_id
    freshness.record_token_post(
        identity.token_id, slug=slug,
        stored_event_id=None if telemetry else new_id,
        stored_telemetry_id=new_id if telemetry else None,
    )

    return SourceIngestResult(
        ok=True,
        slug=slug,
        source_type=source_type,
        source_instance_id=identity.source_instance_id or "",
        event_id=outcome.event_id,
        idempotent=outcome.duplicate,
        summary=event.summary,
        indicators_extracted=(
            1 if event.indicator and not outcome.duplicate else 0
        ),
    )
