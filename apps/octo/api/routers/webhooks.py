"""POST /api/v1/webhooks/{vendor_slug} — inbound vendor delivery webhooks.

Public endpoint (no operator session): authenticity is established by the
vendor's webhook signature, verified against the per-instance signing secret
stored in the credential vault — not by a bearer/session. v1 implements the
``resend`` vendor; the path is vendor-keyed so future push adapters slot in.

Flow per request:
  1. Look up the active (non-disabled) adapter instance for the slug.
  2. Load its decrypted creds and REQUIRE proof of the per-instance webhook
     secret (Resend: Svix signature within a ±5 min replay window; Datto:
     shared token header). FAIL CLOSED: no instance, an unreadable vault, and
     an unset or unusable secret are all the SAME generic 401 as a wrong
     token — an unverified request is never accepted, the status never
     reveals which integrations exist, and there is no dev bypass. The real
     reason is logged for the operator.
  3. Normalize the payload via the adapter, route to a tenant, and ingest.

A verified event whose tenant cannot be attributed is never dropped: the
platform resolves it (``instances.tenant_autocreate.deliver`` — tenant map →
same-name suggestion (held) → auto-create → quarantine) and answers 202 with
``ingested: false`` + the hold reason when it was quarantined, so the vendor
does not retry what a human will route. Genuine persistence failures for a
known tenant raise (5xx) so the vendor retries.

Datto is a DOORBELL (see ``adapters.datto.doorbell``): the body is read for
the alert uid (and raised/resolved), the full alert is fetched from Datto's
API through the running instance and stored — the poller's shape, so the two
doors agree and the sink collapses the copies. The fetch runs synchronously
inside the request, bounded (``instances.doorbell``): one per uid per minute,
an instance budget, a deadline well under the vendor's patience. When it is
not possible, a body that parsed is stored as sent (as before); a body that
did not is answered 202 'unresolvable' — never a 5xx for Athena's own lookup
failure, which would only make the vendor retry a request that cannot get
better.

Every outcome on a vendor's own webhook URL is also noted per instance in
``instances.webhook_receipt`` (accepted / rejected + a coarse reason class),
so the Integrations card can tell "rejected here" from "never arrived here" —
the second one is an edge problem, not an Athena one. That bookkeeping is
memory-only on this path and cannot fail or delay a response.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, Request

from apps.octo import credentials
from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.adapters.datto import doorbell as datto_doorbell
from apps.octo.adapters.datto.job_output import JobOutputStore, normalize_job_output
from apps.octo.adapters.resend import ResendSourceAdapter
from apps.octo.api.errors import APIError
from apps.octo.ingest import SqliteIngestSink
from apps.octo.instances import (
    InstanceRecord, doorbell, list_instances, tenant_autocreate, tenant_map,
    webhook_receipt,
)
from apps.octo.instances.webhook_auth import (
    REPLACE_HINT,
    TOKEN_HEADER,
    WEBHOOK_SECRET_FIELDS,
    configured_secret,
    secret_problem,
    svix_key,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

_MAX_BODY_BYTES = 1_000_000  # 1 MB — delivery webhooks are small JSON
_SVIX_TOLERANCE_SEC = 300    # Svix reference tolerance: ±5 minutes


def _active_instance(vendor_slug: str) -> Optional[InstanceRecord]:
    for record in list_instances(include_disabled=False):
        if record.vendor_slug == vendor_slug:
            return record
    return None


def _rejected() -> APIError:
    """THE reject. Every pre-auth failure on these session-less routes — no
    instance, unreadable vault, unset/unusable secret, bad token or signature
    — answers with this one generic 401, so an unauthenticated caller learns
    nothing about which integrations exist or how they are configured. The
    operator-facing reason always goes to the log instead."""
    return APIError("AUTH_INVALID", "webhook authentication failed")


def _note_rejected(
    route: str, instance: Any, reason: webhook_receipt.RejectReason,
) -> None:
    """Receipt bookkeeping for a vendor's OWN webhook URL (route == vendor
    slug). Sub-routes are left out on purpose: the job-output relay is posted
    to by endpoints, which says nothing about whether the vendor's cloud can
    reach the ingest hostname."""
    if route in WEBHOOK_SECRET_FIELDS:
        webhook_receipt.record_rejected(getattr(instance, "id", None), reason)


def _proof_failed(
    route: str, what: str, instance: Any = None,
    reason: webhook_receipt.RejectReason = "bad_token",
) -> APIError:
    """The secret is fine but the request's proof isn't. Logged (never the
    presented value) so '401 with the right config' is diagnosable: a sender
    using the wrong token, a clock more than 5 min off, or a replay."""
    logger.warning(
        "[webhook:%s] REJECTED — %s did not verify against the configured secret",
        route, what,
    )
    _note_rejected(route, instance, reason)
    return _rejected()


def _require_instance(route: str, vendor_slug: str) -> InstanceRecord:
    """The active instance for the vendor, or the generic 401 (NOT a 404:
    a distinct status let anyone enumerate the configured integrations)."""
    instance = _active_instance(vendor_slug)
    if instance is None:
        logger.warning(
            "[webhook:%s] REJECTED — no active %s integration is configured, "
            "so there is no secret to verify inbound requests against. If this "
            "sender is expected, create the integration under Settings → "
            "Integrations.",
            route, vendor_slug,
        )
        raise _rejected()
    return instance


def _require_secret(
    route: str, vendor_slug: str, field: str, instance: InstanceRecord
) -> str:
    """Return the instance's webhook secret, or 401 when there is no USABLE one.

    Fail closed: these routes are reachable without a session, so a missing
    or unusable secret must never degrade to "accept unverified". The caller
    gets the same generic 401 as a bad token (no config-state oracle); the
    operator gets a log line that says exactly what to fix. "Usable" is
    `webhook_auth.secret_problem` — the same check the Integrations warning
    uses, so the log and the UI cannot disagree.
    """
    instance_id = getattr(instance, "id", "?")
    try:
        creds = credentials.load(instance.cred_ref)
    except Exception:
        # Key-version mismatch / missing key file. Without this the request
        # died as a bare text 500 (which vendors also retry). Logged with the
        # traceback — vault errors name the key file/version, never a value.
        logger.exception(
            "[webhook:%s] REJECTED — stored credentials for the active %s "
            "integration (instance id=%s) could not be read from the vault, so "
            "inbound requests cannot be verified. Check that the adapter "
            "credentials key file is present and matches the key version the "
            "instance was saved with; failing that: %s",
            route, vendor_slug, instance_id, REPLACE_HINT,
        )
        _note_rejected(route, instance, "not_configured")
        raise _rejected()

    problem = secret_problem(creds, field)
    if problem:
        # Value-free by construction: `field` is the credential's NAME from
        # WEBHOOK_SECRET_FIELDS (e.g. RESEND_WEBHOOK_SECRET) and `problem` is
        # one of secret_problem's fixed phrases. No part of the stored or the
        # presented secret — not even a prefix — is ever logged on any path
        # here (tests/test_webhook_log_hygiene.py).
        logger.error(
            "[webhook:%s] REJECTED — %s %s on the active %s integration "
            "(instance id=%s), so inbound requests cannot be verified. Fix: %s "
            "Use the same value on the sender.",
            route, field, problem, vendor_slug, instance_id, REPLACE_HINT,
        )
        _note_rejected(route, instance, "not_configured")
        raise _rejected()
    return configured_secret(creds, field)


def _token_matches(presented: Optional[str], secret: str) -> bool:
    """Constant-time shared-token check. Compared as bytes so a non-ASCII
    header value is a clean mismatch rather than a TypeError (→ 500)."""
    return hmac.compare_digest((presented or "").encode(), secret.encode())


def _verify_svix_signature(
    secret: str, headers: Any, body_bytes: bytes
) -> bool:
    """True when the Svix/Resend signature verifies (see `_svix_failure`)."""
    return _svix_failure(secret, headers, body_bytes) is None


def _svix_failure(
    secret: str, headers: Any, body_bytes: bytes
) -> Optional[webhook_receipt.RejectReason]:
    """Verify a Svix/Resend webhook signature: None when it verifies, else
    the receipt reason class — 'replay_window' for a malformed or stale
    timestamp, 'bad_token' for everything else (missing headers included).
    The caller answers the same generic 401 either way; the class only ever
    reaches the operator's card.

    signed content = "{id}.{timestamp}.{body}"; signature is base64 HMAC-SHA256
    keyed by the base64-decoded portion after the ``whsec_`` prefix. The
    ``svix-signature`` header carries one or more space-separated ``v1,<sig>``
    entries; any match passes.

    Replay window: the timestamp is part of the signed content, so it cannot
    be altered — but without a freshness check one captured request (a proxy
    log, a body dump) could be re-injected forever. Like the Svix reference
    implementation, reject when the timestamp is not an integer or is more
    than ``_SVIX_TOLERANCE_SEC`` from now in EITHER direction.
    """
    svix_id = headers.get("svix-id") or headers.get("webhook-id")
    svix_ts = headers.get("svix-timestamp") or headers.get("webhook-timestamp")
    svix_sig = headers.get("svix-signature") or headers.get("webhook-signature")
    if not (svix_id and svix_ts and svix_sig):
        return "bad_token"

    # isdecimal + ASCII: int() alone would also take '+5', ' 5 ', '5_0' and
    # non-ASCII digits, none of which a real sender emits.
    # length cap: int() of a multi-thousand-digit string raises ValueError
    # (int-max-str-digits) → an unauthenticated 500
    if not (len(svix_ts) <= 12 and svix_ts.isascii() and svix_ts.isdecimal()):
        return "replay_window"
    if abs(time.time() - int(svix_ts)) > _SVIX_TOLERANCE_SEC:
        return "replay_window"

    key = svix_key(secret)
    if key is None:
        # Unreachable via the routes (_require_secret already refused an
        # unusable secret, loudly); kept so this function is safe on its own.
        return "bad_token"

    signed = f"{svix_id}.{svix_ts}.".encode() + body_bytes
    expected = base64.b64encode(
        hmac.new(key, signed, hashlib.sha256).digest()
    ).decode()

    for entry in svix_sig.split(" "):
        candidate = entry.split(",", 1)[1] if "," in entry else entry
        if hmac.compare_digest(candidate.encode(), expected.encode()):
            return None
    return "bad_token"


def _parse_verified(
    route: str, instance: InstanceRecord, body_bytes: bytes
) -> dict[str, Any]:
    """`_parse_envelope` for a request that has already proved itself: a bad
    body is noted on the instance's receipts before the 422 goes out."""
    try:
        return _parse_envelope(body_bytes)
    except APIError:
        _note_rejected(route, instance, "malformed")
        raise


def _parse_envelope(body_bytes: bytes) -> dict[str, Any]:
    if len(body_bytes) > _MAX_BODY_BYTES:
        raise APIError("VALIDATION_FAILED", "webhook body too large")
    try:
        envelope = json.loads(body_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise APIError("VALIDATION_FAILED", f"invalid webhook body: {exc}")
    if not isinstance(envelope, dict):
        raise APIError("VALIDATION_FAILED", "webhook body is not a JSON object")
    return envelope


def _route_and_ingest(
    adapter: Any, vendor_slug: str, envelope: dict[str, Any], instance: InstanceRecord
) -> dict[str, Any]:
    """Shared tail for every vendor webhook: route → extract → ingest.

    With a persisted instance the platform resolves the tenant (tenant map →
    same-name suggestion (held) → auto-create → quarantine) and nothing is dropped: a held
    event answers 202 ``ingested: false`` with its ``reason`` so the vendor
    does not retry what a human will route. Without an instance id (a
    record built outside the registry) the legacy pass-through applies.
    """
    instance_id = getattr(instance, "id", None)
    event = adapter.extract_event(envelope)
    if instance_id is not None:
        try:
            delivery = tenant_autocreate.deliver(
                instance_id=instance_id,
                vendor_slug=vendor_slug,
                adapter=adapter,
                envelope=envelope,
                event=event,
                sink=SqliteIngestSink(),
                default_tenant_slug=instance.default_tenant_slug or None,
                door="webhook",
            )
        except Exception:
            # Still a 5xx (the vendor retries) — but the request DID reach
            # Athena and verify, and the card must not go on saying that none has.
            webhook_receipt.record_rejected(instance_id, "store_failed")
            raise
        if delivery.status == "quarantined":
            # Received, verified and STORED (in quarantine): that is an
            # accepted webhook for the card's "last received" — the held
            # count is stated once, by the card's lifecycle line, not again
            # as a rejection. (Datto's Test Webhook holds every time; it
            # must not read as a failing endpoint.)
            webhook_receipt.record_accepted(instance_id)
            if delivery.quarantine_created:
                logger.warning(
                    "[webhook:%s] HELD event %s in quarantine (%s) — it could not be "
                    "attributed to a tenant. It stays held until a human routes or "
                    "discards it under Settings → Tenants → Quarantine.",
                    vendor_slug, event.vendor_event_id, delivery.reason,
                )
            return {
                "status": "accepted", "ingested": False,
                "reason": "quarantined", "quarantine_reason": delivery.reason,
            }
        webhook_receipt.record_accepted(instance_id)
        return {
            "status": "accepted",
            "ingested": True,
            "tenant": delivery.slug,
            "event_id": event.vendor_event_id,
            "idempotent": delivery.status == "duplicate",
            "routing": delivery.outcome,
        }

    # Legacy pass-through (no persisted instance): vendor id → mapping → raw
    # id → instance default.
    vendor_tid = adapter.route_to_tenant(envelope)
    tenant = (
        tenant_map.resolve(instance_id, vendor_tid)
        or vendor_tid
        or instance.default_tenant_slug
    )
    if not tenant:
        logger.warning(
            "[webhook:%s] event has no tenant id and no instance default", vendor_slug,
        )
        return {"status": "accepted", "ingested": False, "reason": "unroutable"}
    try:
        outcome = SqliteIngestSink().ingest(tenant, vendor_slug, event)
    except FileNotFoundError:
        logger.warning(
            "[webhook:%s] event %s — tenant %r is not provisioned",
            vendor_slug, event.vendor_event_id, tenant,
        )
        return {"status": "accepted", "ingested": False, "reason": "tenant-not-provisioned"}
    return {
        "status": "accepted",
        "ingested": True,
        "tenant": tenant,
        "event_id": event.vendor_event_id,
        # True when the sink already held this exact event (vendor retry /
        # replay) — nothing new was written.
        "idempotent": bool(getattr(outcome, "duplicate", False)),
    }


@router.post("/resend")
async def resend_webhook(request: Request) -> dict[str, Any]:
    body_bytes = await request.body()
    instance = _require_instance("resend", "resend")
    secret = _require_secret(
        "resend", "resend", WEBHOOK_SECRET_FIELDS["resend"], instance
    )
    failure = _svix_failure(secret, request.headers, body_bytes)
    if failure is not None:
        raise _proof_failed(
            "resend", "the Svix signature (or its ±5 min timestamp window)",
            instance, failure,
        )

    envelope = _parse_verified("resend", instance, body_bytes)
    return _route_and_ingest(ResendSourceAdapter(), "resend", envelope, instance)


@router.post("/datto")
async def datto_webhook(request: Request) -> dict[str, Any]:
    """Datto RMM alert raised/resolved webhook. Datto RMM has no signature
    scheme, so authenticity is a shared token the operator also configures on
    the Datto webhook as the `X-Webhook-Token` header, compared against the
    instance's DATTO_WEBHOOK_SECRET. Header only — a `?token=` query param
    would put the secret in URLs, proxy access logs and vendor-side config
    exports, so it is deliberately not accepted.

    Once verified the request is a DOORBELL (module docstring): the alert it
    names is fetched from Datto and stored in the poller's shape. The
    response says which copy was stored — ``"via": "api"`` (fetched) or
    ``"via": "template"`` (the body as sent, because the fetch was not
    possible) — so Datto's own test result tells the operator which path ran.
    """
    body_bytes = await request.body()
    instance = _require_instance("datto", "datto")
    secret = _require_secret(
        "datto", "datto", WEBHOOK_SECRET_FIELDS["datto"], instance
    )
    if not _token_matches(request.headers.get(TOKEN_HEADER.lower()), secret):
        raise _proof_failed("datto", "the X-Webhook-Token header", instance)

    envelope, bell = _datto_envelope("datto", instance, body_bytes)
    fetched = (
        await _datto_doorbell_fetch(request, instance, bell)
        if bell.alert_uid is not None else None
    )
    if fetched is not None:
        result = _route_and_ingest(DattoSourceAdapter(), "datto", fetched, instance)
        return {**result, "via": "api"}
    if envelope is not None:
        # The templated body, as before: still routable and readable on its
        # own when it follows the guide (ids + short labels).
        result = _route_and_ingest(DattoSourceAdapter(), "datto", envelope, instance)
        return {**result, "via": "template"}
    # Not JSON, but it named an alert — and that alert could not be fetched.
    # A 202: the vendor must not retry a body that will never parse, and a
    # 5xx for Athena's own lookup failure would make it do exactly that.
    instance_id = getattr(instance, "id", None)
    webhook_receipt.record_rejected(instance_id, "unresolvable")
    logger.warning(
        "[webhook:datto] DROPPED doorbell for alert %s — the body was not "
        "valid JSON and the alert could not be fetched from Datto (see the "
        "lines above; not stored anywhere). Switch the webhook body to the "
        "ID-only template from the Setup guide so it always parses.",
        bell.alert_uid,
    )
    return {"status": "accepted", "ingested": False, "reason": "unresolvable"}


def _datto_envelope(
    route: str, instance: InstanceRecord, body_bytes: bytes,
) -> tuple[Optional[dict[str, Any]], datto_doorbell.Doorbell]:
    """(parsed body, doorbell). The body when it IS a JSON object, with the
    bell read from its fields; otherwise None, with the bell read by a strict
    scan of the raw text — a body that yields neither is the 422 'malformed'
    it always was (so is one over the size limit: it is not scanned)."""
    try:
        envelope = _parse_envelope(body_bytes)
    except APIError as exc:
        if len(body_bytes) > _MAX_BODY_BYTES:
            _note_rejected(route, instance, "malformed")
            raise
        bell = datto_doorbell.read_raw(body_bytes)
        if bell.alert_uid is None:
            _note_rejected(route, instance, "malformed")
            # The parser's own words (position only, never content) plus the
            # fix — this is what the vendor's test tool shows the operator.
            raise APIError(
                exc.code,
                f"{exc.message}; the body names no alertUid either — switch "
                "the webhook body to the ID-only template from the Setup guide",
            ) from None
        logger.info(
            "[webhook:%s] body is not valid JSON but names alert %s — used as "
            "a doorbell (the vendor does not JSON-escape template variables; "
            "switch to the ID-only template from the Setup guide)",
            route, bell.alert_uid,
        )
        return None, bell
    return envelope, datto_doorbell.read_envelope(envelope)


def _running_adapter(request: Any, instance_id: Optional[int]) -> Any:
    """The live adapter of a running instance, or None (not running, or no
    manager in this process)."""
    state = getattr(getattr(request, "app", None), "state", None)
    manager = getattr(state, "instance_manager", None)
    if manager is None or instance_id is None:
        return None
    return manager.running_adapter(instance_id)


_MAX_FLIGHTS = 4096


def _doorbell_flight(request: Any, instance_id: int, alert_uid: str) -> asyncio.Lock:
    """One lock per (instance, alert): concurrent rings for one alert wait
    for the first fetch and reuse it, while one slow fetch never queues rings
    for OTHER alerts behind it (the instance budget bounds the total). On
    app.state because an asyncio.Lock belongs to the loop that serves the
    app; idle locks are dropped when the table fills."""
    state = getattr(getattr(request, "app", None), "state", None)
    if state is None:
        return asyncio.Lock()      # no app (a unit test's bare request): unshared
    locks = getattr(state, "doorbell_flights", None)
    if locks is None:
        locks = state.doorbell_flights = {}
    key = (instance_id, alert_uid)
    lock = locks.get(key)
    if lock is None:
        if len(locks) >= _MAX_FLIGHTS:
            for idle in [k for k, held in locks.items() if not held.locked()]:
                del locks[idle]
        lock = locks[key] = asyncio.Lock()
    return lock


async def _datto_doorbell_fetch(
    request: Any, instance: InstanceRecord, bell: datto_doorbell.Doorbell,
) -> Optional[dict[str, Any]]:
    """The alert the bell names, as Datto's API holds it, delivered as the
    bell reports it (raised / resolved) — or None when the fetch is not
    possible (logged; the caller falls back). Never raises."""
    instance_id = getattr(instance, "id", None)
    uid = bell.alert_uid
    assert uid is not None
    adapter = _running_adapter(request, instance_id)
    fetch = getattr(adapter, "fetch_alert", None)
    if not callable(fetch):
        logger.info(
            "[webhook:datto] alert %s not fetched — the integration is not "
            "running in this process; the webhook body is used as sent", uid,
        )
        return None

    known = doorbell.recent(instance_id, uid)
    if known is None:
        async with _doorbell_flight(request, instance_id or 0, uid):
            known = doorbell.recent(instance_id, uid)   # whoever held the lock
            if known is None:
                known = await _ask_datto(instance_id, uid, fetch)
    if known is None or known.alert is None:
        return None
    return datto_doorbell.as_delivered(known.alert, bell)


async def _ask_datto(
    instance_id: Optional[int], uid: str, fetch: Any,
) -> Optional[doorbell.Remembered]:
    """ONE vendor read for `uid` (caller holds its flight lock), remembered
    for the per-uid window whatever it yields. None — nothing remembered —
    when the instance budget is spent: a later ring may fit."""
    wait = doorbell.take_fetch(instance_id)
    if wait:
        logger.warning(
            "[webhook:datto] alert %s not fetched — this integration's fetch "
            "budget (%d/min) is spent; retry possible in %ds. Webhook bodies "
            "are used as sent meanwhile.",
            uid, doorbell.FETCHES_PER_MINUTE, wait,
        )
        return None
    try:
        # Blocking network IO on a thread, bounded: the vendor is waiting for
        # its 2xx. The client's own read timeout is shorter than the deadline,
        # so a slow vendor normally surfaces as a transport failure first.
        alert = await asyncio.wait_for(
            asyncio.to_thread(fetch, uid, timeout_seconds=doorbell.FETCH_TIMEOUT_SEC),
            timeout=doorbell.FETCH_DEADLINE_SEC,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "[webhook:datto] alert %s not fetched — Datto did not answer within "
            "%.0fs (not asked again for %.0fs)",
            uid, doorbell.FETCH_DEADLINE_SEC, doorbell.PER_ID_WINDOW_SEC,
        )
        doorbell.remember(instance_id, uid, failure="timeout")
        return doorbell.Remembered(None, "timeout")
    except doorbell.AlertFetchError as exc:
        logger.warning(
            "[webhook:datto] alert %s not fetched (%s): %s (not asked again "
            "for %.0fs)", uid, exc.kind, exc.message, doorbell.PER_ID_WINDOW_SEC,
        )
        doorbell.remember(instance_id, uid, failure=exc.kind)
        return doorbell.Remembered(None, exc.kind)
    except Exception as exc:  # noqa: BLE001 — an adapter bug, not a vendor answer
        # Class name only: an exception's text can embed what it was given.
        logger.error(
            "[webhook:datto] alert %s not fetched — the adapter raised %s",
            uid, type(exc).__name__,
        )
        doorbell.remember(instance_id, uid, failure="transport")
        return doorbell.Remembered(None, "transport")
    if not isinstance(alert, dict):
        logger.error(
            "[webhook:datto] alert %s not fetched — the adapter answered with "
            "something that is not an alert object", uid,
        )
        doorbell.remember(instance_id, uid, failure="transport")
        return doorbell.Remembered(None, "transport")
    logger.info(
        "[webhook:datto] alert %s fetched from Datto for the doorbell", uid,
    )
    doorbell.remember(instance_id, uid, alert=alert)
    return doorbell.Remembered(alert, None)


@router.post("/datto/job-output")
async def datto_job_output(request: Request) -> dict[str, Any]:
    """Datto RMM quick-job output relay sink.

    Datto's API does not return quick-job stdout; the job-wrapper
    (``adapters.datto.job_output.build_relay_wrapper``) POSTs the captured
    stdout/stderr here so output can be read without an RMM-UI download.
    Authenticity is a **scoped, write-only token** (``DATTO_JOB_OUTPUT_TOKEN``),
    distinct from the alert-webhook secret so it can be rotated independently
    and is the only secret embedded on endpoints. Stored keyed by ``jobUid``.

    Same fail-closed rule as every route here: a missing token is a hard
    reject, and the token is read from the `X-Webhook-Token` header only
    (the relay wrapper never used the query-param form).
    """
    body_bytes = await request.body()
    instance = _require_instance("datto-job-output", "datto")
    secret = _require_secret(
        "datto-job-output", "datto", "DATTO_JOB_OUTPUT_TOKEN", instance
    )
    if not _token_matches(request.headers.get(TOKEN_HEADER.lower()), secret):
        raise _proof_failed("datto-job-output", "the X-Webhook-Token header")

    envelope = _parse_envelope(body_bytes)
    record = normalize_job_output(envelope)
    JobOutputStore.default().save(record)
    logger.info(
        "[webhook:datto-job-output] stored job=%s host=%s exit=%s "
        "(stdout=%dc stderr=%dc, %d secret-shaped value(s) redacted)",
        record.job_uid or "?", record.hostname or "?", record.exit_code,
        len(record.stdout), len(record.stderr), record.redactions,
    )
    return {"status": "accepted", "stored": True, "jobUid": record.job_uid}
