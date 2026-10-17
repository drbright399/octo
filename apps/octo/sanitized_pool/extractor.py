"""Pool extractor — scaffolded, disabled-by-default.

The runtime that ties the M1-M9 safety envelope together on the WRITE
side. Scans per-tenant events.db for IOC candidates, validates them
via M1 + M7 + M8 (shapes), identifies the contributing tenant via M2
(HMAC), and writes pattern rows through M4 dual-write audit. Rejects
land in `sanitization_rejects` carrying the M3 `source_tenant_hmac`
column (NOT the plaintext slug — see migration 023 rationale).

Status: SCAFFOLDED. The extractor is disabled by default and stays
that way until:
  1. The L2 LLM container that will consume pool data is built (no
     point creating pool data with no consumer).
  2. The bundle's super_admin explicitly opts in via Settings →
     System → Sanitized Pool. The opt-in is recorded in
     `bundle_config.sanitized_pool_extractor_enabled` (JSON true).

Per-tenant disablement (Rick's instruction): a future enhancement
adds a per-tenant exclusion list — tenants who opt out are skipped
even when the global flag is on. v0 ships global flag only; the
per-tenant list lands when the Settings UI does. The `is_enabled()`
gate is the single chokepoint for that future check.

Candidate extraction (v0):
  Pulls IOCs from `events.payload` JSON where the payload carries an
  explicit `iocs` field — a list of objects `{type, value, subkind?}`.
  Real source-specific extractors (Datto EDR, Wazuh, RocketCyber)
  will plug in per-source parsers later; the v0 shape is the
  framework-level shape that buoy adapters can already emit.

Cursor + resumability:
  `pool_extractor_cursor` (migration 024) tracks `last_event_id` per
  tenant. Each run reads `WHERE id > cursor.last_event_id ORDER BY id
  ASC LIMIT max_events`, processes them, then advances the cursor in
  a single transaction. Crash before advance = next run retries the
  same range. Crash after advance = next run continues forward.
  Per-event idempotency is guaranteed by the `(ioc_type, ioc_value)`
  UNIQUE index on `patterns` plus tenant_hmac dedup in the
  `tenant_hmacs` JSON array.

Audit:
  Every pattern write + every reject write goes through M4
  `pool_audit.append()` so both the global audit chain and the
  contributing tenant's audit chain see the event. Cursor advances
  are NOT audited (they're internal bookkeeping, not pool writes).

Banked 2026-05-21 — Section B remaining substrate. The extractor is
the bridge between per-tenant data and the cross-tenant pool; every
control in the envelope flows through it.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable, Literal, Optional

from apps.octo import paths as octo_paths
from apps.octo.auth import audit as audit_mod
from apps.octo.db import connect
from apps.octo.sanitized_pool import audit as pool_audit
from apps.octo.sanitized_pool import identity, shapes


# bundle_config key for the global enable flag. Defaults to false
# (disabled) if the row is missing or malformed.
EXTRACTOR_ENABLED_KEY = "sanitized_pool_extractor_enabled"

# Default cap on events processed per run. Bounds wall-clock per
# tenant and keeps the cursor advancing in reasonable increments.
DEFAULT_MAX_EVENTS_PER_RUN = 500


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Candidate:
    """An IOC candidate pulled from a single event payload.

    `source_event_id` carries the originating event_id so audit rows
    can reference back to the row that produced the contribution.
    """
    kind: str
    value: str
    subkind: Optional[str] = None
    source_event_id: int = 0


@dataclass(frozen=True)
class ExtractionStats:
    """Per-run statistics returned by `run_extraction_for_tenant`."""
    tenant_slug: str
    events_scanned: int = 0
    candidates_seen: int = 0
    patterns_written: int = 0
    patterns_updated: int = 0
    rejects_written: int = 0
    advanced_cursor_to: int = 0
    status: str = "never"
    error: Optional[str] = None


@dataclass(frozen=True)
class WriteOutcome:
    """Per-candidate result. `kind` is the discriminator."""
    kind: Literal["pattern_new", "pattern_updated", "reject", "skipped_duplicate"]
    pattern_id: Optional[int] = None
    reject_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Enablement gate
# ---------------------------------------------------------------------------

def is_enabled(registry_conn: sqlite3.Connection) -> bool:
    """Return True iff the bundle's super_admin has explicitly opted in.

    Safe defaults:
      - bundle_config table missing → False
      - row missing → False
      - malformed JSON → False
      - value isn't a literal `true` → False

    A configuration error MUST NOT silently enable extraction.
    """
    try:
        row = registry_conn.execute(
            "SELECT value_json FROM bundle_config WHERE key = ?",
            (EXTRACTOR_ENABLED_KEY,),
        ).fetchone()
    except sqlite3.OperationalError:
        return False
    if row is None:
        return False
    try:
        # Row factory may or may not be set on the caller's conn.
        raw = row["value_json"] if hasattr(row, "keys") else row[0]
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError, KeyError):
        return False
    return parsed is True


# ---------------------------------------------------------------------------
# Candidate extraction from event payloads
# ---------------------------------------------------------------------------

def extract_candidates_from_payload(
    payload: object,
    *,
    source_event_id: int = 0,
) -> list[Candidate]:
    """Pull IOC candidates from a single event payload.

    v0 shape: the payload may carry an `iocs` field — a list of dicts
    `{type, value, subkind?}`. This is the framework-level contract
    buoy adapters should emit; per-source parsers (Datto, Wazuh, etc.)
    will plug in alongside this later via a registry.

    Defensive against malformed payloads:
      - non-dict payload → []
      - missing `iocs` field → []
      - `iocs` not a list → []
      - individual candidate missing `type` or `value` → skipped
      - non-string type/value/subkind → skipped (shapes.validate
        rejects these too, but we skip pre-validation to keep the
        rejects log focused on actual attacks, not noise)
    """
    if not isinstance(payload, dict):
        return []
    raw = payload.get("iocs")
    if not isinstance(raw, list):
        return []
    out: list[Candidate] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        value = item.get("value")
        sub = item.get("subkind")
        if not isinstance(kind, str) or not isinstance(value, str):
            continue
        if sub is not None and not isinstance(sub, str):
            sub = None
        out.append(Candidate(
            kind=kind,
            value=value,
            subkind=sub,
            source_event_id=source_event_id,
        ))
    return out


# ---------------------------------------------------------------------------
# Pattern write path (per-candidate)
# ---------------------------------------------------------------------------

# Map shapes.Accepted (kind, subkind) → patterns.ioc_type allowlist.
# patterns CHECK constraint:
#   ('ip','ipv6','domain','url','md5','sha1','sha256','email','cidr','other')
_IOC_TYPE_MAP: dict[tuple[str, Optional[str]], str] = {
    ("file_hash", "md5"):    "md5",
    ("file_hash", "sha1"):   "sha1",
    ("file_hash", "sha256"): "sha256",
    ("ip",        "ipv4"):   "ip",
    ("ip",        "ipv6"):   "ipv6",
    ("domain",    None):     "domain",
    ("url",       None):     "url",
}


def _patterns_ioc_type(accepted: shapes.Accepted) -> str:
    """Map the validator's (kind, subkind) tuple to the patterns
    CHECK-constraint allowlist value."""
    key = (accepted.kind, accepted.subkind)
    if key not in _IOC_TYPE_MAP:
        raise ValueError(
            f"no patterns.ioc_type mapping for accepted shape "
            f"kind={accepted.kind!r} subkind={accepted.subkind!r}"
        )
    return _IOC_TYPE_MAP[key]


def _utcnow() -> str:
    """ISO-8601 UTC timestamp matching patterns column defaults."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%f")[:-3] + "Z"


def _audit_entry_for_pattern(
    *,
    actor: str,
    action: str,
    target_id: str,
    tenant_slug: str,
    state: dict,
    source_event_id: int,
) -> audit_mod.AuditEntry:
    """Build the AuditEntry used for a pool pattern write.

    `state` is logged as the after_state — carries the (ioc_type,
    ioc_value, tenant_hmac, hmac_version) so a reader of either chain
    can reconstruct what was contributed. Pre-image not stored
    explicitly (it equals state['ioc_value']).
    """
    return audit_mod.AuditEntry(
        actor=actor,
        actor_kind="service",
        action=action,
        target_kind="pattern",
        target_id=target_id,
        client_slug=tenant_slug,
        after_state=state,
        reason=f"pool extractor: event_id={source_event_id}",
    )


def write_candidate(
    candidate: Candidate,
    tenant_slug: str,
    patterns_conn: sqlite3.Connection,
    global_audit_conn: sqlite3.Connection,
    tenant_audit_conn: sqlite3.Connection,
    *,
    actor: str = "octo-pool-extractor",
    now: Optional[str] = None,
) -> WriteOutcome:
    """Process a single candidate: validate, identify, write.

    Order of operations:
      1. Shape validation (M1 + M7 + M8).
      2. Tenant identity (M2 HMAC).
      3a. Accepted → upsert into patterns, dual-write audit (M4).
      3b. Rejected → insert into sanitization_rejects with HMAC + reason_code,
          dual-write audit (M4).

    Returns a WriteOutcome describing what happened. Raises only on
    catastrophic errors (DB unreachable, audit chain compromised);
    routine validation failures are recorded as `reject` outcomes.
    """
    if now is None:
        now = _utcnow()
    result = shapes.validate_pattern(
        candidate.kind, candidate.value, subkind=candidate.subkind,
    )
    tenant_hmac = identity.tenant_hmac(tenant_slug)
    hmac_v = identity.hmac_version()

    if isinstance(result, shapes.Rejected):
        return _record_reject(
            result=result,
            tenant_slug=tenant_slug,
            tenant_hmac_hex=tenant_hmac,
            hmac_v=hmac_v,
            source_event_id=candidate.source_event_id,
            patterns_conn=patterns_conn,
            global_audit_conn=global_audit_conn,
            tenant_audit_conn=tenant_audit_conn,
            actor=actor,
            now=now,
        )

    # Accepted path.
    ioc_type = _patterns_ioc_type(result)
    return _upsert_pattern(
        ioc_type=ioc_type,
        ioc_value=result.canonical_value,
        tenant_slug=tenant_slug,
        tenant_hmac_hex=tenant_hmac,
        hmac_v=hmac_v,
        source_event_id=candidate.source_event_id,
        patterns_conn=patterns_conn,
        global_audit_conn=global_audit_conn,
        tenant_audit_conn=tenant_audit_conn,
        actor=actor,
        now=now,
    )


def _upsert_pattern(
    *,
    ioc_type: str,
    ioc_value: str,
    tenant_slug: str,
    tenant_hmac_hex: str,
    hmac_v: str,
    source_event_id: int,
    patterns_conn: sqlite3.Connection,
    global_audit_conn: sqlite3.Connection,
    tenant_audit_conn: sqlite3.Connection,
    actor: str,
    now: str,
) -> WriteOutcome:
    """UPSERT into patterns. Either INSERT new row or APPEND tenant_hmac
    to existing row's tenant_hmacs array (deduplicating)."""
    row = patterns_conn.execute(
        "SELECT id, tenant_hmacs, client_count, severity_max, confidence_avg, "
        "first_seen, last_seen FROM patterns "
        "WHERE ioc_type = ? AND ioc_value = ?",
        (ioc_type, ioc_value),
    ).fetchone()

    if row is None:
        # NEW pattern.
        tenant_hmacs_json = json.dumps([tenant_hmac_hex])
        # client_hashes / pepper_version are legacy NOT-NULL columns
        # from migration 003. Pre-M2 they held the peppered identity;
        # post-M2 we keep them schema-satisfied but empty so the
        # eventual cleanup migration can drop them without risk.
        #
        # TLP default is RED (single-tenant). AMBER (cross-MSP
        # federation) is deferred entirely from v1 per the
        # 2026-05-21 v2 reviewer round — dead code with cross-MSP
        # semantics is still attack surface. Federation will be
        # reintroduced in v1.1 alongside the network-policy enforcement
        # layer the reviewers required.
        patterns_conn.execute(
            """
            INSERT INTO patterns (
                ioc_type, ioc_value, first_seen, last_seen, tlp,
                client_hashes, client_count, severity_max,
                confidence_avg, pepper_version, tenant_hmacs,
                hmac_version, promoted_at, last_updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ioc_type, ioc_value, now, now, "red",
                # legacy columns:
                "[]", 1, "medium", 0.5, "deprecated",
                # M2 columns:
                tenant_hmacs_json, hmac_v,
                now, now,
            ),
        )
        new_id = patterns_conn.execute(
            "SELECT last_insert_rowid()"
        ).fetchone()[0]

        # M4 dual-write audit.
        entry = _audit_entry_for_pattern(
            actor=actor,
            action="pool_pattern_added",
            target_id=str(new_id),
            tenant_slug=tenant_slug,
            state={
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "tenant_hmac": tenant_hmac_hex,
                "hmac_version": hmac_v,
                "source_event_id": source_event_id,
            },
            source_event_id=source_event_id,
        )
        pool_audit.append(global_audit_conn, tenant_audit_conn, entry)
        return WriteOutcome(kind="pattern_new", pattern_id=int(new_id))

    # EXISTING pattern — append HMAC if not already present.
    existing_json = row["tenant_hmacs"] if hasattr(row, "keys") else row[1]
    try:
        existing = json.loads(existing_json) if existing_json else []
    except (json.JSONDecodeError, TypeError):
        existing = []
    if not isinstance(existing, list):
        existing = []
    if tenant_hmac_hex in existing:
        # Same tenant already contributed this IOC — touch last_seen
        # but no new contribution to audit.
        patterns_conn.execute(
            "UPDATE patterns SET last_seen = ?, last_updated_at = ? "
            "WHERE id = ?",
            (now, now, row["id"]),
        )
        return WriteOutcome(kind="skipped_duplicate", pattern_id=int(row["id"]))

    existing.append(tenant_hmac_hex)
    new_count = len(set(existing))
    patterns_conn.execute(
        "UPDATE patterns SET tenant_hmacs = ?, client_count = ?, "
        "last_seen = ?, hmac_version = ?, last_updated_at = ? "
        "WHERE id = ?",
        (json.dumps(existing), new_count, now, hmac_v, now, row["id"]),
    )

    entry = _audit_entry_for_pattern(
        actor=actor,
        action="pool_pattern_tenant_added",
        target_id=str(row["id"]),
        tenant_slug=tenant_slug,
        state={
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "tenant_hmac": tenant_hmac_hex,
            "hmac_version": hmac_v,
            "client_count_after": new_count,
            "source_event_id": source_event_id,
        },
        source_event_id=source_event_id,
    )
    pool_audit.append(global_audit_conn, tenant_audit_conn, entry)
    return WriteOutcome(kind="pattern_updated", pattern_id=int(row["id"]))


def _record_reject(
    *,
    result: shapes.Rejected,
    tenant_slug: str,
    tenant_hmac_hex: str,
    hmac_v: str,
    source_event_id: int,
    patterns_conn: sqlite3.Connection,
    global_audit_conn: sqlite3.Connection,
    tenant_audit_conn: sqlite3.Connection,
    actor: str,
    now: str,
) -> WriteOutcome:
    """Insert into sanitization_rejects via the M3 HMAC + reason_code
    columns. The legacy `source_slug` column gets a placeholder value
    (NOT the real slug) — once migration 023 cleanup ships, that
    column will be dropped entirely."""
    # Legacy NOT NULL columns:
    #   source_slug (free text, pre-M2) → "<hmac>" sentinel so reads
    #     of the legacy column don't expose the plaintext slug. M3
    #     surfaces read source_tenant_hmac, not source_slug.
    #   reason (free text, pre-M3 stable reason_code) → mirror the
    #     reason_code value.
    patterns_conn.execute(
        """
        INSERT INTO sanitization_rejects (
            rejected_at, source_slug, reason, raw_excerpt,
            source_tenant_hmac, reason_code, hmac_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            now,
            "<hmac>",  # M3: never write plaintext slug
            result.reason_code, result.raw_excerpt,
            tenant_hmac_hex, result.reason_code, hmac_v,
        ),
    )
    reject_id = patterns_conn.execute(
        "SELECT last_insert_rowid()"
    ).fetchone()[0]

    entry = _audit_entry_for_pattern(
        actor=actor,
        action="pool_candidate_rejected",
        target_id=str(reject_id),
        tenant_slug=tenant_slug,
        state={
            "reason_code": result.reason_code,
            "tenant_hmac": tenant_hmac_hex,
            "hmac_version": hmac_v,
            "source_event_id": source_event_id,
        },
        source_event_id=source_event_id,
    )
    pool_audit.append(global_audit_conn, tenant_audit_conn, entry)
    return WriteOutcome(kind="reject", reject_id=int(reject_id))


# ---------------------------------------------------------------------------
# Cursor helpers
# ---------------------------------------------------------------------------

def _load_cursor(
    patterns_conn: sqlite3.Connection,
    tenant_slug: str,
) -> int:
    """Return the cursor's `last_event_id` for the tenant. 0 if no row."""
    row = patterns_conn.execute(
        "SELECT last_event_id FROM pool_extractor_cursor "
        "WHERE tenant_slug = ?",
        (tenant_slug,),
    ).fetchone()
    if row is None:
        return 0
    val = row["last_event_id"] if hasattr(row, "keys") else row[0]
    return int(val or 0)


def _save_cursor(
    patterns_conn: sqlite3.Connection,
    tenant_slug: str,
    *,
    last_event_id: int,
    status: str,
    error: Optional[str],
    events_seen_delta: int,
    patterns_delta: int,
    rejects_delta: int,
    now: str,
) -> None:
    """UPSERT cursor row with run results.

    Deltas are added to existing totals; first-time runs start from 0
    via the INSERT defaults.
    """
    patterns_conn.execute(
        """
        INSERT INTO pool_extractor_cursor (
            tenant_slug, last_event_id, last_run_at, last_run_status,
            last_error, events_seen_total, patterns_written, rejects_written
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_slug) DO UPDATE SET
            last_event_id    = excluded.last_event_id,
            last_run_at      = excluded.last_run_at,
            last_run_status  = excluded.last_run_status,
            last_error       = excluded.last_error,
            events_seen_total = pool_extractor_cursor.events_seen_total + ?,
            patterns_written = pool_extractor_cursor.patterns_written + ?,
            rejects_written  = pool_extractor_cursor.rejects_written + ?
        """,
        (
            tenant_slug, last_event_id, now, status, error,
            events_seen_delta, patterns_delta, rejects_delta,
            events_seen_delta, patterns_delta, rejects_delta,
        ),
    )


# ---------------------------------------------------------------------------
# Per-tenant run
# ---------------------------------------------------------------------------

def run_extraction_for_tenant(
    tenant_slug: str,
    *,
    registry_conn: sqlite3.Connection,
    events_conn: sqlite3.Connection,
    patterns_conn: sqlite3.Connection,
    global_audit_conn: sqlite3.Connection,
    tenant_audit_conn: sqlite3.Connection,
    max_events: int = DEFAULT_MAX_EVENTS_PER_RUN,
    actor: str = "octo-pool-extractor",
) -> ExtractionStats:
    """One extraction pass over the tenant's events.db.

    Flow:
      1. Check `is_enabled(registry_conn)`. If false → return status
         "disabled" stats; no DB writes.
      2. Load cursor → cursor_id.
      3. Read events with id > cursor_id ORDER BY id ASC LIMIT max_events.
      4. For each event, extract candidates from payload, write each
         candidate via `write_candidate()`. Accumulate counts.
      5. Save cursor with status="ok" + advanced last_event_id.

    Any exception during step 4 leaves the cursor at its previous
    position + saves status="error" with the error message. Next run
    retries the same range.
    """
    now = _utcnow()
    if not is_enabled(registry_conn):
        return ExtractionStats(
            tenant_slug=tenant_slug,
            status="disabled",
        )

    cursor_id = _load_cursor(patterns_conn, tenant_slug)

    try:
        # Athena's own incident records (`athena.incident`: an analyst's
        # summary, the rule) are not vendor payloads to mine.
        events = events_conn.execute(
            "SELECT id, payload FROM events "
            "WHERE id > ? AND source <> 'athena' ORDER BY id ASC LIMIT ?",
            (cursor_id, max_events),
        ).fetchall()
    except sqlite3.OperationalError as exc:
        # The tenant's events.db may not be initialized yet (no events
        # table). Record + skip rather than crash the multi-tenant run.
        _save_cursor(
            patterns_conn, tenant_slug,
            last_event_id=cursor_id,
            status="error",
            error=f"events table unavailable: {exc}",
            events_seen_delta=0, patterns_delta=0, rejects_delta=0,
            now=now,
        )
        return ExtractionStats(
            tenant_slug=tenant_slug,
            status="error",
            error=f"events table unavailable: {exc}",
        )

    # RESTRICTED (rule B7, CSAM — v0.17.1): an event naming a domain the
    # tenant holds as restricted evidence never feeds the cross-tenant pool.
    # The list unreadable: nothing is extracted this run (the cursor stays).
    from apps.octo.threat import restricted

    gate = restricted.Gate.for_tenant(tenant_slug)
    if gate.failed:
        return ExtractionStats(tenant_slug=tenant_slug, status="error",
                               error="the restricted-evidence list could not be read")

    events_scanned = 0
    candidates_seen = 0
    patterns_written = 0
    patterns_updated = 0
    rejects_written = 0
    last_seen_id = cursor_id
    error: Optional[str] = None

    try:
        for ev in events:
            events_scanned += 1
            ev_id = int(ev["id"] if hasattr(ev, "keys") else ev[0])
            raw_payload = ev["payload"] if hasattr(ev, "keys") else ev[1]
            if gate.hits(raw_payload):
                last_seen_id = ev_id                    # skipped for good, never mined
                continue
            try:
                payload = json.loads(raw_payload) if raw_payload else {}
            except (json.JSONDecodeError, TypeError):
                payload = {}
            candidates = extract_candidates_from_payload(
                payload, source_event_id=ev_id,
            )
            candidates_seen += len(candidates)
            for cand in candidates:
                outcome = write_candidate(
                    cand, tenant_slug,
                    patterns_conn, global_audit_conn, tenant_audit_conn,
                    actor=actor, now=now,
                )
                if outcome.kind == "pattern_new":
                    patterns_written += 1
                elif outcome.kind == "pattern_updated":
                    patterns_updated += 1
                elif outcome.kind == "reject":
                    rejects_written += 1
            last_seen_id = ev_id
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"

    status = "ok" if error is None else "error"
    advanced_to = last_seen_id if error is None else cursor_id
    _save_cursor(
        patterns_conn, tenant_slug,
        last_event_id=advanced_to,
        status=status,
        error=error,
        events_seen_delta=events_scanned,
        patterns_delta=patterns_written + patterns_updated,
        rejects_delta=rejects_written,
        now=now,
    )

    return ExtractionStats(
        tenant_slug=tenant_slug,
        events_scanned=events_scanned,
        candidates_seen=candidates_seen,
        patterns_written=patterns_written,
        patterns_updated=patterns_updated,
        rejects_written=rejects_written,
        advanced_cursor_to=advanced_to,
        status=status,
        error=error,
    )


# ---------------------------------------------------------------------------
# Multi-tenant orchestrator (thin)
# ---------------------------------------------------------------------------

def run_extraction(
    *,
    tenant_slugs: Iterable[str],
    data_root: Optional[Path] = None,
    max_events_per_tenant: int = DEFAULT_MAX_EVENTS_PER_RUN,
    actor: str = "octo-pool-extractor",
) -> dict[str, ExtractionStats]:
    """Run extraction for each named tenant. Returns per-tenant stats.

    Opens its own connections per tenant. Caller is responsible for
    choosing tenant_slugs (typically: all active tenants from the
    registry, with a per-tenant opt-out filter applied — that filter
    is a future enhancement; v0 trusts the caller's slug list). A slug
    the path layer refuses (not a slug, escaping the data root, through a
    symlink) is that tenant's `error` — like missing DB files — and the
    other tenants still run.

    Thin orchestrator — the real per-tenant logic lives in
    `run_extraction_for_tenant`. This exists so the scheduled-job
    entrypoint has one symbol to call.
    """
    registry_path = (
        octo_paths.registry_db_path()
        if data_root is None
        else data_root / "registry.db"
    )
    patterns_path = (
        octo_paths.patterns_db_path()
        if data_root is None
        else data_root / "global" / "patterns.db"
    )
    global_audit_path = (
        octo_paths.global_audit_db_path()
        if data_root is None
        else data_root / "global" / "audit.db"
    )

    results: dict[str, ExtractionStats] = {}
    registry_conn = connect(registry_path, read_only=True)
    patterns_conn = connect(patterns_path)
    global_audit_conn = connect(global_audit_path)
    try:
        for slug in tenant_slugs:
            # Both through the path layer's containment check (spec §2.3:
            # slug validated, realpath'd, under the data root, no symlink),
            # whichever data root is in use — before anything touches them.
            try:
                events_path = octo_paths.client_db_path(slug, "events", root=data_root)
                tenant_audit_path = octo_paths.client_db_path(slug, "audit", root=data_root)
            except octo_paths.SlugError as exc:
                results[slug] = ExtractionStats(
                    tenant_slug=slug,
                    status="error",
                    error=f"tenant path refused: {exc}",
                )
                continue
            if not events_path.exists() or not tenant_audit_path.exists():
                results[slug] = ExtractionStats(
                    tenant_slug=slug,
                    status="error",
                    error=f"tenant DB files missing for {slug}",
                )
                continue
            events_conn = connect(events_path, read_only=True)
            tenant_audit_conn = connect(tenant_audit_path)
            try:
                stats = run_extraction_for_tenant(
                    slug,
                    registry_conn=registry_conn,
                    events_conn=events_conn,
                    patterns_conn=patterns_conn,
                    global_audit_conn=global_audit_conn,
                    tenant_audit_conn=tenant_audit_conn,
                    max_events=max_events_per_tenant,
                    actor=actor,
                )
            finally:
                events_conn.close()
                tenant_audit_conn.close()
            results[slug] = stats
    finally:
        registry_conn.close()
        patterns_conn.close()
        global_audit_conn.close()
    return results
