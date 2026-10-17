"""Tenant resolution on the ingest path: map → name suggestion → auto-create → quarantine.

Adapter-agnostic. Every poller and webhook that used to DROP an event whose
vendor tenant id (Datto siteUid, RocketCyber customerId, …) resolved to no
client now hands it to `deliver()`, which decides — under the product
rulings — where the event lands:

  1. MAPPED        the instance's tenant map knows the vendor id → that client
                   (if that client is not active → quarantine 'offboarded-tenant';
                   an offboarded tenant is never resurrected by traffic — which
                   is why offboarding FREEZES a tenant's mappings rather than
                   deleting them: the site stays known as "theirs").
  2. PASS-THROUGH  the vendor id IS an active client slug (a forwarder stamped
                   `_octo_tenant_slug`) → that client, no mapping written.
                   Only for adapters whose tenant ids CAN be slugs: one that
                   declares `tenant_ids_are_slugs = False` (RocketCyber's
                   numeric customer ids — "2002" is also a valid slug, and a
                   client named by a number would silently receive another
                   customer's events) skips this step entirely.
  3. NAME MATCH    the vendor's NAME for the site (adapter hook
                   `vendor_tenant_label(envelope)`, else the cached discovery
                   listing — never a live vendor call here) is the SAME NAME
                   (`tenant_lifecycle.exact_name_key`: case, accents,
                   punctuation and spacing ignored, legal suffixes KEPT) as an
                   existing client → the event is HELD, never linked: a name is
                   a suggestion, not evidence (the same-name rule,
                   2026-10-01 — two businesses can share a name, and "Acme
                   Pharmacy, Inc." is not "Acme Pharmacy LLC"). Exactly one active
                   client → quarantine 'name-match-suggested' (or
                   'name-already-mapped' when a different site of this
                   instance is already mapped to it) with a one-click "map to
                   <client>" suggestion in the review UI (`name_suggestions`);
                   the operator's click maps the site (match_source 'manual').
                   Two or more → quarantine 'ambiguous-name'. Only inactive
                   ones → quarantine 'offboarded-tenant'. Nothing is written
                   to the tenant map by a name, ever.
  4. AUTO-CREATE   no same-name client and a name is known → a new tenant
                   (a name that only differs by its legal suffix makes a NEW
                   tenant, pending review — the tenant manager's duplicate
                   hint shows the pair to a human): slug from the
                   name (-2, -3 … on collision; an offboarded slug is never
                   reused because the PK is taken), origin 'auto', kind
                   'unclassified', review_state 'pending', ai_policy 'none',
                   created_by_instance_id set; DBs provisioned; mapping
                   written; audited with the integration as the actor.
                   Bounded per instance: AUTOCREATE_PER_HOUR new tenants per
                   rolling hour and AUTOCREATE_MAX_PENDING tenants still
                   awaiting review — beyond either → quarantine
                   'autocreate-limit' (a flood of fake sites cannot become a
                   flood of tenants). Concurrent deliveries for one new site
                   (poll + webhook) produce ONE tenant: the whole decision is
                   re-made under the registry write lock.
  5. NO NAME       vendor id known, no name: an adapter that can list its
                   tenants → quarantine 'name-unknown' (the manager's Reload
                   fills the discovery cache and the next delivery resolves;
                   a placeholder tenant would be a permanently wrong name a
                   human must fix). An adapter that cannot → a placeholder
                   tenant '<vendor> site <first 8 of id>' (cleaned like any
                   vendor text), the only bucket available.
  6. NO ID         no vendor tenant id at all → the instance default tenant
                   if one is set AND active (an offboarded / archived /
                   disabled default holds as 'offboarded-tenant'; a default
                   naming a client that does not exist holds as
                   'default-tenant-missing'), else quarantine 'no-tenant-id'.

Nothing is dropped. Nothing is created from a disabled instance, and
quarantine never creates anything on its own.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from apps.octo import client_provisioning, paths
from apps.octo.auth import audit
from apps.octo.db import connect
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.instances import freshness, quarantine, tenant_map, vendor_tenants
from apps.octo.instances.manager import get_instance
from apps.octo.instances.tenant_lifecycle import (
    clean_display_name,
    exact_name_key,
    slug_from_name,
)

logger = logging.getLogger(__name__)

AUTOCREATE_PER_HOUR = 25
AUTOCREATE_MAX_PENDING = 200
_MAX_SLUG_ATTEMPTS = 50

ACTOR_KIND = "system"

# One creator at a time in this process; the registry's BEGIN IMMEDIATE
# serialises across processes. Cheap insurance against thread contention.
_create_lock = threading.Lock()
# Instances whose "bound reached" line has been logged since the last create:
# a poller re-lists held alerts every cycle, and one warning is the message.
_limit_logged: set[int] = set()


def _warn_limited_once(instance_id: int) -> None:
    with _create_lock:
        if instance_id in _limit_logged:
            return
        _limit_logged.add(instance_id)
    logger.warning(
        "[tenant-autocreate] instance id=%s: auto-create bound reached (%d/hour, "
        "%d pending review) — traffic from further new sites is held in quarantine "
        "until tenants are reviewed (or the hour passes)",
        instance_id, AUTOCREATE_PER_HOUR, AUTOCREATE_MAX_PENDING,
    )


def actor_for(instance_id: int) -> str:
    """The audit actor for something an integration did by itself."""
    return f"adapter-instance:{instance_id}"


@dataclass(frozen=True)
class Resolution:
    slug: Optional[str]              # ingest here; None = quarantine
    # mapped | passthrough | auto-created | default | quarantine ('auto-linked'
    # is no longer produced: a name only ever suggests — callers that still
    # test for it are harmless)
    outcome: str
    reason: Optional[str] = None     # quarantine reason (quarantine.REASONS)
    vendor_tenant_id: Optional[str] = None
    vendor_tenant_label: Optional[str] = None


@dataclass(frozen=True)
class Delivery:
    status: str                      # stored | duplicate | quarantined
    outcome: str
    slug: Optional[str] = None
    reason: Optional[str] = None
    event_id: Optional[int] = None
    quarantine_id: Optional[int] = None
    quarantine_created: bool = False

    @property
    def ingested(self) -> bool:
        return self.status in ("stored", "duplicate")


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------

def _client_status(conn: sqlite3.Connection, slug: str) -> Optional[str]:
    row = conn.execute("SELECT status FROM clients WHERE slug = ?", (slug,)).fetchone()
    return row[0] if row else None


def _name_matches(conn: sqlite3.Connection, key: str) -> tuple[list[str], list[str]]:
    """(active slugs, inactive slugs) whose display_name is the SAME NAME as
    `key` (`exact_name_key`: legal suffixes kept)."""
    active: list[str] = []
    inactive: list[str] = []
    for slug, display_name, status in conn.execute(
        "SELECT slug, display_name, status FROM clients",
    ).fetchall():
        if exact_name_key(display_name) == key:
            (active if status == "active" else inactive).append(slug)
    return active, inactive


# The hold reasons that come with a "map to <client>" suggestion.
SUGGESTION_REASONS: tuple[str, ...] = ("name-match-suggested", "name-already-mapped")


@dataclass(frozen=True)
class NameSuggestion:
    slug: str
    display_name: str


def name_suggestions(labels: Iterable[Optional[str]]) -> dict[str, NameSuggestion]:
    """{label: suggestion} for the vendor site names that are the SAME NAME
    (`exact_name_key`) as exactly ONE active client — what the review UI
    offers as "map to <client>". A suggestion is never applied by itself: a
    human clicks it (the click maps the site, match_source 'manual'). One
    registry read for the whole batch; {} when it cannot be read."""
    wanted = {lab: exact_name_key(lab) for lab in labels if isinstance(lab, str) and lab}
    wanted = {lab: key for lab, key in wanted.items() if key}
    if not wanted:
        return {}
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
        try:
            rows = reg.execute(
                "SELECT slug, display_name FROM clients WHERE status = 'active'",
            ).fetchall()
        finally:
            reg.close()
    except sqlite3.Error:
        return {}
    by_key: dict[str, list[tuple[str, str]]] = {}
    for slug, display_name in rows:
        key = exact_name_key(display_name)
        if key:
            by_key.setdefault(key, []).append((slug, display_name))
    out: dict[str, NameSuggestion] = {}
    for label, key in wanted.items():
        hits = by_key.get(key) or []
        if len(hits) == 1:
            out[label] = NameSuggestion(hits[0][0], hits[0][1])
    return out


_PLACEHOLDER_ID_CHARS = 8


def placeholder_label(vendor_slug: str, vendor_tenant_id: str) -> str:
    """The display name a tenant is auto-created with when its vendor gives
    no name ("<vendor> site <id prefix>"; "" when that cleans to nothing).
    It names the vendor, so client-facing views replace it while it stands."""
    # The vendor id is vendor text too: cleaned so register_client can never
    # refuse the placeholder on the ingest path.
    return clean_display_name(
        f"{vendor_slug} site {vendor_tenant_id[:_PLACEHOLDER_ID_CHARS]}"
    )


def is_placeholder_label(name: str, vendor_slug: str) -> bool:
    """Whether `name` is still `placeholder_label(vendor_slug, …)` — i.e. no
    one has renamed the auto-created tenant yet."""
    head = f"{vendor_slug} site "
    return name.startswith(head) and 0 < len(name) - len(head) <= _PLACEHOLDER_ID_CHARS


def is_placeholder_slug(
    slug: str, vendor_slug: str, vendor_tenant_ids: Iterable[str] = (),
) -> bool:
    """Whether `slug` was made from `placeholder_label(vendor_slug, …)` — it
    then names the vendor, and a slug is never renamed. With the vendor ids
    the tenant was created for (its mapping on the creating instance) the
    answer is exact: the placeholder's slug, or it with free_slug's "-N".
    Without them (the mapping was since re-pointed), the placeholder SHAPE
    decides: "<vendor>-site-<≤8 id chars>", optionally "-N"."""
    ids = [v for v in vendor_tenant_ids if v]
    if ids:
        for vendor_tenant_id in ids:
            base = slug_from_name(placeholder_label(vendor_slug, vendor_tenant_id), fallback="")
            if base and re.fullmatch(re.escape(base) + r"(?:-\d+)?", slug):
                return True
        return False
    head = slug_from_name(vendor_slug, fallback="")
    if not head:
        return False
    match = re.fullmatch(re.escape(head) + r"-site-([a-z0-9-]+?)(?:-\d+)?", slug)
    return bool(match) and len(match.group(1)) <= _PLACEHOLDER_ID_CHARS


def placeholder_parts(
    conn: sqlite3.Connection, slugs: Optional[Iterable[str]] = None,
) -> dict[str, frozenset[str]]:
    """Auto-created tenants still carrying their placeholder, among `slugs`
    (None = every tenant): slug → {'name'} and/or {'slug'}.

      name  the display name is still "<vendor> site <id>" — rename it
      slug  the slug was made from that placeholder ("<vendor>-site-<id>")
            and can't be renamed; it stays after the display name changes

    Either names the vendor that created the tenant, which a client user
    must never learn (owner decision 2026-09-28 (b)). Tenants with neither
    are absent. {} on a registry older than migration 033."""
    wanted = None if slugs is None else sorted(set(slugs))
    if wanted is not None and not wanted:
        return {}
    where = "c.origin = 'auto'"
    params: list[Any] = []
    if wanted is not None:
        where += f" AND c.slug IN ({','.join('?' * len(wanted))})"
        params = list(wanted)
    try:
        rows = conn.execute(
            "SELECT c.slug, c.display_name, i.vendor_slug FROM clients c "
            f"JOIN adapter_instances i ON i.id = c.created_by_instance_id WHERE {where}",
            params,
        ).fetchall()
        site_ids: dict[str, list[str]] = {}
        for slug, vendor_tenant_id in conn.execute(
            "SELECT m.octo_client_slug, m.vendor_tenant_id FROM adapter_tenant_map m "
            "JOIN clients c ON c.slug = m.octo_client_slug "
            f"AND c.created_by_instance_id = m.adapter_instance_id WHERE {where}",
            params,
        ).fetchall():
            site_ids.setdefault(slug, []).append(vendor_tenant_id)
    except sqlite3.OperationalError:  # pre-033 registry: no auto-created tenants
        return {}
    out: dict[str, frozenset[str]] = {}
    for slug, display_name, vendor_slug in rows:
        parts = set()
        if is_placeholder_label(display_name or "", vendor_slug):
            parts.add("name")
        if is_placeholder_slug(slug, vendor_slug, site_ids.get(slug, ())):
            parts.add("slug")
        if parts:
            out[slug] = frozenset(parts)
    return out


def _label_from_discovery(instance_id: int, cred_ref: str, vendor_tenant_id: str) -> Optional[str]:
    discovery = vendor_tenants.latest(instance_id, cred_ref)
    if discovery is None:
        return None
    for t in discovery.tenants:
        if t.id == vendor_tenant_id:
            return t.label
    return None


def autocreate_status(instance_id: Optional[int]) -> dict[str, Any]:
    """`{created_last_hour, pending, limited}` for the card / bound check."""
    if instance_id is None:
        return {"created_last_hour": 0, "pending": 0, "limited": False}
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return _autocreate_status(reg, instance_id)
    except sqlite3.OperationalError:  # migration 033 not applied yet
        return {"created_last_hour": 0, "pending": 0, "limited": False}
    finally:
        reg.close()


def _autocreate_status(conn: sqlite3.Connection, instance_id: int) -> dict[str, Any]:
    since = format_utc_ms(datetime.now(timezone.utc) - timedelta(hours=1))
    recent = conn.execute(
        "SELECT COUNT(*) FROM clients WHERE created_by_instance_id = ? "
        "AND origin = 'auto' AND onboarded_at >= ?", (instance_id, since),
    ).fetchone()[0]
    # ACTIVE rows only, like the tenant list's "needs review" count: a pending
    # tenant that was merged or offboarded is off the reviewer's plate and
    # must not hold a cap slot for good.
    pending = conn.execute(
        "SELECT COUNT(*) FROM clients WHERE created_by_instance_id = ? "
        "AND origin = 'auto' AND review_state = 'pending' AND status = 'active'",
        (instance_id,),
    ).fetchone()[0]
    return {
        "created_last_hour": int(recent),
        "pending": int(pending),
        "limited": recent >= AUTOCREATE_PER_HOUR or pending >= AUTOCREATE_MAX_PENDING,
    }


def pending_auto_created(instance_id: Optional[int]) -> int:
    return autocreate_status(instance_id)["pending"]


def card_warnings(
    instance_id: Optional[int], vendor_display_name: str, *, status: Optional[dict] = None,
) -> list[str]:
    """Operator-facing lines for the Integrations card; [] when nothing
    needs a human. Pass an `autocreate_status()` result to reuse it."""
    st = status if status is not None else autocreate_status(instance_id)
    lines: list[str] = []
    if st["pending"]:
        lines.append(
            f"{st['pending']} tenant(s) were created from {vendor_display_name} "
            "traffic and await review — tag what each one is (client / internal / "
            "dev / vendor / other) under Settings → Tenants."
        )
    if st["limited"]:
        lines.append(
            f"Auto-create is PAUSED for {vendor_display_name}: the bound of "
            f"{AUTOCREATE_PER_HOUR} new tenants per hour / {AUTOCREATE_MAX_PENDING} "
            "awaiting review is reached. Traffic from further new sites is held in "
            "quarantine until tenants are reviewed (or the hour passes)."
        )
    return lines


# ---------------------------------------------------------------------------
# Resolve
# ---------------------------------------------------------------------------

def resolve_tenant(
    *,
    instance_id: int,
    vendor_slug: str,
    vendor_tenant_id: Optional[str],
    vendor_tenant_label: Optional[str],
    default_tenant_slug: Optional[str],
    supports_discovery: bool,
    allow_passthrough: bool = True,
) -> Resolution:
    """Where an event from `vendor_tenant_id` on this instance belongs. May
    write (a mapping, a tenant) — see the module docstring for the rules.
    `allow_passthrough=False`: the vendor id is never taken as a client slug
    (rule 2 is skipped)."""
    label = clean_display_name(vendor_tenant_label) or None
    if not vendor_tenant_id:
        if default_tenant_slug:
            # The default is a mapping like any other: an offboarded (or
            # archived, or disabled) default never receives traffic again.
            # A default naming NO client at all is a different fault (a
            # misconfigured or hand-edited instance row), held under its
            # own reason so the operator is not sent looking for an
            # offboarding that never happened.
            status = _status_of(default_tenant_slug)
            if status == "active":
                return Resolution(default_tenant_slug, "default")
            if status is None:
                return Resolution(None, "quarantine", "default-tenant-missing")
            return Resolution(None, "quarantine", "offboarded-tenant")
        return Resolution(None, "quarantine", "no-tenant-id")

    vendor_tenant_id = vendor_tenant_id.strip()[: vendor_tenants.MAX_ID_CHARS]
    mapped = tenant_map.resolve(instance_id, vendor_tenant_id)
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        if mapped:
            status = _client_status(reg, mapped)
            if status == "active":
                return Resolution(mapped, "mapped", vendor_tenant_id=vendor_tenant_id)
            return Resolution(
                None, "quarantine", "offboarded-tenant",
                vendor_tenant_id=vendor_tenant_id, vendor_tenant_label=label,
            )
        if (
            allow_passthrough
            and paths.SLUG_RE.match(vendor_tenant_id)
            and _client_status(reg, vendor_tenant_id) == "active"
        ):
            return Resolution(vendor_tenant_id, "passthrough", vendor_tenant_id=vendor_tenant_id)
    finally:
        reg.close()

    record = get_instance(instance_id)
    if record is None or record.disabled_at is not None or record.status == "disabled":
        return Resolution(
            None, "quarantine", "instance-disabled",
            vendor_tenant_id=vendor_tenant_id, vendor_tenant_label=label,
        )
    if label is None:
        label = clean_display_name(
            _label_from_discovery(instance_id, record.cred_ref, vendor_tenant_id)
        ) or None
    if label is None:
        if supports_discovery:
            return Resolution(
                None, "quarantine", "name-unknown", vendor_tenant_id=vendor_tenant_id,
            )
        label = placeholder_label(vendor_slug, vendor_tenant_id) or None
        if label is None:
            return Resolution(
                None, "quarantine", "name-unknown", vendor_tenant_id=vendor_tenant_id,
            )

    return _link_or_create(
        instance_id=instance_id, vendor_tenant_id=vendor_tenant_id, label=label,
    )


def _decide(
    conn: sqlite3.Connection, *, instance_id: int, vendor_tenant_id: str, key: str, label: str,
) -> tuple[str, Any]:
    """The decision for an unmapped vendor tenant, from the registry as it is
    NOW: ('mapped', slug) | ('create', None) | ('quarantine', reason). Pure
    read — run once without the lock (so a re-listed alert that only ever
    quarantines never takes the write lock) and again under it before
    anything is written. A NAME never maps a site (the same-name rule):
    the same name as one client is held with a suggestion for a human."""
    row = conn.execute(
        "SELECT octo_client_slug FROM adapter_tenant_map "
        "WHERE adapter_instance_id = ? AND vendor_tenant_id = ?",
        (instance_id, vendor_tenant_id),
    ).fetchone()
    if row is not None:
        if _client_status(conn, row[0]) == "active":
            return "mapped", row[0]
        return "quarantine", "offboarded-tenant"
    active, inactive = _name_matches(conn, key) if key else ([], [])
    if len(active) == 1:
        # A suggestion either way. Said more precisely when the client
        # already has a different site on this instance (a second site of
        # the client — or a guessable name on a compromised feed).
        already = conn.execute(
            "SELECT 1 FROM adapter_tenant_map WHERE adapter_instance_id = ? "
            "AND octo_client_slug = ? AND vendor_tenant_id != ? LIMIT 1",
            (instance_id, active[0], vendor_tenant_id),
        ).fetchone()
        if already is not None:
            return "quarantine", "name-already-mapped"
        return "quarantine", "name-match-suggested"
    if len(active) > 1:
        return "quarantine", "ambiguous-name"
    if inactive:
        return "quarantine", "offboarded-tenant"
    if _autocreate_status(conn, instance_id)["limited"]:
        return "quarantine", "autocreate-limit"
    return "create", None


def _link_or_create(*, instance_id: int, vendor_tenant_id: str, label: str) -> Resolution:
    """Hold (a name match, an ambiguity, …) or auto-create. Decided from a
    plain read first; when that says "create", decided AGAIN under the
    registry write lock and applied there — so two deliveries for one new
    site cannot both create."""
    key = exact_name_key(label)
    ids = {"vendor_tenant_id": vendor_tenant_id, "vendor_tenant_label": label}

    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        action, payload = _decide(
            reg, instance_id=instance_id, vendor_tenant_id=vendor_tenant_id, key=key, label=label,
        )
    finally:
        reg.close()
    if action == "mapped":
        return Resolution(payload, "mapped", vendor_tenant_id=vendor_tenant_id)
    if action == "quarantine":
        if payload == "autocreate-limit":
            _warn_limited_once(instance_id)
        return Resolution(None, "quarantine", payload, **ids)

    with _create_lock:
        reg = connect(paths.registry_db_path())
        try:
            reg.execute("BEGIN IMMEDIATE")
            try:
                action, payload = _decide(
                    reg, instance_id=instance_id, vendor_tenant_id=vendor_tenant_id,
                    key=key, label=label,
                )
                if action == "mapped":
                    reg.execute("COMMIT")
                    return Resolution(payload, "mapped", vendor_tenant_id=vendor_tenant_id)
                if action == "quarantine":
                    reg.execute("COMMIT")
                    return Resolution(None, "quarantine", payload, **ids)

                slug = free_slug(reg, slug_from_name(label))
                try:
                    client_provisioning.register_client(
                        reg, slug, label, origin="auto", kind="unclassified",
                        review_state="pending", created_by_instance_id=instance_id,
                        ai_policy="none",
                    )
                except (client_provisioning.InvalidClientError,
                        client_provisioning.ClientExistsError) as exc:
                    # Vendor text the registry refuses is held, never a 5xx
                    # the vendor retries forever (nothing in the message is
                    # vendor-derived; the type is enough for the log).
                    reg.execute("ROLLBACK")
                    logger.error(
                        "[tenant-autocreate] instance id=%s: registry refused new tenant "
                        "%r (%s); event held", instance_id, slug, type(exc).__name__,
                    )
                    return Resolution(None, "quarantine", "store-failed", **ids)
                _insert_mapping(reg, instance_id, vendor_tenant_id, slug, label)
                # Audit BEFORE commit: a failed audit write rolls the creation back.
                _audit(
                    instance_id, "tenant_auto_create", slug,
                    after={"slug": slug, "display_name": label, "origin": "auto",
                           "kind": "unclassified", "review_state": "pending",
                           "ai_policy": "none", "instance_id": instance_id,
                           "vendor_tenant_id": vendor_tenant_id},
                    reason="created from incoming integration traffic (no matching client)",
                )
                reg.execute("COMMIT")
            except Exception:
                if reg.in_transaction:
                    reg.execute("ROLLBACK")
                raise
        finally:
            reg.close()

        try:
            client_provisioning.provision_client_dbs(slug)
        except Exception as exc:  # noqa: BLE001
            client_provisioning.unregister_client(slug)
            logger.error(
                "[tenant-autocreate] instance id=%s: provisioning DBs for new tenant "
                "%r failed (%s); registration rolled back", instance_id, slug,
                type(exc).__name__,
            )
            return Resolution(None, "quarantine", "store-failed", **ids)
    _limit_logged.discard(instance_id)
    logger.info(
        "[tenant-autocreate] instance id=%s: created tenant %r for vendor tenant %r "
        "(pending review)", instance_id, slug, vendor_tenant_id,
    )
    return Resolution(slug, "auto-created", **ids)


def _status_of(slug: str) -> Optional[str]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return _client_status(reg, slug)
    finally:
        reg.close()


def free_slug(conn: sqlite3.Connection, base: str) -> str:
    """`base`, or `base-2`, `base-3` … — the first slug no row (of ANY status)
    holds, so an offboarded or archived slug is never reused."""
    from apps.octo.auth.config import RESERVED_SLUGS

    taken = {r[0] for r in conn.execute("SELECT slug FROM clients").fetchall()}
    candidate = base
    if base in RESERVED_SLUGS:
        candidate = f"{base}-2"
    n = 1
    while candidate in taken or candidate in RESERVED_SLUGS:
        n += 1
        if n > _MAX_SLUG_ATTEMPTS:
            candidate = f"{base[:30].rstrip('-')}-{uuid.uuid4().hex[:8]}"
            break
        suffix = f"-{n}"
        candidate = f"{base[: max(1, 48 - len(suffix))].rstrip('-')}{suffix}"
    return candidate


def _insert_mapping(
    conn: sqlite3.Connection, instance_id: int, vendor_tenant_id: str, slug: str, label: str,
) -> None:
    conn.execute(
        "INSERT INTO adapter_tenant_map (adapter_instance_id, vendor_tenant_id, "
        " octo_client_slug, vendor_tenant_label, match_source, updated_by_operator_id) "
        "VALUES (?, ?, ?, ?, 'auto', NULL)",
        (instance_id, vendor_tenant_id, slug, label[: vendor_tenants.MAX_LABEL_CHARS]),
    )


def _audit(
    instance_id: int, action: str, slug: str, *, after: dict[str, Any], reason: str,
) -> None:
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=actor_for(instance_id),
            actor_kind=ACTOR_KIND,
            action=action,
            target_kind="client",
            target_id=slug,
            client_slug=slug,
            after_state=after,
            reason=reason,
            request_id=str(uuid.uuid4()),
        ))
    finally:
        g_audit.close()


# ---------------------------------------------------------------------------
# Deliver — the one call pollers and webhooks make
# ---------------------------------------------------------------------------

def deliver(
    *,
    instance_id: int,
    vendor_slug: str,
    adapter: Any,
    envelope: dict[str, Any],
    event: Any,
    sink: Any,
    default_tenant_slug: Optional[str],
    door: str,
) -> Delivery:
    """Resolve the tenant for `event` (extracted from `envelope`) and ingest it
    there, or hold it in quarantine. `door` is 'poll' or 'webhook'. Raises
    only on a genuine store failure for a KNOWN tenant (the caller decides:
    a webhook answers 5xx so the vendor retries; a poller logs and moves on)."""
    vendor_tid = adapter.route_to_tenant(envelope)
    hook = getattr(adapter, "vendor_tenant_label", None)
    label = hook(envelope) if callable(hook) else None
    res = resolve_tenant(
        instance_id=instance_id,
        vendor_slug=vendor_slug,
        vendor_tenant_id=vendor_tid,
        vendor_tenant_label=label,
        default_tenant_slug=default_tenant_slug,
        supports_discovery=bool(getattr(type(adapter), "supports_tenant_discovery", False)),
        allow_passthrough=bool(getattr(type(adapter), "tenant_ids_are_slugs", True)),
    )
    if res.slug is not None:
        inner = getattr(sink, "inner", sink)
        try:
            outcome = inner.ingest(res.slug, vendor_slug, event)
        except FileNotFoundError:
            # Registered but no events.db (a seeded row, a half-provisioned
            # tenant): hold rather than lose it.
            held = _hold(instance_id, vendor_slug, door, "store-failed", envelope, event, res)
            if held.created:
                freshness.record_event(instance_id=instance_id)
            return Delivery(
                "quarantined", res.outcome, slug=None, reason="store-failed",
                quarantine_id=held.id, quarantine_created=held.created,
            )
        duplicate = bool(getattr(outcome, "duplicate", False))
        if not duplicate:
            freshness.record_event(instance_id=instance_id, slug=res.slug)
        return Delivery(
            "duplicate" if duplicate else "stored", res.outcome, slug=res.slug,
            event_id=getattr(outcome, "event_id", None),
        )

    held = _hold(instance_id, vendor_slug, door, res.reason or "no-tenant-id", envelope, event, res)
    if held.created:
        # Received (a re-listed alert already held is not news) — but it
        # belongs to no tenant yet.
        freshness.record_event(instance_id=instance_id)
    return Delivery(
        "quarantined", res.outcome, reason=res.reason,
        quarantine_id=held.id, quarantine_created=held.created,
    )


def _hold(
    instance_id: int, vendor_slug: str, door: str, reason: str,
    envelope: dict[str, Any], event: Any, res: Resolution,
) -> quarantine.Held:
    return quarantine.hold(
        instance_id=instance_id,
        vendor_slug=vendor_slug,
        source=door,
        reason=reason,
        payload=envelope,
        vendor_tenant_id=res.vendor_tenant_id,
        vendor_tenant_label=res.vendor_tenant_label,
        event_summary=getattr(event, "summary", None),
        payload_sha256=getattr(event, "payload_sha256", None),
    )
