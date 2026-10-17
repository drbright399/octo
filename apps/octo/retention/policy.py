"""Retention policy — the data-class catalogue and the EFFECTIVE retention.

Sources, and how they combine (the one place this is decided):

  bundle_config_retention (registry, migration 012 + 036)
      one row per data class: retention_days (super_admin-editable),
      legal_baseline_days, editable. The bundle-wide setting.
  clients.retention_days (registry, migration 001; 30-2555, default 365)
      a per-tenant value that applies to the 'events' class ONLY (it is the
      tenant's signal-event retention; no route writes it today, every row
      holds the 365 default).

  effective(class, tenant) =
      permanent                     when the class's retention_days is NULL
                                    ('audit' — never pruned, not editable);
      max(bundle, tenant)           for 'events' — a tenant value can only
                                    LENGTHEN retention (migration 012: per-
                                    tenant overrides exist for tenants that
                                    need STRICTER, i.e. longer, retention);
                                    shortening one tenant below the bundle
                                    needs an explicit override table that does
                                    not exist;
      bundle                        for every other class;
      … then never below legal_baseline_days (the floor): a super_admin may
      store a below-baseline value (the console warns), the job does not
      delete below the baseline. The result says which rule won (`basis`).

`RETENTION_DEFAULTS` is the fallback when a registry predates a class's
seed row (and the seed the admin surface falls back to).

AGE of a row = when it ARRIVED (owner decision 2026-09-29): a signal by
`events.ingested_at`, raw telemetry by `telemetry_raw.ingested_at`, an
hourly roll-up by `telemetry_hourly.last_arrival` — never the VENDOR's
timestamp (`received_at`: on the source-adapter path the vendor's time of
the event, which stays stored and shown). History a vendor hands over late
(a 400-day-old incident RocketCyber lists today) is kept for the full
retention from today. Rows stored before 036 are aged by their received_at,
the best available estimate, once the one-off backfill has stamped them
(`apps.octo.ingest.arrival`). Agent notes (`created_at`) and indicators
(`last_seen`, `promoted_at`) are Athena's own clock already. The first-seen
ledger's fixed 365-day "forget" rule stays on the sensor's `last_seen`.

FAIL CLOSED for enforcement: the retention JOB reads the policy with
`load_policies(…, strict=True)`, which raises `PolicyUnavailable` when the
registry cannot be read. Falling back to the defaults there would delete
everything a LONGER stored setting (or a tenant's own longer retention) is
keeping — so a job that cannot read the policy deletes nothing. Only the
display paths use the lenient defaults fallback.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Data class → defaults. The migrations seed the same values.
RETENTION_DEFAULTS: dict[str, dict] = {
    "events": {
        "days": 365,
        "legal_baseline_days": 365,
        "regulator_basis": "HIPAA §164.312(b); SOC2 CC7.2; CJIS §5.4.1",
        "editable": True,
        "description": (
            "Ingested SIGNAL events from all source adapters (alerts, "
            "detections, blocked DNS, honeypot hits). Drives the /search "
            "default window + dashboard widgets. 1-year baseline = HIPAA "
            "audit-log floor."
        ),
    },
    "indicators_auto": {
        "days": 90,
        "legal_baseline_days": 90,
        "regulator_basis": "Operational baseline (no regulator citation)",
        "editable": True,
        "description": (
            "IOCs auto-extracted from ingested events. Transient "
            "enrichment — no regulator mandates retention; 90d aligns "
            "with the parent event window."
        ),
    },
    "indicators_promoted": {
        "days": 2190,
        "legal_baseline_days": 2190,
        "regulator_basis": "HIPAA §164.530(j) — 6-year records retention",
        "editable": True,
        "description": (
            "IOCs an analyst has manually promoted. These become part "
            "of the incident record and inherit HIPAA's 6-year "
            "retention floor."
        ),
    },
    "secure_notepad": {
        "days": 90,
        "legal_baseline_days": 90,
        "regulator_basis": "Operational; consolidates into ticket on close",
        "editable": True,
        "description": (
            "Per-ticket secure notepad — ephemeral scratchpad. "
            "Consolidates into the ticket body at close; 90d post-close "
            "shred keeps the buffer tight."
        ),
    },
    "audit": {
        "days": None,
        "legal_baseline_days": None,
        "regulator_basis": "HIPAA §164.312(b); SOC2 CC4.1; SOX §404 — permanent",
        "editable": False,
        "description": (
            "Append-only audit chain. PERMANENT — regulator requirement. "
            "Not editable from this panel; super_admin override would "
            "break the chain-of-custody invariant. Archive to cold "
            "storage instead when size becomes a concern."
        ),
    },
    "agent_notes": {
        "days": 2190,
        "legal_baseline_days": 2190,
        "regulator_basis": "HIPAA §164.530(j) — analyst rationale = incident record",
        "editable": True,
        "description": (
            "Octo agent notes attached to events / tickets / "
            "indicators. Analyst rationale is part of the incident "
            "record under HIPAA's 6-year floor."
        ),
    },
    "telemetry_raw": {
        "days": 7,
        "legal_baseline_days": 7,
        "regulator_basis": (
            "Operational baseline (no regulator citation); long-term raw "
            "copies live in the cold archive"
        ),
        "editable": True,
        "description": (
            "Raw DNS / TLS / HTTP / flow metadata from buoys (telemetry.db). "
            "Archived to a compressed daily file under OCTO_ARCHIVE_ROOT "
            "before it is pruned, when the archive is configured."
        ),
    },
    "telemetry_rollup": {
        "days": 180,
        "legal_baseline_days": 180,
        "regulator_basis": "Operational baseline (no regulator citation)",
        "editable": True,
        "description": (
            "Hourly counts per event type, domain and device (telemetry.db) — "
            "the DNS summary and trend view."
        ),
    },
    # Entity resolution (migration 040, entities.db — `apps.octo.entity.retention`).
    "entity_lookup_lease": {
        "days": 90,
        "legal_baseline_days": 7,
        "regulator_basis": ("Operational baseline (no regulator citation); minimisation — "
                            "leases name people's devices"),
        "editable": True,
        "description": (
            "Who had which LAN address when (entities.db lk_ip_lease, joins, ghosts, MAC "
            "anomalies). Guest networks are kept 7 days whatever this says."
        ),
    },
    "entity_lookup_egress": {
        "days": 400,
        "legal_baseline_days": 30,
        "regulator_basis": "Operational baseline (no regulator citation)",
        "editable": True,
        "description": (
            "Which public address was each site's internet connection when (entities.db "
            "lk_site_egress, subnets). No personal data; places year-old signals."
        ),
    },
    "entity_resolution": {
        "days": 365,
        "legal_baseline_days": 30,
        "regulator_basis": "Follows the signal events it explains",
        "editable": True,
        "description": (
            "Stored answers (\"which site, which device, how sure, why\") for alerts. "
            "Candidate details are cut to a count when the leases behind them are pruned."
        ),
    },
    "entity_links": {
        "days": 400,
        "legal_baseline_days": 30,
        "regulator_basis": "Operational baseline (no regulator citation)",
        "editable": True,
        "description": (
            "Retired and rejected links and expired suppressions, counted from when they "
            "ended. Active links are never pruned."
        ),
    },
    "entity_inventory": {
        "days": 90,
        "legal_baseline_days": 7,
        "regulator_basis": "Operational baseline (no regulator citation)",
        "editable": True,
        "description": (
            "Datto device inventory rows not seen for this long, and NextDNS device "
            "presence hours."
        ),
    },
}

# Classes a per-tenant clients.retention_days applies to.
TENANT_OVERRIDE_CLASSES = frozenset({"events"})

# first_seen_domains: a domain not looked up for this long is forgotten, so
# its return is reported as first-seen again (and random-subdomain churn
# does not grow the ledger forever). Not an editable class: it is part of
# what "first seen" MEANS.
FIRST_SEEN_FORGET_DAYS = 365


@dataclass(frozen=True)
class ClassPolicy:
    data_class: str
    configured_days: Optional[int]
    legal_baseline_days: Optional[int]
    editable: bool


@dataclass(frozen=True)
class EffectiveRetention:
    data_class: str
    days: Optional[int]            # None = permanent
    configured_days: Optional[int]
    legal_baseline_days: Optional[int]
    tenant_days: Optional[int]
    basis: str                     # permanent | bundle | tenant_override | legal_baseline_floor

    @property
    def floored(self) -> bool:
        return self.basis == "legal_baseline_floor"

    def as_dict(self) -> dict:
        return {
            "effective_days": self.days,
            "configured_days": self.configured_days,
            "legal_baseline_days": self.legal_baseline_days,
            "tenant_days": self.tenant_days,
            "basis": self.basis,
        }


def _default_policy(data_class: str) -> ClassPolicy:
    d = RETENTION_DEFAULTS[data_class]
    return ClassPolicy(data_class, d["days"], d["legal_baseline_days"], bool(d["editable"]))


class PolicyUnavailable(Exception):
    """The retention policy (registry) could not be read — enforce nothing."""


def load_policies(
    registry_db: Optional[Path], *, strict: bool = False,
) -> dict[str, ClassPolicy]:
    """Every known class: the registry's row where there is one, the default
    otherwise (a registry that predates a class's seed row).

    strict=False (display): never raises — an unreadable registry yields the
    defaults. strict=True (the retention job): a missing or unreadable
    registry, or a missing bundle_config_retention table, raises
    PolicyUnavailable."""
    out = {k: _default_policy(k) for k in RETENTION_DEFAULTS}
    if registry_db is None or not Path(registry_db).exists():
        if strict:
            raise PolicyUnavailable(f"registry not found: {registry_db}")
        return out
    try:
        conn = sqlite3.connect(f"file:{registry_db}?mode=ro", uri=True, timeout=5.0)
        try:
            rows = conn.execute(
                "SELECT data_class, retention_days, legal_baseline_days, editable "
                "FROM bundle_config_retention"
            ).fetchall()
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as exc:
        if strict:
            raise PolicyUnavailable(
                f"bundle_config_retention unreadable: {type(exc).__name__}: {exc}") from exc
        return out
    for data_class, days, baseline, editable in rows:
        out[data_class] = ClassPolicy(
            data_class,
            int(days) if days is not None else None,
            int(baseline) if baseline is not None else None,
            bool(editable),
        )
    return out


def effective_retention(
    policy: ClassPolicy, *, tenant_days: Optional[int] = None,
) -> EffectiveRetention:
    """The retention the job applies — see the module docstring."""
    tenant = (
        int(tenant_days)
        if tenant_days is not None and policy.data_class in TENANT_OVERRIDE_CLASSES
        else None
    )
    if policy.configured_days is None:
        return EffectiveRetention(
            policy.data_class, None, None, policy.legal_baseline_days, tenant, "permanent",
        )
    configured = policy.configured_days
    baseline = policy.legal_baseline_days
    days = max(d for d in (configured, tenant, baseline) if d is not None)
    # Which rule won: the bundle when it alone suffices; else the floor when
    # the tenant value does not go beyond it (every tenant row holds the
    # 365-day column default, which is not a choice anyone made); else the
    # tenant's own, longer, value.
    if configured >= days:
        basis = "bundle"
    elif baseline is not None and baseline >= (tenant or 0):
        basis = "legal_baseline_floor"
    else:
        basis = "tenant_override"
    return EffectiveRetention(
        policy.data_class, days, configured, baseline, tenant, basis,
    )
