#!/usr/bin/env python3
"""dev_seed.py — provision synthetic tenants + events for the local dev pair.

The dev backend at ~/.octo-dev/data/ ships empty — no clients, no events —
so the V3 throughput widget renders a flat zero line in dev. That makes
widget iteration painful. This script seeds 3 distinctly-synthetic tenants
with a few days of realistic event traffic so dashboards behave the same
way they do against live data.

**Synthetic-only.** Every tenant slug starts with `dev-` so it's
impossible to confuse with a real customer. Re-running is idempotent:
existing rows aren't duplicated, only the tail is topped up to the
target window.

Run it via:
    OCTO_DATA_ROOT=~/.octo-dev/data ./packages/.venv/bin/python scripts/dev_seed.py

Or just let ./scripts/dev.sh call it (it does so by default if
DEV_SEED=1 is set in the environment).

Event-type distribution (illustrative):
  suricata.dns      ~55%
  pihole.query      ~45%
  wazuh.alert       ~0.05% (alerts only, much lower volume)
  suricata.tls      ~0.03%
  opencanary.*      ~0.0001% (rare honeypot hits)

Target rate: ~1,000 events/hour per tenant (EVENTS_PER_HOUR_BASELINE).
Pattern: business-hours (Mon-Fri 8am-5pm UTC) get 1.5x base rate;
night/weekend get 0.5x base. Occasional 5-minute spikes 2x per day.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Repo root on sys.path so the strict dev-root check (apps.octo.dev.dev_root,
# standard library only) imports when this runs as a plain script.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from apps.octo.dev.dev_root import dev_root_problem  # noqa: E402


# Slug-aligned with scripts/dev_seed_buoys.py::SYNTHETIC_BUOYS (the
# canonical 15-buoy fictional demo fleet, agreed 2026-05-19). One tenant
# per buoy keeps /search, /tickets, /fleet, the dashboard widgets, and
# the agent triage feed all reading from the same set of slugs — a click
# on a buoy in the map lands on the same tenant the operator sees in
# /search.
SYNTHETIC_TENANTS: list[tuple[str, str]] = [
    ("dev-buoy-acme",           "[DEV] Acme Corp"),
    ("dev-buoy-vandelay",       "[DEV] Vandelay Imports"),
    ("dev-buoy-soylent",        "[DEV] Soylent Foods"),
    ("dev-buoy-dunder",         "[DEV] Dunder Mifflin"),
    ("dev-buoy-los-pollos",     "[DEV] Los Pollos Hermanos"),
    ("dev-buoy-waystar",        "[DEV] Waystar Media"),
    ("dev-buoy-hooli",          "[DEV] Hooli Cloud"),
    ("dev-buoy-gringotts",      "[DEV] Gringotts Financial"),
    ("dev-buoy-cyberdyne",      "[DEV] Cyberdyne Robotics"),
    ("dev-buoy-pied-piper",     "[DEV] Pied Piper Tech"),
    ("dev-buoy-globex",         "[DEV] Globex Medical"),
    ("dev-buoy-wonka",          "[DEV] Wonka Industries"),
    ("dev-buoy-planet-express", "[DEV] Planet Express"),
    ("dev-buoy-duff",           "[DEV] Duff Brewing"),
    ("dev-buoy-initech",        "[DEV] Initech Legal LLP"),
]

# Event-type weights (must sum to ~1.0). Illustrative mix.
EVENT_TYPE_DISTRIBUTION: list[tuple[str, str, float]] = [
    # (event_type, severity, weight)
    ("suricata.dns",      "info",    0.55),
    ("pihole.query",      "info",    0.44),
    ("suricata.tls",      "info",    0.005),
    ("suricata.http",     "info",    0.002),
    ("suricata.alert",    "low",     0.002),
    ("wazuh.alert",       "medium",  0.0008),
    ("opencanary.telnet", "high",    0.0001),
    ("opencanary.ssh",    "high",    0.00005),
]

# Target volume per tenant. Lowered from 3000 to 1000 (2026-05-19) once
# the synthetic fleet went from 3 to 15 tenants — at 3000/hr × 15 × 3d
# the seeder produces ~3M events and takes 20+ min; 1000/hr keeps it
# under a minute while still rendering as continuous traffic in the UI.
EVENTS_PER_HOUR_BASELINE = 1000
DEFAULT_HISTORY_DAYS = 3


def _events_db_schema_sql() -> str:
    """Build the events.db schema by concatenating migration 002's
    @target:events section + every later migration that ALTERs the
    events table.

    Earlier versions of this script only read migration 002 — that
    skipped migration 004's `summary` column, which the runtime search
    endpoint requires. Each new column-adding migration must be listed
    here so a fresh `dev-seed` matches the runtime backend's expectations.
    """
    repo_root = Path(__file__).resolve().parents[1]
    parts: list[str] = []

    # 002 — base table.
    sql_002 = (repo_root / "apps" / "octo" / "migrations"
               / "002-initialize-client-dbs.sql").read_text()
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in sql_002.splitlines():
        if line.startswith("-- @target:"):
            current = line.split(":", 1)[1].strip()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    parts.append("\n".join(sections["events"]))

    # 004 — adds `summary` column + idempotency-key index + summary index.
    # Only the per-client-events parts; the registry.db pieces of this
    # migration are NOT applicable to events.db.
    parts.append("""
ALTER TABLE events ADD COLUMN summary TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_events_summary
    ON events(summary) WHERE summary != '';
""")

    # 011 — adds agent_notes + agent_pattern_links tables. Per-tenant
    # agent layer per the internal agent-notes-in-search design (notes
    # plus pattern links).
    # We extract directly from the migration file so any future schema
    # change there propagates here automatically.
    sql_011 = (repo_root / "apps" / "octo" / "migrations"
               / "011-agent-notes.sql").read_text()
    parts.append(_extract_target_section(sql_011, "events"))

    # 028 — agent_notes.query_kind column (Slice 7d). Tracks which
    # canned-query template produced operator-triggered enrichment.
    sql_028 = (repo_root / "apps" / "octo" / "migrations"
               / "028-agent-notes-query-kind.sql").read_text()
    parts.append(_extract_target_section(sql_028, "events"))

    # 029 — agent_notes.disposition column (Task #119b). Autonomous Triage
    # L1 verdict (noise/pattern/escalate/uncertain) on every triaged event.
    sql_029 = (repo_root / "apps" / "octo" / "migrations"
               / "029-agent-notes-disposition.sql").read_text()
    parts.append(_extract_target_section(sql_029, "events"))

    # 036 — events.ingested_at (the ARRIVAL time retention ages a signal by)
    # + its index.
    sql_036 = (repo_root / "apps" / "octo" / "migrations"
               / "036-data-tiering-retention.sql").read_text()
    parts.append(_extract_target_section(sql_036, "events"))

    return "\n".join(parts)


def _extract_target_section(sql: str, target: str) -> str:
    """Pull the `@target: <name>` block out of a multi-target migration
    file. Same shape as the runner's parser — kept local to the seeder
    so we don't have to import the apps.octo.migration module."""
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in sql.splitlines():
        if line.startswith("-- @target:"):
            current = line.split(":", 1)[1].strip()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return "\n".join(sections.get(target, []))


def _indicators_db_schema_sql() -> str:
    """Per-client `indicators.db` schema — extracted from migration 002's
    @target:indicators block. Same caveat as `_events_db_schema_sql`:
    any later migration that ALTERs `indicators` must be appended here."""
    repo_root = Path(__file__).resolve().parents[1]
    sql_002 = (repo_root / "apps" / "octo" / "migrations"
               / "002-initialize-client-dbs.sql").read_text()
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in sql_002.splitlines():
        if line.startswith("-- @target:"):
            current = line.split(":", 1)[1].strip()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return "\n".join(sections["indicators"])


def _register_tenant(reg_path: Path, slug: str, display_name: str) -> None:
    conn = sqlite3.connect(reg_path)
    try:
        # kind 'dev': the registry refuses a confirmed tenant without a kind
        # (migration 034), and a seeded tenant IS a dev one.
        conn.execute(
            "INSERT OR IGNORE INTO clients (slug, display_name, kind) VALUES (?, ?, 'dev')",
            (slug, display_name),
        )
        conn.commit()
    finally:
        conn.close()


def _ensure_events_db(client_dir: Path, schema_sql: str) -> None:
    client_dir.mkdir(parents=True, exist_ok=True)
    db = client_dir / "events.db"
    if db.exists():
        # Already initialized; nothing to do.
        return
    conn = sqlite3.connect(db)
    try:
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()


def _ensure_indicators_db(client_dir: Path, schema_sql: str) -> None:
    client_dir.mkdir(parents=True, exist_ok=True)
    db = client_dir / "indicators.db"
    if db.exists():
        return
    conn = sqlite3.connect(db)
    try:
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()


def _tickets_db_schema_sql() -> str:
    """Per-client `tickets.db` schema. Concatenates migration 013's
    base table with every later migration that touches the tickets
    target. Per an internal rule (the dev seed must match the runtime
    schema): each new column-adding migration MUST be listed here or fresh seeds
    silently drift from runtime expectations.

    Layered:
      013 — base tickets table
      014 — ticket_notes table (FK → tickets)
      016 — adds push_to_autotask + is_billable + billing_code_id +
            contract_id columns + ticket_charges + push state tables
      017 — adds due_at column + partial index

    Migration 015 targets registry, not tickets — skip here. Slice 9h
    housecleaning added 014/016/017 after seeder-schema drift was
    found during the 2026-05-22 review.
    """
    repo_root = Path(__file__).resolve().parents[1]
    parts: list[str] = []

    # 013 — base table.
    sql_013 = (repo_root / "apps" / "octo" / "migrations"
               / "013-tickets.sql").read_text()
    parts.append(_extract_target_section(sql_013, "tickets"))

    # 014 — ticket_notes table.
    sql_014 = (repo_root / "apps" / "octo" / "migrations"
               / "014-ticket-notes.sql").read_text()
    parts.append(_extract_target_section(sql_014, "tickets"))

    # 016 — adds 4 ALTER TABLE columns to tickets + ticket_charges.
    # The migration also creates autotask_push_log + autotask_push_state
    # state tables; the @target:tickets section is the canonical block.
    sql_016 = (repo_root / "apps" / "octo" / "migrations"
               / "016-ticket-autotask-writeback.sql").read_text()
    parts.append(_extract_target_section(sql_016, "tickets"))

    # 017 — due_at column + index.
    sql_017 = (repo_root / "apps" / "octo" / "migrations"
               / "017-ticket-due-at.sql").read_text()
    parts.append(_extract_target_section(sql_017, "tickets"))

    return "\n".join(parts)


def _ensure_tickets_db(client_dir: Path, schema_sql: str) -> None:
    client_dir.mkdir(parents=True, exist_ok=True)
    db = client_dir / "tickets.db"
    if db.exists():
        return
    conn = sqlite3.connect(db)
    try:
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()


# Synthetic IOC pool — deterministic per (tenant, rng). Values look
# realistic enough to filter on; none are real. Distribution leans
# heavily toward IPs and domains, the most commonly extracted IOC
# types.
_IOC_TYPE_WEIGHTS: list[tuple[str, float]] = [
    ("ip",     0.45),
    ("domain", 0.35),
    ("url",    0.08),
    ("sha256", 0.06),
    ("md5",    0.03),
    ("sha1",   0.02),
    ("cve",    0.01),
]


def _pick_ioc_type(rng: random.Random) -> str:
    r = rng.random()
    cum = 0.0
    for t, w in _IOC_TYPE_WEIGHTS:
        cum += w
        if r <= cum:
            return t
    return "other"


def _make_ioc_value(ioc_type: str, rng: random.Random) -> str:
    if ioc_type == "ip":
        # Use TEST-NET-2 / 198.51.100.0/24 + TEST-NET-3 / 203.0.113.0/24
        # plus a few generic-looking ranges. NONE of these route.
        net = rng.choice(["198.51.100", "203.0.113", "192.0.2", "185.220.101"])
        return f"{net}.{rng.randint(1, 254)}"
    if ioc_type == "domain":
        base = rng.choice([
            "fake-update-server", "tracker-cdn", "ad-pixel-relay",
            "miner-pool-edge", "synthetic-c2", "lure-cdn",
        ])
        tld = rng.choice([".test", ".invalid", ".example"])
        return f"{base}-{rng.randint(100, 999)}{tld}"
    if ioc_type == "url":
        host = _make_ioc_value("domain", rng)
        path = rng.choice(["/update", "/beacon", "/track", "/install.sh", "/payload"])
        return f"https://{host}{path}"
    if ioc_type == "sha256":
        return "".join(rng.choice("0123456789abcdef") for _ in range(64))
    if ioc_type == "sha1":
        return "".join(rng.choice("0123456789abcdef") for _ in range(40))
    if ioc_type == "md5":
        return "".join(rng.choice("0123456789abcdef") for _ in range(32))
    if ioc_type == "cve":
        return f"CVE-{rng.choice([2024, 2025, 2026])}-{rng.randint(1000, 49999)}"
    return f"synthetic-{rng.randint(1000, 99999)}"


def _make_ioc_context(ioc_type: str, ioc_value: str, rng: random.Random) -> str:
    if ioc_type == "ip":
        return rng.choice([
            f"Outbound connection to {ioc_value} flagged by suricata",
            f"Repeated DNS queries returned {ioc_value}",
            f"Honeypot interaction from {ioc_value}",
        ])
    if ioc_type == "domain":
        return rng.choice([
            f"DGA-pattern domain {ioc_value} contacted by 2 endpoints",
            f"NXDOMAIN spike on {ioc_value}",
            f"Pi-hole blocked {ioc_value}",
        ])
    if ioc_type == "url":
        return f"HTTP GET observed against {ioc_value}"
    if ioc_type in ("sha256", "sha1", "md5"):
        return f"File hash matched in {rng.randint(1, 4)} endpoint scan(s)"
    if ioc_type == "cve":
        return f"Affected package observed in inventory; severity per NVD"
    return "Synthetic context"


def _ioc_severity(rng: random.Random) -> str:
    r = rng.random()
    if r < 0.55:
        return "low"
    if r < 0.85:
        return "medium"
    if r < 0.97:
        return "high"
    return "critical"


# ---------------------------------------------------------------------------
# Agent notes + pattern links — synthetic seed
# ---------------------------------------------------------------------------
#
# Spec: the internal agent-notes-in-search design (notes plus pattern
# links). Per the
# build order, ~10% of seeded events get an `agent_notes` row from
# one of shallow/deep/athena. A subset of those rows also get a
# pattern-link edge to another event in the same tenant.
#
# This is fixture data — none of it represents real agent reasoning;
# it just exists so the /search drawer + future /tickets sidecar can
# render against representative shapes during dev.

_AGENT_NOTE_TEMPLATES: list[tuple[str, str, float]] = [
    # (agent_id, template-prefix, base_confidence)
    #
    # 'octo' = the data-plane agent shipped in the OCTO container.
    # Default: deterministic heuristic rules. Optional LLM context mode
    # (post-launch) produces the higher-confidence summaries below.
    #
    # 'athena' = future analyst-partner orchestrator (conversational,
    # not yet built). Templates here are PREVIEWS so the UI distinction
    # is meaningful in dev; they get replaced by real conversational
    # output when that workstream lands.
    ("octo",   "Heuristic flag — pattern matches",                       0.62),
    ("octo",   "Repeat behaviour from same host:",                       0.58),
    ("octo",   "Cross-correlation across recent events suggests",        0.74),
    ("octo",   "Detected anomaly: deviation from baseline",              0.71),
    ("athena", "Operator-facing summary (preview, athena not built):",   0.85),
    ("athena", "Recommend triage as (preview, athena not built):",       0.82),
]

_PATTERN_RELATIONS: list[tuple[str, str]] = [
    ("same_ioc",  "Same indicator value as the linked event."),
    ("same_host", "Same source_host as the linked event."),
    ("same_ttp",  "Same MITRE technique observed."),
    ("temporal",  "Occurred within 90s of the linked event."),
    ("semantic", "Embedding similarity above 0.78."),
]


def _make_agent_note(event_type: str, severity: str, rng: random.Random) -> tuple[str, str, float]:
    """Return (agent_id, note_text, confidence). Touch of variability
    keyed off the event's own type so notes feel attached rather than
    boilerplate."""
    agent_id, prefix, base_conf = rng.choice(_AGENT_NOTE_TEMPLATES)
    tail = {
        "suricata.dns":     "DNS-tunnel-shaped query.",
        "suricata.tls":     "JA3 fingerprint loosely matches known C2.",
        "pihole.query":     "ad/track domain — low signal but high volume.",
        "wazuh.alert":      f"rule_level={rng.randint(3,12)}; likely {severity}.",
        "suricata.alert":   "ET ruleset hit; needs human eyes.",
        "opencanary.ssh":   "honeypot tripped from new source IP.",
        "opencanary.telnet": "honeypot tripped — uncommon protocol in this segment.",
    }.get(event_type, "see payload for context.")
    confidence = round(min(0.99, max(0.05, base_conf + rng.gauss(0, 0.08))), 2)
    return agent_id, f"{prefix} {tail}", confidence


def seed_agent_layer(
    client_dir: Path,
    note_target_ratio: float,
    pattern_link_ratio: float,
    rng: random.Random,
) -> tuple[int, int]:
    """Insert `agent_notes` for ~note_target_ratio of recent events and
    `agent_pattern_links` for ~pattern_link_ratio of those notes.

    Idempotent: looks at the highest existing agent_notes.id and only
    adds for newer events. Returns (notes_added, links_added)."""
    db = client_dir / "events.db"
    if not db.exists():
        return 0, 0
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        # Skip if tables aren't present (e.g., the dev DB pre-dates
        # migration 011 and the in-script schema-update hasn't run).
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        if "agent_notes" not in names or "agent_pattern_links" not in names:
            return 0, 0

        # "Recent" = the last 12 hours of events. We avoid annotating
        # the entire historical window — keeps fixture cost bounded.
        recent_cutoff = (datetime.now(timezone.utc) - timedelta(hours=12))
        cutoff_iso = recent_cutoff.isoformat(timespec="milliseconds").replace("+00:00", "Z")

        # Only insert notes for events that don't already have one.
        # The LEFT JOIN keeps this idempotent — re-running the seeder
        # doesn't duplicate notes.
        candidate_rows = conn.execute(
            """
            SELECT e.id, e.event_type, e.severity, e.source_host
              FROM events e
              LEFT JOIN agent_notes n
                ON n.ref_kind = 'event' AND n.ref_id = e.id
             WHERE e.received_at >= ?
               AND n.id IS NULL
             ORDER BY e.id DESC
             LIMIT 5000
            """,
            (cutoff_iso,),
        ).fetchall()

        note_inserts: list[tuple] = []
        for row in candidate_rows:
            if rng.random() > note_target_ratio:
                continue
            agent_id, note_text, confidence = _make_agent_note(
                row["event_type"], row["severity"], rng,
            )
            note_inserts.append((
                "event",
                row["id"],
                agent_id,
                note_text,
                confidence,
                f"synthetic-{rng.randrange(10**8):08d}",
            ))
        if note_inserts:
            conn.executemany(
                "INSERT INTO agent_notes "
                "(ref_kind, ref_id, agent_id, note_text, confidence, "
                " audit_request_id) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                note_inserts,
            )

        # Pattern links — for a fraction of the annotated events, link
        # to another recent event in the same tenant with one of the
        # five relation types.
        link_inserts: list[tuple] = []
        annotated_event_ids = [r[1] for r in note_inserts]
        if annotated_event_ids:
            other_pool = [r["id"] for r in candidate_rows]
            for from_id in annotated_event_ids:
                if rng.random() > pattern_link_ratio:
                    continue
                if len(other_pool) < 2:
                    continue
                to_id = from_id
                # avoid self-edge
                attempts = 0
                while to_id == from_id and attempts < 5:
                    to_id = rng.choice(other_pool)
                    attempts += 1
                if to_id == from_id:
                    continue
                relation, rationale = rng.choice(_PATTERN_RELATIONS)
                strength = round(rng.uniform(0.55, 0.95), 2)
                # Weighted toward 'octo' (the actual data-plane agent
                # identity). 'athena' kept in the mix as a placeholder
                # preview until the conversational orchestrator ships.
                agent = rng.choice(["octo", "octo", "octo", "octo", "athena"])
                link_inserts.append((
                    "event", from_id, "event", to_id,
                    relation, strength, rationale, agent,
                ))
            if link_inserts:
                conn.executemany(
                    "INSERT INTO agent_pattern_links "
                    "(from_kind, from_id, to_kind, to_id, "
                    " relation, strength, rationale, created_by_agent) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    link_inserts,
                )
        conn.commit()
        return len(note_inserts), len(link_inserts)
    finally:
        conn.close()


# Tuning: roughly 12% of recent events get an agent note, and ~30%
# of those get a pattern-link edge.
AGENT_NOTE_RATIO = 0.12
PATTERN_LINK_RATIO = 0.30


def _latest_received_at(db: Path) -> datetime | None:
    """Returns the most recent received_at as a UTC datetime, or None
    if the DB is empty. Used for idempotent top-up."""
    if not db.exists():
        return None
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT received_at FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return None
    # ISO-8601 with milliseconds and 'Z'
    s = row[0].rstrip("Z")
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


def _hourly_rate_factor(t: datetime) -> float:
    """Business-hours multiplier — 1.5x weekdays 8am-5pm UTC,
    0.5x night/weekend. Crude but enough texture for a dev curve."""
    weekday = t.weekday()  # Mon=0, Sun=6
    hour = t.hour
    if weekday < 5 and 8 <= hour < 17:
        return 1.5
    if weekday >= 5 or hour < 6 or hour >= 22:
        return 0.5
    return 1.0


def _pick_event_type(rng: random.Random) -> tuple[str, str]:
    r = rng.random()
    acc = 0.0
    for et, sev, w in EVENT_TYPE_DISTRIBUTION:
        acc += w
        if r <= acc:
            return et, sev
    # Fallback — should never hit if weights sum to ~1
    return EVENT_TYPE_DISTRIBUTION[0][0], EVENT_TYPE_DISTRIBUTION[0][1]


def _make_summary(event_type: str, source_host: str, rng: random.Random) -> str:
    """Short operator-facing one-liner for the row. Mirrors what each
    adapter's `human_summary()` would emit in production, but kept
    deterministic-feeling so search results read as recognizable lines
    instead of `synthetic-…` placeholders."""
    if event_type == "suricata.dns":
        return f"DNS query observed on {source_host}"
    if event_type == "suricata.tls":
        return f"TLS handshake observed on {source_host}"
    if event_type == "pihole.query":
        return f"Pi-hole query · {source_host}"
    if event_type == "wazuh.alert":
        return f"Wazuh rule level {rng.randint(3, 12)} on {source_host}"
    if event_type == "opencanary.honeypot":
        return f"Honeypot trip on {source_host}"
    return f"{event_type} from {source_host}"


def _make_payload(event_type: str, tenant_slug: str, rng: random.Random) -> str:
    """Return a compact synthetic payload matching the shape adapters
    emit. Just enough structure for `summary` columns and event-type
    drilldowns to work — not full fidelity."""
    base = {
        "_adapter": event_type.split(".")[0],
        "_adapter_version": "dev",
        "_buoy": f"buoy-{tenant_slug.removeprefix('dev-')}-1",
        "event_type": event_type,
        "_synthetic": True,
    }
    if event_type == "suricata.dns":
        base["dns"] = {
            "query": rng.choice([
                "windows.msn.com", "googleads.g.doubleclick.net",
                "www.example.com", "telemetry.local",
            ]),
            "type": "A",
        }
    elif event_type == "pihole.query":
        base["raw_query"] = {
            "client": f"192.168.{rng.randint(1, 4)}.{rng.randint(2, 254)}",
            "domain": rng.choice([
                "windows.msn.com", "captive.apple.com",
                "ntp.ubuntu.com", "edge.microsoft.com",
            ]),
        }
    elif event_type == "wazuh.alert":
        base["rule"] = {
            "id": str(rng.randint(5000, 5999)),
            "level": rng.randint(3, 12),
        }
    return json.dumps(base, separators=(",", ":"))


def _insert_batch(
    db: Path, batch: list[tuple[str, str, str, str, str, str, str, str]],
) -> None:
    """Insert (received_at, source, source_host, event_type, severity,
    payload, payload_sha256, summary) tuples. payload_sha256 is a
    placeholder — NOT a real hash; this is synthetic data."""
    conn = sqlite3.connect(db)
    try:
        conn.executemany(
            "INSERT INTO events "
            "(received_at, source, source_host, event_type, severity, "
            " payload, payload_sha256, summary, ingested_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            # Synthetic history: its arrival is its received_at.
            [(*row, row[0]) for row in batch],
        )
        conn.commit()
    finally:
        conn.close()


def seed_tickets(
    client_dir: Path,
    tickets_schema_sql: str,
    rng: random.Random,
    target_count: int = 25,
) -> int:
    """Derive synthetic tickets from recent high/medium-severity events.

    Tickets are how the operator surface gets exercised before Autotask
    round-trip is wired, so we want a believable distribution:

        new                ~25%   (just landed, unassigned)
        in_progress        ~30%   (assigned, mid-investigation)
        waiting_customer   ~15%   (blocked on tenant reply)
        waiting_vendor     ~10%   (blocked on vendor RMA / EDR triage)
        resolved           ~10%   (fixed but kept open for grace window)
        closed             ~10%   (terminal)

    Severity, title, source_event_id all inherit from the originating
    event. Assignment is split: ~60% assigned to operator_id=1 (the
    factory super_admin in dev), the rest unassigned to exercise the
    'queue' filter path. autotask_id is left NULL — these are
    Athena-originated until/unless we wire the round-trip.

    Idempotent: we look at the highest existing source_event_id and
    only consider events newer than that on each run.
    """
    _ensure_tickets_db(client_dir, tickets_schema_sql)
    tdb = client_dir / "tickets.db"
    edb = client_dir / "events.db"
    if not edb.exists():
        return 0

    # Find the watermark — last seeded source_event_id.
    t = sqlite3.connect(tdb)
    try:
        row = t.execute(
            "SELECT COALESCE(MAX(source_event_id), 0), COUNT(*) FROM tickets"
        ).fetchone()
        watermark, current_count = row[0], row[1]
    finally:
        t.close()

    if current_count >= target_count:
        return 0

    # Pull eligible events. Filter to medium+ severity since that's the
    # band where an MSP would actually cut a ticket.
    e = sqlite3.connect(edb)
    e.row_factory = sqlite3.Row
    try:
        rows = e.execute(
            "SELECT id, severity, summary, event_type, source_host, received_at "
            "  FROM events "
            " WHERE id > ? AND severity IN ('medium','high','critical') "
            " ORDER BY id ASC LIMIT 200",
            (watermark,),
        ).fetchall()
    finally:
        e.close()
    if not rows:
        return 0

    needed = max(0, target_count - current_count)
    chosen = rows[: needed * 3]  # sampling pool 3x the target so distribution stays varied

    status_weights: list[tuple[str, float]] = [
        ("new",              0.25),
        ("in_progress",      0.30),
        ("waiting_customer", 0.15),
        ("waiting_vendor",   0.10),
        ("resolved",         0.10),
        ("closed",           0.10),
    ]

    def _pick_status() -> str:
        r = rng.random(); cum = 0.0
        for s, w in status_weights:
            cum += w
            if r <= cum:
                return s
        return "new"

    queues = ["L1", "after-hours", "compliance", None, None, None]

    t = sqlite3.connect(tdb)
    inserted = 0
    try:
        for row in chosen:
            if inserted >= needed:
                break
            status = _pick_status()
            assignee = 1 if rng.random() < 0.6 else None
            queue = rng.choice(queues) if assignee is None else None
            title_root = row["summary"] or f"{row['event_type']} from {row['source_host']}"
            title = f"[{row['severity'].upper()}] {title_root[:80]}"
            description = (
                f"Auto-derived from event #{row['id']} ({row['event_type']}) "
                f"received {row['received_at']}. Synthetic — DEV seed."
            )
            closed_at = row["received_at"] if status in ("closed", "resolved") else None
            cur = t.execute(
                "INSERT INTO tickets "
                "(title, description, severity, status, "
                " assignee_operator_id, queue, source_event_id, "
                " opened_at, updated_at, closed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (title, description, row["severity"], status,
                 assignee, queue, row["id"],
                 row["received_at"], row["received_at"], closed_at),
            )
            tid = cur.lastrowid
            # Initial 'new' history row.
            t.execute(
                "INSERT INTO ticket_status_history "
                "(ticket_id, from_status, to_status, "
                " changed_by_operator_id, reason, source, changed_at) "
                "VALUES (?, NULL, 'new', NULL, 'auto-derived from event', "
                " 'system', ?)",
                (tid, row["received_at"]),
            )
            if status != "new":
                t.execute(
                    "INSERT INTO ticket_status_history "
                    "(ticket_id, from_status, to_status, "
                    " changed_by_operator_id, reason, source, changed_at) "
                    "VALUES (?, 'new', ?, ?, ?, 'operator', ?)",
                    (tid, status, assignee or 1,
                     f"seed: transitioned to {status}",
                     row["received_at"]),
                )

            # Agent annotation on the ticket itself — ~35% of seeded
            # tickets get a `ref_kind='ticket'` agent_note in events.db
            # so the operator can see the "agent has weighed in" badge
            # on the list page without opening every ticket. Notes are
            # idempotent against the seed's RNG because the watermark
            # filters out tickets we've already processed.
            if rng.random() < 0.35:
                agent_id, note_text, conf = _make_agent_note(
                    row["event_type"], row["severity"], rng,
                )
                # Insert into the parent events.db (where agent_notes
                # lives). Same connection style as seed_agent_layer.
                ae = sqlite3.connect(edb)
                try:
                    ae.execute(
                        "INSERT INTO agent_notes "
                        "(ref_kind, ref_id, agent_id, note_text, "
                        " confidence, audit_request_id, created_at) "
                        "VALUES ('ticket', ?, ?, ?, ?, ?, ?)",
                        (tid, agent_id, note_text, conf,
                         f"seed-{rng.randrange(10**8):08d}",
                         row["received_at"]),
                    )
                    ae.commit()
                finally:
                    ae.close()
            inserted += 1
        t.commit()
    finally:
        t.close()
    return inserted


def seed_indicators(
    client_dir: Path,
    indicators_schema_sql: str,
    target_count: int,
    history_days: int,
    rng: random.Random,
) -> int:
    """Top up per-client `indicators.db` to `target_count` rows. Idempotent:
    no-op once the DB has >= target rows. About 15% of inserted indicators
    are marked `promoted` (manually-flagged high-confidence) — the rest
    are auto-extracted with mid-range confidence.

    Synthetic IOC values use TEST-NET ranges + `.test/.invalid/.example`
    TLDs so none of them route or resolve. Promoted/unpromoted split lets
    the future C-mode `promoted_only` filter actually exercise both
    states in dev."""
    _ensure_indicators_db(client_dir, indicators_schema_sql)
    db = client_dir / "indicators.db"
    conn = sqlite3.connect(db)
    try:
        existing = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
        needed = max(0, target_count - existing)
        if needed == 0:
            return 0
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(days=history_days)
        batch: list[tuple] = []
        for _ in range(needed):
            ioc_type = _pick_ioc_type(rng)
            value = _make_ioc_value(ioc_type, rng)
            severity = _ioc_severity(rng)
            confidence = round(rng.uniform(0.30, 0.95), 2)
            first_seen = window_start + timedelta(
                seconds=rng.uniform(0, (now - window_start).total_seconds()),
            )
            last_seen = first_seen + timedelta(
                seconds=rng.uniform(0, max(1, (now - first_seen).total_seconds())),
            )
            hits = rng.randint(1, 40)
            promoted_at = None
            if rng.random() < 0.15:
                promoted_at = (first_seen + timedelta(
                    seconds=rng.uniform(0, (last_seen - first_seen).total_seconds()),
                )).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            batch.append((
                value,
                ioc_type,
                "synthetic-dev-extractor",
                severity,
                confidence,
                _make_ioc_context(ioc_type, value, rng),
                first_seen.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                last_seen.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                hits,
                promoted_at,
            ))
        # INSERT OR IGNORE to skip the very rare (value, type) duplicates
        # the random generator can produce.
        conn.executemany(
            "INSERT OR IGNORE INTO indicators "
            "(value, type, source, severity, confidence, context, "
            " first_seen, last_seen, hits, promoted_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            batch,
        )
        conn.commit()
        return conn.total_changes
    finally:
        conn.close()


# Target IOC volume per tenant in dev. Enough variety to exercise filters
# without making the table feel cluttered.
INDICATORS_PER_TENANT_TARGET = 250


def seed_tenant(
    data_root: Path,
    slug: str,
    display_name: str,
    schema_sql: str,
    history_days: int,
    rng: random.Random,
    indicators_schema_sql: str | None = None,
    tickets_schema_sql: str | None = None,
    seed_agent_layer_enabled: bool = True,
) -> dict:
    reg = data_root / "registry.db"
    client_dir = data_root / "clients" / slug
    db = client_dir / "events.db"

    _register_tenant(reg, slug, display_name)
    _ensure_events_db(client_dir, schema_sql)

    # Indicators are seeded once per tenant (or topped up to target).
    iocs_added = 0
    if indicators_schema_sql is not None:
        iocs_added = seed_indicators(
            client_dir, indicators_schema_sql,
            target_count=INDICATORS_PER_TENANT_TARGET,
            history_days=history_days, rng=rng,
        )

    now = datetime.now(timezone.utc).replace(microsecond=0)
    window_start = now - timedelta(days=history_days)

    # Idempotent top-up: only generate events after the last existing one.
    last = _latest_received_at(db)
    gen_start = max(window_start, last + timedelta(seconds=1)) if last else window_start
    if gen_start >= now:
        # Even when events are current, the agent layer may still have
        # rows to add (e.g., last tick inserted new events without
        # notes yet — this tick fills them in).
        if seed_agent_layer_enabled:
            notes_added_early, links_added_early = seed_agent_layer(
                client_dir, AGENT_NOTE_RATIO, PATTERN_LINK_RATIO, rng,
            )
        else:
            notes_added_early, links_added_early = 0, 0
        return {
            "slug": slug, "added": 0, "iocs_added": iocs_added,
            "notes_added": notes_added_early,
            "links_added": links_added_early,
            "skipped": "events already up-to-date",
        }

    source = f"buoy:buoy-{slug.removeprefix('dev-')}-1 [DEV synthetic]"
    source_host = f"buoy-{slug.removeprefix('dev-')}-1"

    batch: list[tuple[str, str, str, str, str, str, str]] = []
    BATCH_SIZE = 5000
    inserted = 0

    cursor = gen_start
    one_minute = timedelta(minutes=1)
    while cursor < now:
        rate_factor = _hourly_rate_factor(cursor)
        # Inject occasional spikes — 1-2 per day, lasting ~5 min, +3x
        if rng.random() < (1 / (60 * 12)):  # ~ twice a day if iterating per minute
            rate_factor *= 3.0
        events_this_minute = max(
            1, int((EVENTS_PER_HOUR_BASELINE / 60) * rate_factor + rng.gauss(0, 5))
        )
        for _ in range(events_this_minute):
            jitter_sec = rng.uniform(0, 60)
            ts = cursor + timedelta(seconds=jitter_sec)
            if ts >= now:
                break
            et, sev = _pick_event_type(rng)
            ts_iso = ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")
            batch.append((
                ts_iso, source, source_host, et, sev,
                _make_payload(et, slug, rng),
                "synthetic-" + "0" * 56,
                _make_summary(et, source_host, rng),
            ))
            if len(batch) >= BATCH_SIZE:
                _insert_batch(db, batch)
                inserted += len(batch)
                batch.clear()
        cursor += one_minute

    if batch:
        _insert_batch(db, batch)
        inserted += len(batch)

    # Agent layer — synthetic notes + pattern links over recent events.
    # Idempotent (skips events that already have notes), so it's safe
    # to call on every continuous tick. Gated by
    # seed_agent_layer_enabled so the operator can run the seeder
    # without manufacturing fake triage notes (e.g., when octo-llm
    # is running and they want the feed to show only real output).
    if seed_agent_layer_enabled:
        notes_added, links_added = seed_agent_layer(
            client_dir, AGENT_NOTE_RATIO, PATTERN_LINK_RATIO, rng,
        )
    else:
        notes_added, links_added = 0, 0

    tickets_added = 0
    if tickets_schema_sql is not None:
        tickets_added = seed_tickets(client_dir, tickets_schema_sql, rng)

    return {
        "slug": slug, "added": inserted,
        "iocs_added": iocs_added,
        "notes_added": notes_added,
        "links_added": links_added,
        "tickets_added": tickets_added,
        "window_from": gen_start.isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-root", default=os.environ.get("OCTO_DATA_ROOT"),
        help="OCTO data root (default: $OCTO_DATA_ROOT)",
    )
    parser.add_argument(
        "--days", type=int, default=DEFAULT_HISTORY_DAYS,
        help=f"Days of history to seed (default: {DEFAULT_HISTORY_DAYS})",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="RNG seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--continuous", action="store_true",
        help=(
            "After the initial top-up, keep running and emit new events on "
            "a tick. Useful for keeping the /search default 15m window "
            "populated without manually re-running. Ctrl+C to stop. "
            "See --tick-seconds."
        ),
    )
    parser.add_argument(
        "--tick-seconds", type=int, default=15,
        help=(
            "In --continuous mode, sleep this many seconds between "
            "top-up batches (default: 15). Lower = more responsive, "
            "higher = less CPU."
        ),
    )
    parser.add_argument(
        "--no-agent-layer", action="store_true",
        default=(os.environ.get("DEV_SEED_AGENT_LAYER", "1") != "1"),
        help=(
            "Skip seeding synthetic agent_notes + agent_pattern_links. "
            "Use this when you have octo-llm running locally and want "
            "the /tickets Agent Triage Feed to show ONLY real model-"
            "generated notes. Defaults from env DEV_SEED_AGENT_LAYER=0."
        ),
    )
    args = parser.parse_args()

    if not args.data_root:
        print("ERROR: --data-root or OCTO_DATA_ROOT required", file=sys.stderr)
        return 2
    data_root = Path(args.data_root).expanduser()

    # Refuse to run against any non-dev data root, before touching anything
    # under it. The `dev-` slug prefix + this check catch the footguns; the
    # check is the strict one (resolved path under ~/.octo-dev, /tmp or
    # /var/tmp, never a production data-root location), not a substring.
    problem = dev_root_problem(data_root)
    if problem is not None:
        print(f"REFUSING: {problem}. Synthetic data MUST NOT touch real OCTO "
              "bundles.", file=sys.stderr)
        return 3
    data_root = data_root.resolve()

    if not (data_root / "registry.db").exists():
        print(f"ERROR: registry.db not found under {data_root}", file=sys.stderr)
        print("       Start the dev backend once first to provision it.",
              file=sys.stderr)
        return 2

    schema_sql = _events_db_schema_sql()
    indicators_schema_sql = _indicators_db_schema_sql()
    tickets_schema_sql = _tickets_db_schema_sql()
    rng = random.Random(args.seed)
    print(f"[dev_seed] seeding {len(SYNTHETIC_TENANTS)} tenants into {data_root}")
    print(f"[dev_seed]   target window: last {args.days} days @ "
          f"~{EVENTS_PER_HOUR_BASELINE} events/hr/tenant")
    print(f"[dev_seed]   indicators target: {INDICATORS_PER_TENANT_TARGET}/tenant "
          "(mix of auto-extracted + ~15% promoted)")
    print(f"[dev_seed]   distribution: {[e[0] for e in EVENT_TYPE_DISTRIBUTION[:3]]}+...")
    print()
    total_added = 0
    total_iocs = 0
    total_notes = 0
    total_links = 0
    total_tickets = 0
    for slug, display_name in SYNTHETIC_TENANTS:
        # Re-seed the RNG so tenants get reproducibly different streams
        rng = random.Random(args.seed + hash(slug) % 10000)
        result = seed_tenant(
            data_root, slug, display_name, schema_sql, args.days, rng,
            indicators_schema_sql=indicators_schema_sql,
            tickets_schema_sql=tickets_schema_sql,
            seed_agent_layer_enabled=not args.no_agent_layer,
        )
        iocs = result.get("iocs_added", 0)
        notes = result.get("notes_added", 0)
        links = result.get("links_added", 0)
        tickets = result.get("tickets_added", 0)
        total_iocs += iocs
        total_notes += notes
        total_links += links
        total_tickets += tickets
        if "skipped" in result:
            print(f"  {slug:<22} — events up-to-date · +{iocs} IOC(s) "
                  f"· +{notes} note(s) · +{links} link(s) · +{tickets} ticket(s)")
        else:
            print(f"  {slug:<22} — +{result['added']:,} events · +{iocs} IOC(s) "
                  f"· +{notes} note(s) · +{links} link(s) · +{tickets} ticket(s)")
            total_added += result["added"]
    print()
    print(f"[dev_seed] done. Total: {total_added:,} events + {total_iocs} indicators "
          f"+ {total_notes} agent notes + {total_links} pattern links "
          f"+ {total_tickets} tickets inserted.")
    print(f"[dev_seed] To re-seed from scratch: rm -rf "
          f"{data_root}/clients/dev-* && re-run.")

    if args.continuous:
        return _run_continuous(
            data_root=data_root,
            schema_sql=schema_sql,
            indicators_schema_sql=indicators_schema_sql,
            tickets_schema_sql=tickets_schema_sql,
            seed=args.seed,
            history_days=args.days,
            tick_seconds=args.tick_seconds,
            seed_agent_layer_enabled=not args.no_agent_layer,
        )

    return 0


def _run_continuous(
    *,
    data_root: Path,
    schema_sql: str,
    indicators_schema_sql: str,
    tickets_schema_sql: str,
    seed: int,
    history_days: int,
    tick_seconds: int,
    seed_agent_layer_enabled: bool = True,
) -> int:
    """Sleep-loop that tops up each tenant's events.db on a tick.

    Each iteration calls `seed_tenant()` — its internal "generate from
    last_received_at to now" logic means we only ever insert events
    *after* the previous tick's tail. If a tick takes longer than
    `tick_seconds` (e.g., a slow disk), the next iteration just covers
    the extra elapsed time on its first pass, no events are skipped.

    The IOC count is held steady — `seed_indicators()` is a noop once
    the per-tenant count hits its target — so the loop only adds
    indicators in the rare case one was deleted manually.

    Ctrl+C (SIGINT) exits cleanly. We trap it explicitly so the cleanup
    line gets printed; KeyboardInterrupt without trapping is ugly under
    a process supervisor.
    """
    import signal
    stop_requested = [False]

    def _on_signal(signum: int, frame: object) -> None:  # noqa: ARG001
        stop_requested[0] = True

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    print()
    print(f"[dev_seed] continuous mode — tick every {tick_seconds}s. Ctrl+C to stop.")
    sys.stdout.flush()
    tick = 0
    total_inserted_continuous = 0
    while not stop_requested[0]:
        tick += 1
        per_tick_added = 0
        for slug, display_name in SYNTHETIC_TENANTS:
            # Per-tenant RNG seeded with tick number so each tick advances
            # the stream deterministically. gen_start moves forward each
            # call via _latest_received_at(), so fresh events emerge even
            # under the fixed parent seed.
            tenant_rng = random.Random(seed + hash(slug) % 10000 + tick)
            result = seed_tenant(
                data_root, slug, display_name, schema_sql, history_days, tenant_rng,
                indicators_schema_sql=indicators_schema_sql,
                tickets_schema_sql=tickets_schema_sql,
                seed_agent_layer_enabled=seed_agent_layer_enabled,
            )
            per_tick_added += result.get("added", 0)
        total_inserted_continuous += per_tick_added

        # One line per tick — at the default 15s interval that's ~4
        # lines/min, fine for a long-running dev tool. Flush so log
        # supervisors see progress without buffering.
        now = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"[dev_seed]   {now}Z · tick {tick:>4} · +{per_tick_added:>3} events "
              f"· {total_inserted_continuous:,} total")
        sys.stdout.flush()

        # Sleep in 1s slices so SIGINT propagates fast.
        for _ in range(tick_seconds):
            if stop_requested[0]:
                break
            time.sleep(1)

    print()
    print(f"[dev_seed] continuous mode stopped after {tick} tick(s) · "
          f"{total_inserted_continuous:,} events emitted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
