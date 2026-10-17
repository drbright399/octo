"""RESTRICTED evidence — CSAM lookups (rule B7; Rick, 2026-10-06).

  "Confirmed CSAM lookups is an automated Black Tier item. That's
  state/federal law enforcement territory that needs to be handled
  immediately."

WHAT IS KEPT, AND WHERE. A NextDNS block whose reasons include `csam` is NOT
an ordinary alert: the poller never writes it to the tenant's `events`
table (so it is never in an alert list, a search, an export, an indicator,
the threat-intel pulse, the triage worker, a model prompt or the sanitized
pool) and never counts it in the coalescing ledger. It writes the log line
HERE instead — `restricted_evidence` in the tenant's events.db: one row per
line (exactly once: `(source, line_id)` is unique), the line itself and its
sha256, append-only (the triggers refuse a delete, and every update but the
engine's one-time link to its incident). The retention job never touches
this table (it prunes only the tables it knows), so the evidence outlives
any window.

THE RULE. The tier engine reads the rows not yet processed and opens B7 —
an automated, LIVE Black — one incident per DEVICE (the dedupe key names the
device; later lookups append to the open incident, linking their rows). The
incident's evidence window opens from the FIRST lookup (`windows.
first_detection` reads the rows linked here).

WHO SEES IT. Admin and super_admin only — and every view is audited (the
API). An analyst sees "restricted incident at <tenant>" and nothing else; a
client user sees nothing unless the MSP's switch (`registry.
csam_client_notice`, OFF by default) lets the neutral 60-minute line through.
Paging is immediate and neutral: "Restricted Black incident at <tenant> —
open Athena" — never the domain, the URL, the device or the category.

NOTHING IS DONE TO THE DEVICE. No lockdown, isolation, allow / unblock or
remediation step is proposed or offered for a restricted incident —
preserving the evidence and not tipping off the user.

NEVER LOOKED UP. Athena never resolves, fetches, enriches (PTR, RDAP,
threat intelligence, domain age) or previews a domain from a restricted
incident. `refuse_enrichment()` — the gate for any resolve / PTR / RDAP /
domain-age path (none exists in Athena today) — raises `RestrictedContent`
for such a domain, its registrable ROOT (an RDAP lookup is about the root)
or any name under either. The NextDNS log search, the triage worker, both
model calls and every read surface use the EXACT domain (and names under
it) through `Gate` / `restricted_domains` — a root can be a whole hosting
provider. The console shows the value DEFANGED ("example[.]test") under
the fixed "DO NOT OPEN" warning and the checklist below.

OTHER SENSORS (fixer, v0.17.1). The same lookup also reaches Athena through a
buoy: Pi-hole records NextDNS's answer as an upstream block (a SIGNAL in
events.db — and an indicator), Suricata logs the query (telemetry.db). Those
rows usually arrive BEFORE the NextDNS poll keeps the line, so they are not
held back at ingest; they are hidden at READ time instead. `Gate` is the one
check: a tenant's restricted DOMAINS (not their roots), matched at DNS-label
boundaries (the domain itself or a name under it — never a longer name that
merely contains it). Every general surface — the events search and its
payload drawer, the indicators search, the DNS telemetry search and summary,
the export, the dashboard feed and pulse, the Fleet drawer, an incident's
evidence list — leaves those rows out for EVERY role; admins read them in
one place only: the restricted incident's audited detail (`related_records`,
defanged). The triage worker and the model calls skip them, and a model
call waits `SENSOR_HOLD` for a DNS sensor's block (the NextDNS poll may not
have kept the line yet). A list that cannot be read hides / refuses
everything (fail closed).
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from apps.octo import paths
from apps.octo.ingest.timestamps import format_utc_ms, utcnow_iso

logger = logging.getLogger(__name__)

TABLE = "restricted_evidence"
CSAM = "csam"
CATEGORIES = (CSAM,)
BUSY_TIMEOUT_SEC = 10.0
PENDING_BATCH = 500

WARNING = "DO NOT OPEN — do not visit, resolve or investigate the content"
CHECKLIST: tuple[str, ...] = (
    "Do not open or investigate the content yourself.",
    "Preserve the device as-is.",
    "Contact law enforcement (US: report via the NCMEC CyberTipline).",
    "Inform the client's leadership / legal contact — not the user involved.",
    "Confirm your obligations with legal counsel.",
)
# What every operator who is NOT admin+ reads about a restricted incident.
ANALYST_LINE = "restricted incident"
# What the store / the Fleet / Athena's own lifecycle records say about one
# (no category, no device, no domain).
NEUTRAL_SUMMARY = "Restricted incident"
# The admin-visible summary B7 opens with (never the domain).
CSAM_SUMMARY = "CSAM-category lookup blocked by DNS protection"
# The log-line fields kept as evidence (the poller's alert payload keeps the
# same set).
LINE_KEYS = ("timestamp", "domain", "root", "tracker", "encrypted", "protocol", "clientIp",
             "client", "device", "status", "reasons")

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    category      TEXT NOT NULL CHECK (category IN ('csam')),
    source        TEXT NOT NULL,
    line_id       TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    received_at   TEXT NOT NULL,
    profile_id    TEXT,
    device_key    TEXT NOT NULL DEFAULT '',
    device_name   TEXT,
    client_ip     TEXT,
    domain        TEXT NOT NULL DEFAULT '',
    root          TEXT NOT NULL DEFAULT '',
    reasons       TEXT NOT NULL DEFAULT '[]',
    record        TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    incident_id   INTEGER,
    processed_at  TEXT,
    UNIQUE (source, line_id)
);
CREATE INDEX IF NOT EXISTS idx_restricted_evidence_pending ON {TABLE}(processed_at, id);
CREATE INDEX IF NOT EXISTS idx_restricted_evidence_incident ON {TABLE}(incident_id);
CREATE TRIGGER IF NOT EXISTS restricted_evidence_no_delete BEFORE DELETE ON {TABLE}
BEGIN SELECT RAISE(ABORT, 'restricted evidence is never deleted'); END;
CREATE TRIGGER IF NOT EXISTS restricted_evidence_frozen BEFORE UPDATE ON {TABLE}
WHEN OLD.processed_at IS NOT NULL
  OR NEW.id IS NOT OLD.id OR NEW.category IS NOT OLD.category
  OR NEW.source IS NOT OLD.source OR NEW.line_id IS NOT OLD.line_id
  OR NEW.observed_at IS NOT OLD.observed_at OR NEW.received_at IS NOT OLD.received_at
  OR NEW.profile_id IS NOT OLD.profile_id OR NEW.device_key IS NOT OLD.device_key
  OR NEW.device_name IS NOT OLD.device_name OR NEW.client_ip IS NOT OLD.client_ip
  OR NEW.domain IS NOT OLD.domain OR NEW.root IS NOT OLD.root
  OR NEW.reasons IS NOT OLD.reasons OR NEW.record IS NOT OLD.record
  OR NEW.record_sha256 IS NOT OLD.record_sha256
BEGIN SELECT RAISE(ABORT, 'restricted evidence is frozen (linked once to its incident)'); END;
"""


class RestrictedContent(Exception):
    """A value Athena must never resolve, fetch, enrich or preview."""


def has_table(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                        (TABLE,)).fetchone() is not None


def ensure(conn: sqlite3.Connection) -> None:
    """Create the table (idempotent) — inside the caller's transaction."""
    if has_table(conn):
        return
    buf = ""
    for line in _SCHEMA.splitlines(keepends=True):
        buf += line
        if buf.strip() and sqlite3.complete_statement(buf):
            conn.execute(buf.strip())
            buf = ""


def _db(slug: str) -> Path:
    return paths.client_dir(slug) / "events.db"


@contextmanager
def _write(slug: str) -> Iterator[sqlite3.Connection]:
    path = _db(slug)
    if not path.exists():
        raise FileNotFoundError(f"tenant {slug} has no event store")
    conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_SEC, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            ensure(conn)
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


@contextmanager
def _read(slug: str) -> Iterator[Optional[sqlite3.Connection]]:
    path = _db(slug)
    if not path.exists():
        yield None
        return
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        yield conn if has_table(conn) else None
    finally:
        conn.close()


def _clip(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join("".join(c if c.isprintable() else " " for c in value).split())[:limit]


# ---------------------------------------------------------------------------
# Writes — the poller (record) and the store (link, inside its transaction)
# ---------------------------------------------------------------------------

def record_nextdns(slug: str, *, profile_id: str, profile_name: Optional[str],
                   line: dict[str, Any], line_id: str, observed_at: str,
                   arrived: Optional[str] = None) -> Optional[int]:
    """Keep one NextDNS log line carrying a CSAM reason as restricted
    evidence, exactly once. Returns the new row id, None when the line was
    kept before (overlapping windows). Raises sqlite3.Error / OSError (the
    poller treats it as a store fault and reads the page again)."""
    device = line.get("device") if isinstance(line.get("device"), dict) else {}
    kept = {k: line[k] for k in LINE_KEYS if k in line}
    rec = {"source": "nextdns", "profile_id": profile_id, "profile_name": profile_name,
           "line_id": line_id, "log": kept}
    text = json.dumps(rec, sort_keys=True, separators=(",", ":"), default=str)
    domain = _clip(line.get("domain"), 253).lower().rstrip(".")
    root = _clip(line.get("root"), 253).lower().rstrip(".") or domain
    reasons = [r.get("id") if isinstance(r, dict) else r
               for r in (line.get("reasons") if isinstance(line.get("reasons"), list) else [])
               ][:32]
    device_key = _clip(device.get("id"), 64) or _clip(line.get("clientIp"), 64)
    with _write(slug) as conn:
        cur = conn.execute(
            f"INSERT OR IGNORE INTO {TABLE} (category, source, line_id, observed_at, "
            "received_at, profile_id, device_key, device_name, client_ip, domain, root, "
            "reasons, record, record_sha256) VALUES (?, 'nextdns', ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "?, ?, ?)",
            (CSAM, line_id, observed_at, arrived or utcnow_iso(), profile_id, device_key,
             _clip(device.get("name"), 128) or None, _clip(line.get("clientIp"), 64) or None,
             domain, root, json.dumps(reasons, default=str), text,
             hashlib.sha256(text.encode("utf-8")).hexdigest()))
        return int(cur.lastrowid) if cur.rowcount == 1 else None


def link(conn: sqlite3.Connection, ids: Iterable[int], incident_id: Optional[int],
         at_s: str) -> int:
    """Link not-yet-processed rows to their incident (None: processed with no
    incident — an analyst verdict blocked the key) — ONCE, inside the
    caller's transaction. Returns how many rows were linked."""
    want = [int(i) for i in ids if isinstance(i, int) and not isinstance(i, bool)]
    if not want or not has_table(conn):
        return 0
    n = 0
    for i in want:
        n += conn.execute(f"UPDATE {TABLE} SET incident_id = ?, processed_at = ? "
                          "WHERE id = ? AND processed_at IS NULL",
                          (incident_id, at_s, i)).rowcount
    return n


def mark_processed(slug: str, ids: Iterable[int], *, at_s: Optional[str] = None) -> int:
    """Rows a verdict kept from any incident: processed, still kept."""
    with _write(slug) as conn:
        return link(conn, ids, None, at_s or utcnow_iso())


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def pending(slug: str, limit: int = PENDING_BATCH) -> list[dict[str, Any]]:
    """Rows the engine has not processed yet, oldest first (no domain in
    what it returns — the engine never needs one)."""
    with _read(slug) as conn:
        if conn is None:
            return []
        return [dict(r) for r in conn.execute(
            f"SELECT id, category, source, observed_at, received_at, profile_id, device_key, "
            f"device_name, client_ip FROM {TABLE} WHERE processed_at IS NULL "
            "ORDER BY id LIMIT ?", (int(limit),)).fetchall()]


def first_seen(conn: sqlite3.Connection, incident_id: int) -> list[str]:
    """The observation and arrival times of the rows linked to an incident
    (`windows.first_detection`)."""
    if not has_table(conn):
        return []
    out: list[str] = []
    for a, b in conn.execute(f"SELECT observed_at, received_at FROM {TABLE} "
                             "WHERE incident_id = ?", (incident_id,)).fetchall():
        out.extend(v for v in (a, b) if v)
    return out


def defang(value: Optional[str]) -> str:
    """"example[.]test" — shown so nothing can open, resolve or link it by
    accident (the console never renders it as a link)."""
    return (value or "").replace(".", "[.]").replace("://", "[://]")


def for_incident(slug: str, incident_id: int) -> list[dict[str, Any]]:
    """The incident's restricted evidence as the ADMIN detail shows it:
    defanged domains, the device, the times, the record's sha256 — never a
    link. The API audits the read."""
    with _read(slug) as conn:
        if conn is None:
            return []
        rows = conn.execute(
            f"SELECT id, category, source, observed_at, received_at, profile_id, device_key, "
            f"device_name, client_ip, domain, root, reasons, record_sha256 FROM {TABLE} "
            "WHERE incident_id = ? ORDER BY observed_at, id", (incident_id,)).fetchall()
    out = []
    for r in rows:
        try:
            reasons = json.loads(r["reasons"] or "[]")
        except ValueError:
            reasons = []
        out.append({
            "id": int(r["id"]), "category": r["category"], "source": r["source"],
            "observed_at": r["observed_at"], "received_at": r["received_at"],
            "profile_id": r["profile_id"], "device_key": r["device_key"] or None,
            "device_name": r["device_name"], "client_ip": r["client_ip"],
            "domain_defanged": defang(r["domain"]), "root_defanged": defang(r["root"]),
            "reasons": [x for x in reasons if isinstance(x, str)][:32],
            "record_sha256": r["record_sha256"],
        })
    return out


def restricted_values(slug: str) -> set[str]:
    """Every domain AND its registrable root the tenant holds as restricted
    evidence ({} when there is none) — the ENRICHMENT gate's list (an RDAP or
    domain-age lookup is about the root). Raises sqlite3.Error when the store
    cannot be read (the gate then refuses — fail closed)."""
    with _read(slug) as conn:
        if conn is None:
            return set()
        out: set[str] = set()
        for d, r in conn.execute(f"SELECT DISTINCT domain, root FROM {TABLE}").fetchall():
            out.update(v.lower().rstrip(".") for v in (d, r) if v)
        return out


def restricted_domains(slug: str) -> set[str]:
    """The exact domains the tenant holds as restricted evidence (NOT their
    roots: a root can be a whole hosting provider) — the list every READ
    surface, the triage worker and the model calls hide (`Gate`). Raises
    sqlite3.Error / OSError when the store cannot be read."""
    with _read(slug) as conn:
        if conn is None:
            return set()
        return {str(d).lower().rstrip(".") for (d,) in
                conn.execute(f"SELECT DISTINCT domain FROM {TABLE}").fetchall() if d}


def _norm(value: Any) -> str:
    text = value.strip().lower().rstrip(".") if isinstance(value, str) else ""
    for scheme in ("https://", "http://", "hxxps://", "hxxp://"):
        if text.startswith(scheme):
            text = text[len(scheme):]
    text = text.replace("[.]", ".").split("/", 1)[0].split(":", 1)[0]
    return text


def matches(value: Any, values: set[str]) -> bool:
    """`value` (a domain, host or URL) IS one of `values` or a name under
    one of them."""
    v = _norm(value)
    if not v or not values:
        return False
    return any(v == d or v.endswith("." + d) for d in values)


def refuse_enrichment(slug: str, value: Any, *, values: Optional[set[str]] = None) -> None:
    """THE gate every resolve / fetch / enrich / preview path asks first
    (PTR, RDAP, threat intelligence, domain age, a model prompt, a preview).
    Raises RestrictedContent when `value` is — or is under — a domain the
    tenant holds as restricted evidence, and when that list cannot be read
    (fail closed). `values`: the tenant's list, read once by a batch."""
    try:
        known = values if values is not None else restricted_values(slug)
    except (sqlite3.Error, OSError):
        raise RestrictedContent("the restricted-evidence list could not be read — nothing "
                                "is looked up") from None
    if matches(value, known):
        raise RestrictedContent("a domain from a restricted incident is never resolved, "
                                "fetched, enriched or previewed")


# A DNS name inside free text: the value itself, or a name under it — at a
# label boundary on both sides ("img.bad.test" and "bad.test." name it;
# "notbad.test" and "bad.testing" do not).
_LABEL = "a-z0-9-"


def _pattern(values: Iterable[str]) -> Optional[re.Pattern[str]]:
    vals = sorted({_norm(v) for v in values if isinstance(v, str)} - {""}, key=len,
                  reverse=True)
    if not vals:
        return None
    alt = "|".join(re.escape(v) for v in vals)
    return re.compile(rf"(?<![{_LABEL}])(?:{alt})(?![{_LABEL}])", re.IGNORECASE)


def text_mentions(text: Any, values: set[str]) -> bool:
    """Does a stored record's text (an event payload, a summary) name one of
    `values` — the domain itself or a name under it, at DNS-label boundaries
    (never a longer name that merely contains it)? The triage worker's and
    the model calls' check."""
    if not values or not isinstance(text, str) or not text:
        return False
    rx = _pattern(values)
    return rx is not None and rx.search(text) is not None


SQL_FN = "athena_restricted"


class Gate:
    """One tenant's restricted DOMAINS for one read: `hits(*texts)` says
    whether a row names one; `where(conn, *columns)` installs the same test
    as a SQL function and returns the predicate that keeps a row OUT (None
    when there is nothing to hide — the query is unchanged). A list that
    could not be read (`failed`) hides every row (fail closed)."""

    __slots__ = ("values", "failed", "_rx")

    def __init__(self, values: Optional[Iterable[str]]):
        self.failed = values is None
        self.values = frozenset(v for v in (_norm(x) for x in (values or ())) if v)
        self._rx = _pattern(self.values)

    @classmethod
    def for_tenant(cls, slug: str) -> "Gate":
        try:
            return cls(restricted_domains(slug))
        except (sqlite3.Error, OSError):
            logger.warning("[restricted] %s: the restricted-evidence list could not be read "
                           "— rows are hidden this read (fail closed)", slug)
            return cls(None)

    @property
    def active(self) -> bool:
        return self.failed or self._rx is not None

    def hits(self, *texts: Any) -> bool:
        if self.failed:
            return True
        if self._rx is None:
            return False
        return any(isinstance(t, str) and t and self._rx.search(t) is not None for t in texts)

    def defang(self, text: Any) -> str:
        """`text` with every restricted name in it defanged (never a live
        form)."""
        if not isinstance(text, str):
            return ""
        if self._rx is None:
            return text
        return self._rx.sub(lambda m: defang(m.group(0)), text)

    def where(self, conn: sqlite3.Connection, *columns: str) -> Optional[str]:
        """`athena_restricted(col, …) = 0` — installed on `conn` — or None."""
        if not self.active:
            return None
        conn.create_function(SQL_FN, -1, lambda *a: 1 if self.hits(*a) else 0,
                             deterministic=True)
        return f"{SQL_FN}({', '.join(columns)}) = 0"


def gate_sql(gate: Gate, conn: sqlite3.Connection, where_sql: str, *columns: str) -> str:
    """Append the gate's predicate to a "WHERE …" fragment ("" = none)."""
    pred = gate.where(conn, *columns)
    if pred is None:
        return where_sql
    return f"{where_sql} AND {pred}" if where_sql.strip() else f"WHERE {pred}"


# A DNS sensor's block reaches Athena within seconds; the NextDNS poll that
# keeps the CSAM line as restricted evidence runs every 10 minutes (and can
# lag behind a log backlog). Until then nothing marks the sensor's row — so a
# MODEL never sees a DNS sensor's block younger than this.
SENSOR_HOLD = timedelta(minutes=30)


def dns_sensor_record(row: Any) -> bool:
    """A buoy DNS sensor's record of a lookup: a Pi-hole query (in events.db
    it is a block — answered ones are telemetry) or a Suricata record that
    carries DNS."""
    try:
        event_type = str(row["event_type"] or "")
        source = str(row["source"] or "")
        payload = row["payload"] if isinstance(row["payload"], str) else ""
    except (KeyError, IndexError, TypeError):
        return False
    if event_type == "pihole.query" or event_type.startswith("suricata.dns"):
        return True
    return source == "suricata" and '"dns"' in payload


def sensor_hold(row: Any, now: Optional[datetime] = None) -> bool:
    """True while a DNS sensor's record is too young for a model: the NextDNS
    poll may not yet have kept the line that would mark it restricted."""
    if not dns_sensor_record(row):
        return False
    try:
        at = datetime.fromisoformat(str(row["received_at"]).replace("Z", "+00:00"))
    except (KeyError, IndexError, TypeError, ValueError):
        return True                                  # unknown age: hold (fail closed)
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return (now or datetime.now(timezone.utc)) - at < SENSOR_HOLD


RELATED_LIMIT = 50
RELATED_PAYLOAD_CHARS = 600


def related_records(slug: str, incident_id: int, *, limit: int = RELATED_LIMIT
                    ) -> list[dict[str, Any]]:
    """The other sensors' records that name a domain of this incident (a
    Pi-hole upstream block, a Suricata DNS alert) — hidden from every other
    surface; the ADMIN detail lists them here, defanged, newest first."""
    with _read(slug) as conn:
        if conn is None:
            return []
        gate = Gate(str(d) for (d,) in conn.execute(
            f"SELECT DISTINCT domain FROM {TABLE} WHERE incident_id = ?",
            (incident_id,)).fetchall() if d)
        if gate._rx is None:
            return []
        pred = gate.where(conn, "summary", "payload", "source_host")
        rows = conn.execute(
            "SELECT id, received_at, source, source_host, event_type, summary, payload "
            f"FROM events WHERE source <> 'athena' AND NOT ({pred}) "
            "ORDER BY received_at DESC, id DESC LIMIT ?", (int(limit),)).fetchall()
    return [{"event_id": int(r["id"]), "received_at": r["received_at"],
             "source": r["source"], "event_type": r["event_type"],
             "source_host": gate.defang(r["source_host"]) or None,
             "summary_defanged": gate.defang(r["summary"]),
             # The sensor's own record (a Pi-hole row names the LAN client) —
             # defanged, clipped; never a link.
             # (defanged BEFORE it is clipped: a cut never leaves a live
             # partial name)
             "payload_defanged": _clip(gate.defang(r["payload"]), RELATED_PAYLOAD_CHARS)}
            for r in rows]


def now_s() -> str:
    from datetime import datetime, timezone

    return format_utc_ms(datetime.now(timezone.utc))
