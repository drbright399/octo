"""Client provisioning — create a new MSP client + its per-client data DBs.

The production "add client" lifecycle: the runtime counterpart to dev_seed's
tenant seeding. Inserts the row into registry.db's `clients` table and
provisions the per-client `events.db` + `indicators.db` (+ `telemetry.db`,
migration 036) by applying every migration's `@target:events` /
`@target:indicators` / `@target:telemetry` sections through the
migration runner — so a freshly-created client's schema is always current, with
no hand-maintained migration list. Ingest (`SqliteIngestSink`) requires these
DBs to exist, so this is the gate to a source's telemetry actually landing for a
client (file-level, per-DB tenant isolation — see docs/architecture.md).

Two layers, so the ingest-path auto-creator (`instances.tenant_autocreate`)
can register a client AND its tenant mapping in ONE registry transaction:
  * `register_client(conn, …)` — the INSERT, on the caller's connection, no
    commit;
  * `provision_client_dbs(slug)` / `unregister_client(slug)` — the file side
    and its undo.
`create_client()` composes them for the plain admin case.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Optional

from apps.octo import migration, paths
from apps.octo.db import connect, transaction

# Mirrors the `clients.slug` CHECK in migration 001: lowercase alphanumeric
# words joined by single hyphens (no leading/trailing/double hyphens). `\Z`,
# not `$` (which also matches before a trailing newline) — the same pattern
# as `paths.SLUG_RE`.
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*\Z")

# Lifecycle columns added by migration 033. The vocabularies are the CHECK
# lists there; `instances.tenant_lifecycle` is the operator-facing home of
# the same enums (kept in sync by a test).
ORIGINS = ("manual", "auto", "bootstrap")
KINDS = ("unclassified", "client", "internal", "dev", "vendor", "other")
REVIEW_STATES = ("confirmed", "pending")
AI_POLICIES = ("none", "local", "cloud")

MAX_DISPLAY_NAME = 200


class ClientExistsError(Exception):
    """A client with this slug already exists."""


class InvalidClientError(Exception):
    """The slug or display name failed validation."""


def _target_section(sql: str, target: str) -> str:
    """Extract the `-- @target: <target>` block from a migration file. Same
    parser the runner uses; kept local so we apply ONLY the per-client sections
    (NOT the no-target prelude, which carries registry-DB DDL that must never
    leak into a client's events.db / indicators.db)."""
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in sql.splitlines():
        if line.startswith("-- @target:"):
            current = line.split(":", 1)[1].strip()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return "\n".join(sections.get(target, []))


def _provision_db(db_path, target: str) -> None:
    """Build a per-client DB by applying every migration's @target:<target>
    section in order — current schema, no hand-maintained list, no leak.

    A NEW file is born with auto_vacuum = INCREMENTAL (it can only be set
    before the first table exists), so the retention job can return pruned
    pages to the filesystem in short steps instead of a full VACUUM."""
    conn = sqlite3.connect(db_path)
    try:
        if not conn.execute(
            "SELECT 1 FROM sqlite_master LIMIT 1"
        ).fetchone():
            conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
        for m in migration.list_migrations(kind="forward"):
            body = _target_section(m.sql, target)
            if body.strip():
                conn.executescript(body)
        conn.commit()
    finally:
        conn.close()


def validate_new_client(slug: str, display_name: str) -> tuple[str, str]:
    """Normalise + validate the two required fields; raises InvalidClientError."""
    slug = (slug or "").strip()
    display_name = " ".join((display_name or "").split())
    if not _SLUG_RE.match(slug):
        raise InvalidClientError(
            "slug must be lowercase alphanumeric words joined by single hyphens "
            "(e.g. 'acme-corp')"
        )
    if not display_name:
        raise InvalidClientError("display_name is required")
    if len(display_name) > MAX_DISPLAY_NAME or not display_name.isprintable():
        raise InvalidClientError(
            f"display_name must be at most {MAX_DISPLAY_NAME} printable characters"
        )
    return slug, display_name


def default_review_state(kind: str) -> str:
    """'confirmed' only when the tenant says what it is. "Reviewed" means "a
    human said what it is", so an 'unclassified' tenant is born 'pending' —
    the same rule the admin API applies (`create_manual_tenant`)."""
    return "pending" if kind == "unclassified" else "confirmed"


def register_client(
    conn: sqlite3.Connection,
    slug: str,
    display_name: str,
    *,
    origin: str = "manual",
    kind: str = "unclassified",
    review_state: Optional[str] = None,
    created_by_instance_id: Optional[int] = None,
    ai_policy: str = "none",
    compliance_flags_json: str = "[]",
) -> None:
    """INSERT the registry row on the caller's connection (inside whatever
    transaction the caller holds — nothing is committed here). Raises
    ClientExistsError / InvalidClientError; the lifecycle enums are checked
    here so a bad value is an exception, not a CHECK failure mid-transaction.
    `review_state` defaults from `kind` (`default_review_state`), and a
    confirmed-but-unclassified tenant is refused outright. (The registry
    refuses it too, since migration 034: a bare-SQL INSERT that takes the
    column defaults — confirmed + unclassified — fails its trigger, so a
    seed or fixture must say `kind` or `review_state = 'pending'`.)

    The lifecycle columns exist from migration 033 on; a registry that has not
    been migrated yet (older tests build a bare `clients` table) gets the
    001-shaped INSERT so plain creation keeps working there."""
    slug, display_name = validate_new_client(slug, display_name)
    if review_state is None:
        review_state = default_review_state(kind)
    if origin not in ORIGINS:
        raise InvalidClientError(f"origin must be one of {', '.join(ORIGINS)}")
    if kind not in KINDS:
        raise InvalidClientError(f"kind must be one of {', '.join(KINDS)}")
    if review_state not in REVIEW_STATES:
        raise InvalidClientError(
            f"review_state must be one of {', '.join(REVIEW_STATES)}"
        )
    if review_state == "confirmed" and kind == "unclassified":
        raise InvalidClientError("an 'unclassified' client cannot be born 'confirmed'")
    if ai_policy not in AI_POLICIES:
        raise InvalidClientError(f"ai_policy must be one of {', '.join(AI_POLICIES)}")
    if conn.execute("SELECT 1 FROM clients WHERE slug = ?", (slug,)).fetchone():
        raise ClientExistsError(f"client {slug!r} already exists")
    columns = {r[1] for r in conn.execute("PRAGMA table_info(clients)")}
    if "origin" in columns:
        conn.execute(
            "INSERT INTO clients (slug, display_name, origin, kind, review_state, "
            " created_by_instance_id, ai_policy, compliance_flags) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                slug, display_name, origin, kind, review_state,
                created_by_instance_id, ai_policy, compliance_flags_json,
            ),
        )
    else:
        conn.execute(
            "INSERT INTO clients (slug, display_name) VALUES (?, ?)",
            (slug, display_name),
        )


def provision_client_dbs(slug: str) -> None:
    """Create the client dir + events.db / indicators.db / telemetry.db /
    entities.db at current schema. (telemetry.db — migration 036 — and
    entities.db — 040 — are also created lazily on first write, which is how
    tenants provisioned before them get one.)"""
    from apps.octo.entity import db as entity_db
    from apps.octo.ingest import telemetry

    # `paths.client_dir` validates the slug and proves the directory is
    # inside the data root (no symlink, no escape) BEFORE it is created.
    client_dir = paths.client_dir(slug)
    client_dir.mkdir(parents=True, exist_ok=True)
    _provision_db(client_dir / "events.db", "events")
    _provision_db(client_dir / "indicators.db", "indicators")
    telemetry.ensure_db(client_dir / telemetry.DB_NAME)
    entity_db.ensure_db(client_dir / entity_db.DB_NAME)


def unregister_client(slug: str) -> None:
    """Undo a registration whose DB provisioning failed (never for a client
    that has data — offboard/archive is the lifecycle for those)."""
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute("DELETE FROM adapter_tenant_map WHERE octo_client_slug = ?", (slug,))
            reg.execute("DELETE FROM clients WHERE slug = ?", (slug,))
    except sqlite3.OperationalError:
        # Pre-030 registry (no tenant map): the row alone.
        reg.execute("DELETE FROM clients WHERE slug = ?", (slug,))
        reg.commit()
    finally:
        reg.close()


def create_client(
    slug: str,
    display_name: str,
    *,
    origin: str = "manual",
    kind: str = "unclassified",
    review_state: Optional[str] = None,
    created_by_instance_id: Optional[int] = None,
    ai_policy: str = "none",
    compliance_flags_json: str = "[]",
) -> None:
    """Register a client and provision its per-client data DBs. Idempotency is
    NOT assumed — raises ClientExistsError if the slug is taken. Without an
    explicit `review_state` an 'unclassified' client is born 'pending'
    (`default_review_state`)."""
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            register_client(
                reg, slug, display_name,
                origin=origin, kind=kind, review_state=review_state,
                created_by_instance_id=created_by_instance_id,
                ai_policy=ai_policy, compliance_flags_json=compliance_flags_json,
            )
    finally:
        reg.close()
    slug = slug.strip()

    try:
        provision_client_dbs(slug)
    except Exception:
        # Roll the registry row back so a failed provision doesn't orphan it.
        unregister_client(slug)
        raise
