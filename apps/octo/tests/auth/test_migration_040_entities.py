"""Migration 040 (entity resolution, slice 1): its own per-tenant DB
(`@target: entities`), the registry switch, the known-benign registry, the
entity retention classes and the `entity_review` notice kind — forward,
rollback, forward again; nothing destroyed."""
from __future__ import annotations

import sqlite3

import pytest

from apps.octo.auth import bootstrap
from apps.octo.db import connect
from apps.octo.entity import db as entity_db
from apps.octo.migration import apply_migration, list_migrations


def _migration(number: int, kind: str = "forward"):
    return next(m for m in list_migrations(kind=kind) if m.number == number)


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def test_040_has_entities_and_registry_sections():
    for kind in ("forward", "rollback"):
        sql = _migration(40, kind).sql
        assert "-- @target: entities" in sql and "-- @target: registry" in sql
    # 046: inv_device.ext_ip; 047: the device's serial / manufacturer / model.
    assert entity_db.migration_numbers() == [40, 46, 47]


def test_entities_db_is_created_current_with_incremental_vacuum(tmp_path):
    entity_db.reset_schema_cache()
    tenant = tmp_path / "clients" / "acme-corp"
    tenant.mkdir(parents=True)
    path = tenant / "entities.db"
    assert entity_db.ensure_db(path) == [40, 46, 47]
    assert entity_db.ensure_db(path) == []
    conn = sqlite3.connect(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 47
        assert conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2          # incremental
        assert {"site", "site_vendor_ref", "lk_site_egress", "lk_ip_lease", "lk_site_subnet",
                "lk_watermark", "lk_join", "lk_mac_anomaly", "resolution", "resolution_dep",
                "link_suppression", "link_conflict", "resolver_cursor", "resolution_run",
                "inv_device", "ndns_device", "ndns_device_hour", "ndns_presence_hour",
                "ndns_ip_day", "device_link", "device_watch", "maint"} <= _tables(conn)
        # No table holds a tenant slug (isolation is the file).
        for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            assert not {"slug", "client_slug", "tenant", "tenant_slug"} & cols, table
        # A name only ever suggests, capped at 45.
        conn.execute("INSERT INTO site (site_id, label, anchor, created_at, created_by, "
                     "updated_at) VALUES ('st_1', 'Site', 'unifi', 'x', 'x', 'x')")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO site_vendor_ref (site_id, vendor, vendor_scope_id, state, "
                         "score, rule_id, rule_version, inputs_sha256, valid_from, decided_by, "
                         "decided_at, created_at) VALUES ('st_1', 'nextdns', 'p', 'auto', 90, "
                         "'N-SITE', 1, 'h', 'x', 'rule:N-SITE@1', 'x', 'x')")
    finally:
        conn.close()


def test_registry_forward_rollback_forward(tmp_path, monkeypatch):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path / "root"))
    info = bootstrap.init_data_root()
    reg_path = tmp_path / "root" / "registry.db"
    assert info
    conn = connect(reg_path)
    try:
        # v0.17.5 (048), v0.17.3 (047), v0.17.2 (046), v0.17 (044), v0.16
        # (043), v0.15 (042) and v0.14 (041), independent of 040, sit on top:
        # roll them back first, newest first, the way rollback_v0175 →
        # rollback_v0173 → rollback_v0172 → rollback_v017 → rollback_v016 →
        # rollback_v015 → rollback_v014 → rollback_v013 run.
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 48
        apply_migration(conn, _migration(48, "rollback"), target="registry")
        apply_migration(conn, _migration(47, "rollback"), target="registry")
        apply_migration(conn, _migration(46, "rollback"), target="registry")
        apply_migration(conn, _migration(44, "rollback"), target="registry")
        apply_migration(conn, _migration(43, "rollback"), target="registry")
        apply_migration(conn, _migration(42, "rollback"), target="registry")
        apply_migration(conn, _migration(41, "rollback"), target="registry")
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 40
        conn.execute("INSERT INTO clients (slug, display_name, kind) VALUES ('acme-corp', "
                     "'Acme Corp', 'client')")
        assert conn.execute("SELECT entity_resolution FROM clients").fetchone()[0] == "off"
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE clients SET entity_resolution = 'maybe'")
        conn.execute("UPDATE clients SET entity_resolution = 'shadow'")
        (seed,) = conn.execute("SELECT * FROM known_benign_rules").fetchall()
        assert (seed["match_kind"], seed["pattern"], seed["level"]) == \
            ("regex", r"www\.go{3,}gle\.com", "low")
        classes = {r[0] for r in conn.execute("SELECT data_class FROM bundle_config_retention")}
        assert {"entity_lookup_lease", "entity_lookup_egress", "entity_resolution",
                "entity_links", "entity_inventory"} <= classes
        conn.execute("UPDATE known_benign_rules SET enabled = 0")
        apply_migration(conn, _migration(40, "rollback"), target="registry")
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 38
        cols = {r[1] for r in conn.execute("PRAGMA table_info(clients)")}
        assert "entity_resolution" not in cols
        assert "known_benign_rules" not in _tables(conn)
        assert not {r[0] for r in conn.execute("SELECT data_class FROM bundle_config_retention")
                    if r[0].startswith("entity_")}
        apply_migration(conn, _migration(40), target="registry")
        assert conn.execute("SELECT entity_resolution FROM clients").fetchone()[0] == "shadow"
        rows = conn.execute("SELECT enabled FROM known_benign_rules").fetchall()
        assert [r[0] for r in rows] == [0]                     # the kept rule, not a new seed
    finally:
        conn.close()


def test_a_second_rollback_keeps_the_state_of_then_not_older_rows(tmp_path, monkeypatch):
    """forward → rollback → forward → (the operator changes things) →
    rollback → forward: what comes back is the state at the SECOND rollback.
    A switch turned OFF in between stays off; a rule edited in between keeps
    its edit; the kept tables are spent by each re-upgrade."""
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path / "root"))
    bootstrap.init_data_root()
    conn = connect(tmp_path / "root" / "registry.db")
    try:
        apply_migration(conn, _migration(41, "rollback"), target="registry")   # v0.14 first
        conn.execute("INSERT INTO clients (slug, display_name, kind) VALUES ('acme-corp', "
                     "'Acme Corp', 'client')")
        conn.execute("UPDATE clients SET entity_resolution = 'on'")
        fwd, back = _migration(40), _migration(40, "rollback")
        apply_migration(conn, back, target="registry")
        apply_migration(conn, fwd, target="registry")
        assert conn.execute("SELECT entity_resolution FROM clients").fetchone()[0] == "on"
        assert conn.execute("SELECT COUNT(*) FROM clients_entity_resolution_rolled_back_040"
                            ).fetchone()[0] == 0                    # spent
        assert conn.execute("SELECT COUNT(*) FROM known_benign_rules_rolled_back_040"
                            ).fetchone()[0] == 0
        # The operator turns the client OFF and edits the seed rule.
        conn.execute("UPDATE clients SET entity_resolution = 'off'")
        conn.execute("UPDATE known_benign_rules SET label = 'Samsung probe (edited)'")
        apply_migration(conn, back, target="registry")
        apply_migration(conn, fwd, target="registry")
        assert conn.execute("SELECT entity_resolution FROM clients").fetchone()[0] == "off"
        assert [r[0] for r in conn.execute("SELECT label FROM known_benign_rules")] == \
            ["Samsung probe (edited)"]
    finally:
        conn.close()
