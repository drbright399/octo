"""Migration 046 (v0.17.2 — alert verdicts, expected conditions, the
enrichment cache, the IPS buckets' remotes, the Datto devices' external IP)
— forward, rollback, forward again — and scripts/rollback_v0172.py.

Pins:
  - registry: alert_verdict append-only (no update, no delete), "repeats"
    ≤ 24 h and only on an ack; expected_condition revoked / reviewed but
    never deleted, review ≤ 90 days, a reason ≥ 10 characters, frozen
    except the reminder stamp and ONE revoke, never a NextDNS 'csam'
    signature; enrichment_cache; user_version 46;
  - telemetry: unifi_signal_buckets.remotes; entities: inv_device.ext_ip;
  - the rollback LEAVES the registry tables (version → the newest registry
    migration before 046), keeps the two columns' values aside and drops
    them (telemetry → 39, entities → 40); a re-upgrade puts them back and
    spends what was kept;
  - rollback_v0172: dry run by default, the tenant files then the registry,
    a newer root (v0.17.5's 48, v0.17.3's 47) refused until rollback_v0175
    and rollback_v0173 ran, nothing to do after it ran; rollback_v017
    refuses a 46 root until this ran.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sqlite3
from pathlib import Path

import pytest

from apps.octo.auth import bootstrap
from apps.octo.client_provisioning import create_client
from apps.octo.db import connect
from apps.octo.entity import db as entity_db
from apps.octo.ingest import telemetry
from apps.octo.migration import list_migrations

SCRIPTS = Path(__file__).resolve().parents[4] / "scripts"
TABLES = {"alert_verdict", "expected_condition", "enrichment_cache"}
NOW, LATER = "2026-10-06T12:00:00.000Z", "2026-11-01T12:00:00.000Z"


def _migration(number: int, kind: str = "forward"):
    return next(m for m in list_migrations(kind=kind) if m.number == number)


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _cols(conn, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def _script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path / "root"))
    bootstrap.init_data_root()
    create_client("acme-corp", "Acme Corp", kind="client")
    telemetry.reset_schema_cache()
    entity_db.reset_schema_cache()
    yield tmp_path / "root"
    telemetry.reset_schema_cache()
    entity_db.reset_schema_cache()


def test_046_targets_the_registry_telemetry_and_entities():
    for kind in ("forward", "rollback"):
        sql = _migration(46, kind).sql
        for target in ("registry", "telemetry", "entities"):
            assert f"-- @target: {target}" in sql
        assert "-- @target: events" not in sql


def test_the_rollback_returns_each_file_to_the_newest_migration_before_046():
    """When the parallel v0.17.1 branch (045) is merged, this fails until the
    rollback's versions name 45 wherever 045 has a section."""
    back = _migration(46, "rollback").sql
    chunks = re.split(r"^-- @target: (\w+)\s*$", back, flags=re.MULTILINE)
    sections = dict(zip(chunks[1::2], chunks[2::2]))
    for target, versions in sections.items():
        before = max(m.number for m in list_migrations() if m.number < 46 and (
            f"-- @target: {target}" in m.sql or (target == "registry" and m.number == 1)))
        assert re.findall(r"PRAGMA user_version = (\d+)", versions) == [str(before)], target


def test_registry_constraints(root):
    reg = connect(root / "registry.db")
    try:
        assert reg.execute("PRAGMA user_version").fetchone()[0] == 48   # v0.17.5 on top
        assert TABLES <= _tables(reg)
        ins = ("INSERT INTO alert_verdict (tenant_slug, event_id, source, device_key, "
               "signature_key, verdict, actor, at, repeat_until) VALUES "
               "('acme-corp', 7, 'unifi', 'd', 's', ?, 1, ?, ?)")
        vid = reg.execute(ins, ("ack", NOW, "2026-10-07T12:00:00.000Z")).lastrowid
        for bad in (("ack", NOW, "2026-10-07T13:00:00.000Z"),        # > 24 h
                    ("confirmed", NOW, "2026-10-06T13:00:00.000Z"),  # only on an ack
                    ("dismissed", NOW, None)):
            with pytest.raises(sqlite3.IntegrityError):
                reg.execute(ins, bad)
        with pytest.raises(sqlite3.IntegrityError, match="never changed"):
            reg.execute("UPDATE alert_verdict SET note = 'x' WHERE id = ?", (vid,))
        with pytest.raises(sqlite3.IntegrityError, match="never deleted"):
            reg.execute("DELETE FROM alert_verdict")

        ins = ("INSERT INTO expected_condition (tenant_slug, source, device_key, signature_key, "
               "label, reason, origin_event_id, created_by, created_at, review_at) VALUES "
               "('acme-corp', 'unifi', 'd', ?, 'label', ?, 7, 1, ?, ?)")
        rid = reg.execute(ins, ("unifi.ips_threat:sig", "Siris backup to the cloud", NOW,
                                LATER)).lastrowid
        for bad in (("unifi.ips_threat:sig", "too short", NOW, LATER),
                    ("unifi.ips_threat:sig", "Siris backup to the cloud", NOW,
                     "2027-01-05T12:00:01.000Z"),                     # > 90 days
                    ("nextdns:csam|x.example.test", "never acceptable here", NOW, LATER)):
            with pytest.raises(sqlite3.IntegrityError):
                reg.execute(ins, bad)
        with pytest.raises(sqlite3.IntegrityError, match="frozen"):
            reg.execute("UPDATE expected_condition SET review_at = ? WHERE id = ?",
                        ("2026-12-01T00:00:00.000Z", rid))
        reg.execute("UPDATE expected_condition SET reminded_at = ? WHERE id = ?", (NOW, rid))
        reg.execute("UPDATE expected_condition SET revoked_at = ?, revoked_by = 1, "
                    "revoke_reason = 'moved' WHERE id = ?", (NOW, rid))
        with pytest.raises(sqlite3.IntegrityError, match="frozen"):
            reg.execute("UPDATE expected_condition SET revoke_reason = 'other' WHERE id = ?",
                        (rid,))
        with pytest.raises(sqlite3.IntegrityError, match="never deleted"):
            reg.execute("DELETE FROM expected_condition")
        # Never client-wide: an expected condition, and a "repeats for 24 h",
        # always name ONE device (a RocketCyber incident names none).
        with pytest.raises(sqlite3.IntegrityError):
            reg.execute("INSERT INTO expected_condition (tenant_slug, source, device_key, "
                        "signature_key, label, reason, origin_event_id, created_by, created_at, "
                        "review_at) VALUES ('acme-corp', 'rocketcyber', '', 'rocketcyber:x', "
                        "'label', 'a client-wide rule', 7, 1, ?, ?)", (NOW, LATER))
        with pytest.raises(sqlite3.IntegrityError):
            reg.execute("INSERT INTO alert_verdict (tenant_slug, event_id, source, device_key, "
                        "signature_key, verdict, actor, at, repeat_until) VALUES "
                        "('acme-corp', 8, 'rocketcyber', '', 's', 'ack', 1, ?, ?)",
                        (NOW, "2026-10-07T12:00:00.000Z"))
        # The vendor's alert identity rides on a verdict (an ack covers the
        # other rows of the same alert).
        reg.execute("INSERT INTO alert_verdict (tenant_slug, event_id, source, device_key, "
                    "signature_key, verdict, actor, at, alert_ref) VALUES "
                    "('acme-corp', 9, 'rocketcyber', '', 's', 'ack', 1, ?, 'rocketcyber:101')",
                    (NOW,))
        assert "alert_ref" in _cols(reg, "alert_verdict")
        reg.execute("INSERT INTO enrichment_cache (kind, key, value_json, ok, fetched_at, "
                    "expires_at) VALUES ('ip', '203.0.113.9', '{}', 1, ?, ?)", (NOW, LATER))
        reg.execute("DELETE FROM enrichment_cache")                   # a cache: prunable
    finally:
        reg.close()


def _tenant_files(root: Path) -> tuple[Path, Path]:
    tel = root / "clients" / "acme-corp" / "telemetry.db"
    ent = root / "clients" / "acme-corp" / "entities.db"
    telemetry.ensure_db(tel)
    entity_db.ensure_db(ent)
    conn = sqlite3.connect(tel)
    conn.execute("INSERT INTO unifi_signal_buckets (bucket_key, hour, scope, kind, subject, "
                 "first_seen, last_seen, remotes) VALUES ('b1', 'h', 's', 'ips_threat', "
                 "'c|sig|blocked', 'a', 'b', '{\"203.0.113.9\":2}')")
    conn.commit()
    conn.close()
    conn = sqlite3.connect(ent)
    conn.execute("INSERT INTO inv_device (adapter_instance_id, device_uid, site_uid, hostname, "
                 "first_seen_at, updated_at, ext_ip) VALUES (1, 'dev-1', 'site-a', 'WS-1', "
                 "'a', 'b', '203.0.113.129')")
    conn.commit()
    conn.close()
    return tel, ent


def _v(path: Path) -> int:
    conn = sqlite3.connect(path)
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()


def test_rollback_v0172_script_keeps_everything_and_a_reupgrade_takes_it_back(root, capsys):
    tel, ent = _tenant_files(root)
    reg = connect(root / "registry.db")
    reg.execute("INSERT INTO alert_verdict (tenant_slug, event_id, source, signature_key, "
                "verdict, actor, at) VALUES ('acme-corp', 7, 'unifi', 's', 'ack', 1, ?)", (NOW,))
    reg.close()
    mod = _script("rollback_v0172")
    assert _script("rollback_v017").main(["--data-root", str(root)]) == 1  # 48: not its own
    assert "48" in json.loads(capsys.readouterr().out)["error"]
    # v0.17.5 (048) and v0.17.3 (047) sit on top: refused until
    # rollback_v0175 and rollback_v0173 ran (an entities.db at 47 rolled back
    # by 046 alone would keep 047's columns).
    assert mod.main(["--data-root", str(root)]) == 1
    assert "48" in json.loads(capsys.readouterr().out)["error"]
    assert (_v(ent), _v(root / "registry.db")) == (47, 48)               # nothing written
    assert _script("rollback_v0175").main(["--data-root", str(root), "--apply"]) == 0
    capsys.readouterr()
    assert mod.main(["--data-root", str(root)]) == 1                      # 47: still refused
    assert "47" in json.loads(capsys.readouterr().out)["error"]
    assert _script("rollback_v0173").main(["--data-root", str(root), "--apply"]) == 0
    capsys.readouterr()

    assert mod.main(["--data-root", str(root)]) == 0                      # dry run
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] is False
    assert [(Path(s["file"]).name, s["target"]) for s in out["steps"]] == [
        ("telemetry.db", "telemetry"), ("entities.db", "entities"), ("registry.db", "registry")]
    assert (_v(tel), _v(ent), _v(root / "registry.db")) == (46, 46, 46)  # nothing written

    assert mod.main(["--data-root", str(root), "--apply"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["failed"] == [] and all(d["integrity"] == "ok" for d in out["done"])
    assert (_v(tel), _v(ent), _v(root / "registry.db")) == (39, 40, 44)
    conn = sqlite3.connect(tel)
    try:
        assert "remotes" not in _cols(conn, "unifi_signal_buckets")
        assert conn.execute("SELECT bucket_key, remotes FROM "
                            "unifi_bucket_remotes_rolled_back_046").fetchall() == \
            [("b1", '{"203.0.113.9":2}')]
    finally:
        conn.close()
    conn = sqlite3.connect(ent)
    try:
        assert "ext_ip" not in _cols(conn, "inv_device")
        assert conn.execute("SELECT device_uid, ext_ip FROM inv_device_ext_ip_rolled_back_046"
                            ).fetchall() == [("dev-1", "203.0.113.129")]
    finally:
        conn.close()
    conn = sqlite3.connect(root / "registry.db")
    try:                                                    # the registry tables are left
        assert TABLES <= _tables(conn)
        assert conn.execute("SELECT COUNT(*) FROM alert_verdict").fetchone()[0] == 1
    finally:
        conn.close()
    assert mod.main(["--data-root", str(root), "--apply"]) == 0           # nothing left
    assert json.loads(capsys.readouterr().out)["steps"] == []

    # Re-upgrade: the registry on start, the tenant files lazily.
    bootstrap.init_data_root()
    telemetry.reset_schema_cache()
    entity_db.reset_schema_cache()
    assert telemetry.ensure_db(tel) == [46] and entity_db.ensure_db(ent) == [46, 47]
    conn = sqlite3.connect(tel)
    try:
        assert conn.execute("SELECT remotes FROM unifi_signal_buckets").fetchone()[0] == \
            '{"203.0.113.9":2}'
        assert conn.execute("SELECT COUNT(*) FROM unifi_bucket_remotes_rolled_back_046"
                            ).fetchone()[0] == 0                          # spent
    finally:
        conn.close()
    conn = sqlite3.connect(ent)
    try:
        assert conn.execute("SELECT ext_ip FROM inv_device").fetchone()[0] == "203.0.113.129"
    finally:
        conn.close()
    assert _v(root / "registry.db") == 48                                 # 046 … 048 again
    assert mod.main(["--data-root", str(root)]) == 1                      # newer: refused
    assert "48" in json.loads(capsys.readouterr().out)["error"]
    assert mod.main(["--data-root", str(root.parent / "missing")]) == 2
