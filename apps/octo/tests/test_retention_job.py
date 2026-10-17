"""The retention job (`apps.octo.retention.job`) on real tenants and files.

Clock: an injected `now` (2026-09-29 12:00 UTC); rows are written with
received_at / created_at / last_seen relative to it. Nothing sleeps.

Pins:
  * per class: events, agent_notes, indicators (auto / promoted),
    telemetry_raw (whole UTC days), telemetry_rollup, first_seen_domains —
    expired rows go, the rest stay; secure_notepad has no store; the audit
    chain is never touched;
  * effective retention: legal-baseline floor; a tenant's retention_days only
    lengthens 'events'; the report says which rule won;
  * ONE audit row per tenant per run (actor retention-job, system), written
    before the deletes, its planned counts = what was deleted; chain valid;
  * dry run: the same counts, and not one byte written anywhere;
  * archive: written before the prune, verbatim rows, checksum + manifest;
    disabled → pruned and SAID; unusable root or a failed day → those rows
    kept (blocked); restore round-trip;
  * space: an incremental DB gives pages back; a pre-036 events.db is
    reported, and convert_to_incremental() makes the next prune reclaim;
  * the run lock (overlap → skipped); an audit failure stops the run before
    any delete; the nightly sweep moves fallback rows.
(Evidence windows — Tier Black, 044 — through this job:
`test_retention_evidence_windows.py`.)
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import sqlite3
from datetime import timedelta

import pytest

from apps.octo.retention import job as job_module
from apps.octo.retention.archive import ColdArchive
from apps.octo.retention.job import RetentionJob, convert_to_incremental, last_run
from apps.octo.tests._tiering_fixtures import (
    NOW, ago, audit_rows, db, event_note, file_digests, insert_event, insert_events_many, iso,
    live_signal, make_root, open_ticket, pihole_payload, rows, write_telemetry,
    write_telemetry_many,
)

A, B = "acme-corp", "globex"


@pytest.fixture
def root(tmp_path, monkeypatch):
    return make_root(tmp_path, monkeypatch, tenants=(A, B))


def _job(root, **kw) -> RetentionJob:
    kw.setdefault("archive_from_env", False)
    return RetentionJob(data_root=root, now=lambda: NOW, **kw)


def _set_class_days(root, data_class: str, days: int) -> None:
    conn = sqlite3.connect(root / "registry.db")
    conn.execute("UPDATE bundle_config_retention SET retention_days = ? WHERE data_class = ?",
                 (days, data_class))
    conn.commit()
    conn.close()


def _set_tenant_days(root, slug: str, days: int) -> None:
    conn = sqlite3.connect(root / "registry.db")
    conn.execute("UPDATE clients SET retention_days = ? WHERE slug = ?", (days, slug))
    conn.commit()
    conn.close()


def _note(root, slug: str, created_at: str, *, ref_kind: str = "ticket", ref_id: int = 1) -> int:
    """An agent note (by default about a ticket — a note about an EVENT makes
    that event evidence, which the job holds)."""
    conn = sqlite3.connect(db(root, slug, "events"))
    cur = conn.execute(
        "INSERT INTO agent_notes (ref_kind, ref_id, agent_id, note_text, confidence, "
        " created_at, audit_request_id) VALUES (?, ?, 'octo', 'n', 0.5, ?, 'r')",
        (ref_kind, ref_id, created_at))
    conn.commit()
    conn.close()
    return int(cur.lastrowid)


def _indicator(root, slug: str, value: str, last_seen: str, promoted_at=None) -> int:
    conn = sqlite3.connect(db(root, slug, "indicators"))
    cur = conn.execute(
        "INSERT INTO indicators (value, type, source, severity, confidence, first_seen, "
        " last_seen, promoted_at) VALUES (?, 'ip', 'wazuh', 'high', 0.5, ?, ?, ?)",
        (value, last_seen, last_seen, promoted_at))
    conn.commit()
    conn.close()
    return int(cur.lastrowid)


def _hourly(root, slug: str, hour: str, domain: str = "old.example.test",
            arrived: str | None = None) -> None:
    """An hourly roll-up row whose latest sighting ARRIVED at `arrived`
    (default: its hour — a live feed)."""
    conn = sqlite3.connect(db(root, slug, "telemetry"))
    conn.execute(
        "INSERT INTO telemetry_hourly (hour, event_type, domain, device, count, first_seen, "
        " last_seen, last_arrival) VALUES (?, 'pihole.query', ?, '192.0.2.10', 5, ?, ?, ?)",
        (hour, domain, hour, hour, arrived or hour.replace(":00Z", ":00.000Z")))
    conn.commit()
    conn.close()


def _seed_all(root, slug: str) -> dict:
    s: dict = {}
    s["event_old"] = insert_event(root, slug, event_type="wazuh.alert", payload={"n": 1},
                                  received_at=ago(days=400), severity="high")
    s["event_new"] = insert_event(root, slug, event_type="wazuh.alert", payload={"n": 2},
                                  received_at=ago(days=100), severity="high")
    s["note_old"] = _note(root, slug, ago(days=2200))
    s["note_new"] = _note(root, slug, ago(days=30))
    s["ind_auto_old"] = _indicator(root, slug, "203.0.113.1", ago(days=100))
    s["ind_auto_new"] = _indicator(root, slug, "203.0.113.2", ago(days=10))
    s["ind_prom_old"] = _indicator(root, slug, "203.0.113.3", ago(days=2200), ago(days=2300))
    s["ind_prom_new"] = _indicator(root, slug, "203.0.113.4", ago(days=100), ago(days=2300))
    # Raw telemetry: cutoff = midnight 7 days back (2026-09-22T00:00Z).
    s["raw_old"] = [
        write_telemetry(root, slug, received_at=iso(NOW - timedelta(days=9, hours=h)),
                        domain="old.example.test", n=h)
        for h in range(3)
    ]
    s["raw_edge"] = write_telemetry(root, slug, received_at="2026-09-21T23:59:59.000Z",
                                    domain="edge.example.test", n=9)
    s["raw_kept"] = write_telemetry(root, slug, received_at="2026-09-22T00:00:00.000Z",
                                    domain="kept.example.test", n=10)
    _hourly(root, slug, "2026-03-01T10:00:00Z")          # > 180 d
    _hourly(root, slug, "2026-06-01T10:00:00Z", "mid.example.test")  # < 180 d
    conn = sqlite3.connect(db(root, slug, "telemetry"))
    conn.execute("INSERT INTO first_seen_domains VALUES ('gone.example.test', ?, 'x', "
                 "'pihole.query', ?)", (ago(days=800), ago(days=400)))
    conn.commit()
    conn.close()
    return s


def _left(root, slug, name, table, key="id") -> set:
    return {r[0] for r in rows(db(root, slug, name), f"SELECT {key} FROM {table}")}


# ---------------------------------------------------------------------------
# Per class
# ---------------------------------------------------------------------------

def test_every_class_is_enforced_and_the_audit_chain_untouched(root):
    s = _seed_all(root, A)
    audit_before = rows(root / "global" / "audit.db", "SELECT * FROM audit_log")
    report = _job(root).run(trigger="script")
    assert report.status == "ok", report.as_dict()
    t = next(t for t in report.tenants if t.slug == A)
    c = t.classes
    assert (c["events"].deleted, c["agent_notes"].deleted) == (1, 1)
    assert (c["indicators_auto"].deleted, c["indicators_promoted"].deleted) == (1, 1)
    assert c["telemetry_raw"].deleted == 4
    assert c["telemetry_rollup"].deleted == 1
    assert c["first_seen_domains"].deleted == 1
    assert c["secure_notepad"].status == "no_store"
    assert c["audit"].status == "permanent"
    assert _left(root, A, "events", "events") == {s["event_new"]}
    assert _left(root, A, "events", "agent_notes") == {s["note_new"]}
    assert _left(root, A, "indicators", "indicators") == {s["ind_auto_new"], s["ind_prom_new"]}
    assert _left(root, A, "telemetry", "telemetry_raw") == {s["raw_kept"]}
    # The roll-up keeps 180 days: only the March hour goes (the pruned raw
    # rows' hours stay counted).
    assert _left(root, A, "telemetry", "telemetry_hourly", "hour") == {
        "2026-06-01T10:00:00Z", "2026-09-20T10:00:00Z", "2026-09-20T11:00:00Z",
        "2026-09-20T12:00:00Z", "2026-09-21T23:00:00Z", "2026-09-22T00:00:00Z"}
    assert "gone.example.test" not in _left(root, A, "telemetry", "first_seen_domains", "domain")
    # The chain: every row that was there is still there, unchanged.
    audit_after = rows(root / "global" / "audit.db", "SELECT * FROM audit_log")
    assert audit_after[:len(audit_before)] == audit_before
    from apps.octo.auth import audit
    g = sqlite3.connect(root / "global" / "audit.db")
    g.row_factory = sqlite3.Row
    try:
        assert audit.verify(g)[0]
    finally:
        g.close()


def test_a_plan_row_per_tenant_with_deletions_and_one_run_row(root):
    """Audit volume (v0.11 T4): a tenant with something to delete gets its
    plan row BEFORE the deletes; a tenant with nothing gets none; the run
    gets ONE summary row after every tenant, with what actually happened."""
    _seed_all(root, A)
    live_signal(root, B)          # ingest is live (the scheduled run's clock check)
    audit_db = root / "global" / "audit.db"
    before = rows(audit_db, "SELECT COUNT(*) FROM audit_log")[0][0]
    report = _job(root).run(trigger="scheduler")
    rows_ = audit_rows(root, "retention_enforce")
    assert [r["client_slug"] for r in rows_] == [A]            # B had nothing: no row
    [r] = rows_
    assert (r["actor"], r["actor_kind"], r["target_kind"]) == ("retention-job", "system", "client")
    assert r["request_id"] == report.run_id
    after = json.loads(r["after_state"])
    t = next(t for t in report.tenants if t.slug == A)
    assert t.audit_row_id == r["id"]
    for name, cls in after["classes"].items():
        assert cls["planned"] == t.classes[name].deleted, name
    assert after["classes"]["events"]["basis"] == "bundle"
    assert after["archive"]["enabled"] is False
    assert after["trigger"] == "scheduler"
    # The run's summary row: after the plan row, the whole outcome.
    [run_row] = audit_rows(root, "retention_run")
    assert (run_row["actor"], run_row["client_slug"], run_row["target_kind"],
            run_row["target_id"], run_row["request_id"]) == (
        "retention-job", "global", "retention_run", report.run_id, report.run_id)
    assert run_row["id"] > r["id"] and report.audit_row_id == run_row["id"]
    summary = json.loads(run_row["after_state"])
    assert summary["status"] == "ok" and summary["deleted_total"] == 10
    assert summary["idle_tenants"] == [B]
    acme = summary["tenants"][A]
    assert acme["plan_audit_row_id"] == r["id"] and acme["deleted"] == 10
    assert acme["classes"]["events"] == {
        "status": "ok", "planned": 1, "deleted": 1, "held": 0, "referenced": 0, "evidence": 0,
        "error": None}
    assert "audit" not in acme["classes"]                     # nothing happened there
    # Two rows for the run, not two per tenant.
    assert rows(audit_db, "SELECT COUNT(*) FROM audit_log")[0][0] == before + 2
    # A quiet night: one row in all.
    _job(root).run(trigger="scheduler")
    assert rows(audit_db, "SELECT COUNT(*) FROM audit_log")[0][0] == before + 3
    assert len(audit_rows(root, "retention_enforce")) == 1
    # The run is on record for Settings → System.
    run = [r for r in rows(root / "registry.db",
                           "SELECT run_id, status, deleted_total, summary_json "
                           "FROM retention_runs ORDER BY id")][0]
    assert run[0] == report.run_id and run[1] == "ok"
    assert run[2] == report.deleted_total == 10
    rec = json.loads(run[3])
    assert rec["tenants"][A]["classes"]["events"]["deleted"] == 1
    assert rec["run_audit_row_id"] == run_row["id"]


# ---------------------------------------------------------------------------
# Effective retention
# ---------------------------------------------------------------------------

def test_legal_baseline_is_a_floor(root):
    ev = insert_event(root, A, event_type="wazuh.alert", payload={"n": 5},
                      received_at=ago(days=100), severity="high")
    _set_class_days(root, "events", 30)        # stored below the 365-day baseline
    report = _job(root).run()
    c = next(t for t in report.tenants if t.slug == A).classes["events"]
    assert (c.effective_days, c.basis, c.configured_days) == (365, "legal_baseline_floor", 30)
    assert c.deleted == 0
    assert _left(root, A, "events", "events") == {ev}


def test_tenant_override_only_lengthens_events(root):
    for slug in (A, B):
        insert_event(root, slug, event_type="wazuh.alert", payload={"n": slug},
                     received_at=ago(days=400), severity="high")
    _set_tenant_days(root, A, 730)             # A keeps two years
    _set_tenant_days(root, B, 30)              # B asks for less: the bundle wins
    report = _job(root).run()
    by = {t.slug: t.classes["events"] for t in report.tenants}
    assert (by[A].effective_days, by[A].basis, by[A].deleted) == (730, "tenant_override", 0)
    assert (by[B].effective_days, by[B].basis, by[B].deleted) == (365, "bundle", 1)
    # The override applies to 'events' only.
    assert next(t for t in report.tenants if t.slug == A).classes["agent_notes"].tenant_days is None


def test_a_longer_bundle_setting_is_honoured(root):
    insert_event(root, A, event_type="wazuh.alert", payload={"n": 1},
                 received_at=ago(days=400), severity="high")
    _set_class_days(root, "events", 730)
    report = _job(root).run()
    c = next(t for t in report.tenants if t.slug == A).classes["events"]
    assert (c.effective_days, c.deleted) == (730, 0)


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------

def test_dry_run_is_truthful_and_writes_nothing(root, tmp_path):
    _seed_all(root, A)
    arch_root = tmp_path / "archive"
    arch_root.mkdir()
    before = file_digests(root)
    dry = _job(root, archive=ColdArchive(arch_root)).run(dry_run=True)
    assert file_digests(root) == before
    assert list(arch_root.iterdir()) == []
    assert audit_rows(root, "retention_enforce") == []
    assert last_run(root / "registry.db") is None
    real = _job(root, archive=ColdArchive(arch_root)).run()
    for d, r in zip(dry.tenants, real.tenants):
        assert {k: c.planned for k, c in d.classes.items()} == \
               {k: c.deleted for k, c in r.classes.items()}


# ---------------------------------------------------------------------------
# Archive
# ---------------------------------------------------------------------------

def test_archive_is_written_before_the_prune(root, tmp_path):
    s = _seed_all(root, A)
    originals = {
        r[0]: r for r in rows(db(root, A, "telemetry"),
                              "SELECT id, received_at, payload, payload_sha256 FROM telemetry_raw")
    }
    arch = ColdArchive(tmp_path / "archive")
    (tmp_path / "archive").mkdir()
    report = _job(root, archive=arch).run()
    t = next(t for t in report.tenants if t.slug == A)
    assert t.classes["telemetry_raw"].deleted == 4
    assert t.archive["days"] == ["2026-09-20", "2026-09-21"]
    archived = arch.read_day(A, "2026-09-20") + arch.read_day(A, "2026-09-21")
    assert {r["id"] for r in archived} == set(s["raw_old"]) | {s["raw_edge"]}
    for r in archived:
        assert (r["id"], r["received_at"], r["payload"], r["payload_sha256"]) == originals[r["id"]]
        assert r["tenant"] == A
    assert arch.verify_day(A, "2026-09-20")
    manifest = arch.manifest(A)
    assert set(manifest["days"]) == {"2026-09-20", "2026-09-21"}
    sidecar = arch.day_file(A, "2026-09-21").with_name(
        arch.day_file(A, "2026-09-21").name + ".sha256").read_text()
    assert sidecar.split()[0] == hashlib.sha256(
        arch.day_file(A, "2026-09-21").read_bytes()).hexdigest()
    # Chunked archiving: a tiny chunk size produces the same file content.
    chunked = ColdArchive(tmp_path / "archive-chunked")
    (tmp_path / "archive-chunked").mkdir()
    _seed_all(root, B)
    _job(root, archive=chunked, archive_chunk=1).run(slugs=[B])
    assert len(chunked.read_day(B, "2026-09-20")) == 3
    with gzip.open(chunked.day_file(B, "2026-09-20")) as fh:
        assert len(fh.read().splitlines()) == 3                 # three members, one stream
    # A later run that finds a late row for an archived day appends it once.
    late = write_telemetry(root, A, received_at="2026-09-21T12:00:00.000Z",
                           domain="late.example.test", n=77)
    _job(root, archive=arch).run()
    _job(root, archive=arch).run()
    ids = [r["id"] for r in arch.read_day(A, "2026-09-21")]
    assert ids.count(late) == 1 and len(ids) == len(set(ids))
    with gzip.open(arch.day_file(A, "2026-09-21")) as fh:   # still one valid gzip stream
        assert len(fh.read().splitlines()) == len(ids)


def test_archive_disabled_prunes_and_says_so(root):
    _seed_all(root, A)
    report = _job(root).run()
    assert report.archive["enabled"] is False
    assert "WITHOUT a cold copy" in report.archive["reason"]
    t = next(t for t in report.tenants if t.slug == A)
    assert t.classes["telemetry_raw"].deleted == 4
    assert "archive disabled" in t.archive["note"]
    after = json.loads(audit_rows(root, "retention_enforce")[0]["after_state"])
    assert after["archive"]["enabled"] is False and "disabled" in after["archive"]["note"]


def test_env_configures_the_archive(root, tmp_path, monkeypatch):
    target = tmp_path / "env-archive"
    target.mkdir(mode=0o700)
    target.chmod(0o700)          # as docs/operations/bundle.md sets it up (owner only)
    monkeypatch.setenv("OCTO_ARCHIVE_ROOT", str(target))
    _seed_all(root, A)
    report = RetentionJob(data_root=root, now=lambda: NOW).run()
    assert {k: report.archive[k] for k in ("enabled", "root", "usable", "reason", "warning")} == {
        "enabled": True, "root": str(target), "usable": True, "reason": None, "warning": None}
    # No recipients configured: plaintext, and the run says so
    # (apps/octo/retention/tests/test_archive_encryption.py for the rest).
    assert report.archive["encrypted"] is False
    assert report.archive["encryption"]["mode"] == "off"
    assert report.archive["encryption_note"].startswith("archive NOT encrypted")
    assert (target / "telemetry" / A / "manifest.json").exists()


def test_an_unusable_archive_root_blocks_the_raw_prune(root, tmp_path):
    s = _seed_all(root, A)
    report = _job(root, archive=ColdArchive(tmp_path / "not-mounted")).run()
    t = next(t for t in report.tenants if t.slug == A)
    raw = t.classes["telemetry_raw"]
    assert (raw.status, raw.deleted, raw.held) == ("blocked", 0, 4)
    assert report.status == "partial"
    assert set(s["raw_old"]) | {s["raw_edge"]} <= _left(root, A, "telemetry", "telemetry_raw")
    # Everything else is still enforced.
    assert t.classes["events"].deleted == 1
    after = json.loads(audit_rows(root, "retention_enforce")[0]["after_state"])
    assert after["classes"]["telemetry_raw"]["planned"] == 0
    assert after["classes"]["telemetry_raw"]["held"] == 4


def test_a_failed_day_is_kept_and_the_others_pruned(root, tmp_path):
    s = _seed_all(root, A)
    arch = ColdArchive(tmp_path / "archive")
    (tmp_path / "archive").mkdir()
    # Make ONE day's file impossible to write: a directory stands in its place.
    arch.day_file(A, "2026-09-21").mkdir(parents=True)
    report = _job(root, archive=arch).run()
    raw = next(t for t in report.tenants if t.slug == A).classes["telemetry_raw"]
    assert raw.status == "blocked" and raw.deleted == 3 and raw.held == 1
    left = _left(root, A, "telemetry", "telemetry_raw")
    assert s["raw_edge"] in left and not set(s["raw_old"]) & left
    assert arch.verify_day(A, "2026-09-20")


def test_archive_folders_and_files_are_owner_only_whatever_the_umask(root, tmp_path):
    """The archive holds unmasked DNS with device names for every tenant:
    folders 0700, day files / sidecars / manifest 0600 even under umask 022;
    the restore script's scratch DB 0600; a root open to others is flagged."""
    import os
    import stat

    import scripts.restore_telemetry_archive as restore_script
    from apps.octo.retention.job import archive_status

    _seed_all(root, A)
    arch_root = tmp_path / "archive"
    arch_root.mkdir(mode=0o755)
    os.chmod(arch_root, 0o755)
    old_umask = os.umask(0o022)
    try:
        _job(root, archive=ColdArchive(arch_root)).run()
        out = tmp_path / "scratch" / "acme-dns.db"
        assert restore_script.main([
            "--archive-root", str(arch_root), "--tenant", A,
            "--day", "2026-09-20", "--out", str(out)]) == 0
    finally:
        os.umask(old_umask)
    made = list((arch_root / "telemetry").rglob("*"))
    assert any(p.name == "manifest.json" for p in made)
    assert any(p.name.endswith(".jsonl.gz.sha256") for p in made)
    for path in [arch_root / "telemetry", *made]:
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == (0o700 if path.is_dir() else 0o600), (path, oct(mode))
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    # The operator's root: 0755 is flagged (not blocking); 0700 is fine.
    status = archive_status(ColdArchive(arch_root), from_env=False)
    assert status["usable"] is True and "chmod 700" in status["warning"]
    os.chmod(arch_root, 0o700)
    assert archive_status(ColdArchive(arch_root), from_env=False)["warning"] is None
    assert archive_status(None, from_env=False)["warning"] is None


def test_restore_round_trip(root, tmp_path):
    import scripts.restore_telemetry_archive as restore_script

    s = _seed_all(root, A)
    originals = rows(db(root, A, "telemetry"),
                     "SELECT id, received_at, source, event_type, domain, device, payload, "
                     "payload_sha256 FROM telemetry_raw WHERE id IN (?, ?, ?, ?) ORDER BY id",
                     (*s["raw_old"], s["raw_edge"]))
    arch_root = tmp_path / "archive"
    arch_root.mkdir()
    _job(root, archive=ColdArchive(arch_root)).run()
    out = tmp_path / "scratch" / "acme-dns.db"
    assert restore_script.main([
        "--archive-root", str(arch_root), "--tenant", A,
        "--from", "2026-09-20", "--to", "2026-09-21", "--out", str(out)]) == 0
    restored = rows(out, "SELECT id, received_at, source, event_type, domain, device, payload, "
                         "payload_sha256 FROM telemetry_raw ORDER BY id")
    assert restored == originals
    assert rows(out, "SELECT SUM(count) FROM telemetry_hourly") == [(4,)]
    # Refusals: an existing file, the live data root, a tampered day.
    assert restore_script.main(["--archive-root", str(arch_root), "--tenant", A,
                                "--day", "2026-09-20", "--out", str(out)]) == 2
    assert restore_script.main(["--archive-root", str(arch_root), "--tenant", A,
                                "--day", "2026-09-20",
                                "--out", str(root / "clients" / A / "x.db")]) == 2
    f = ColdArchive(arch_root).day_file(A, "2026-09-20")
    f.write_bytes(f.read_bytes() + gzip.compress(b'{"id": 999999}\n'))
    other = tmp_path / "scratch" / "tampered.db"
    assert restore_script.main(["--archive-root", str(arch_root), "--tenant", A,
                                "--day", "2026-09-20", "--out", str(other)]) == 1


# ---------------------------------------------------------------------------
# Space
# ---------------------------------------------------------------------------

def test_incremental_vacuum_reclaims_telemetry_space(root):
    big = "x" * 4000
    write_telemetry_many(root, A, [
        {"received_at": iso(NOW - timedelta(days=10, minutes=i)), "domain": f"d{i}.example.test",
         "n": i, "payload": json.dumps({"pad": big, "i": i})}
        for i in range(400)
    ])
    tdb = db(root, A, "telemetry")
    size_before = tdb.stat().st_size + (tdb.with_name("telemetry.db-wal").stat().st_size
                                        if tdb.with_name("telemetry.db-wal").exists() else 0)
    report = _job(root).run()
    t = next(t for t in report.tenants if t.slug == A)
    assert t.classes["telemetry_raw"].deleted == 400
    vac = t.vacuum["telemetry"]
    assert vac["auto_vacuum"] == "incremental"
    assert vac["reclaimed_bytes"] > 1_000_000
    assert vac["freelist_bytes_after"] == 0
    assert tdb.stat().st_size < size_before


def test_a_pre_036_events_db_is_reported_then_converted(root):
    """events.db without incremental auto-vacuum: the nightly run does not
    VACUUM it (unbounded lock) but reports the reusable space; the one-time
    conversion makes the next prune give pages back."""
    edb = db(root, A, "events")
    conn = sqlite3.connect(edb)
    conn.execute("PRAGMA auto_vacuum = NONE")
    conn.execute("VACUUM")
    conn.close()
    assert rows(edb, "PRAGMA auto_vacuum") == [(0,)]
    pad = {"pad": "y" * 3000}
    insert_events_many(root, A, [(ago(days=400, minutes=i), {**pad, "i": i})
                                 for i in range(300)])
    report = _job(root).run()
    vac = next(t for t in report.tenants if t.slug == A).vacuum["events"]
    assert vac["auto_vacuum"] == "none" and vac["reclaimed_bytes"] == 0
    assert vac["reusable_bytes"] > 500_000
    converted = convert_to_incremental(edb)
    assert converted["changed"] and converted["bytes_after"] < converted["bytes_before"]
    assert rows(edb, "PRAGMA auto_vacuum") == [(2,)]
    insert_events_many(root, A, [(ago(days=500, minutes=i), {**pad, "j": i})
                                 for i in range(300)])
    again = next(t for t in _job(root).run().tenants if t.slug == A).vacuum["events"]
    assert again["auto_vacuum"] == "incremental" and again["reclaimed_bytes"] > 500_000
    assert convert_to_incremental(edb)["changed"] is False


def test_vacuum_is_bounded_by_its_budget(root):
    write_telemetry_many(root, A, [
        {"received_at": iso(NOW - timedelta(days=10, minutes=i)), "n": i,
         "payload": json.dumps({"pad": "z" * 4000, "i": i})}
        for i in range(200)
    ])
    ticks = iter(range(1000))
    report = _job(root, vacuum_budget_sec=2, vacuum_step_pages=1,
                  monotonic=lambda: float(next(ticks))).run()
    vac = next(t for t in report.tenants if t.slug == A).vacuum["telemetry"]
    assert vac["budget_exhausted"] is True and vac["steps"] <= 2
    assert vac["freelist_bytes_after"] > 0          # the rest waits for tomorrow


# ---------------------------------------------------------------------------
# Safety
# ---------------------------------------------------------------------------

def test_an_overlapping_run_is_skipped(root):
    _seed_all(root, A)
    before = file_digests(root)
    held = job_module._Lock(root / job_module.LOCK_NAME)
    assert held.acquire()
    try:
        report = _job(root).run()
    finally:
        held.release()
    assert report.status == "skipped" and report.tenants == []
    assert file_digests(root) == before
    assert _job(root).run().status == "ok"          # free again


def test_an_audit_failure_stops_the_run_before_any_delete(root):
    _seed_all(root, A)
    _seed_all(root, B)
    events_before = {s: _left(root, s, "events", "events") for s in (A, B)}
    audit_db = root / "global" / "audit.db"
    os.chmod(audit_db, 0o444)
    try:
        report = _job(root).run()
    finally:
        os.chmod(audit_db, 0o644)
    assert report.status == "failed"
    assert "audit" in report.tenants[0].error
    assert len(report.tenants) == 1                 # B never started
    assert {s: _left(root, s, "events", "events") for s in (A, B)} == events_before
    assert last_run(root / "registry.db")["status"] == "failed"
    assert audit_rows(root, "retention_run") == []          # the chain was unwritable


def test_a_failed_summary_row_is_said_and_the_deletes_stand(root):
    """The run's summary row comes after the deletes (each preceded by its
    tenant's plan row). If it cannot be written the deletes stand, and the
    run says so — partial, with the reason."""
    _seed_all(root, A)
    audit_db = root / "global" / "audit.db"

    class _LockAfterLastTenant(RetentionJob):
        # The audit DB turns read-only after the last tenant's deletes —
        # a real failure, exactly where the summary row is written.
        def _tenant(self, result, *a, **kw):
            super()._tenant(result, *a, **kw)
            if result.slug == B:
                for f in audit_db.parent.glob("audit.db*"):
                    os.chmod(f, 0o444)

    try:
        report = _LockAfterLastTenant(data_root=root, now=lambda: NOW,
                                      archive_from_env=False).run()
    finally:
        for f in audit_db.parent.glob("audit.db*"):
            os.chmod(f, 0o644)
    assert report.status == "partial" and report.deleted_total == 10
    assert "summary audit row could not be written" in report.note
    assert len(audit_rows(root, "retention_enforce")) == 1
    assert audit_rows(root, "retention_run") == []
    assert "summary audit row" in (last_run(root / "registry.db")["error"] or "")


def test_the_nightly_sweep_moves_fallback_rows(root):
    """Telemetry that fell back into events.db at ingest moves on the next
    run; a blocked lookup stays."""
    moved = insert_event(root, A, event_type="pihole.query", payload=pihole_payload(2),
                         received_at=ago(days=1))
    kept = insert_event(root, A, event_type="pihole.query", payload=pihole_payload(1),
                        received_at=ago(days=1))
    old = insert_event(root, A, event_type="pihole.query", payload=pihole_payload(3, n=5),
                       received_at=ago(days=30))
    report = _job(root).run()
    t = next(t for t in report.tenants if t.slug == A)
    assert t.sweep["moved"] == 1
    assert _left(root, A, "events", "events") == {kept, old}   # old: outside the sweep window
    assert rows(db(root, A, "telemetry"), "SELECT origin_event_id FROM telemetry_raw") == [(moved,)]


def test_classes_filter(root):
    _seed_all(root, A)
    report = _job(root).run(classes=["telemetry_raw"])
    c = next(t for t in report.tenants if t.slug == A).classes
    assert c["telemetry_raw"].deleted == 4
    assert c["events"].status == "skipped" and c["events"].deleted == 0
    with pytest.raises(ValueError):
        _job(root).run(classes=["nope"])


def test_the_script_convert_vacuum_takes_the_run_lock(root, capsys):
    import scripts.enforce_retention as script

    edb = db(root, A, "events")
    conn = sqlite3.connect(edb)
    conn.execute("PRAGMA auto_vacuum = NONE")
    conn.execute("VACUUM")
    conn.close()
    held = job_module._Lock(root / job_module.LOCK_NAME)
    assert held.acquire()
    try:
        assert script.main(["--data-root", str(root), "--convert-vacuum"]) == 3
    finally:
        held.release()
    assert rows(edb, "PRAGMA auto_vacuum") == [(0,)]
    assert script.main(["--data-root", str(root), "--convert-vacuum", "--slug", A]) == 0
    assert rows(edb, "PRAGMA auto_vacuum") == [(2,)]
    assert f"{A}/events.db: converted" in capsys.readouterr().out


def test_an_empty_append_writes_nothing(tmp_path):
    arch = ColdArchive(tmp_path)
    out = arch.append(A, "2026-09-20", [])
    assert out.rows_added == 0 and not arch.day_file(A, "2026-09-20").parent.joinpath(
        arch.day_file(A, "2026-09-20").name + ".sha256").exists()
    assert arch.manifest(A) == {}


def _script_on_the_test_clock(monkeypatch) -> None:
    """The script builds its own RetentionJob on the real clock; the rows
    here are seeded relative to NOW — so its job runs on NOW too (the
    product's clock handling is untouched)."""

    class _OnTheTestClock(RetentionJob):
        def __init__(self, *args, **kwargs):
            kwargs.setdefault("now", lambda: NOW)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(job_module, "RetentionJob", _OnTheTestClock)


def test_the_script(root, capsys, monkeypatch):
    import scripts.enforce_retention as script

    _script_on_the_test_clock(monkeypatch)
    _seed_all(root, A)
    assert script.main(["--data-root", str(root), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "archive: DISABLED" in out and "dry run — nothing was written" in out
    assert f"{A}: expiring events 1" in out
    # A run by hand that deletes must say why.
    assert script.main(["--data-root", str(root), "--slug", A]) == 2
    assert "--reason" in capsys.readouterr().err
    assert audit_rows(root, "retention_enforce") == []
    assert script.main(["--data-root", str(root), "--slug", A, "--json",
                        "--reason", "alice: disk cleanup before the audit"]) == 0
    out = capsys.readouterr().out
    report = json.loads(out[out.index("\n{") + 1:])
    assert report["mode"] == "enforce" and report["deleted_total"] == 10
    # Who ran it, and why, is on every audit row of the run.
    for action in ("retention_enforce", "retention_run"):
        [row] = audit_rows(root, action)
        by = json.loads(row["after_state"])["initiated_by"]
        assert by["by"] == "script" and by["script"] == "enforce_retention.py"
        assert by["os_user"] and by["host"]
        assert by["reason"] == "alice: disk cleanup before the audit"
        assert row["reason"] == "alice: disk cleanup before the audit"


def test_safe_under_concurrent_ingest(root):
    """Live telemetry keeps arriving (another thread, the real store) while
    the job prunes in tiny batches: no writer fails, every new row stays,
    every expired row goes."""
    import threading

    write_telemetry_many(root, A, [
        {"received_at": iso(NOW - timedelta(days=10, seconds=i)), "n": i,
         "payload": json.dumps({"old": i})}
        for i in range(300)
    ])
    errors: list = []
    written: list[int] = []
    start = threading.Event()

    def ingest() -> None:
        start.wait()
        try:
            for i in range(150):
                written.append(write_telemetry(
                    root, A, received_at=iso(NOW - timedelta(minutes=i)),
                    domain=f"live{i}.example.test", n=10_000 + i))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t = threading.Thread(target=ingest)
    t.start()
    start.set()
    report = _job(root, batch_size=7, vacuum_step_pages=4).run()
    t.join()
    assert not errors
    raw = next(x for x in report.tenants if x.slug == A).classes["telemetry_raw"]
    assert raw.deleted == 300
    left = _left(root, A, "telemetry", "telemetry_raw")
    assert set(written) <= left and len(left) == 150


# ---------------------------------------------------------------------------
# Evidence — events an incident record cites are held
# ---------------------------------------------------------------------------

def _old_signal(root, slug, n, days=400) -> int:
    return insert_event(root, slug, event_type="wazuh.alert", payload={"n": n},
                        received_at=ago(days=days), severity="high")


def test_events_cited_by_an_incident_record_are_held(root):
    """A year-old signal a ticket was opened from, that an agent note is
    about, that a pattern link or an incident lists, is evidence: kept, and
    reported as held; the unreferenced one of the same age goes."""
    ticketed, noted, linked, incident, plain = (_old_signal(root, A, n) for n in range(5))
    open_ticket(root, A, ticketed)
    event_note(root, A, noted)
    conn = sqlite3.connect(db(root, A, "events"))
    conn.execute(
        "INSERT INTO agent_pattern_links (from_kind, from_id, to_kind, to_id, relation, "
        " strength, rationale, created_by_agent) VALUES ('ticket', 9, 'event', ?, "
        " 'same_host', 0.5, 'r', 'octo')", (linked,))
    conn.execute(
        "INSERT INTO incidents (severity, indicator_ids, event_ids, summary, evidence_refs) "
        "VALUES ('high', '[]', ?, 's', '[]')", (json.dumps([incident, None, "x"]),))
    # An incident row with a malformed list must not break the guard.
    conn.execute(
        "INSERT INTO incidents (severity, indicator_ids, event_ids, summary, evidence_refs) "
        "VALUES ('high', '[]', 'not json', 's', '[]')")
    conn.commit()
    conn.close()
    dry = _job(root).run(dry_run=True).tenants[0].classes["events"]
    assert (dry.planned, dry.referenced) == (1, 4)
    report = _job(root).run()
    ev = next(t for t in report.tenants if t.slug == A).classes["events"]
    assert (ev.planned, ev.deleted, ev.referenced) == (1, 1, 4)
    assert _left(root, A, "events", "events") == {ticketed, noted, linked, incident}
    plan = json.loads(audit_rows(root, "retention_enforce")[0]["after_state"])
    assert plan["classes"]["events"]["referenced"] == 4
    result = json.loads(audit_rows(root, "retention_run")[0]["after_state"])["tenants"][A]
    assert result["classes"]["events"] == {
        "status": "ok", "planned": 1, "deleted": 1, "held": 0, "referenced": 4, "evidence": 0,
        "error": None}


def test_a_held_event_lives_as_long_as_its_longest_referrer(root):
    """The note about an event is kept 2190 days; once it ages out, the next
    run prunes the event too."""
    ev = _old_signal(root, A, 1, days=2300)
    note = event_note(root, A, ev, created_at=ago(days=2200))
    first = next(t for t in _job(root).run().tenants if t.slug == A).classes
    assert (first["events"].deleted, first["events"].referenced) == (0, 1)
    assert first["agent_notes"].deleted == 1               # the note aged out…
    assert note not in _left(root, A, "events", "agent_notes")
    second = next(t for t in _job(root).run().tenants if t.slug == A).classes
    assert (second["events"].deleted, second["events"].referenced) == (1, 0)   # …then the event


class _Hooked(RetentionJob):
    """The real job, with a hook that runs between the plan (its audit row)
    and the deletes — where a concurrent writer can act."""

    def __init__(self, *a, between=None, **kw):
        super().__init__(*a, **kw)
        self._between = between

    def _audit(self, result, report):
        row_id = super()._audit(result, report)
        if self._between is not None and result.slug == A:
            self._between()
        return row_id


def _hooked(root, between, **kw):
    kw.setdefault("archive_from_env", False)
    return _Hooked(data_root=root, now=lambda: NOW, between=between, **kw)


def test_a_citation_made_after_the_plan_still_holds_the_event(root):
    """A ticket opened / a note written from an event between the plan and
    the delete: the note is re-checked inside the DELETE, tickets.db is
    re-read just before it — the event stays."""
    via_ticket, via_note, plain = (_old_signal(root, A, n) for n in range(3))

    def cite():
        open_ticket(root, A, via_ticket)
        event_note(root, A, via_note)

    report = _hooked(root, cite).run()
    ev = next(t for t in report.tenants if t.slug == A).classes["events"]
    assert ev.planned == 3 and ev.deleted == 1
    assert _left(root, A, "events", "events") == {via_ticket, via_note}
    result = json.loads(audit_rows(root, "retention_run")[0]["after_state"])["tenants"][A]
    assert result["classes"]["events"]["deleted"] == 1      # the chain says what happened


def test_unreadable_references_fail_closed(root):
    """tickets.db that cannot be opened (permissions after a restore) must
    not read as "no tickets": no event is deleted; the other classes are."""
    ticketed = _old_signal(root, A, 1)
    plain = _old_signal(root, A, 2)
    open_ticket(root, A, ticketed)
    _note(root, A, ago(days=2200))
    tickets = root / "clients" / A / "tickets.db"
    os.chmod(tickets, 0)
    try:
        report = _job(root).run()
    finally:
        os.chmod(tickets, 0o644)
    c = next(t for t in report.tenants if t.slug == A).classes
    assert c["events"].status == "error" and c["events"].deleted == 0
    assert "references unreadable" in c["events"].note
    assert _left(root, A, "events", "events") == {ticketed, plain}
    assert c["agent_notes"].deleted == 1
    assert report.status == "partial"


# ---------------------------------------------------------------------------
# Fail closed on the policy
# ---------------------------------------------------------------------------

def test_an_unreadable_registry_fails_the_run_and_deletes_nothing(root):
    """events set to 730 days; the registry cannot be read at run time. The
    defaults (365) must NOT be applied: nothing is swept, planned, audited or
    deleted, and the run says failed."""
    _set_class_days(root, "events", 730)
    ev = _old_signal(root, A, 1, days=500)
    moved = insert_event(root, A, event_type="pihole.query", payload=pihole_payload(2),
                         received_at=ago(days=1))
    registry = root / "registry.db"
    os.chmod(registry, 0)
    try:
        report = _job(root).run()
    finally:
        os.chmod(registry, 0o644)
    assert report.status == "failed" and report.tenants == []
    assert "policy unreadable" in report.note
    assert _left(root, A, "events", "events") == {ev, moved}
    assert audit_rows(root, "retention_enforce") == []
    # Readable again: the stored 730 days hold the 500-day signal.
    again = next(t for t in _job(root).run().tenants if t.slug == A).classes["events"]
    assert (again.effective_days, again.deleted) == (730, 0)


def test_a_registry_without_the_policy_table_fails_the_run(root):
    conn = sqlite3.connect(root / "registry.db")
    conn.execute("ALTER TABLE bundle_config_retention RENAME TO bcr_elsewhere")
    conn.commit()
    conn.close()
    ev = _old_signal(root, A, 1)
    report = _job(root).run()
    assert report.status == "failed"
    assert _left(root, A, "events", "events") == {ev}


# ---------------------------------------------------------------------------
# Legal-baseline floor (with nothing else masking it)
# ---------------------------------------------------------------------------

def test_the_floor_holds_without_a_tenant_value_masking_it(root):
    """The tenant's own value at its minimum (30 — the column is NOT NULL,
    default 365, which would mask the floor): a 30-day events setting is
    enforced at the 365-day baseline; agent notes set to 365 days are
    enforced at their 2190-day baseline."""
    _set_tenant_days(root, A, 30)
    _set_class_days(root, "events", 30)
    _set_class_days(root, "agent_notes", 365)
    kept_ev = _old_signal(root, A, 1, days=300)
    gone_ev = _old_signal(root, A, 2, days=400)
    kept_note = _note(root, A, ago(days=1000))
    gone_note = _note(root, A, ago(days=2200))
    report = _job(root).run()
    c = next(t for t in report.tenants if t.slug == A).classes
    assert (c["events"].effective_days, c["events"].basis, c["events"].tenant_days) == \
        (365, "legal_baseline_floor", 30)
    assert (c["agent_notes"].effective_days, c["agent_notes"].basis) == (2190, "legal_baseline_floor")
    assert _left(root, A, "events", "events") == {kept_ev}
    assert _left(root, A, "events", "agent_notes") == {kept_note}
    assert gone_ev not in _left(root, A, "events", "events")
    assert gone_note not in _left(root, A, "events", "agent_notes")


# ---------------------------------------------------------------------------
# Rows that arrive between the plan and the delete
# ---------------------------------------------------------------------------

def test_a_raw_row_landing_on_an_archived_day_after_the_archive_survives(root, tmp_path):
    """A replayed buoy queue can land an OLD-day raw row after that day was
    archived and before it is pruned. The prune is bounded by the ids that
    were archived, so the row stays — and the next run archives it first."""
    arch = ColdArchive(tmp_path / "archive")
    (tmp_path / "archive").mkdir()
    s = _seed_all(root, A)
    late: list[int] = []

    def replay():
        late.append(write_telemetry(root, A, received_at="2026-09-20T05:00:00.000Z",
                                    domain="late.example.test", n=500))

    _hooked(root, replay, archive=arch).run()
    left = _left(root, A, "telemetry", "telemetry_raw")
    assert late[0] in left and not set(s["raw_old"]) & left
    assert late[0] not in {r["id"] for r in arch.read_day(A, "2026-09-20")}
    _job(root, archive=arch).run()
    assert late[0] not in _left(root, A, "telemetry", "telemetry_raw")
    assert late[0] in {r["id"] for r in arch.read_day(A, "2026-09-20")}


def test_a_signal_landing_after_the_plan_is_not_deleted_uncounted(root):
    """The events delete is bounded by the planned ids: an expired-looking
    row stored after the plan (a poller importing history) waits for the
    next run's plan and audit row."""
    planned = _old_signal(root, A, 1)
    late: list[int] = []
    report = _hooked(root, lambda: late.append(_old_signal(root, A, 2))).run()
    ev = next(t for t in report.tenants if t.slug == A).classes["events"]
    assert (ev.planned, ev.deleted) == (1, 1)
    assert _left(root, A, "events", "events") == {late[0]}
    assert planned not in _left(root, A, "events", "events")


def test_a_failed_prune_then_rerun_never_archives_a_row_twice(root, tmp_path):
    """The day is archived, then its prune fails (telemetry.db read-only);
    the rerun archives the same rows again as a no-op and prunes them."""
    arch = ColdArchive(tmp_path / "archive")
    (tmp_path / "archive").mkdir()
    s = _seed_all(root, A)
    tdb = db(root, A, "telemetry")

    def lock_telemetry():
        os.chmod(tdb, 0o444)

    try:
        first = _hooked(root, lock_telemetry, archive=arch).run()
    finally:
        for f in tdb.parent.glob("telemetry.db*"):
            os.chmod(f, 0o644)
    raw = next(t for t in first.tenants if t.slug == A).classes["telemetry_raw"]
    assert raw.status == "error" and raw.deleted == 0
    assert set(s["raw_old"]) <= _left(root, A, "telemetry", "telemetry_raw")
    result = json.loads(audit_rows(root, "retention_run")[0]["after_state"])["tenants"][A]
    assert result["classes"]["telemetry_raw"]["deleted"] == 0
    assert result["classes"]["telemetry_raw"]["error"]
    second = _job(root, archive=arch).run()
    assert next(t for t in second.tenants if t.slug == A).classes["telemetry_raw"].deleted == 4
    for day in ("2026-09-20", "2026-09-21"):
        ids = [r["id"] for r in arch.read_day(A, day)]
        assert len(ids) == len(set(ids))
    assert sorted(r["id"] for r in arch.read_day(A, "2026-09-20")) == sorted(s["raw_old"])


def test_the_archive_parses_a_day_file_once_per_run(root, tmp_path, monkeypatch):
    from apps.octo.retention import archive as archive_module

    arch = ColdArchive(tmp_path / "archive")
    (tmp_path / "archive").mkdir()
    write_telemetry_many(root, A, [
        {"received_at": iso(NOW - timedelta(days=9, minutes=i)), "n": i,
         "payload": json.dumps({"i": i})} for i in range(30)
    ])
    # A day file already holding some of the day (an earlier partial run).
    arch.append(A, "2026-09-20", [{"id": 1, "received_at": "2026-09-20T11:59:00.000Z",
                                   "payload": "{}", "payload_sha256": "x"}])
    parses: list[str] = []
    real_parse = archive_module._parse
    monkeypatch.setattr(archive_module, "_parse",
                        lambda data, where: parses.append(where) or real_parse(data, where))
    report = _job(root, archive=arch, archive_chunk=4).run(slugs=[A])
    assert next(t for t in report.tenants if t.slug == A).classes["telemetry_raw"].deleted == 30
    assert len(parses) == 1                     # once for the day, not once per chunk
    ids = [r["id"] for r in arch.read_day(A, "2026-09-20")]
    assert len(ids) == len(set(ids)) == 30      # row 1 was archived already


# ---------------------------------------------------------------------------
# The sweep
# ---------------------------------------------------------------------------

def test_dry_run_counts_what_the_sweep_would_move_and_prune(root):
    """A fallback row stored at 23:00 on the day before the raw cutoff: the
    real run moves it and prunes it in the same pass, so the dry run must
    count it in telemetry_raw."""
    insert_event(root, A, event_type="pihole.query", payload=pihole_payload(2, n=1),
                 received_at="2026-09-21T23:00:00.000Z")
    insert_event(root, A, event_type="pihole.query", payload=pihole_payload(3, n=2),
                 received_at="2026-09-28T23:00:00.000Z")         # moved, not expired
    dry = _job(root).run(dry_run=True)
    real = _job(root).run()
    d = next(t for t in dry.tenants if t.slug == A)
    r = next(t for t in real.tenants if t.slug == A)
    assert d.sweep["moved"] == r.sweep["moved"] == 2
    assert d.classes["telemetry_raw"].planned == r.classes["telemetry_raw"].deleted == 1
    for k in d.classes:
        assert d.classes[k].planned == r.classes[k].deleted, k


def test_the_sweep_resumes_where_the_last_completed_sweep_stopped(root):
    """The resume point is an events.db id, not a time window: a fallback
    row carrying an OLD timestamp (a long telemetry-store outage, a buoy
    replaying its queue) is still moved. A sweep that failed does not
    advance the resume point."""
    first = _job(root).run()
    through = first.tenants[0].sweep["through_id"]
    run = last_run(root / "registry.db")
    assert run["summary"]["tenants"][A]["sweep_through_id"] == through
    old_fallback = insert_event(root, A, event_type="pihole.query",
                                payload=pihole_payload(2, n=7), received_at=ago(days=30))
    # telemetry.db refuses writes for this run: the sweep fails, the rest goes on.
    tdb = db(root, A, "telemetry")
    os.chmod(tdb, 0o444)
    try:
        failed = _job(root).run()
    finally:
        for f in tdb.parent.glob("telemetry.db*"):      # SQLite made -wal/-shm 0444 too
            os.chmod(f, 0o644)
    ta = next(t for t in failed.tenants if t.slug == A)
    assert ta.sweep["error"] and ta.sweep["moved"] == 0
    assert last_run(root / "registry.db")["summary"]["tenants"][A]["sweep_through_id"] is None
    assert old_fallback in _left(root, A, "events", "events")
    # Repaired: the next run picks up from the last COMPLETED sweep.
    fixed = next(t for t in _job(root).run().tenants if t.slug == A)
    assert fixed.sweep["moved"] == 1
    assert old_fallback not in _left(root, A, "events", "events")
    # …and, 30 days old, it is past the raw retention: pruned in the same run
    # (it was an answered lookup — telemetry — all along).
    assert fixed.classes["telemetry_raw"].deleted == 1


def test_a_resume_point_beyond_the_file_falls_back_to_the_window(root):
    """events.db restored from an older backup: ids below the stored resume
    point come again; the sweep then looks back SWEEP_DAYS instead."""
    _job(root).run()
    conn = sqlite3.connect(root / "registry.db")
    summary = json.loads(conn.execute("SELECT summary_json FROM retention_runs").fetchone()[0])
    summary["tenants"][A]["sweep_through_id"] = 10_000
    conn.execute("UPDATE retention_runs SET summary_json = ?", (json.dumps(summary),))
    conn.commit()
    conn.close()
    fallback = insert_event(root, A, event_type="pihole.query", payload=pihole_payload(2),
                            received_at=ago(days=1))
    t = next(t for t in _job(root).run().tenants if t.slug == A)
    assert t.sweep["moved"] == 1 and fallback not in _left(root, A, "events", "events")


# ---------------------------------------------------------------------------
# The one-time conversion's disk check
# ---------------------------------------------------------------------------

def test_convert_checks_twice_the_file_in_its_own_directory(root, monkeypatch):
    edb = db(root, A, "events")
    conn = sqlite3.connect(edb)
    conn.execute("PRAGMA auto_vacuum = NONE")
    conn.execute("VACUUM")
    conn.close()
    insert_events_many(root, A, [(ago(days=1, minutes=i), {"pad": "p" * 2000, "i": i})
                                 for i in range(200)])
    wal = edb.with_name("events.db-wal")
    size = edb.stat().st_size + (wal.stat().st_size if wal.exists() else 0)
    seen: list[str] = []
    real_statvfs = os.statvfs

    class _Vfs:
        def __init__(self, free):
            self.f_bavail, self.f_frsize = free, 1

    def statvfs(path):
        seen.append(str(path))
        return _Vfs(int(size * 1.5))            # enough for one copy, not two

    monkeypatch.setattr(job_module.os, "statvfs", statvfs)
    out = convert_to_incremental(edb)
    assert out["changed"] is False and "refused" in out["note"]
    assert seen == [str(edb.parent)]
    monkeypatch.setattr(job_module.os, "statvfs", real_statvfs)
    out = convert_to_incremental(edb)
    assert out["changed"] and out["temp_dir"] == str(edb.parent)
    # temp_store_directory is process-global in SQLite: it was put back.
    probe = sqlite3.connect(":memory:")
    try:
        assert probe.execute("PRAGMA temp_store_directory").fetchone() in (None, ("",), (None,))
    finally:
        probe.close()
