"""Moving pre-036 telemetry out of events.db (`apps.octo.retention.move` and
`scripts/move_telemetry_out_of_events.py`).

Real tenants (client_provisioning), rows written into events.db as the
pre-036 sink wrote them. Pins:
  * only rows the ingest classifier calls telemetry move; blocked DNS,
    alert-carrying records, other types, referenced rows (ticket / agent
    note) and oversize payloads stay;
  * a moved row's identity is untouched: payload text, payload_sha256,
    received_at, source, source_host, severity, event_type — and
    origin_event_id = its events.db id;
  * the roll-up and first-seen ledger are rebuilt from the moved rows;
  * deletes happen only after the copy is committed, and a run interrupted
    between the two finishes cleanly (no double count) — idempotent,
    resumable, batch size irrelevant;
  * a dry run is truthful and writes nothing.
"""
from __future__ import annotations

import json
import os
import sqlite3

import pytest

from apps.octo.ingest import telemetry
from apps.octo.retention.move import move_tenant
from apps.octo.tests._tiering_fixtures import (
    ago, db, event_note, file_digests, insert_event, make_root, open_ticket, pihole_payload,
    rows, suricata_payload,
)

SLUG = "acme-corp"
IDENTITY = ("received_at, source, source_host, event_type, severity, payload, payload_sha256")


@pytest.fixture
def root(tmp_path, monkeypatch):
    r = make_root(tmp_path, monkeypatch, tenants=(SLUG,))
    # A tenant from before 036: no telemetry.db yet.
    for side in ("", "-wal", "-shm"):
        p = r / "clients" / SLUG / f"telemetry.db{side}"
        if p.exists():
            p.unlink()
    telemetry.reset_schema_cache()
    return r


def _seed(root) -> dict[str, int]:
    ids = {
        "answered": insert_event(root, SLUG, event_type="pihole.query",
                                 payload=pihole_payload(2, "a.example.test", n=1),
                                 received_at=ago(days=2, hours=1)),
        "cached": insert_event(root, SLUG, event_type="pihole.query",
                               payload=pihole_payload(3, "a.example.test", client="192.0.2.11", n=2),
                               received_at=ago(days=2, minutes=30)),
        "old_dns": insert_event(root, SLUG, event_type="suricata.dns",
                                payload=suricata_payload("dns", "old.example.test"),
                                received_at=ago(days=20)),
        "tls": insert_event(root, SLUG, event_type="suricata.tls",
                            payload=suricata_payload("tls", tls={"sni": "login.example.test"}),
                            received_at=ago(hours=5)),
        "blocked": insert_event(root, SLUG, event_type="pihole.query",
                                payload=pihole_payload(1, "ads.example.test", n=3),
                                received_at=ago(days=1), severity="low"),
        "alert_dns": insert_event(root, SLUG, event_type="suricata.dns",
                                  payload=suricata_payload("dns", alert={"signature_id": 1}),
                                  received_at=ago(days=1)),
        "wazuh": insert_event(root, SLUG, event_type="wazuh.alert",
                              payload={"rule": {"level": 10}}, received_at=ago(days=1),
                              severity="high"),
        "noted": insert_event(root, SLUG, event_type="suricata.dns",
                              payload=suricata_payload("dns", "noted.example.test"),
                              received_at=ago(days=1)),
        "oversize": insert_event(root, SLUG, event_type="suricata.http",
                                 payload=suricata_payload(
                                     "http", http={"hostname": "big.example.test",
                                                   "body": "x" * (telemetry.MAX_PAYLOAD_BYTES + 1)}),
                                 received_at=ago(days=1)),
    }
    conn = sqlite3.connect(db(root, SLUG, "events"))
    try:
        conn.execute(
            "INSERT INTO agent_notes (ref_kind, ref_id, agent_id, note_text, confidence, "
            " audit_request_id) VALUES ('event', ?, 'octo', 'looked at this', 0.5, 'r-1')",
            (ids["noted"],),
        )
        conn.commit()
    finally:
        conn.close()
    return ids


MOVED = ("answered", "cached", "old_dns", "tls")
KEPT = ("blocked", "alert_dns", "wazuh", "noted", "oversize")


def test_dry_run_is_truthful_and_writes_nothing(root):
    _seed(root)
    before = file_digests(root)
    report = move_tenant(SLUG, data_root=root, dry_run=True)
    assert file_digests(root) == before
    assert not (root / "clients" / SLUG / "telemetry.db").exists()
    assert (report.scanned, report.telemetry, report.moved, report.deleted) == (8, 6, 4, 4)
    assert (report.kept_signal, report.kept_referenced, report.kept_oversize) == (2, 1, 1)
    # …and the real run does exactly that.
    real = move_tenant(SLUG, data_root=root, dry_run=False)
    assert (real.moved, real.deleted, real.kept_signal, real.kept_referenced,
            real.kept_oversize) == (4, 4, 2, 1, 1)


def test_move_copies_verbatim_and_keeps_signals(root):
    ids = _seed(root)
    originals = {
        name: rows(db(root, SLUG, "events"), f"SELECT {IDENTITY} FROM events WHERE id = ?",
                   (ids[name],))[0]
        for name in ids
    }
    report = move_tenant(SLUG, data_root=root, dry_run=False, batch_size=2)
    assert report.error is None
    left = {r[0] for r in rows(db(root, SLUG, "events"), "SELECT id FROM events")}
    assert left == {ids[k] for k in KEPT}
    tdb = db(root, SLUG, "telemetry")
    for name in MOVED:
        [copy] = rows(tdb, f"SELECT {IDENTITY} FROM telemetry_raw WHERE origin_event_id = ?",
                      (ids[name],))
        assert copy == originals[name], name
    # Roll-up + first-seen rebuilt from the moved rows.
    assert rows(tdb, "SELECT event_type, domain, device, count FROM telemetry_hourly "
                     "WHERE domain = 'a.example.test' ORDER BY device") == [
        ("pihole.query", "a.example.test", "192.0.2.10", 1),
        ("pihole.query", "a.example.test", "192.0.2.11", 1),
    ]
    first = dict(rows(tdb, "SELECT domain, first_seen FROM first_seen_domains"))
    assert set(first) == {"a.example.test", "old.example.test", "login.example.test"}
    assert first["old.example.test"] == originals["old_dns"][0]


def test_interrupted_run_finishes_without_double_counting(root):
    """A crash after the copy committed but before the delete: the copy is
    there, the source row too. The next run finds the copy (origin id),
    finishes the delete, and counts nothing twice."""
    ids = _seed(root)
    [src] = rows(db(root, SLUG, "events"),
                 "SELECT id, received_at, source, source_host, event_type, severity, payload, "
                 "payload_sha256 FROM events WHERE id = ?", (ids["answered"],))
    telemetry.TelemetryStore(root).write(SLUG, [telemetry.TelemetryRow(
        received_at=src[1], source=src[2], event_type=src[4], severity=src[5],
        source_host=src[3], domain="a.example.test", device="192.0.2.10", payload=src[6],
        payload_truncated=False, payload_sha256=src[7], origin_event_id=src[0],
    )])
    report = move_tenant(SLUG, data_root=root, dry_run=False)
    assert report.already_copied == 1 and report.moved == 3 and report.deleted == 4
    tdb = db(root, SLUG, "telemetry")
    assert rows(tdb, "SELECT COUNT(*) FROM telemetry_raw") == [(4,)]
    assert rows(tdb, "SELECT SUM(count) FROM telemetry_hourly") == [(4,)]
    # Idempotent: a further run finds nothing to do.
    again = move_tenant(SLUG, data_root=root, dry_run=False)
    assert (again.moved, again.deleted, again.already_copied) == (0, 0, 0)
    assert rows(tdb, "SELECT SUM(count) FROM telemetry_hourly") == [(4,)]


def test_a_row_changed_after_the_copy_is_not_deleted(root):
    """A copy made earlier (an interrupted run) that no longer matches the
    row's identity (sha, received_at) — the row changed since — is never
    followed by a delete: the newer version stays in events.db."""
    ids = _seed(root)
    # The interrupted run's copy, then the row changes.
    [src] = rows(db(root, SLUG, "events"),
                 "SELECT id, received_at, source, source_host, event_type, severity, payload, "
                 "payload_sha256 FROM events WHERE id = ?", (ids["tls"],))
    telemetry.TelemetryStore(root).write(SLUG, [telemetry.TelemetryRow(
        received_at=src[1], source=src[2], event_type=src[4], severity=src[5],
        source_host=src[3], domain="login.example.test", device="192.0.2.10",
        payload=src[6], payload_truncated=False, payload_sha256=src[7], origin_event_id=src[0],
    )])
    conn = sqlite3.connect(db(root, SLUG, "events"))
    conn.execute("UPDATE events SET received_at = ? WHERE id = ?", (ago(hours=1), ids["tls"]))
    conn.commit()
    conn.close()
    report = move_tenant(SLUG, data_root=root, dry_run=False)
    assert report.kept_changed == 1 and report.moved == 3
    assert rows(db(root, SLUG, "events"), "SELECT received_at FROM events WHERE id = ?",
                (ids["tls"],)) == [(ago(hours=1),)]


def test_since_bounds_the_sweep(root):
    ids = _seed(root)
    report = move_tenant(SLUG, data_root=root, dry_run=False, since=ago(days=8))
    assert report.moved == 3                  # the 20-day-old row is outside
    assert rows(db(root, SLUG, "events"), "SELECT COUNT(*) FROM events WHERE id = ?",
                (ids["old_dns"],)) == [(1,)]


def test_the_script_dry_run_then_real(root, capsys):
    import scripts.move_telemetry_out_of_events as script

    _seed(root)
    before = file_digests(root)
    assert script.main(["--data-root", str(root), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "would move 4" in out and "dry run — nothing was written" in out
    assert file_digests(root) == before
    assert script.main(["--data-root", str(root), "--no-prune", "--json"]) == 0
    out = capsys.readouterr().out
    report = json.loads(out[out.index("{"):])
    assert report["move"][0]["moved"] == 4 and report["retention"] is None
    assert script.main(["--data-root", str(root), "--slug", "nobody"]) == 2


# ---------------------------------------------------------------------------
# Evidence — fail closed, re-checked per batch
# ---------------------------------------------------------------------------

def _events(root) -> set[int]:
    return {r[0] for r in rows(db(root, SLUG, "events"), "SELECT id FROM events")}


def _after_copy(monkeypatch, hook):
    """Run `hook(batch)` right after each telemetry copy commits — between
    the move's copy and its delete, where a concurrent writer can act. The
    real store does the write."""
    real = telemetry.TelemetryStore.write

    def write(self, slug, batch, **kw):
        out = real(self, slug, batch, **kw)
        hook(batch)
        return out

    monkeypatch.setattr(telemetry.TelemetryStore, "write", write)


def test_unreadable_tickets_db_stops_the_move(root):
    """tickets.db that cannot be opened must not read as "no tickets": the
    move stops for the tenant before copying or deleting anything."""
    ids = _seed(root)
    open_ticket(root, SLUG, ids["answered"])
    before = _events(root)
    tickets = root / "clients" / SLUG / "tickets.db"
    os.chmod(tickets, 0)
    try:
        report = move_tenant(SLUG, data_root=root, dry_run=False)
    finally:
        os.chmod(tickets, 0o644)
    assert report.error and "references unreadable" in report.error
    assert (report.moved, report.deleted) == (0, 0)
    assert _events(root) == before
    assert report.through_id is None            # the nightly resume point stays put
    again = move_tenant(SLUG, data_root=root, dry_run=False)
    assert again.error is None and ids["answered"] in _events(root)
    assert again.kept_referenced == 2           # the ticketed row + the noted one


def test_a_ticket_opened_mid_move_keeps_its_event(root, monkeypatch):
    """batch_size=1: a ticket is opened from a LATER row while the first row
    is being moved (checked before that row is copied), and from the row
    just copied (checked again just before its delete). Both stay."""
    ids = _seed(root)
    order = sorted(ids[k] for k in MOVED)
    first, later = order[0], order[-1]
    opened: list[int] = []

    def open_tickets(batch):
        if not opened:
            opened.append(open_ticket(root, SLUG, first))
            opened.append(open_ticket(root, SLUG, later))

    _after_copy(monkeypatch, open_tickets)
    report = move_tenant(SLUG, data_root=root, dry_run=False, batch_size=1)
    assert report.error is None
    assert {first, later} <= _events(root)
    assert report.kept_referenced == 3          # + the noted row
    assert report.deleted == len(MOVED) - 2
    # The later row was never copied (checked before its copy).
    assert rows(db(root, SLUG, "telemetry"),
                "SELECT COUNT(*) FROM telemetry_raw WHERE origin_event_id = ?", (later,)) == [(0,)]


def test_a_note_written_mid_move_keeps_its_event(root, monkeypatch):
    """A note about an event written after the event's copy committed: the
    DELETE re-checks events.db's references inside the statement."""
    ids = _seed(root)
    target = ids["answered"]
    _after_copy(monkeypatch, lambda batch: event_note(root, SLUG, target)
                if any(r.origin_event_id == target for r in batch) else None)
    report = move_tenant(SLUG, data_root=root, dry_run=False)
    assert target in _events(root)
    assert report.kept_referenced == 2 and report.kept_changed == 0


def test_a_row_changed_between_copy_and_delete_is_not_deleted(root, monkeypatch):
    """The delete matches id AND payload_sha256 AND received_at: a row whose
    identity changed after it was copied stays (never lose the newer
    version)."""
    ids = _seed(root)
    target = ids["cached"]

    def rewrite(batch):
        if any(r.origin_event_id == target for r in batch):
            conn = sqlite3.connect(db(root, SLUG, "events"))
            conn.execute("UPDATE events SET payload_sha256 = 'rewritten' WHERE id = ?", (target,))
            conn.commit()
            conn.close()

    _after_copy(monkeypatch, rewrite)
    report = move_tenant(SLUG, data_root=root, dry_run=False)
    assert report.kept_changed == 1
    assert rows(db(root, SLUG, "events"), "SELECT payload_sha256 FROM events WHERE id = ?",
                (target,)) == [("rewritten",)]


def test_pattern_links_and_incidents_are_evidence_too(root):
    ids = _seed(root)
    conn = sqlite3.connect(db(root, SLUG, "events"))
    conn.execute(
        "INSERT INTO agent_pattern_links (from_kind, from_id, to_kind, to_id, relation, "
        " strength, rationale, created_by_agent) VALUES ('event', ?, 'ticket', 3, "
        " 'temporal', 0.4, 'r', 'athena')", (ids["tls"],))
    conn.execute(
        "INSERT INTO incidents (severity, indicator_ids, event_ids, summary, evidence_refs) "
        "VALUES ('critical', '[]', ?, 's', '[]')", (json.dumps([ids["old_dns"]]),))
    conn.commit()
    conn.close()
    report = move_tenant(SLUG, data_root=root, dry_run=False)
    assert {ids["tls"], ids["old_dns"]} <= _events(root)
    assert report.kept_referenced == 3


# ---------------------------------------------------------------------------
# The script's preview of the one irreversible step
# ---------------------------------------------------------------------------

def _freeze_retention_clock(monkeypatch) -> None:
    """The fixtures plant rows around the fixed fixture NOW (2026-09-29), but
    the script builds its RetentionJob with the REAL clock. From 2026-10-06
    the "new" rows were older than the 7-day raw-telemetry cutoff and the
    expected counts drifted (a time bomb, not a product bug). Pin the
    retention clock to the fixtures' NOW."""
    from apps.octo.retention import job as retention_job
    from apps.octo.tests._tiering_fixtures import NOW

    class _FixedDatetime(retention_job.datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW if tz is not None else NOW.replace(tzinfo=None)

    monkeypatch.setattr(retention_job, "datetime", _FixedDatetime)


def _old_history(root, n_old=3, n_new=2) -> None:
    for i in range(n_old):
        insert_event(root, SLUG, event_type="pihole.query",
                     payload=pihole_payload(2, f"h{i}.example.test", n=100 + i),
                     received_at=ago(days=30, minutes=i))
    for i in range(n_new):
        insert_event(root, SLUG, event_type="pihole.query",
                     payload=pihole_payload(3, f"n{i}.example.test", n=200 + i),
                     received_at=ago(hours=2, minutes=i))


def test_script_dry_run_counts_the_prune_and_refuses_without_an_archive(root, capsys, monkeypatch):
    import scripts.move_telemetry_out_of_events as script

    _freeze_retention_clock(monkeypatch)
    _old_history(root)
    before = file_digests(root)
    assert script.main(["--data-root", str(root), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "would move 5" in out
    assert "telemetry_raw would prune WITHOUT a copy (archive disabled): 3" in out
    assert file_digests(root) == before
    # The real run refuses to delete history without a copy unless told to.
    assert script.main(["--data-root", str(root)]) == 2
    assert "DELETED WITHOUT A COPY" in capsys.readouterr().err
    assert file_digests(root) == before
    assert script.main(["--data-root", str(root), "--prune-without-archive", "--json"]) == 0
    out = capsys.readouterr().out
    assert "telemetry_raw pruned WITHOUT a copy (archive disabled): 3" in out
    report = json.loads(out[out.index("\n{") + 1:])
    assert report["move"][0]["moved"] == 5
    [t] = report["retention"]["tenants"]
    assert t["classes"]["telemetry_raw"]["deleted"] == 3
    assert rows(db(root, SLUG, "telemetry"), "SELECT COUNT(*) FROM telemetry_raw") == [(2,)]


def test_script_with_the_archive_archives_what_it_prunes(root, capsys, tmp_path, monkeypatch):
    import scripts.move_telemetry_out_of_events as script
    from apps.octo.retention.archive import ColdArchive

    target = tmp_path / "archive"
    target.mkdir()
    monkeypatch.setenv("OCTO_ARCHIVE_ROOT", str(target))
    _freeze_retention_clock(monkeypatch)
    _old_history(root)
    assert script.main(["--data-root", str(root), "--dry-run"]) == 0
    assert "telemetry_raw would archive, then prune: 3" in capsys.readouterr().out
    assert script.main(["--data-root", str(root)]) == 0
    assert "telemetry_raw archived + pruned: 3" in capsys.readouterr().out
    day = ago(days=30)[:10]
    archived = ColdArchive(target).read_day(SLUG, day)
    assert len(archived) == 3 and all(r["origin_event_id"] for r in archived)


def test_script_dry_run_says_an_unusable_archive_mount(root, capsys, tmp_path, monkeypatch):
    """Step 3 of the upgrade is where a missing / mis-owned array mount first
    shows: the dry run names it UNUSABLE with the reason, never "enabled"."""
    import scripts.move_telemetry_out_of_events as script

    monkeypatch.setenv("OCTO_ARCHIVE_ROOT", str(tmp_path / "not-mounted"))
    _old_history(root)
    assert script.main(["--data-root", str(root), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "UNUSABLE: archive root" in out and "does not exist (mount missing?)" in out
    assert "archive: enabled" not in out
    assert "telemetry_raw would prune nothing (archive unusable)" in out


def test_script_move_only_takes_the_run_lock(root, capsys):
    import scripts.move_telemetry_out_of_events as script
    from apps.octo.retention import job as job_module

    _old_history(root)
    held = job_module._Lock(root / job_module.LOCK_NAME)
    assert held.acquire()
    try:
        assert script.main(["--data-root", str(root), "--no-prune"]) == 3
        assert script.main(["--data-root", str(root), "--prune-without-archive"]) == 3
    finally:
        held.release()
    assert len(_events(root)) == 5              # nothing moved while the lock was held


# ---------------------------------------------------------------------------
# Disk: the preview's estimate and the real run's free-space check (T2)
# ---------------------------------------------------------------------------

def test_disk_estimate_uses_the_measured_row_sizes():
    from apps.octo.retention import move as move_module

    assert (move_module.RAW_ROW_BYTES, move_module.HOURLY_ROW_BYTES) == (716, 231)
    # Typical DNS rows (~300 B payload): the measured per-row cost wins —
    # about three times the payload.
    assert move_module.disk_estimate(1000, 300_000) == 947_000
    # Larger payloads than the measured rows: never below 3× the payload.
    assert move_module.disk_estimate(10, 50_000) == 150_000
    assert move_module.disk_estimate(0, 0) == 0


def _free(monkeypatch, value: int) -> None:
    from apps.octo.retention import move as move_module

    monkeypatch.setattr(move_module, "free_bytes", lambda _path: value)


def test_the_dry_run_prints_the_estimate_and_the_free_space(root, capsys, monkeypatch):
    import scripts.move_telemetry_out_of_events as script

    _old_history(root)
    _free(monkeypatch, 10**12)
    assert script.main(["--data-root", str(root), "--dry-run", "--no-prune"]) == 0
    out = capsys.readouterr().out
    need = 5 * (716 + 231)
    assert f"~{need / 1_000_000:.1f} MB on disk" in out
    assert "needs 2×" in out and "— enough" in out
    _free(monkeypatch, 2 * need - 1)
    assert script.main(["--data-root", str(root), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "NOT ENOUGH" in out and "the real run will REFUSE" in out


def test_the_real_run_refuses_under_twice_the_estimate(root, capsys, monkeypatch):
    import scripts.move_telemetry_out_of_events as script
    from apps.octo.retention import move as move_module

    _old_history(root)
    rows_, payload = move_module.candidate_totals(db(root, SLUG, "events"))
    assert rows_ == 5 and payload > 0
    need = move_module.disk_estimate(rows_, payload)
    before = file_digests(root)
    _free(monkeypatch, 2 * need - 1)
    assert script.main(["--data-root", str(root), "--prune-without-archive"]) == 2
    captured = capsys.readouterr()
    assert "refused: not enough free disk" in captured.err
    assert "NOT ENOUGH" in captured.out
    assert file_digests(root) == before                    # nothing moved
    assert script.main(["--data-root", str(root), "--no-prune"]) == 2
    assert file_digests(root) == before
    # Exactly twice the estimate is enough …
    _free(monkeypatch, 2 * need)
    assert script.main(["--data-root", str(root), "--no-prune"]) == 0
    assert "— enough" in capsys.readouterr().out
    assert len(_events(root)) == 0


def test_ignore_free_space_proceeds(root, capsys, monkeypatch):
    import scripts.move_telemetry_out_of_events as script

    _old_history(root)
    _free(monkeypatch, 0)
    assert script.main(["--data-root", str(root), "--no-prune", "--ignore-free-space"]) == 0
    assert "NOT ENOUGH" in capsys.readouterr().out
    assert len(_events(root)) == 0
