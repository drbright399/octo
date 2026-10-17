"""The retention job and the telemetry move build every tenant path through
the path layer's containment check (`paths.client_dir` / `client_db_path` /
`resolve_inside`, spec §2.3) — never by hand from a slug.

Pins:
  * a tenant directory that is a symlink (to another tenant's directory,
    or out of the data root) is that tenant's error: nothing is read,
    swept or pruned through it — the other tenant's rows stay;
  * a tenant store file (events.db / telemetry.db) that is a symlink is
    refused the same way;
  * the scheduled run's clock check skips a refused tenant instead of
    crashing the run;
  * `move_tenant` refuses a traversal slug, a symlinked tenant directory
    and a symlinked events.db before opening anything;
  * valid tenants: unchanged (their own runs prune and move as always).
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from apps.octo import paths
from apps.octo.retention.job import RetentionJob
from apps.octo.retention.move import move_tenant
from apps.octo.tests._tiering_fixtures import (
    NOW, ago, db, insert_event, make_root, pihole_payload, rows, write_telemetry,
)

A, B = "acme-corp", "globex"
EVIL = "evil-corp"


@pytest.fixture
def root(tmp_path, monkeypatch):
    return make_root(tmp_path, monkeypatch, tenants=(A, B))


def _job(root, **kw) -> RetentionJob:
    kw.setdefault("archive_from_env", False)
    return RetentionJob(data_root=root, now=lambda: NOW, **kw)


def _old_signal(root, slug, n=0, days=400) -> int:
    return insert_event(root, slug, event_type="wazuh.alert", payload={"n": n},
                        received_at=ago(days=days), severity="high")


def _ids(root, slug, name, table) -> set:
    return {r[0] for r in rows(db(root, slug, name), f"SELECT id FROM {table}")}


def _replace_with_symlink(path, target) -> None:
    for side in ("", "-wal", "-shm"):
        p = path.with_name(path.name + side)
        if p.exists() or p.is_symlink():
            p.unlink()
    path.symlink_to(target)


# ---------------------------------------------------------------------------
# The retention job
# ---------------------------------------------------------------------------

def test_a_symlinked_tenant_directory_is_refused_and_nothing_pruned_through_it(root):
    old = _old_signal(root, B)
    (root / "clients" / EVIL).symlink_to(root / "clients" / B)
    report = _job(root).run(trigger="script", slugs=[EVIL])
    [t] = report.tenants
    assert t.slug == EVIL
    assert t.error and "SlugError" in t.error and "symlink" in t.error
    assert t.classes == {}                            # not even planned
    assert report.status == "partial"
    assert old in _ids(root, B, "events", "events")   # B's row is still there
    # B's own run: unchanged.
    report = _job(root).run(trigger="script", slugs=[B])
    [t] = report.tenants
    assert t.error is None and t.classes["events"].deleted == 1
    assert old not in _ids(root, B, "events", "events")


def test_a_tenant_directory_symlinked_out_of_the_root_is_refused(root, tmp_path):
    outside = tmp_path / "outside-tenant"
    outside.mkdir()
    (root / "clients" / EVIL).symlink_to(outside)
    report = _job(root).run(trigger="script", dry_run=True)
    by = {t.slug: t for t in report.tenants}
    assert set(by) == {A, B, EVIL}
    assert by[EVIL].error and "SlugError" in by[EVIL].error and "escapes" in by[EVIL].error
    assert by[A].error is None and by[B].error is None
    assert list(outside.iterdir()) == []              # nothing created out there


def test_a_symlinked_events_db_is_refused(root):
    old = _old_signal(root, B)
    _replace_with_symlink(db(root, A, "events"), db(root, B, "events"))
    report = _job(root).run(trigger="script", slugs=[A])
    [t] = report.tenants
    assert t.error and "symlink" in t.error
    assert old in _ids(root, B, "events", "events")


def test_a_symlinked_telemetry_db_is_refused(root):
    kept = write_telemetry(root, B, received_at=ago(days=400))
    _replace_with_symlink(db(root, A, "telemetry"), db(root, B, "telemetry"))
    report = _job(root).run(trigger="script", slugs=[A])
    [t] = report.tenants
    # The tenant's error (refused before anything is deleted), not merely a
    # class's: nothing of A is pruned while its telemetry.db points elsewhere.
    assert t.error and "SlugError" in t.error
    assert report.status == "partial"
    assert all(c.deleted == 0 for c in t.classes.values())
    assert kept in _ids(root, B, "telemetry", "telemetry_raw")


def test_the_clock_check_skips_a_refused_tenant(root):
    insert_event(root, A, event_type="wazuh.alert", payload={"n": 1},
                 received_at=ago(hours=1), severity="high")
    (root / "clients" / EVIL).symlink_to(root / "clients" / B)
    job = _job(root)
    assert job._newest_arrival([A, EVIL, "../" + B]) == job._newest_arrival([A])
    report = job.run(trigger="scheduler")
    by = {t.slug: t for t in report.tenants}
    assert by[EVIL].error and "symlink" in by[EVIL].error
    assert by[A].error is None and by[B].error is None
    assert report.status == "partial"


def test_valid_tenants_resolve_to_the_same_paths(root):
    real = os.path.realpath(root)
    for slug in (A, B):
        assert paths.client_dir(slug, root=root) == Path(real) / "clients" / slug


# ---------------------------------------------------------------------------
# move_tenant
# ---------------------------------------------------------------------------

def _dns_row(root, slug) -> int:
    return insert_event(root, slug, event_type="pihole.query",
                        payload=pihole_payload(2, "a.example.test", n=1),
                        received_at=ago(days=2))


@pytest.mark.parametrize("slug", ["../" + B, f"{A}/../{B}", "..", "", f"{B}\n", "/etc"])
def test_move_refuses_a_traversal_slug(root, slug):
    with pytest.raises(paths.SlugError):
        move_tenant(slug, data_root=root, dry_run=True)


def test_move_refuses_a_symlinked_tenant_directory(root):
    row = _dns_row(root, B)
    (root / "clients" / EVIL).symlink_to(root / "clients" / B)
    for dry_run in (True, False):
        with pytest.raises(paths.SlugError):
            move_tenant(EVIL, data_root=root, dry_run=dry_run)
    assert row in _ids(root, B, "events", "events")
    assert rows(db(root, B, "telemetry"),
                "SELECT COUNT(*) FROM telemetry_raw WHERE origin_event_id = ?", (row,)) == [(0,)]


def test_move_refuses_a_symlinked_events_db(root):
    row = _dns_row(root, B)
    _replace_with_symlink(db(root, A, "events"), db(root, B, "events"))
    with pytest.raises(paths.SlugError):
        move_tenant(A, data_root=root, dry_run=False)
    assert row in _ids(root, B, "events", "events")


def test_move_for_a_valid_tenant_is_unchanged(root):
    row = _dns_row(root, A)
    report = move_tenant(A, data_root=root, dry_run=False)
    assert report.error is None and report.moved == 1
    assert row not in _ids(root, A, "events", "events")
    assert rows(db(root, A, "telemetry"),
                "SELECT COUNT(*) FROM telemetry_raw WHERE origin_event_id = ?", (row,)) == [(1,)]


def test_move_of_a_tenant_without_events_db_reports_nothing(root):
    report = move_tenant("never-provisioned", data_root=root, dry_run=True)
    assert report.scanned == 0 and report.error is None
    assert not (root / "clients" / "never-provisioned").exists()


def test_sqlite_is_never_opened_through_a_refused_path(root, monkeypatch):
    (root / "clients" / EVIL).symlink_to(root / "clients" / B)
    opened = []
    real = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **kw: opened.append(a) or real(*a, **kw))
    with pytest.raises(paths.SlugError):
        move_tenant(EVIL, data_root=root, dry_run=True)
    assert opened == []
