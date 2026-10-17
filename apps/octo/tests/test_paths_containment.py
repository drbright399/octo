"""The path layer's one containment check (spec §2.3) — `paths.resolve_inside`
and everything built on it: `client_dir`, `client_db_path`, `tile_path`, the
telemetry store's `db_path_for`, the ingest sink — plus `db.connect`'s URI.

Hostile names: '..' segments, '/' and '\\' separators, absolute paths, NUL
bytes, a trailing newline, symlinked tenant directories / files (inside and
outside the root, dangling, looping). Valid names keep resolving to exactly
the path they always did, whether or not it exists yet.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from shared_adapter_contract.types import CanonicalEvent

from apps.octo import client_provisioning, paths
from apps.octo.db import connect
from apps.octo.ingest import SqliteIngestSink
from apps.octo.ingest import telemetry


HOSTILE_SLUGS = [
    "..",
    ".",
    "",
    "../escape",
    "../../etc",
    "acme/../../escape",
    "acme/events",
    "acme\\..\\escape",
    "..\\escape",
    "/etc",
    "/etc/passwd",
    "acme\x00",
    "ac\x00me",
    "acme\n",
    "acme%2F..",
    "%2e%2e",
    "global",       # reserved
    "_archive",     # reserved (and not slug-shaped)
]


@pytest.fixture
def root(monkeypatch, tmp_path) -> Path:
    data = tmp_path / "octo-data"
    (data / "clients").mkdir(parents=True)
    monkeypatch.setenv("OCTO_DATA_ROOT", str(data))
    return paths.data_root()


# Which refusal fired. Not the bare word "symlink": pytest names each test's
# tmp directory after the test, so every path in a message from a
# test_symlinked_* test contains it and the match would prove nothing.
_SYMLINK = "symlink refused"
_ESCAPES = "escapes its root"


def _provision(slug: str) -> Path:
    client_provisioning.provision_client_dbs(slug)
    return paths.data_root() / "clients" / slug


# ---------------------------------------------------------------------------
# Valid names: unchanged results
# ---------------------------------------------------------------------------

def test_valid_slug_resolves_to_the_plain_path_whether_or_not_it_exists(root):
    assert paths.client_dir("acme-corp") == root / "clients" / "acme-corp"
    assert (paths.client_db_path("acme-corp", "events")
            == root / "clients" / "acme-corp" / "events.db")
    assert not (root / "clients" / "acme-corp").exists()   # nothing created
    cdir = _provision("acme-corp")
    assert paths.client_dir("acme-corp") == cdir
    for name in sorted(paths.CLIENT_DB_NAMES):
        assert paths.client_db_path("acme-corp", name) == cdir / f"{name}.db"
    assert telemetry.db_path_for("acme-corp") == cdir / "telemetry.db"
    assert telemetry.db_path_for("acme-corp", root) == cdir / "telemetry.db"


def test_valid_tile_name_resolves_under_the_tiles_dir(root):
    assert paths.tile_path("us.pmtiles") == root / "tiles" / "us.pmtiles"


def test_unknown_client_db_name_is_still_a_plain_value_error(root):
    with pytest.raises(ValueError, match="unknown client DB name"):
        paths.client_db_path("acme-corp", "../registry")


# ---------------------------------------------------------------------------
# Hostile slugs / names
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("slug", HOSTILE_SLUGS)
def test_hostile_slug_is_refused_everywhere(root, slug):
    with pytest.raises(paths.SlugError):
        paths.validate_slug(slug)
    with pytest.raises(paths.SlugError):
        paths.client_dir(slug)
    with pytest.raises(paths.SlugError):
        paths.client_db_path(slug, "events")
    with pytest.raises(paths.SlugError):
        telemetry.db_path_for(slug)
    with pytest.raises(paths.SlugError):
        telemetry.db_path_for(slug, root)


def test_slug_re_no_longer_accepts_a_trailing_newline():
    assert paths.SLUG_RE.match("acme-corp")
    assert paths.SLUG_RE.match("acme-corp\n") is None
    assert client_provisioning._SLUG_RE.match("acme-corp\n") is None


def test_the_invalid_slug_message_states_the_pattern_actually_enforced():
    # The message quotes SLUG_RE itself (\Z, not the old `$` that let a
    # trailing newline through), and the refused value only repr()-escaped.
    with pytest.raises(paths.SlugError) as exc:
        paths.validate_slug("acme-corp\n")
    message = str(exc.value)
    assert paths.SLUG_RE.pattern in message and paths.SLUG_RE.pattern.endswith("\\Z")
    assert "$" not in message
    assert "'acme-corp\\n'" in message and "\n" not in message


@pytest.mark.parametrize("segment", [
    "..", ".", "", "a/b", "../x", "a\\b", "..\\x", "/etc/passwd", "/", "a\x00b",
])
def test_resolve_inside_refuses_anything_but_one_plain_segment(root, segment):
    with pytest.raises(paths.SlugError):
        paths.resolve_inside(root, "clients", segment)
    with pytest.raises(paths.SlugError):
        paths.resolve_inside(root, segment)


@pytest.mark.parametrize("segment", [None, 3, b"acme"])
def test_resolve_inside_refuses_non_string_segments(root, segment):
    with pytest.raises(paths.SlugError):
        paths.resolve_inside(root, segment)          # type: ignore[arg-type]


def test_resolve_inside_needs_a_segment(root):
    with pytest.raises(paths.SlugError):
        paths.resolve_inside(root)


@pytest.mark.parametrize("name", [
    "../registry.db", "..", "/etc/passwd", "a/b.pmtiles", "..\\x.pmtiles",
    "x\x00.pmtiles",
])
def test_tile_path_refuses_traversal(root, name):
    with pytest.raises(paths.SlugError):
        paths.tile_path(name)


# ---------------------------------------------------------------------------
# Symlinks: refused below the root whether the target exists or not
# ---------------------------------------------------------------------------

def test_symlinked_client_dir_to_another_tenant_is_refused(root):
    acme = _provision("acme-corp")
    (root / "clients" / "globex").symlink_to(acme, target_is_directory=True)
    with pytest.raises(paths.SlugError, match=_SYMLINK):
        paths.client_dir("globex")
    # The file exists through the link — and also when it does not.
    for name in ("events", "audit"):
        with pytest.raises(paths.SlugError, match=_SYMLINK):
            paths.client_db_path("globex", name)
    with pytest.raises(paths.SlugError, match=_SYMLINK):
        telemetry.db_path_for("globex")
    # The real tenant is untouched.
    assert paths.client_dir("acme-corp") == acme


def test_symlinked_client_dir_out_of_the_root_is_refused(root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "clients" / "initech").symlink_to(outside, target_is_directory=True)
    with pytest.raises(paths.SlugError):
        paths.client_dir("initech")
    with pytest.raises(paths.SlugError):
        paths.client_db_path("initech", "events")


def test_symlinked_db_file_is_refused(root):
    acme = _provision("acme-corp")
    globex = root / "clients" / "globex"
    globex.mkdir()
    (globex / "events.db").symlink_to(acme / "events.db")
    assert paths.client_dir("globex") == globex
    with pytest.raises(paths.SlugError, match=_SYMLINK):
        paths.client_db_path("globex", "events")


def test_dangling_and_looping_symlinks_are_refused(root, tmp_path):
    (root / "clients" / "dangling").symlink_to(tmp_path / "nowhere")
    loop = root / "clients" / "loop"
    loop.symlink_to(loop)
    for slug in ("dangling", "loop"):
        with pytest.raises(paths.SlugError):
            paths.client_dir(slug)
        with pytest.raises(paths.SlugError):
            paths.client_db_path(slug, "events")


def test_symlinked_clients_dir_is_refused(root, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "acme-corp").mkdir(parents=True)
    (root / "clients").rmdir()
    (root / "clients").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(paths.SlugError, match=_ESCAPES):
        paths.client_dir("acme-corp")


def test_symlinked_tile_file_is_refused(root, tmp_path):
    tiles = root / "tiles"
    tiles.mkdir()
    (tiles / "real.pmtiles").write_bytes(b"x")
    secret = tmp_path / "secret.pmtiles"
    secret.write_bytes(b"s")
    (tiles / "out.pmtiles").symlink_to(secret)
    (tiles / "in.pmtiles").symlink_to(tiles / "real.pmtiles")
    assert paths.tile_path("real.pmtiles") == tiles / "real.pmtiles"
    for name, why in (("out.pmtiles", _ESCAPES), ("in.pmtiles", _SYMLINK)):
        with pytest.raises(paths.SlugError, match=why):
            paths.tile_path(name)


def test_a_symlink_above_the_root_is_the_operators_layout(tmp_path):
    """The root itself may sit behind a symlink (bulk storage): it is
    resolved first, and only what is below it must be symlink-free."""
    real = tmp_path / "real-root"
    (real / "clients").mkdir(parents=True)
    link = tmp_path / "link-root"
    link.symlink_to(real, target_is_directory=True)
    assert paths.resolve_inside(link, "clients", "acme-corp") == real / "clients" / "acme-corp"
    assert paths.client_dir("acme-corp", root=link) == real / "clients" / "acme-corp"


def test_a_relative_or_slash_terminated_root_names_the_same_place(tmp_path, monkeypatch):
    real = tmp_path / "data"
    (real / "clients").mkdir(parents=True)
    expected = real / "clients" / "acme-corp" / "events.db"
    monkeypatch.chdir(tmp_path)
    for root in ("data", "data/", "./data", str(real) + "/", str(real) + "//"):
        assert paths.client_db_path("acme-corp", "events", root=root) == expected, root


def test_a_sibling_sharing_the_roots_name_prefix_is_outside_it(tmp_path):
    """'<root>2' starts with '<root>' as a string: the check compares
    against '<root>/', so a link into the sibling is an escape."""
    root = tmp_path / "root"
    (root / "clients").mkdir(parents=True)
    sibling = tmp_path / "root2" / "clients" / "acme-corp"
    sibling.mkdir(parents=True)
    (root / "clients" / "acme-corp").symlink_to(sibling, target_is_directory=True)
    with pytest.raises(paths.SlugError, match=_ESCAPES):
        paths.client_dir("acme-corp", root=root)


# ---------------------------------------------------------------------------
# The ingest sink: every writer's door checks the slug itself
# ---------------------------------------------------------------------------

def _event() -> CanonicalEvent:
    return CanonicalEvent(
        vendor_event_id="evt-001",
        received_at="2026-05-11T08:00:00.000Z",
        severity="high",
        indicator="203.0.113.7",
        indicator_type="ip",
        source_host="host-1",
        summary="test alert",
        payload={"rule": {"id": "5503"}},
        payload_sha256="a" * 64,
    )


def test_sink_refuses_a_traversal_slug_even_when_the_target_db_exists(root):
    """Before the sink went through the path layer, 'clients/../../escape'
    named an existing events.db outside the tenant tree and the event was
    written there."""
    _provision("acme-corp")
    escape = root.parent / "escape"
    escape.mkdir()
    client_provisioning._provision_db(escape / "events.db", "events")
    sink = SqliteIngestSink(data_root=root, publish_to_stream=False)
    for slug in ("../../escape", "../escape", str(escape)):
        with pytest.raises(FileNotFoundError):
            sink.ingest(slug, "wazuh", _event())
    conn = sqlite3.connect(escape / "events.db")
    try:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    finally:
        conn.close()
    # A valid tenant still ingests.
    assert sink.ingest("acme-corp", "wazuh", _event()).event_id >= 1


def test_sink_refuses_a_symlinked_tenant_dir(root):
    acme = _provision("acme-corp")
    (root / "clients" / "globex").symlink_to(acme, target_is_directory=True)
    sink = SqliteIngestSink(data_root=root, publish_to_stream=False)
    with pytest.raises(paths.SlugError, match=_SYMLINK):
        sink.ingest("globex", "wazuh", _event())
    conn = sqlite3.connect(acme / "events.db")
    try:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# db.connect: the path is data, never URI syntax
# ---------------------------------------------------------------------------

def test_connect_read_only_cannot_be_overridden_by_the_path(tmp_path):
    weird = tmp_path / "x?mode=rwc#.db"
    plain = sqlite3.connect(weird)          # not a URI: a file with that name
    plain.execute("CREATE TABLE t (a)")
    plain.execute("INSERT INTO t VALUES (1)")
    plain.commit()
    plain.close()
    conn = connect(weird, read_only=True)
    try:
        assert conn.execute("SELECT a FROM t").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO t VALUES (2)")
    finally:
        conn.close()
    assert sorted(os.listdir(tmp_path)) == ["x?mode=rwc#.db"]


def test_connect_round_trips_percent_and_space(tmp_path):
    p = tmp_path / "a b%41.db"
    conn = connect(p)
    conn.execute("CREATE TABLE t (a)")
    conn.close()
    assert sorted(os.listdir(tmp_path)) == ["a b%41.db"]


@pytest.mark.parametrize("name", ["plain.db", "a b.db", "ü-ñ.db", "x#y.db", "c:d.db"])
def test_connect_opens_exactly_the_named_file(tmp_path, name):
    """Names the old raw URI already handled (space, non-ASCII) still open
    the same file; '#' no longer cuts the name short."""
    folder = tmp_path / "dir with space" / "ü"
    folder.mkdir(parents=True)
    conn = connect(folder / name)
    conn.execute("CREATE TABLE t (a)")
    conn.close()
    assert os.listdir(folder) == [name]
    ro = connect(folder / name, read_only=True)
    try:
        assert ro.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0
    finally:
        ro.close()
