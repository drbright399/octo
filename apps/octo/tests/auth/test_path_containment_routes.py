"""Path containment at the HTTP edge: hostile tenant slugs and basemap file
names — URL-encoded so they reach the handler decoded — and symlinks planted
in the data tree never make a route touch a file outside the tenant's own
directory (spec §2.3, `paths.resolve_inside`).

Status mapping: a tile name the containment helper refuses is a 404 like a
missing file (the tiles route maps SlugError itself). A slug the path layer
refuses on a wildcard caller's tenant route, or a tenant directory that is a
symlink, reaches the app-wide SlugError handler (apps/octo/api/errors.py): a
404 with the API's NOT_FOUND body, never a 500, never naming the refused
value or a server path, and nothing is created or read first.
"""
from __future__ import annotations

import logging
from urllib.parse import unquote

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.agent import notes as agent_notes
from apps.octo.api import errors
from apps.octo.tests.auth.test_search_events import (
    _apply_events_db_migration,
    _elevate,
    _first_event_id,
    _insert_event,
    _login,
    _register_client,
)


def _super_admin(auth_client) -> dict:
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!", role="admin", athena_role="super_admin",
        scope_slugs=["*"],
    )
    _login(auth_client, op)
    return op


def _viewer(auth_client) -> dict:
    op = auth_client.provision_operator(
        "bob", "Hunter22!Hunter22!", role="viewer", athena_role="viewer",
        scope_slugs=["*"],
    )
    _login(auth_client, op)
    return op


def _tenant_with_note(slug: str, text: str) -> None:
    _register_client(slug)
    client_provisioning.provision_client_dbs(slug)
    agent_notes.insert_agent_note(
        slug, ref_kind="event", ref_id=1, agent_id="octo", note_text=text,
        confidence=0.5, request_id=f"req-{slug}",
    )


def _assert_slug_refused_as_not_found(r, *, data_root, raw: str = "") -> None:
    """The SlugError answer: 404 with exactly the body APIError("NOT_FOUND")
    gives, its fixed message, and neither the refused (decoded) value nor
    the data-root path anywhere in the response."""
    assert r.status_code == 404, r.text
    body = r.json()
    assert set(body) == {"code", "message", "request_id"}
    assert body["code"] == "NOT_FOUND"
    assert body["message"] == errors.ERROR_CODES["NOT_FOUND"][1]
    if raw:
        assert unquote(raw) not in r.text
    assert str(data_root) not in r.text
    assert "symlink" not in r.text and "escapes" not in r.text


def _tenant_tree(root) -> set[str]:
    """Every name under the tenant tree (the registry / audit DBs beside it
    change on every authenticated request — sessions, WAL files)."""
    clients = root / "clients"
    return {str(p.relative_to(clients)) for p in clients.rglob("*")}


# ---------------------------------------------------------------------------
# /api/v1/tiles/{filename}
# ---------------------------------------------------------------------------

def test_tiles_valid_name_still_served(auth_client, auth_data_root):
    _viewer(auth_client)
    tiles = paths.tiles_dir()
    tiles.mkdir(parents=True, exist_ok=True)
    (tiles / "us.pmtiles").write_bytes(b"tile-bytes")
    r = auth_client.get("/api/v1/tiles/us.pmtiles")
    assert r.status_code == 200
    assert r.content == b"tile-bytes"


def test_tiles_symlinked_file_is_404_inside_or_outside(auth_client, auth_data_root, tmp_path):
    _viewer(auth_client)
    tiles = paths.tiles_dir()
    tiles.mkdir(parents=True, exist_ok=True)
    (tiles / "real.pmtiles").write_bytes(b"real")
    secret = tmp_path / "secret.bin"
    secret.write_bytes(b"secret-bytes")
    (tiles / "out.pmtiles").symlink_to(secret)
    (tiles / "in.pmtiles").symlink_to(tiles / "real.pmtiles")
    for name in ("out.pmtiles", "in.pmtiles"):
        r = auth_client.get(f"/api/v1/tiles/{name}")
        assert r.status_code == 404, name
        assert r.json()["code"] == "NOT_FOUND"
        assert b"secret-bytes" not in r.content


def test_tiles_missing_dir_and_directory_named_like_a_tile_are_404(auth_client, auth_data_root):
    _viewer(auth_client)
    assert not paths.tiles_dir().exists()
    r = auth_client.get("/api/v1/tiles/us.pmtiles")
    assert r.status_code == 404 and r.json()["code"] == "NOT_FOUND"
    (paths.tiles_dir() / "dir.pmtiles").mkdir(parents=True)
    r = auth_client.get("/api/v1/tiles/dir.pmtiles")
    assert r.status_code == 404 and r.json()["code"] == "NOT_FOUND"


@pytest.mark.parametrize("raw", [
    "..%2Fregistry.db",            # decoded '/' → no route matches
    "%2e%2e%2Fregistry.db",
    "..%2F..%2Fsecret.pmtiles",
    "%2Fetc%2Fpasswd",
    "%2Fetc.pmtiles",
])
def test_tiles_url_encoded_separator_never_serves_a_file(auth_client, auth_data_root, raw):
    _viewer(auth_client)
    r = auth_client.get(f"/api/v1/tiles/{raw}")
    assert r.status_code in (404, 422), r.text
    assert b"SQLite format" not in r.content


@pytest.mark.parametrize("raw", [
    "%2e%2e",                      # '..'
    "..pmtiles",
    "..%5Cregistry.pmtiles",       # backslash
    "us%00.pmtiles",               # NUL
    "us.pmtiles%0A",               # trailing newline: `$` alone let it through
])
def test_tiles_url_encoded_hostile_name_reaching_the_handler_is_refused(
    auth_client, auth_data_root, raw,
):
    _viewer(auth_client)
    tiles = paths.tiles_dir()
    tiles.mkdir(parents=True, exist_ok=True)
    (tiles / "us.pmtiles").write_bytes(b"tile-bytes")
    r = auth_client.get(f"/api/v1/tiles/{raw}")
    assert r.status_code in (404, 422), r.text
    assert r.content != b"tile-bytes"


# ---------------------------------------------------------------------------
# A tenant route: /api/v1/agent-notes/{client_slug}/{ref_kind}/{ref_id}
# ---------------------------------------------------------------------------

def test_agent_notes_valid_slug_still_works(auth_client, auth_data_root):
    _super_admin(auth_client)
    _tenant_with_note("acme-corp", "acme's own note")
    r = auth_client.get("/api/v1/agent-notes/acme-corp/event/1")
    assert r.status_code == 200, r.text
    assert [n["note_text"] for n in r.json()["notes"]] == ["acme's own note"]


@pytest.mark.parametrize("raw", ["%2e%2e", "%2E%2E", "%2E", "acme-corp%0A", "acme%5C..%5Cx",
                                 "%00"])
def test_agent_notes_url_encoded_traversal_reaches_handler_and_is_refused(
    auth_client, auth_data_root, raw,
):
    _super_admin(auth_client)
    _tenant_with_note("acme-corp", "acme's own note")
    before = _tenant_tree(auth_data_root)
    r = auth_client.get(f"/api/v1/agent-notes/{raw}/event/1")
    _assert_slug_refused_as_not_found(r, data_root=auth_data_root, raw=raw)
    assert "acme's own note" not in r.text
    assert _tenant_tree(auth_data_root) == before


def test_agent_notes_symlinked_tenant_dir_is_refused(auth_client, auth_data_root):
    """'globex' → acme-corp's directory: before the containment check ran on
    every client path, globex's notes route read acme-corp's events.db. Now
    it fails closed: the path layer refuses the symlink (asserted directly,
    so the 404 below is that refusal and not some other miss)."""
    _super_admin(auth_client)
    _tenant_with_note("acme-corp", "acme's own note")
    _register_client("globex")
    (auth_data_root / "clients" / "globex").symlink_to(
        auth_data_root / "clients" / "acme-corp", target_is_directory=True,
    )
    # "symlink refused", not "symlink": the tmp path in the message already
    # contains the test's own name.
    with pytest.raises(paths.SlugError, match="symlink refused"):
        paths.client_dir("globex")
    r = auth_client.get("/api/v1/agent-notes/globex/event/1")
    _assert_slug_refused_as_not_found(r, data_root=auth_data_root)
    assert "acme's own note" not in r.text


def test_a_refusal_is_logged_by_route_template_with_the_value_escaped(
    auth_client, auth_data_root, caplog,
):
    _super_admin(auth_client)
    _tenant_with_note("acme-corp", "acme's own note")
    with caplog.at_level(logging.WARNING, logger=errors.logger.name):
        r = auth_client.get("/api/v1/agent-notes/acme-corp%0Ainjected/event/1")
    _assert_slug_refused_as_not_found(r, data_root=auth_data_root)
    [rec] = [x for x in caplog.records if x.name == errors.logger.name]
    line = rec.getMessage()
    # The route template, never the raw (caller-supplied) URL ...
    assert "/api/v1/agent-notes/{client_slug}/{ref_kind}/{ref_id}" in line
    assert "%0A" not in line
    # ... and the refused value only repr()-escaped: no raw newline can
    # forge a second log line. The response never names it at all.
    assert "\n" not in line
    assert "acme-corp\\ninjected" in line
    assert "injected" not in r.text


# ---------------------------------------------------------------------------
# A step-up tenant route: GET /api/v1/search/event/{client_slug}/{event_id}
# ---------------------------------------------------------------------------

def _elevated_super_admin(auth_client) -> dict:
    op = _super_admin(auth_client)
    _elevate(auth_client, op)
    return op


def _tenant_with_event(root, slug: str, summary: str) -> int:
    _register_client(slug)
    cdir = root / "clients" / slug
    _apply_events_db_migration(cdir)
    _insert_event(cdir, "2026-01-01T00:00:00.000Z", summary=summary)
    return _first_event_id(cdir)


def test_search_event_valid_slug_still_works(auth_client, auth_data_root):
    _elevated_super_admin(auth_client)
    eid = _tenant_with_event(auth_data_root, "acme-corp", "acme's own event")
    r = auth_client.get(f"/api/v1/search/event/acme-corp/{eid}")
    assert r.status_code == 200, r.text
    assert r.json()["client_slug"] == "acme-corp"


@pytest.mark.parametrize("raw", ["%2e%2e", "%2E%2E", "acme-corp%0A", "acme%5C..%5Cx", "%00",
                                 "Acme-Corp"])
def test_search_event_malformed_tenant_is_404(auth_client, auth_data_root, raw):
    _elevated_super_admin(auth_client)
    eid = _tenant_with_event(auth_data_root, "acme-corp", "acme's own event")
    before = _tenant_tree(auth_data_root)
    r = auth_client.get(f"/api/v1/search/event/{raw}/{eid}")
    _assert_slug_refused_as_not_found(r, data_root=auth_data_root, raw=raw)
    assert "acme's own event" not in r.text
    assert _tenant_tree(auth_data_root) == before


def test_search_event_symlinked_tenant_dir_is_404(auth_client, auth_data_root):
    _elevated_super_admin(auth_client)
    eid = _tenant_with_event(auth_data_root, "acme-corp", "acme's own event")
    _register_client("globex")
    (auth_data_root / "clients" / "globex").symlink_to(
        auth_data_root / "clients" / "acme-corp", target_is_directory=True,
    )
    with pytest.raises(paths.SlugError, match="symlink refused"):
        paths.client_db_path("globex", "events")
    r = auth_client.get(f"/api/v1/search/event/globex/{eid}")
    _assert_slug_refused_as_not_found(r, data_root=auth_data_root)
    assert "acme's own event" not in r.text


# ---------------------------------------------------------------------------
# A tenant route that CREATES files: POST /api/v1/tickets/{slug}
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["%2e%2e", "%2E%2E", "acme-corp%0A", "%5Cetc"])
def test_ticket_create_url_encoded_traversal_creates_nothing(auth_client, auth_data_root, raw):
    _super_admin(auth_client)
    before = _tenant_tree(auth_data_root)
    r = auth_client.post(f"/api/v1/tickets/{raw}", json={"title": "probe"})
    _assert_slug_refused_as_not_found(r, data_root=auth_data_root, raw=raw)
    assert _tenant_tree(auth_data_root) == before
    assert not (auth_data_root / "tickets.db").exists()     # clients/../tickets.db


def test_ticket_create_into_symlinked_tenant_dir_is_refused(auth_client, auth_data_root, tmp_path):
    _super_admin(auth_client)
    outside = tmp_path / "outside"
    outside.mkdir()
    _register_client("initech")
    (auth_data_root / "clients" / "initech").symlink_to(outside, target_is_directory=True)
    with pytest.raises(paths.SlugError, match="escapes its root"):
        paths.client_dir("initech")
    r = auth_client.post("/api/v1/tickets/initech", json={"title": "probe"})
    _assert_slug_refused_as_not_found(r, data_root=auth_data_root)
    assert str(outside) not in r.text
    assert list(outside.iterdir()) == []


def test_ticket_create_into_tenant_dir_symlinked_inside_the_root_is_refused(
    auth_client, auth_data_root,
):
    """A symlink whose target is ANOTHER tenant inside the root: contained,
    but refused all the same (it would write into acme-corp's tickets)."""
    _super_admin(auth_client)
    _register_client("acme-corp")
    client_provisioning.provision_client_dbs("acme-corp")
    _register_client("globex")
    (auth_data_root / "clients" / "globex").symlink_to(
        auth_data_root / "clients" / "acme-corp", target_is_directory=True,
    )
    before = _tenant_tree(auth_data_root)
    r = auth_client.post("/api/v1/tickets/globex", json={"title": "probe"})
    _assert_slug_refused_as_not_found(r, data_root=auth_data_root)
    assert _tenant_tree(auth_data_root) == before
