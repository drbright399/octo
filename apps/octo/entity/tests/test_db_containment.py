"""`TenantDB` builds its path through the path layer's one containment check
(`paths.client_db_path` → `paths.resolve_inside`, spec §2.3) — never by
hand from the slug — and its own guard still holds on every connection.

Pins:
  * a valid tenant resolves to exactly `<data_root>/clients/<slug>/entities.db`,
    and write / connect / read behave as before;
  * a traversal or otherwise invalid slug is refused before any path exists;
  * a symlinked tenant directory or entities.db (pointing at another
    tenant, outside the root, dangling, looping) is refused at
    `for_tenant` — EntityPathError, as before;
  * a symlink swapped in AFTER `for_tenant` is refused by write / connect /
    read (the per-connection guard), and nothing is created through it;
  * `guard` refuses another tenant's file, a symlinked hop and a wrong name.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from apps.octo import paths
from apps.octo.entity import db as entity_db
from apps.octo.entity.db import EntityPathError, TenantDB

A, B = "acme-corp", "example-bakery"


@pytest.fixture
def root(tmp_path, monkeypatch) -> Path:
    r = tmp_path / "octo-data"
    for slug in (A, B):
        (r / "clients" / slug).mkdir(parents=True)
    monkeypatch.setenv("OCTO_DATA_ROOT", str(r))
    entity_db.reset_schema_cache()
    yield r
    entity_db.reset_schema_cache()


def _real_root(root: Path) -> Path:
    return Path(os.path.realpath(root))


# ---------------------------------------------------------------------------
# Valid tenants: unchanged
# ---------------------------------------------------------------------------

def test_valid_tenant_path_is_the_contained_one(root):
    tdb = TenantDB.for_tenant(A)
    assert tdb.slug == A
    assert tdb.path == _real_root(root) / "clients" / A / "entities.db"
    assert tdb.path == paths.client_db_path(A, "entities")
    assert not tdb.exists()                         # nothing created by building it


def test_valid_tenant_write_connect_read_round_trip(root):
    tdb = TenantDB.for_tenant(A)
    with tdb.read() as conn:
        assert conn is None                         # no file yet: never created by a read
    assert not tdb.exists()
    with tdb.write() as conn:
        conn.execute("INSERT INTO site (site_id, label, anchor, created_at, created_by, "
                     "updated_at) VALUES ('st_1', 'Site', 'unifi', 'x', 'x', 'x')")
    assert tdb.exists()
    with tdb.connect() as conn:
        assert conn.execute("SELECT label FROM site").fetchone()[0] == "Site"
    with TenantDB.for_tenant(A).read() as conn:
        assert conn is not None
        assert conn.execute("SELECT COUNT(*) FROM site").fetchone()[0] == 1
    # B's file is untouched.
    assert not (root / "clients" / B / "entities.db").exists()


def test_a_tenant_never_provisioned_is_still_refused_a_file(root):
    tdb = TenantDB.for_tenant("never-provisioned")
    with pytest.raises(FileNotFoundError):
        with tdb.write():
            pass
    assert not (root / "clients" / "never-provisioned").exists()


# ---------------------------------------------------------------------------
# Traversal / invalid slugs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("slug", [
    "..", "../" + B, f"{A}/../{B}", f"{A}/..", "/etc", f"{A}\\..\\{B}",
    f"{A}\x00", f"{A}\n", "", ".", "ACME",
])
def test_traversal_and_invalid_slugs_are_refused(root, slug):
    with pytest.raises(ValueError):
        TenantDB.for_tenant(slug)


# ---------------------------------------------------------------------------
# Symlinks at construction
# ---------------------------------------------------------------------------

def test_a_symlinked_tenant_directory_is_refused(root):
    (root / "clients" / "evil-corp").symlink_to(root / "clients" / B)
    with pytest.raises(EntityPathError):
        TenantDB.for_tenant("evil-corp")


def test_a_symlinked_tenant_directory_outside_the_root_is_refused(root, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (root / "clients" / "evil-corp").symlink_to(outside)
    with pytest.raises(EntityPathError):
        TenantDB.for_tenant("evil-corp")


def test_a_symlinked_entities_db_is_refused(root):
    TenantDB.for_tenant(B).ensure()
    (root / "clients" / A / "entities.db").symlink_to(root / "clients" / B / "entities.db")
    with pytest.raises(EntityPathError):
        TenantDB.for_tenant(A)


def test_a_dangling_symlinked_entities_db_is_refused(root):
    (root / "clients" / A / "entities.db").symlink_to(root / "clients" / A / "missing.db")
    with pytest.raises(EntityPathError):
        TenantDB.for_tenant(A)
    assert not (root / "clients" / A / "missing.db").exists()


def test_a_looping_symlink_is_refused(root):
    (root / "clients" / A / "entities.db").symlink_to(root / "clients" / A / "entities.db")
    with pytest.raises(EntityPathError):
        TenantDB.for_tenant(A)


# ---------------------------------------------------------------------------
# Symlinks swapped in after construction: the per-connection guard
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method", ["write", "connect", "read"])
def test_a_symlink_swapped_in_after_construction_is_refused(root, method):
    TenantDB.for_tenant(B).ensure()
    tdb = TenantDB.for_tenant(A)
    (root / "clients" / A / "entities.db").symlink_to(root / "clients" / B / "entities.db")
    with pytest.raises(EntityPathError):
        with getattr(tdb, method)():
            pass


@pytest.mark.parametrize("method", ["write", "connect", "read"])
def test_a_tenant_directory_swapped_for_a_symlink_is_refused(root, tmp_path, method):
    tdb = TenantDB.for_tenant(A)
    os.rmdir(root / "clients" / A)
    (root / "clients" / A).symlink_to(root / "clients" / B)
    with pytest.raises(EntityPathError):
        with getattr(tdb, method)():
            pass
    assert not (root / "clients" / B / "entities.db").exists()   # nothing created through it


# ---------------------------------------------------------------------------
# guard()
# ---------------------------------------------------------------------------

def test_guard_accepts_only_this_tenants_file(root):
    TenantDB.guard(A, _real_root(root) / "clients" / A / "entities.db")
    with pytest.raises(EntityPathError):
        TenantDB.guard(A, root / "clients" / B / "entities.db")
    with pytest.raises(EntityPathError):
        TenantDB.guard(A, root / "clients" / A / "events.db")
    with pytest.raises(EntityPathError):
        TenantDB.guard(A, root / "clients" / A / ".." / B / "entities.db")


def test_guard_refuses_a_path_through_a_symlink(root):
    evil = root / "clients" / A / "evil"
    evil.symlink_to(root / "clients" / B)
    with pytest.raises(EntityPathError):
        TenantDB.guard(B, evil / "entities.db")       # resolves to B's file, still refused
    with pytest.raises(EntityPathError):
        TenantDB.guard(A, evil / "entities.db")


def test_guard_refuses_an_invalid_slug(root):
    with pytest.raises(ValueError):
        TenantDB.guard("../" + B, root / "clients" / B / "entities.db")
