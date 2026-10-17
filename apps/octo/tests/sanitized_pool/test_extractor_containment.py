"""`run_extraction` builds each tenant's events.db / audit.db through the
path layer's containment check (`paths.client_db_path`, spec §2.3) whichever
data root is in use — never `data_root / "clients" / slug / ...` by hand.

Pins:
  * a valid tenant resolves and runs exactly as before (an explicit data
    root and the configured one alike);
  * a traversal / invalid slug, a symlinked tenant directory (another
    tenant's, or out of the root) and a symlinked events.db are that
    tenant's `error` — nothing is opened through them — and the other
    tenants still run.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from apps.octo.sanitized_pool import extractor
from apps.octo.tests.sanitized_pool.test_extractor import (
    _init_audit_db, _init_events_db, _init_patterns_db, _init_registry_db,
)

A, B = "acme-corp", "example-bakery"
EVIL = "evil-corp"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "octo-data"
    _init_registry_db(r / "registry.db", extractor_enabled=False)
    _init_patterns_db(r / "global" / "patterns.db")
    _init_audit_db(r / "global" / "audit.db")
    for slug in (A, B):
        _init_events_db(r / "clients" / slug / "events.db")
        _init_audit_db(r / "clients" / slug / "audit.db")
    return r


def _opened(monkeypatch) -> list[str]:
    seen: list[str] = []
    real = extractor.connect

    def spy(path, *a, **kw):
        seen.append(str(path))
        return real(path, *a, **kw)

    monkeypatch.setattr(extractor, "connect", spy)
    return seen


def test_valid_tenants_run_with_an_explicit_root(root, monkeypatch):
    opened = _opened(monkeypatch)
    out = extractor.run_extraction(tenant_slugs=[A, B], data_root=root)
    assert {s: out[s].status for s in out} == {A: "disabled", B: "disabled"}
    for slug in (A, B):
        assert str(root / "clients" / slug / "events.db") in opened
        assert str(root / "clients" / slug / "audit.db") in opened


def test_valid_tenants_run_with_the_configured_root(root, monkeypatch):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    out = extractor.run_extraction(tenant_slugs=[A])
    assert out[A].status == "disabled" and out[A].error is None


def test_missing_files_are_still_reported(root):
    out = extractor.run_extraction(tenant_slugs=["never-provisioned"], data_root=root)
    assert out["never-provisioned"].status == "error"
    assert "missing" in (out["never-provisioned"].error or "")


@pytest.mark.parametrize("slug", ["../" + B, f"{A}/../{B}", "..", "", f"{A}\n", "/etc", "ACME"])
@pytest.mark.parametrize("configured", [False, True])
def test_a_traversal_slug_is_that_tenants_error(root, monkeypatch, slug, configured):
    if configured:
        monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    opened = _opened(monkeypatch)
    out = extractor.run_extraction(
        tenant_slugs=[slug, A], data_root=None if configured else root,
    )
    assert out[slug].status == "error"
    assert (out[slug].error or "").startswith("tenant path refused")
    assert out[A].status == "disabled"                  # the others still run
    assert not any(B in p for p in opened)


def test_a_symlinked_tenant_directory_is_refused(root, monkeypatch):
    (root / "clients" / EVIL).symlink_to(root / "clients" / B)
    opened = _opened(monkeypatch)
    out = extractor.run_extraction(tenant_slugs=[EVIL, A], data_root=root)
    assert out[EVIL].status == "error" and "symlink" in (out[EVIL].error or "")
    assert out[A].status == "disabled"
    assert not any(B in p for p in opened)


def test_a_tenant_directory_symlinked_out_of_the_root_is_refused(root, tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    _init_events_db(outside / "events.db")
    _init_audit_db(outside / "audit.db")
    (root / "clients" / EVIL).symlink_to(outside)
    opened = _opened(monkeypatch)
    out = extractor.run_extraction(tenant_slugs=[EVIL], data_root=root)
    assert out[EVIL].status == "error" and "refused" in (out[EVIL].error or "")
    assert not any(str(outside) in p for p in opened)


def test_a_symlinked_events_db_is_refused(root, monkeypatch):
    events = root / "clients" / A / "events.db"
    events.unlink()
    events.symlink_to(root / "clients" / B / "events.db")
    opened = _opened(monkeypatch)
    out = extractor.run_extraction(tenant_slugs=[A], data_root=root)
    assert out[A].status == "error" and "symlink" in (out[A].error or "")
    assert not any(p.endswith("events.db") and "clients" in p for p in opened)
    # B's file is untouched and still B's.
    conn = sqlite3.connect(root / "clients" / B / "events.db")
    try:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    finally:
        conn.close()
