"""Client provisioning — create_client registers the row + provisions DBs."""
from __future__ import annotations

import sqlite3

import pytest

from apps.octo import client_provisioning, paths


def _setup(tmp_path, monkeypatch):
    reg = tmp_path / "registry.db"
    conn = sqlite3.connect(reg)
    conn.execute(
        "CREATE TABLE clients (slug TEXT PRIMARY KEY, display_name TEXT NOT NULL, "
        "status TEXT NOT NULL DEFAULT 'active')"
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(paths, "registry_db_path", lambda: reg)
    monkeypatch.setattr(paths, "client_dir", lambda slug: tmp_path / "clients" / slug)
    return reg


def test_create_client_provisions_dbs(tmp_path, monkeypatch):
    reg = _setup(tmp_path, monkeypatch)
    client_provisioning.create_client("acme-corp", "Acme Corp")

    row = sqlite3.connect(reg).execute(
        "SELECT display_name FROM clients WHERE slug = 'acme-corp'"
    ).fetchone()
    assert row and row[0] == "Acme Corp"

    cdir = tmp_path / "clients" / "acme-corp"
    assert (cdir / "events.db").exists()
    assert (cdir / "indicators.db").exists()
    tables = {
        r[0]
        for r in sqlite3.connect(cdir / "events.db").execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert "events" in tables, tables


def test_create_client_rejects_duplicate(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    client_provisioning.create_client("acme-corp", "Acme")
    with pytest.raises(client_provisioning.ClientExistsError):
        client_provisioning.create_client("acme-corp", "Acme Again")


def test_create_client_rejects_bad_slug(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    for bad in ("Acme Corp", "acme_corp", "-acme", "acme-", "acme--corp", ""):
        with pytest.raises(client_provisioning.InvalidClientError):
            client_provisioning.create_client(bad, "X")


def _setup_lifecycle(tmp_path, monkeypatch):
    """A registry with the migration-033 lifecycle columns."""
    reg = tmp_path / "registry.db"
    conn = sqlite3.connect(reg)
    conn.execute(
        "CREATE TABLE clients (slug TEXT PRIMARY KEY, display_name TEXT NOT NULL, "
        "status TEXT NOT NULL DEFAULT 'active', compliance_flags TEXT NOT NULL DEFAULT '[]', "
        "origin TEXT NOT NULL DEFAULT 'manual', kind TEXT NOT NULL DEFAULT 'unclassified', "
        "review_state TEXT NOT NULL DEFAULT 'confirmed', created_by_instance_id INTEGER, "
        "ai_policy TEXT NOT NULL DEFAULT 'none')"
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(paths, "registry_db_path", lambda: reg)
    monkeypatch.setattr(paths, "client_dir", lambda slug: tmp_path / "clients" / slug)
    return reg


def test_create_client_writes_lifecycle_columns(tmp_path, monkeypatch):
    reg = _setup_lifecycle(tmp_path, monkeypatch)
    client_provisioning.create_client(
        "acme-corp", "  Acme   Corp ", origin="auto", kind="unclassified",
        review_state="pending", created_by_instance_id=7, ai_policy="none",
        compliance_flags_json='["hipaa"]',
    )
    row = sqlite3.connect(reg).execute(
        "SELECT display_name, origin, kind, review_state, created_by_instance_id, "
        "ai_policy, compliance_flags FROM clients WHERE slug = 'acme-corp'"
    ).fetchone()
    assert row == ("Acme Corp", "auto", "unclassified", "pending", 7, "none", '["hipaa"]')
    assert (tmp_path / "clients" / "acme-corp" / "events.db").exists()


def test_review_state_defaults_from_kind_and_unclassified_is_never_born_confirmed(
    tmp_path, monkeypatch,
):
    """"Reviewed" means "a human said what it is": left to its default an
    unclassified client is born pending, a classified one confirmed — the
    admin API's rule — and the invalid pair is refused outright."""
    reg = _setup_lifecycle(tmp_path, monkeypatch)
    client_provisioning.create_client("vague-co", "Vague Co")
    client_provisioning.create_client("acme-corp", "Acme Corp", kind="client")
    client_provisioning.create_client("lab-box", "Lab Box", kind="dev", review_state="pending")
    rows = dict(sqlite3.connect(reg).execute("SELECT slug, review_state FROM clients"))
    assert rows == {"vague-co": "pending", "acme-corp": "confirmed", "lab-box": "pending"}
    with pytest.raises(client_provisioning.InvalidClientError):
        client_provisioning.create_client("odd-co", "Odd Co", review_state="confirmed")


@pytest.mark.parametrize("kw", [
    {"origin": "vendor"}, {"kind": "ignored"}, {"review_state": "maybe"}, {"ai_policy": "all"},
])
def test_create_client_rejects_unknown_lifecycle_values(tmp_path, monkeypatch, kw):
    _setup_lifecycle(tmp_path, monkeypatch)
    with pytest.raises(client_provisioning.InvalidClientError):
        client_provisioning.create_client("acme-corp", "Acme", **kw)


def test_create_client_rejects_unprintable_or_oversize_display_name(tmp_path, monkeypatch):
    _setup_lifecycle(tmp_path, monkeypatch)
    with pytest.raises(client_provisioning.InvalidClientError):
        client_provisioning.create_client("acme-corp", "Acme\x00Corp")
    with pytest.raises(client_provisioning.InvalidClientError):
        client_provisioning.create_client("acme-corp", "x" * 300)


def test_failed_provisioning_rolls_the_row_back(tmp_path, monkeypatch):
    reg = _setup_lifecycle(tmp_path, monkeypatch)

    def _boom(slug):
        raise OSError("disk full")

    monkeypatch.setattr(client_provisioning, "provision_client_dbs", _boom)
    with pytest.raises(OSError):
        client_provisioning.create_client("acme-corp", "Acme")
    assert sqlite3.connect(reg).execute("SELECT COUNT(*) FROM clients").fetchone()[0] == 0
