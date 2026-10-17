"""Tier Black slice 1 — shared fixtures: a REAL data root (registry at 044,
tenant event stores), fictional tenants (Acme / Example), operators with
roles and scopes (alice, bob, …), and a FAKE mailer: no e-mail ever leaves a
test (`notify.MAILER_FACTORY`)."""
from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import pytest

from apps.octo import paths
from apps.octo.db import connect, transaction

A, B = "acme-corp", "example-bakery"


@dataclass
class FakeMailer:
    sent: list[tuple[str, str, str]] = field(default_factory=list)
    configured: bool = True

    def factory(self):
        if not self.configured:
            return None

        def _send(to: str, subject: str, body: str) -> bool:
            self.sent.append((to, subject, body))
            return True

        return _send


@pytest.fixture
def mailer(monkeypatch) -> FakeMailer:
    from apps.octo.threat import notify

    fake = FakeMailer()
    monkeypatch.setattr(notify, "MAILER_FACTORY", fake.factory)
    return fake


@pytest.fixture
def troot(monkeypatch, tmp_path, mailer):
    """A data root at the current schema, two client tenants, no workers."""
    from cryptography.fernet import Fernet

    from apps.octo.auth import bootstrap
    from apps.octo.client_provisioning import create_client
    from apps.octo.fleet import build, sources
    from apps.octo.threat import store

    root = tmp_path / "octo-data"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    pepper = secrets / "pepper.env"
    pepper.write_text("PEPPER_VERSION=pepper_v1\nPEPPER_HEX=" + "ab" * 32 + "\n")
    os.chmod(pepper, 0o400)
    monkeypatch.setenv("OCTO_PEPPER_PATH", str(pepper))
    mfa = secrets / "mfa-key.env"
    mfa.write_text(f"MFA_KEY_VERSION=v1\nMFA_KEY_BASE64={Fernet.generate_key().decode()}\n")
    os.chmod(mfa, 0o400)
    monkeypatch.setenv("OCTO_MFA_KEY_PATH", str(mfa))
    monkeypatch.setenv("OCTO_ADAPTER_CREDENTIALS_KEY_PATH", str(secrets / "cred-key.env"))
    monkeypatch.setenv(build.CACHE_ENV, "0")
    from apps.octo.credentials import ensure_key_file

    ensure_key_file()
    bootstrap.init_data_root()
    store.reset_schema_cache()
    sources.reset_incident_cache()
    build.invalidate()
    create_client(A, "Acme Corp", kind="client")
    create_client(B, "Example Bakery", kind="client")
    yield root
    store.reset_schema_cache()
    sources.reset_incident_cache()
    build.invalidate()


def add_operator(username: str, role: str, scope: Optional[list[str]] = None) -> int:
    """An operator with one Console role and its scope — no password (these
    tests never sign in)."""
    from apps.octo.auth import operators

    op = operators.create_operator(username=username, email=f"{username}@example.test",
                                   role=role, scope_slugs=scope or ["*"], actor="system",
                                   reason="threat test fixture")
    return int(op["operator_id"])


def disable_operator(oid: int) -> None:
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute("UPDATE operators SET disabled_at = '2026-01-01T00:00:00.000Z' "
                        "WHERE id = ?", (oid,))
    finally:
        reg.close()


def insert_event(slug: str, *, source: str, event_type: str, payload: dict,
                 received_at: Optional[str] = None, source_host: Optional[str] = None,
                 severity: str = "high") -> int:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        cur = conn.execute(
            "INSERT INTO events (received_at, source, source_host, event_type, severity, "
            "payload, payload_sha256) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (received_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
             source, source_host, event_type, severity, json.dumps(payload),
             f"sha-{os.urandom(6).hex()}"))
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def notices(kind: Optional[str] = None) -> list[sqlite3.Row]:
    reg = sqlite3.connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        sql = "SELECT * FROM operator_notices"
        args: tuple = ()
        if kind:
            sql += " WHERE kind = ?"
            args = (kind,)
        return reg.execute(sql + " ORDER BY id", args).fetchall()
    finally:
        reg.close()


def audit_rows(action: Optional[str] = None) -> list[sqlite3.Row]:
    g = sqlite3.connect(paths.global_audit_db_path())
    g.row_factory = sqlite3.Row
    try:
        if action:
            return g.execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id",
                             (action,)).fetchall()
        return g.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    finally:
        g.close()
