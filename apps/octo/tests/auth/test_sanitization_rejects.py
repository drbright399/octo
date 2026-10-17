"""Coverage for the M3 sanitization_rejects router.

Two endpoints:
  - GET /api/v1/admin/sanitization/rejects (super_admin only)
  - GET /api/v1/dashboard/sanitization/reject-counts (analyst+)

Tests:
  - Role gating works as specified
  - Empty-pool case
  - Seeded rejects flow through with correct shape
  - Aggregate counts respect the time window
  - Aggregate response carries no per-tenant data
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from apps.octo.tests.auth.test_search_events import _login


def _seed_reject(
    patterns_path: Path,
    *,
    rejected_at: str,
    reason_code: str,
    raw_excerpt: str,
    source_tenant_hmac: str | None = None,
    source_slug: str | None = None,
) -> None:
    """Insert one synthetic reject row directly. Bypasses the extractor
    (which doesn't yet exist) — tests the router's read behavior in
    isolation.

    `source_slug` defaults to a placeholder string because migration
    003's NOT NULL constraint persists until the cleanup migration
    drops the column. Tests can pass an explicit string to assert
    legacy-row behavior.
    """
    conn = sqlite3.connect(str(patterns_path))
    try:
        conn.execute(
            """
            INSERT INTO sanitization_rejects
                (rejected_at, source_slug, reason, raw_excerpt,
                 source_tenant_hmac, reason_code, hmac_version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (rejected_at, source_slug or "<placeholder>", reason_code, raw_excerpt,
             source_tenant_hmac, reason_code, "v1"),
        )
        conn.commit()
    finally:
        conn.close()


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _hours_ago(h: int) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(hours=h)).isoformat()


# ---------------------------------------------------------------------------
# Role gating
# ---------------------------------------------------------------------------

def test_raw_rejects_requires_super_admin(auth_client, auth_data_root):
    # Fixture defaults `role` (OCTO-API role) to "admin"; the role_gates
    # max-tier check inspects ALL roles, so we set both the OCTO-API
    # role and the Athena-Console role to analyst to genuinely
    # exercise the under-tier path.
    op = auth_client.provision_operator(
        "alice", "pw1234567890",
        role="analyst", athena_role="analyst",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/admin/sanitization/rejects")
    # Analyst tier < super_admin → ISOLATION_VIOLATION
    assert r.status_code == 403, r.text


def test_reject_counts_requires_at_least_analyst(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "vic", "pw1234567890",
        role="viewer", athena_role="viewer",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/sanitization/reject-counts")
    # viewer < analyst → ISOLATION_VIOLATION
    assert r.status_code == 403, r.text


# ---------------------------------------------------------------------------
# Empty-pool behavior
# ---------------------------------------------------------------------------

def test_raw_rejects_empty_when_patterns_db_missing(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/admin/sanitization/rejects")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["rejects"] == []
    assert body["total_returned"] == 0


def test_reject_counts_empty_when_patterns_db_missing(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "bob", "pw1234567890", athena_role="analyst",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/sanitization/reject-counts")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["counts"] == []
    assert body["total"] == 0


# ---------------------------------------------------------------------------
# Seeded data
# ---------------------------------------------------------------------------

def _ensure_patterns_db(auth_data_root: Path) -> Path:
    """Return the patterns.db path.

    The auth_client fixture's create_app() invokes the patterns
    auto-migrate at boot, so by the time this helper is called the
    schema is already current (migration 3 + migration 23 applied).
    We just need to confirm the file exists + return its path.
    """
    from apps.octo.auth.bootstrap import ensure_patterns_migrations_applied
    p = auth_data_root / "global" / "patterns.db"
    p.parent.mkdir(parents=True, exist_ok=True)
    # Belt-and-suspenders: if the fixture's create_app() hasn't yet
    # touched the patterns DB (e.g. because the patterns_db file
    # didn't exist when create_app ran), apply migrations now.
    if not p.exists():
        ensure_patterns_migrations_applied(p)
    return p


def test_seeded_rejects_visible_to_super_admin(auth_client, auth_data_root):
    pdb = _ensure_patterns_db(auth_data_root)
    _seed_reject(
        pdb,
        rejected_at=_hours_ago(2),
        reason_code="url_invalid_chars",
        raw_excerpt="https://evil.com/\\x00",
        source_tenant_hmac="a" * 64,
    )
    _seed_reject(
        pdb,
        rejected_at=_hours_ago(1),
        reason_code="hash_bad_length",
        raw_excerpt="aaa",
        source_tenant_hmac="b" * 64,
    )
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/admin/sanitization/rejects?window_hours=24")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_returned"] == 2
    reasons = sorted(row["reason_code"] for row in body["rejects"])
    assert reasons == ["hash_bad_length", "url_invalid_chars"]
    # HMAC visible to super_admin. The legacy source_slug column has
    # a NOT-NULL constraint so we seeded it with a placeholder; that
    # column will be dropped by a cleanup migration once the
    # extractor consistently writes the HMAC column.
    for row in body["rejects"]:
        assert len(row["source_tenant_hmac"]) == 64
        assert row["source_slug"] == "<placeholder>"


def test_aggregate_counts_group_by_reason_code(auth_client, auth_data_root):
    pdb = _ensure_patterns_db(auth_data_root)
    # 3 url-invalid + 2 hash-bad in last hour
    for _ in range(3):
        _seed_reject(
            pdb, rejected_at=_hours_ago(0),
            reason_code="url_invalid_chars", raw_excerpt="x",
            source_tenant_hmac="a" * 64,
        )
    for _ in range(2):
        _seed_reject(
            pdb, rejected_at=_hours_ago(0),
            reason_code="hash_bad_length", raw_excerpt="y",
            source_tenant_hmac="b" * 64,
        )
    op = auth_client.provision_operator(
        "bob", "pw1234567890", athena_role="analyst",
    )
    _login(auth_client, op)
    r = auth_client.get(
        "/api/v1/dashboard/sanitization/reject-counts?window_hours=2",
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 5
    by_code = {c["reason_code"]: c["count"] for c in body["counts"]}
    assert by_code["url_invalid_chars"] == 3
    assert by_code["hash_bad_length"] == 2
    # The aggregate endpoint MUST NOT leak tenant info anywhere in
    # the response.
    body_text = r.text
    assert "tenant" not in body_text.lower(), \
        "aggregate response leaked the word 'tenant' — possible per-tenant data leak"


def test_window_hours_filters_out_old_rows(auth_client, auth_data_root):
    pdb = _ensure_patterns_db(auth_data_root)
    _seed_reject(
        pdb, rejected_at=_hours_ago(48),
        reason_code="url_invalid_chars", raw_excerpt="old",
        source_tenant_hmac="a" * 64,
    )
    _seed_reject(
        pdb, rejected_at=_hours_ago(1),
        reason_code="url_invalid_chars", raw_excerpt="recent",
        source_tenant_hmac="a" * 64,
    )
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    # 24h window: should see only the 1-hour-ago row, not the 48-hour-ago one.
    r = auth_client.get("/api/v1/admin/sanitization/rejects?window_hours=24")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_returned"] == 1
    assert body["rejects"][0]["raw_excerpt"] == "recent"
