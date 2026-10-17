"""Coverage for the super_admin Data Management surface
(apps/octo/api/routers/admin_data.py)."""
from __future__ import annotations

from pathlib import Path

from apps.octo.tests.auth.test_search_events import (
    _apply_events_db_migration,
    _register_client,
    _insert_event,
    _login,
)
from apps.octo.tests.auth.test_search_indicators import _elevate


def _seed_one_tenant(auth_data_root: Path, slug: str) -> None:
    _register_client(slug)
    cdir = auth_data_root / "clients" / slug
    _apply_events_db_migration(cdir)
    _insert_event(
        cdir,
        received_at="2026-05-14T10:00:00.000Z",
        event_type="wazuh.alert", severity="high",
        source_host=f"buoy-{slug}-1", summary="test event for stats",
    )


def test_storage_stats_super_admin_sees_tenant_breakdown(auth_client, auth_data_root):
    _seed_one_tenant(auth_data_root, "acme")
    _seed_one_tenant(auth_data_root, "globex")
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    r = auth_client.get("/api/v1/admin/data/storage-stats")
    assert r.status_code == 200, r.text
    body = r.json()
    assert {t["slug"] for t in body["tenants"]} >= {"acme", "globex"}
    # Each tenant has size > 0 for events.db (we inserted a row)
    acme = next(t for t in body["tenants"] if t["slug"] == "acme")
    events_stat = next(d for d in acme["dbs"] if d["name"] == "events")
    assert events_stat["size_bytes"] > 0
    assert events_stat["row_count_estimate"] >= 1
    # Globals contain registry + patterns + audit
    assert {g["name"] for g in body["globals"]} == {"registry", "patterns", "audit"}
    # Disk stats present + non-negative
    assert body["disk"]["total_bytes"] > 0
    assert body["disk"]["used_pct"] >= 0


def test_storage_stats_blocked_for_admin_tier(auth_client, auth_data_root):
    """admin role (tier 3) sits below super_admin (tier 4) and gets 403."""
    _seed_one_tenant(auth_data_root, "acme")
    op = auth_client.provision_operator(
        "alice-admin", "pw1234567890", athena_role="admin",
    )
    _login(auth_client, op)

    r = auth_client.get("/api/v1/admin/data/storage-stats")
    assert r.status_code in (401, 403), r.text


def test_retention_patch_happy_path_audits_change(auth_client, auth_data_root):
    """Super_admin changes events retention from the regulator-baseline
    365 → 180 (below baseline). Old value + new value land in the
    audit log."""
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    _elevate(auth_client, op)      # v0.11: the job enforces it — step-up

    # Confirm starting state
    r0 = auth_client.get("/api/v1/admin/data/retention")
    assert r0.status_code == 200
    initial = {p["data_class"]: p for p in r0.json()["policies"]}
    assert initial["events"]["days"] == 365
    assert initial["events"]["editable"] is True
    assert initial["events"]["legal_baseline_days"] == 365
    assert initial["events"]["regulator_basis"]  # non-empty
    assert 180 in initial["events"]["allowed_days"]

    # Apply the change (180 = below the 365 regulator baseline; UI
    # gates this behind the acknowledged-disclosure modal, but the
    # server still accepts it — the modal is UI policy, not API policy)
    r1 = auth_client.patch(
        "/api/v1/admin/data/retention/events",
        json={"retention_days": 180},
    )
    assert r1.status_code == 200, r1.text
    body = r1.json()
    assert body["data_class"] == "events"
    assert body["retention_days"] == 180
    assert body["previous_days"] == 365

    # GET reflects new state
    r2 = auth_client.get("/api/v1/admin/data/retention")
    nxt = {p["data_class"]: p for p in r2.json()["policies"]}
    assert nxt["events"]["days"] == 180

    # Audit log has the change with operator id + before + after
    import sqlite3
    from apps.octo import paths
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        row = conn.execute(
            "SELECT actor, target_id, before_state, after_state "
            "  FROM audit_log "
            " WHERE action = 'admin_data.retention_update' "
            " ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    import json
    assert json.loads(row[2])["retention_days"] == 365
    assert json.loads(row[3])["retention_days"] == 180
    assert row[1] == "events"


def test_retention_patch_rejects_audit_class(auth_client, auth_data_root):
    """Audit retention is uneditable — regulator requirement.
    Any PATCH attempt is rejected even by super_admin."""
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.patch(
        "/api/v1/admin/data/retention/audit",
        json={"retention_days": 30},
    )
    # Either VALIDATION_FAILED (422 — not in ALLOWED_RETENTION_DAYS) or
    # ISOLATION_VIOLATION (403 — defense-in-depth check in handler).
    assert r.status_code in (403, 422), r.text
    assert r.json().get("code") in ("VALIDATION_FAILED", "ISOLATION_VIOLATION")


def test_retention_patch_rejects_unknown_values(auth_client, auth_data_root):
    """Days values outside the allowlist are rejected, even by
    super_admin. Prevents '1 day' misconfigs that retroactively delete
    prod telemetry."""
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    _elevate(auth_client, op)
    # 7 days is not in the events allowed set
    r = auth_client.patch(
        "/api/v1/admin/data/retention/events",
        json={"retention_days": 7},
    )
    assert r.status_code == 422, r.text
    assert r.json().get("code") == "VALIDATION_FAILED"


def test_retention_surfaces_regulator_baseline_and_basis(auth_client, auth_data_root):
    """Every editable policy exposes legal_baseline_days +
    regulator_basis so the UI can render the disclosure modal."""
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/admin/data/retention")
    assert r.status_code == 200
    policies = {p["data_class"]: p for p in r.json()["policies"]}

    # Editable classes: baseline must match the seeded retention_days
    # (defaults ship at the regulator baseline).
    for cls in ("events", "indicators_auto", "indicators_promoted",
                "secure_notepad", "agent_notes"):
        p = policies[cls]
        assert p["editable"] is True
        assert p["legal_baseline_days"] == p["days"], (
            f"{cls} default {p['days']} should equal baseline "
            f"{p['legal_baseline_days']} — defaults must ship AT baseline"
        )
        assert p["regulator_basis"], f"{cls} missing regulator_basis"

    # Audit row: baseline is null (no fixed-day baseline; permanent)
    assert policies["audit"]["legal_baseline_days"] is None
    assert policies["audit"]["regulator_basis"]  # still cited


def test_retention_patch_blocked_for_admin_tier(auth_client, auth_data_root):
    """Below super_admin gets 403 even with valid values — the role is
    checked BEFORE the step-up (a 403, never a pointless re-auth prompt),
    and even with an active step-up window."""
    op = auth_client.provision_operator(
        "alice-admin", "pw1234567890", athena_role="admin",
    )
    _login(auth_client, op)
    r = auth_client.patch(
        "/api/v1/admin/data/retention/events",
        json={"retention_days": 180},
    )
    assert r.status_code == 403, r.text
    _elevate(auth_client, op)
    r = auth_client.patch(
        "/api/v1/admin/data/retention/events",
        json={"retention_days": 180},
    )
    assert r.status_code == 403, r.text


def test_retention_patch_needs_step_up(auth_client, auth_data_root):
    """v0.11: the nightly job ENFORCES the value — lowering it deletes data at
    the next run. A super_admin session alone (a stolen or unattended
    cookie) gets 401 STEP_UP_REQUIRED and changes nothing; with a fresh
    step-up window the change applies."""
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.patch(
        "/api/v1/admin/data/retention/events",
        json={"retention_days": 180},
    )
    assert r.status_code == 401, r.text
    assert r.json()["code"] == "STEP_UP_REQUIRED"
    policies = {p["data_class"]: p for p in
                auth_client.get("/api/v1/admin/data/retention").json()["policies"]}
    assert policies["events"]["days"] == 365
    _elevate(auth_client, op)
    r = auth_client.patch(
        "/api/v1/admin/data/retention/events",
        json={"retention_days": 180},
    )
    assert r.status_code == 200, r.text
    assert r.json()["previous_days"] == 365


def test_retention_shows_audit_as_permanent_and_uneditable(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    r = auth_client.get("/api/v1/admin/data/retention")
    assert r.status_code == 200, r.text
    body = r.json()
    policies = {p["data_class"]: p for p in body["policies"]}
    # Audit MUST be permanent + uneditable — regulator-requirement
    # invariant. Surface it as such in the panel; never make it editable
    # from the UI.
    assert policies["audit"]["days"] is None
    assert policies["audit"]["editable"] is False
    # Other classes are editable + have non-None day counts
    assert policies["events"]["editable"] is True
    assert isinstance(policies["events"]["days"], int)
    assert policies["events"]["days"] > 0


def test_storage_stats_surfaces_mount_point_and_quota(
    auth_client, auth_data_root, monkeypatch,
):
    """Cloud/self-hosted deploys need a way to declare 'this bundle is
    allocated N bytes of a shared volume' — surface that AS WELL AS the
    raw volume capacity. Mount-point label helps operators correlate
    the report against their cloud volume attachment."""
    _seed_one_tenant(auth_data_root, "acme")
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    # No quota set — `used_pct_against_quota` should be null.
    monkeypatch.delenv("BUNDLE_STORAGE_QUOTA_BYTES", raising=False)
    r = auth_client.get("/api/v1/admin/data/storage-stats")
    assert r.status_code == 200
    body = r.json()
    assert body["disk"]["quota_bytes"] is None
    assert body["disk"]["used_pct_against_quota"] is None
    # mount_point + device come from /proc/self/mountinfo. On Linux
    # they'll be populated; on a containerized test runner they may be
    # None. Either is valid — we just check the keys exist.
    assert "mount_point" in body["disk"]
    assert "mount_device" in body["disk"]

    # With a quota set, used_pct_against_quota should compute.
    monkeypatch.setenv("BUNDLE_STORAGE_QUOTA_BYTES", "1000000")  # 1 MB cap
    r2 = auth_client.get("/api/v1/admin/data/storage-stats")
    body2 = r2.json()
    assert body2["disk"]["quota_bytes"] == 1000000
    # data_root has at least one tenant DB; pct should be a real
    # number between 0 and 100 (or higher, if test fixture exceeds the
    # 1 MB cap — that's fine, the field is just computed).
    assert isinstance(body2["disk"]["used_pct_against_quota"], (int, float))


# ---------------------------------------------------------------------------
# Row counts over the exact-count gate: a marked estimate, not "—" (S1)
# ---------------------------------------------------------------------------

def _fill_events(cdir: Path, n: int, *, payload_bytes: int = 600) -> None:
    import sqlite3

    conn = sqlite3.connect(cdir / "events.db")
    try:
        conn.executemany(
            "INSERT INTO events (received_at, source, event_type, severity, payload, "
            " payload_sha256) VALUES ('2026-05-14T10:00:00.000Z', 'wazuh', 'wazuh.alert', "
            " 'high', ?, 'x')",
            [('{"pad": "%s"}' % ("x" * payload_bytes),) for _ in range(n)],
        )
        conn.commit()
    finally:
        conn.close()


def test_storage_stats_exact_below_the_gate_estimate_above_it(
    auth_client, auth_data_root, monkeypatch,
):
    import sqlite3

    _seed_one_tenant(auth_data_root, "acme")
    _seed_one_tenant(auth_data_root, "globex")
    acme = auth_data_root / "clients" / "acme"
    _fill_events(acme, 20_000)                     # ~12 MB on disk
    # The telemetry move / retention leave long deleted runs of ids: 3 of
    # every 4 rows, in contiguous blocks, gone.
    conn = sqlite3.connect(acme / "events.db")
    try:
        for start in range(1, 20_001, 1000):
            conn.execute("DELETE FROM events WHERE id BETWEEN ? AND ?",
                         (start + 250, start + 999))
        conn.commit()
        real = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finally:
        conn.close()
    assert 4_000 < real < 6_000
    monkeypatch.setenv("OCTO_STORAGE_EXACT_COUNT_MAX_MB", "5")
    op = auth_client.provision_operator("alice", "pw1234567890", athena_role="super_admin")
    _login(auth_client, op)
    body = auth_client.get("/api/v1/admin/data/storage-stats").json()

    def events(slug):
        t = next(t for t in body["tenants"] if t["slug"] == slug)
        return next(d for d in t["dbs"] if d["name"] == "events")

    big, small = events("acme"), events("globex")
    assert big["size_bytes"] >= 5 * 1024 * 1024
    assert big["row_count_exact"] is False
    # Density-sampled, not MAX(rowid) - MIN(rowid) + 1 (which says ~20,000).
    assert abs(big["row_count_estimate"] - real) <= real * 0.1, (big, real)
    assert (small["row_count_estimate"], small["row_count_exact"]) == (1, True)
    assert all(g["row_count_exact"] for g in body["globals"])


def test_the_count_gate_defaults_to_256_mb_and_is_configurable(monkeypatch):
    from apps.octo.api.routers import admin_data

    monkeypatch.delenv("OCTO_STORAGE_EXACT_COUNT_MAX_MB", raising=False)
    assert admin_data.count_gate_bytes() == 256 * 1024 * 1024
    monkeypatch.setenv("OCTO_STORAGE_EXACT_COUNT_MAX_MB", "50")
    assert admin_data.count_gate_bytes() == 50 * 1024 * 1024
    monkeypatch.setenv("OCTO_STORAGE_EXACT_COUNT_MAX_MB", "lots")
    assert admin_data.count_gate_bytes() == 256 * 1024 * 1024


def test_the_estimate_of_a_small_span_is_the_count(tmp_path):
    import sqlite3

    from apps.octo.api.routers.admin_data import _estimate_rows

    conn = sqlite3.connect(tmp_path / "t.db")
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    conn.executemany("INSERT INTO t (id, v) VALUES (?, 'x')", [(i,) for i in (3, 9, 400)])
    assert _estimate_rows(conn, "t") == 3
    conn.execute("DELETE FROM t")
    assert _estimate_rows(conn, "t") == 0
    conn.close()
