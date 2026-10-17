"""Settings → System after migration 036: the retention surface shows the new
telemetry classes, what the job actually enforces, and the last run.

Pins:
  * role matrix for GET /admin/data/retention and /storage-stats (unchanged
    gate, re-checked with the new fields): unauth 401; viewer, analyst,
    admin 403; super_admin 200;
  * telemetry_raw / telemetry_rollup listed, editable within their allowed
    sets (never below the operational baseline);
  * effective_days / floored: a below-baseline setting is shown as floored;
  * last_run: None until an enforcing run; then its counts per class
    (a dry run leaves it None); scheduler + archive status;
  * archive encryption (2026-10-07): required / off, recipients as short
    forms + fingerprints only, plaintext vs encrypted file counts, the
    reason a required encryption is unusable;
  * storage stats list a tenant's telemetry.db.
"""
from __future__ import annotations

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.retention.job import RetentionJob
from apps.octo.tests._tiering_fixtures import insert_event, write_telemetry
from apps.octo.tests.auth.test_dashboard_throughput import _login
from apps.octo.tests.auth.test_search_indicators import _elevate

RET = "/api/v1/admin/data/retention"
STATS = "/api/v1/admin/data/storage-stats"
PW = "pw1234567890"


def _op(auth_client, name: str, role: str) -> dict:
    op = auth_client.provision_operator(name, PW, role=role, athena_role=role)
    _login(auth_client, op)
    return op


def test_unauthenticated_is_401(auth_client, auth_data_root):
    assert auth_client.get(RET).status_code == 401
    assert auth_client.get(STATS).status_code == 401


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
def test_below_super_admin_is_403(auth_client, auth_data_root, role):
    _op(auth_client, "bob", role)
    for url in (RET, STATS):
        r = auth_client.get(url)
        assert r.status_code == 403, (url, r.text)
    r = auth_client.patch(f"{RET}/telemetry_raw", json={"retention_days": 14})
    assert r.status_code == 403


def test_new_classes_effective_days_and_last_run(auth_client, auth_data_root):
    from apps.octo.ingest import sink as sink_module
    from apps.octo.ingest import telemetry

    telemetry.reset_schema_cache()
    sink_module.reset_telemetry_fallbacks()     # process-wide counter: start clean
    client_provisioning.create_client("acme-corp", "Acme Corp", kind="client")
    op = _op(auth_client, "alice", "super_admin")
    body = auth_client.get(RET).json()
    by = {p["data_class"]: p for p in body["policies"]}
    assert (by["telemetry_raw"]["days"], by["telemetry_raw"]["legal_baseline_days"],
            by["telemetry_raw"]["editable"], by["telemetry_raw"]["allowed_days"]) == (
        7, 7, True, [7, 14, 30, 90])
    assert (by["telemetry_rollup"]["days"], by["telemetry_rollup"]["allowed_days"]) == (
        180, [180, 365, 730])
    assert by["audit"]["effective_days"] is None and by["audit"]["enforced"] is False
    assert by["secure_notepad"]["enforced"] is False
    assert by["events"]["effective_days"] == 365 and by["events"]["floored"] is False
    assert body["last_run"] is None
    assert body["scheduler"] == {"enabled": False, "hour_utc": None, "next_run_at": None,
                                 "last_failure": None}
    assert body["archive"]["enabled"] is False

    # A below-baseline setting is stored but shown floored (a change needs
    # step-up: the job enforces it).
    _elevate(auth_client, op)
    r = auth_client.patch(f"{RET}/events", json={"retention_days": 90})
    assert r.status_code == 200, r.text
    ev = next(p for p in auth_client.get(RET).json()["policies"] if p["data_class"] == "events")
    assert (ev["days"], ev["effective_days"], ev["floored"]) == (90, 365, True)
    # Telemetry values outside the allowed set are refused.
    assert auth_client.patch(f"{RET}/telemetry_raw", json={"retention_days": 3}).status_code == 422
    assert auth_client.patch(f"{RET}/telemetry_raw", json={"retention_days": 14}).status_code == 200

    # A dry run leaves no trace; an enforcing run is shown with its counts.
    root = paths.data_root()
    insert_event(root, "acme-corp", event_type="wazuh.alert", payload={"n": 1},
                 received_at="2024-01-01T00:00:00.000Z", severity="high")
    write_telemetry(root, "acme-corp", received_at="2024-01-01T00:00:00.000Z", n=1)
    RetentionJob(data_root=root, archive_from_env=False).run(dry_run=True)
    assert auth_client.get(RET).json()["last_run"] is None
    report = RetentionJob(data_root=root, archive_from_env=False).run(trigger="script")
    body = auth_client.get(RET).json()
    assert body["last_run"]["run_id"] == report.run_id
    # events 1 + raw 1 + its 2024 roll-up hour 1 + its first-seen domain 1
    assert body["last_run"]["status"] == "ok" and body["last_run"]["deleted_total"] == 4
    by = {p["data_class"]: p for p in body["policies"]}
    assert by["events"]["last_run_deleted"] == 1
    assert by["telemetry_raw"]["last_run_deleted"] == 1
    assert by["telemetry_rollup"]["last_run_deleted"] == 1
    assert by["agent_notes"]["last_run_deleted"] == 0
    assert by["events"]["last_run_referenced"] == 0
    assert by["events"]["last_run_evidence"] == 0
    assert body["telemetry_store"] == {"recent_fallbacks": 0, "window_hours": 24,
                                       "last_fallback_at": None, "tenants": {},
                                       "last_sweep_moved": 0, "last_sweep_errors": []}


def test_the_backfill_run_and_skipped_classes_are_not_shown_as_the_last_run(
        auth_client, auth_data_root):
    """The one-off move's run (trigger 'backfill') is not "the last retention
    run": the page still says retention never ran. A run limited to some
    classes shows no "last run: 0 deleted" for the classes it skipped."""
    from apps.octo.ingest import telemetry

    telemetry.reset_schema_cache()
    client_provisioning.create_client("acme-corp", "Acme Corp", kind="client")
    _op(auth_client, "alice", "super_admin")
    root = paths.data_root()
    classes = ("telemetry_raw", "telemetry_rollup", "first_seen_domains")
    RetentionJob(data_root=root, archive_from_env=False, sweep_days=None).run(
        trigger="backfill", classes=classes)
    body = auth_client.get(RET).json()
    assert body["last_run"] is None
    assert all(p["last_run_deleted"] is None for p in body["policies"])
    report = RetentionJob(data_root=root, archive_from_env=False).run(
        trigger="script", classes=classes)
    body = auth_client.get(RET).json()
    assert body["last_run"]["run_id"] == report.run_id
    by = {p["data_class"]: p for p in body["policies"]}
    assert by["telemetry_raw"]["last_run_deleted"] == 0
    assert by["events"]["last_run_deleted"] is None          # not part of that run
    assert by["agent_notes"]["last_run_deleted"] is None


def test_referenced_holds_and_store_fallbacks_are_shown(auth_client, auth_data_root):
    """Settings → System says how many expired events were held as evidence,
    and that telemetry writes were refused (moved by the nightly sweep)."""
    import os

    from apps.octo.ingest import sink as sink_module
    from apps.octo.ingest import telemetry
    from apps.octo.tests._tiering_fixtures import event_note, pihole_payload

    telemetry.reset_schema_cache()
    sink_module.reset_telemetry_fallbacks()
    client_provisioning.create_client("acme-corp", "Acme Corp", kind="client")
    root = paths.data_root()
    ev = insert_event(root, "acme-corp", event_type="wazuh.alert", payload={"n": 1},
                      received_at="2024-01-01T00:00:00.000Z", severity="high")
    event_note(root, "acme-corp", ev)
    # A refused telemetry write, through the real sink.
    import hashlib
    import json

    from shared_adapter_contract.types import CanonicalEvent

    from datetime import datetime, timedelta, timezone

    payload = pihole_payload(2, "www.example.test")
    tdb = root / "clients" / "acme-corp" / "telemetry.db"
    # The job below runs on the real clock and sweeps SWEEP_DAYS back: the
    # refused write must be recent (a fixed 2026-09-29 fell out of the sweep
    # on 2026-10-07 — a time bomb).
    recent = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z")
    os.chmod(tdb, 0o444)
    try:
        sink_module.SqliteIngestSink(root, publish_to_stream=False).ingest(
            "acme-corp", "buoy:acme", CanonicalEvent(
                vendor_event_id="1", received_at=recent, severity="info",
                indicator=None, indicator_type=None, source_host="buoy-acme-1",
                summary="pihole.query", payload=payload,
                payload_sha256=hashlib.sha256(json.dumps(payload).encode()).hexdigest()),
            event_type="pihole.query")
    finally:
        for f in tdb.parent.glob("telemetry.db*"):
            os.chmod(f, 0o644)
    RetentionJob(data_root=root, archive_from_env=False).run(trigger="script")
    _op(auth_client, "alice", "super_admin")
    body = auth_client.get(RET).json()
    ev_policy = next(p for p in body["policies"] if p["data_class"] == "events")
    assert (ev_policy["last_run_deleted"], ev_policy["last_run_referenced"]) == (0, 1)
    assert body["telemetry_store"]["recent_fallbacks"] == 1
    assert body["telemetry_store"]["window_hours"] == 24
    assert body["telemetry_store"]["last_fallback_at"]
    assert body["telemetry_store"]["tenants"] == {"acme-corp": 1}
    assert body["telemetry_store"]["last_sweep_moved"] == 1


def test_storage_stats_list_the_telemetry_db(auth_client, auth_data_root):
    from apps.octo.ingest import telemetry

    telemetry.reset_schema_cache()
    client_provisioning.create_client("acme-corp", "Acme Corp", kind="client")
    write_telemetry(paths.data_root(), "acme-corp", received_at="2026-09-29T10:00:00.000Z")
    _op(auth_client, "alice", "super_admin")
    body = auth_client.get(STATS).json()
    acme = next(t for t in body["tenants"] if t["slug"] == "acme-corp")
    tele = next(d for d in acme["dbs"] if d["name"] == "telemetry")
    assert tele["size_bytes"] > 0 and tele["row_count_estimate"] == 1


def test_rows_kept_inside_evidence_windows_are_shown(auth_client, auth_data_root):
    """Settings → System says how many expired rows the last run KEPT because
    they lie inside an evidence window (Tier Black, 044) — per class."""
    from datetime import datetime, timezone

    from apps.octo.threat import store

    store.reset_schema_cache()
    client_provisioning.create_client("acme-corp", "Acme Corp", kind="client")
    root = paths.data_root()
    trigger = insert_event(root, "acme-corp", event_type="wazuh.alert", payload={"n": 0},
                           received_at="2024-01-01T00:00:00.000Z", severity="high")
    store.open_incident("acme-corp", tier="black", rule_id="B6", rule_version=1,
                        key="acme-corp|ws-01|analyst|", summary="hands on keyboard",
                        scope="device", opened_by="7", reason="the client called",
                        event_ids=[trigger], now=datetime(2024, 1, 2, tzinfo=timezone.utc))
    insert_event(root, "acme-corp", event_type="wazuh.alert", payload={"n": 1},
                 received_at="2024-06-01T00:00:00.000Z", severity="high")
    write_telemetry(root, "acme-corp", received_at="2024-06-01T00:00:00.000Z", n=1)
    RetentionJob(data_root=root, archive_from_env=False).run(trigger="script")
    _op(auth_client, "alice", "super_admin")
    by = {p["data_class"]: p for p in auth_client.get(RET).json()["policies"]}
    assert by["events"]["last_run_evidence"] == 1                 # (the trigger: cited)
    assert by["telemetry_raw"]["last_run_evidence"] == 1
    assert by["events"]["last_run_deleted"] == 0


def test_archive_encryption_is_shown(auth_client, auth_data_root, tmp_path, monkeypatch):
    """Settings → System (super_admin, the page's gate — role matrix above):
    archive encryption required / off, the recipients as short forms and
    fingerprints (never a whole key), plaintext vs encrypted file counts, and
    why a REQUIRED encryption is unusable (nothing is pruned then)."""
    import json
    import os

    pytest.importorskip("pyrage")
    from apps.octo.retention import archive_crypto as crypto
    from apps.octo.retention.archive import ColdArchive
    from apps.octo.retention.tests._crypto_fixtures import keypair, recipients_file, row

    arch_root = tmp_path / "archive"
    arch_root.mkdir()
    os.chmod(arch_root, 0o700)
    key = keypair(tmp_path)
    ColdArchive(arch_root).append("acme-corp", "2026-10-06", [row(1, "2026-10-06")])
    ColdArchive(arch_root, encryption=crypto.with_recipients((key.public,))).append(
        "acme-corp", "2026-10-07", [row(2, "2026-10-07")])
    monkeypatch.setenv("OCTO_ARCHIVE_ROOT", str(arch_root))
    monkeypatch.delenv(crypto.POLICY_ENV, raising=False)
    monkeypatch.setenv(crypto.RECIPIENTS_ENV, str(recipients_file(tmp_path, key.public)))
    _op(auth_client, "alice", "super_admin")
    body = auth_client.get(RET).json()
    a = body["archive"]
    assert (a["enabled"], a["usable"], a["encrypted"]) == (True, True, True)
    enc = a["encryption"]
    assert (enc["mode"], enc["source"], enc["custody"], enc["scheme"]) == (
        "required", "default", "operator", "age-x25519")
    assert enc["recipients"] == [{"short": crypto.recipient_short(key.public),
                                  "fingerprint": crypto.recipient_fingerprint(key.public)}]
    assert a["files"] == {"plaintext": 1, "encrypted": 1, "plaintext_temp": 0, "complete": True}
    assert key.public not in json.dumps(body) and key.secret not in json.dumps(body)
    # Required, recipients gone: unusable, and why.
    monkeypatch.setenv(crypto.RECIPIENTS_ENV, str(tmp_path / "missing.txt"))
    a = auth_client.get(RET).json()["archive"]
    assert a["usable"] is False and a["encrypted"] is False
    assert a["reason"].startswith("archive encryption is required but unusable")
    assert "does not exist" in a["encryption"]["error"]
    # Off: said.
    monkeypatch.setenv(crypto.POLICY_ENV, "off")
    a = auth_client.get(RET).json()["archive"]
    assert a["usable"] is True and a["encrypted"] is False
    assert a["encryption_note"].startswith("archive NOT encrypted — OCTO_ARCHIVE_ENCRYPTION=off")
