"""/dashboard/throughput counts ALL ingest — signals (events.db) and, since
migration 036, telemetry (telemetry.db) — and every minute of a sub-hour
bucket.

Pins:
  * whole-hour buckets: events + the telemetry hourly roll-up;
  * sub-hour buckets: events + raw telemetry rows, each floored onto the
    bucket grid (a 15-minute bucket takes all 15 minutes — keying on the
    minute used to drop every row not stamped at a bucket's first minute);
  * scope: a viewer's throughput covers only their tenant's stores.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from apps.octo import client_provisioning
from apps.octo.tests._tiering_fixtures import insert_event, write_telemetry
from apps.octo.tests.auth.test_dashboard_throughput import _login

URL = "/api/v1/dashboard/throughput"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _seed(root, slug: str, base: datetime, n_events: int, n_tele: int) -> None:
    for i in range(n_events):
        insert_event(root, slug, event_type="wazuh.alert", payload={"i": i, "s": slug},
                     received_at=_iso(base + timedelta(minutes=i % 10)), severity="high")
    for i in range(n_tele):
        write_telemetry(root, slug, received_at=_iso(base + timedelta(minutes=1 + i % 13)),
                        domain=f"d{i}.example.test", n=i)


def test_hourly_and_sub_hour_buckets_count_signals_and_telemetry(auth_client, auth_data_root):
    from apps.octo.ingest import telemetry

    telemetry.reset_schema_cache()
    for slug in ("acme-corp", "globex"):
        client_provisioning.create_client(slug, slug.title(), kind="client")
    now = datetime.now(timezone.utc)
    # An hour-aligned base inside the window, two hours back (so every seeded
    # minute is complete and in the past).
    base = (now - timedelta(hours=2)).replace(minute=0, second=0, microsecond=0)
    _seed(auth_data_root, "acme-corp", base, n_events=3, n_tele=12)
    _seed(auth_data_root, "globex", base, n_events=1, n_tele=5)
    op = auth_client.provision_operator("alice", "pw1234567890", athena_role="super_admin")
    _login(auth_client, op)

    hourly = auth_client.get(URL, params={"window_hours": 6, "bucket_minutes": 60}).json()
    by_t = {p["t"]: p["v"] for p in hourly["points"]}
    key = base.strftime("%Y-%m-%dT%H:00:00Z")
    assert by_t[key] == 3 + 12 + 1 + 5
    assert sum(by_t.values()) == 21

    quarter = auth_client.get(URL, params={"window_minutes": 360, "bucket_minutes": 15}).json()
    assert sum(p["v"] for p in quarter["points"]) == 21
    by_q = {p["t"]: p["v"] for p in quarter["points"]}
    assert by_q[base.strftime("%Y-%m-%dT%H:%M:00Z")] == 21     # minutes 0-13 → first bucket


def test_a_viewer_counts_only_their_tenant(auth_client, auth_data_root):
    from apps.octo.ingest import telemetry

    telemetry.reset_schema_cache()
    for slug in ("acme-corp", "globex"):
        client_provisioning.create_client(slug, slug.title(), kind="client")
    base = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(
        minute=0, second=0, microsecond=0)
    _seed(auth_data_root, "acme-corp", base, n_events=2, n_tele=4)
    _seed(auth_data_root, "globex", base, n_events=5, n_tele=9)
    op = auth_client.provision_operator("bob", "pw1234567890", role="viewer",
                                        athena_role="viewer", scope_slugs=["acme-corp"])
    _login(auth_client, op)
    body = auth_client.get(URL, params={"window_hours": 6, "bucket_minutes": 60}).json()
    assert sum(p["v"] for p in body["points"]) == 6
