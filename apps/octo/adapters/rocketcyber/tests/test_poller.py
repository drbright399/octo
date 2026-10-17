"""One poll cycle → stored events, end to end on the real pieces: a persisted
adapter_instances row, the real RocketCyberSourceAdapter / Client / Poller,
the real registry, tenant map, auto-create, quarantine and ingest sink. Only
the vendor socket is fake (fake_rocketcyber.py).

Pinned here: routing per customer (and the provider's own id; a customer id
is never taken as a client slug), auto-create of an unknown customer,
quarantine without an accountId, the change model (a status change is a NEW
row labelled by presentation; a repeat, an event-count change or a PSA ticket
is not), closures that arrive long after an incident left the 14-day window,
restarts (seeded from the store; history judged by the newest timestamp and
anchored on the instance), the first-run lookback bound, and that the map
stays bounded.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.adapters.rocketcyber import RocketCyberSourceAdapter
from apps.octo.adapters.rocketcyber.poller import RocketCyberPoller
from apps.octo.adapters.rocketcyber.tests.fake_rocketcyber import (
    CREDS,
    INCIDENTS_PATH,
    PROVIDER_ID,
    FakeRocketCyberTransport,
    ago,
    changed,
    client_factory,
    incident,
    real_client,
    resolved,
)
from apps.octo.client_provisioning import create_client
from apps.octo.db import connect
from apps.octo.ingest import SqliteIngestSink
from apps.octo.instances import (
    create_instance,
    freshness,
    quarantine,
    tenant_map,
    vendor_contact,
    vendor_tenants,
)
from apps.octo.instances.tenant_map import MappingIngestSink, TenantMapping
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401


@pytest.fixture(autouse=True)
def _clean_state():
    quarantine.reset_schema_cache()
    vendor_tenants.reset()
    vendor_contact.reset()
    freshness.reset()
    yield
    quarantine.reset_schema_cache()
    vendor_tenants.reset()
    vendor_contact.reset()
    freshness.reset()


def _instance(**config):
    return create_instance(
        vendor_slug="rocketcyber", display_name="RocketCyber",
        credentials_dict=dict(CREDS),
        instance_config={"poll_interval_sec": 0.01, **config},
    )


def _poller(
    transport: FakeRocketCyberTransport, record, *, default: str | None = None,
    **kwargs,
) -> RocketCyberPoller:
    return RocketCyberPoller(
        adapter=RocketCyberSourceAdapter(client_factory=client_factory(transport)),
        client=real_client(transport),
        sink=MappingIngestSink(SqliteIngestSink(publish_to_stream=False), record.id),
        default_tenant_slug=default or "_unmapped",
        instance_id=record.id,
        **kwargs,
    )


def _events(slug: str) -> list[sqlite3.Row]:
    db = paths.client_dir(slug) / "events.db"
    if not db.exists():
        return []
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM events ORDER BY id").fetchall()
    finally:
        conn.close()


def _clients() -> dict[str, dict]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        rows = reg.execute(
            "SELECT slug, display_name, origin, review_state, created_by_instance_id FROM clients",
        ).fetchall()
    finally:
        reg.close()
    return {r["slug"]: dict(r) for r in rows}


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_cycle_stores_each_incident_under_its_customers_tenant(bedrock_root):  # noqa: F811
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    create_client("example-bakery", "Example Bakery")
    tenant_map.set_mappings(record.id, [
        TenantMapping("2001", "acme-corp"), TenantMapping("2002", "example-bakery"),
    ])
    transport = FakeRocketCyberTransport()
    transport.incidents = [
        incident(1), incident(2),
        incident(3, account_id=2002, account_name="Example Bakery", psa_id="T9"),
    ]
    poller = _poller(transport, record)
    await poller._drain_once()

    acme, bakery = _events("acme-corp"), _events("example-bakery")
    assert len(acme) == 2 and len(bakery) == 1
    row = bakery[0]
    assert (row["source"], row["event_type"], row["severity"]) == (
        "rocketcyber", "rocketcyber.incident", "high")
    assert row["summary"] == "RocketCyber · Suspicious PowerShell execution 3"
    assert row["received_at"] == transport.incidents[2]["updatedAt"]
    assert row["source_host"] is None
    # One read per status for the whole provider — not one per customer.
    queries = transport.incident_queries()
    assert [q["status"] for q in queries] == ["open", "resolved", "suppressed"]
    assert {q["accountId"] for q in queries} == {str(PROVIDER_ID)}
    # Freshness: the receive clock moved for the instance and both tenants.
    assert freshness.tenant_last_event("acme-corp") is not None
    assert freshness.instance_last_event(record.id, None) is not None
    assert poller.last_event_at is not None


@pytest.mark.asyncio
async def test_the_providers_own_incidents_route_like_any_customer(bedrock_root):  # noqa: F811
    record = _instance()
    create_client("internal-msp", "Internal")
    tenant_map.set_mappings(record.id, [TenantMapping(str(PROVIDER_ID), "internal-msp")])
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1, account_id=PROVIDER_ID, account_name="Example MSP")]
    await _poller(transport, record)._drain_once()
    assert len(_events("internal-msp")) == 1


@pytest.mark.asyncio
async def test_an_unknown_customer_becomes_a_pending_tenant(bedrock_root):  # noqa: F811
    record = _instance()
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1), incident(2)]
    await _poller(transport, record)._drain_once()

    row = _clients()["acme-corp"]
    assert (row["display_name"], row["origin"], row["review_state"]) == (
        "Acme Corp", "auto", "pending")
    assert row["created_by_instance_id"] == record.id
    assert len(_events("acme-corp")) == 2
    (m,) = tenant_map.get_mappings(record.id)
    assert (m.vendor_tenant_id, m.octo_client_slug, m.match_source, m.vendor_tenant_label) == (
        "2001", "acme-corp", "auto", "Acme Corp")


@pytest.mark.asyncio
async def test_an_incident_without_an_account_id_is_quarantined_or_uses_the_default(bedrock_root):  # noqa: F811
    record = _instance()
    transport = FakeRocketCyberTransport()
    orphan = incident(1)
    del orphan["accountId"]
    transport.incidents = [orphan]
    await _poller(transport, record)._drain_once()
    rows, total = quarantine.list_rows(instance_id=record.id)
    assert total == 1 and rows[0].reason == "no-tenant-id" and rows[0].source == "poll"
    assert rows[0].event_summary == "RocketCyber · Suspicious PowerShell execution 1"

    create_client("catch-all", "Catch All")
    await _poller(transport, record, default="catch-all")._drain_once()
    assert len(_events("catch-all")) == 1


@pytest.mark.asyncio
async def test_a_held_incident_is_retried_and_stored_once_its_customer_is_mapped(bedrock_root):  # noqa: F811
    record = _instance()
    create_client("acme-east", "Acme Corp")
    create_client("acme-west", "ACME CORP.")
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1)]
    poller = _poller(transport, record)
    for _ in range(3):
        await poller._drain_once()
    rows, total = quarantine.list_rows(instance_id=record.id)
    assert total == 1 and rows[0].reason == "ambiguous-name"      # held ONCE
    assert rows[0].vendor_tenant_id == "2001" and rows[0].vendor_tenant_label == "Acme Corp"

    tenant_map.set_mappings(record.id, [TenantMapping("2001", "acme-west")])
    await poller._drain_once()
    assert len(_events("acme-west")) == 1
    await poller._drain_once()
    assert len(_events("acme-west")) == 1                          # and only once


# ---------------------------------------------------------------------------
# The change model
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_status_change_is_a_new_row_and_a_repeat_is_not(bedrock_root):  # noqa: F811
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    tenant_map.set_mappings(record.id, [TenantMapping("2001", "acme-corp")])
    transport = FakeRocketCyberTransport()
    original = incident(1)
    transport.incidents = [original]
    poller = _poller(transport, record)

    await poller._drain_once()
    await poller._drain_once()                   # plain repeat
    await poller._drain_once()
    assert len(_events("acme-corp")) == 1

    transport.incidents = [resolved(original)]
    await poller._drain_once()
    rows = _events("acme-corp")
    assert len(rows) == 2
    assert rows[1]["summary"] == "RocketCyber · Suspicious PowerShell execution 1 — resolved"
    assert rows[1]["severity"] == "medium" and rows[1]["event_type"] == "rocketcyber.incident"
    assert rows[1]["received_at"] >= rows[0]["received_at"]
    shown = RocketCyberSourceAdapter.present_event(json.loads(rows[1]["payload"]))
    assert "Status: resolved" in shown.detail

    for _ in range(2):
        await poller._drain_once()
    assert len(_events("acme-corp")) == 2        # the resolution is not repeated

    # Reopened, suppressed: each its own version.
    transport.incidents = [changed(transport.incidents[0], status="suppressed")]
    await poller._drain_once()
    rows = _events("acme-corp")
    assert len(rows) == 3 and rows[2]["severity"] == "medium"
    assert rows[2]["summary"].endswith(" — suppressed")


@pytest.mark.asyncio
async def test_neither_an_event_count_change_nor_other_edits_are_a_new_row(bedrock_root):  # noqa: F811
    """An ongoing detection's count grows every few minutes: each one used to
    store another identical-looking HIGH row that triage escalated."""
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    tenant_map.set_mappings(record.id, [TenantMapping("2001", "acme-corp")])
    transport = FakeRocketCyberTransport()
    original = incident(1, event_count=1)
    transport.incidents = [original]
    poller = _poller(transport, record)
    await poller._drain_once()

    transport.incidents = [changed(original, psaId="T77")]
    await poller._drain_once()
    for count in range(2, 12):
        transport.incidents = [changed(transport.incidents[0], eventCount=count)]
        await poller._drain_once()
    assert len(_events("acme-corp")) == 1

    # The status change is a new row — and it carries the current count.
    transport.incidents = [resolved(transport.incidents[0])]
    await poller._drain_once()
    rows = _events("acme-corp")
    assert len(rows) == 2 and rows[1]["severity"] == "medium"
    assert "11 events" in RocketCyberSourceAdapter.present_event(
        json.loads(rows[1]["payload"])).detail


@pytest.mark.asyncio
async def test_a_restart_replays_nothing_that_is_already_stored(bedrock_root):  # noqa: F811
    """The map is process memory; after a restart the window is delivered
    again and the sink's (source, payload, timestamp) guard collapses it."""
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    tenant_map.set_mappings(record.id, [TenantMapping("2001", "acme-corp")])
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1), resolved(incident(2))]
    await _poller(transport, record)._drain_once()
    assert len(_events("acme-corp")) == 2

    restarted = _poller(transport, record)
    await restarted._drain_once()
    assert len(_events("acme-corp")) == 2
    assert restarted.tracked == 2                # the new map is seeded
    # …and a change seen after the restart is still a new row.
    transport.incidents = [resolved(transport.incidents[0]), transport.incidents[1]]
    await restarted._drain_once()
    assert len(_events("acme-corp")) == 3


@pytest.mark.asyncio
async def test_the_first_run_lookback_bounds_what_is_imported(bedrock_root):  # noqa: F811
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    tenant_map.set_mappings(record.id, [TenantMapping("2001", "acme-corp")])
    transport = FakeRocketCyberTransport()
    recent = incident(1, created=ago(days=3))
    old = incident(2, created=ago(days=10))       # in the 14-day window, before the 7-day bound
    transport.incidents = [recent, old]
    poller = _poller(transport, record)
    await poller._drain_once()

    rows = _events("acme-corp")
    assert [r["summary"] for r in rows] == ["RocketCyber · Suspicious PowerShell execution 1"]
    assert poller.tracked == 2                    # the old one is remembered, silently
    # The window READ still covers 14 days.
    assert transport.incident_queries()[0]["createdAt"].split("|")[0] <= ago(days=14).date().isoformat()

    await poller._drain_once()
    assert len(_events("acme-corp")) == 1         # still not imported

    # A later change to the old incident IS news.
    transport.incidents = [recent, resolved(old)]
    await poller._drain_once()
    rows = _events("acme-corp")
    assert len(rows) == 2 and rows[1]["summary"].endswith("execution 2 — resolved")


@pytest.mark.asyncio
async def test_lookback_zero_imports_nothing_that_already_exists(bedrock_root):  # noqa: F811
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    tenant_map.set_mappings(record.id, [TenantMapping("2001", "acme-corp")])
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1, created=ago(minutes=30))]
    poller = _poller(transport, record, initial_lookback_days=0)
    await poller._drain_once()
    assert _events("acme-corp") == []
    transport.incidents.append(incident(2, created=ago(minutes=-1)))    # created after start
    await poller._drain_once()
    assert len(_events("acme-corp")) == 1


@pytest.mark.asyncio
async def test_the_map_forgets_what_left_the_window_and_holds_while_truncated(bedrock_root):  # noqa: F811
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    tenant_map.set_mappings(record.id, [TenantMapping("2001", "acme-corp")])
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(n) for n in range(1, 6)]
    poller = _poller(transport, record)
    await poller._drain_once()
    assert poller.tracked == 5

    transport.incidents = transport.incidents[:2]         # three aged out
    await poller._drain_once()
    assert poller.tracked == 2

    # A truncated listing proves nothing about what is absent: keep the map.
    from apps.octo.adapters.rocketcyber.client import IncidentListing
    poller._process(IncidentListing(transport.incidents[:1], truncated=True))
    assert poller.tracked == 2


@pytest.mark.asyncio
async def test_the_map_is_hard_bounded(bedrock_root, monkeypatch):  # noqa: F811
    from apps.octo.adapters.rocketcyber import poller as poller_module
    from apps.octo.adapters.rocketcyber.client import IncidentListing

    monkeypatch.setattr(poller_module, "MAX_TRACKED_INCIDENTS", 3)
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    tenant_map.set_mappings(record.id, [TenantMapping("2001", "acme-corp")])
    poller = _poller(FakeRocketCyberTransport(), record)
    poller._process(IncidentListing([incident(n) for n in range(1, 7)], truncated=True))
    assert poller.tracked == 3
    assert list(poller._seen) == [5004, 5005, 5006]       # the oldest went first


@pytest.mark.asyncio
async def test_a_failed_store_is_retried_next_cycle(bedrock_root, monkeypatch):  # noqa: F811
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    tenant_map.set_mappings(record.id, [TenantMapping("2001", "acme-corp")])
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1)]
    poller = _poller(transport, record)
    real_ingest = SqliteIngestSink.ingest
    broken = {"on": True}

    def _ingest(self, *args, **kwargs):
        if broken["on"]:
            raise sqlite3.OperationalError("database is locked")
        return real_ingest(self, *args, **kwargs)

    monkeypatch.setattr(SqliteIngestSink, "ingest", _ingest)
    await poller._drain_once()
    assert _events("acme-corp") == [] and poller.tracked == 0
    broken["on"] = False
    await poller._drain_once()
    assert len(_events("acme-corp")) == 1


@pytest.mark.asyncio
async def test_a_poller_without_an_instance_uses_only_the_default_tenant(bedrock_root):  # noqa: F811
    """No instance, no tenant map: every incident goes to the default tenant.
    A customer id is never used as a slug — "2001" names another client."""
    create_client("acme-corp", "Acme Corp")
    create_client("2001", "Some Other Customer")
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1)]
    poller = RocketCyberPoller(
        adapter=RocketCyberSourceAdapter(), client=real_client(transport),
        sink=SqliteIngestSink(publish_to_stream=False), default_tenant_slug="acme-corp",
    )
    await poller._drain_once()
    raw = incident(2)
    del raw["accountId"]
    transport.incidents = [raw]
    await poller._drain_once()
    assert len(_events("acme-corp")) == 2
    assert _events("2001") == []


# ---------------------------------------------------------------------------
# Closures long after the 14-day window
# ---------------------------------------------------------------------------

class _Clock:
    """The poller's clock, movable: `advance(days=16)` is sixteen days later."""

    def __init__(self) -> None:
        self.now = datetime.now(timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta) -> None:
        self.now += timedelta(**delta)


def _mapped_instance(**config):
    record = _instance(**config)
    create_client("acme-corp", "Acme Corp")
    tenant_map.set_mappings(record.id, [TenantMapping("2001", "acme-corp")])
    return record


@pytest.mark.asyncio
async def test_a_resolution_after_the_incident_left_the_window_is_still_stored(bedrock_root):  # noqa: F811
    record = _mapped_instance()
    transport = FakeRocketCyberTransport()
    original = incident(1, created=ago(days=2))
    transport.incidents = [original]
    clock = _Clock()
    poller = _poller(transport, record, now=clock)
    await poller._drain_once()
    assert [r["severity"] for r in _events("acme-corp")] == ["high"]

    clock.advance(days=16)        # 18 days old: outside every createdAt window but open's
    await poller._drain_once()
    assert len(_events("acme-corp")) == 1 and poller.tracked == 1

    transport.incidents = [resolved(original)]     # resolved in the console on day 18
    transport.queries.clear()
    await poller._drain_once()
    rows = _events("acme-corp")
    assert len(rows) == 2
    assert rows[1]["summary"] == "RocketCyber · Suspicious PowerShell execution 1 — resolved"
    assert rows[1]["severity"] == "medium"
    # Found by its creation date: resolved + suppressed, one day either side.
    created_day = datetime.fromisoformat(original["createdAt"].replace("Z", "+00:00")).date()
    rechecks = [q for q in transport.incident_queries() if q["createdAt"].startswith(
        (created_day - timedelta(days=1)).isoformat())]
    assert [q["status"] for q in rechecks] == ["resolved", "suppressed"]
    assert rechecks[0]["createdAt"].endswith((created_day + timedelta(days=1)).isoformat())

    await poller._drain_once()
    assert len(_events("acme-corp")) == 2 and poller.tracked == 0   # closed, out of every read


@pytest.mark.asyncio
async def test_an_old_open_incident_on_first_connect_is_tracked_until_it_closes(bedrock_root):  # noqa: F811
    """Created 60 days before the instance: history, not imported — but its
    closure is news whenever it comes."""
    record = _mapped_instance()
    transport = FakeRocketCyberTransport()
    old = incident(1, created=ago(days=60))
    transport.incidents = [old]
    poller = _poller(transport, record)
    await poller._drain_once()
    assert _events("acme-corp") == [] and poller.tracked == 1

    transport.incidents = [resolved(old)]
    await poller._drain_once()
    rows = _events("acme-corp")
    assert [r["summary"] for r in rows] == ["RocketCyber · Suspicious PowerShell execution 1 — resolved"]


@pytest.mark.asyncio
async def test_an_open_incident_that_vanishes_entirely_stops_being_tracked(bedrock_root):  # noqa: F811
    record = _mapped_instance()
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1, created=ago(days=30)), incident(2)]
    poller = _poller(transport, record)
    await poller._drain_once()
    assert poller.tracked == 2
    transport.incidents = transport.incidents[1:]          # deleted in RocketCyber
    await poller._drain_once()
    assert poller.tracked == 1 and len(_events("acme-corp")) == 1


@pytest.mark.asyncio
async def test_a_truncated_closure_lookup_proves_nothing(bedrock_root, monkeypatch):  # noqa: F811
    record = _mapped_instance()
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1, created=ago(days=30))]
    poller = _poller(transport, record)
    await poller._drain_once()
    transport.incidents = []
    monkeypatch.setattr(poller, "_read_closed_around", lambda day: ([], False))
    await poller._drain_once()
    assert poller.tracked == 1                   # still waiting for its closure


@pytest.mark.asyncio
async def test_closure_lookups_are_bounded_per_cycle_and_drain(bedrock_root):  # noqa: F811
    from apps.octo.adapters.rocketcyber.poller import MAX_RECHECK_DAYS_PER_CYCLE

    record = _mapped_instance()
    transport = FakeRocketCyberTransport()
    # 15 open incidents, three days apart (each lookup finds only its own).
    olds = [incident(n, created=ago(days=20 + 3 * n)) for n in range(1, 16)]
    transport.incidents = list(olds)
    poller = _poller(transport, record)
    await poller._drain_once()
    assert poller.tracked == 15

    transport.incidents = [resolved(i) for i in olds]
    transport.queries.clear()
    await poller._drain_once()
    # 3 cycle reads + 2 per looked-up date, never more than the bound.
    assert len(transport.incident_queries()) == 3 + 2 * MAX_RECHECK_DAYS_PER_CYCLE
    assert len(_events("acme-corp")) == MAX_RECHECK_DAYS_PER_CYCLE
    await poller._drain_once()
    assert len(_events("acme-corp")) == 15
    await poller._drain_once()
    assert len(_events("acme-corp")) == 15 and poller.tracked == 0


@pytest.mark.asyncio
async def test_resolutions_arrive_even_if_an_unfiltered_listing_were_open_only(bedrock_root):  # noqa: F811
    record = _mapped_instance()
    transport = FakeRocketCyberTransport()
    transport.default_status = "open"          # the default was never observed
    original = incident(1)
    transport.incidents = [original]
    poller = _poller(transport, record)
    await poller._drain_once()
    transport.incidents = [resolved(original)]
    await poller._drain_once()
    assert [r["severity"] for r in _events("acme-corp")] == ["high", "medium"]


# ---------------------------------------------------------------------------
# Restarts
# ---------------------------------------------------------------------------

def _backdate_instance(record, *, days: float) -> None:
    """The instance was saved `days` ago (it has been polling since)."""
    from apps.octo.ingest.timestamps import format_utc_ms

    reg = sqlite3.connect(paths.registry_db_path())
    try:
        reg.execute(
            "UPDATE adapter_instances SET configured_at = ? WHERE id = ?",
            (format_utc_ms(datetime.now(timezone.utc) - timedelta(days=days)), record.id),
        )
        reg.commit()
    finally:
        reg.close()


@pytest.mark.asyncio
async def test_a_restart_does_not_re_store_what_changed_only_in_ways_that_are_not_a_version(bedrock_root):  # noqa: F811
    """RocketCyber → PSA attaches a ticket minutes after creation (updatedAt
    moves; a new payload). Across a restart that used to be a second,
    identical HIGH row for nearly every incident."""
    record = _mapped_instance()
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(n) for n in range(1, 6)]
    await _poller(transport, record)._drain_once()
    assert len(_events("acme-corp")) == 5

    transport.incidents = [
        changed(i, psaId=f"T{n}", eventCount=9) for n, i in enumerate(transport.incidents)
    ]
    restarted = _poller(transport, record)
    await restarted._drain_once()
    assert len(_events("acme-corp")) == 5
    assert restarted.tracked == 5

    transport.incidents[0] = resolved(transport.incidents[0])
    await restarted._drain_once()
    assert [r["severity"] for r in _events("acme-corp")] == ["high"] * 5 + ["medium"]


@pytest.mark.asyncio
async def test_a_status_change_made_while_athena_was_down_is_not_taken_for_history(bedrock_root):  # noqa: F811
    """Stored open when it was 2 days old; resolved while Athena was down,
    when it was 10 days old — past the 7-day first-run bound."""
    record = _mapped_instance()
    _backdate_instance(record, days=30)
    transport = FakeRocketCyberTransport()
    original = incident(1, created=ago(days=10))
    transport.incidents = [original]
    await _poller(transport, record)._drain_once()
    assert len(_events("acme-corp")) == 1

    transport.incidents = [resolved(original)]
    restarted = _poller(transport, record)
    await restarted._drain_once()
    rows = _events("acme-corp")
    assert len(rows) == 2 and rows[1]["summary"].endswith("execution 1 — resolved")


@pytest.mark.asyncio
async def test_history_is_judged_by_the_newest_timestamp_even_without_the_store(
    bedrock_root, monkeypatch,  # noqa: F811
):
    """Even when the stored rows cannot be read, a recent change is never
    history: the rule looks at updatedAt / resolvedAt, not only createdAt."""
    record = _mapped_instance()

    def _unreadable(self, now):
        raise sqlite3.OperationalError("fixture: the store cannot be read")

    monkeypatch.setattr(RocketCyberPoller, "_stored_versions", _unreadable)
    transport = FakeRocketCyberTransport()
    busy = incident(1, created=ago(days=8), updated=ago(hours=1))   # still active
    quiet = incident(2, created=ago(days=8))                        # untouched since
    transport.incidents = [busy, quiet]
    poller = _poller(transport, record)
    await poller._drain_once()
    assert [r["summary"] for r in _events("acme-corp")] == [
        "RocketCyber · Suspicious PowerShell execution 1"]

    transport.incidents = [resolved(busy), resolved(quiet)]
    restarted = _poller(transport, record)
    await restarted._drain_once()
    assert sorted(r["summary"] for r in _events("acme-corp"))[1:] == [
        "RocketCyber · Suspicious PowerShell execution 1 — resolved",
        "RocketCyber · Suspicious PowerShell execution 2 — resolved",
    ]


@pytest.mark.asyncio
async def test_a_restart_keeps_tracking_an_open_incident_older_than_the_window(bedrock_root):  # noqa: F811
    record = _mapped_instance()
    _backdate_instance(record, days=60)
    transport = FakeRocketCyberTransport()
    original = incident(1, created=ago(days=40))
    transport.incidents = [original]
    await _poller(transport, record)._drain_once()          # stored open back then
    assert len(_events("acme-corp")) == 1

    restarted = _poller(transport, record)
    assert restarted.tracked == 0
    await restarted._drain_once()
    assert restarted.tracked == 1 and len(_events("acme-corp")) == 1
    transport.incidents = [resolved(original)]
    await restarted._drain_once()
    assert len(_events("acme-corp")) == 2


def test_restart_seeding_reads_through_the_summary_index(bedrock_root):  # noqa: F811
    """A tenant's events.db holds every source's events; the seed must not
    scan them all."""
    from apps.octo.adapters.rocketcyber.poller import _SEED_PARAMS, _SEED_SQL
    from apps.octo.adapters.rocketcyber.presentation import HEADLINE_PREFIX, present_incident

    create_client("acme-corp", "Acme Corp")
    conn = sqlite3.connect(paths.client_dir("acme-corp") / "events.db")
    try:
        plan = " ".join(str(r[-1]) for r in conn.execute(f"EXPLAIN QUERY PLAN {_SEED_SQL}", _SEED_PARAMS))
    finally:
        conn.close()
    assert "idx_events_summary" in plan, plan
    # …which only works while every headline starts with the prefix.
    for raw in (incident(1), resolved(incident(2)), {"id": 3}, {}, "junk"):
        assert present_incident(raw).headline.startswith(HEADLINE_PREFIX)


# ---------------------------------------------------------------------------
# A customer id is never a client slug
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_an_unmapped_customer_never_lands_in_a_client_whose_slug_is_its_id(bedrock_root):  # noqa: F811
    record = _instance()
    create_client("2002", "Some Other Customer")        # e.g. named by a PSA number
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1, account_id=2002, account_name="Example Bakery")]
    await _poller(transport, record)._drain_once()
    assert _events("2002") == []
    assert len(_events("example-bakery")) == 1           # auto-created, as for any unknown customer
    (m,) = tenant_map.get_mappings(record.id)
    assert (m.vendor_tenant_id, m.octo_client_slug, m.match_source) == (
        "2002", "example-bakery", "auto")


def test_pass_through_stays_for_adapters_whose_ids_are_slugs(bedrock_root):  # noqa: F811
    from apps.octo.instances.tenant_autocreate import resolve_tenant

    record = _instance()
    create_client("2002", "Some Other Customer")
    common = dict(
        instance_id=record.id, vendor_slug="rocketcyber", vendor_tenant_id="2002",
        vendor_tenant_label=None, default_tenant_slug=None, supports_discovery=True,
    )
    assert resolve_tenant(**common).outcome == "passthrough"
    refused = resolve_tenant(**common, allow_passthrough=False)
    assert refused.slug is None and refused.reason == "name-unknown"


# ---------------------------------------------------------------------------
# History-skipped incidents survive a restart (v0.11 R3)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_history_skipped_incident_does_not_resurface_after_a_restart(bedrock_root):  # noqa: F811
    """Skipped as history at first connect (never stored). Its updatedAt
    later moves — a PSA ticket, a growing event count — which is not a new
    version. A restart used to forget it (the seed read stored rows only)
    and stored it as a brand-new HIGH row; the skip is persisted now."""
    from apps.octo.instances import poller_state

    record = _mapped_instance()
    transport = FakeRocketCyberTransport()
    old = incident(1, created=ago(days=60))
    transport.incidents = [old]
    await _poller(transport, record)._drain_once()
    assert _events("acme-corp") == []
    marks = poller_state.load(record.id, "history_skipped")
    assert marks == {"5001": ["open", None, old["createdAt"]]}

    transport.incidents = [changed(old, psaId="T77", eventCount=12)]
    restarted = _poller(transport, record)
    await restarted._drain_once()
    assert _events("acme-corp") == []                      # not a new HIGH row
    assert restarted.tracked == 1

    # Its closure is still news — after another restart, too.
    transport.incidents = [resolved(transport.incidents[0])]
    again = _poller(transport, record)
    await again._drain_once()
    rows = _events("acme-corp")
    assert [(r["severity"], r["summary"]) for r in rows] == [
        ("medium", "RocketCyber · Suspicious PowerShell execution 1 — resolved")]
    # Delivered now: no longer a history mark (a stored version tracks it).
    assert poller_state.load(record.id, "history_skipped") == {}


@pytest.mark.asyncio
async def test_history_marks_follow_the_map_and_a_registry_fault_is_harmless(
    bedrock_root,  # noqa: F811
):
    """The persisted marks hold only what is still tracked; a registry that
    cannot be written never stops the poll (the poller behaves as before)."""
    from apps.octo.instances import poller_state

    record = _mapped_instance()
    transport = FakeRocketCyberTransport()
    a = incident(1, created=ago(days=60))
    b = incident(2, created=ago(days=61))
    transport.incidents = [a, b]
    poller = _poller(transport, record)
    await poller._drain_once()
    assert set(poller_state.load(record.id, "history_skipped")) == {"5001", "5002"}
    transport.incidents = [a]                          # b deleted in RocketCyber
    await poller._drain_once()
    assert set(poller_state.load(record.id, "history_skipped")) == {"5001"}

    # A registry that cannot be written (read-only file): the poll goes on.
    import os

    reg = paths.registry_db_path()
    files = [f for f in reg.parent.glob("registry.db*")]
    for f in files:
        os.chmod(f, 0o444)
    try:
        transport.incidents = [a, incident(3, created=ago(days=62))]
        await poller._drain_once()                      # no exception
    finally:
        for f in files:
            os.chmod(f, 0o644)
    assert poller.tracked == 2 and _events("acme-corp") == []
    # Not persisted then — and written on the next cycle that can.
    assert set(poller_state.load(record.id, "history_skipped")) == {"5001"}
    await poller._drain_once()
    assert set(poller_state.load(record.id, "history_skipped")) == {"5001", "5003"}


# ---------------------------------------------------------------------------
# A PSA ticket attached after the alert was stored (v0.11 R4)
# ---------------------------------------------------------------------------

def _psa_notes(slug: str) -> list[tuple]:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        return conn.execute(
            "SELECT ref_kind, ref_id, agent_id, query_kind, disposition, note_text "
            "FROM agent_notes WHERE query_kind = 'vendor_update' ORDER BY id").fetchall()
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_a_late_psa_ticket_is_recorded_on_the_stored_row_without_a_new_alert(bedrock_root):  # noqa: F811
    """RocketCyber fills psaId minutes after the incident was stored. That is
    not a new version — no new alert row — but it is recorded on the stored
    row (a note), once, across restarts; the row's identity (payload, its
    sha, received_at) is untouched."""
    record = _mapped_instance()
    transport = FakeRocketCyberTransport()
    first = incident(1)                         # psaId None at first report
    transport.incidents = [first]
    poller = _poller(transport, record)
    await poller._drain_once()
    [row] = _events("acme-corp")
    identity = (row["payload"], row["payload_sha256"], row["received_at"])

    transport.incidents = [changed(first, psaId="T77")]
    await poller._drain_once()
    await poller._drain_once()                  # the next cycle: nothing more
    rows = _events("acme-corp")
    assert len(rows) == 1
    assert (rows[0]["payload"], rows[0]["payload_sha256"], rows[0]["received_at"]) == identity
    [note] = _psa_notes("acme-corp")
    assert note[:5] == ("event", row["id"], "octo", "vendor_update", None)
    assert "PSA ticket T77" in note[5] and "no new alert row" in note[5]

    # A restart: the note is found again, not written twice.
    restarted = _poller(transport, record)
    await restarted._drain_once()
    assert len(_psa_notes("acme-corp")) == 1 and len(_events("acme-corp")) == 1

    # A different ticket later: noted too. The closure is a new version as
    # before — and its row carries the ticket in its own payload (no note).
    transport.incidents = [changed(transport.incidents[0], psaId="T78")]
    await restarted._drain_once()
    assert [n[5].split(" to ")[0] for n in _psa_notes("acme-corp")] == [
        "RocketCyber attached PSA ticket T77", "RocketCyber attached PSA ticket T78"]
    transport.incidents = [resolved(transport.incidents[0])]
    await restarted._drain_once()
    await restarted._drain_once()
    assert len(_events("acme-corp")) == 2 and len(_psa_notes("acme-corp")) == 2


@pytest.mark.asyncio
async def test_a_psa_ticket_in_the_first_report_needs_no_note(bedrock_root):  # noqa: F811
    record = _mapped_instance()
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1, psa_id="T5")]
    poller = _poller(transport, record)
    await poller._drain_once()
    await poller._drain_once()
    assert len(_events("acme-corp")) == 1 and _psa_notes("acme-corp") == []
