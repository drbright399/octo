"""Auto-link / auto-create / quarantine on the POLL path — end to end on the
real pieces: a persisted adapter_instances row, the real DattoSourceAdapter /
DattoClient / DattoPoller, the real registry, the real ingest sink and the
real quarantine store. Only the vendor socket is fake (tests/fake_datto.py).

What used to happen: an alert whose siteUid mapped to no client was DROPPED
and counted. Now every one lands somewhere — a tenant (existing or new) or
the quarantine bucket — under the product rulings pinned here.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import threading

import pytest

from apps.octo import paths
from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.adapters.datto.poller import DattoPoller
from apps.octo.adapters.datto.tests.fake_datto import (
    CREDS,
    FakeDattoTransport,
    client_factory,
    real_client,
)
from apps.octo.auth import audit
from apps.octo.client_provisioning import create_client
from apps.octo.db import connect
from apps.octo.ingest import SqliteIngestSink
from apps.octo.instances import (
    create_instance,
    quarantine,
    tenant_autocreate,
    tenant_map,
    vendor_tenants,
)
from apps.octo.instances.manager import disable_instance
from apps.octo.instances.tenant_map import MappingIngestSink
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401


@pytest.fixture(autouse=True)
def _clean_state():
    quarantine.reset_schema_cache()
    vendor_tenants.reset()
    yield
    quarantine.reset_schema_cache()
    vendor_tenants.reset()


def _api_alert(n: int, *, site_uid: str, site_name: str | None = "Acme Corp", ts=1700000000):
    """A /api/v2 alert object, as the poller feeds it."""
    asi = {"siteUid": site_uid, "deviceName": f"WS-{n:02d}"}
    if site_name is not None:
        asi["siteName"] = site_name
    return {
        "alertUid": f"alert-{n}", "priority": "High", "timestamp": ts + n,
        "alertSourceInfo": asi,
        "alertContext": {"@class": "eventlog_ctx", "message": f"event {n}"},
    }


def _instance(**config):
    return create_instance(
        vendor_slug="datto", display_name="Datto RMM", credentials_dict=dict(CREDS),
        instance_config={"poll_interval_sec": 0.01, **config},
    )


def _poller(transport: FakeDattoTransport, record, *, default: str | None = None) -> DattoPoller:
    return DattoPoller(
        adapter=DattoSourceAdapter(client_factory=client_factory(transport)),
        client=real_client(transport),
        sink=MappingIngestSink(SqliteIngestSink(publish_to_stream=False), record.id),
        default_tenant_slug=default or "_unmapped",
        initial_cursor="2023-01-01T00:00:00.000Z",
        instance_id=record.id,
    )


def _clients() -> dict[str, dict]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        rows = reg.execute(
            "SELECT slug, display_name, status, origin, kind, review_state, "
            "created_by_instance_id, ai_policy FROM clients",
        ).fetchall()
    finally:
        reg.close()
    return {r["slug"]: dict(r) for r in rows}


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


def _audit_actions() -> list[tuple[str, str, str]]:
    g = connect(paths.global_audit_db_path(), read_only=True)
    try:
        return [
            (r["action"], r["actor"], r["target_id"])
            for r in g.execute("SELECT action, actor, target_id FROM audit_log ORDER BY id")
        ]
    finally:
        g.close()


# ---------------------------------------------------------------------------
# Auto-create
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unmapped_site_with_a_name_becomes_a_pending_tenant(bedrock_root, caplog):  # noqa: F811
    record = _instance()
    transport = FakeDattoTransport()
    transport.alerts = [
        _api_alert(1, site_uid="site-uid-0001", site_name="Acme Corp"),
        _api_alert(2, site_uid="site-uid-0001", site_name="Acme Corp"),
    ]
    with caplog.at_level("INFO"):
        await _poller(transport, record)._drain_once()

    clients = _clients()
    assert "acme-corp" in clients
    row = clients["acme-corp"]
    assert row["display_name"] == "Acme Corp"
    assert (row["origin"], row["kind"], row["review_state"]) == ("auto", "unclassified", "pending")
    assert row["created_by_instance_id"] == record.id and row["ai_policy"] == "none"
    assert row["status"] == "active"
    # Its DBs exist and BOTH alerts landed there with the adapter's own shape.
    events = _events("acme-corp")
    assert [e["event_type"] for e in events] == ["datto.eventlog", "datto.eventlog"]
    assert events[0]["summary"].startswith("Event log")
    # The mapping is written with match_source 'auto' and the vendor's name.
    (m,) = tenant_map.get_mappings(record.id)
    assert (m.vendor_tenant_id, m.octo_client_slug, m.match_source, m.vendor_tenant_label) == (
        "site-uid-0001", "acme-corp", "auto", "Acme Corp")
    # Audited with the integration as the actor — once, not per alert.
    assert _audit_actions() == [
        ("tenant_auto_create", f"adapter-instance:{record.id}", "acme-corp"),
    ]
    assert audit.verify(connect(paths.global_audit_db_path()))[0] is True
    assert quarantine.counts(record.id)["held"] == 0
    assert "DROPPED" not in caplog.text
    assert tenant_autocreate.autocreate_status(record.id) == {
        "created_last_hour": 1, "pending": 1, "limited": False,
    }


@pytest.mark.asyncio
async def test_slug_collision_gets_a_numeric_suffix_and_never_reuses_an_old_slug(bedrock_root):  # noqa: F811
    record = _instance()
    create_client("acme-corp", "Some Other Business")            # slug taken, name differs
    reg = connect(paths.registry_db_path())
    reg.execute("INSERT INTO clients (slug, display_name, status, offboarded_at, kind) "
                "VALUES ('acme-corp-2', 'Gone', 'offboarded', '2026-01-01T00:00:00.000Z', 'client')")
    reg.commit(); reg.close()

    transport = FakeDattoTransport()
    transport.alerts = [_api_alert(1, site_uid="site-uid-0009", site_name="Acme Corp")]
    await _poller(transport, record)._drain_once()

    clients = _clients()
    assert "acme-corp-3" in clients and clients["acme-corp-3"]["origin"] == "auto"
    assert clients["acme-corp-2"]["status"] == "offboarded"     # untouched
    assert tenant_map.resolve(record.id, "site-uid-0009") == "acme-corp-3"


@pytest.mark.asyncio
async def test_concurrent_deliveries_for_one_new_site_create_one_tenant(bedrock_root):  # noqa: F811
    record = _instance()
    adapter = DattoSourceAdapter()
    sink = SqliteIngestSink(publish_to_stream=False)
    envelopes = [_api_alert(n, site_uid="site-uid-0042", site_name="Widget Co") for n in range(8)]
    results: list = []
    errors: list = []

    def _one(env):
        try:
            results.append(tenant_autocreate.deliver(
                instance_id=record.id, vendor_slug="datto", adapter=adapter, envelope=env,
                event=adapter.extract_event(env), sink=sink, default_tenant_slug=None,
                door="poll",
            ))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_one, args=(env,)) for env in envelopes]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    created = [r for r in results if r.outcome == "auto-created"]
    assert len(created) == 1
    assert all(r.status == "stored" and r.slug == "widget-co" for r in results)
    assert [s for s in _clients() if s.startswith("widget")] == ["widget-co"]
    assert len(_events("widget-co")) == 8
    assert _audit_actions().count(("tenant_auto_create", f"adapter-instance:{record.id}", "widget-co")) == 1


@pytest.mark.asyncio
async def test_hourly_cap_holds_further_new_sites_and_flags_the_card(bedrock_root, monkeypatch):  # noqa: F811
    monkeypatch.setattr(tenant_autocreate, "AUTOCREATE_PER_HOUR", 2)
    record = _instance()
    transport = FakeDattoTransport()
    transport.alerts = [
        _api_alert(n, site_uid=f"site-uid-{n:04d}", site_name=f"Business {n}") for n in range(1, 5)
    ]
    await _poller(transport, record)._drain_once()

    made = sorted(s for s in _clients() if s.startswith("business-"))
    assert made == ["business-1", "business-2"]
    held, total = quarantine.list_rows(instance_id=record.id)
    assert total == 2 and {r.reason for r in held} == {"autocreate-limit"}
    assert {r.vendor_tenant_id for r in held} == {"site-uid-0003", "site-uid-0004"}
    assert {r.vendor_tenant_label for r in held} == {"Business 3", "Business 4"}
    st = tenant_autocreate.autocreate_status(record.id)
    assert st["limited"] is True and st["created_last_hour"] == 2
    lines = tenant_autocreate.card_warnings(record.id, "Datto RMM")
    assert any("PAUSED" in line for line in lines)
    assert any("2 tenant(s) were created" in line for line in lines)

    # Reviewing does not lift the HOURLY bound (that one needs the hour to pass) …
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET review_state = 'confirmed', kind = 'client'")
    reg.commit(); reg.close()
    assert tenant_autocreate.autocreate_status(record.id)["limited"] is True
    # … but a poll after the hour creates the rest, and the same alerts are
    # not held twice meanwhile.
    await _poller(transport, record)._drain_once()
    assert quarantine.list_rows(instance_id=record.id)[1] == 2
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET onboarded_at = '2020-01-01T00:00:00.000Z'")
    reg.commit(); reg.close()
    await _poller(transport, record)._drain_once()
    assert sorted(s for s in _clients() if s.startswith("business-")) == [
        "business-1", "business-2", "business-3", "business-4"]


@pytest.mark.asyncio
async def test_pending_review_cap_holds_new_sites(bedrock_root, monkeypatch):  # noqa: F811
    monkeypatch.setattr(tenant_autocreate, "AUTOCREATE_MAX_PENDING", 1)
    record = _instance()
    transport = FakeDattoTransport()
    transport.alerts = [
        _api_alert(1, site_uid="site-uid-0001", site_name="First"),
        _api_alert(2, site_uid="site-uid-0002", site_name="Second"),
    ]
    await _poller(transport, record)._drain_once()
    assert "first" in _clients() and "second" not in _clients()
    assert quarantine.list_rows(instance_id=record.id, reason="autocreate-limit")[1] == 1
    # A human confirms the first → the bound frees → the next poll creates the second.
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET review_state = 'confirmed', kind = 'client' WHERE slug = 'first'")
    reg.commit(); reg.close()
    await _poller(transport, record)._drain_once()
    assert "second" in _clients()


@pytest.mark.asyncio
async def test_pending_cap_counts_active_tenants_only(bedrock_root, monkeypatch):  # noqa: F811
    """A pending auto-created tenant that was merged (archived) or offboarded
    is off the reviewer's plate: it must not hold a cap slot for good, or
    auto-create pauses permanently after enough merges."""
    monkeypatch.setattr(tenant_autocreate, "AUTOCREATE_MAX_PENDING", 1)
    record = _instance()
    transport = FakeDattoTransport()
    transport.alerts = [
        _api_alert(1, site_uid="site-uid-0001", site_name="First"),
        _api_alert(2, site_uid="site-uid-0002", site_name="Second"),
    ]
    await _poller(transport, record)._drain_once()
    assert "first" in _clients() and "second" not in _clients()
    assert tenant_autocreate.autocreate_status(record.id) == {
        "created_last_hour": 1, "pending": 1, "limited": True}
    # 'first' is merged away (archived, review_state still 'pending' — no
    # one can confirm an archived row) → the slot frees.
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = 'archived', archived_at = '2026-01-01T00:00:00.000Z' "
                "WHERE slug = 'first'")
    reg.commit(); reg.close()
    assert tenant_autocreate.autocreate_status(record.id)["pending"] == 0
    await _poller(transport, record)._drain_once()
    assert "second" in _clients()
    # Same for an offboarded pending tenant.
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = 'offboarded' WHERE slug = 'second'")
    reg.commit(); reg.close()
    assert tenant_autocreate.autocreate_status(record.id)["pending"] == 0


# ---------------------------------------------------------------------------
# A name is a suggestion, never a link (the same-name rule, 2026-10-01)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_the_same_name_is_held_with_a_suggestion_never_linked(bedrock_root):  # noqa: F811
    """A vendor site whose name is the SAME NAME as one client (case and
    punctuation aside) used to be linked to it by itself. Two businesses can
    share a name: it is now held, with that client as a one-click
    suggestion for a human — no mapping, no event in the client's store."""
    record = _instance()
    create_client("acme-pharmacy", "Acme Pharmacy, Inc.")        # a hand-typed tenant
    transport = FakeDattoTransport()
    transport.alerts = [_api_alert(1, site_uid="site-uid-0001", site_name="ACME PHARMACY INC")]
    await _poller(transport, record)._drain_once()

    assert set(_clients()) == {"acme-pharmacy"}                 # nothing new
    assert tenant_map.get_mappings(record.id) == []            # nothing linked
    assert _events("acme-pharmacy") == []
    rows, total = quarantine.list_rows(instance_id=record.id)
    assert total == 1 and rows[0].reason == "name-match-suggested"
    assert (rows[0].vendor_tenant_id, rows[0].vendor_tenant_label) == (
        "site-uid-0001", "ACME PHARMACY INC")
    sug = tenant_autocreate.name_suggestions(["ACME PHARMACY INC"])
    assert sug == {"ACME PHARMACY INC": tenant_autocreate.NameSuggestion("acme-pharmacy",
                                                                       "Acme Pharmacy, Inc.")}
    assert _audit_actions() == []                # nothing happened by itself
    # Polled again: held once, still nothing linked.
    await _poller(transport, record)._drain_once()
    assert quarantine.counts(record.id)["held"] == 1 and tenant_map.get_mappings(record.id) == []
    # Once a human maps the site, its traffic routes like any other.
    tenant_map.set_mappings(record.id, [tenant_map.TenantMapping("site-uid-0001", "acme-pharmacy")])
    transport.alerts = [_api_alert(2, site_uid="site-uid-0001", site_name="ACME PHARMACY INC")]
    await _poller(transport, record)._drain_once()
    assert len(_events("acme-pharmacy")) == 1


@pytest.mark.asyncio
async def test_a_different_legal_suffix_is_a_different_business(bedrock_root):  # noqa: F811
    """"Acme Pharmacy, Inc." is not "Acme Pharmacy LLC": legal suffixes are never
    stripped into equality. The look-alike gets its OWN new tenant, pending
    review (the tenant manager's duplicate hint shows the pair) — its events
    never reach the existing client."""
    record = _instance()
    create_client("acme-pharmacy", "Acme Pharmacy, Inc.")
    transport = FakeDattoTransport()
    transport.alerts = [_api_alert(1, site_uid="site-uid-0002", site_name="Acme Pharmacy LLC")]
    await _poller(transport, record)._drain_once()

    clients = _clients()
    assert set(clients) == {"acme-pharmacy", "acme-pharmacy-llc"}
    assert (clients["acme-pharmacy-llc"]["origin"], clients["acme-pharmacy-llc"]["review_state"]) == (
        "auto", "pending")
    assert _events("acme-pharmacy") == [] and len(_events("acme-pharmacy-llc")) == 1
    assert tenant_map.resolve(record.id, "site-uid-0002") == "acme-pharmacy-llc"
    assert quarantine.counts(record.id)["held"] == 0
    # The only same-name client of "Acme Pharmacy LLC" is its own new tenant.
    assert tenant_autocreate.name_suggestions(["Acme Pharmacy LLC"])["Acme Pharmacy LLC"].slug == (
        "acme-pharmacy-llc")


@pytest.mark.asyncio
async def test_ambiguous_name_is_quarantined_not_guessed(bedrock_root):  # noqa: F811
    record = _instance()
    create_client("acme-east", "Acme Corp")
    create_client("acme-west", "ACME CORP.")
    transport = FakeDattoTransport()
    transport.alerts = [_api_alert(1, site_uid="site-uid-0001", site_name="Acme Corp")]
    await _poller(transport, record)._drain_once()

    assert set(_clients()) == {"acme-east", "acme-west"}
    assert tenant_map.get_mappings(record.id) == []
    rows, total = quarantine.list_rows(instance_id=record.id)
    assert total == 1 and rows[0].reason == "ambiguous-name"
    assert rows[0].vendor_tenant_label == "Acme Corp" and rows[0].source == "poll"
    assert rows[0].event_summary.startswith("Event log")
    assert _events("acme-east") == [] and _events("acme-west") == []
    assert _audit_actions() == []                # nothing was created or linked


@pytest.mark.asyncio
async def test_a_second_site_matching_an_already_mapped_client_is_held_for_a_human(bedrock_root):  # noqa: F811
    """A second site whose name is the same name as a client that is
    already mapped here may be a branch office — or a guessable name on a
    compromised feed — so it is held as 'name-already-mapped' (with the
    client as a suggestion), never linked by itself."""
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    tenant_map.set_mappings(record.id, [tenant_map.TenantMapping("site-uid-a", "acme-corp")])
    transport = FakeDattoTransport()
    transport.alerts = [
        _api_alert(1, site_uid="site-uid-a", site_name="Acme Corp"),      # the mapped site
        _api_alert(2, site_uid="site-uid-b", site_name="ACME CORP."),     # a look-alike
    ]
    await _poller(transport, record)._drain_once()

    assert len(_events("acme-corp")) == 1                                 # only site-uid-a's
    assert {m.vendor_tenant_id for m in tenant_map.get_mappings(record.id)} == {"site-uid-a"}
    rows, total = quarantine.list_rows(instance_id=record.id)
    assert total == 1 and rows[0].reason == "name-already-mapped"
    assert rows[0].vendor_tenant_id == "site-uid-b" and rows[0].vendor_tenant_label == "ACME CORP."
    assert tenant_autocreate.name_suggestions(["ACME CORP."])["ACME CORP."].slug == "acme-corp"
    assert _audit_actions() == []                # no auto-link row: nothing happened by itself
    # Once a human maps the second site there, its traffic routes like any other.
    tenant_map.set_mappings(record.id, [
        tenant_map.TenantMapping("site-uid-a", "acme-corp"),
        tenant_map.TenantMapping("site-uid-b", "acme-corp"),
    ])
    transport.alerts = [_api_alert(3, site_uid="site-uid-b", site_name="ACME CORP.")]
    await _poller(transport, record)._drain_once()
    assert len(_events("acme-corp")) == 2 and quarantine.counts(record.id)["held"] == 1


# ---------------------------------------------------------------------------
# Offboarded tenants are never resurrected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_offboarded_tenant_name_quarantines_and_is_never_recreated(bedrock_root):  # noqa: F811
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = 'offboarded', offboarded_at = '2026-01-01T00:00:00.000Z' "
                "WHERE slug = 'acme-corp'")
    reg.commit(); reg.close()
    transport = FakeDattoTransport()
    transport.alerts = [_api_alert(1, site_uid="site-uid-0001", site_name="Acme Corp")]
    for _ in range(3):
        await _poller(transport, record)._drain_once()

    assert set(_clients()) == {"acme-corp"} and _clients()["acme-corp"]["status"] == "offboarded"
    rows, total = quarantine.list_rows(instance_id=record.id)
    assert total == 1 and rows[0].reason == "offboarded-tenant"     # held ONCE
    assert _events("acme-corp") == []


@pytest.mark.asyncio
async def test_mapping_to_a_non_active_tenant_quarantines(bedrock_root):  # noqa: F811
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    tenant_map.set_mappings(record.id, [tenant_map.TenantMapping("site-uid-0001", "acme-corp")])
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = 'disabled' WHERE slug = 'acme-corp'")
    reg.commit(); reg.close()
    transport = FakeDattoTransport()
    transport.alerts = [_api_alert(1, site_uid="site-uid-0001", site_name="Acme Corp")]
    await _poller(transport, record)._drain_once()
    rows, total = quarantine.list_rows(instance_id=record.id)
    assert total == 1 and rows[0].reason == "offboarded-tenant"
    assert _events("acme-corp") == []


# ---------------------------------------------------------------------------
# No name / no id
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_site_name_holds_as_name_unknown_until_discovery_fills_the_cache(bedrock_root):  # noqa: F811
    record = _instance()
    transport = FakeDattoTransport()
    transport.alerts = [_api_alert(1, site_uid="site-uid-0001", site_name=None)]
    await _poller(transport, record)._drain_once()
    rows, total = quarantine.list_rows(instance_id=record.id)
    assert total == 1 and rows[0].reason == "name-unknown"
    assert _clients() == {}                       # no placeholder for a discoverable vendor
    assert transport.count("/api/v2/account/sites") == 0   # never a live vendor call on ingest

    # The manager opens the mapping panel (Reload) → the cache knows the name.
    listing = DattoSourceAdapter(client_factory=client_factory(transport)).list_vendor_tenants(CREDS)
    vendor_tenants.store(record.id, record.cred_ref, listing)
    await _poller(transport, record)._drain_once()
    assert "example-site" in _clients()            # named from discovery
    assert tenant_map.resolve(record.id, "site-uid-0001") == "example-site"
    assert quarantine.list_rows(instance_id=record.id)[1] == 1   # the earlier hold stays for review


@pytest.mark.asyncio
async def test_no_tenant_id_uses_the_instance_default_else_quarantines(bedrock_root):  # noqa: F811
    record = _instance()
    transport = FakeDattoTransport()
    alert = _api_alert(1, site_uid="", site_name=None)
    del alert["alertSourceInfo"]["siteUid"]
    transport.alerts = [alert]
    await _poller(transport, record)._drain_once()
    rows, total = quarantine.list_rows(instance_id=record.id)
    assert total == 1 and rows[0].reason == "no-tenant-id" and rows[0].vendor_tenant_id is None

    create_client("catch-all", "Catch All")
    await _poller(transport, record, default="catch-all")._drain_once()
    assert len(_events("catch-all")) == 1


@pytest.mark.asyncio
async def test_an_offboarded_instance_default_never_receives_traffic(bedrock_root):  # noqa: F811
    """The default is a mapping like any other: once that tenant is not
    active, an id-less event holds as 'offboarded-tenant' instead of landing
    in the departed client's store (the mapped and pass-through paths already
    refused; the default path must too)."""
    record = _instance()
    create_client("catch-all", "Catch All")
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = 'offboarded', offboarded_at = '2026-01-01T00:00:00.000Z' "
                "WHERE slug = 'catch-all'")
    reg.commit(); reg.close()
    transport = FakeDattoTransport()
    alert = _api_alert(1, site_uid="", site_name=None)
    del alert["alertSourceInfo"]["siteUid"]
    transport.alerts = [alert]
    await _poller(transport, record, default="catch-all")._drain_once()
    assert _events("catch-all") == []
    rows, total = quarantine.list_rows(instance_id=record.id)
    assert total == 1 and rows[0].reason == "offboarded-tenant" and rows[0].vendor_tenant_id is None


@pytest.mark.asyncio
async def test_adapter_without_discovery_gets_a_placeholder_tenant(bedrock_root):  # noqa: F811
    record = _instance()

    class _NoDiscovery(DattoSourceAdapter):
        supports_tenant_discovery = False

        def vendor_tenant_label(self, raw_envelope):
            return None

    adapter = _NoDiscovery()
    env = _api_alert(1, site_uid="0a1b2c3d-1111-2222-3333-444455556666", site_name=None)
    delivery = tenant_autocreate.deliver(
        instance_id=record.id, vendor_slug="datto", adapter=adapter, envelope=env,
        event=adapter.extract_event(env), sink=SqliteIngestSink(publish_to_stream=False),
        default_tenant_slug=None, door="poll",
    )
    assert delivery.status == "stored" and delivery.outcome == "auto-created"
    row = _clients()[delivery.slug]
    assert row["display_name"] == "datto site 0a1b2c3d" and row["review_state"] == "pending"


@pytest.mark.parametrize("site_uid, expect", [
    ("bad\x01id-0001", "datto site bad id-0"),      # control char → cleaned, still created
    ("\x01\x02\x03\x1f", "datto site"),             # nothing printable → the vendor part alone
])
def test_placeholder_name_is_cleaned_vendor_text_and_never_raises(bedrock_root, site_uid, expect):  # noqa: F811
    """The vendor id is vendor text too: a non-printable id must never make
    register_client raise out of deliver() (a 5xx the vendor retries for
    ever) — it is cleaned like any site name, and the event is stored or
    held, never lost."""
    record = _instance()

    class _NoDiscovery(DattoSourceAdapter):
        supports_tenant_discovery = False

        def vendor_tenant_label(self, raw_envelope):
            return None

    adapter = _NoDiscovery()
    env = _api_alert(1, site_uid=site_uid, site_name=None)
    delivery = tenant_autocreate.deliver(
        instance_id=record.id, vendor_slug="datto", adapter=adapter, envelope=env,
        event=adapter.extract_event(env), sink=SqliteIngestSink(publish_to_stream=False),
        default_tenant_slug=None, door="webhook",
    )
    assert delivery.status in ("stored", "quarantined")
    if delivery.status == "stored":
        assert delivery.outcome == "auto-created"
        assert _clients()[delivery.slug]["display_name"] == expect
        assert len(_events(delivery.slug)) == 1
    else:
        assert delivery.quarantine_created and _clients() == {}


def test_free_slug_fallback_is_always_a_valid_slug(bedrock_root):  # noqa: F811
    """After the numeric suffixes run out the uuid fallback must not glue a
    trailing hyphen onto a hyphen ('aaa--c519…' is not a slug)."""
    from apps.octo import client_provisioning

    base = "a" * 29 + "-z"
    reg = connect(paths.registry_db_path())
    reg.execute("INSERT INTO clients (slug, display_name, kind) VALUES (?, ?, 'client')", (base, "x"))
    for n in range(2, tenant_autocreate._MAX_SLUG_ATTEMPTS + 2):
        reg.execute("INSERT INTO clients (slug, display_name, kind) VALUES (?, ?, 'client')",
                    (f"{base}-{n}", "x"))
    reg.commit()
    out = tenant_autocreate.free_slug(reg, base)
    reg.close()
    assert out.startswith("a" * 29 + "-") and "--" not in out
    assert client_provisioning._SLUG_RE.match(out), out
    assert paths.SLUG_RE.match(out), out


# ---------------------------------------------------------------------------
# Disabled instance / pass-through / quarantine idempotency
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_disabled_instance_never_creates(bedrock_root):  # noqa: F811
    record = _instance()
    disable_instance(record.id, disabled_by_operator_id=None, reason="test")
    transport = FakeDattoTransport()
    transport.alerts = [_api_alert(1, site_uid="site-uid-0001", site_name="Acme Corp")]
    await _poller(transport, record)._drain_once()
    assert _clients() == {}
    rows, _ = quarantine.list_rows(instance_id=record.id)
    assert [r.reason for r in rows] == ["instance-disabled"]


@pytest.mark.asyncio
async def test_forwarder_stamped_slug_passes_through_to_that_client(bedrock_root):  # noqa: F811
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    transport = FakeDattoTransport()
    alert = _api_alert(1, site_uid="site-uid-0001", site_name="Acme Corp")
    alert["_octo_tenant_slug"] = "acme-corp"
    transport.alerts = [alert]
    await _poller(transport, record)._drain_once()
    assert len(_events("acme-corp")) == 1
    assert tenant_map.get_mappings(record.id) == []    # a directive, not a vendor id


@pytest.mark.asyncio
async def test_relisted_open_alert_is_held_once_and_logged_once(bedrock_root, caplog):  # noqa: F811
    record = _instance()
    create_client("acme-east", "Acme Corp")
    create_client("acme-west", "Acme Corp")
    transport = FakeDattoTransport()
    transport.alerts = [_api_alert(1, site_uid="site-uid-0001", site_name="Acme Corp")]
    with caplog.at_level("WARNING"):
        for _ in range(4):
            await _poller(transport, record)._drain_once()
    assert quarantine.list_rows(instance_id=record.id)[1] == 1
    assert caplog.text.count("HELD alert") == 1
    assert "DROPPED" not in caplog.text


def test_held_payload_is_the_envelope_the_adapter_saw(bedrock_root):  # noqa: F811
    record = _instance()
    adapter = DattoSourceAdapter()
    env = _api_alert(7, site_uid="site-uid-0001", site_name=None)
    delivery = tenant_autocreate.deliver(
        instance_id=record.id, vendor_slug="datto", adapter=adapter, envelope=env,
        event=adapter.extract_event(env), sink=SqliteIngestSink(publish_to_stream=False),
        default_tenant_slug=None, door="webhook",
    )
    assert delivery.status == "quarantined" and delivery.quarantine_created
    row = quarantine.get(delivery.quarantine_id)
    assert row.source == "webhook" and row.payload_sha256 == adapter.extract_event(env).payload_sha256
    assert json.loads(quarantine.payload_text(row.id)) == env
