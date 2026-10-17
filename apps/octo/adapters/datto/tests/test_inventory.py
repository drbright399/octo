"""The Datto inventory feed (read-only): the REAL DattoClient / InventoryPoller
/ entity consumer against the fake Datto transport — only the socket is
fake. Per MAPPED site of EVERY tenant (v0.17.2, Rick's decision D — whatever
its entity switch; identity LINKING only for shadow / on), every page (max
250), at most one read per site per 30 minutes, the allowlisted fields only
(NEVER a UDF, never the logged-in user, never the remote-control address),
mapped to OCSF Device Inventory Info at the boundary, into the tenant's
entities.db."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo.adapters.datto import feed
from apps.octo.adapters.datto.client import INVENTORY_FIELDS, MAX_PAGE_SIZE
from apps.octo.adapters.datto.inventory import InventoryPoller, ocsf_device
from apps.octo.adapters.datto.tests.fake_datto import (
    CREDS,
    WEB_REMOTE_MARKER,
    FakeDattoTransport,
    inventory_device,
    real_client,
)
from apps.octo.client_provisioning import create_client
from apps.octo.entity import db as entity_db
from apps.octo.entity import switch
from apps.octo.entity.db import TenantDB
from apps.octo.entity.feeders.datto import DattoInventoryFeeder
from apps.octo.instances import create_instance, tenant_map
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401

T0 = datetime(2026, 10, 1, 14, 0, tzinfo=timezone.utc)


class _Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> datetime:
        return self.t


@pytest.fixture
def inv(bedrock_root):  # noqa: F811
    entity_db.reset_schema_cache()
    switch.reset()
    transport = FakeDattoTransport()
    rec = create_instance(vendor_slug="datto", display_name="Datto RMM",
                          credentials_dict=dict(CREDS), instance_config={})
    create_client("acme-corp", "Acme Corp", kind="client")
    create_client("example-bakery", "Example Bakery", kind="client")
    tenant_map.set_mappings(rec.id, [TenantMapping("site-a", "acme-corp", "Site A", "manual"),
                                     TenantMapping("site-b", "example-bakery", "Bakery", "manual")])
    switch.set_mode("acme-corp", "on")
    clock = _Clock()
    poller = InventoryPoller(client=real_client(transport), instance_id=rec.id, spacing_sec=0,
                             now=clock, consumer=DattoInventoryFeeder())
    yield transport, poller, clock, rec
    switch.reset()


def _devices(slug: str = "acme-corp") -> list:
    with TenantDB.for_tenant(slug).connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM inv_device ORDER BY device_uid")]


def test_a_mapped_site_is_read_whole_and_never_a_udf(inv):
    transport, poller, clock, _rec = inv
    nets = ("192.0.2", "198.51.100")             # TEST-NET: 260 distinct addresses
    transport.site_devices["site-a"] = [
        inventory_device(f"dev-{i:04d}", f"WS-{i:04d}", site_uid="site-a",
                         int_ip=f"{nets[i // 250]}.{i % 250 + 1}")
        for i in range(260)]
    transport.device_page_size = MAX_PAGE_SIZE
    transport.site_devices["site-b"] = [inventory_device("dev-b1", "BAKERY-PC",
                                                         site_uid="site-b")]
    out = poller.run_once()
    # Both tenants' sites are read — B's switch is off (D).
    assert out["sites"] == 2 and out["devices"] == 261 and out["skipped"] == 0
    paths = [p for _m, p in transport.calls if p.startswith("/api/v2/site/")]
    assert paths == ["/api/v2/site/site-a/devices"] * 2 + ["/api/v2/site/site-b/devices"]
    rows = _devices()
    assert len(rows) == 260
    for slug in ("acme-corp", "example-bakery"):
        blob = json.dumps(_devices(slug)) + (TenantDB.for_tenant(slug).path.read_bytes()
                                             .decode("latin-1"))
        for secret in ("BITLOCKER", "alice", WEB_REMOTE_MARKER, "udf", "extIpAddress"):
            assert secret.lower() not in blob.lower()
    r = rows[0]
    assert (r["hostname"], r["device_type"], r["online"], r["os"], r["domain"]) == \
        ("WS-0000", "Desktop", 1, "Microsoft Windows 11 Pro", "WORKGROUP")
    assert r["online_since"] == "2026-10-01T14:00:00.000Z" and r["int_ip"] == "192.0.2.1"
    assert r["ext_ip"] == "203.0.113.129"                           # D: the external IP
    assert [d["hostname"] for d in _devices("example-bakery")] == ["BAKERY-PC"]


def test_the_client_keeps_only_the_allowlisted_fields(inv):
    transport, _poller, _clock, _rec = inv
    transport.site_devices["site-a"] = [inventory_device("dev-1", "WS-1", site_uid="site-a")]
    listing = real_client(transport).site_devices("site-a")
    assert set(listing.devices[0]) <= set(INVENTORY_FIELDS)
    # Never a UDF, never the logged-in user, never the remote-control URL —
    # by name, at the socket's edge (D: the external IP is the only addition).
    assert not [f for f in INVENTORY_FIELDS
                if "udf" in f.lower() or f in ("lastLoggedInUser", "webRemoteUrl")]
    assert "extIpAddress" in INVENTORY_FIELDS
    assert "FIXTURE-BITLOCKER" not in json.dumps(listing.devices)
    assert listing.devices[0]["deviceType"] == "Desktop" and not listing.truncated
    o = ocsf_device(listing.devices[0], site_uid="site-a", polled_at="2026-10-01T14:00:00.000Z")
    assert (o["class_uid"], o["category_uid"], o["activity_id"], o["type_uid"]) == \
        (5001, 5, 2, 500102)
    assert o["device"]["hostname"] == "WS-1" and o["device"]["type_id"] == 2
    assert o["device"]["is_managed"] is True and o["metadata"]["version"] == "1.3.0"


def test_online_since_survives_and_an_absent_device_is_missing(inv):
    transport, poller, clock, _rec = inv
    transport.site_devices["site-a"] = [inventory_device("dev-1", "WS-1", site_uid="site-a"),
                                        inventory_device("dev-2", "WS-2", site_uid="site-a")]
    poller.run_once()
    clock.t = T0 + timedelta(minutes=30)
    transport.site_devices["site-a"] = [inventory_device("dev-1", "WS-1", site_uid="site-a")]
    poller.run_once()
    one, two = _devices()
    assert one["online_since"] == "2026-10-01T14:00:00.000Z" and one["missing_since"] is None
    assert two["missing_since"] == "2026-10-01T14:30:00.000Z" and two["online"] is None
    clock.t = T0 + timedelta(minutes=60)
    transport.site_devices["site-a"] = [inventory_device("dev-1", "WS-1", site_uid="site-a",
                                                         online=False)]
    poller.run_once()
    assert _devices()[0]["online"] == 0 and _devices()[0]["online_since"] is None


def test_a_failed_read_marks_nothing_missing_and_moves_no_watermark(inv):
    transport, poller, clock, _rec = inv
    transport.site_devices["site-a"] = [inventory_device("dev-1", "WS-1", site_uid="site-a")]
    poller.run_once()
    clock.t = T0 + timedelta(minutes=30)
    transport.data_status = 502
    out = poller.run_once()
    assert out["errors"] and _devices()[0]["missing_since"] is None
    with TenantDB.for_tenant("acme-corp").connect() as conn:
        wm = conn.execute("SELECT * FROM lk_watermark WHERE source = 'datto.devices'").fetchone()
    assert wm["last_ok_at"] == "2026-10-01T14:00:00.000Z" and wm["last_error"]


def _link_with_a_nextdns_device(slug: str, name: str, ip: str) -> None:
    from apps.octo.entity import normalize as nz

    with TenantDB.for_tenant(slug).write() as conn:
        conn.execute("INSERT INTO ndns_device (profile_id, device_id, name, name_key, local_ip, "
                     "first_seen, last_seen) VALUES ('p-1', 'd-1', ?, ?, ?, ?, ?)",
                     (name, nz.name_key(nz.hostname(name)), ip, "2026-10-01T13:00:00.000Z",
                      "2026-10-01T13:00:00.000Z"))


def test_a_switched_off_tenant_keeps_its_device_list_but_is_never_linked(inv):
    """D: the device list of a tenant whose entity switch is OFF is read and
    kept (names + counts) — identity LINKING stays gated exactly as before."""
    transport, poller, clock, _rec = inv
    switch.set_mode("acme-corp", "off")
    transport.site_devices["site-a"] = [inventory_device("dev-1", "WS-1", site_uid="site-a",
                                                         int_ip="192.0.2.11")]
    transport.site_devices["site-b"] = []
    _link_with_a_nextdns_device("acme-corp", "WS-1", "192.0.2.11")
    out = poller.run_once()
    assert out["sites"] == 2 and out["skipped"] == 0
    assert [d["hostname"] for d in _devices()] == ["WS-1"]
    with TenantDB.for_tenant("acme-corp").connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM device_link").fetchone()[0] == 0
    # Switched on: the same list links the same-name, same-address device.
    switch.set_mode("acme-corp", "on")
    clock.t = T0 + timedelta(minutes=30)
    poller.run_once()
    with TenantDB.for_tenant("acme-corp").connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM device_link").fetchone()[0] == 1


def test_one_read_per_site_per_30_minutes_and_never_an_unmapped_site(inv):
    transport, poller, clock, rec = inv
    transport.site_devices["site-a"] = [inventory_device("dev-1", "WS-1", site_uid="site-a")]
    transport.site_devices["site-b"] = []
    transport.site_devices["site-unmapped"] = [inventory_device("dev-x", "X", site_uid="x")]
    poller.run_once()
    clock.t = T0 + timedelta(minutes=29)
    out = poller.run_once()                        # inside the budget: nothing read
    assert out["sites"] == 0 and out["skipped"] == 2
    clock.t = T0 + timedelta(minutes=30)
    assert poller.run_once()["sites"] == 2
    reads = [p for _m, p in transport.calls if p.startswith("/api/v2/site/")]
    assert reads.count("/api/v2/site/site-a/devices") == 2
    assert "/api/v2/site/site-unmapped/devices" not in reads
    # The round's own interval never goes under 30 minutes either.
    fast = InventoryPoller(client=real_client(transport), instance_id=rec.id,
                           interval_sec=60, spacing_sec=0, now=clock)
    assert fast._interval == 1800.0


def test_the_feed_never_raises_into_the_poller(inv):
    transport, _poller, _clock, rec = inv

    class Boom:
        def wants(self, slug):
            return True

        def on_inventory(self, slug, site_uid, snapshot):
            raise RuntimeError("consumer bug")

    transport.site_devices["site-a"] = [inventory_device("dev-1", "WS-1", site_uid="site-a")]
    transport.site_devices["site-b"] = []
    p = InventoryPoller(client=real_client(transport), instance_id=rec.id, spacing_sec=0,
                        consumer=Boom())
    assert p.run_once()["sites"] == 2
    assert feed.call(Boom(), "nope", default="x") == "x"


def test_a_429_ends_the_round_and_holds_the_next_ones(inv):
    """Datto blocks an IP that keeps calling after HTTP 429 (and the alerts
    poller shares that IP and token): the inventory STOPS at the first 429 —
    never the next site — and waits before its next round."""
    transport, poller, clock, rec = inv
    sites = [f"site-{i:02d}" for i in range(40)]
    for s in sites:
        transport.site_devices[s] = [inventory_device(f"{s}-dev", f"WS-{s}", site_uid=s)]
    tenant_map.set_mappings(rec.id, [TenantMapping(s, "acme-corp", s, "manual") for s in sites])
    transport.data_status = 429
    out = poller.run_once()
    reads = [p for _m, p in transport.calls if p.startswith("/api/v2/site/")]
    assert len(reads) == 1 and out["sites"] == 0 and out.get("held_until")
    # The next round (15 minutes on) is still held: no call at all.
    clock.t = T0 + timedelta(minutes=10)
    assert poller.run_once().get("held_until")
    assert len([p for _m, p in transport.calls if p.startswith("/api/v2/site/")]) == 1
    # After the hold, the round runs again (Datto answers again).
    transport.data_status = 200
    clock.t = T0 + timedelta(minutes=31)
    out = poller.run_once()
    assert out["sites"] == 40 and not out.get("held_until")
