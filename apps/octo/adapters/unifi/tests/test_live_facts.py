"""Review round 3 (UniFi adapter): the live API facts of 2026-10-01 20:00
(archived outside the repo):

  * the system log's first page is NEWEST FIRST — the window reader pages a
    descending list with no skipped and no duplicated event across pages
    (late writes landing while it pages included);
  * IPS events have no signature parameter: the threat's name comes from
    title_raw / message_raw; SRC_IP / DST_IP are {id, name, not_actionable};
    DEVICE is the reporting gateway;
  * the integration site id differs from the fleet siteId on every console;
  * no nextToken at fleet size 43 (one call each, complete)."""
from __future__ import annotations

from datetime import timedelta

from apps.octo.adapters.unifi import poller as poller_mod
from apps.octo.adapters.unifi.tests.fake_unifi import (
    HOST_A,
    HOST_B,
    HOST_C,
    INTEGRATION_DEFAULT,
    SCOPE_A,
    SCOPE_B,
    SITE_DEFAULT,
    ips_event,
    lan,
)

A, B = "acme-corp", "example-bakery"


# ---------------------------------------------------------------------------
# Live facts: the system log is NEWEST FIRST
# ---------------------------------------------------------------------------

def _ips(world, n: int, start, *, step_s: int = 1, host: str = HOST_A) -> list[dict]:
    items = [ips_event(start + timedelta(seconds=i * step_s), client_n=10 + i % 200,
                       lan_ip=f"10.20.{i // 200}.{10 + i % 200}", eid=f"ips-{i:05d}",
                       signature=f"ET MALWARE Example Beacon {i}")
             for i in range(n)]
    world.transport.site(host).log.extend(items)
    return items


def test_a_descending_log_is_paged_with_no_skip_and_no_duplicate(world, monkeypatch):
    """Three FULL pages, newest first. Two writes land WHILE the window is
    paged (each pushes the descending list down a slot): the next page
    repeats an item (kept once) and the two OLDEST items move to a fourth
    page the first answer never announced (the old reader stopped at the
    first page count and lost them for good — they are older than the
    re-read overlap). The late writes themselves are read by the next
    window's overlap. Every event exactly once."""
    monkeypatch.setattr("apps.octo.adapters.unifi.client.LOG_PAGE_SIZE", 10)
    now = world.clock.now()
    _ips(world, 30, now - timedelta(minutes=40), step_s=60)
    world.map_sites({SCOPE_A: A})
    late = [ips_event(now - timedelta(seconds=30 - k), client_n=90 + k, lan_ip=f"10.20.9.{k}",
                      eid=f"late-{k}", signature=f"ET SCAN Late {k}") for k in range(2)]
    pages = []

    def before(call):  # noqa: ANN001
        if "system-log" in call.path:
            pages.append(call.body["pageNumber"])
            if call.body["pageNumber"] in (1, 2) and late:
                world.transport.site(HOST_A).log.append(late.pop(0))

    world.transport.before_request = before
    p = world.poller()
    p.run_cycle()
    world.clock.advance(330)
    p.run_cycle()
    ids = [x["event"]["id"] for x in world.payloads(A, "unifi.ips_threat")]
    assert len(ids) == len(set(ids)) == 32                        # all, once each
    assert {"ips-00000", "ips-00001", "late-0", "late-1"} <= set(ids)
    assert 3 in pages                                              # past the first count


def test_more_pages_than_the_cap_are_read_in_more_windows_never_dropped(world, monkeypatch):
    """A window with more pages than HARD_MAX_LOG_PAGES (newest first): the
    pages read are the NEWEST; the older rest is read next — nothing is
    dropped, nothing is read twice."""
    monkeypatch.setattr(poller_mod, "MAX_LOG_PAGES_PER_WINDOW", 2)
    monkeypatch.setattr(poller_mod, "HARD_MAX_LOG_PAGES", 2)
    monkeypatch.setattr("apps.octo.adapters.unifi.client.LOG_PAGE_SIZE", 10)
    now = world.clock.now()
    _ips(world, 65, now - timedelta(minutes=4), step_s=2)         # 7 pages inside 5 minutes
    world.map_sites({SCOPE_A: A})
    world.poller().run_cycle()
    ids = [p["event"]["id"] for p in world.payloads(A, "unifi.ips_threat")]
    assert len(ids) == len(set(ids)) == 65


# ---------------------------------------------------------------------------
# Live facts: the IPS event's real shape
# ---------------------------------------------------------------------------

def test_an_ips_event_of_the_live_shape_names_the_threat_from_its_text(world):
    world.map_sites({SCOPE_A: A})
    at = world.clock.now() - timedelta(minutes=10)
    world.transport.site(HOST_A).log.extend([
        ips_event(at, eid="ips-1", signature="ET POLICY Example Tor Exit"),
        ips_event(at + timedelta(seconds=20), eid="ips-2", remote_ip="198.51.100.9",
                  signature="ET POLICY Example Tor Exit"),
        ips_event(at + timedelta(seconds=40), eid="ips-3", signature="ET SCAN Example Probe"),
    ])
    world.poller().run_cycle()
    payloads = world.payloads(A, "unifi.ips_threat")
    # Same LAN client + same threat within the hour = ONE alert, whatever the
    # remote address; another threat = another alert.
    assert len(payloads) == 2
    first = payloads[0]
    assert first["ips"]["signature"] == "ET POLICY Example Tor Exit"
    assert first["ips"]["local_ip"] == lan(37)                       # from SRC_IP {id, name}
    assert first["ips"]["remote_ip"] == "203.0.113.66"               # from DST_IP {id, name}
    assert first["ips"]["gateway"] == "acme-gateway"                 # DEVICE = the gateway
    assert "mac" not in first["ips"].get("client", {})               # no CLIENT parameter
    assert first["ocsf"]["finding_info"]["analytic"]["name"] == "ET POLICY Example Tor Exit"
    from apps.octo.adapters.unifi.presentation import present

    assert "ET POLICY Example Tor Exit" in present(first).headline


# ---------------------------------------------------------------------------
# Live facts: integration ids and the fleet without nextToken
# ---------------------------------------------------------------------------

def test_the_clients_endpoint_takes_the_integration_id_never_the_fleet_site_id(world):
    """The integration site id DIFFERS from the fleet siteId on every site
    consoles (live 2026-10-01): the per-console internalReference lookup is
    required, on every console."""
    world.transport.site(HOST_B).integration_id = "0f0f0f0f-0000-4000-8000-0000000000bb"
    world.map_sites({SCOPE_A: A, SCOPE_B: B})
    world.poller().run_cycle()
    lookups = [c.path.split("/")[4] for c in world.transport.calls
               if c.path.endswith("/integration/v1/sites")]
    assert sorted(lookups) == sorted([HOST_A, HOST_B])           # one lookup per console
    used = {c.path.split("/")[4]: c.path.split("/")[-2]
            for c in world.transport.calls_to("/clients")}
    assert used == {HOST_A: INTEGRATION_DEFAULT, HOST_B: "0f0f0f0f-0000-4000-8000-0000000000bb"}
    for site_id in used.values():
        assert site_id != SITE_DEFAULT                            # never the fleet siteId
    assert all(SITE_DEFAULT not in c.path for c in world.transport.calls_to("/clients"))


def test_a_fleet_answer_without_next_token_is_one_complete_call(world):
    """A few dozen consoles (a production-size fleet): {data, httpStatusCode, traceId}, NO
    nextToken — one call each, read as complete."""
    for i in range(40):
        world.transport.add_console(f"F1X7D{i:04d}" + "0" * 46 + f":2000000{i:02d}", f"udm-{i}")
    seen = []

    def before(call):  # noqa: ANN001
        seen.append(call.path)

    world.transport.before_request = before
    p = world.poller()
    p.run_cycle()
    assert seen.count("/v1/hosts") == 1 and seen.count("/v1/sites") == 1
    assert len(p.fleet_view()) == 43 and p.snapshot()["consoles"] == 43
    listing = world.transport._fleet  # noqa: SLF001 — the fake answers like the live API
    assert listing is not None
    assert HOST_C in {scope.split("/")[0] for scope in p.fleet_view()}
