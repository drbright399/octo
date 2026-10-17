"""The REAL UniFiClient against the fake cloud (only the socket is fake):
paths, paging, the snapshot rule, the boundary, the status classes, and that
the key never appears in an error."""
from __future__ import annotations

from datetime import timedelta

import pytest

from apps.octo.adapters.unifi import sanitize
from apps.octo.adapters.unifi.client import (
    UniFiAuthError,
    UniFiClientError,
    UniFiConfig,
    UniFiConsoleError,
    UniFiThrottledError,
)
from apps.octo.adapters.unifi.limiter import reset_limiters
from apps.octo.adapters.unifi.tests.fake_unifi import (
    API_KEY,
    HOST_A,
    INTEGRATION_DEFAULT,
    FakeClock,
    FakeUniFiTransport,
    fake_limiter,
    ips_event,
    lan,
    mac,
    ms,
    real_client,
    standard_fleet,
)


@pytest.fixture
def env():
    reset_limiters()
    clock = FakeClock()
    transport = FakeUniFiTransport(clock)
    standard_fleet(transport)
    limiter = fake_limiter(clock)
    yield clock, transport, real_client(transport, limiter=limiter), limiter
    reset_limiters()


def test_the_fleet_is_paged_and_stripped(env):
    clock, transport, client, _ = env
    transport.fleet_page_size = 2
    hosts = client.list_hosts()
    assert [h["id"] for h in hosts.items][0] == HOST_A and len(hosts.items) == 3
    assert [c.query.get("nextToken") for c in transport.calls] == [None, "2"]
    assert all(c.query["pageSize"] == "500" for c in transport.calls)
    for h in hosts.items:
        assert sanitize.find_secret_keys(h) == []
        assert "userData" not in h or "apiToken" not in h["userData"]
        assert "x_ssh_password" not in h["reportedState"]
    sites = client.list_sites()
    assert all("utm_token" not in s for s in sites.items)
    assert sites.items[0]["statistics"]["wans"]["WAN"]["externalIp"] == "203.0.113.129"


def test_the_console_paths_always_name_the_console(env):
    clock, transport, client, _ = env
    sites = client.integration_sites(HOST_A)
    assert [(s.id, s.internal_reference) for s in sites] == [(INTEGRATION_DEFAULT, "default")]
    assert transport.calls[-1].path == (
        f"/v1/connector/consoles/{HOST_A}/proxy/network/integration/v1/sites")
    with pytest.raises(UniFiClientError):
        client.integration_sites("../../v1/hosts")
    with pytest.raises(UniFiClientError):
        client.system_log(HOST_A, "default/../x", from_ms=0, to_ms=1)


def test_clients_are_read_whole_or_not_at_all(env):
    clock, transport, client, _ = env
    transport.site(HOST_A).clients = [{"id": f"c{i}", "macAddress": mac(i), "ipAddress": lan(9)}
                                      for i in range(450)]
    snap = client.clients(HOST_A, INTEGRATION_DEFAULT)
    assert (snap.total, len(snap.clients), snap.pages) == (450, 450, 3)
    transport.clients_fail_after_page[HOST_A] = 2
    with pytest.raises(UniFiConsoleError):
        client.clients(HOST_A, INTEGRATION_DEFAULT)


def test_the_system_log_is_a_post_with_the_window(env):
    clock, transport, client, _ = env
    now = clock.now()
    transport.site(HOST_A).log.append(ips_event(now - timedelta(minutes=1), eid="x-1"))
    page = client.system_log(HOST_A, "default", from_ms=ms(now - timedelta(hours=1)),
                             to_ms=ms(now))
    assert [e["id"] for e in page.events] == ["x-1"] and page.total_pages == 1
    call = transport.calls[-1]
    assert call.method == "POST" and call.path.endswith("/v2/api/site/default/system-log/all")
    assert call.body == {"timestampFrom": ms(now - timedelta(hours=1)), "timestampTo": ms(now),
                         "pageNumber": 0, "pageSize": 500}


def test_networks_keep_an_allowlist_only(env):
    clock, transport, client, _ = env
    nets = client.networks(HOST_A, "default")
    assert [n["name"] for n in nets] == ["Office", "Guest", "Site VPN"]
    assert set(nets[0]) <= {"_id", "name", "purpose", "ip_subnet", "vlan", "vlan_enabled",
                            "networkgroup", "dhcpd_enabled", "dhcpd_dns_enabled", "dhcpd_dns_1",
                            "dhcpd_dns_2", "dhcpd_dns_3", "dhcpd_dns_4", "domain_name", "enabled"}
    assert "fixture" not in str(nets).replace("office.example.test", "")


def test_status_classes_and_the_key_never_echoed(env):
    clock, transport, client, limiter = env
    transport.console_status[HOST_A] = 502
    with pytest.raises(UniFiConsoleError) as e1:
        client.integration_sites(HOST_A)
    transport.console_status[HOST_A] = 400            # an older Network version: ONE console
    with pytest.raises(UniFiConsoleError):
        client.integration_sites(HOST_A)
    del transport.console_status[HOST_A]
    transport.console_timeout.add(HOST_A)
    with pytest.raises(UniFiConsoleError):
        client.integration_sites(HOST_A)
    transport.throttle_next = 1
    transport.retry_after = "90"
    with pytest.raises(UniFiThrottledError) as e2:
        client.list_hosts()
    assert e2.value.retry_in_sec >= 90 and limiter.throttled_for() >= 89
    clock.advance(100)
    transport.key = "fixture-another-key-" + "9" * 24
    with pytest.raises(UniFiAuthError) as e3:
        client.list_sites()
    transport.unreachable = True
    with pytest.raises(UniFiClientError) as e4:
        client.list_hosts()
    for exc in (e1.value, e2.value, e3.value, e4.value):
        assert API_KEY not in str(exc)


def test_redirects_are_never_followed(env, monkeypatch):
    clock, transport, client, _ = env
    real = transport._answer

    def redirect(request, parts, call):  # noqa: ANN001
        r = real(request, parts, call)
        r.status_code = 302
        r.headers["Location"] = "https://elsewhere.example.test/"
        return r

    monkeypatch.setattr(transport, "_answer", redirect)
    with pytest.raises(UniFiClientError, match="redirect"):
        client.list_hosts()
    assert len(transport.calls) == 1


def test_check_access_is_one_call(env):
    clock, transport, client, _ = env
    ok, detail, n = client.check_access()
    assert ok and n == 3 and "3 console(s)" in detail and transport.paths() == ["/v1/hosts"]
    transport.key = "fixture-another-key-" + "9" * 24
    ok, detail, _ = client.check_access()
    assert not ok and "HTTP 401" in detail


def test_a_default_config_points_at_the_cloud():
    cfg = UniFiConfig(api_key=API_KEY)
    assert cfg.api_url == "https://api.ui.com" and cfg.min_spacing_sec == 1.0
