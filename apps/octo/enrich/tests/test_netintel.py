"""Remote-IP enrichment never uses the local (system) resolver and never
contacts the remote address: PTR over DNS-over-HTTPS to public resolvers BY
IP LITERAL, RDAP servers resolved over DoH and reached by address with the
name as SNI / Host, every answer cached; the background worker is rate
limited, caches failures for an hour and does nothing when switched off.
Every request here goes to an httpx.MockTransport."""
from __future__ import annotations

import ipaddress
import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from apps.octo.enrich import cache, labels, netintel, worker

REMOTE = "203.0.113.66"
PTR_NAME = "scanner-07.ch1.censys-scanner.com"
IANA_IP, ARIN_IP = "192.0.2.10", "192.0.2.20"
RDAP_BODY = {
    "objectClassName": "ip network", "handle": "NET-203-0-113-0-1", "name": "CENSYS-EXAMPLE",
    "startAddress": "203.0.113.0", "endAddress": "203.0.113.255", "country": "US",
    "port43": "whois.arin.net",
    "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
    "entities": [{"roles": ["registrant"],
                  "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                           ["fn", {}, "text", "Censys, Inc."]]]}],
}


class Net:
    """The fake internet: public DoH resolvers + IANA + ARIN, nothing else."""

    def __init__(self, *, ptr: str = PTR_NAME, forward: str = REMOTE) -> None:
        self.requests: list[httpx.Request] = []
        self.ptr, self.forward = ptr, forward
        self.fail_doh: set[str] = set()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host = request.url.host
        if host in ("1.1.1.1", "8.8.8.8"):
            if host in self.fail_doh:
                return httpx.Response(503)
            q = parse_qs(urlsplit(str(request.url)).query)
            name, rtype = q["name"][0], q["type"][0]
            answers = {
                (ipaddress.ip_address(REMOTE).reverse_pointer, "PTR"): [(12, self.ptr + ".")],
                (self.ptr, "A"): [(1, self.forward)],
                ("data.iana.org", "A"): [(1, IANA_IP)],
                ("rdap.arin.net", "A"): [(1, ARIN_IP)],
            }.get((name, rtype))
            body = {"Status": 0 if answers else 3,
                    "Answer": [{"name": name, "type": t, "data": d} for t, d in answers or []]}
            return httpx.Response(200, json=body)
        if host == IANA_IP and request.headers.get("host") == "data.iana.org":
            return httpx.Response(200, json={"services": [
                [["198.51.100.0/24"], ["https://rdap.db.ripe.net/"]],
                [["203.0.113.0/24"], ["https://rdap.arin.net/registry/"]]]})
        if host == ARIN_IP and request.headers.get("host") == "rdap.arin.net":
            assert request.url.path == f"/registry/ip/{REMOTE}"
            return httpx.Response(200, json=RDAP_BODY)
        raise AssertionError(f"unexpected request to {request.url}")


def _intel(net: Net, **kw: Any) -> netintel.NetIntel:
    return netintel.NetIntel(httpx.Client(transport=httpx.MockTransport(net)), **kw)


def test_a_lookup_uses_doh_by_ip_and_rdap_by_sni_never_the_resolver_or_the_ip(troot,
                                                                              no_resolver):
    net = Net()
    found = _intel(net).lookup(REMOTE)
    assert found.as_dict() == {"ip": REMOTE, "ptr": PTR_NAME, "ptr_confirmed": True,
                               "org": "Censys, Inc.", "net_name": "CENSYS-EXAMPLE",
                               "cidr": "203.0.113.0/24", "country": "US", "rir": "arin"}
    hosts = [r.url.host for r in net.requests]
    assert REMOTE not in hosts                                     # never the address itself
    assert set(hosts) <= {"1.1.1.1", IANA_IP, ARIN_IP}            # IP literals only
    for r in net.requests:
        if r.url.host in (IANA_IP, ARIN_IP):
            name = r.headers["host"]
            assert name in netintel.RDAP_HOSTS
            assert r.extensions.get("sni_hostname") == name       # the TLS name is the server's
    assert no_resolver == []                                      # the system resolver: never
    assert cache.get(cache.HOST, "rdap.arin.net") == {"addresses": [ARIN_IP],
                                                      "fetched_at": cache.get(
                                                          cache.HOST, "rdap.arin.net")[
                                                          "fetched_at"]}
    assert cache.get(cache.BOOTSTRAP, "v4")["services"]
    # A second lookup reuses the cached RDAP server address and bootstrap.
    net.requests.clear()
    _intel(net).lookup(REMOTE)
    assert [r.url.host for r in net.requests].count(IANA_IP) == 0


def test_an_unconfirmed_ptr_is_kept_but_says_so(troot, no_resolver):
    net = Net(forward="198.51.100.99")                 # the name points elsewhere
    found = _intel(net).lookup(REMOTE)
    assert found.ptr == PTR_NAME and found.ptr_confirmed is False
    # No label rests on the unconfirmed PTR — only on the registry's owner.
    assert labels.labels(REMOTE, found.as_dict()) == [
        {"kind": "scanner", "name": "Censys", "basis": "rdap"}]


def test_a_request_that_would_contact_the_remote_itself_is_refused(troot, no_resolver):
    net = Net()
    intel = _intel(net, doh=(f"https://{REMOTE}/dns-query",))
    with pytest.raises(netintel.NetIntelError):
        intel.lookup(REMOTE)
    assert net.requests == []


def test_a_failing_resolver_falls_back_to_the_other_and_rdap_redirects_stay_in_the_rirs(
        troot, no_resolver):
    net = Net()
    net.fail_doh.add("1.1.1.1")
    found = _intel(net).lookup(REMOTE)
    assert found.ptr_confirmed and "8.8.8.8" in [r.url.host for r in net.requests]

    def redirecting(request: httpx.Request) -> httpx.Response:
        if request.url.host == ARIN_IP:
            return httpx.Response(302, headers={"location": "https://rdap.evil.example/ip/x"})
        return net(request)

    intel = netintel.NetIntel(httpx.Client(transport=httpx.MockTransport(redirecting)))
    with pytest.raises(netintel.NetIntelError, match="RDAP server"):
        intel.rdap(REMOTE)


def test_an_rdap_name_answered_with_a_local_address_is_never_followed(troot, no_resolver):
    def lying(request: httpx.Request) -> httpx.Response:
        if request.url.host in ("1.1.1.1", "8.8.8.8"):
            q = parse_qs(urlsplit(str(request.url)).query)
            if q["name"][0] in ("data.iana.org", "rdap.arin.net"):
                return httpx.Response(200, json={"Status": 0, "Answer": [
                    # A LAN (RFC 1918) answer is the case under test: it must stay private.
                    # scan-sensitive: allow[ip-private] generic RFC 1918 value under test
                    {"name": q["name"][0], "type": 1, "data": "10.20.0.1"}]})
        raise AssertionError(f"unexpected request to {request.url}")

    intel = netintel.NetIntel(httpx.Client(transport=httpx.MockTransport(lying)))
    with pytest.raises(netintel.NetIntelError, match="no address"):
        intel.rdap(REMOTE)


def test_rdap_parsing_prefers_the_registrant():
    body = json.loads(json.dumps(RDAP_BODY))
    body["entities"].insert(0, {"roles": ["abuse"], "vcardArray": [
        "vcard", [["fn", {}, "text", "Abuse Desk"]]]})
    assert netintel.parse_rdap(body)["org"] == "Censys, Inc."
    body["entities"] = []
    assert netintel.parse_rdap(body)["org"] == "CENSYS-EXAMPLE"
    with pytest.raises(netintel.NetIntelError):
        netintel.parse_rdap(["not", "an", "object"])


def test_only_remote_unicast_addresses_are_enriched():
    assert netintel.enrichable("203.0.113.9") and netintel.enrichable("2001:db8::9")
    # The site's own address space is the classification under test: RFC 1918,
    # CGNAT (an address in the /23 Tailscale never assigns, so never a real
    # node) and link-local values, generic and made up.
    # scan-sensitive: allow[ip-private,ip-tailnet] generic local values under test
    local = ("10.0.0.5", "172.16.3.3", "192.168.1.1", "100.115.92.1", "169.254.1.1")
    for ip in (*local, "127.0.0.1", "224.0.0.1", "0.0.0.0", "fe80::1", "fd00::1", "not-an-ip",
               None):
        assert not netintel.enrichable(ip), ip


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------

def test_scanner_and_vendor_labels():
    # The table carries exactly the two published Cortex Xpanse ranges,
    # pinned literally so a typo in labels.py fails here.
    xpanse_cidrs = [n for n, name in labels.SCANNER_NETWORKS if name == "Palo Alto Cortex Xpanse"]
    assert xpanse_cidrs == [
        "147.185.132.0/23",  # scan-sensitive: allow[ip-public] Cortex Xpanse published scanner range
        "35.203.210.0/23",  # scan-sensitive: allow[ip-public] Cortex Xpanse published scanner range
    ]
    # An address inside each of them (the upper half of a /23 included)
    # carries the network's label.
    xpanse = [ipaddress.ip_network(n) for n in xpanse_cidrs]
    assert labels.labels(str(xpanse[0][10]), None) == [
        {"kind": "scanner", "name": "Palo Alto Cortex Xpanse", "basis": "network"}]
    assert labels.labels(str(xpanse[1][257]), None)[0]["name"] == "Palo Alto Cortex Xpanse"
    shodan = {"ptr": "census12.shodan.io", "ptr_confirmed": True}
    assert labels.labels("198.51.100.4", shodan) == [
        {"kind": "scanner", "name": "Shodan", "basis": "ptr"}]
    assert labels.labels("198.51.100.4", dict(shodan, ptr_confirmed=False)) == []
    backup = {"ptr": "bdr-12.dattobackup.com", "ptr_confirmed": True}
    assert labels.labels("198.51.100.5", backup) == [
        {"kind": "vendor", "name": "Datto backup cloud", "basis": "ptr"}]
    assert labels.labels("198.51.100.6", {"org": "Shadowserver (example registrant)"}) == [
        {"kind": "scanner", "name": "Shadowserver", "basis": "rdap"}]
    for ptr, name in (("scan-1.stretchoid.com", "Stretchoid"),
                      ("x.internet-measurement.com", "internet-measurement.com (Driftnet)"),
                      ("probe-3.onyphe.net", "Onyphe"), ("a.binaryedge.ninja", "BinaryEdge"),
                      ("scanner.modat.io", "Modat"), ("h1.infrawatch.io", "InfraWatch (Hydra)")):
        assert labels.labels("198.51.100.7", {"ptr": ptr, "ptr_confirmed": True})[0]["name"] \
            == name


# ---------------------------------------------------------------------------
# The worker
# ---------------------------------------------------------------------------

class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class CountingIntel:
    seen: list[str] = []
    fail: set[str] = set()

    def lookup(self, ip: str) -> netintel.IpIntel:
        CountingIntel.seen.append(ip)
        if ip in CountingIntel.fail:
            raise netintel.NetIntelError("rdap: RDAP HTTP 503; ptr: no DoH resolver answered")
        return netintel.IpIntel(ip, None, False, "Example Hosting", None, None, None, None)

    def close(self) -> None:
        pass


def test_the_worker_is_rate_limited_caches_failures_and_skips_local(troot, monkeypatch,
                                                                    no_resolver):
    monkeypatch.setenv(worker.ENV, "on")
    CountingIntel.seen, CountingIntel.fail = [], {"198.51.100.3"}
    clock = Clock()
    w = worker.EnrichmentWorker(intel_factory=CountingIntel, rate_per_min=2, clock=clock)
    # A LAN (RFC 1918) address is skipped: it must stay private.
    # scan-sensitive: allow[ip-private] generic RFC 1918 value: the worker skips it
    assert w.enqueue(["198.51.100.1", "198.51.100.2", "198.51.100.3", "10.0.0.1",
                      "198.51.100.1"]) == 3
    assert w.run_once() == 2 and len(w.pending()) == 1               # the minute's budget
    clock.t += 61
    assert w.run_once() == 1 and w.pending() == []
    assert CountingIntel.seen == ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    assert cache.get(cache.IP, "198.51.100.1")["org"] == "Example Hosting"
    assert cache.get(cache.IP, "198.51.100.3") is None                # a failure is no answer
    assert cache.get(cache.IP, "198.51.100.3", include_failed=True)["failed"] is True
    assert w.enqueue(["198.51.100.1", "198.51.100.3"]) == 0           # cached (either way)
    monkeypatch.setenv(worker.ENV, "off")
    assert w.enqueue(["198.51.100.50"]) == 0 and not worker.enabled()
