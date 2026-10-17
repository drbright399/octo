"""Client address resolution (`apps.octo.api.client_ip`).

Addresses are documentation ranges only: 192.0.2.0/24 plays the docker
network the reverse proxy (.10), the console (.20) and the tunnel (.30) sit
on; 203.0.113.0/24 are internet clients; 198.51.100.0/24 are callers on the
published port (the tailnet path); 2001:db8::/32 is IPv6.
"""
from __future__ import annotations

import ipaddress

import pytest
from starlette.requests import Request

from apps.octo.api import client_ip as cip

PROXY_NET = "192.0.2.0/24"
CADDY, CONSOLE, TUNNEL = "192.0.2.10", "192.0.2.20", "192.0.2.30"
CLIENT_A, CLIENT_B = "203.0.113.5", "203.0.113.6"
DIRECT = "198.51.100.7"

GARBAGE = [
    "", " ", ",", "unknown", "localhost", "203.0.113.5:443", "203.0.113",
    "203.0.113.5.1", "203.0.113.256", "0203.0.113.5", "<script>", "'; DROP",
    "\x00", "2001:db8::zz", "[2001:db8::1]:443", "1" * 200, "203.0.113.5 203.0.113.6",
]


def _trusted(raw: str = PROXY_NET):
    return cip.parse_trusted_proxies(raw)[0]


# ---------------------------------------------------------------------------
# parse_ip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value, expected", [
    ("203.0.113.5", "203.0.113.5"),
    ("  203.0.113.5 ", "203.0.113.5"),
    ("2001:db8::5", "2001:db8::5"),
    ("[2001:db8::5]", "2001:db8::5"),
    ("::ffff:192.0.2.20", "192.0.2.20"),    # what a dual-stack socket reports
    ("2001:DB8:0:0::5", "2001:db8::5"),
])
def test_parse_ip_accepts_bare_addresses(value, expected):
    assert str(cip.parse_ip(value)) == expected


@pytest.mark.parametrize("value", GARBAGE + [None, 7, b"203.0.113.5", ["203.0.113.5"]])
def test_parse_ip_refuses_everything_else_without_raising(value):
    assert cip.parse_ip(value) is None


# ---------------------------------------------------------------------------
# OCTO_TRUSTED_PROXIES parsing
# ---------------------------------------------------------------------------

def test_trusted_proxies_parse_networks_and_addresses():
    nets, refused = cip.parse_trusted_proxies(
        " 192.0.2.0/24, 198.51.100.9 ,2001:db8:a::/48,, 192.0.2.0/24")
    assert [str(n) for n in nets] == ["192.0.2.0/24", "198.51.100.9/32", "2001:db8:a::/48"]
    assert refused == ()


@pytest.mark.parametrize("raw", [
    "192.0.2.10/32,192.0.2.20/32",
    "192.0.2.10/32, 192.0.2.20/32",
    "192.0.2.10/32 192.0.2.20/32",
    "192.0.2.10/32\t192.0.2.20/32\n",
    # what `docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}'` prints
    "192.0.2.10/32 192.0.2.20/32 ",
    " ,192.0.2.10 ,, 192.0.2.20, ",
])
def test_entries_are_separated_by_commas_or_whitespace(raw):
    nets, problems = cip.parse_trusted_proxies(raw)
    assert [str(n) for n in nets] == ["192.0.2.10/32", "192.0.2.20/32"]
    assert problems == ()


def test_trusted_proxies_refuse_garbage_and_trust_everyone():
    nets, problems = cip.parse_trusted_proxies(
        "garbage, 0.0.0.0/0, ::/0, 192.0.2.0/33, 192.0.2.0/24")
    assert [str(n) for n in nets] == ["192.0.2.0/24"]
    assert problems == (
        "entry 1 is not an IP address or network; its value is not repeated here",
        "entry 2 (0.0.0.0/0) would trust every address",
        "entry 3 (::/0) would trust every address",
        "entry 4 is not an IP address or network; its value is not repeated here",
    )


@pytest.mark.parametrize("raw, fix", [
    # `docker network inspect ... {{.IPv4Address}}` prints addresses this way.
    ("192.0.2.10/24", "write 192.0.2.10/32 for that one address, or 192.0.2.0/24"),
    ("192.0.2.10/16", "write 192.0.2.10/32 for that one address, or 192.0.0.0/16"),
    ("2001:db8::5/48", "write 2001:db8::5/128 for that one address, or 2001:db8::/48"),
])
def test_an_entry_with_host_bits_is_refused_never_widened(raw, fix):
    nets, problems = cip.parse_trusted_proxies(raw)
    assert nets == ()                       # not the whole subnet, not anything
    assert problems == (f"entry 1 ({raw}) has host bits set: {fix} for the whole network",)


@pytest.mark.parametrize("raw, fix", [
    ("::ffff:192.0.2.0/124", "192.0.2.0/28"),
    ("::ffff:192.0.2.10", "192.0.2.10/32"),
    ("::ffff:c000:20a/128", "192.0.2.10/32"),
])
def test_an_ipv4_mapped_entry_is_refused_not_left_to_match_nothing(raw, fix):
    # Peers and chain entries are compared as IPv4, so a mapped network
    # would never match: the setting would quietly trust nobody.
    nets, problems = cip.parse_trusted_proxies(raw)
    assert nets == ()
    assert problems == (
        f"entry 1 ({raw}) is an IPv4-mapped IPv6 network, which never matches: write {fix}",)
    # The IPv4 form it names is accepted and matches the mapped peer.
    nets, problems = cip.parse_trusted_proxies(fix)
    assert problems == ()
    assert cip.resolve_client_ip("::ffff:192.0.2.10", CLIENT_A, nets) == CLIENT_A


def test_an_ipv6_network_that_merely_contains_mapped_space_is_accepted():
    nets, problems = cip.parse_trusted_proxies("2001:db8::/64, ::/80")
    assert problems == ()
    assert [str(n) for n in nets] == ["2001:db8::/64", "::/80"]


@pytest.mark.parametrize("raw", [
    "bundle-net",                            # a network NAME, not its subnet
    "192.0.2.10/32;192.0.2.20/32",           # wrong separator
    "192.0.2.10/32|192.0.2.20/32",
    "fe80::1%eth0",                          # zone id: free text in Python
    "s3cr3t-Value-pasted-by-mistake",
    "x" * 300,
])
def test_an_entry_that_is_not_an_address_is_named_by_position_only(raw):
    nets, problems = cip.parse_trusted_proxies(f"192.0.2.10, {raw}")
    assert [str(n) for n in nets] == ["192.0.2.10/32"]
    assert len(problems) == 1
    assert problems[0].startswith("entry 2 is not an IP address or network")
    assert raw not in problems[0] and raw.split("/")[0] not in problems[0]
    if ";" in raw or "|" in raw:
        assert "separate entries with commas or spaces" in problems[0]


def test_check_trusted_proxies_refuses_any_unusable_entry(monkeypatch):
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", "192.0.2.10, s3cr3t-Value, 192.0.2.0/0")
    with pytest.raises(cip.TrustedProxiesError) as exc:
        cip.check_trusted_proxies()
    message = str(exc.value)
    assert message.startswith("OCTO_TRUSTED_PROXIES is not valid, so octo-core will not start")
    assert "entry 2 is not an IP address or network" in message
    assert "entry 3 (192.0.2.0/0) would trust every address" in message
    assert "s3cr3t" not in message
    assert "separated by commas or spaces" in message
    for ok in ("", "  ", "192.0.2.0/28", "192.0.2.10 192.0.2.20", "2001:db8::/64"):
        monkeypatch.setenv("OCTO_TRUSTED_PROXIES", ok)
        assert cip.check_trusted_proxies() == cip.trusted_proxies()
    monkeypatch.delenv("OCTO_TRUSTED_PROXIES")
    assert cip.check_trusted_proxies() == ()


def test_the_runtime_warning_names_positions_not_values(monkeypatch, caplog):
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", "192.0.2.10, s3cr3t-Runtime-Value")
    with caplog.at_level("WARNING", logger=cip.__name__):
        assert cip.trusted_proxies() == (ipaddress.ip_network("192.0.2.10/32"),)
    assert "entry 2 is not an IP address or network" in caplog.text
    assert "s3cr3t" not in caplog.text


def test_unset_or_empty_setting_trusts_nobody(monkeypatch):
    monkeypatch.delenv("OCTO_TRUSTED_PROXIES", raising=False)
    assert cip.trusted_proxies() == ()
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", "  ")
    assert cip.trusted_proxies() == ()
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", PROXY_NET)
    assert cip.trusted_proxies() == (ipaddress.ip_network(PROXY_NET),)


# ---------------------------------------------------------------------------
# resolve_client_ip — the three paths
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("trusted", ["", PROXY_NET])
def test_path3_direct_caller_spoofed_header_is_ignored(trusted):
    """Untrusted peer (or nothing configured): the peer, whatever it claims."""
    for claim in (CLIENT_A, f"{CLIENT_A}, {CADDY}", CADDY, "garbage"):
        assert cip.resolve_client_ip(DIRECT, claim, _trusted(trusted)) == DIRECT


def test_nothing_configured_even_a_proxy_peer_is_the_client():
    assert cip.resolve_client_ip(CADDY, CLIENT_A, ()) == CADDY


def test_path1_proxy_sets_the_header_client_is_believed():
    assert cip.resolve_client_ip(CADDY, CLIENT_A, _trusted()) == CLIENT_A
    assert cip.resolve_client_ip(CADDY, "2001:db8::5", _trusted()) == "2001:db8::5"


def test_path2_console_appends_its_peer_rightmost_untrusted_wins():
    assert cip.resolve_client_ip(CONSOLE, f"{CLIENT_A}, {CADDY}", _trusted()) == CLIENT_A
    # A value the client sent ahead of the real chain is never reached.
    chain = f"{CLIENT_B}, {CLIENT_A}, {CADDY}"
    assert cip.resolve_client_ip(CONSOLE, chain, _trusted()) == CLIENT_A
    # Several header lines are one chain, in order.
    assert cip.resolve_client_ip(CONSOLE, [CLIENT_A, CADDY], _trusted()) == CLIENT_A


def test_path2_before_the_proxy_route_change_lumps_on_the_tunnel_as_today():
    """The proxy's default header names the tunnel (a trusted hop): a chain
    of trusted hops answers its left-most hop, one address for everybody."""
    assert cip.resolve_client_ip(CONSOLE, f"{TUNNEL}, {CADDY}", _trusted()) == TUNNEL
    assert cip.resolve_client_ip(CONSOLE, TUNNEL, _trusted()) == TUNNEL


def test_trusted_peer_without_header_is_itself():
    assert cip.resolve_client_ip(CADDY, None, _trusted()) == CADDY
    assert cip.resolve_client_ip(CADDY, [], _trusted()) == CADDY
    assert cip.resolve_client_ip(CADDY, "", _trusted()) == CADDY


@pytest.mark.parametrize("junk", GARBAGE)
def test_garbage_never_becomes_the_address(junk):
    # Garbage right of everything: the walk stops at the nearest trusted hop.
    assert cip.resolve_client_ip(CONSOLE, f"{CLIENT_A}, {junk}", _trusted()) == CONSOLE
    assert cip.resolve_client_ip(CONSOLE, f"{CLIENT_A}, {CADDY}, {junk}", _trusted()) == CONSOLE
    assert cip.resolve_client_ip(CONSOLE, f"{CLIENT_A}, {junk}, {CADDY}", _trusted()) == CADDY
    # Garbage left of the answer is never reached.
    assert cip.resolve_client_ip(CADDY, f"{junk}, {CLIENT_A}", _trusted()) == CLIENT_A
    # The whole header garbage: the peer.
    assert cip.resolve_client_ip(CADDY, junk, _trusted()) == CADDY


def test_ipv4_mapped_peer_is_matched_against_ipv4_networks():
    assert cip.resolve_client_ip("::ffff:192.0.2.10", CLIENT_A, _trusted()) == CLIENT_A


def test_peer_that_is_not_an_address_is_never_trusted():
    assert cip.resolve_client_ip("testclient", CLIENT_A, _trusted()) == "testclient"
    assert cip.resolve_client_ip(None, CLIENT_A, _trusted()) == "unknown"
    assert cip.resolve_client_ip("", CLIENT_A, _trusted()) == "unknown"


def test_huge_header_is_bounded_and_never_crashes():
    chain = ", ".join([CLIENT_B] * 50_000 + [CLIENT_A, CADDY])
    assert cip.resolve_client_ip(CONSOLE, chain, _trusted()) == CLIENT_A
    # Only the right-most entries are read: a chain of trusted hops longer
    # than that answers the left-most hop that WAS read, never the far end.
    long_trusted = ", ".join([CLIENT_B] + [CADDY] * (cip.MAX_CHAIN_ENTRIES + 5))
    assert cip.resolve_client_ip(CONSOLE, long_trusted, _trusted()) == CADDY


def test_unverified_hint_is_the_rightmost_wellformed_address():
    assert cip.unverified_forwarded_hint(f"{CLIENT_B}, {CLIENT_A}") == CLIENT_A
    assert cip.unverified_forwarded_hint(f"{CLIENT_A}, garbage") == CLIENT_A
    assert cip.unverified_forwarded_hint("garbage, <x>") is None
    assert cip.unverified_forwarded_hint(None) is None


# ---------------------------------------------------------------------------
# client_ip(request)
# ---------------------------------------------------------------------------

def _request(peer: str | None, xff: list[str] | None = None) -> Request:
    headers = [(b"x-forwarded-for", v.encode("latin-1")) for v in (xff or [])]
    scope = {"type": "http", "method": "GET", "path": "/x", "headers": headers,
             "client": (peer, 1234) if peer is not None else None}
    return Request(scope)


def test_client_ip_reads_the_setting_per_call(monkeypatch):
    req = _request(CADDY, [CLIENT_A])
    monkeypatch.delenv("OCTO_TRUSTED_PROXIES", raising=False)
    assert cip.client_ip(req) == CADDY
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", PROXY_NET)
    assert cip.client_ip(req) == CLIENT_A
    assert cip.client_ip(_request(DIRECT, [CLIENT_A])) == DIRECT
    assert cip.client_ip(_request(None, [CLIENT_A])) == "unknown"


def _private_notes(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if "is a private address" in r.getMessage()]


def test_a_private_client_named_by_a_trusted_proxy_is_logged_once(monkeypatch, caplog):
    """The misroute the deploy guide's checks look for: the reverse proxy
    reached the console over the shared network, so the console (trusted)
    appends an address octo-core does not trust and every user behind it is
    that one address. Logged once per address, at most 64 addresses."""
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", "192.0.2.0/28")     # the proxy network
    monkeypatch.setattr(cip, "_warned_private", set())
    console, hop = "192.0.2.5", "192.0.2.100"                      # hop: not trusted
    with caplog.at_level("WARNING", logger=cip.__name__):
        for _ in range(3):
            assert cip.client_ip(_request(console, [f"{CLIENT_A}, {hop}"])) == hop
        # Not for a chain of trusted hops, not for an untrusted peer.
        assert cip.client_ip(_request(console, ["192.0.2.6"])) == "192.0.2.6"
        assert cip.client_ip(_request(DIRECT, [hop])) == DIRECT
    (note,) = _private_notes(caplog)
    assert note.startswith(f"client address {hop}, named by trusted proxy {console}, "
                           "is a private address")
    caplog.clear()
    with caplog.at_level("WARNING", logger=cip.__name__):
        for i in range(200):
            cip.client_ip(_request(console, [f"198.51.100.{i}"]))
    assert len(_private_notes(caplog)) == cip._MAX_WARNED_PEERS - 1


def test_a_public_client_named_by_a_trusted_proxy_is_not_logged(monkeypatch, caplog):
    # Documentation ranges count as private in Python; stand in for a public
    # client (what the edge always names) by declaring CLIENT_A public.
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", PROXY_NET)
    monkeypatch.setattr(cip, "_warned_private", set())
    monkeypatch.setattr(cip, "_is_private_use", lambda ip: str(ip) != CLIENT_A)
    with caplog.at_level("WARNING", logger=cip.__name__):
        assert cip.client_ip(_request(CONSOLE, [f"{CLIENT_A}, {CADDY}"])) == CLIENT_A
    assert _private_notes(caplog) == []


def test_client_ip_with_a_garbage_setting_trusts_only_the_valid_part(monkeypatch):
    """Startup refuses such a value (check_trusted_proxies); if the
    environment changed under a running process anyway, an unusable entry
    means fewer trusted proxies, never more."""
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", "not-a-network, 0.0.0.0/0")
    assert cip.client_ip(_request(DIRECT, [CLIENT_A])) == DIRECT
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", f"not-a-network, {PROXY_NET}")
    assert cip.client_ip(_request(CADDY, [CLIENT_A])) == CLIENT_A
    # Host bits: the one address is not widened to its network.
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", "192.0.2.10/24")
    assert cip.client_ip(_request(CONSOLE, [CLIENT_A])) == CONSOLE
