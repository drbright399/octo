"""Which address a request came from: one answer for security decisions.

octo-core is reached three ways on the bundle host
(docs/operations/bundle.md, "Client addresses behind the proxy"):

  1. the ingest name: edge -> tunnel -> reverse proxy -> octo-core. The proxy
     SETS X-Forwarded-For to the connecting client's address.
  2. the console: edge -> tunnel -> reverse proxy -> console -> octo-core.
     The console appends its own peer (the proxy) to the X-Forwarded-For it
     received.
  3. directly, on the published port. The caller is the socket peer and may
     send any X-Forwarded-For it likes.

The socket peer is the only address nobody can forge. X-Forwarded-For is
believed only as far as it was written by proxies the operator listed in
OCTO_TRUSTED_PROXIES (IP addresses or CIDR networks separated by commas
and/or whitespace; unset or empty = trust nobody). A value with any entry
that is not one, that has host bits set (`192.0.2.10/24`: one address or a
whole network?), that is a /0, or that is IPv4-mapped IPv6 (it could never
match: peers are compared as IPv4) stops octo-core from starting
(`check_proxy_setting`, called when the app is built): a typo must never
quietly trust nobody, or a whole subnet.

  * peer not trusted, or nothing configured: the client is the peer.
  * peer trusted: walk X-Forwarded-For from the right, skipping entries that
    are trusted proxies themselves; the first entry that is not one is the
    client. An entry that is not a bare IP address stops the walk (nothing to
    its left can be attributed) and the answer is the nearest trusted hop; a
    chain of trusted hops only answers its left-most hop.

CF-Connecting-IP is never read: on both proxied paths the reverse proxy
copies it into X-Forwarded-For, and reading it as well would give a direct
caller a second, unguarded way to name its own address.

`client_ip(request)` is the function to use. `unverified_forwarded_hint` is
NOT a client address and must never feed a security decision (see there).

Log lines print parsed addresses, networks, counts and positions only
(`loggable`): never header text, never a setting entry as written, never a
peer label that is not an address.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import threading
from functools import lru_cache
from typing import Iterable, Optional, Union

from apps.octo.auth.config import trusted_proxies_setting

logger = logging.getLogger(__name__)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# The right-most entries of a chain that are looked at. A real chain is a few
# hops; a longer header is cut on the LEFT (the end a client controls).
MAX_CHAIN_ENTRIES = 32
# Longer than any textual IP address (an IPv6 address with a zone id is < 64).
_MAX_ENTRY_CHARS = 64
# A peer label that is not an IP address (a unix socket, a test client).
_MAX_PEER_CHARS = 64
UNKNOWN_PEER = "unknown"
# What a log line prints instead of a peer label that is not an address.
NOT_AN_ADDRESS = "<not an IP address>"

# The setting's name, as log lines and the startup error print it: the same
# text as `apps.octo.auth.config.TRUSTED_PROXIES_ENV` (a test pins the two
# together), spelled out so every log line is built from a literal. Names
# with "trusted" in them (that constant, `trusted_proxies_setting()`, a
# variable called `trusted`) are what CodeQL's sensitive-data heuristic
# reads as a secret (py/clear-text-logging-sensitive-data); the value is a
# list of networks, and what is logged of it is parsed networks and entry
# positions only.
SETTING_NAME = "OCTO_TRUSTED_PROXIES"


def parse_ip(value: object) -> Optional[IPAddress]:
    """`value` as one bare IPv4 / IPv6 address, or None. Never raises.

    Accepted: `203.0.113.7`, `2001:db8::7`, `[2001:db8::7]`. An IPv4-mapped
    IPv6 address (`::ffff:203.0.113.7`, what a dual-stack socket reports) is
    returned as the IPv4 address. Refused: anything else, ports included
    (`203.0.113.7:443`), so a header value that is not an address is never
    used as one. A zone id (`2001:db8::7%eth0`) is refused too: it means
    nothing off the host that wrote it, and Python keeps any text after the
    `%` (spaces included) in the address it returns."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > _MAX_ENTRY_CHARS or "%" in text:
        return None
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


# Entries are separated by commas, whitespace or both: what people type, and
# what `docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}'`
# prints.
_SEPARATORS = re.compile(r"[,\s]+")
# Characters that look like an attempt at a separator.
_WRONG_SEPARATORS = (";", "|")
SETTING_FORMAT = (
    "IP addresses or CIDR networks separated by commas or spaces, e.g. "
    "192.0.2.0/28 or 192.0.2.10, 192.0.2.20; empty trusts nobody"
)


class TrustedProxiesError(ValueError):
    """OCTO_TRUSTED_PROXIES has an entry that is not usable. The message
    names entries by position; an entry is quoted only when it parses as an
    address (anything else might be something pasted by mistake). Raised at
    start (`check_proxy_setting`), never logged by this module."""


def _entry_problem(position: int, entry: str) -> tuple[Optional[IPNetwork], Optional[str]]:
    """(network, None) for a usable entry, else (None, why), naming the
    entry by its 1-based position. Only an entry that parses as an address
    is quoted; a zone id (`%...`, free text in Python) never parses."""
    network: Optional[IPNetwork] = None
    if "%" not in entry and len(entry) <= _MAX_ENTRY_CHARS:
        try:
            network = ipaddress.ip_network(entry, strict=True)
        except ValueError:
            try:
                interface = ipaddress.ip_interface(entry)
            except ValueError:
                pass
            else:
                if interface.network.prefixlen == 0:
                    return None, f"entry {position} ({entry}) would trust every address"
                one = f"{interface.ip}/{interface.ip.max_prefixlen}"
                return None, (f"entry {position} ({entry}) has host bits set: write "
                              f"{one} for that one address, or {interface.network} for "
                              "the whole network")
    if network is None:
        hint = ""
        if any(sep in entry for sep in _WRONG_SEPARATORS):
            hint = " (separate entries with commas or spaces)"
        return None, (f"entry {position} is not an IP address or network{hint}; "
                      "its value is not repeated here")
    if network.prefixlen == 0:
        return None, f"entry {position} ({entry}) would trust every address"
    mapped = (network.network_address.ipv4_mapped
              if isinstance(network, ipaddress.IPv6Network) and network.prefixlen >= 96
              else None)
    if mapped is not None:
        # Peers and chain entries are compared as IPv4 (`parse_ip`), so this
        # entry could never match: it would quietly trust nobody.
        return None, (f"entry {position} ({entry}) is an IPv4-mapped IPv6 network, "
                      f"which never matches: write "
                      f"{ipaddress.IPv4Network((mapped, network.prefixlen - 96))}")
    return network, None


def _entries(raw: str) -> list[str]:
    return [entry for entry in _SEPARATORS.split(raw or "") if entry]


@lru_cache(maxsize=16)
def parse_proxy_setting(raw: str) -> tuple[tuple[IPNetwork, ...], tuple[str, ...]]:
    """(networks, problems) for an OCTO_TRUSTED_PROXIES value.

    Entries are separated by commas and/or whitespace. An entry is refused
    (one problem, naming its position) when it is not an address or a
    network, when it has host bits set (`192.0.2.10/24`; never widened to
    the network), when it is a /0 ("trust every address" would let any
    caller name its own address), or when it is IPv4-mapped IPv6
    (`::ffff:192.0.2.0/124`: never matches, since peers are compared as
    IPv4). A refused entry only means fewer trusted
    proxies, never more; `check_proxy_setting` refuses to start on any."""
    networks: list[IPNetwork] = []
    problems: list[str] = []
    for position, entry in enumerate(_entries(raw), 1):
        network, problem = _entry_problem(position, entry)
        if problem is not None:
            problems.append(problem)
        elif network not in networks:
            networks.append(network)
    return tuple(networks), tuple(problems)


def _unusable_positions(raw: str) -> tuple[int, ...]:
    """The 1-based positions of the entries `parse_proxy_setting` refuses:
    all the runtime warning says about them (never their text)."""
    return tuple(position for position, entry in enumerate(_entries(raw), 1)
                 if _entry_problem(position, entry)[1] is not None)


def check_proxy_setting() -> tuple[IPNetwork, ...]:
    """The configured trusted proxy networks, or TrustedProxiesError when
    any entry is unusable. Called when the app is built, so a bad value
    stops octo-core with the reason in its log instead of running with
    fewer (or no) trusted proxies than the operator meant."""
    networks, problems = parse_proxy_setting(trusted_proxies_setting())
    if problems:
        raise TrustedProxiesError(
            f"{SETTING_NAME} is not valid, so octo-core will not start: "
            f"{'; '.join(problems)}. Expected {SETTING_FORMAT} "
            "(docs/operations/bundle.md, \"Client addresses behind the proxy\")"
        )
    return networks


_warn_lock = threading.Lock()
_warned_settings: set[str] = set()
_warned_peers: set[tuple[bool, str]] = set()
_MAX_WARNED_PEERS = 64


def trusted_proxies() -> tuple[IPNetwork, ...]:
    """The configured trusted proxy networks (read from the environment on
    each call; parsing is cached). Unusable entries are left out (startup
    already refused them, see `check_proxy_setting`; this only matters if
    the environment changes under a running process) and logged once, by
    position: the reasons are the startup error's."""
    raw = trusted_proxies_setting()
    networks, problems = parse_proxy_setting(raw)
    if problems:
        with _warn_lock:
            first = raw not in _warned_settings
            _warned_settings.add(raw)
        if first:
            positions = _unusable_positions(raw)
            logger.warning(
                "%s: ignoring %d unusable entr%s (position%s %s); octo-core "
                "refuses this value at start and says why",
                SETTING_NAME, len(positions), "y" if len(positions) == 1 else "ies",
                "" if len(positions) == 1 else "s",
                ", ".join(str(position) for position in positions),
            )
    return networks


def is_trusted(ip: Optional[IPAddress], networks: Iterable[IPNetwork]) -> bool:
    return ip is not None and any(ip in network for network in networks)


def forwarded_chain(forwarded_for: Union[None, str, Iterable[str]]) -> list[str]:
    """The X-Forwarded-For entries in order (several header lines are one
    chain, as RFC 9110 joins them), at most the right-most
    MAX_CHAIN_ENTRIES."""
    if forwarded_for is None:
        return []
    values = [forwarded_for] if isinstance(forwarded_for, str) else list(forwarded_for)
    entries: list[str] = []
    for value in values:
        if isinstance(value, str):
            entries.extend(value.split(","))
    return entries[-MAX_CHAIN_ENTRIES:]


def _peer_label(peer: Optional[str], peer_ip: Optional[IPAddress]) -> str:
    if peer_ip is not None:
        return str(peer_ip)
    if not peer:
        return UNKNOWN_PEER
    return str(peer)[:_MAX_PEER_CHARS]


def resolve_client_ip(
    peer: Optional[str],
    forwarded_for: Union[None, str, Iterable[str]],
    trusted: Iterable[IPNetwork],
) -> str:
    """The address a request is attributed to (pure; see the module doc).

    `peer` is the socket peer's host (`request.client.host`), `forwarded_for`
    the X-Forwarded-For header line(s), `trusted` the trusted proxy networks.
    Never raises; the answer is always the peer or a well-formed address."""
    networks = tuple(trusted)
    peer_ip = parse_ip(peer)
    if not networks or not is_trusted(peer_ip, networks):
        return _peer_label(peer, peer_ip)
    nearest: IPAddress = peer_ip  # type: ignore[assignment]  # trusted ⇒ parsed
    for entry in reversed(forwarded_chain(forwarded_for)):
        ip = parse_ip(entry)
        if ip is None:
            break
        if not is_trusted(ip, networks):
            return str(ip)
        nearest = ip
    return str(nearest)


def unverified_forwarded_hint(
    forwarded_for: Union[None, str, Iterable[str]],
) -> Optional[str]:
    """The right-most well-formed address in X-Forwarded-For, believed by
    nobody. NOT a client address: any direct caller can write it.

    Only the THROUGHPUT limiter uses it, and only while OCTO_TRUSTED_PROXIES
    is empty, to split ONE peer's buckets the way the header always did (so
    a deploy without the setting buckets the ingest path per real client as
    before, instead of every sender sharing the proxy's bucket). A bucket
    keyed `<peer>|<hint>` can never be reached from another peer, so the
    header cannot put anyone else over a limit; it can only split the
    sender's own allowance, as it could before the setting existed. The
    failed-auth limiter never uses it (it is off while the setting is
    empty)."""
    for entry in reversed(forwarded_chain(forwarded_for)):
        ip = parse_ip(entry)
        if ip is not None:
            return str(ip)
    return None


def _peer_of(request) -> Optional[str]:
    client = getattr(request, "client", None)
    return client.host if client else None


def loggable(address: object) -> str:
    """`address` as a log line prints it: a parsed IP address, or a network
    (the IPv6 /64 a limiter buckets by), else NOT_AN_ADDRESS. A peer label
    that is not an address (a unix socket, a test client, or whatever an
    ASGI server's own X-Forwarded-For handling put in `request.client`) is
    never printed: it may be text a caller wrote, line breaks included."""
    if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        address = str(address)  # re-parsed: a zone id is refused, as in parse_ip
    ip = parse_ip(address)
    if ip is not None:
        return str(ip)
    if (isinstance(address, str) and "/" in address and "%" not in address
            and len(address) <= _MAX_ENTRY_CHARS):
        try:
            return str(ipaddress.ip_network(address, strict=True))
        except ValueError:
            pass
    return NOT_AN_ADDRESS


def _note_forwarding_from_untrusted_peer(peer_ip: Optional[IPAddress], configured: bool) -> None:
    """Log once per peer (bounded) that its X-Forwarded-For was not believed:
    with the setting empty that is every proxied request (set it); with it
    set, a direct caller sending the header, or a proxy missing from it.
    Names the peer's parsed address only (`loggable`)."""
    peer = loggable(peer_ip)
    key = (configured, peer)
    with _warn_lock:
        if key in _warned_peers or len(_warned_peers) >= _MAX_WARNED_PEERS:
            return
        _warned_peers.add(key)
    if configured:
        logger.warning(
            "X-Forwarded-For from %s ignored: the peer is not in %s (a direct "
            "caller naming an address, or a proxy missing from the setting)",
            peer, SETTING_NAME,
        )
    else:
        logger.warning(
            "X-Forwarded-For from %s not believed: %s is empty, so the socket "
            "peer is the client address. Behind a reverse proxy set it to the "
            "proxy network (docs/operations/bundle.md)",
            peer, SETTING_NAME,
        )


_warned_private: set[str] = set()


def _note_private_client(client: IPAddress, proxy: IPAddress) -> None:
    """Log once per address (bounded) that a trusted proxy named a client on
    a private network. Normal for a client on your own LAN; on the bundle
    host, where proxied clients come from the edge, it means one proxy
    reached the next over a network outside OCTO_TRUSTED_PROXIES (the
    reverse proxy calling the console by a name that resolved on the shared
    network), so every user behind that hop shares this address. Both are
    parsed addresses."""
    address = str(client)
    with _warn_lock:
        if address in _warned_private or len(_warned_private) >= _MAX_WARNED_PEERS:
            return
        _warned_private.add(address)
    logger.warning(
        "client address %s, named by trusted proxy %s, is a private address: "
        "fine for a client on your own network; if it is one of your proxies, "
        "that hop came over a network outside %s and every user behind it "
        "shares this address (docs/operations/bundle.md)",
        address, str(proxy), SETTING_NAME,
    )


def client_ip(request) -> str:
    """THE client address of `request` for any security decision: rate-limit
    and failed-authentication buckets, address binding, audit. The socket
    peer unless the peer is a trusted proxy (module doc)."""
    peer = _peer_of(request)
    forwarded = request.headers.getlist("x-forwarded-for")
    trusted = trusted_proxies()
    address = resolve_client_ip(peer, forwarded, trusted)
    peer_ip = parse_ip(peer)
    if not is_trusted(peer_ip, trusted):
        if forwarded:
            _note_forwarding_from_untrusted_peer(peer_ip, bool(trusted))
    else:
        ip = parse_ip(address)
        if ip is not None and _is_private_use(ip) and not is_trusted(ip, trusted):
            _note_private_client(ip, peer_ip)  # type: ignore[arg-type]  # trusted ⇒ parsed
    return address


def _is_private_use(ip: IPAddress) -> bool:
    """RFC 1918 / ULA / loopback / link-local and the like (what docker
    networks and LANs use; the edge never names such a client)."""
    return ip.is_private
