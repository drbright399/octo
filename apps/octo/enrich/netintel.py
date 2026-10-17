"""Who is a remote address — PTR over DNS-over-HTTPS, the owner over RDAP.

WHAT IS CONTACTED, AND WHAT NEVER IS:
  * DNS goes to PUBLIC DoH resolvers addressed BY IP LITERAL
    (`https://1.1.1.1/dns-query`, `https://8.8.8.8/resolve`, the JSON API)
    — the bundle's own resolver is never asked for anything here (it may be
    a filtering resolver whose block page lies, and an IOC must not leave
    through it), and the system resolver (`socket.getaddrinfo` on a name) is
    never used: an RDAP server's name is itself resolved over DoH, then
    reached by its address with the name as the TLS SNI / certificate
    check and the Host header.
  * RDAP goes only to the IANA bootstrap and the five RIRs' RDAP servers
    (`RDAP_HOSTS`); a redirect is followed only to one of them (≤ 2).
  * The REMOTE ADDRESS ITSELF is never contacted: every request's target
    address is checked against the address being looked up (`_guard`) and
    refused if it is the same.
Everything read is untrusted text: cleaned (printable, bounded) and only
ever shown as data.
"""
from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import urlencode, urlsplit

import httpx

from apps.octo.enrich import cache

logger = logging.getLogger(__name__)

DOH_ENDPOINTS: tuple[str, ...] = ("https://1.1.1.1/dns-query", "https://8.8.8.8/resolve")
RDAP_BOOTSTRAP = {4: "https://data.iana.org/rdap/ipv4.json",
                  6: "https://data.iana.org/rdap/ipv6.json"}
RDAP_HOSTS = frozenset({"data.iana.org", "rdap.arin.net", "rdap.db.ripe.net", "rdap.apnic.net",
                        "rdap.lacnic.net", "rdap.afrinic.net"})
RDAP_FALLBACK = "https://rdap.arin.net/registry/"
TIMEOUT_SEC = 8.0
MAX_BYTES = 512 * 1024
MAX_REDIRECTS = 2
USER_AGENT = "athena-octo-enrichment/1"
_TYPES = {"A": 1, "AAAA": 28, "PTR": 12}


class NetIntelError(Exception):
    """A lookup that could not be answered (the class name only is logged)."""


def clean(value: Any, limit: int = 120) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join("".join(c if c.isprintable() else " " for c in value).split())[:limit]


def enrichable(ip: Optional[str]) -> bool:
    """A remote address worth looking up: a valid unicast address outside
    the site's own networks (RFC 1918, CGNAT, link-local, loopback, ULA)."""
    from apps.octo.adapters.unifi.catalogue import is_local

    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return False
    return not (is_local(str(addr)) or addr.is_multicast or addr.is_unspecified
                or addr.is_loopback or addr.is_link_local)


@dataclass(frozen=True)
class IpIntel:
    ip: str
    ptr: Optional[str]
    ptr_confirmed: bool
    org: Optional[str]
    net_name: Optional[str]
    cidr: Optional[str]
    country: Optional[str]
    rir: Optional[str]

    def as_dict(self) -> dict[str, Any]:
        return {"ip": self.ip, "ptr": self.ptr, "ptr_confirmed": self.ptr_confirmed,
                "org": self.org, "net_name": self.net_name, "cidr": self.cidr,
                "country": self.country, "rir": self.rir}


def _vcard_fn(entity: dict[str, Any]) -> str:
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) > 1 and isinstance(card[1], list)):
        return ""
    for prop in card[1]:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
            return clean(prop[3])
    return ""


def _entities(obj: dict[str, Any], depth: int = 0) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for e in (obj.get("entities") or [])[:20] if isinstance(obj.get("entities"), list) else []:
        if isinstance(e, dict):
            out.append(e)
            if depth < 2:
                out.extend(_entities(e, depth + 1))
    return out


def parse_rdap(body: Any) -> dict[str, Optional[str]]:
    """The owner of an IP network from an RDAP answer: the registrant's
    name (else another entity's, else the network's name), the network's
    name, its CIDR, country and registry."""
    if not isinstance(body, dict):
        raise NetIntelError("rdap answer is not an object")
    ents = _entities(body)
    org = ""
    for role in ("registrant", "administrative", "technical"):
        for e in ents:
            roles = e.get("roles")
            if isinstance(roles, list) and role in roles:
                org = _vcard_fn(e)
                if org:
                    break
        if org:
            break
    if not org:
        org = next((n for n in (_vcard_fn(e) for e in ents) if n), "")
    cidr = ""
    for c in body.get("cidr0_cidrs") or [] if isinstance(body.get("cidr0_cidrs"), list) else []:
        if isinstance(c, dict):
            prefix = c.get("v4prefix") or c.get("v6prefix")
            if prefix and isinstance(c.get("length"), int):
                cidr = clean(f"{prefix}/{c['length']}", 60)
                break
    if not cidr and body.get("startAddress") and body.get("endAddress"):
        cidr = clean(f"{body['startAddress']} – {body['endAddress']}", 90)
    port43 = clean(body.get("port43"), 60).lower()
    rir = next((r for r in ("arin", "ripe", "apnic", "lacnic", "afrinic") if r in port43), "")
    return {"org": org or clean(body.get("name")) or None,
            "net_name": clean(body.get("name")) or None, "cidr": cidr or None,
            "country": clean(body.get("country"), 8) or None, "rir": rir or None}


class NetIntel:
    """One lookup session. `client`: an httpx.Client (tests pass one over a
    MockTransport — nothing real is contacted)."""

    def __init__(self, client: Optional[httpx.Client] = None, *,
                 doh: tuple[str, ...] = DOH_ENDPOINTS,
                 cache_get: Callable[..., Any] = cache.get,
                 cache_put: Callable[..., Any] = cache.put) -> None:
        self._client = client or httpx.Client(timeout=TIMEOUT_SEC, follow_redirects=False,
                                              trust_env=False, headers={"User-Agent": USER_AGENT})
        self._own = client is None
        self._doh = doh
        self._get, self._put = cache_get, cache_put
        self.requests = 0

    def close(self) -> None:
        if self._own:
            self._client.close()

    # ----- transport -----

    @staticmethod
    def _guard(target: str, subject: Optional[str]) -> None:
        """Never the address being looked up (nor a name that IS it)."""
        if not subject:
            return
        try:
            same = ipaddress.ip_address(target) == ipaddress.ip_address(subject)
        except ValueError:
            same = target.strip().lower() == subject.strip().lower()
        if same:
            raise NetIntelError("refused: the request would contact the remote address itself")

    def _send(self, url: str, *, subject: Optional[str], host_header: Optional[str] = None,
              accept: str = "application/json") -> httpx.Response:
        parts = urlsplit(url)
        self._guard(parts.hostname or "", subject)
        headers = {"Accept": accept}
        extensions: dict[str, Any] = {}
        if host_header:
            headers["Host"] = host_header
            extensions["sni_hostname"] = host_header
        self.requests += 1
        try:
            r = self._client.get(url, headers=headers, extensions=extensions)
        except httpx.HTTPError as exc:
            raise NetIntelError(type(exc).__name__) from None
        if len(r.content) > MAX_BYTES:
            raise NetIntelError("answer too large")
        return r

    @staticmethod
    def _json(r: httpx.Response) -> Any:
        try:
            return json.loads(r.content.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise NetIntelError("answer is not JSON") from None

    # ----- DNS over HTTPS -----

    def doh(self, name: str, rtype: str, *, subject: Optional[str]) -> list[str]:
        """The `rtype` answers for `name` from the first DoH resolver that
        answers ([] for NXDOMAIN / no data)."""
        last: Optional[Exception] = None
        for endpoint in self._doh:
            url = f"{endpoint}?{urlencode({'name': name, 'type': rtype})}"
            try:
                r = self._send(url, subject=subject, accept="application/dns-json")
                if r.status_code != 200:
                    raise NetIntelError(f"DoH HTTP {r.status_code}")
                body = self._json(r)
            except NetIntelError as exc:
                last = exc
                continue
            if not isinstance(body, dict):
                last = NetIntelError("DoH answer is not an object")
                continue
            if body.get("Status") not in (0, 3):
                last = NetIntelError(f"DoH status {body.get('Status')}")
                continue
            want = _TYPES[rtype]
            return [clean(a.get("data"), 253).rstrip(".") for a in (body.get("Answer") or [])
                    if isinstance(a, dict) and a.get("type") == want and a.get("data")]
        raise NetIntelError(str(last) if last else "no DoH resolver answered")

    def resolve_host(self, host: str, *, subject: Optional[str]) -> list[str]:
        """An RDAP server's addresses — over DoH, cached a day."""
        held = self._get(cache.HOST, host)
        if isinstance(held, dict) and isinstance(held.get("addresses"), list) and \
                held["addresses"]:
            return [str(a) for a in held["addresses"]]
        # A public address only: an answer pointing an RDAP name at the
        # bundle's own networks is never followed.
        addrs = [a for a in self.doh(host, "A", subject=subject) if _is_ip(a) and enrichable(a)]
        if not addrs:
            raise NetIntelError(f"{host} has no address")
        self._put(cache.HOST, host, {"addresses": addrs}, ttl=cache.HOST_TTL)
        return addrs

    def https_json(self, url: str, *, subject: Optional[str]) -> Any:
        """GET an RDAP / bootstrap URL by the server's DoH-resolved address
        (never the system resolver), following ≤ 2 redirects within
        RDAP_HOSTS."""
        for _ in range(MAX_REDIRECTS + 1):
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            if parts.scheme != "https" or host not in RDAP_HOSTS:
                raise NetIntelError("not an RDAP server Athena uses")
            path = parts.path + (f"?{parts.query}" if parts.query else "")
            last: Optional[Exception] = None
            r: Optional[httpx.Response] = None
            for addr in self.resolve_host(host, subject=subject):
                target = f"[{addr}]" if ":" in addr else addr
                try:
                    r = self._send(f"https://{target}{path}", subject=subject, host_header=host,
                                   accept="application/rdap+json, application/json")
                    break
                except NetIntelError as exc:
                    if "refused" in str(exc):
                        raise
                    last = exc
            if r is None:
                raise NetIntelError(str(last) if last else "RDAP unreachable")
            if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                url = r.headers["location"]
                continue
            if r.status_code != 200:
                raise NetIntelError(f"RDAP HTTP {r.status_code}")
            return self._json(r)
        raise NetIntelError("too many RDAP redirects")

    # ----- the two answers -----

    def ptr(self, ip: str) -> tuple[Optional[str], bool]:
        """The PTR name and whether it is FORWARD-CONFIRMED (the name's own
        A / AAAA records include `ip`)."""
        names = self.doh(ipaddress.ip_address(ip).reverse_pointer, "PTR", subject=ip)
        if not names:
            return None, False
        name = names[0].lower()
        try:
            forward = self.doh(name, "AAAA" if ":" in ip else "A", subject=ip)
        except NetIntelError:
            return name, False
        return name, any(_same_ip(a, ip) for a in forward)

    def rdap_base(self, ip: str) -> str:
        version = ipaddress.ip_address(ip).version
        boot = self._get(cache.BOOTSTRAP, f"v{version}")
        if not (isinstance(boot, dict) and isinstance(boot.get("services"), list)):
            try:
                boot = self.https_json(RDAP_BOOTSTRAP[version], subject=ip)
                if isinstance(boot, dict) and isinstance(boot.get("services"), list):
                    self._put(cache.BOOTSTRAP, f"v{version}",
                              {"services": boot["services"]}, ttl=cache.OK_TTL)
            except NetIntelError:
                boot = None
        addr = ipaddress.ip_address(ip)
        best: tuple[int, str] = (-1, RDAP_FALLBACK)
        for svc in (boot or {}).get("services") or []:
            if not (isinstance(svc, list) and len(svc) == 2):
                continue
            urls = [u for u in svc[1] if isinstance(u, str) and u.startswith("https://")]
            for prefix in svc[0] if isinstance(svc[0], list) else []:
                try:
                    net = ipaddress.ip_network(str(prefix), strict=False)
                except ValueError:
                    continue
                if urls and net.version == addr.version and addr in net and \
                        net.prefixlen > best[0]:
                    best = (net.prefixlen, urls[0])
        base = best[1]
        return base if base.endswith("/") else base + "/"

    def rdap(self, ip: str) -> dict[str, Optional[str]]:
        return parse_rdap(self.https_json(f"{self.rdap_base(ip)}ip/{ip}", subject=ip))

    def lookup(self, ip: str) -> IpIntel:
        """PTR (+ forward confirmation) and owner. One of the two may fail
        (the other is still kept); both failing raises."""
        ip = str(ipaddress.ip_address(ip))
        errors: list[str] = []
        try:
            ptr, confirmed = self.ptr(ip)
        except NetIntelError as exc:
            ptr, confirmed = None, False
            errors.append(f"ptr: {exc}")
        try:
            owner = self.rdap(ip)
        except NetIntelError as exc:
            owner = {}
            errors.append(f"rdap: {exc}")
        if len(errors) == 2:
            raise NetIntelError("; ".join(errors))
        return IpIntel(ip, ptr, confirmed, owner.get("org"), owner.get("net_name"),
                       owner.get("cidr"), owner.get("country"), owner.get("rir"))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _same_ip(a: str, b: str) -> bool:
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return False
