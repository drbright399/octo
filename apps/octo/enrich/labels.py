"""Labels for a remote address: a KNOWN INTERNET SCANNER (research and
attack-surface scanners that touch every address on the internet) or KNOWN
VENDOR INFRASTRUCTURE (a backup cloud, an RMM relay). Information for the
analyst only — a label never hides, lowers or suppresses anything.

The evidence a label rests on, strongest first:
  network  the address is in a range the scanner publishes (static list
           below — review it when a vendor announces new ranges);
  ptr      the PTR name ends in the vendor's domain AND is forward-
           confirmed (the name resolves back to the address — a PTR alone
           is whatever the address's owner wrote);
  rdap     the registry's owner of the network names the vendor (a WHOLE
           word of the org / network name — the holder's own words: the
           console shows it as "owner name mentions …").
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional

# Published scanner ranges (2026). Cortex Xpanse's two are Rick's examples.
SCANNER_NETWORKS: tuple[tuple[str, str], ...] = (
    ("147.185.132.0/23", "Palo Alto Cortex Xpanse"),  # scan-sensitive: allow[ip-public] Cortex Xpanse published scanner range
    ("35.203.210.0/23", "Palo Alto Cortex Xpanse"),  # scan-sensitive: allow[ip-public] Cortex Xpanse published scanner range
    ("162.142.125.0/24", "Censys"),  # scan-sensitive: allow[ip-public] Censys published scanner range
    ("167.94.138.0/24", "Censys"),  # scan-sensitive: allow[ip-public] Censys published scanner range
    ("167.94.145.0/24", "Censys"),  # scan-sensitive: allow[ip-public] Censys published scanner range
    ("167.94.146.0/24", "Censys"),  # scan-sensitive: allow[ip-public] Censys published scanner range
    ("167.248.133.0/24", "Censys"),  # scan-sensitive: allow[ip-public] Censys published scanner range
    ("199.45.154.0/24", "Censys"),  # scan-sensitive: allow[ip-public] Censys published scanner range
    ("199.45.155.0/24", "Censys"),  # scan-sensitive: allow[ip-public] Censys published scanner range
    ("206.168.34.0/24", "Censys"),  # scan-sensitive: allow[ip-public] Censys published scanner range
    ("2602:80d:1000::/44", "Censys"),
)
# PTR domain → scanner (a forward-confirmed PTR ending in it).
SCANNER_DOMAINS: tuple[tuple[str, str], ...] = (
    ("censys-scanner.com", "Censys"),
    ("shodan.io", "Shodan"),
    ("onyphe.net", "Onyphe"),
    ("infrawatch.io", "InfraWatch (Hydra)"),
    ("modat.io", "Modat"),
    ("shadowserver.org", "Shadowserver"),
    ("binaryedge.ninja", "BinaryEdge"),
    ("stretchoid.com", "Stretchoid"),
    ("internet-measurement.com", "internet-measurement.com (Driftnet)"),
    ("leakix.net", "LeakIX"),
    ("recyber.net", "Recyber"),
)
# RDAP owner words → scanner.
SCANNER_OWNERS: tuple[tuple[str, str], ...] = (
    ("censys", "Censys"), ("shodan", "Shodan"), ("onyphe", "Onyphe"),
    ("infrawatch", "InfraWatch (Hydra)"),
    ("modat", "Modat"), ("shadowserver", "Shadowserver"), ("binaryedge", "BinaryEdge"),
    ("stretchoid", "Stretchoid"), ("internet measurement", "internet-measurement.com (Driftnet)"),
    ("driftnet", "internet-measurement.com (Driftnet)"), ("leakix", "LeakIX"),
)
# PTR domain → vendor infrastructure.
VENDOR_DOMAINS: tuple[tuple[str, str], ...] = (
    ("dattobackup.com", "Datto backup cloud"),
    ("datto.com", "Datto"),
    ("centrastage.net", "Datto RMM"),
    ("kaseya.net", "Kaseya"),
    ("kaseya.com", "Kaseya"),
    ("rocketcyber.com", "RocketCyber"),
    ("nextdns.io", "NextDNS"),
    ("ui.com", "Ubiquiti"),
)

_NETS = tuple((ipaddress.ip_network(n), name) for n, name in SCANNER_NETWORKS)
# WHOLE words of the owner's names ("modat" never matches "Accommodation";
# "CENSYS-ARIN-01" still matches "censys"). The owner's name is whatever the
# holder of the network registered: an RDAP label reads "owner name
# mentions …" in the console, never a verdict.
_OWNER_PATTERNS = tuple(
    (word, re.compile(r"(?<![a-z0-9])" + re.escape(word).replace(r"\ ", r"[\s_-]+")
                      + r"(?![a-z0-9])"), name)
    for word, name in SCANNER_OWNERS)


def _under(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


def labels(ip: str, info: Optional[dict[str, Any]]) -> list[dict[str, Any]]:
    """[{kind: 'scanner' | 'vendor', name, basis: 'network' | 'ptr' |
    'rdap'}] — deduplicated by (kind, name), strongest basis first."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, name: str, basis: str) -> None:
        if (kind, name) not in seen:
            seen.add((kind, name))
            out.append({"kind": kind, "name": name, "basis": basis})

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return out
    for net, name in _NETS:
        if addr.version == net.version and addr in net:
            add("scanner", name, "network")
    info = info or {}
    ptr = str(info.get("ptr") or "").lower().rstrip(".")
    if ptr and info.get("ptr_confirmed"):
        for domain, name in SCANNER_DOMAINS:
            if _under(ptr, domain):
                add("scanner", name, "ptr")
        for domain, name in VENDOR_DOMAINS:
            if _under(ptr, domain):
                add("vendor", name, "ptr")
    owner = " ".join(str(info.get(k) or "") for k in ("org", "net_name")).lower()
    if owner.strip():
        for word, pattern, name in _OWNER_PATTERNS:
            if pattern.search(owner):
                add("scanner", name, "rdap")
    return out
