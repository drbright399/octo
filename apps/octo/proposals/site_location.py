"""Autotask addresses → Fleet SITE-location proposals (kind 'site_location',
source 'autotask').

WHAT IS READ. Per Autotask instance, the companies MAPPED to an ACTIVE
tenant (`autotask_tenant_company_map`, and numeric company ids in the
generic `adapter_tenant_map`), ACTIVE ones only, address fields only
(`AutotaskClient.query_companies`), and their active CompanyLocations
(`query_company_locations`). When CompanyLocations is refused (the API
user's security level, or not offered) the company address alone is used —
the review panel says so (`last_refresh.locations`). Nothing else is read,
and nothing is sent anywhere: the refresh NEVER geocodes.

CANDIDATES. The company address and each active location, normalized
(`address.parse`): US only (countryID 237 or none) — anything else is
skipped and counted (`skipped_non_us`); an empty address is dropped. Inside
one tenant, the same address (same street / city / state and unit) is ONE
candidate — the company record wins (it is read whether or not
CompanyLocations is), the duplicates' names are kept for the matching; on a
run that could not read CompanyLocations, the company record keeps the names
its open proposal was matched with (its target never flips with the API
user's rights or a timeout). A company mapped to TWO tenants is a candidate
of each (flagged `shared_company`, never pre-assigned to a site).

RECORDS. A proposal belongs to one Autotask instance (its `instance_id`;
the source hash names it) and one tenant: a company re-mapped to another
client is a new record there, and the old client's open proposal closes;
one instance's refresh never touches another's proposals.

TARGET (which Fleet entry a candidate pins):
  * a tenant with no UniFi site → its own tenant-level Fleet entry (the `t-`
    key — the pin the drawer edits for such a client);
  * ONE UniFi site → that site (several distinct addresses for it are each
    proposed, flagged `several_addresses`: the operator confirms the one
    where the site is) — flagged `site_name_differs` when the site's name
    says something none of the address's names do (a client's only site is
    a branch, its Autotask address the head office);
  * SEVERAL UniFi sites → the site whose name (or console name) best matches
    the candidate's name — token overlap, the tenant's / company's own words
    and generic words ("office", "main", "inc") ignored, at least half the
    tokens shared, one clear winner — else NO target ("pick a site": the
    operator chooses when confirming). A company address of a multi-site
    client is usually that.
  * a company shared by two tenants → NO target, whatever the sites.
A CONFIRMED proposal is offered again only for a new UniFi site of its
tenant while the confirmed target is gone (a client that gained sites, a
site re-mapped) — never because a UniFi instance is disabled for a while.

WARNINGS (flags_json):
  shared_address        the same street / city / state is a candidate of a
                        DIFFERENT tenant too (listed). Never merged: two
                        businesses at one address are two proposals.
  shared_company        the Autotask company is mapped to other tenants too
                        (listed): whose address it is, is the operator's call.
  incomplete            no street (or only a PO box — `po_box`), or no ZIP.
  several_addresses     a single-site (or tenant-level) client with more than
                        one distinct address in Autotask.
  site_name_differs     a single-site client whose site's name matches none
                        of the address's names.
  current_pin_differs   the target already has a pin set by hand (its own —
                        typed or confirmed earlier — or the client's fallback
                        location): confirming pins it here instead. Settled
                        when the operator's lookup lands within 250 m of it.
  far_from_console      after a lookup only: the first match is more than
                        25 km from where the site's UniFi console says it is.
The last two are recomputed whenever proposals are read (`live_flags`) —
against the target only while it is still the proposal's tenant's.

WHEN. On demand (admin+, "Refresh from Autotask") and daily from the
Autotask poller (`due` + `refresh_scheduled`); one refresh at a time; the
outcome (counts only — never a name or an address) is kept per instance in
`adapter_poller_state` under `location_proposals` for the panel.

LOOKUP / CONFIRM. The geocoder runs only when an operator presses Look up on
ONE proposal (the one-line address, unit stripped — nothing else leaves the
box). A confirm writes the site location with origin 'autotask' and closes
the proposal in ONE registry transaction — only if the proposal and the
site's pin are still what the operator reviewed; the API audits before it.
"""
from __future__ import annotations

import hashlib
import logging
import math
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.fleet import build, geocode, locations
from apps.octo.proposals import address as addr
from apps.octo.proposals import store

logger = logging.getLogger(__name__)

KIND = "site_location"
SOURCE = "autotask"
STATE_KEY = "location_proposals"
FAR_KM = 25.0
SAME_PIN_KM = 0.25
MATCH_MIN = 0.5
DAILY_SEC = 24 * 3600.0
LIVE_FLAGS = ("current_pin_differs", "far_from_console")

# Words that say nothing about WHICH site a name means.
_NOISE = frozenset({
    "the", "of", "and", "at", "a", "an", "inc", "llc", "ltd", "llp", "lp", "co", "corp",
    "corporation", "company", "pllc", "pc", "pa", "dba", "group", "services", "site", "sites",
    "default", "main", "office", "offices", "hq", "headquarters", "location", "locations",
    "network", "unifi", "primary", "building",
})

_refresh_lock = threading.Lock()


class RefreshBusy(Exception):
    """Another refresh is running."""


# ---------------------------------------------------------------------------
# What the proposer needs of the Fleet
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SiteRef:
    key: str
    tenant_slug: str
    kind: str                                   # 'unifi' | 'tenant'
    name: str
    console_name: str
    console_location: Optional[locations.Location]
    location: Optional[locations.Location]


def fleet_refs(entries: Iterable[Any]) -> list[SiteRef]:
    """`build.SiteEntry` → SiteRef (name, console, what the console reports,
    the effective pin)."""
    out: list[SiteRef] = []
    for e in entries:
        unifi = getattr(e, "unifi", None) or {}
        out.append(SiteRef(key=e.key, tenant_slug=e.tenant_slug, kind=e.kind, name=e.name or "",
                           console_name=e.console_name or "",
                           console_location=unifi.get("console_location"),
                           location=e.location))
    return out


def tenant_key(slug: str) -> str:
    return build.site_key("tenant", slug)


def valid_targets(slug: str, refs: Iterable[SiteRef]) -> list[str]:
    """Where a proposal of this tenant may be confirmed: its UniFi sites, or
    — a client without one — its tenant-level entry."""
    sites = [r.key for r in refs if r.tenant_slug == slug and r.kind == "unifi"]
    return sites or [tenant_key(slug)]


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    tenant_slug: str
    tenant_name: str
    company_id: int
    company_name: str
    origin: str                                 # 'company' | 'location'
    location_id: Optional[int]
    name: str
    is_primary: bool
    address: addr.Address
    instance_id: int
    names: list[str] = field(default_factory=list)
    shared_with: list[str] = field(default_factory=list)
    """Other tenants the same Autotask company is mapped to."""
    target_key: Optional[str] = None
    target_mode: str = "pick"                   # 'site' | 'tenant' | 'pick'
    match: Optional[dict[str, Any]] = None
    flags: list[dict[str, Any]] = field(default_factory=list)

    @property
    def source_ref(self) -> str:
        return f"location:{self.location_id}" if self.origin == "location" \
            else f"company:{self.company_id}"

    def source_hash(self) -> str:
        """The normalized source data, the tenant it maps to (a company
        re-mapped to another client is new data for that client) and the
        Autotask instance it was read from (two instances' company ids are
        two namespaces)."""
        body = store.dumps({"instance": self.instance_id, "tenant": self.tenant_slug,
                            "ref": self.source_ref, "address": self.address.digest()})
        return hashlib.sha256(body.encode("utf-8")).hexdigest()[:32]

    def payload(self) -> dict[str, Any]:
        return {
            "origin": self.origin, "company_id": self.company_id,
            "location_id": self.location_id, "instance_id": self.instance_id,
            "name": self.name, "names": self.names, "is_primary": self.is_primary,
            "address": self.address.as_dict(), "query": self.address.query(),
            "label": self.address.label(), "target_mode": self.target_mode,
            "match": self.match,
        }


def mapped_companies(instance_id: int) -> dict[int, list[str]]:
    """Autotask company id → the tenant slugs it is mapped to for this
    instance (sorted; usually one — the maps allow a company on two
    tenants): the Autotask company map (015) and numeric ids of the generic
    tenant map (030). {} when neither is readable."""
    out: dict[int, list[str]] = {}
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError):
        return out
    try:
        for sql in ("SELECT autotask_company_id, tenant_slug FROM autotask_tenant_company_map "
                    "WHERE adapter_instance_id = ? ORDER BY tenant_slug",
                    "SELECT vendor_tenant_id, octo_client_slug FROM adapter_tenant_map "
                    "WHERE adapter_instance_id = ? ORDER BY vendor_tenant_id"):
            try:
                rows = reg.execute(sql, (int(instance_id),)).fetchall()
            except sqlite3.OperationalError:
                continue
            for cid, slug in rows:
                try:
                    company = int(str(cid).strip())
                except (TypeError, ValueError):
                    continue
                slugs = out.setdefault(company, []) if slug and company >= 0 else None
                if slugs is not None and str(slug) not in slugs:
                    slugs.append(str(slug))
    finally:
        reg.close()
    return {company: sorted(slugs) for company, slugs in out.items()}


def _int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _parse(rec: dict[str, Any]) -> addr.Address:
    return addr.parse(rec.get("address1"), rec.get("address2"), rec.get("city"),
                      rec.get("state"), rec.get("postalCode"), rec.get("countryID"))


def _empty(a: addr.Address) -> bool:
    return not (a.street or a.city or a.zip)


def build_candidates(companies: list[dict[str, Any]], company_locations: list[dict[str, Any]],
                     mapping: dict[int, list[str]], tenant_names: dict[str, str],
                     instance_id: int) -> tuple[list[Candidate], list[dict[str, Any]]]:
    """(candidates, skipped) — skipped: [{tenant, ref, why: 'non_us'}]. A
    company mapped to several tenants is a candidate of each."""
    skipped: list[dict[str, Any]] = []
    raw: list[Candidate] = []
    active: dict[int, tuple[dict[str, Any], list[str]]] = {}
    for c in companies:
        cid = _int(c.get("id"))
        slugs = [s for s in mapping.get(cid, []) if s in tenant_names] if cid is not None else []
        if cid is None or c.get("isActive") is False or not slugs:
            continue
        active[cid] = (c, slugs)
    for cid, (c, slugs) in sorted(active.items()):
        cname = addr.clean(c.get("companyName"), 200)
        for slug in slugs:
            raw.append(Candidate(slug, tenant_names[slug], cid, cname, "company", None, cname,
                                 False, _parse(c), instance_id,
                                 shared_with=[s for s in slugs if s != slug]))
    for loc in sorted(company_locations, key=lambda x: _int(x.get("id")) or 0):
        lid, cid = _int(loc.get("id")), _int(loc.get("companyID"))
        if lid is None or cid not in active or loc.get("isActive") is False:
            continue
        c, slugs = active[cid]
        cname = addr.clean(c.get("companyName"), 200)
        for slug in slugs:
            raw.append(Candidate(slug, tenant_names[slug], cid, cname, "location", lid,
                                 addr.clean(loc.get("name"), 200) or cname,
                                 loc.get("isPrimary") is True, _parse(loc), instance_id,
                                 shared_with=[s for s in slugs if s != slug]))
    kept: list[Candidate] = []
    groups: dict[tuple[str, str], list[Candidate]] = {}
    for cand in raw:
        if _empty(cand.address):
            continue
        if not cand.address.us:
            skipped.append({"tenant": cand.tenant_slug, "ref": cand.source_ref,
                            "why": "non_us"})
            continue
        key = cand.address.key()
        ident = f"{key}#{cand.address.digest()['unit']}" if key else \
            store.dumps(cand.address.digest())
        groups.setdefault((cand.tenant_slug, ident), []).append(cand)
    for group in groups.values():
        # The company record first (read with or without CompanyLocations,
        # so the proposal does not change with the API user's rights); then
        # one with a ZIP, the primary location, the oldest.
        best = min(group, key=lambda c: (c.origin != "company", not c.address.zip,
                                         not c.is_primary, c.location_id or 0))
        names: list[str] = []
        for cand in [best, *[g for g in group if g is not best]]:
            for n in (cand.name, cand.company_name if cand.origin == "company" else ""):
                if n and n not in names:
                    names.append(n)
        best.names = names
        kept.append(best)
    kept.sort(key=lambda c: (c.tenant_slug, c.origin != "company", c.location_id or 0))
    return kept, skipped


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

def _tokens(*names: Optional[str], noise: frozenset[str] | set[str]) -> set[str]:
    return {t for t in addr.name_tokens(*names) if t not in noise and not t.isdigit()
            and len(t) >= 2}


def _score(a: set[str], b: set[str]) -> tuple[float, set[str]]:
    if not a or not b:
        return 0.0, set()
    shared = a & b
    return len(shared) / len(a | b), shared


def match_site(names: list[str], sites: list[SiteRef], noise: set[str]) -> \
        Optional[tuple[SiteRef, float]]:
    """The one site these names clearly mean, or None (conservative)."""
    want = _tokens(*names, noise=noise)
    if not want:
        return None
    scored: list[tuple[float, SiteRef, set[str]]] = []
    for s in sites:
        best = max((_score(want, _tokens(n, noise=noise)) for n in (s.name, s.console_name)),
                   key=lambda x: x[0])
        scored.append((best[0], s, best[1]))
    scored.sort(key=lambda x: -x[0])
    top = scored[0]
    second = scored[1][0] if len(scored) > 1 else 0.0
    if top[0] >= MATCH_MIN and top[0] > second and any(len(t) >= 3 for t in top[2]):
        return top[1], round(top[0], 2)
    return None


def assign_targets(cands: list[Candidate], refs: list[SiteRef]) -> None:
    by_tenant: dict[str, list[SiteRef]] = {}
    for r in refs:
        if r.kind == "unifi":
            by_tenant.setdefault(r.tenant_slug, []).append(r)
    per_tenant: dict[str, list[Candidate]] = {}
    for c in cands:
        per_tenant.setdefault(c.tenant_slug, []).append(c)
    for slug, group in per_tenant.items():
        sites = sorted(by_tenant.get(slug, []), key=lambda r: r.key)
        noise = set(_NOISE) | addr.name_tokens(group[0].tenant_name)
        for c in group:
            noise |= addr.name_tokens(c.company_name)
        for c in group:
            if c.shared_with:
                # One Autotask company on several clients: whose address
                # this is, is the operator's call — never pre-assigned.
                c.target_key, c.target_mode, c.match = None, "pick", None
            elif not sites:
                c.target_key, c.target_mode, c.match = tenant_key(slug), "tenant", None
            elif len(sites) == 1:
                c.target_key, c.target_mode = sites[0].key, "site"
                c.match = {"why": "only_site"}
                if _name_differs(c, sites[0], noise):
                    c.flags.append({"code": "site_name_differs", "site": sites[0].name})
            else:
                hit = match_site(c.names or [c.name], sites, noise)
                if hit is None:
                    c.target_key, c.target_mode, c.match = None, "pick", None
                else:
                    c.target_key, c.target_mode = hit[0].key, "site"
                    c.match = {"why": "name", "site": hit[0].name, "score": hit[1]}
        if len(group) > 1 and len(sites) <= 1:
            for c in group:
                c.flags.append({"code": "several_addresses", "count": len(group)})


def _name_differs(c: Candidate, only: SiteRef, noise: set[str]) -> bool:
    """A single-site client's site whose name says something (not "Default",
    not the client's own name) that none of the address's names — nor its
    street or city — say: the address may be another building of the client
    (a branch vs the head office)."""
    said = _tokens(only.name, noise=noise)
    if not any(len(t) >= 3 for t in said):
        return False
    mine = _tokens(*(c.names or [c.name]), c.address.street, c.address.city, noise=noise)
    return not (said & mine)


# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------

def km(a_lat: float, a_lng: float, b_lat: float, b_lng: float) -> float:
    la1, lo1, la2, lo2 = map(math.radians, (a_lat, a_lng, b_lat, b_lng))
    h = math.sin((la2 - la1) / 2) ** 2 + \
        math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371.0 * math.asin(min(1.0, math.sqrt(h)))


def flag_candidates(cands: list[Candidate], refs: list[SiteRef]) -> None:
    """shared_address, shared_company, incomplete, current_pin_differs
    (refresh time)."""
    tenants_at: dict[str, set[str]] = {}
    for c in cands:
        k = c.address.key()
        if k:
            tenants_at.setdefault(k, set()).add(c.tenant_slug)
    by_key = {r.key: r for r in refs}
    for c in cands:
        others = sorted(tenants_at.get(c.address.key(), set()) - {c.tenant_slug}) \
            if c.address.key() else []
        if others:
            c.flags.append({"code": "shared_address", "tenants": others})
        if c.shared_with:
            c.flags.append({"code": "shared_company", "tenants": sorted(c.shared_with)})
        missing = c.address.missing()
        if missing:
            c.flags.append({"code": "incomplete", "missing": missing,
                            **({"po_box": True} if c.address.po_box else {})})
        pin = _hand_pin(own_ref(by_key, c.target_key, c.tenant_slug))
        if pin is not None:
            c.flags.append(pin)


def own_ref(refs_by_key: dict[str, SiteRef], key: Optional[str],
            slug: str) -> Optional[SiteRef]:
    """The Fleet entry `key` — only while it is `slug`'s: a site re-mapped
    to another tenant shows nothing of that tenant (its name, its pin, its
    console) on this tenant's proposal (`locations.site_override_for`'s
    rule)."""
    ref = refs_by_key.get(key) if key else None
    return ref if ref is not None and ref.tenant_slug == slug else None


def _hand_pin(ref: Optional[SiteRef]) -> Optional[dict[str, Any]]:
    """The target's pin set by hand — its own ('site': typed, or confirmed
    from a proposal) or the client's fallback ('manual', Settings →
    Tenants) — as a warning."""
    loc = ref.location if ref is not None else None
    if loc is None or loc.source not in ("site", "manual"):
        return None
    return {"code": "current_pin_differs",
            "pin": {"lat": loc.lat, "lng": loc.lng, "label": loc.label, "source": loc.source,
                    "origin": loc.origin}}


def live_flags(p: store.Proposal, refs_by_key: dict[str, SiteRef]) -> list[dict[str, Any]]:
    """An OPEN proposal's warnings as of now: the stored ones, with
    current_pin_differs and far_from_console recomputed against today's
    pin / console of its target — while the target is still the proposal's
    tenant's (a decided proposal keeps what it was decided with)."""
    if not p.open:
        return list(p.flags)
    out = [f for f in p.flags if isinstance(f, dict) and f.get("code") not in LIVE_FLAGS]
    ref = own_ref(refs_by_key, p.target_key, p.tenant_slug)
    first = _first_match(p)
    pin = _hand_pin(ref)
    if pin is not None and not (first is not None and km(
            first["lat"], first["lng"], pin["pin"]["lat"], pin["pin"]["lng"]) <= SAME_PIN_KM):
        out.append(pin)
    far = _far(first, ref)
    if far is not None:
        out.append(far)
    return out


def _first_match(p: store.Proposal) -> Optional[dict[str, Any]]:
    matches = (p.geocode or {}).get("matches")
    if not isinstance(matches, list) or not matches or not isinstance(matches[0], dict):
        return None
    m = matches[0]
    return m if locations.valid_pair(m.get("lat"), m.get("lng")) else None


def _far(match: Optional[dict[str, Any]], ref: Optional[SiteRef]) -> Optional[dict[str, Any]]:
    console = ref.console_location if ref is not None else None
    if match is None or console is None:
        return None
    d = km(match["lat"], match["lng"], console.lat, console.lng)
    return {"code": "far_from_console", "km": round(d, 1)} if d > FAR_KM else None


# ---------------------------------------------------------------------------
# The refresh
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def refresh(client: Any, instance_id: int, *, fleet: Iterable[Any],
            trigger: str = "manual") -> dict[str, Any]:
    """Read Autotask (mapped active companies + their locations) and sync the
    proposals. RefreshBusy while another refresh runs; an Autotask error on
    the COMPANIES read propagates (nothing is changed); a CompanyLocations
    failure falls back to the company addresses. Returns the summary (counts
    only), also kept for the panel."""
    from apps.octo.adapters.autotask.client import (
        AutotaskAuthError,
        AutotaskClientError,
        AutotaskRefusedError,
    )
    from apps.octo.fleet import sources
    from apps.octo.instances import poller_state

    if not _refresh_lock.acquire(blocking=False):
        raise RefreshBusy()
    try:
        tenants = {slug: t.name for slug, t in sources.tenants().items()}
        mapping = {cid: kept for cid, slugs in mapped_companies(instance_id).items()
                   if (kept := [s for s in slugs if s in tenants])}
        companies = client.query_companies(sorted(mapping)) if mapping else []
        read_ids = sorted({cid for c in companies
                           if (cid := _int(c.get("id"))) is not None and cid in mapping
                           and c.get("isActive") is not False})
        locs: list[dict[str, Any]] = []
        loc_state = "none"
        if read_ids:
            try:
                locs = client.query_company_locations(read_ids)
                loc_state = "read"
            except AutotaskRefusedError:
                loc_state = "refused"
            except AutotaskAuthError:
                raise
            except AutotaskClientError:
                loc_state = "unavailable"

        def owns(p: store.Proposal) -> bool:
            # This instance's proposals only (another instance's company ids
            # are another namespace).
            return p.source == SOURCE and p.payload.get("instance_id") in (None, instance_id)

        cands, skipped = build_candidates(companies, locs, mapping, tenants, instance_id)
        if loc_state != "read":
            _keep_matched_names(cands, owns)
        refs = fleet_refs(fleet)
        assign_targets(cands, refs)
        flag_candidates(cands, refs)
        items = [store.Item(c.tenant_slug, c.target_key, c.source_ref, c.source_hash(),
                            c.payload(), c.flags) for c in cands]
        sites_now = {r.key for r in refs if r.kind == "unifi"}
        # Per tenant: the Fleet entries that are its own now.
        own_now: dict[str, set[str]] = {s: set(valid_targets(s, refs)) for s in tenants}
        read_pairs = {(cid, slug) for cid in read_ids for slug in mapping[cid]}

        def may_sweep(p: store.Proposal) -> bool:
            # What this run read in full: every company record; the location
            # records too when CompanyLocations was read — else only those
            # of a company no longer read for that tenant (inactive,
            # unmapped, re-mapped).
            if not owns(p):
                return False
            if p.source_ref.startswith("company:"):
                return True
            if p.source_ref.startswith("location:"):
                return loc_state in ("read", "none") or \
                    (p.payload.get("company_id"), p.tenant_slug) not in read_pairs
            return False

        def may_retarget(confirmed: store.Proposal, item: store.Item) -> bool:
            # A confirmed address is offered again only for a NEW UniFi site
            # of its tenant while the confirmed target is no longer the
            # tenant's (a client that gained sites, a site re-mapped to
            # another client) — never for the client-level entry a disabled
            # UniFi instance leaves behind.
            return item.target_key in sites_now and \
                confirmed.target_key not in own_now.get(item.tenant_slug, set())

        counts = store.sync(KIND, SOURCE, items, keep_flags=("far_from_console",), owns=owns,
                            may_sweep=may_sweep, may_retarget=may_retarget)
        summary: dict[str, Any] = {
            "at": _now_iso(), "trigger": trigger, "instance_id": instance_id,
            "companies_mapped": len(mapping), "companies_read": len(read_ids),
            "locations": loc_state, "locations_read": len(locs),
            "candidates": len(cands), "skipped_non_us": len(skipped),
            "skipped_tenants": sorted({s["tenant"] for s in skipped}), **counts,
        }
        poller_state.save(instance_id, STATE_KEY, summary)
        logger.info("[proposals] %s refresh (instance %s): %d companies, locations %s, "
                    "%d candidates, %d new, %d superseded", trigger, instance_id,
                    len(read_ids), loc_state, len(cands), counts["created"],
                    counts["superseded"])
        return summary
    finally:
        _refresh_lock.release()


def _keep_matched_names(cands: list[Candidate], owns: Any) -> None:
    """CompanyLocations not read this run: a company record keeps the names
    its open proposal (the same data) was matched with — the locations'
    names merged into it on the last full read — so its target (and a
    lookup's settled warnings) never flip with the API user's rights or a
    timeout."""
    stored: dict[tuple[str, str, str], list[str]] = {}
    for p in store.list_proposals(KIND, statuses=(store.OPEN,)):
        names = p.payload.get("names")
        if owns(p) and isinstance(names, list):
            stored[(p.source_ref, p.tenant_slug, p.source_hash)] = \
                [n for n in names if isinstance(n, str)]
    for c in cands:
        for n in stored.get((c.source_ref, c.tenant_slug, c.source_hash()), []):
            if n not in c.names:
                c.names.append(n)


def last_refresh(instance_id: int) -> Optional[dict[str, Any]]:
    from apps.octo.instances import poller_state

    value = poller_state.load(instance_id, STATE_KEY)
    return value if isinstance(value, dict) else None


def due(instance_id: int, every_sec: float = DAILY_SEC, *,
        now: Optional[datetime] = None) -> bool:
    """True when the last refresh (any trigger) is older than `every_sec`,
    or there was none."""
    last = last_refresh(instance_id)
    at = last.get("at") if last else None
    if not isinstance(at, str):
        return True
    try:
        when = datetime.strptime(at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    return ((now or datetime.now(timezone.utc)) - when).total_seconds() >= every_sec


def refresh_scheduled(client: Any, instance_id: int) -> Optional[dict[str, Any]]:
    """The daily run (the Autotask poller's thread): the Fleet as the API
    sees it (the process's running instances), else built without them."""
    from apps.octo.instances.manager import current_manager

    manager = current_manager()
    model = build.get_model(manager) if manager is not None else build.build(None)
    try:
        return refresh(client, instance_id, fleet=model.sites, trigger="daily")
    except RefreshBusy:
        return None


# ---------------------------------------------------------------------------
# Lookup, confirm, reject (the API authorizes and audits first)
# ---------------------------------------------------------------------------

def lookup(p: store.Proposal, refs_by_key: dict[str, SiteRef]) -> list[dict[str, Any]]:
    """Ask the geocoder for this proposal's address (the one-line query,
    unit stripped) and keep the matches. geocode.GeocodeError propagates
    (invalid / off / unreachable)."""
    query = geocode.clean_address(p.payload.get("query"))
    matches = geocode.lookup(query)
    ref = own_ref(refs_by_key, p.target_key, p.tenant_slug)
    console = ref.console_location if ref is not None else None
    out = []
    for m in matches:
        item = m.as_dict()
        if console is not None:
            item["km_from_console"] = round(km(m.lat, m.lng, console.lat, console.lng), 1)
        out.append(item)
    geo = {"provider": geocode.provider(), "at": _now_iso(), "matches": out}
    flags = [f for f in p.flags if isinstance(f, dict) and f.get("code") != "far_from_console"]
    far = _far(out[0] if out else None, ref)
    if far is not None:
        flags.append(far)
    if not store.set_lookup(p.id, geo, flags):
        raise store.ProposalError("this proposal was decided or replaced meanwhile — reload")
    return out


def pin_set_at(key: str, slug: str, *, conn: Optional[sqlite3.Connection] = None) -> Optional[str]:
    """When `key`'s own pin (a site override of THIS tenant) was last set —
    None when it has none. What a confirm is checked against."""
    row = locations.site_override_for(locations.all_site_overrides(conn), key, slug)
    at = row.get("set_at") if row is not None else None
    return at if isinstance(at, str) else None


_UNCHECKED = object()

PIN_CHANGED = "the site's pin changed since you loaded it — reload, then confirm again"


def confirm(p: store.Proposal, *, key: str, lat: float, lng: float, label: str, actor: int,
            reason: str, expected_updated_at: Optional[str] = None,
            expected_pin_set_at: Any = _UNCHECKED) -> None:
    """Pin `key` at (lat, lng) with origin 'autotask' and close the proposal
    as confirmed — one transaction (both or neither), and only if the
    proposal (`expected_updated_at`) and the site's own pin
    (`expected_pin_set_at`: its set_at, None = no pin) are still what the
    operator reviewed — else ProposalError and nothing is written."""
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            if expected_pin_set_at is not _UNCHECKED and \
                    pin_set_at(key, p.tenant_slug, conn=reg) != expected_pin_set_at:
                raise store.ProposalError(PIN_CHANGED)
            store.decide(reg, p.id, "confirmed", actor=actor, reason=reason, target_key=key,
                         expected_updated_at=expected_updated_at)
            locations.write_site_override(reg, key, p.tenant_slug, lat, lng, label,
                                          actor=actor, origin="autotask", proposal_id=p.id)
    finally:
        reg.close()
    build.invalidate()


def reject(p: store.Proposal, *, actor: int, reason: str,
           expected_updated_at: Optional[str] = None) -> None:
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            store.decide(reg, p.id, "rejected", actor=actor, reason=reason,
                         expected_updated_at=expected_updated_at)
    finally:
        reg.close()
