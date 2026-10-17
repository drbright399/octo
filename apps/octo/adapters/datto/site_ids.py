"""Each MAPPED Datto site's numeric portal id — what the Fleet drawer's "Open
in Datto RMM — <site>" link is built from (`links.site_portal_url`).

The portal addresses a site by a NUMBER (``/site/<number>/<name slug>``);
mappings, alerts and the device list carry only the site UID. The account's
site list (``GET /api/v2/account/sites`` — `DattoClient.list_sites_drained`,
the read the mapping picker makes) carries both.

  READ   by the inventory poller only (`InventoryPoller`), NEVER on a page
         load: at most once a day (`REFRESH`), sooner only when a site was
         mapped since the last read — at most one try per mapped set a day,
         failed or not. An HTTP 429 holds the inventory like any other read.
  KEEP   for the instance's MAPPED site uids only: uid → {id, name} — the
         digits (`links.site_portal_id`: 1–12 ASCII digits) and the name for
         the link's label (printable, whitespace collapsed, ≤ NAME_MAX).
         Nothing else of the site object is kept or logged.
  STORE  `adapter_poller_state` (instance, STATE_KEY) — no migration:
         {"at": <iso>, "mapped": [uids looked for], "sites": {uid: {id, name}}}.
  USE    the fleet build reads it (a registry read; no vendor call) and
         re-validates every value (`known`); a uid no longer mapped is
         ignored there and dropped at the next read.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Iterable, Optional

from apps.octo.adapters.datto.links import SITE_ID_RE, site_portal_id
from apps.octo.ingest.timestamps import format_utc_ms, normalize_timestamp
from apps.octo.instances import poller_state

STATE_KEY = "datto_site_portal_ids"
REFRESH = timedelta(days=1)
NAME_MAX = 120
MAX_SITES = 5000


def clean_name(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    flat = " ".join("".join(c if c.isprintable() else " " for c in value).split())
    return flat[:NAME_MAX] or None


def extract(sites: Iterable[Any], mapped: Iterable[str]) -> dict[str, dict[str, str]]:
    """uid → {id[, name]} for the entries of the site list whose uid is in
    `mapped` and whose numeric id is valid — nothing else."""
    wanted = {u for u in mapped if isinstance(u, str) and u}
    out: dict[str, dict[str, str]] = {}
    for site in sites:
        if not isinstance(site, dict):
            continue
        uid = site.get("uid")
        if not isinstance(uid, str) or uid not in wanted or uid in out:
            continue
        site_id = site_portal_id(site)
        if site_id is None:
            continue
        entry = {"id": site_id}
        name = clean_name(site.get("name"))
        if name:
            entry["name"] = name
        out[uid] = entry
    return out


def _valid_sites(raw: Any) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    if not isinstance(raw, dict):
        return out
    for uid, entry in list(raw.items())[:MAX_SITES]:
        if not isinstance(uid, str) or not uid or not isinstance(entry, dict):
            continue
        site_id = entry.get("id")
        if not isinstance(site_id, str) or not SITE_ID_RE.fullmatch(site_id):
            continue
        clean = {"id": site_id}
        name = clean_name(entry.get("name"))
        if name:
            clean["name"] = name
        out[uid] = clean
    return out


def load(instance_id: int) -> Optional[dict[str, Any]]:
    """The stored state, re-validated: {at, mapped, sites} — or None (none
    stored, unreadable, not this shape)."""
    raw = poller_state.load(instance_id, STATE_KEY)
    if not isinstance(raw, dict):
        return None
    at = normalize_timestamp(raw.get("at"))
    mapped = raw.get("mapped")
    if not at or not isinstance(mapped, list):
        return None
    return {"at": at, "mapped": sorted({u for u in mapped if isinstance(u, str) and u}),
            "sites": _valid_sites(raw.get("sites"))}


def known(instance_id: int) -> dict[str, dict[str, str]]:
    """uid → {id[, name]} — what link building may use ({} when none)."""
    state = load(instance_id)
    return state["sites"] if state else {}


def due(state: Optional[dict[str, Any]], mapped: Iterable[str], now: datetime) -> bool:
    """A read is due: none stored, the stored one is a day old, or a site is
    mapped that the stored read did not look for."""
    wanted = set(mapped)
    if not wanted:
        return False
    if state is None:
        return True
    try:
        at = datetime.fromisoformat(str(state["at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return True
    if now - at >= REFRESH:
        return True
    return bool(wanted - set(state.get("mapped") or []))


def save(instance_id: int, *, mapped: Iterable[str], found: dict[str, dict[str, str]],
         now: datetime, previous: Optional[dict[str, Any]] = None,
         complete: bool = True) -> bool:
    """Store `found` for the mapped uids. A listing that stopped early
    (`complete=False`) keeps the previously known ids of mapped uids it did
    not reach."""
    wanted = sorted({u for u in mapped if isinstance(u, str) and u})
    sites = {uid: found[uid] for uid in wanted if uid in found}
    if not complete and previous:
        for uid, entry in (previous.get("sites") or {}).items():
            if uid in wanted and uid not in sites:
                sites[uid] = entry
    return poller_state.save(instance_id, STATE_KEY, {
        "at": format_utc_ms(now), "mapped": wanted, "sites": sites})
