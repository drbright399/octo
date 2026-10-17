"""Test helpers for v0.17.2: store a UniFi IPS hit through the REAL
catalogue → coalescing ledger → event sink path."""
from __future__ import annotations

from datetime import datetime
from typing import Optional


SCOPE_B = ("F1X70003000000000000000000000000000000000000000000000000:100000003"
           "/f1x7517e0000000000000001")
# The hit's LAN end. RFC 1918 on purpose, never a TEST-NET address: the
# catalogue tells the site's own end from the remote end by its address
# space (`catalogue.is_local`), so the LAN client must be private.
# scan-sensitive: allow[ip-private] synthetic RFC 1918 LAN client: TEST-NET reads as remote
LAN_IP = "10.20.0.37"


def store_ips_hit(slug: str, scope: str, at: datetime, *, remote: str = "203.0.113.66",
                  lan_ip: str = LAN_IP, blocked: bool = True, inbound: bool = False,
                  signature: str = "ET MALWARE Example Beacon",
                  eid: Optional[str] = None) -> int:
    """One IPS hit: claimed / counted in the tenant's ledger, its bucket's
    alert stored in events.db on first sight. Returns the bucket's event id."""
    from apps.octo.adapters.unifi import catalogue
    from apps.octo.adapters.unifi import store as ustore
    from apps.octo.adapters.unifi.adapter import UniFiSourceAdapter
    from apps.octo.adapters.unifi.poller import split_scope
    from apps.octo.adapters.unifi.tests.fake_unifi import ips_event
    from apps.octo.ingest import SqliteIngestSink

    raw = ips_event(at, blocked=blocked, lan_ip=lan_ip, remote_ip=remote, signature=signature,
                    inbound=inbound, eid=eid)
    ev = catalogue.normalise(raw)
    assert ev is not None
    cls = catalogue.classify(ev.category, ev.subcategory, ev.event, ev.vendor_severity)
    host_id, site_id = split_scope(scope)  # type: ignore[misc]
    ctx = catalogue.SiteContext(scope=scope, host_id=host_id, site_id=site_id,
                                internal_ref="default", site_name="Example Site",
                                console_name="console-3")
    payload = catalogue.signal_payload(cls, ev, ctx)
    sig = payload["signal"]
    key = catalogue.bucket_key(scope, cls.kind, sig["subject"], sig["bucket_hour"])
    claim = ustore.Claim(key=key, hour=sig["bucket_hour"], kind=cls.kind, subject=sig["subject"],
                         seen=ev.iso, payload=payload,
                         remote=(payload.get("ips") or {}).get("remote_ip"))
    result = ustore.claim(slug, scope, [claim])
    if result.new_claims:
        event = UniFiSourceAdapter().extract_event(payload)
        event_id = SqliteIngestSink(publish_to_stream=False).ingest(slug, "unifi", event).event_id
        ustore.set_event(slug, key, int(event_id))
        return int(event_id)
    held = [b for b in ustore.buckets(slug) if b["bucket_key"] == key]
    return int(held[0]["event_id"])
