"""DNS block tuning (Rick, 2026-10-06): "a block is NextDNS doing its job".

  A1  blocks are a GREEN-pin story with the count shown — a NOTICE "N
      threats blocked today" (operators: the top reasons; a client user:
      vendor-free "N threats blocked by DNS protection today");
  A2  Yellow ONLY when the DEVICE looks wrong: (a) HIGH blocks on the same
      device in ≥ 3 (the `dns_beacon_hours` knob) distinct clock hours in
      24 h; (b) ANY block in a device-originated reason (DGA, tunneling,
      exfiltration, payload delivery);
  A3  CSAM is never part of it (rule B7);
  A4  Red / Black still only from incidents;
  A5  "Threats stopped this week: N" for operators (the API test).

The false-positive shapes: one phishing click → a green notice; 3 HIGH hours
on one device → Yellow; 3 HIGH hours spread over 3 devices → still green;
one DGA → Yellow.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from apps.octo.adapters.nextdns import store as nd_store
from apps.octo.fleet import build, sources
from apps.octo.fleet import state as fs
from apps.octo.fleet.tests import test_build as tb
from apps.octo.fleet.tests.test_build import A, _by_name, fleet, iso  # noqa: F401
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401

NOW = datetime(2026, 10, 6, 15, 20, tzinfo=timezone.utc)
VENDOR_WORDS = ("nextdns", "unifi", "datto", "rocketcyber", "wazuh")


def dev(name: str, hours: int = 0, originated: tuple = ()) -> sources.DnsDevice:
    return sources.DnsDevice(key=f"id-{name}", name=name, profile_id="abc123",
                             high_hours=hours, originated=originated)


def prof(*, high: int = 0, medium: int = 0, devices: tuple = (), fresh: bool = True,
         reasons: tuple = (), loose: tuple = ()) -> fs.DnsProfile:
    return fs.DnsProfile("abc123", "Profile abc123", "active", False, fresh, high + medium,
                         threats_high=high, threats_medium=medium, top_reasons=reasons,
                         devices=devices, originated_unattributed=loose)


def layer(*profiles: fs.DnsProfile, settings: Optional[dict] = None) -> fs.Layer:
    return fs.security_layer(ips=None, dns=list(profiles), rc=None, now=NOW, settings=settings)


def _no_vendor(text: str) -> bool:
    return not any(w in text.lower() for w in VENDOR_WORDS)


# ---------------------------------------------------------------------------
# The rule (state.py)
# ---------------------------------------------------------------------------

def test_a1_one_phishing_click_is_a_green_notice_with_the_count():
    lay = layer(prof(high=1, reasons=(("googlesafebrowsing", 1),),
                     devices=(dev("ws-placeholder-01", hours=1),)))
    assert lay.state == fs.NOTICE                              # never colours the pin
    (r,) = lay.reasons
    assert r.text == "1 threat blocked today — top: Google Safe Browsing threat ×1"
    assert r.neutral == "1 threat blocked by DNS protection today" and _no_vendor(r.neutral)
    v = fs.site_verdict({"security": lay})
    assert v.state == fs.NOTICE


def test_a1_operators_get_the_top_two_reasons():
    lay = layer(prof(high=5, medium=4, reasons=(("threat-intelligence-feeds", 5), ("nrd", 3),
                                               ("typosquatting", 1))))
    assert lay.reasons[0].text == ("9 threats blocked today — top: threat-intelligence domain "
                                   "×5, newly registered domain ×3")
    assert [x["reason"] for x in lay.data["dns_top_reasons"]] == [
        "threat-intelligence-feeds", "nrd"]


def test_a2a_three_high_hours_on_one_device_is_yellow():
    lay = layer(prof(high=3, devices=(dev("ws-placeholder-02", hours=3),)))
    assert lay.state == fs.WARN
    warn = [r for r in lay.reasons if r.state == fs.WARN]
    assert [r.text for r in warn] == [
        "ws-placeholder-02: repeated high-risk lookups in 3 separate hours — possible infection"]
    assert warn[0].neutral == "a device made repeated high-risk lookups — possible infection"
    assert "ws-placeholder" not in warn[0].neutral and _no_vendor(warn[0].neutral)
    assert lay.data["dns_flagged_devices"][0]["high_hours"] == 3


def test_a2a_three_high_hours_spread_over_three_devices_stays_green():
    lay = layer(prof(high=3, devices=(dev("ws-a", hours=1), dev("ws-b", hours=1),
                                      dev("ws-c", hours=1))))
    assert lay.state == fs.NOTICE
    assert not [r for r in lay.reasons if r.state == fs.WARN]


def test_a2a_the_threshold_is_the_knob():
    two = prof(high=2, devices=(dev("ws-d", hours=2),))
    assert layer(two).state == fs.NOTICE                        # default 3
    assert layer(two, settings={"dns_beacon_hours": 2}).state == fs.WARN
    three = prof(high=3, devices=(dev("ws-e", hours=3),))
    assert layer(three, settings={"dns_beacon_hours": 4}).state == fs.NOTICE
    # A nonsense value never silences it: the default.
    assert layer(three, settings={"dns_beacon_hours": "bad"}).state == fs.WARN


def test_a2b_one_device_originated_block_is_yellow():
    lay = layer(prof(high=1, devices=(dev("ws-f", hours=1, originated=(("dga", 1),)),)))
    assert lay.state == fs.WARN
    warn = [r for r in lay.reasons if r.state == fs.WARN]
    assert warn[0].text == ("ws-f: DGA (algorithm-generated) domain lookup blocked — possible "
                            "infection")
    assert warn[0].neutral == "a device made automated suspicious lookups — possible infection"
    for rid in ("tunneling-endpoints", "dns-data-exfiltration", "dns-payload-delivery"):
        assert layer(prof(high=1, devices=(dev("x", originated=((rid, 1),)),))).state == \
            fs.WARN, rid
    # Counted by the roll-ups but no device named: still Yellow, at the profile.
    loose = layer(prof(high=2, loose=(("tunneling-endpoints", 2),)))
    assert loose.state == fs.WARN
    assert "device not identified" in [r for r in loose.reasons if r.state == fs.WARN][0].text


def test_a2_a_stale_profile_flags_no_device_and_health_never_red():
    lay = layer(prof(high=9, fresh=False, devices=(dev("ws-g", hours=9),)))
    assert lay.state == fs.UNKNOWN
    worst = layer(prof(high=50, devices=tuple(dev(f"ws-{n}", hours=24,
                                                  originated=(("dga", 9),))
                                              for n in range(5))))
    assert worst.state == fs.WARN                               # A4: never Red / Black


# ---------------------------------------------------------------------------
# The per-device source: the coalescing ledger (sources.py) through the build
# ---------------------------------------------------------------------------

def _bucket(slug: str, *, n: int, hour: datetime, device: str, reason: str,
            root: Optional[str] = None, profile: str = "p-acme1", name: str = "") -> None:
    h = hour.strftime("%Y-%m-%dT%H:00:00Z")
    b = nd_store.Bucket(key=f"k-{n}-{device}-{reason}-{h}", hour=h, profile_id=profile,
                        reason_id=reason, root=root or f"r{n}.bad-example.test",
                        device=device)
    (out,) = nd_store.count_hits(slug, [(b, iso(hour), f"line-{n}-{device}")],
                                 arrived=iso(hour))
    if name and out.kind == "new":
        nd_store.set_event(slug, b.key, _alert(slug, name))


def _alert(slug: str, device_name: str) -> int:
    """The alert a bucket's first line created: `source_host` = the device's
    name as NextDNS reported it."""
    import json
    import os
    import sqlite3

    from apps.octo import paths

    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        cur = conn.execute(
            "INSERT INTO events (received_at, source, source_host, event_type, severity, "
            "payload, payload_sha256) VALUES (?, 'nextdns', ?, 'nextdns.security_block', "
            "'high', ?, ?)", (iso(tb.NOW), device_name, json.dumps({"x": device_name}),
                              f"sha-{os.urandom(8).hex()}"))
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _rollup(slug: str, hour: datetime, *, high: int = 0, medium: int = 0,
            reasons: Optional[dict] = None, profile: str = "p-acme1") -> None:
    nd_store.upsert_hourly(slug, nd_store.HourlyRow(
        hour.strftime("%Y-%m-%dT%H:00:00Z"), profile, 500, 0, high + medium, 500 - high - medium,
        high, medium, 0, 0, reasons or {}))


def _security(mgr) -> fs.Layer:
    return _by_name(build.build(mgr, now=tb.NOW))["Acme HQ"].layers["security"]


def test_ledger_three_hours_one_device_is_yellow_named_three_devices_is_green(fleet):  # noqa: F811
    mgr, _ = fleet
    now = tb.NOW
    for k in range(3):
        _bucket(A, n=k, hour=now - timedelta(hours=k), device="dev-beacon",
                reason="threat-intelligence-feeds", name="ws-placeholder-09")
    _rollup(A, now, high=3, reasons={"threat-intelligence-feeds": 3})
    counts = sources.dns_threats(A, ["p-acme1"], now - timedelta(hours=24))
    (d,) = counts["p-acme1"].devices
    assert d.high_hours == 3 and d.name == "ws-placeholder-09"
    sec = _security(mgr)
    assert sec.state == fs.WARN
    assert ("ws-placeholder-09: repeated high-risk lookups in 3 separate hours — possible "
            "infection") in [r.text for r in sec.reasons]


def test_ledger_three_hours_over_three_devices_and_known_benign_stay_green(fleet):  # noqa: F811
    mgr, _ = fleet
    now = tb.NOW
    for k, device in enumerate(("dev-a", "dev-b", "dev-c")):
        _bucket(A, n=k, hour=now - timedelta(hours=k), device=device,
                reason="threat-intelligence-feeds")
    # A known-benign probe every hour on one device: never "beaconing".
    for k in range(6):
        _bucket(A, n=10 + k, hour=now - timedelta(hours=k), device="dev-probe",
                reason="threat-intelligence-feeds", root="kb:1")
    _rollup(A, now, high=3)
    assert sources.dns_threats(A, ["p-acme1"], now - timedelta(hours=24))["p-acme1"] \
        .devices == ()
    sec = _security(mgr)
    assert sec.state == fs.NOTICE
    assert not [r for r in sec.reasons if r.state == fs.WARN]


def test_ledger_one_dga_block_is_yellow(fleet):  # noqa: F811
    mgr, _ = fleet
    _bucket(A, n=1, hour=tb.NOW, device="dev-dga", reason="dga", root="*",
            name="ws-placeholder-10")
    _rollup(A, tb.NOW, high=1, reasons={"dga": 1})
    sec = _security(mgr)
    assert sec.state == fs.WARN
    assert any(r.text.startswith("ws-placeholder-10: DGA") for r in sec.reasons)


def test_ledger_csam_is_never_counted_nor_a_top_reason(fleet):  # noqa: F811
    """A3: CSAM blocks are B7's — the roll-up counts them (a number), the
    Fleet takes them out of every count, every top reason and every device
    rule."""
    mgr, _ = fleet
    _rollup(A, tb.NOW, high=3, reasons={"csam": 2, "threat-intelligence-feeds": 1})
    for k in range(4):                                         # an old pre-v0.17.1 bucket
        _bucket(A, n=20 + k, hour=tb.NOW - timedelta(hours=k), device="dev-x", reason="csam")
    counts = sources.dns_threats(A, ["p-acme1"], tb.NOW - timedelta(hours=24))
    c = counts["p-acme1"]
    assert c.high == 1 and c.total == 1
    assert [rid for rid, _n in c.reasons] == ["threat-intelligence-feeds"]
    assert c.devices == ()
    sec = _security(mgr)
    assert sec.state == fs.NOTICE
    text = " ".join(r.text + " " + r.neutral for r in sec.reasons).lower()
    assert "csam" not in text and "1 threat blocked today" in text


def test_a5_the_weeks_count_sums_seven_days_without_benign_or_csam(fleet):  # noqa: F811
    mgr, _ = fleet
    for day in range(9):                                       # 9 days, 2 per day
        _rollup(A, tb.NOW - timedelta(days=day, hours=1), high=1, medium=1)
    _rollup(A, tb.NOW, high=2, reasons={"csam": 2})            # CSAM: out
    week = sources.dns_week(A, ["p-acme1", "p-acme2"], tb.NOW)
    assert week == 14                                          # 7 days × 2
    model = build.build(mgr, now=tb.NOW)
    assert model.dns_week[A] == 14


# ---------------------------------------------------------------------------
# Fixer round (review: precision / false positives)
# ---------------------------------------------------------------------------

def _hits(slug: str, *, key: str, hour: datetime, line_at: datetime, device: str,
          reason: str, root: str = "r.bad-example.test", span: str = "hour",
          n: int = 1) -> None:
    """`n` lines of one ledger bucket, observed at `line_at`."""
    h = hour.strftime("%Y-%m-%dT%H:00:00Z" if span == "hour" else "%Y-%m-%dT00:00:00Z")
    b = nd_store.Bucket(key=key, hour=h, profile_id="p-acme1", reason_id=reason, root=root,
                        device=device, span=span)
    nd_store.count_hits(slug, [(b, iso(line_at), f"{key}-line-{i}") for i in range(n)],
                        arrived=iso(line_at))


def test_p1_a_public_ip_is_a_network_never_one_device(fleet):  # noqa: F811
    """Gateway / linked-IP traffic: NextDNS names no device and the client IP
    is the office's public address. Three people's blocks in three hours
    are not a beacon; a DGA block behind it still is Yellow."""
    mgr, _ = fleet
    now = tb.NOW
    for k, ip in enumerate(("203.0.113.10", "203.0.113.10", "203.0.113.10")):
        _bucket(A, n=k, hour=now - timedelta(hours=k), device=ip,
                reason="threat-intelligence-feeds")
    for k in range(4):                                         # an IPv6 address too
        _bucket(A, n=10 + k, hour=now - timedelta(hours=k), device="2001:db8::10",
                reason="googlesafebrowsing")
    _rollup(A, now, high=7, reasons={"threat-intelligence-feeds": 3, "googlesafebrowsing": 4})
    assert sources.dns_threats(A, ["p-acme1"], now - timedelta(hours=24))["p-acme1"] \
        .devices == ()
    sec = _security(mgr)
    assert sec.state == fs.NOTICE
    assert not [r for r in sec.reasons if r.state == fs.WARN]
    # One DGA lookup behind that address: Yellow, named as a network.
    _bucket(A, n=20, hour=now, device="203.0.113.10", reason="dga", root="*")
    _rollup(A, now, high=8, reasons={"threat-intelligence-feeds": 3, "googlesafebrowsing": 4,
                                     "dga": 1})
    (d,) = sources.dns_threats(A, ["p-acme1"], now - timedelta(hours=24))["p-acme1"].devices
    assert d.network and d.high_hours == 0 and d.name == "a device behind 203.0.113.10"
    build.invalidate()
    sec = _security(mgr)
    assert sec.state == fs.WARN
    assert [r.text for r in sec.reasons if r.state == fs.WARN] == [
        "a device behind 203.0.113.10: DGA (algorithm-generated) domain lookup blocked — "
        "possible infection"]


def test_p1_the_rule_never_counts_hours_for_a_network_key():
    net = sources.DnsDevice(key="203.0.113.10", name="a device behind 203.0.113.10",
                            profile_id="abc123", high_hours=9, network=True)
    assert layer(prof(high=9, devices=(net,))).state == fs.NOTICE


def test_p2_a_known_benign_rule_quiets_a_device_originated_reason(fleet):  # noqa: F811
    """A vendor domain NextDNS calls DGA, matched by an operator's known-benign
    rule, filed under `kb:<rule>` (a DAY bucket): the roll-up alone cannot
    tell — the per-reason known-benign hits are taken out."""
    mgr, _ = fleet
    now = tb.NOW
    _rollup(A, now - timedelta(hours=2), high=2, reasons={"dga": 2})
    c = sources.dns_threats(A, ["p-acme1"], now - timedelta(hours=24))["p-acme1"]
    assert c.originated_unattributed == (("dga", 2),)          # the control: Yellow
    _hits(A, key="kb-dga", hour=now, line_at=now - timedelta(hours=2), device="dev-vendor",
          reason="dga", root="kb:1", span="day", n=2)
    c = sources.dns_threats(A, ["p-acme1"], now - timedelta(hours=24))["p-acme1"]
    assert c.originated_unattributed == () and c.reasons == () and c.benign == 2
    sec = _security(mgr)
    assert sec.state == fs.NOTICE
    assert not [r for r in sec.reasons if r.state == fs.WARN]


def test_p4_the_device_window_is_24_hours_not_25(fleet):  # noqa: F811
    """The clock hour `since` falls in counts only for its later hits — a
    DGA block 24 h 15 min ago is not "today"."""
    now = tb.NOW.replace(minute=20, second=0)
    since = now - timedelta(hours=24)
    boundary = since.replace(minute=0)
    _hits(A, key="old", hour=boundary, line_at=boundary + timedelta(minutes=5),
          device="dev-old", reason="dga", root="*")
    _rollup(A, boundary, high=1, reasons={"dga": 1})
    c = sources.dns_threats(A, ["p-acme1"], since)["p-acme1"]
    assert c.devices == () and c.originated_unattributed == ()
    _hits(A, key="new", hour=boundary, line_at=boundary + timedelta(minutes=30),
          device="dev-new", reason="dga", root="*")
    (d,) = sources.dns_threats(A, ["p-acme1"], since)["p-acme1"].devices
    assert d.key == "dev-new" and d.originated == (("dga", 1),)


def test_p5_p6_top_reasons_and_the_drawer_count_leave_known_benign_out(fleet):  # noqa: F811
    mgr, _ = fleet
    now = tb.NOW
    _rollup(A, now, high=41, reasons={"threat-intelligence-feeds": 40, "googlesafebrowsing": 1})
    _hits(A, key="kb-probe", hour=now, line_at=now, device="dev-tv",
          reason="threat-intelligence-feeds", root="kb:1", span="day", n=40)
    c = sources.dns_threats(A, ["p-acme1"], now - timedelta(hours=24))["p-acme1"]
    assert c.reasons == (("googlesafebrowsing", 1),)
    assert (c.total, c.high, c.benign) == (1, 1, 40)
    sec = _security(mgr)
    (r,) = [x for x in sec.reasons if x.code == fs.REASON_DNS_BLOCKS]
    assert r.text == ("1 threat blocked today — top: Google Safe Browsing threat ×1 "
                      "(+40 known-benign not counted)")
    # The drawer's "DNS threats 24 h" is the notice's number.
    assert sec.data["dns_threats_24h"] == 1
    assert [p["threats_24h"] for p in sec.data["dns_profiles"] if p["profile_id"] == "p-acme1"] \
        == [1]


def test_p7_filter_bypass_is_policy_never_a_threat(fleet):  # noqa: F811
    mgr, _ = fleet
    now = tb.NOW
    _rollup(A, now, medium=6, reasons={"bypass-methods": 5, "nrd": 1})
    c = sources.dns_threats(A, ["p-acme1"], now - timedelta(hours=24))["p-acme1"]
    assert (c.total, c.medium, c.bypass) == (1, 1, 5)
    assert c.reasons == (("nrd", 1),)
    assert sources.dns_week(A, ["p-acme1"], now) == 1          # A5: security categories only
    sec = _security(mgr)
    (r,) = [x for x in sec.reasons if x.code == fs.REASON_DNS_BLOCKS]
    assert r.text == ("1 threat blocked today — top: newly registered domain ×1 "
                      "(+5 filter-bypass not counted)")
    assert r.neutral == "1 threat blocked by DNS protection today"
    # Only bypass blocks: an operator-only notice, never a "threat".
    only = fs.DnsProfile("abc123", "Profile abc123", "active", False, True, 0,
                         threats_high=0, threats_medium=0, threats_bypass=3)
    lay = layer(only)
    (r,) = lay.reasons
    assert lay.state == fs.NOTICE and r.operator_only
    assert r.text == ("3 DNS-filter bypass blocks (VPN / proxy / Tor — policy, not a threat) "
                      "today")
