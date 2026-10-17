"""Known-benign rules (Rick, 2026-10-01): the Samsung connectivity probe —
"www.g" + many "o" + "gle.com" on a NextDNS threat-intelligence feed since
09-24 — is downgraded IN ATHENA to LOW, labelled known-benign, and STAYS
BLOCKED (never an allowlist). The real poller / client / sink, fake socket."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from apps.octo import paths
from apps.octo.adapters.nextdns import NextDNSSourceAdapter
from apps.octo.adapters.nextdns.presentation import EVENT_BLOCK
from apps.octo.adapters.nextdns.tests.fake_nextdns import T0, block_line
from apps.octo.db import connect
from apps.octo.instances import known_benign as kb

ACME = "acme-corp"


@pytest.fixture(autouse=True)
def _fresh_rules():
    kb.reset()
    yield
    kb.reset()


def _payloads(world):
    return [json.loads(r["payload"]) for r in world.events(ACME, EVENT_BLOCK)]


def test_the_seeded_samsung_probe_is_low_labelled_and_still_blocked(world):
    t = world.transport
    t.set_rate("abc123")
    start = T0.replace(hour=2)
    t.add_lines("abc123",
                block_line(start, domain="www.gooogle.com", root="gooogle.com",
                           device_id="P1", device_name="Galaxy S24"),
                block_line(start + timedelta(minutes=9), domain="www.goooooogle.com",
                           root="goooooogle.com", device_id="P1", device_name="Galaxy S24"),
                block_line(start + timedelta(minutes=3), domain="c2.bad-example.test"))
    world.map(abc123=ACME)
    world.poller().run_cycle()
    alerts = _payloads(world)
    probe = [a for a in alerts if a["log"]["domain"].startswith("www.go")]
    real = [a for a in alerts if a["log"]["domain"] == "c2.bad-example.test"]
    assert len(probe) == 1                       # one per device per rule per day (LOW)
    p = probe[0]
    assert p["signal"]["level"] == "low" and p["signal"]["bucket_span"] == "day"
    benign = p["signal"]["known_benign"]
    assert benign["still_blocked"] is True and "Samsung" in benign["label"]
    assert p["log"]["status"] == "blocked"       # NextDNS blocked it; Athena only files it low
    assert real and real[0]["signal"]["level"] == "high" and "known_benign" not in real[0]["signal"]
    shown = NextDNSSourceAdapter.present_event(p)
    assert "known-benign" in shown.headline and "STILL BLOCKED" in shown.detail
    row = next(r for r in world.events(ACME, EVENT_BLOCK)
               if json.loads(r["payload"])["log"]["domain"].startswith("www.go"))
    assert row["severity"] == "low"


def test_google_itself_and_a_probe_on_a_second_feed_are_not_downgraded(world):
    t = world.transport
    t.set_rate("abc123")
    start = T0.replace(hour=2)
    t.add_lines("abc123",
                block_line(start, domain="www.google.com", root="google.com"),
                block_line(start + timedelta(minutes=1), domain="www.gooogle.com",
                           root="gooogle.com", extra_reasons=(("cryptojacking", "Cryptojacking"),)))
    world.map(abc123=ACME)
    world.poller().run_cycle()
    assert all("known_benign" not in a["signal"] and a["signal"]["level"] == "high"
               for a in _payloads(world))


def test_a_disabled_rule_downgrades_nothing(world):
    reg = connect(paths.registry_db_path())
    try:
        reg.execute("UPDATE known_benign_rules SET enabled = 0")
    finally:
        reg.close()
    kb.reset()
    t = world.transport
    t.set_rate("abc123")
    t.add_lines("abc123", block_line(T0.replace(hour=2), domain="www.gooogle.com",
                                     root="gooogle.com"))
    world.map(abc123=ACME)
    world.poller().run_cycle()
    assert [a["signal"]["level"] for a in _payloads(world)] == ["high"]


@pytest.mark.parametrize("kind,pattern,ok", [
    ("regex", r"www\.go{3,}gle\.com", True),
    ("regex", "www.go{3,}gle.com", True),            # '.' is always a literal dot
    ("regex", "(a|b).example", False),
    ("regex", "a*b*c*.example", False),               # three unbounded quantifiers
    # Bounded but wide ranges backtrack like unbounded ones (review round 3).
    ("regex", "[a-z.]{0,999}[a-z.]{0,999}[a-z.]{0,999}[a-z.]{0,999}0", False),
    ("regex", "[a-z.]{0,99}[a-z.]{0,99}[a-z.]{0,99}0", False),
    ("regex", "[a-z.]{0,99}x{2}y?[a-z.]{1,200}0", True),  # two wide + narrow ones
    ("regex", "^www", False),
    ("exact", "probe.example", True),
    ("suffix", ".example", False),
])
def test_patterns_are_a_restricted_linear_time_language(kind, pattern, ok):
    if ok:
        assert kb.validate_pattern(kind, pattern)
    else:
        with pytest.raises(kb.RuleError):
            kb.validate_pattern(kind, pattern)


def test_the_seed_matches_only_the_probe_shape(world):
    rules = kb.load(fresh=True)
    (seed,) = rules
    assert seed.reasons == ("threat-intelligence-feeds",) and seed.level == "low"
    for domain, hit in (("www.gooogle.com", True), ("www.goooooooooogle.com", True),
                        ("www.google.com", False), ("gooogle.com", False),
                        ("www.gooogle.com.bad.example", False), ("wwwxgooogle.com", False)):
        assert bool(kb.match("nextdns", domain, ["threat-intelligence-feeds"])) is hit, domain
    assert kb.match("nextdns", "www.gooogle.com", ["threat-intelligence-feeds", "dga"]) is None


def test_the_widest_accepted_pattern_matches_a_long_name_quickly():
    """Two wide quantifiers (the most allowed) on a 253-character name that
    does NOT match: quadratic at worst — well under the 0.16 s the old
    four-range pattern took per line."""
    import time

    rx = kb.validate_pattern("regex", "[a-z.]{0,250}x?y?[a-z.]{0,250}0")
    pattern = __import__("re").compile(rx)
    name = ("a" * 60 + ".") * 4 + "b" * 9                  # 253 characters, no '0'
    assert len(name) == 253
    started = time.perf_counter()
    for _ in range(5):
        assert pattern.fullmatch(name) is None
    assert (time.perf_counter() - started) / 5 < 0.05

