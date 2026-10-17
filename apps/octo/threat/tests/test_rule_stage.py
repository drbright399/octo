"""Rule stage and the storm brake: a SHADOW rule writes `threat_would_fire`
(plus an operator-only notice) and never colours a pin; the stage is a code
constant (no settings key, no runtime switch reaches a rule — least of all
a Black one); a restart never fires on backlog; the brake holds ONE
automated rule at a Red ceiling for ≤ 24 h, never an analyst's declaration,
never an existing Black, and expires on its own."""
from __future__ import annotations

import inspect
import json
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.fleet import state as fs
from apps.octo.threat import brake, engine, evaluators, registry, rules, store
from apps.octo.threat.tests.conftest import A, insert_event

NOW = datetime(2026, 10, 3, 15, 0, tzinfo=timezone.utc)


def test_slice_one_stages_are_code_constants():
    assert {r.id: r.stage for r in rules.RULES.values()} == {
        "B6": rules.LIVE, "R8": rules.LIVE, "R6": rules.SHADOW, "R2-W": rules.SHADOW,
        "B7": rules.LIVE, "FR2": rules.LIVE}
    # v0.17.1: B7 (CSAM) is the one automated LIVE Black, and RESTRICTED.
    assert rules.RULES["B7"].automated and rules.RULES["B7"].tier == rules.BLACK
    assert rules.RULES["B7"].restricted and rules.restricted("B7")
    assert not any(r.restricted for r in rules.RULES.values() if r.id != "B7")
    # Frozen: a stage cannot be flipped at runtime.
    with pytest.raises(Exception):
        rules.RULES["R6"].stage = rules.LIVE  # type: ignore[misc]


def test_no_settings_key_reaches_a_red_or_black_rule():
    assert not any("setting" in f or "knob" in f or "threshold" in f
                   for f in rules.RULE_FIELDS)
    for fn in (evaluators.r6, evaluators.r2_wazuh):
        assert "settings" not in inspect.signature(fn).parameters
    # Every knob tunes Yellow ↔ Notice or a duration; none can name Red / Black
    # and none is named after a rule.
    for knob in registry.KNOBS.values():
        if knob.choices:
            assert set(knob.choices) <= {fs.NOTICE, fs.WARN}
        assert not any(r.lower() in knob.key for r in rules.RULES)
        with pytest.raises(ValueError):
            knob.valid("bad" if knob.choices else 10_000)
    # The B6 rule takes no input but a person.
    assert rules.RULES["B6"].inputs == ("analyst",) and rules.RULES["B6"].kind == rules.HUMAN
    # The caution-first note for B1 (Rick, 9.1) is recorded with the registry.
    assert "BLACK now" in rules.__doc__ and "B1" in rules.__doc__


def test_shadow_writes_would_fire_and_never_colours(troot):
    worker = engine.TierWorker(now=lambda: NOW)
    worker.run_once()
    insert_event(A, source="wazuh", event_type="wazuh.alert",
                 payload={"rule": {"level": 12, "groups": ["yara"], "description": "x"},
                          "agent": {"name": "ws-07"}})
    worker.run_once()
    assert store.list_incidents(A) == []
    counts = {"R2-W": 1}
    layer = fs.threat_layer([], now=NOW, would_fire=counts)
    assert layer.state == fs.NOTICE                       # never a colour
    assert fs.client_layer(layer).state == fs.OK          # never a client's


def test_a_restart_never_fires_on_backlog(troot):
    insert_event(A, source="wazuh", event_type="wazuh.alert",
                 payload={"rule": {"level": 12, "groups": ["yara"]}, "agent": {"name": "x"}})
    first = engine.TierWorker(now=lambda: NOW).run_once()
    assert first[A]["would_fire"] == 0                    # the backlog is skipped
    assert store.would_fires(A, NOW - timedelta(days=1)) == []


def _brake(rule_id: str, hours: float, at: datetime = NOW) -> int:
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            return brake.set_brake(reg, rule_id, by=1, reason="a storm of would-fires",
                                   hours=hours, now=at)
    finally:
        reg.close()


def test_brake_bounds(troot):
    with pytest.raises(brake.BrakeError, match="never braked"):
        brake.validate("B6", 4)
    with pytest.raises(brake.BrakeError, match="never braked"):
        brake.validate("R8", 4)
    with pytest.raises(brake.BrakeError, match="24"):
        brake.validate("R6", 25)
    with pytest.raises(brake.BrakeError, match="24"):
        brake.validate("R6", 0)
    with pytest.raises(brake.BrakeError, match="no rule"):
        brake.validate("B99", 1)
    _brake("R6", 24, at=datetime.now(timezone.utc))
    with pytest.raises(brake.BrakeError, match="already"):
        _brake("R6", 1, at=datetime.now(timezone.utc))
    # The table refuses more than 24 h whatever the code says.
    reg = connect(paths.registry_db_path())
    try:
        import sqlite3

        with pytest.raises(sqlite3.IntegrityError):
            reg.execute("INSERT INTO rule_brake (rule_id, set_by, set_at, expires_at, reason) "
                        "VALUES ('R2-W', 1, '2026-10-03T00:00:00.000Z', "
                        "'2026-10-04T00:30:00.000Z', 'too long')")
    finally:
        reg.close()


def test_the_brake_caps_what_a_rule_opens_and_expires(troot):
    _brake("R6", 2, at=NOW)
    assert brake.ceiling("R6", "black", NOW + timedelta(hours=1)) == "red"
    assert brake.ceiling("R6", "black", NOW + timedelta(hours=3)) == "black"   # expired
    assert brake.ceiling("B6", "black", NOW + timedelta(hours=1)) == "black"   # a person
    # An existing Black is untouched by a brake.
    inc = store.open_incident(A, tier="black", rule_id="B6", rule_version=1, key="k",
                              summary="x", scope="tenant", opened_by="1", now=NOW).incident
    _brake("R2-W", 1, at=NOW)
    assert store.get(A, inc.id).tier == "black"


def test_the_threat_layer_shows_the_operator_only_shadow_notice():
    layer = fs.threat_layer([], now=NOW, would_fire={"R6": 3})
    (r,) = layer.reasons
    assert r.operator_only and "R6" in r.text and json.dumps(r.neutral) == '""'
