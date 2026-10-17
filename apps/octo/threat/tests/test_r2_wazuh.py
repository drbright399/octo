"""R2-W — a Wazuh malware-group verdict at level ≥ 12 (a VirusTotal
positive, a YARA match, a rootcheck trojan) is R2-W (SHADOW in slice 1);
every other level-12 rule is not."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from apps.octo.threat import engine, evaluators, store
from apps.octo.threat.tests.conftest import A, insert_event


def _alert(level: int, groups: list[str], description: str = "alert", **data) -> dict:
    return {"id": 3, "source": "wazuh", "event_type": "wazuh.alert",
            "payload": json.dumps({"rule": {"id": "87105", "level": level, "groups": groups,
                                            "description": description},
                                   "agent": {"name": "ws-07"}, "data": data})}


@pytest.mark.parametrize("alert,why", [
    (_alert(12, ["virustotal"], virustotal={"malicious": "1", "positives": 31}),
     "VirusTotal positive"),
    (_alert(13, ["yara", "malware"]), "YARA match"),
    (_alert(12, ["rootcheck"], "Trojaned version of file detected"), "rootcheck trojan"),
])
def test_listed_malware_groups_fire(alert, why):
    out = evaluators.r2_wazuh(alert)
    assert out.kind == evaluators.INCIDENT and out.rule_id == "R2-W" and out.tier == "red"
    assert out.why == why and out.device_ref == "ws-07"


@pytest.mark.parametrize("alert", [
    _alert(12, ["authentication_failures", "sshd"], "Multiple authentication failures"),
    _alert(12, ["syscheck"], "Integrity checksum changed"),
    _alert(12, ["virustotal"], virustotal={"malicious": "0", "positives": 0}),   # clean
    _alert(12, ["rootcheck"], "Host-based anomaly: a file is hidden"),            # no trojan
    _alert(11, ["yara"]),                                                         # < 12
])
def test_other_level_12_rules_do_not(alert):
    assert evaluators.r2_wazuh(alert).kind == evaluators.IGNORE


def test_r2w_is_shadow_a_would_fire_never_a_colour(troot):
    worker = engine.TierWorker(now=lambda: datetime(2026, 10, 3, 15, 0, tzinfo=timezone.utc))
    worker.run_once()
    a = _alert(12, ["yara"])
    insert_event(A, source="wazuh", event_type="wazuh.alert", payload=json.loads(a["payload"]),
                 source_host="ws-07")
    out = worker.run_once()
    assert out[A]["would_fire"] == 1
    assert store.list_incidents(A) == []
    # The same event is never evaluated twice (the cursor moved).
    assert worker.run_once()[A]["would_fire"] == 0
