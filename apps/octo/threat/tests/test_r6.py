"""R6 — deception (buoy OpenCanary), SHADOW in slice 1: a plaintext
credential on an SSH / RDP / HTTP / FTP / MSSQL canary from an internal
address not on the scanner allowlist → R6 (a would-fire); a port touch →
Yellow; SMB / NTLM / SNMP → ignored; the allowlisted Datto discovery node →
ignored; the submitted password is NEVER stored by the rule."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

import pytest

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.threat import engine, evaluators, registry, store
from apps.octo.threat.tests.conftest import A, insert_event

SECRET = "Winter2026!fixture"
# R6 fires only for an INTERNAL source (RFC 1918 / ULA: `evaluators._private`;
# a documentation address reads as outside), so both are private on purpose:
# the Datto network-discovery node and a LAN host (fixtures).
# scan-sensitive: allow[ip-private] synthetic RFC 1918 fixtures: R6 needs an internal source
SCANNER, INSIDER = "10.0.0.250", "10.0.0.31"


def _canary(logtype: int, service: str, *, src: str = INSIDER, user: str = "admin",
            password: str | None = SECRET, port: int = 22) -> dict:
    logdata = {"honeypot_user_attempt": user} if user else {}
    if password is not None:
        logdata["honeypot_pw_attempt"] = password
    return {"id": 1, "event_type": f"opencanary.{service}", "source": "forwarder",
            "payload": json.dumps({"event_type": f"opencanary.{service}", "severity": "high",
                                   "raw_canary": {"logtype": logtype, "src_host": src,
                                                  "dst_port": port, "logdata": logdata}})}


@pytest.mark.parametrize("logtype,service,port", [
    (4002, "ssh", 22), (14001, "rdp", 3389), (3001, "http", 80), (2000, "ftp", 21),
    (9001, "mssql", 1433)])
def test_a_credential_attempt_is_r6(logtype, service, port):
    out = evaluators.r6(_canary(logtype, service, port=port), allowlist={SCANNER})
    assert out.kind == evaluators.INCIDENT and out.rule_id == "R6" and out.tier == "red"
    assert out.device_ref == f"ip:{INSIDER}"


def test_a_port_touch_is_yellow():
    out = evaluators.r6(_canary(5001, "portscan", user="", password=None),
                        allowlist={SCANNER})
    assert out.kind == evaluators.YELLOW and out.fact_kind == "canary_touch"
    # A credential from OUTSIDE (a canary exposed by mistake) is no R6 either.
    out = evaluators.r6(_canary(4002, "ssh", src="203.0.113.7"), allowlist={SCANNER})
    assert out.kind == evaluators.YELLOW
    # An allowlist that cannot be read never makes a Red.
    assert evaluators.r6(_canary(4002, "ssh"), allowlist=None).kind == evaluators.YELLOW


@pytest.mark.parametrize("logtype,service", [(5000, "smb"), (16001, "snmp")])
def test_smb_ntlm_and_snmp_are_ignored(logtype, service):
    out = evaluators.r6(_canary(logtype, service), allowlist={SCANNER})
    assert out.kind == evaluators.IGNORE


def test_the_allowlisted_discovery_node_is_ignored():
    out = evaluators.r6(_canary(4002, "ssh", src=SCANNER), allowlist={SCANNER})
    assert out.kind == evaluators.IGNORE and "allowlisted" in out.why


def test_the_password_is_never_stored(troot):
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            registry.add_allowlist(reg, slug=A, ip=SCANNER, label="Datto discovery", by=7)
    finally:
        reg.close()
    worker = engine.TierWorker(now=lambda: datetime(2026, 10, 3, 15, 0, tzinfo=timezone.utc))
    worker.run_once()                                     # the cursor starts at the newest
    row = _canary(4002, "ssh")
    insert_event(A, source="forwarder", event_type="opencanary.ssh",
                 payload=json.loads(row["payload"]))
    insert_event(A, source="forwarder", event_type="opencanary.portscan",
                 payload=json.loads(_canary(5001, "portscan", user="", password=None)
                                    ["payload"]))
    out = worker.run_once()
    assert out[A]["would_fire"] == 1 and out[A]["yellow"] == 1
    # SHADOW: a would-fire row and a fact — never an incident.
    assert store.list_incidents(A) == []
    (wf,) = store.would_fires(A, datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert wf["rule_id"] == "R6" and wf["tier"] == "red"
    conn = sqlite3.connect(paths.client_dir(A) / "events.db")
    try:
        facts = [r[0] for r in conn.execute("SELECT attrs FROM threat_fact")]
        dump = json.dumps(facts) + json.dumps(
            [list(r) for r in conn.execute("SELECT * FROM threat_would_fire")])
    finally:
        conn.close()
    assert SECRET not in dump
    attrs = json.loads(next(f for f in facts if "password" in f))
    # The LENGTH only: no hash a real password typed into the decoy could be
    # cracked back from (a random salt made it useless for correlation too).
    assert attrs["password"] == {"length": len(SECRET)}
    # In shadow a credential attempt is at least the Yellow a port touch is.
    from apps.octo.fleet import sources

    assert sources.canary_touches(A, datetime.now(timezone.utc)) == 2   # facts at arrival


def test_the_forwarder_never_sends_a_tried_secret():
    """The buoy keeps the tried user name and only the LENGTH of a tried
    secret (someone may type a REAL password into a decoy that looks like a
    real server)."""
    from apps.octo.buoy.forwarder.adapters import opencanary

    out = opencanary._sanitize_credential_keys({"logtype": 4002, "logdata": {
        "USERNAME": "admin", "PASSWORD": SECRET, "nested": [{"api_key": "k-123456"}]}})
    assert out["logdata"]["honeypot_user_attempt"] == "admin"
    assert out["logdata"]["honeypot_pw_attempt"] == f"[redacted: {len(SECRET)} chars]"
    assert out["logdata"]["nested"][0]["honeypot_api_key_attempt"] == "[redacted: 8 chars]"
    assert SECRET not in json.dumps(out)
    # The rule still sees a credential attempt, and its length.
    row = {"id": 1, "event_type": "opencanary.ssh",
           "payload": json.dumps({"raw_canary": {"logtype": 4002, "src_host": INSIDER,
                                                 "logdata": out["logdata"]}})}
    r6 = evaluators.r6(row, allowlist={SCANNER})
    assert r6.kind == evaluators.INCIDENT and r6.attrs["password"] == {"length": len(SECRET)}


def test_the_ingest_route_redacts_what_an_older_forwarder_still_sends():
    data = {"raw_canary": {"logdata": {"honeypot_user_attempt": "admin",
                                       "honeypot_pw_attempt": SECRET},
                           "deeper": {"secret": "s3cr3t-fixture"}}}
    out = evaluators.redact_canary_secrets(data)
    assert out["raw_canary"]["logdata"] == {"honeypot_user_attempt": "admin",
                                            "honeypot_pw_attempt":
                                                f"[redacted: {len(SECRET)} chars]"}
    assert out["raw_canary"]["deeper"]["secret"] == "[redacted: 14 chars]"
    # Idempotent on the forwarder's stand-in.
    assert evaluators.redact_canary_secrets(out) == out
