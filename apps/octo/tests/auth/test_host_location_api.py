"""The host pin — the OCTO hub on the Fleet map (registry bundle_config row
`octo_location`, 022) — through the real routes: operators read it (client
users never see coordinates); only a super_admin moves it, with a reason,
validated like a site pin, audited BEFORE the write (no audit, no write; a
failed write says so); a missing row is created; and the address lookup's
on/off switch the editor reads (admin+)."""
from __future__ import annotations

import json
import sqlite3

import pytest

from apps.octo import paths
from apps.octo.fleet import geocode
from apps.octo.tests.auth.test_dashboard_throughput import _login

PW = "pw1234567890"
URL = "/api/v1/dashboard/octo-location"


def _op(client, name: str, role: str, scope_slugs=None) -> dict:
    client.cookies.clear()
    op = client.provision_operator(name, PW, role=role, athena_role=role,
                                   scope_slugs=scope_slugs)
    _login(client, op)
    return op


def _audit(action: str) -> list[sqlite3.Row]:
    conn = sqlite3.connect(paths.global_audit_db_path())
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id",
                            (action,)).fetchall()
    finally:
        conn.close()


def _row() -> dict | None:
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        row = conn.execute("SELECT value_json, updated_by FROM bundle_config "
                           "WHERE key = 'octo_location'").fetchone()
    finally:
        conn.close()
    return {"value": json.loads(row[0]), "by": row[1]} if row else None


BODY = {"lat": 41.2565, "lng": -100.7512, "display": "Example Hub", "city": "Exampleton, IL",
        "reason": "the MSP office moved"}


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
def test_only_a_super_admin_moves_the_host_pin(auth_client, role):
    _op(auth_client, f"op-{role}", role, ["acme-corp"] if role == "viewer" else None)
    # Reading: operators only — a client user never sees coordinates.
    assert auth_client.get(URL).status_code == (403 if role == "viewer" else 200)
    assert auth_client.put(URL, json=BODY).status_code == 403
    assert _audit("octo_location_set") == []


def test_a_super_admin_moves_it_audited_before_the_write(auth_client):
    sa = _op(auth_client, "sa-host", "super_admin")
    before = auth_client.get(URL).json()
    r = auth_client.put(URL, json=BODY)
    assert r.status_code == 200, r.text
    got = r.json()
    assert (got["lat"], got["lng"], got["city"]) == (41.2565, -100.7512, "Exampleton, IL")
    assert got["slug"] == before["slug"] and got["msp"] == before["msp"]   # msp unchanged
    assert auth_client.get(URL).json() == got
    (row,) = _audit("octo_location_set")
    assert row["target_kind"] == "bundle_config" and row["target_id"] == "octo_location"
    assert row["client_slug"] == "global" and row["reason"] == "the MSP office moved"
    assert json.loads(row["before_state"])["lat"] == before["lat"]
    assert json.loads(row["after_state"])["lat"] == 41.2565
    stored = _row()
    assert stored["value"] == got and stored["by"] == sa["id"]
    # Only what is given changes: display / city / msp are kept when omitted.
    r = auth_client.put(URL, json={"lat": 41.3, "lng": -100.8, "msp": "Example MSP",
                                   "reason": "fine tune"})
    assert r.status_code == 200
    assert r.json()["city"] == "Exampleton, IL" and r.json()["msp"] == "Example MSP"


@pytest.mark.parametrize("bad", [
    {**BODY, "reason": ""}, {**BODY, "reason": "x"}, {k: v for k, v in BODY.items()
                                                      if k != "reason"},
    {**BODY, "reason": "     "}, {**BODY, "reason": " \n x\t "},
    {**BODY, "lat": 0, "lng": 0}, {**BODY, "lat": 95}, {**BODY, "lng": -181},
    {**BODY, "slug": "elsewhere"}, {**BODY, "display": "x" * 61},
])
def test_validation(auth_client, bad):
    _op(auth_client, "sa-bad", "super_admin")
    assert auth_client.put(URL, json=bad).status_code == 422
    assert _audit("octo_location_set") == []


def test_a_missing_row_is_created(auth_client):
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        conn.execute("DELETE FROM bundle_config WHERE key = 'octo_location'")
        conn.commit()
    finally:
        conn.close()
    _op(auth_client, "sa-new", "super_admin")
    assert auth_client.get(URL).json()["city"] == "Kansas City"       # the placeholder
    r = auth_client.put(URL, json={"lat": 41.25, "lng": -100.75, "reason": "first placement"})
    assert r.status_code == 200, r.text
    assert r.json()["display"] == "Primary"
    assert _row()["value"]["lat"] == 41.25
    (row,) = _audit("octo_location_set")
    assert row["before_state"] in (None, "null")


def test_labels_are_cleaned(auth_client):
    _op(auth_client, "sa-clean", "super_admin")
    r = auth_client.put(URL, json={**BODY, "display": " Hub\x00 One ", "city": "Example\nTown"})
    assert r.status_code == 200
    assert (r.json()["display"], r.json()["city"]) == ("Hub One", "Example Town")


def test_the_geocoder_switch(auth_client, monkeypatch):
    _op(auth_client, "ana-geo", "analyst")
    assert auth_client.get("/api/v1/fleet/geocoder").status_code == 403
    _op(auth_client, "adm-geo", "admin")
    monkeypatch.setenv(geocode.GEOCODER_ENV, "census")
    assert auth_client.get("/api/v1/fleet/geocoder").json() == {"provider": "census"}
    monkeypatch.setenv(geocode.GEOCODER_ENV, "off")
    assert auth_client.get("/api/v1/fleet/geocoder").json() == {"provider": None}
    _op(auth_client, "view-geo", "viewer", ["acme-corp"])
    assert auth_client.get("/api/v1/fleet/geocoder").status_code == 403


def test_no_audit_no_write(auth_client, monkeypatch):
    from apps.octo.auth import audit

    _op(auth_client, "sa-noaudit", "super_admin")
    before = _row()

    def down(*_a, **_k):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(audit, "append", down)
    with pytest.raises(RuntimeError):
        auth_client.put(URL, json=BODY)
    assert _row() == before


def test_a_failed_write_says_so(auth_client, monkeypatch):
    from apps.octo.api.routers import dashboard

    _op(auth_client, "sa-fail", "super_admin")
    before = _row()

    def locked(_conn):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(dashboard, "transaction", locked)
    with pytest.raises(sqlite3.OperationalError):
        auth_client.put(URL, json=BODY)
    assert _row() == before
    (ok,) = _audit("octo_location_set")
    (failed,) = _audit("octo_location_set_failed")
    assert failed["id"] > ok["id"]
    assert json.loads(failed["after_state"]) == {"error": "OperationalError"}
    assert "nothing was written" in failed["reason"]
