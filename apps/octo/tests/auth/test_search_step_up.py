"""Step-up auth flow for the /search surface.

Covers:
- /search/status returns elevated=False for a fresh session
- /search/elevate with valid creds elevates + audits
- /search/elevate with wrong password fails + audits step_up_failed
- /search/elevate with wrong TOTP fails + audits step_up_failed
- require_step_up dep is enforced on protected routes (STEP_UP_REQUIRED)
- Sliding window math: slide() extends until, capped at absolute
- Absolute cap forces re-auth
- revoke() clears elevation
"""
from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from apps.octo import paths
from apps.octo.auth import sessions, step_up


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, op: dict) -> None:
    r = client.post("/api/v1/auth/password/begin", json={
        "username": op["username"], "password": op["password"],
    })
    challenge = r.json()["challenge_id"]
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r2 = client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": code,
    })
    assert r2.status_code == 200, r2.text


def _session_row(operator_id: int) -> sqlite3.Row | None:
    reg = sqlite3.connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        return reg.execute(
            "SELECT * FROM sessions WHERE operator_id = ? "
            "ORDER BY issued_at DESC LIMIT 1",
            (operator_id,),
        ).fetchone()
    finally:
        reg.close()


def _session_info(operator_id: int) -> sessions.SessionInfo:
    """Reconstruct SessionInfo from DB row. Lets tests inspect
    step-up state without needing the API client."""
    row = _session_row(operator_id)
    assert row is not None
    return sessions._row_to_info(row)


# ---------------------------------------------------------------------------
# /search/status
# ---------------------------------------------------------------------------

def test_status_returns_unelevated_for_fresh_session(auth_client):
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    r = auth_client.get("/api/v1/search/status")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["elevated"] is False
    assert body["granted_at"] is None
    assert body["expires_at"] is None
    assert body["ttl_minutes"] >= 5  # config min
    assert body["absolute_cap_hours"] >= 1


def test_status_returns_elevated_after_elevate(auth_client):
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r = auth_client.post("/api/v1/search/elevate", json={
        "current_password": op["password"], "totp_code": code,
    })
    assert r.status_code == 200, r.text
    s = auth_client.get("/api/v1/search/status").json()
    assert s["elevated"] is True
    assert s["granted_at"] is not None
    assert s["expires_at"] is not None
    assert s["absolute_expires_at"] is not None


# ---------------------------------------------------------------------------
# /search/elevate — happy path + failures
# ---------------------------------------------------------------------------

def test_elevate_success_sets_step_up_columns(auth_client):
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r = auth_client.post("/api/v1/search/elevate", json={
        "current_password": op["password"], "totp_code": code,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["elevated"] is True
    assert body["granted_at"] != ""
    assert body["expires_at"] != ""
    # DB-level confirmation
    row = _session_row(op["id"])
    assert row["step_up_auth_granted_at"] is not None
    assert row["step_up_auth_until"] is not None


def test_elevate_wrong_password_401(auth_client):
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r = auth_client.post("/api/v1/search/elevate", json={
        "current_password": "wrong-password-xxx", "totp_code": code,
    })
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_PASSWORD_INVALID"
    # Session row must NOT have step-up columns populated
    row = _session_row(op["id"])
    assert row["step_up_auth_granted_at"] is None
    assert row["step_up_auth_until"] is None


def test_elevate_wrong_totp_401(auth_client):
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    r = auth_client.post("/api/v1/search/elevate", json={
        "current_password": op["password"], "totp_code": "000000",
    })
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_TOTP_INVALID"
    row = _session_row(op["id"])
    assert row["step_up_auth_granted_at"] is None


def test_elevate_unauthenticated_401(auth_client):
    auth_client.cookies.clear()
    r = auth_client.post("/api/v1/search/elevate", json={
        "current_password": "x", "totp_code": "000000",
    })
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# step_up.status_for / grant / slide / revoke — unit-level math
# ---------------------------------------------------------------------------

def test_grant_sets_until_to_ttl_window(auth_client):
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    row = _session_row(op["id"])
    info = sessions._row_to_info(row)
    before = datetime.now(timezone.utc)
    status = step_up.grant(info.id)
    assert status.elevated
    assert status.granted_at is not None
    assert status.expires_at is not None
    assert status.expires_at > before
    # default TTL 30 minutes; allow 1m slop
    delta = status.expires_at - status.granted_at
    assert timedelta(minutes=29) <= delta <= timedelta(minutes=31)


def test_slide_extends_until_within_absolute_cap(auth_client, monkeypatch):
    # Tighten TTL for predictable assertions
    monkeypatch.setenv("SEARCH_STEP_UP_TTL_MINUTES", "10")
    monkeypatch.setenv("SEARCH_STEP_UP_ABSOLUTE_HOURS", "1")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    info = _session_info(op["id"])
    step_up.grant(info.id)
    info = _session_info(op["id"])  # reload after grant
    first_until = info.step_up_auth_until
    # Wait briefly so "now+10m" > "first_until - epsilon"
    time.sleep(0.05)
    new_status = step_up.slide(info)
    assert new_status.expires_at >= first_until


def test_slide_caps_at_absolute_window(auth_client, monkeypatch):
    monkeypatch.setenv("SEARCH_STEP_UP_TTL_MINUTES", "10")
    monkeypatch.setenv("SEARCH_STEP_UP_ABSOLUTE_HOURS", "1")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    info = _session_info(op["id"])
    step_up.grant(info.id)
    info = _session_info(op["id"])
    granted = info.step_up_auth_granted_at
    assert granted is not None
    cap = granted + timedelta(hours=1)
    status = step_up.slide(info)
    assert status.expires_at <= cap


def test_revoke_clears_step_up(auth_client):
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    info = _session_info(op["id"])
    step_up.grant(info.id)
    info = _session_info(op["id"])
    assert info.step_up_auth_until is not None
    step_up.revoke(info.id)
    info = _session_info(op["id"])
    assert info.step_up_auth_granted_at is None
    assert info.step_up_auth_until is None


# ---------------------------------------------------------------------------
# require_step_up dep — unauthenticated/unelevated callers blocked
# ---------------------------------------------------------------------------

class _FakeRequest:
    """Minimal Request stand-in for direct unit-testing the dep."""
    def __init__(self, ip: str = "127.0.0.1", forwarded_for: str | None = None):
        from starlette.datastructures import Headers
        self.headers = Headers(
            {"x-forwarded-for": forwarded_for} if forwarded_for is not None else {})
        class _Client:
            host = ip
        self.client = _Client()


def test_require_step_up_blocks_unelevated(auth_client):
    """Confirm the dep raises STEP_UP_REQUIRED on an unelevated session."""
    from apps.octo.api.errors import APIError
    from apps.octo.api.routers.search import require_step_up

    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    info = _session_info(op["id"])
    with pytest.raises(APIError) as exc:
        require_step_up(_FakeRequest(), info=info)
    assert exc.value.code == "STEP_UP_REQUIRED"


def test_require_step_up_allows_elevated(auth_client):
    from apps.octo.api.routers.search import require_step_up

    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    info = _session_info(op["id"])
    step_up.grant(info.id, ip_address="127.0.0.1")
    info = _session_info(op["id"])
    result = require_step_up(_FakeRequest("127.0.0.1"), info=info)
    assert result.id == info.id


# ---------------------------------------------------------------------------
# IP binding — subnet default, env-configurable
# ---------------------------------------------------------------------------

def test_ip_prefix_subnet_ipv4_takes_24(monkeypatch):
    monkeypatch.delenv("SEARCH_STEP_UP_IP_BINDING", raising=False)
    assert step_up.compute_ip_prefix("203.0.113.42") == "203.0.113.0/24"


def test_ip_prefix_subnet_ipv6_takes_48(monkeypatch):
    monkeypatch.delenv("SEARCH_STEP_UP_IP_BINDING", raising=False)
    assert step_up.compute_ip_prefix("2001:db8:1:2:3:4:5:6") == "2001:db8:1::/48"


def test_ip_prefix_strict_returns_full_address(monkeypatch):
    monkeypatch.setenv("SEARCH_STEP_UP_IP_BINDING", "strict")
    assert step_up.compute_ip_prefix("203.0.113.42") == "203.0.113.42/32"


def test_ip_prefix_off_returns_none(monkeypatch):
    monkeypatch.setenv("SEARCH_STEP_UP_IP_BINDING", "off")
    assert step_up.compute_ip_prefix("203.0.113.42") is None


def test_ip_prefix_unparseable_returns_none():
    assert step_up.compute_ip_prefix("not-an-ip") is None
    assert step_up.compute_ip_prefix(None) is None
    assert step_up.compute_ip_prefix("") is None


# Documentation ranges: 192.0.2.0/24 is the proxy network (reverse proxy .10,
# console .20), 203.0.113.0/24 internet clients, 198.51.100.0/24 callers on
# the published (tailnet) port.
_PROXY_NET = "192.0.2.0/24"
_PROXY, _CONSOLE = "192.0.2.10", "192.0.2.20"
_VICTIM, _CLIENT = "203.0.113.42", "203.0.113.77"
_DIRECT = "198.51.100.7"


def test_request_ip_believes_forwarded_for_only_from_a_trusted_proxy(monkeypatch):
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", _PROXY_NET)
    # Path 1 / path 2: the right-most entry that is not a trusted hop.
    assert step_up.request_ip_from_headers(_VICTIM, _PROXY) == _VICTIM
    assert step_up.request_ip_from_headers(f"{_VICTIM}, {_PROXY}", _CONSOLE) == _VICTIM
    # Never the LEFT-most entry: that one is whatever the client wrote.
    assert step_up.request_ip_from_headers(
        f"{_VICTIM}, {_CLIENT}, {_PROXY}", _CONSOLE) == _CLIENT
    # A peer that is not a trusted proxy: its header is ignored.
    assert step_up.request_ip_from_headers(_VICTIM, _DIRECT) == _DIRECT
    assert step_up.request_ip_from_headers(f"{_VICTIM}, {_PROXY}", _DIRECT) == _DIRECT


def test_request_ip_with_the_setting_empty_is_the_socket_peer(monkeypatch):
    monkeypatch.delenv("OCTO_TRUSTED_PROXIES", raising=False)
    # The old behaviour took the left-most entry from anyone.
    assert step_up.request_ip_from_headers(f"{_VICTIM}, {_PROXY}", _PROXY) == _PROXY
    assert step_up.request_ip_from_headers(_VICTIM, _DIRECT) == _DIRECT


def test_request_ip_falls_back_to_client_host(monkeypatch):
    for setting in ("", _PROXY_NET):
        monkeypatch.setenv("OCTO_TRUSTED_PROXIES", setting)
        assert step_up.request_ip_from_headers(None, "192.0.2.1") == "192.0.2.1"
        assert step_up.request_ip_from_headers("", "192.0.2.1") == "192.0.2.1"
        assert step_up.request_ip_from_headers(None, None) is None
        assert step_up.request_ip_from_headers(_VICTIM, None) is None


def test_check_ip_binding_same_subnet_passes(auth_client):
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    step_up.grant(_session_info(op["id"]).id, ip_address="203.0.113.42")
    info = _session_info(op["id"])
    # Same /24, different host
    assert step_up.check_ip_binding(info, "203.0.113.55") is True


def test_check_ip_binding_different_subnet_fails(auth_client):
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    step_up.grant(_session_info(op["id"]).id, ip_address="203.0.113.42")
    info = _session_info(op["id"])
    # /24 differs
    assert step_up.check_ip_binding(info, "198.51.100.42") is False


def test_check_ip_binding_off_mode_always_passes(auth_client, monkeypatch):
    monkeypatch.setenv("SEARCH_STEP_UP_IP_BINDING", "off")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    # grant in off mode → no prefix stored
    step_up.grant(_session_info(op["id"]).id, ip_address="203.0.113.42")
    info = _session_info(op["id"])
    assert info.step_up_auth_ip_prefix is None
    # And subsequent check from totally different IP still passes
    assert step_up.check_ip_binding(info, "198.51.100.99") is True


def test_require_step_up_raises_network_changed_on_mismatch(auth_client):
    """The whole point: stolen cookie from a different network → revoke."""
    from apps.octo.api.errors import APIError
    from apps.octo.api.routers.search import require_step_up

    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    step_up.grant(_session_info(op["id"]).id, ip_address="203.0.113.42")
    info = _session_info(op["id"])
    # Request comes from a different /24
    with pytest.raises(APIError) as exc:
        require_step_up(_FakeRequest("198.51.100.42"), info=info)
    assert exc.value.code == "STEP_UP_NETWORK_CHANGED"
    # And the clearance should now be revoked
    info_after = _session_info(op["id"])
    assert info_after.step_up_auth_granted_at is None
    assert info_after.step_up_auth_until is None
    assert info_after.step_up_auth_ip_prefix is None


def _client_from(auth_client, peer: str):
    """A client of the same app whose socket peer is `peer`."""
    from fastapi.testclient import TestClient
    return TestClient(auth_client.app, base_url="https://athena.test",
                      client=(peer, 40_000))


def _elevate_from(auth_client, peer: str, forwarded_for: str | None) -> str | None:
    """Sign in and elevate from socket peer `peer` sending `forwarded_for`;
    the network prefix step-up stored."""
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    tc = _client_from(auth_client, peer)
    _login(tc, op)
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    headers = {"X-Forwarded-For": forwarded_for} if forwarded_for is not None else {}
    r = tc.post(
        "/api/v1/search/elevate",
        json={"current_password": op["password"], "totp_code": code},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    return _session_info(op["id"]).step_up_auth_ip_prefix


def test_elevate_persists_the_client_prefix_behind_a_trusted_proxy(auth_client, monkeypatch):
    """End-to-end, OCTO_TRUSTED_PROXIES set: through the console (path 2)
    the chain is `<client>, <reverse proxy>` from the console's address and
    step-up binds to the client's network, not to whatever the client put
    in front of the chain."""
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", _PROXY_NET)
    prefix = _elevate_from(auth_client, _CONSOLE, f"198.51.100.200, {_VICTIM}, {_PROXY}")
    assert prefix == "203.0.113.0/24"


def test_elevate_from_an_untrusted_peer_binds_to_the_peer(auth_client, monkeypatch):
    """A direct caller (a stolen session on the tailnet, say) naming the
    victim's address in X-Forwarded-For gets bound to its OWN network."""
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", _PROXY_NET)
    assert _elevate_from(auth_client, _DIRECT, _VICTIM) == "198.51.100.0/24"


def test_elevate_with_the_setting_empty_binds_to_the_socket_peer(auth_client, monkeypatch):
    """OCTO_TRUSTED_PROXIES empty: the header is believed from nobody, so
    the console path binds to the console's own address (one constant
    network, as the tunnel's address was before) and nobody can name one."""
    monkeypatch.delenv("OCTO_TRUSTED_PROXIES", raising=False)
    assert _elevate_from(auth_client, _CONSOLE, f"{_VICTIM}, {_PROXY}") == "192.0.2.0/24"


@pytest.mark.parametrize("setting", ["", _PROXY_NET])
def test_a_spoofed_forwarded_for_cannot_keep_a_stolen_elevation(auth_client, monkeypatch, setting):
    """Elevation granted from the victim's network; the same session used
    from another network that names the victim's address in X-Forwarded-For
    is still a network change (the old code believed the left-most entry
    from any peer and let it through)."""
    from apps.octo.api.errors import APIError
    from apps.octo.api.routers.search import require_step_up

    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", setting)
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    step_up.grant(_session_info(op["id"]).id, ip_address=_VICTIM)
    info = _session_info(op["id"])
    with pytest.raises(APIError) as exc:
        require_step_up(_FakeRequest(_DIRECT, forwarded_for=_VICTIM), info=info)
    assert exc.value.code == "STEP_UP_NETWORK_CHANGED"
    assert _session_info(op["id"]).step_up_auth_granted_at is None


def test_require_step_up_follows_the_client_through_a_trusted_proxy(auth_client, monkeypatch):
    from apps.octo.api.errors import APIError
    from apps.octo.api.routers.search import require_step_up

    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", _PROXY_NET)
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    step_up.grant(_session_info(op["id"]).id, ip_address=_VICTIM)
    info = _session_info(op["id"])
    # Same /24 through the console: allowed.
    ok = require_step_up(_FakeRequest(_CONSOLE, f"203.0.113.9, {_PROXY}"), info=info)
    assert ok.id == info.id
    # Another network through the console, even with the victim's address
    # in front of the chain: a network change.
    with pytest.raises(APIError) as exc:
        require_step_up(_FakeRequest(_CONSOLE, f"{_VICTIM}, 198.51.100.9, {_PROXY}"),
                        info=_session_info(op["id"]))
    assert exc.value.code == "STEP_UP_NETWORK_CHANGED"
