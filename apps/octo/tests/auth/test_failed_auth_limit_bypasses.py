"""Attempts to get past (or abuse) the failed-authentication limiter.

Each test is an attack that worked against the first cut of the limiter:
  * a constant bearer header on sign-in made every failed sign-in "the same
    retried token" (counted once), and a proven token carried sign-in past
    a cool-down;
  * a fresh bearer header per request gave a fresh throughput bucket on
    routes that never take a bearer token (search step-up's 5/min);
  * with OCTO_TRUSTED_PROXIES empty every console user is one address, so 30
    wrong passwords from anyone held back every operator's sign-in;
  * parallel guesses all reached auth before the first 401 was counted;
  * the email change's password re-check was not counted at all;
  * a zone id let header text through as "the client address".

Same stand-in app, ranges and fake clock as test_failed_auth_limit.py:
192.0.2.0/24 is the proxy network (reverse proxy .10, console .20, tunnel
.30), 203.0.113.0/24 internet clients, 198.51.100.0/24 tailnet callers.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi import Header, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from apps.octo.api import client_ip as cip
from apps.octo.api import rate_limit as rl
from apps.octo.tests.auth.test_failed_auth_limit import (  # noqa: F401 (real_app: fixture)
    CADDY, CLIENT_A, CLIENT_B, CONSOLE, DIRECT, LIMIT, PROXY_NET, Env,
    _assert_cooling_down, _token, _trip, _who, real_app,
)

TUNNEL = "192.0.2.30"
SIGN_IN = "/api/v1/auth/password/begin"
RIGHT = {"username": "alice", "password": "right-password"}


def _wrong(i: int = 0) -> dict:
    return {"username": f"user{i}", "password": "nope"}


class BypassEnv(Env):
    """The stand-in app plus a step-up route, the profile route, a slow
    bearer route (for parallel requests) and one that raises."""

    def __init__(self) -> None:
        self.gate: asyncio.Event | None = None
        self.reached = 0
        super().__init__()

    def use_limiter(self, limiter: rl.RateLimiter) -> None:
        super().use_limiter(limiter)
        app = self.app

        @app.post("/api/v1/search/elevate")
        async def elevate(request: Request):
            body = await request.json()
            if body.get("password") == "right-password":
                return {"elevated": True}
            return JSONResponse(status_code=401, content={"code": "AUTH_PASSWORD_INVALID"})

        @app.patch("/api/v1/auth/me/profile")
        async def profile(request: Request):
            body = await request.json()
            if "email" in body and body.get("current_password") != "right-password":
                return JSONResponse(status_code=401, content={"code": "AUTH_PASSWORD_INVALID"})
            return {"ok": True}

        @app.get("/api/v1/slow")
        async def slow(authorization: str | None = Header(default=None)):
            self.reached += 1
            await self.gate.wait()
            token = (authorization or "").split(None, 1)[-1]
            if token in self.valid:
                return {"ok": True}
            return JSONResponse(status_code=401, content={"code": "AUTH_INVALID"})

        @app.get("/api/v1/boom")
        def boom():
            raise RuntimeError("route failed")


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", PROXY_NET)
    return BypassEnv()


# ---------------------------------------------------------------------------
# A bearer header on a route that never takes one
# ---------------------------------------------------------------------------

def test_a_constant_bearer_header_does_not_merge_failed_sign_ins(env):
    tc = env.client(DIRECT)
    junk = {"Authorization": "Bearer constant-junk"}
    for i in range(LIMIT):
        assert tc.post(SIGN_IN, json=_wrong(i), headers=junk).status_code == 401
    _assert_cooling_down(tc.post(SIGN_IN, json=RIGHT, headers=junk))
    _assert_cooling_down(tc.post(SIGN_IN, json=RIGHT))


def test_a_proven_token_does_not_carry_sign_in_past_a_cooldown(env):
    buoy = _token()
    env.valid.add(buoy)
    tc = env.client(DIRECT)
    assert _who(tc, buoy).status_code == 200
    with_buoy = {"Authorization": f"Bearer {buoy}"}
    for i in range(LIMIT):
        assert tc.post(SIGN_IN, json=_wrong(i), headers=with_buoy).status_code == 401
    _assert_cooling_down(tc.post(SIGN_IN, json=RIGHT, headers=with_buoy))
    # The failed sign-ins were not the token's failures: it is still proven
    # and still works on its own route.
    assert env.failures.is_known(rl.token_fingerprint(buoy))
    assert _who(tc, buoy).status_code == 200


def test_fresh_bearer_headers_do_not_escape_the_step_up_bucket(env):
    env.use_limiter(rl.RateLimiter({"search_elevate": 3}))
    tc = env.client(DIRECT)
    for _ in range(3):
        r = tc.post("/api/v1/search/elevate", json={"password": "nope"},
                    headers={"Authorization": f"Bearer {_token()}"})
        assert r.status_code == 401
    r = tc.post("/api/v1/search/elevate", json={"password": "right-password"},
                headers={"Authorization": f"Bearer {_token()}"})
    assert (r.status_code, r.headers["X-RateLimit-Class"]) == (429, "search_elevate")


def test_webhooks_with_a_bearer_header_are_address_bucketed_and_not_counted(env):
    env.use_limiter(rl.RateLimiter({"admin_write": LIMIT * 3}))
    tc = env.client(DIRECT)
    for _ in range(LIMIT * 3):
        r = tc.post("/api/v1/webhooks/datto", headers={"Authorization": f"Bearer {_token()}"})
        assert r.status_code == 401
    assert env.failures._addresses == {}
    r = tc.post("/api/v1/webhooks/datto", headers={"Authorization": f"Bearer {_token()}"})
    assert (r.status_code, r.headers["X-RateLimit-Class"]) == (429, "admin_write")


def test_caller_key_ignores_a_bearer_header_on_credential_checks():
    from starlette.requests import Request as SRequest
    mw = rl.RateLimitMiddleware.__new__(rl.RateLimitMiddleware)
    for method, path in [("POST", SIGN_IN), ("POST", "/api/v1/search/elevate/"),
                         ("PATCH", "/api/v1/auth/me/profile"),
                         ("POST", "/api/v1/webhooks/datto")]:
        scope = {"type": "http", "method": method, "path": path,
                 "headers": [(b"authorization", f"Bearer {_token()}".encode())],
                 "client": (DIRECT, 1)}
        assert mw._caller_key(SRequest(scope)) == f"ip:{DIRECT}"
    scope = {"type": "http", "method": "GET", "path": "/api/v1/whoami",
             "headers": [(b"authorization", f"Bearer {_token()}".encode())],
             "client": (DIRECT, 1)}
    assert mw._caller_key(SRequest(scope)).startswith("tok:")


# ---------------------------------------------------------------------------
# Lock-out abuse: a shared address
# ---------------------------------------------------------------------------

def test_default_setting_one_user_cannot_lock_every_console_user_out(env, monkeypatch):
    """Setting empty: every console user arrives as the console with the
    same chain. The limiter is off, so failed sign-ins (and guessed tokens)
    from one of them hold back nobody."""
    monkeypatch.delenv("OCTO_TRUSTED_PROXIES")
    attacker, colleague = env.client(CONSOLE), env.client(CONSOLE)
    chain = {"X-Forwarded-For": f"{TUNNEL}, {CADDY}"}
    for i in range(LIMIT * 3):
        assert attacker.post(SIGN_IN, json=_wrong(i), headers=chain).status_code == 401
    _trip(attacker, n=LIMIT * 3, **chain)
    assert colleague.post(SIGN_IN, json=RIGHT, headers=chain).status_code == 200
    assert colleague.post("/api/v1/search/elevate", json={"password": "right-password"},
                          headers=chain).status_code == 200
    assert env.failures._addresses == {}


@pytest.mark.parametrize("chain", [
    f"{TUNNEL}, {CADDY}",          # the proxy's console route not changed yet
    TUNNEL,
    "",
    f"{CLIENT_A}, garbage",        # nothing right of the garbage is a client
])
def test_a_chain_that_names_no_client_is_neither_counted_nor_held_back(env, chain):
    """Setting present, but the chain from the console ends in trusted hops
    only: the "client" is a proxy, shared by everybody behind it."""
    attacker, colleague = env.client(CONSOLE), env.client(CONSOLE)
    headers = {"X-Forwarded-For": chain} if chain else {}
    for i in range(LIMIT * 3):
        assert attacker.post(SIGN_IN, json=_wrong(i), headers=headers).status_code == 401
    assert colleague.post(SIGN_IN, json=RIGHT, headers=headers).status_code == 200
    assert env.failures._addresses == {}


def test_once_the_chain_names_clients_only_the_guesser_cools_down(env):
    attacker, colleague = env.client(CONSOLE), env.client(CONSOLE)
    for i in range(LIMIT):
        attacker.post(SIGN_IN, json=_wrong(i), headers={"X-Forwarded-For": f"{CLIENT_A}, {CADDY}"})
    _assert_cooling_down(attacker.post(SIGN_IN, json=RIGHT,
                                       headers={"X-Forwarded-For": f"{CLIENT_A}, {CADDY}"}))
    assert colleague.post(SIGN_IN, json=RIGHT,
                          headers={"X-Forwarded-For": f"{CLIENT_B}, {CADDY}"}).status_code == 200


def test_failure_address_is_none_without_the_setting_or_a_client(monkeypatch):
    from starlette.requests import Request as SRequest

    def req(peer, xff=None):
        headers = [(b"x-forwarded-for", xff.encode())] if xff else []
        return SRequest({"type": "http", "method": "GET", "path": "/x",
                         "headers": headers, "client": (peer, 1)})

    monkeypatch.delenv("OCTO_TRUSTED_PROXIES", raising=False)
    assert rl.failure_address(req(DIRECT)) is None
    assert rl.failure_address(req(CADDY, CLIENT_A)) is None
    assert rl.limiter_address(req(CADDY, CLIENT_A)) == f"{CADDY}|{CLIENT_A}"
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", PROXY_NET)
    assert rl.failure_address(req(DIRECT, CLIENT_A)) == DIRECT
    assert rl.failure_address(req(CADDY, CLIENT_A)) == CLIENT_A
    assert rl.failure_address(req(CONSOLE, f"{TUNNEL}, {CADDY}")) is None
    assert rl.failure_address(req(CADDY)) is None
    assert rl.failure_address(req(CADDY, "2001:db8:1:2::5")) == "2001:db8:1:2::/64"


# ---------------------------------------------------------------------------
# Parallel attempts
# ---------------------------------------------------------------------------

async def _parallel(env: BypassEnv, tokens: list[str]) -> list[httpx.Response]:
    env.gate, env.reached = asyncio.Event(), 0
    transport = httpx.ASGITransport(app=env.app, client=(DIRECT, 40_000))
    async with httpx.AsyncClient(transport=transport, base_url="http://octo.test") as c:
        tasks = [asyncio.create_task(c.get("/api/v1/slow",
                                           headers={"Authorization": f"Bearer {t}"}))
                 for t in tokens]
        # Every request either waits in the route or has been answered
        # before any of them is let go.
        for _ in range(100_000):
            await asyncio.sleep(0)
            if env.reached + sum(t.done() for t in tasks) >= len(tasks):
                break
        env.gate.set()
        return list(await asyncio.gather(*tasks))


def test_a_parallel_burst_of_guesses_is_held_to_the_limit(env):
    responses = asyncio.run(_parallel(env, [_token() for _ in range(LIMIT * 20)]))
    codes = [r.status_code for r in responses]
    assert env.reached == LIMIT
    assert codes.count(401) == LIMIT and codes.count(429) == LIMIT * 19
    assert all(r.headers["X-RateLimit-Class"] == "auth_failure"
               for r in responses if r.status_code == 429)
    assert env.failures.retry_after(DIRECT) > 0       # and then the cool-down


def test_one_token_in_parallel_counts_once(env):
    """An operator tool firing many requests with ONE token is not a burst
    of guesses: the same key in flight N times is one attempt."""
    token = _token()
    env.valid.add(token)
    responses = asyncio.run(_parallel(env, [token] * (LIMIT * 10)))
    assert [r.status_code for r in responses] == [200] * (LIMIT * 10)
    assert env.failures._addresses == {}


def test_proven_tokens_are_never_held_by_a_burst(env):
    tokens = [_token() for _ in range(LIMIT * 3)]
    env.valid.update(tokens)
    tc = env.client(DIRECT)
    for t in tokens:
        assert _who(tc, t).status_code == 200            # proven one by one
    responses = asyncio.run(_parallel(env, tokens))
    assert [r.status_code for r in responses] == [200] * len(tokens)


# ---------------------------------------------------------------------------
# Bookkeeping: nothing leaks
# ---------------------------------------------------------------------------

def test_in_flight_slots_are_released_on_error_and_on_throughput_refusal(env):
    tc = TestClient(env.app, client=(DIRECT, 40_000), raise_server_exceptions=False)
    for _ in range(LIMIT * 3):
        r = tc.get("/api/v1/boom", headers={"Authorization": f"Bearer {_token()}"})
        assert r.status_code == 500
    assert env.failures._addresses == {}

    env.use_limiter(rl.RateLimiter({"admin_write": 2}))
    tc = env.client(DIRECT)
    assert tc.post(SIGN_IN, json=RIGHT).status_code == 200
    assert tc.post(SIGN_IN, json=RIGHT).status_code == 200
    r = tc.post(SIGN_IN, json=RIGHT)
    assert (r.status_code, r.headers["X-RateLimit-Class"]) == (429, "admin_write")
    assert env.failures._addresses == {}


def test_successful_attempts_leave_no_state(env):
    tc = env.client(CADDY)
    for i in range(300):
        client = f"203.0.113.{i % 250 + 1}" if i < 250 else f"2001:db8:{i:x}::1"
        assert tc.post(SIGN_IN, json=RIGHT, headers={"X-Forwarded-For": client}).status_code == 200
    assert env.failures._addresses == {}


def test_settle_without_admit_and_unknown_addresses_are_harmless():
    lim = rl.AuthFailureLimiter(LIMIT, 600, 900)
    assert lim.settle("203.0.113.9", "k", failed=False) is False
    assert lim.settle("203.0.113.9", "k", failed=False, reserved=False) is False
    assert lim._addresses == {}
    assert lim.admit("203.0.113.9", "k") == 0
    assert lim.admit("203.0.113.9", "k") == 0          # same key: no new slot
    assert lim._addresses["203.0.113.9"].in_flight == {"k": 2}
    lim.settle("203.0.113.9", "k", failed=False)
    lim.settle("203.0.113.9", "k", failed=False)
    assert lim._addresses == {}


# ---------------------------------------------------------------------------
# Every credential check counts
# ---------------------------------------------------------------------------

def test_the_email_change_password_check_counts(env):
    tc = env.client(DIRECT)
    for _ in range(LIMIT):
        r = tc.patch("/api/v1/auth/me/profile",
                     json={"email": "bob@example.test", "current_password": "nope"})
        assert r.status_code == 401
    _assert_cooling_down(tc.patch("/api/v1/auth/me/profile",
                                  json={"email": "bob@example.test",
                                        "current_password": "right-password"}))
    _assert_cooling_down(tc.post(SIGN_IN, json=RIGHT))


def test_credential_check_routes_exist_in_the_real_app(real_app):
    """The lists name real routes with the right method: a renamed route
    would silently drop out of the count."""
    app, _ = real_app
    routes = {(m, r.path) for r in app.routes for m in getattr(r, "methods", ()) or ()}
    for path in rl.CREDENTIAL_CHECK_PATHS:
        assert ("POST", path) in routes, path
    for method, path in rl.CREDENTIAL_CHECK_OTHER:
        assert (method, path) in routes, (method, path)
    for method, path in [("GET", "/api/v1/whoami"), ("POST", "/api/v1/buoy/heartbeat"),
                         ("POST", "/api/v1/buoy/command/{cmd_id}/result")]:
        assert (method, path) in routes, (method, path)


def test_real_app_sign_in_spray_behind_a_constant_bearer_still_cools_down(real_app):
    app, _ = real_app
    tc = TestClient(app, client=(DIRECT, 40_000))
    junk = {"Authorization": "Bearer constant-junk"}
    for i in range(LIMIT):
        r = tc.post(SIGN_IN, json={"username": f"nobody{i}", "password": "wrong-password"},
                    headers=junk)
        assert (r.status_code, r.json()["code"]) == (401, "AUTH_PASSWORD_INVALID")
    _assert_cooling_down(tc.post(SIGN_IN, json={"username": "nobody", "password": "x"},
                                 headers=junk))


# ---------------------------------------------------------------------------
# Zone ids
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "2001:db8::7%eth0", "fe80::1%a b", "[2001:db8::7%1]", "::ffff:192.0.2.10%z",
])
def test_a_zone_id_is_not_an_address(value):
    assert cip.parse_ip(value) is None


def test_a_zone_id_never_becomes_the_client():
    trusted = cip.parse_trusted_proxies(PROXY_NET)[0]
    assert cip.resolve_client_ip(CADDY, "2001:db8::7%any text", trusted) == CADDY
    assert cip.resolve_client_ip(CONSOLE, f"{CLIENT_A}, 2001:db8::7%x, {CADDY}", trusted) == CADDY
    assert cip.unverified_forwarded_hint(f"{CLIENT_A}, 2001:db8::7%x") == CLIENT_A
