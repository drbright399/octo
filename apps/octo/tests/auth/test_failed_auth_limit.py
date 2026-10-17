"""Rate-limit callers and the failed-authentication limiter.

`RateLimitMiddleware` in front of a small stand-in app (the real routes' auth
is exercised at the end against `create_app()`). Peers are set per client
with TestClient(client=...). Documentation ranges only: 192.0.2.0/24 is the
proxy network (reverse proxy .10, console .20), 203.0.113.0/24 internet
clients, 198.51.100.0/24 callers on the published (tailnet) port.
"""
from __future__ import annotations

import re
import secrets

import pytest
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from apps.octo.api import rate_limit as rl

PROXY_NET = "192.0.2.0/24"
CADDY, CONSOLE = "192.0.2.10", "192.0.2.20"
CLIENT_A, CLIENT_B = "203.0.113.5", "203.0.113.6"
DIRECT, DIRECT_2 = "198.51.100.7", "198.51.100.8"

LIMIT = 5
WINDOW = 600
COOLDOWN = 900


class Clock:
    def __init__(self) -> None:
        self.now = 10_000.0

    def __call__(self) -> float:
        return self.now


def _token(prefix: str = "") -> str:
    return prefix + secrets.token_urlsafe(32)


def _stand_in_app(valid: set[str], limiter: rl.RateLimiter, failures) -> FastAPI:
    app = FastAPI()

    def _bearer_ok(authorization):
        if not authorization or not authorization.lower().startswith("bearer "):
            return False
        parts = authorization.split(None, 1)
        return len(parts) == 2 and parts[1].strip() in valid

    @app.get("/api/v1/whoami")
    def whoami(authorization: str | None = Header(default=None)):
        if _bearer_ok(authorization):
            return {"ok": True}
        return JSONResponse(status_code=401, content={"code": "AUTH_INVALID"})

    @app.post("/api/v1/ingest/{slug}/events", status_code=202)
    def ingest(slug: str, authorization: str | None = Header(default=None)):
        if _bearer_ok(authorization):
            return {"accepted": True}
        return JSONResponse(status_code=401, content={"code": "AUTH_INVALID"})

    @app.post("/api/v1/auth/password/begin")
    async def begin(request: Request):
        body = await request.json()
        if body.get("password") == "right-password":
            return {"ok": True}
        return JSONResponse(status_code=401, content={"code": "AUTH_PASSWORD_INVALID"})

    @app.post("/api/v1/webhooks/datto")
    def webhook():
        return JSONResponse(status_code=401, content={"code": "AUTH_INVALID"})

    @app.get("/api/v1/dashboard")       # a session-cookie route: no credential checked here
    def dashboard():
        return {"ok": True}

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    app.add_middleware(rl.RateLimitMiddleware, limiter=limiter, failures=failures)
    return app


class Env:
    """The stand-in app, its two limiters and a fake clock."""

    def __init__(self) -> None:
        self.clock = Clock()
        self.valid: set[str] = set()
        self.failures = rl.AuthFailureLimiter(LIMIT, WINDOW, COOLDOWN, clock=self.clock)
        self.use_limiter(rl.RateLimiter({"admin_read": 10_000, "admin_write": 10_000}))

    def use_limiter(self, limiter: rl.RateLimiter) -> None:
        self.limiter = limiter
        self.app = _stand_in_app(self.valid, limiter, self.failures)

    def client(self, peer: str) -> TestClient:
        return TestClient(self.app, client=(peer, 40_000))


@pytest.fixture
def env(monkeypatch):
    # The production setting: the failed-auth limiter is off without it
    # (test_default_setting_* below).
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", PROXY_NET)
    return Env()


def _who(tc: TestClient, token: str, **headers):
    return tc.get("/api/v1/whoami", headers={"Authorization": f"Bearer {token}", **headers})


def _assert_cooling_down(r, *, at_most: int = COOLDOWN):
    assert r.status_code == 429, r.text
    assert r.json()["code"] == "RATE_LIMITED"
    assert r.headers["X-RateLimit-Class"] == "auth_failure"
    assert 1 <= int(r.headers["Retry-After"]) <= at_most
    assert r.headers["Cache-Control"] == "no-store"


def _trip(tc: TestClient, n: int = LIMIT, **headers) -> None:
    for _ in range(n):
        assert _who(tc, _token(), **headers).status_code == 401


# ---------------------------------------------------------------------------
# Token buckets: the whole token, hashed
# ---------------------------------------------------------------------------

def test_tokens_sharing_a_prefix_get_separate_buckets(env):
    env.use_limiter(rl.RateLimiter({"admin_read": 3}))
    a, b = _token("SamePfx8"), _token("SamePfx8")
    assert a[:8] == b[:8]
    env.valid |= {a, b}
    tc = env.client(DIRECT)
    for _ in range(3):
        assert _who(tc, a).status_code == 200
    r = _who(tc, a)
    assert (r.status_code, r.headers["X-RateLimit-Class"]) == (429, "admin_read")
    # The OLD key (`tok:` + first 8 characters) made b share a's bucket.
    assert _who(tc, b).status_code == 200


def test_caller_key_holds_neither_the_token_nor_its_prefix():
    mw = rl.RateLimitMiddleware.__new__(rl.RateLimitMiddleware)
    token = _token("Pfx4Key9")
    from starlette.requests import Request as SRequest
    scope = {"type": "http", "method": "GET", "path": "/x",
             "headers": [(b"authorization", f"Bearer {token}".encode())],
             "client": (DIRECT, 1)}
    key = mw._caller_key(SRequest(scope))
    assert re.fullmatch(r"tok:[0-9a-f]{64}", key)
    assert token not in key and token[:8] not in key
    other = dict(scope, headers=[(b"authorization", f"Bearer {token}x".encode())])
    assert mw._caller_key(SRequest(other)) != key


# ---------------------------------------------------------------------------
# Failed-auth limiter
# ---------------------------------------------------------------------------

def test_guessed_tokens_hit_the_limit_then_429_with_retry_after(env):
    attacker, bystander = env.client(DIRECT), env.client(DIRECT_2)
    _trip(attacker)
    _assert_cooling_down(_who(attacker, _token()))
    assert int(_who(attacker, _token()).headers["Retry-After"]) == COOLDOWN
    # Another address is unaffected: its guesses still reach auth (401).
    assert _who(bystander, _token()).status_code == 401
    assert env.failures.retry_after(DIRECT_2) == 0


def test_successes_never_count_and_never_reset_the_count(env):
    good = _token()
    env.valid.add(good)
    tc = env.client(DIRECT)
    for _ in range(LIMIT - 1):
        assert _who(tc, _token()).status_code == 401
        for _ in range(20):                       # successes in between
            assert _who(tc, good).status_code == 200
    assert env.failures.retry_after(DIRECT) == 0
    # The LIMIT-th failure trips it: twenty successes after each failure
    # neither counted nor wiped anything.
    assert _who(tc, _token()).status_code == 401
    _assert_cooling_down(_who(tc, _token()))


def test_an_authenticated_heavy_client_is_never_throttled(env):
    good = _token()
    env.valid.add(good)
    tc = env.client(DIRECT)
    for _ in range(300):
        assert _who(tc, good).status_code == 200
    for _ in range(100):
        r = tc.post("/api/v1/ingest/acme/events", headers={"Authorization": f"Bearer {good}"})
        assert r.status_code == 202
    assert env.failures.retry_after(DIRECT) == 0


def test_cooldown_spares_proven_tokens_and_credential_free_requests(env):
    """A buoy behind the same address keeps working; only credential
    ATTEMPTS that are not already proven are held back."""
    buoy, fresh = _token(), _token()
    env.valid |= {buoy, fresh}
    tc = env.client(DIRECT)
    assert _who(tc, buoy).status_code == 200      # proven on a bearer route
    _trip(tc)
    for _ in range(50):
        assert _who(tc, buoy).status_code == 200
        assert tc.post("/api/v1/ingest/acme/events",
                       headers={"Authorization": f"Bearer {buoy}"}).status_code == 202
    assert tc.get("/api/v1/dashboard").status_code == 200   # session traffic
    assert tc.get("/healthz").status_code == 200
    # Held back: a token never proven here, and sign-in.
    _assert_cooling_down(_who(tc, fresh))
    _assert_cooling_down(tc.post("/api/v1/auth/password/begin",
                                 json={"username": "alice", "password": "right-password"}))


def test_a_token_retried_with_the_same_value_counts_once(env):
    """A buoy left running with a revoked token is one failure, not one per
    heartbeat: it never locks its neighbours out."""
    revoked = _token()
    tc = env.client(DIRECT)
    for _ in range(200):
        assert _who(tc, revoked).status_code == 401
    assert env.failures.retry_after(DIRECT) == 0


def test_cooldown_ends_and_the_window_slides(env):
    tc = env.client(DIRECT)
    _trip(tc)
    env.clock.now += COOLDOWN - 300
    _assert_cooling_down(_who(tc, _token()), at_most=300)
    env.clock.now += 301
    assert _who(tc, _token()).status_code == 401           # reaches auth again
    # Sliding window: failures older than WINDOW no longer count.
    for _ in range(LIMIT - 2):
        assert _who(tc, _token()).status_code == 401
    env.clock.now += WINDOW + 1
    for _ in range(LIMIT - 1):
        assert _who(tc, _token()).status_code == 401
    assert env.failures.retry_after(DIRECT) == 0
    assert _who(tc, _token()).status_code == 401
    _assert_cooling_down(_who(tc, _token()))


def test_failed_sign_ins_count_and_are_held_back(env):
    tc = env.client(DIRECT)
    for i in range(LIMIT):
        r = tc.post("/api/v1/auth/password/begin", json={"username": f"user{i}", "password": "nope"})
        assert r.status_code == 401
    # Even the right password waits: nothing reaches auth during the cool-down.
    _assert_cooling_down(tc.post("/api/v1/auth/password/begin",
                                 json={"username": "alice", "password": "right-password"}))
    env.clock.now += COOLDOWN + 1
    r = tc.post("/api/v1/auth/password/begin", json={"username": "alice", "password": "right-password"})
    assert r.status_code == 200
    # A successful sign-in does not reset earlier failures either.
    for _ in range(LIMIT - 1):
        tc.post("/api/v1/auth/password/begin", json={"username": "x", "password": "nope"})
    assert tc.post("/api/v1/auth/password/begin",
                   json={"username": "alice", "password": "right-password"}).status_code == 200
    assert tc.post("/api/v1/auth/password/begin",
                   json={"username": "x", "password": "nope"}).status_code == 401
    _assert_cooling_down(tc.post("/api/v1/auth/password/begin",
                                 json={"username": "x", "password": "nope"}))


def test_webhook_rejections_are_not_counted(env):
    tc = env.client(DIRECT)
    for _ in range(100):
        r = tc.post("/api/v1/webhooks/datto", headers={"X-Webhook-Token": _token()})
        assert r.status_code == 401
    assert env.failures.retry_after(DIRECT) == 0


def test_a_route_that_ignores_the_token_cannot_prove_it(env):
    guess = _token()
    tc = env.client(DIRECT)
    assert tc.get("/healthz", headers={"Authorization": f"Bearer {guess}"}).status_code == 200
    assert tc.get("/api/v1/dashboard", headers={"Authorization": f"Bearer {guess}"}).status_code == 200
    _trip(tc)
    _assert_cooling_down(_who(tc, guess))


def test_a_proven_token_that_starts_failing_is_forgotten_and_counted(env):
    token = _token()
    env.valid.add(token)
    tc = env.client(DIRECT)
    assert _who(tc, token).status_code == 200
    env.valid.discard(token)                       # revoked
    assert _who(tc, token).status_code == 401
    _trip(tc, LIMIT - 1)
    _assert_cooling_down(_who(tc, token))


def test_turned_off_with_zero(monkeypatch):
    monkeypatch.setenv("OCTO_AUTH_FAILURE_LIMIT", "0")
    assert rl.AuthFailureLimiter.from_env() is None
    monkeypatch.setenv("OCTO_AUTH_FAILURE_LIMIT", "2")          # clamped: never below 5
    assert rl.AuthFailureLimiter.from_env().limit == 5
    monkeypatch.setenv("OCTO_AUTH_FAILURE_LIMIT", "lots")
    monkeypatch.setenv("OCTO_AUTH_FAILURE_WINDOW_SEC", "1")
    monkeypatch.setenv("OCTO_AUTH_FAILURE_COOLDOWN_SEC", "3600")
    lim = rl.AuthFailureLimiter.from_env()
    assert (lim.limit, lim.window_sec, lim.cooldown_sec) == (30, 60, 3600)
    for name in ("OCTO_AUTH_FAILURE_LIMIT", "OCTO_AUTH_FAILURE_WINDOW_SEC",
                 "OCTO_AUTH_FAILURE_COOLDOWN_SEC"):
        monkeypatch.delenv(name)
    lim = rl.AuthFailureLimiter.from_env()
    assert (lim.limit, lim.window_sec, lim.cooldown_sec) == (30, 600, 900)


def test_memory_is_bounded():
    clock = Clock()
    lim = rl.AuthFailureLimiter(LIMIT, WINDOW, COOLDOWN, max_addresses=100,
                                max_known_tokens=50, clock=clock)
    for i in range(LIMIT):
        lim.record_failure("blocked-address")
    for i in range(1_000):
        lim.record_failure(f"addr-{i}")
        lim.note_success(f"fp-{i}")
    assert len(lim._addresses) <= 100 and len(lim._known) <= 50
    assert lim.retry_after("blocked-address") > 0        # a cool-down survives eviction

    # The throughput limiter drops keys idle for a window (one per guessed
    # token must not grow memory for ever).
    limiter = rl.RateLimiter({"admin_read": 10})
    for i in range(500):
        limiter.check_and_record(f"tok:{i}", "admin_read")
    for q in limiter._hits.values():               # age every hit two minutes
        for j in range(len(q)):
            q[j] -= 120
    limiter._last_sweep -= 120
    limiter.check_and_record("tok:new", "admin_read")
    assert list(limiter._hits) == [("tok:new", "admin_read")]


def test_throughput_keys_have_a_hard_cap_that_evicts_the_oldest_idle_first():
    """A flood of fresh callers within ONE minute (the sweep only drops keys
    idle for a minute) is held to max_keys; the keys dropped are the ones
    whose last counted hit is oldest, and an active caller keeps its count."""
    limiter = rl.RateLimiter({"admin_read": 3}, max_keys=100)
    for _ in range(3):
        assert limiter.check_and_record("ip:busy", "admin_read")[0]
    assert limiter.check_and_record("ip:busy", "admin_read")[0] is False
    for i in range(99):
        limiter.check_and_record(f"tok:{i}", "admin_read")
    # Full: busy is the oldest, and a refused request does not refresh it,
    # but it is still in its window and still refused.
    assert len(limiter._hits) == 100
    assert limiter.check_and_record("ip:busy", "admin_read")[0] is False
    limiter.check_and_record("tok:a", "admin_read")
    assert len(limiter._hits) == 100
    assert ("ip:busy", "admin_read") not in limiter._hits      # oldest idle: evicted
    assert ("tok:0", "admin_read") in limiter._hits
    # A hit moves a key to the back: tok:0 survives the next eviction, tok:1 does not.
    limiter.check_and_record("tok:0", "admin_read")
    limiter.check_and_record("tok:b", "admin_read")
    assert ("tok:0", "admin_read") in limiter._hits
    assert ("tok:1", "admin_read") not in limiter._hits
    for i in range(10_000):
        limiter.check_and_record(f"flood:{i}", "admin_read")
        assert len(limiter._hits) <= 100
    # The newest caller is never the one evicted.
    assert ("flood:9999", "admin_read") in limiter._hits
    with pytest.raises(ValueError):
        rl.RateLimiter(max_keys=0)
    assert rl.RateLimiter().max_keys == rl.RateLimiter.MAX_KEYS_DEFAULT


def test_throughput_cap_and_sweep_stay_linear():
    """Eviction pops from the front (O(1) per key), and the sweep stops at
    the first key still in use: the cost per request does not grow with
    the number of keys held. Measured as CPU time, the same number of
    requests against a 200x larger map must cost about the same; an
    implementation that scans the map per eviction or per sweep would be
    two orders of magnitude slower here."""
    import time as _time

    def run(max_keys: int, n: int = 20_000) -> float:
        limiter = rl.RateLimiter({"admin_read": 10}, max_keys=max_keys)
        for i in range(max_keys):                    # fill to the cap first
            limiter.check_and_record(f"fill:{i}", "admin_read")
        start = _time.process_time()
        for i in range(n):
            limiter._last_sweep -= 61                # force a sweep every request
            limiter.check_and_record(f"new:{i}", "admin_read")
        return _time.process_time() - start

    small, large = run(100), run(20_000)
    # ~0.02 s each here; a per-request scan of the map takes tens of seconds.
    assert large < max(10 * small, 0.5), (small, large)
    assert small < 3.0 and large < 3.0, (small, large)

    # The sweep drops exactly the idle front of the map.
    limiter = rl.RateLimiter({"admin_read": 10})
    for i in range(10):
        limiter.check_and_record(f"old:{i}", "admin_read")
    for q in list(limiter._hits.values()):
        q[-1] -= 120
    limiter.check_and_record("fresh", "admin_read")
    limiter._last_sweep -= 61
    limiter.check_and_record("fresh", "admin_read")
    assert list(limiter._hits) == [("fresh", "admin_read")]


# ---------------------------------------------------------------------------
# The three paths
# ---------------------------------------------------------------------------

def test_path3_spoofed_forwarded_for_from_an_untrusted_peer_is_ignored(env, monkeypatch):
    """With the proxy network configured (the production setting), a direct
    caller rotating X-Forwarded-For is still ONE address to both limiters."""
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", PROXY_NET)
    tc = env.client(DIRECT)
    for i in range(LIMIT):
        assert _who(tc, _token(), **{"X-Forwarded-For": f"203.0.113.{100 + i}"}).status_code == 401
    _assert_cooling_down(_who(tc, _token(), **{"X-Forwarded-For": "203.0.113.200"}))
    _assert_cooling_down(_who(tc, _token()))
    assert env.failures.retry_after(DIRECT) > 0
    # Naming another client's address does not touch that client.
    victim = env.client(CADDY)
    assert _who(victim, _token(), **{"X-Forwarded-For": "203.0.113.100"}).status_code == 401

    # The throughput bucket ignores it too.
    env.use_limiter(rl.RateLimiter({"admin_read": 3}))
    tc2 = env.client(DIRECT_2)
    for i in range(3):
        assert tc2.get("/api/v1/dashboard", headers={"X-Forwarded-For": f"203.0.113.{i}"}).status_code == 200
    r = tc2.get("/api/v1/dashboard", headers={"X-Forwarded-For": "203.0.113.99"})
    assert r.status_code == 429 and r.headers["X-RateLimit-Class"] == "admin_read"


def test_paths1_and_2_behind_a_trusted_proxy_each_client_is_its_own(env, monkeypatch):
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", PROXY_NET)
    via_proxy = env.client(CADDY)                  # path 1: proxy sets the header
    via_console = env.client(CONSOLE)              # path 2: console appends its peer
    _trip(via_proxy, **{"X-Forwarded-For": CLIENT_A})
    _assert_cooling_down(_who(via_proxy, _token(), **{"X-Forwarded-For": CLIENT_A}))
    # The same client through the console: same address, same cool-down,
    # whatever it put in front of the chain.
    _assert_cooling_down(_who(via_console, _token(),
                              **{"X-Forwarded-For": f"203.0.113.77, {CLIENT_A}, {CADDY}"}))
    # Other clients behind the same proxy / console are unaffected.
    assert _who(via_proxy, _token(), **{"X-Forwarded-For": CLIENT_B}).status_code == 401
    assert _who(via_console, _token(), **{"X-Forwarded-For": f"{CLIENT_B}, {CADDY}"}).status_code == 401
    assert env.failures.retry_after(CLIENT_A) > 0
    assert env.failures.retry_after(CLIENT_B) == 0
    assert env.failures.retry_after(CADDY) == 0


def test_default_setting_keeps_todays_buckets_but_never_crosses_peers(env, monkeypatch):
    """OCTO_TRUSTED_PROXIES empty: the client address is the peer. The
    THROUGHPUT limiter splits one peer's buckets by its header (the ingest
    path stays per real client as before) and a header can never reach
    another peer's bucket. The failed-auth limiter is off: the only
    per-client hint is a header any direct caller writes, and without it
    every console user is one address (test_failed_auth_limit_bypasses.py)."""
    monkeypatch.delenv("OCTO_TRUSTED_PROXIES", raising=False)
    proxy, other_peer = env.client(CADDY), env.client(DIRECT)
    _trip(proxy, n=LIMIT * 3, **{"X-Forwarded-For": CLIENT_A})
    assert _who(proxy, _token(), **{"X-Forwarded-For": CLIENT_A}).status_code == 401
    assert env.failures._addresses == {}

    env.use_limiter(rl.RateLimiter({"admin_read": 3}))
    proxy, other_peer = env.client(CADDY), env.client(DIRECT)
    for _ in range(3):
        assert proxy.get("/api/v1/dashboard", headers={"X-Forwarded-For": CLIENT_A}).status_code == 200
    r = proxy.get("/api/v1/dashboard", headers={"X-Forwarded-For": CLIENT_A})
    assert (r.status_code, r.headers["X-RateLimit-Class"]) == (429, "admin_read")
    assert proxy.get("/api/v1/dashboard", headers={"X-Forwarded-For": CLIENT_B}).status_code == 200
    # Another peer naming CLIENT_A is not in CLIENT_A's bucket.
    assert other_peer.get("/api/v1/dashboard", headers={"X-Forwarded-For": CLIENT_A}).status_code == 200


@pytest.mark.parametrize("trusted", ["", PROXY_NET])
@pytest.mark.parametrize("junk", [
    "unknown", "<script>alert(1)</script>", "203.0.113.5:443", "'; DROP TABLE x;--",
    ", , ,", "2001:db8::zz", "x" * 5_000, ", ".join(["garbage"] * 2_000),
])
def test_garbage_forwarded_for_never_becomes_a_key(monkeypatch, trusted, junk):
    if trusted:
        monkeypatch.setenv("OCTO_TRUSTED_PROXIES", trusted)
    else:
        monkeypatch.delenv("OCTO_TRUSTED_PROXIES", raising=False)
    from starlette.requests import Request as SRequest
    for peer in (CADDY, DIRECT):
        scope = {"type": "http", "method": "GET", "path": "/x",
                 "headers": [(b"x-forwarded-for", junk.encode())], "client": (peer, 1)}
        assert rl.limiter_address(SRequest(scope)) == peer


def test_ipv6_clients_are_bucketed_by_64(env, monkeypatch):
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", PROXY_NET)
    tc = env.client(CADDY)
    for i in range(LIMIT):
        assert _who(tc, _token(), **{"X-Forwarded-For": f"2001:db8:1:2::{i + 1:x}"}).status_code == 401
    _assert_cooling_down(_who(tc, _token(), **{"X-Forwarded-For": "2001:db8:1:2:ffff::9"}))
    assert _who(tc, _token(), **{"X-Forwarded-For": "2001:db8:1:3::1"}).status_code == 401


def test_the_cool_down_log_line_names_only_a_parsed_address(env, caplog):
    """The address in the log line is parsed (an IPv6 client by its /64
    bucket); a peer label that is not an address (an ASGI server's own
    proxy-header handling can put header text there) is never printed."""
    forged = "evil\nINFO forged line"
    with caplog.at_level("WARNING", logger=rl.__name__):
        _trip(env.client(DIRECT))
        _trip(env.client(CADDY), **{"X-Forwarded-For": "2001:db8:1:2::5"})
        _trip(env.client(forged))
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("failed-auth limit:")]
    assert [line.split(" from ", 1)[1].split(" within ", 1)[0] for line in lines] == [
        DIRECT, "2001:db8:1:2::/64", "<not an IP address>"]
    assert "evil" not in caplog.text and "forged" not in caplog.text


def test_bare_bearer_is_an_address_key_not_a_500(env):
    tc = env.client(DIRECT)
    r = tc.get("/api/v1/whoami", headers={"Authorization": "Bearer "})
    assert r.status_code == 401
    assert env.failures.retry_after(DIRECT) == 0


# ---------------------------------------------------------------------------
# The real app
# ---------------------------------------------------------------------------

@pytest.fixture
def real_app(auth_data_root, monkeypatch):
    from apps.octo.api import create_app
    from apps.octo.auth import operators

    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", PROXY_NET)
    monkeypatch.setenv("OCTO_AUTH_FAILURE_LIMIT", str(LIMIT))
    rl.reset_limiter()
    app = create_app()
    admin = operators.create_operator(
        username="alice", email="alice@example.test", role="admin",
        scope_slugs=["*"], actor="system", reason="failed-auth limiter test",
    )
    return app, admin["plaintext"]


def test_real_app_token_guesses_then_429_and_a_proven_token_still_works(real_app):
    app, admin_token = real_app
    tc = TestClient(app, client=(DIRECT, 40_000))
    other = TestClient(app, client=(DIRECT_2, 40_000))
    assert _who(tc, admin_token).status_code == 200
    for _ in range(LIMIT):
        r = _who(tc, _token())
        assert (r.status_code, r.json()["code"]) == (401, "AUTH_INVALID")
    _assert_cooling_down(_who(tc, _token()))
    assert _who(tc, admin_token).status_code == 200
    _assert_cooling_down(tc.post("/api/v1/auth/password/begin",
                                 json={"username": "alice", "password": "whatever"}))
    assert _who(other, _token()).status_code == 401
    assert app.state.auth_failure_limiter.retry_after(DIRECT) > 0


def test_real_app_failed_sign_ins_then_429(real_app):
    app, _ = real_app
    tc = TestClient(app, client=(DIRECT, 40_000))
    for i in range(LIMIT):
        r = tc.post("/api/v1/auth/password/begin",
                    json={"username": f"nobody{i}", "password": "wrong-password"})
        assert (r.status_code, r.json()["code"]) == (401, "AUTH_PASSWORD_INVALID")
    _assert_cooling_down(tc.post("/api/v1/auth/password/begin",
                                 json={"username": "nobody", "password": "wrong-password"}))
    assert tc.get("/healthz").status_code == 200
