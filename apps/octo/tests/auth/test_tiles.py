"""Tests for the /api/v1/tiles/{filename} endpoint (slice-9 basemap)."""
from __future__ import annotations

import pyotp

from apps.octo import paths


# ---------------------------------------------------------------------------
# Helpers — login + tile fixture
# ---------------------------------------------------------------------------

def _login(client, op: dict) -> None:
    r = client.post("/api/v1/auth/password/begin", json={
        "username": op["username"], "password": op["password"],
    })
    assert r.status_code == 200, r.text
    challenge = r.json()["challenge_id"]
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r2 = client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": code,
    })
    assert r2.status_code == 200, r2.text


def _write_fixture_tile(name: str = "test.pmtiles", n: int = 4096) -> bytes:
    """Drop a deterministic byte sequence into the tiles dir + return it."""
    tiles_dir = paths.tiles_dir()
    tiles_dir.mkdir(parents=True, exist_ok=True)
    payload = bytes((i * 17 + 3) & 0xFF for i in range(n))
    (tiles_dir / name).write_bytes(payload)
    return payload


def _provision_viewer(auth_client) -> dict:
    return auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="viewer", athena_role="viewer", scope_slugs=["*"],
    )


# ---------------------------------------------------------------------------
# Filename validation
# ---------------------------------------------------------------------------

def test_tiles_rejects_unauthenticated(auth_client):
    r = auth_client.get("/api/v1/tiles/test.pmtiles")
    assert r.status_code in (401, 403)


def test_tiles_rejects_non_pmtiles_extension(auth_client):
    op = _provision_viewer(auth_client)
    _login(auth_client, op)
    r = auth_client.get("/api/v1/tiles/sneaky.txt")
    assert r.status_code == 422
    assert r.json()["code"] == "VALIDATION_FAILED"


def test_tiles_rejects_path_traversal(auth_client):
    op = _provision_viewer(auth_client)
    _login(auth_client, op)
    # FastAPI's path-param matching rejects encoded slashes by default,
    # but we want the explicit regex to catch dot-segments too.
    r = auth_client.get("/api/v1/tiles/..foo.pmtiles")
    # `..foo.pmtiles` starts with `.` which our regex refuses.
    assert r.status_code == 422


def test_tiles_rejects_uppercase_filename(auth_client):
    op = _provision_viewer(auth_client)
    _login(auth_client, op)
    r = auth_client.get("/api/v1/tiles/REGION.pmtiles")
    assert r.status_code == 422


def test_tiles_missing_file_returns_404(auth_client):
    op = _provision_viewer(auth_client)
    _login(auth_client, op)
    r = auth_client.get("/api/v1/tiles/does-not-exist.pmtiles")
    assert r.status_code == 404
    assert r.json()["code"] == "NOT_FOUND"


# ---------------------------------------------------------------------------
# Full-file serve (no Range header)
# ---------------------------------------------------------------------------

def test_tiles_full_file_serve(auth_client):
    op = _provision_viewer(auth_client)
    _login(auth_client, op)
    payload = _write_fixture_tile("us.pmtiles", n=8192)
    r = auth_client.get("/api/v1/tiles/us.pmtiles")
    assert r.status_code == 200
    assert r.headers["accept-ranges"] == "bytes"
    assert r.content == payload


def test_tiles_full_file_cache_control(auth_client):
    op = _provision_viewer(auth_client)
    _login(auth_client, op)
    _write_fixture_tile("us.pmtiles", n=1024)
    r = auth_client.get("/api/v1/tiles/us.pmtiles")
    assert "immutable" in r.headers["cache-control"]


# ---------------------------------------------------------------------------
# Range requests — the load-bearing case for PMTiles clients
# ---------------------------------------------------------------------------

def test_tiles_range_request_returns_206(auth_client):
    op = _provision_viewer(auth_client)
    _login(auth_client, op)
    payload = _write_fixture_tile("us.pmtiles", n=8192)
    r = auth_client.get(
        "/api/v1/tiles/us.pmtiles",
        headers={"Range": "bytes=100-199"},
    )
    assert r.status_code == 206
    assert r.content == payload[100:200]
    assert r.headers["content-range"] == "bytes 100-199/8192"
    assert r.headers["content-length"] == "100"


def test_tiles_range_header_first_16k_pmtiles_header(auth_client):
    """PMTiles clients first read ~16 KB of header — must serve that range."""
    op = _provision_viewer(auth_client)
    _login(auth_client, op)
    payload = _write_fixture_tile("us.pmtiles", n=128 * 1024)
    r = auth_client.get(
        "/api/v1/tiles/us.pmtiles",
        headers={"Range": "bytes=0-16383"},
    )
    assert r.status_code == 206
    assert r.content == payload[:16384]
    assert r.headers["content-range"] == "bytes 0-16383/131072"


def test_tiles_range_open_ended_end(auth_client):
    """Range: bytes=N- → from N to end of file."""
    op = _provision_viewer(auth_client)
    _login(auth_client, op)
    payload = _write_fixture_tile("us.pmtiles", n=4096)
    r = auth_client.get(
        "/api/v1/tiles/us.pmtiles",
        headers={"Range": "bytes=4000-"},
    )
    assert r.status_code == 206
    assert r.content == payload[4000:]
    assert r.headers["content-range"] == "bytes 4000-4095/4096"


def test_tiles_range_suffix(auth_client):
    """Range: bytes=-N → last N bytes."""
    op = _provision_viewer(auth_client)
    _login(auth_client, op)
    payload = _write_fixture_tile("us.pmtiles", n=4096)
    r = auth_client.get(
        "/api/v1/tiles/us.pmtiles",
        headers={"Range": "bytes=-100"},
    )
    assert r.status_code == 206
    assert r.content == payload[-100:]


def test_tiles_malformed_range_falls_back_to_full_file(auth_client):
    """Malformed Range header → serve full file at 200 (nginx-style)."""
    op = _provision_viewer(auth_client)
    _login(auth_client, op)
    payload = _write_fixture_tile("us.pmtiles", n=2048)
    for bad in ["junk", "bytes=", "bytes=abc-def", "items=0-100", "bytes=999999-1000"]:
        r = auth_client.get("/api/v1/tiles/us.pmtiles", headers={"Range": bad})
        assert r.status_code == 200, f"bad range {bad!r} should fall back, got {r.status_code}"
        assert r.content == payload


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------

def test_validate_filename_helper():
    from apps.octo.api.routers.tiles import _validate_filename
    from apps.octo.api.errors import APIError
    import pytest as _pytest
    assert _validate_filename("us.pmtiles") == "us.pmtiles"
    assert _validate_filename("us-2026-05.pmtiles") == "us-2026-05.pmtiles"
    assert _validate_filename("region_a.pmtiles") == "region_a.pmtiles"
    for bad in ["UPPER.pmtiles", ".hidden.pmtiles", "foo.txt", "foo", "../foo.pmtiles",
                "foo/bar.pmtiles", "foo.pmtiles ", " foo.pmtiles"]:
        with _pytest.raises(APIError):
            _validate_filename(bad)


def test_parse_range_helper():
    from apps.octo.api.routers.tiles import _parse_range
    # Normal ranges
    assert _parse_range("bytes=0-99", 1000) == (0, 99)
    assert _parse_range("bytes=500-999", 1000) == (500, 999)
    # Open-ended end
    assert _parse_range("bytes=500-", 1000) == (500, 999)
    # Suffix
    assert _parse_range("bytes=-100", 1000) == (900, 999)
    # Malformed
    assert _parse_range("junk", 1000) is None
    assert _parse_range("bytes=abc-def", 1000) is None
    assert _parse_range("bytes=", 1000) is None
    # Start out of range
    assert _parse_range("bytes=10000-20000", 1000) is None
    # Reversed
    assert _parse_range("bytes=900-500", 1000) is None
    # End past total clamps
    s, e = _parse_range("bytes=900-99999", 1000) or (None, None)
    assert s == 900 and e == 999
