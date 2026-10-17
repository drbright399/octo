"""Tests for /api/v1/admin/llm/models (Slice 5c scaffold).

super_admin-only listing + active-model setter. Read-only path
today; download/restart land in slice 5d.
"""
from __future__ import annotations

from pathlib import Path

import pyotp


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


def _elevate(client, op: dict) -> None:
    """Grant step-up auth — required for model write operations."""
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r = client.post("/api/v1/search/elevate", json={
        "current_password": op["password"], "totp_code": code,
    })
    assert r.status_code == 200, r.text


def _stage_models_dir(tmp_path: Path, *names: str) -> Path:
    """Drop empty .gguf files in a synthetic models dir."""
    d = tmp_path / "octo-llm-models"
    d.mkdir(parents=True, exist_ok=True)
    for name in names:
        (d / f"{name}.gguf").write_bytes(b"\x00")
    # Also drop a non-gguf file that should be ignored.
    (d / "README.txt").write_text("readme")
    return d


def test_unauthenticated_rejected(auth_client):
    r = auth_client.get("/api/v1/admin/llm/models")
    assert r.status_code in (401, 403)


def test_analyst_role_forbidden(auth_client, tmp_path, monkeypatch):
    op = auth_client.provision_operator(
        "analyst-alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst",
    )
    _login(auth_client, op)
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(tmp_path))
    r = auth_client.get("/api/v1/admin/llm/models")
    # session_at_least("super_admin") raises ISOLATION_VIOLATION (403)
    assert r.status_code == 403


def test_admin_role_forbidden(auth_client, tmp_path, monkeypatch):
    op = auth_client.provision_operator(
        "admin-alice", "Hunter22!Hunter22!",
        role="admin", athena_role="admin",
    )
    _login(auth_client, op)
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(tmp_path))
    r = auth_client.get("/api/v1/admin/llm/models")
    # admin is below super_admin; same gate.
    assert r.status_code == 403


def test_super_admin_can_list(auth_client, tmp_path, monkeypatch):
    op = auth_client.provision_operator(
        "su-alice", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
    )
    _login(auth_client, op)

    d = _stage_models_dir(
        tmp_path, "granite-3b-q4", "llama-3-8b-q5", "mistral-7b-q4",
    )
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(d))

    r = auth_client.get("/api/v1/admin/llm/models")
    assert r.status_code == 200, r.text
    body = r.json()
    names = sorted(m["name"] for m in body["models"])
    assert names == ["granite-3b-q4", "llama-3-8b-q5", "mistral-7b-q4"]
    # The default-active model marker.
    assert body["active"] == "granite-3b-q4"
    granite = next(m for m in body["models"] if m["name"] == "granite-3b-q4")
    assert granite["is_active"] is True
    # Non-active models have is_active=false.
    other = next(m for m in body["models"] if m["name"] != "granite-3b-q4")
    assert other["is_active"] is False


def test_list_empty_dir(auth_client, tmp_path, monkeypatch):
    op = auth_client.provision_operator(
        "su-alice", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
    )
    _login(auth_client, op)
    empty = tmp_path / "no-models"
    empty.mkdir()
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(empty))
    r = auth_client.get("/api/v1/admin/llm/models")
    assert r.status_code == 200
    assert r.json()["models"] == []


def test_list_skips_non_gguf_files(auth_client, tmp_path, monkeypatch):
    op = auth_client.provision_operator(
        "su-alice", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
    )
    _login(auth_client, op)
    d = tmp_path / "mixed"
    d.mkdir()
    (d / "real-model.gguf").write_bytes(b"\x00")
    (d / "readme.md").write_text("nope")
    (d / "stray.bin").write_bytes(b"\x00")
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(d))

    r = auth_client.get("/api/v1/admin/llm/models")
    assert r.status_code == 200
    names = [m["name"] for m in r.json()["models"]]
    assert names == ["real-model"]


def test_set_active_to_installed_model(auth_client, tmp_path, monkeypatch):
    op = auth_client.provision_operator(
        "factory-root", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
        is_factory=True,
    )
    _login(auth_client, op)
    _elevate(auth_client, op)
    d = _stage_models_dir(tmp_path, "granite-3b-q4", "llama-3-8b-q5")
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(d))

    r = auth_client.put(
        "/api/v1/admin/llm/models/active",
        json={"name": "llama-3-8b-q5"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["active"] == "llama-3-8b-q5"
    assert r.json()["restart_required"] is True

    # Reload list — active flag follows.
    r2 = auth_client.get("/api/v1/admin/llm/models")
    assert r2.json()["active"] == "llama-3-8b-q5"
    active = next(m for m in r2.json()["models"] if m["is_active"])
    assert active["name"] == "llama-3-8b-q5"


def test_set_active_to_missing_model_rejected(
    auth_client, tmp_path, monkeypatch,
):
    """Bad config caught at write time, not at restart time."""
    op = auth_client.provision_operator(
        "factory-root", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
        is_factory=True,
    )
    _login(auth_client, op)
    _elevate(auth_client, op)
    d = _stage_models_dir(tmp_path, "granite-3b-q4")
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(d))

    r = auth_client.put(
        "/api/v1/admin/llm/models/active",
        json={"name": "ghost-model"},
    )
    assert r.status_code == 404, r.text


def test_set_active_without_step_up_rejected(
    auth_client, tmp_path, monkeypatch,
):
    """Slice 5d-3: factory super_admin must hold an active step-up
    window to change the model. Without elevation → STEP_UP_REQUIRED."""
    op = auth_client.provision_operator(
        "factory-root", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
        is_factory=True,
    )
    _login(auth_client, op)
    # NO _elevate call — caller is logged in but not step-up-elevated.
    d = _stage_models_dir(tmp_path, "granite-3b-q4", "llama-3-8b-q5")
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(d))

    r = auth_client.put(
        "/api/v1/admin/llm/models/active",
        json={"name": "llama-3-8b-q5"},
    )
    # STEP_UP_REQUIRED → 401.
    assert r.status_code == 401, r.text


def test_manifest_visible_to_super_admin(auth_client, tmp_path, monkeypatch):
    op = auth_client.provision_operator(
        "su-alice", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
    )
    _login(auth_client, op)
    # Stage a model file matching one of the manifest entries so we
    # can assert installed=True. Use Qwen because it's the default.
    d = _stage_models_dir(tmp_path, "qwen-2.5-3b-q4")
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(d))

    r = auth_client.get("/api/v1/admin/llm/models/manifest")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["manifest_version"] == 1
    names = [m["name"] for m in body["models"]]
    # Slice 7i — three-tier factory selection (dev / balanced / max).
    assert "tinyllama-1.1b-chat" in names
    assert "qwen-2.5-3b-q4" in names
    assert "granite-3.1-8b-q4" in names

    qwen = next(m for m in body["models"] if m["name"] == "qwen-2.5-3b-q4")
    assert qwen["installed"] is True  # we staged it above
    assert qwen["default"] is True    # default tier in the manifest
    assert qwen["tier"] == "balanced"

    granite = next(m for m in body["models"] if m["name"] == "granite-3.1-8b-q4")
    assert granite["installed"] is False
    assert granite["tier"] == "max"

    tiny = next(m for m in body["models"] if m["name"] == "tinyllama-1.1b-chat")
    assert tiny["tier"] == "dev"


def test_manifest_analyst_forbidden(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/admin/llm/models/manifest")
    assert r.status_code == 403


def test_set_active_analyst_forbidden(auth_client, tmp_path, monkeypatch):
    op = auth_client.provision_operator(
        "analyst-alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst",
    )
    _login(auth_client, op)
    d = _stage_models_dir(tmp_path, "granite-3b-q4")
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(d))

    r = auth_client.put(
        "/api/v1/admin/llm/models/active",
        json={"name": "granite-3b-q4"},
    )
    assert r.status_code == 403


def test_set_active_non_factory_super_admin_forbidden(
    auth_client, tmp_path, monkeypatch,
):
    """Slice 5d-1: a normal super_admin (not the factory one) must NOT
    be able to swap the bundle's LLM model. Read is allowed; write is
    factory-only."""
    op = auth_client.provision_operator(
        "regular-su", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
        is_factory=False,
    )
    _login(auth_client, op)
    _elevate(auth_client, op)  # step-up granted, but caller isn't factory
    d = _stage_models_dir(tmp_path, "granite-3b-q4", "llama-3-8b-q5")
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(d))

    # Read still works (regular super_admin sees the list).
    r_list = auth_client.get("/api/v1/admin/llm/models")
    assert r_list.status_code == 200

    # Write is denied — factory gate rejects even with step-up.
    r = auth_client.put(
        "/api/v1/admin/llm/models/active",
        json={"name": "llama-3-8b-q5"},
    )
    assert r.status_code == 403, r.text
    assert "factory" in r.json().get("message", "").lower()


# ===========================================================================
# Slice 9g — OOM precheck on model swap (consensus reviewer S2)
# ===========================================================================

def test_oom_precheck_rejects_when_insufficient_memory(
    auth_client, tmp_path, monkeypatch,
):
    """If the target model's size_bytes_approx × 1.5 + 256MB
    exceeds psutil.virtual_memory().available, set_active rejects
    with 412 PRECONDITION_FAILED. Granite-3.1-8b-q4 in the live
    manifest is 4.5GB, so we mock psutil to return 2GB available
    and expect the rejection."""
    op = auth_client.provision_operator(
        "factory-root", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
        is_factory=True,
    )
    _login(auth_client, op)
    _elevate(auth_client, op)
    # Stage a model file matching the live manifest entry so the
    # precheck reads a real size_bytes_approx.
    d = _stage_models_dir(tmp_path, "granite-3.1-8b-q4")
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(d))

    # Mock psutil.virtual_memory().available — note we replace the
    # CALLABLE, not just the attribute, because the precheck reads
    # `psutil.virtual_memory().available` as an instance attribute.
    class _MockVMem:
        available = 2 * 1024 * 1024 * 1024  # 2GB

    import psutil
    monkeypatch.setattr(psutil, "virtual_memory", lambda: _MockVMem())

    r = auth_client.put(
        "/api/v1/admin/llm/models/active",
        json={"name": "granite-3.1-8b-q4"},
    )
    assert r.status_code == 412, r.text
    msg = r.json().get("message", "")
    assert "insufficient memory" in msg.lower()


def test_oom_precheck_allows_with_sufficient_memory(
    auth_client, tmp_path, monkeypatch,
):
    """When available memory comfortably exceeds the requirement,
    the swap proceeds normally."""
    op = auth_client.provision_operator(
        "factory-root", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
        is_factory=True,
    )
    _login(auth_client, op)
    _elevate(auth_client, op)
    d = _stage_models_dir(tmp_path, "granite-3.1-8b-q4")
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(d))

    class _MockVMem:
        available = 32 * 1024 * 1024 * 1024  # 32GB

    import psutil
    monkeypatch.setattr(psutil, "virtual_memory", lambda: _MockVMem())

    r = auth_client.put(
        "/api/v1/admin/llm/models/active",
        json={"name": "granite-3.1-8b-q4"},
    )
    assert r.status_code == 200, r.text


def test_oom_precheck_skipped_for_byom_model(
    auth_client, tmp_path, monkeypatch,
):
    """BYOM model (not in manifest) has no size_bytes_approx to
    compare against. Precheck skips, swap proceeds, an audit row
    documents the bypass."""
    op = auth_client.provision_operator(
        "factory-root", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
        is_factory=True,
    )
    _login(auth_client, op)
    _elevate(auth_client, op)
    d = _stage_models_dir(tmp_path, "my-custom-byom-model")
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(d))

    # Even with 0 bytes available, BYOM model should swap (with
    # audit logging the bypass).
    class _MockVMem:
        available = 0
    import psutil
    monkeypatch.setattr(psutil, "virtual_memory", lambda: _MockVMem())

    r = auth_client.put(
        "/api/v1/admin/llm/models/active",
        json={"name": "my-custom-byom-model"},
    )
    assert r.status_code == 200, r.text

    # Confirm an audit row documents the bypass.
    from apps.octo import paths
    from apps.octo.db import connect
    g = connect(paths.global_audit_db_path(), read_only=True)
    try:
        row = g.execute(
            "SELECT after_state FROM audit_log "
            "WHERE action = 'octo_llm_swap_oom_precheck_skipped' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        g.close()
    assert row is not None
    assert "byom_no_manifest_size" in (row[0] or "")
