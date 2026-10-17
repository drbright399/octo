"""Tests for the OCTO core entrypoint — config parsing + create_app() factory."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from shared_bridge import SessionContext, TemplateRegistry

from apps.octo.main import (
    BOOTSTRAP_TOKEN_MIN_LENGTH,
    BootstrapTokenConfigError,
    OctoConfig,
    _parse_bootstrap_tokens,
    create_app,
)


def _token(label: str) -> str:
    """A visibly fake bootstrap token, built at runtime, above the minimum."""
    return f"test-bootstrap-token-{label}-" + "x" * 16


def _token_of_length(n: int) -> str:
    """A visibly fake bootstrap token of exactly `n` characters."""
    token = ("test-bootstrap-token-" + "x" * BOOTSTRAP_TOKEN_MIN_LENGTH)[:n]
    assert len(token) == n
    return token


# ---------------------------------------------------------------------------
# Config — env parsing
# ---------------------------------------------------------------------------

def test_octo_config_defaults_match_production_paths() -> None:
    cfg = OctoConfig()
    assert cfg.registry_db_path == "/var/lib/octo/state/registry.db"
    assert cfg.audit_db_path == "/var/lib/octo/state/bridge_audit.db"
    assert cfg.adapters_package == "apps.octo.adapters"
    assert cfg.system_widgets_package == "apps.athena.widgets.system"
    assert cfg.fail_on_discovery_failure is False


def test_octo_config_from_env_reads_overrides(tmp_path: Path) -> None:
    env = {
        "OCTO_REGISTRY_DB_PATH": str(tmp_path / "r.db"),
        "OCTO_AUDIT_DB_PATH": str(tmp_path / "a.db"),
        "OCTO_ADAPTERS_PACKAGE": "tests.fakes.adapters",
        "OCTO_SYSTEM_WIDGETS_PACKAGE": "tests.fakes.widgets",
        "OCTO_FAIL_ON_DISCOVERY_FAILURE": "1",
    }
    cfg = OctoConfig.from_env(env)
    assert cfg.registry_db_path == str(tmp_path / "r.db")
    assert cfg.audit_db_path == str(tmp_path / "a.db")
    assert cfg.adapters_package == "tests.fakes.adapters"
    assert cfg.system_widgets_package == "tests.fakes.widgets"
    assert cfg.fail_on_discovery_failure is True


def test_octo_config_fail_on_discovery_parses_truthy_strings() -> None:
    for truthy in ("1", "true", "TRUE", "yes", "ON"):
        cfg = OctoConfig.from_env({"OCTO_FAIL_ON_DISCOVERY_FAILURE": truthy})
        assert cfg.fail_on_discovery_failure is True
    for falsy in ("0", "false", "no", "off", ""):
        cfg = OctoConfig.from_env({"OCTO_FAIL_ON_DISCOVERY_FAILURE": falsy})
        assert cfg.fail_on_discovery_failure is False


# ---------------------------------------------------------------------------
# Bootstrap token parsing
# ---------------------------------------------------------------------------

def test_parse_bootstrap_tokens_empty() -> None:
    assert _parse_bootstrap_tokens("") == {}
    assert _parse_bootstrap_tokens("   ") == {}


def test_parse_bootstrap_tokens_single() -> None:
    tok1 = _token("one")
    tokens = _parse_bootstrap_tokens(f"{tok1}=10:viewer:client_a:sess1")
    assert tok1 in tokens
    s = tokens[tok1]
    assert s.operator_id == 10
    assert s.operator_role == "viewer"
    assert s.session_tenant == "client_a"
    assert s.session_id == "sess1"


def test_parse_bootstrap_tokens_multiple() -> None:
    tok1, tok2 = _token("one"), _token("two")
    raw = f"{tok1}=10:viewer:client_a:sess1,{tok2}=12:admin:client_b:sess2"
    tokens = _parse_bootstrap_tokens(raw)
    assert set(tokens.keys()) == {tok1, tok2}
    assert tokens[tok2].operator_role == "admin"
    assert tokens[tok2].session_tenant == "client_b"


def test_parse_bootstrap_tokens_skips_empty_entries() -> None:
    """A trailing or doubled comma is an empty entry: no token, nothing to refuse."""
    tok1, tok2 = _token("one"), _token("two")
    raw = f"{tok1}=10:viewer:client_a:sess1,, {tok2}=12:admin:client_b:sess2,"
    assert set(_parse_bootstrap_tokens(raw).keys()) == {tok1, tok2}


# ---------------------------------------------------------------------------
# Malformed entries — fail closed and loud (nothing is skipped silently),
# name the 1-based position and the rule, never echo any part of the entry
# ---------------------------------------------------------------------------

_GOOD_ENTRY_1 = "=10:viewer:client_a:sess1"


def _assert_malformed(raw: str, position: int, rule: str, *must_not_leak: str) -> None:
    with pytest.raises(BootstrapTokenConfigError) as exc_info:
        _parse_bootstrap_tokens(raw)
    msg = str(exc_info.value)
    assert f"entry {position}:" in msg
    assert rule in msg
    for value in must_not_leak:
        _assert_token_not_leaked(exc_info.value, value)


def test_parse_bootstrap_tokens_rejects_entry_without_equals() -> None:
    # The whole entry may well BE a token pasted without its session part.
    lone = _token("lone")
    _assert_malformed(f"{_token('good')}{_GOOD_ENTRY_1},{lone}", 2, "no '='", lone)


@pytest.mark.parametrize(
    "payload, found",
    [("10:viewer", 2), ("10:viewer:client_a", 3), ("10:viewer:client_a:sess1:extra", 5), ("", 1)],
)
def test_parse_bootstrap_tokens_rejects_wrong_field_count(payload: str, found: int) -> None:
    tok = _token("fields")
    _assert_malformed(f"{tok}={payload}", 1, f"found {found}", tok)


def test_parse_bootstrap_tokens_wrong_field_count_does_not_echo_payload() -> None:
    """Token and session fields swapped: the 'payload' is the token itself."""
    tok = _token("swapped")
    _assert_malformed(f"{_token('session-part')}={tok}", 1, "found 1", tok)


@pytest.mark.parametrize(
    "op_id", ["NOT_AN_INT", "", " 7", "+7", "-1", "0", "1_0", "1.0", "\u0663", "9" * 19],
)
def test_parse_bootstrap_tokens_rejects_bad_operator_id(op_id: str) -> None:
    tok = _token("opid")
    _assert_malformed(
        f"{tok}={op_id}:viewer:client_a:sess1", 1, "operator_id must be a positive", tok,
    )


def test_parse_bootstrap_tokens_accepts_large_operator_id() -> None:
    tok = _token("big")
    tokens = _parse_bootstrap_tokens(f"{tok}={'9' * 18}:viewer:client_a:sess1")
    assert tokens[tok].operator_id == int("9" * 18)


@pytest.mark.parametrize(
    "role", ["role-value-not-echoed", "", "Admin", "super-admin", " viewer"],
)
def test_parse_bootstrap_tokens_rejects_unknown_role(role: str) -> None:
    tok = _token("role")
    _assert_malformed(f"{tok}=10:{role}:client_a:sess1", 1, "unknown role", tok)
    if role == "role-value-not-echoed":
        _assert_malformed(f"{tok}=10:{role}:client_a:sess1", 1, "unknown role", role)


@pytest.mark.parametrize(
    "tenant, session_id, field_name",
    [
        ("", "sess1", "tenant"),
        ("client a", "sess1", "tenant"),
        ("client_a", "", "session_id"),
        ("client_a", "sess\t1", "session_id"),
    ],
)
def test_parse_bootstrap_tokens_rejects_empty_or_spaced_tenant_or_session(
    tenant: str, session_id: str, field_name: str,
) -> None:
    tok = _token("fields")
    _assert_malformed(
        f"{tok}=10:viewer:{tenant}:{session_id}", 1, f"{field_name} must be non-empty", tok,
    )


def test_parse_bootstrap_tokens_rejects_duplicate_token() -> None:
    tok = _token("dup")
    raw = f"{tok}=10:viewer:client_a:sess1,{tok}=1:super_admin:msp_root:sess2"
    _assert_malformed(raw, 2, "repeats the one in entry 1", tok)


def test_parse_bootstrap_tokens_malformed_entry_refuses_the_whole_value() -> None:
    """One bad entry stops everything: the valid ones are not half-loaded."""
    good = _token("good")
    with pytest.raises(BootstrapTokenConfigError):
        _parse_bootstrap_tokens(f"{good}{_GOOD_ENTRY_1},{_token('bad')}=10:viewer")


# ---------------------------------------------------------------------------
# Bootstrap token strength — fail closed and loud, never echo the token
# ---------------------------------------------------------------------------

def _assert_token_not_leaked(exc: BaseException, token: str) -> None:
    assert token not in str(exc)
    assert token not in repr(exc)
    assert exc.__cause__ is None
    assert exc.__context__ is None


def test_bootstrap_token_min_length_is_32() -> None:
    assert BOOTSTRAP_TOKEN_MIN_LENGTH == 32


def test_bootstrap_token_config_error_is_a_value_error() -> None:
    assert issubclass(BootstrapTokenConfigError, ValueError)


def test_parse_bootstrap_tokens_rejects_31_char_token() -> None:
    short = _token_of_length(31)
    with pytest.raises(BootstrapTokenConfigError) as exc_info:
        _parse_bootstrap_tokens(f"{short}=10:viewer:client_a:sess1")
    msg = str(exc_info.value)
    assert "entry 1" in msg
    assert "32" in msg
    _assert_token_not_leaked(exc_info.value, short)


def test_parse_bootstrap_tokens_accepts_32_char_token() -> None:
    exact = _token_of_length(32)
    tokens = _parse_bootstrap_tokens(f"{exact}=10:viewer:client_a:sess1")
    assert set(tokens.keys()) == {exact}
    assert tokens[exact].operator_id == 10


def test_parse_bootstrap_tokens_short_token_names_its_position() -> None:
    short = _token_of_length(8)
    raw = f"{_token('first')}=10:viewer:client_a:sess1,{short}=11:admin:client_b:sess2"
    with pytest.raises(BootstrapTokenConfigError) as exc_info:
        _parse_bootstrap_tokens(raw)
    assert "entry 2" in str(exc_info.value)
    _assert_token_not_leaked(exc_info.value, short)


def test_parse_bootstrap_tokens_rejects_empty_token() -> None:
    with pytest.raises(BootstrapTokenConfigError) as exc_info:
        _parse_bootstrap_tokens("=10:viewer:client_a:sess1")
    assert "entry 1" in str(exc_info.value)


def test_parse_bootstrap_tokens_rejects_short_token_even_with_bad_payload() -> None:
    """A weak token is a config error even when its payload is malformed."""
    short = _token_of_length(8)
    with pytest.raises(BootstrapTokenConfigError) as exc_info:
        _parse_bootstrap_tokens(f"{short}=10:viewer")
    _assert_token_not_leaked(exc_info.value, short)


@pytest.mark.parametrize("ws", [" ", "\t", "\n"])
def test_parse_bootstrap_tokens_rejects_whitespace_inside_token(ws: str) -> None:
    spaced = _token("left") + ws + _token("right")
    with pytest.raises(BootstrapTokenConfigError) as exc_info:
        _parse_bootstrap_tokens(f"{spaced}=10:viewer:client_a:sess1")
    msg = str(exc_info.value)
    assert "entry 1" in msg
    assert "whitespace" in msg
    _assert_token_not_leaked(exc_info.value, spaced)
    _assert_token_not_leaked(exc_info.value, _token("left"))


def test_parse_bootstrap_tokens_rejects_whitespace_before_equals() -> None:
    tok = _token("trailing")
    with pytest.raises(BootstrapTokenConfigError) as exc_info:
        _parse_bootstrap_tokens(f"{tok} =10:viewer:client_a:sess1")
    assert "whitespace" in str(exc_info.value)
    _assert_token_not_leaked(exc_info.value, tok)


def test_parse_bootstrap_tokens_allows_whitespace_around_entries() -> None:
    """Whitespace around a whole entry (e.g. after a comma) is not part of the token."""
    tok1, tok2 = _token("one"), _token("two")
    raw = f"  {tok1}=10:viewer:client_a:sess1 ,\n {tok2}=12:admin:client_b:sess2  "
    assert set(_parse_bootstrap_tokens(raw).keys()) == {tok1, tok2}


def test_create_app_rejects_short_bootstrap_token_before_touching_state(
    tmp_path: Path,
) -> None:
    short = _token_of_length(31)
    state = tmp_path / "octo-state"
    cfg = OctoConfig.from_env({
        "OCTO_REGISTRY_DB_PATH": str(state / "registry.db"),
        "OCTO_AUDIT_DB_PATH": str(state / "bridge_audit.db"),
        "OCTO_STATE_DIR": str(state),
        "OCTO_BOOTSTRAP_TOKENS": f"{short}=1:super_admin:msp_root:sess1",
    })
    with pytest.raises(BootstrapTokenConfigError) as exc_info:
        create_app(cfg)
    _assert_token_not_leaked(exc_info.value, short)
    assert not state.exists()


def test_create_app_with_unset_bootstrap_tokens_has_no_static_sessions() -> None:
    cfg = OctoConfig.from_env({
        "OCTO_REGISTRY_DB_PATH": ":memory:",
        "OCTO_AUDIT_DB_PATH": ":memory:",
    })
    assert cfg.bootstrap_tokens_raw == ""
    app = create_app(cfg)
    client = TestClient(app)
    resp = client.post(
        "/bridge/v1/execute",
        json={"template_id": "ping", "params": {}},
        headers={"Authorization": "Bearer " + _token("unknown")},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# create_app() — basic structure
# ---------------------------------------------------------------------------

def test_create_app_with_in_memory_config_returns_fastapi(tmp_path: Path) -> None:
    cfg = OctoConfig(
        registry_db_path=":memory:",
        audit_db_path=":memory:",
        adapters_package="apps.octo.adapters",
        system_widgets_package="apps.athena.widgets.system",
    )
    app = create_app(cfg)
    # Routes installed
    paths = [r.path for r in app.routes if hasattr(r, "path")]
    assert "/healthz" in paths
    assert "/bridge/v1/health" in paths
    assert "/bridge/v1/execute" in paths
    assert "/bridge/v1/audit" in paths


def test_create_app_creates_sqlite_dbs_at_configured_paths(tmp_path: Path) -> None:
    registry_db = tmp_path / "state" / "registry.db"
    audit_db = tmp_path / "state" / "bridge_audit.db"
    cfg = OctoConfig(
        registry_db_path=str(registry_db),
        audit_db_path=str(audit_db),
        adapters_package="apps.octo.adapters",
        system_widgets_package="apps.athena.widgets.system",
    )
    create_app(cfg)
    # Parent dirs should be created automatically
    assert registry_db.parent.exists()
    assert audit_db.parent.exists()


def test_create_app_state_exposes_boot_artifacts() -> None:
    cfg = OctoConfig(registry_db_path=":memory:", audit_db_path=":memory:")
    app = create_app(cfg)
    assert app.state.octo_config is cfg
    assert app.state.booted_framework is not None
    assert app.state.bridge_server is not None
    assert app.state.audit_backend is not None
    assert app.state.registry_backend is not None


def test_create_app_state_dir_is_created_if_specified(tmp_path: Path) -> None:
    state = tmp_path / "octo-state"
    cfg = OctoConfig(
        registry_db_path=":memory:",
        audit_db_path=":memory:",
        state_dir=str(state),
    )
    create_app(cfg)
    assert state.exists()


# ---------------------------------------------------------------------------
# create_app() — endpoints exercised end-to-end
# ---------------------------------------------------------------------------

def test_healthz_returns_ok() -> None:
    cfg = OctoConfig(registry_db_path=":memory:", audit_db_path=":memory:")
    app = create_app(cfg)
    client = TestClient(app)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["service"] == "octo-core"
    assert "adapter_count" in body
    assert "system_widget_count" in body


def test_bridge_health_returns_contract_version() -> None:
    cfg = OctoConfig(registry_db_path=":memory:", audit_db_path=":memory:")
    app = create_app(cfg)
    client = TestClient(app)
    resp = client.get("/bridge/v1/health")
    assert resp.status_code == 200
    assert resp.json()["contract_version"] == "1.0"


def test_bootstrap_token_resolves_to_session() -> None:
    """A bootstrap token from env wires through to a working bridge call."""
    tok1 = _token("one")
    cfg = OctoConfig(
        registry_db_path=":memory:",
        audit_db_path=":memory:",
        bootstrap_tokens_raw=f"{tok1}=10:viewer:client_a:sess1",
    )
    # Inject a registry with one template so the call path is exercisable
    from shared_bridge import QueryTemplate
    reg = TemplateRegistry()
    reg.register(QueryTemplate(
        template_id="ping",
        description="ping",
        parameters={},
        response_schema={"x": "int"},
        requires_tenant_scope=True,
        min_role="viewer",
    ))
    app = create_app(cfg, template_registry=reg)
    client = TestClient(app)
    resp = client.post(
        "/bridge/v1/execute",
        json={"template_id": "ping", "params": {}},
        headers={"Authorization": f"Bearer {tok1}"},
    )
    assert resp.status_code == 200
    assert resp.json()["template_id"] == "ping"


# ---------------------------------------------------------------------------
# fail_on_discovery_failure — strict-mode boot
# ---------------------------------------------------------------------------

def test_fail_on_discovery_failure_aborts_boot_when_set() -> None:
    cfg = OctoConfig(
        registry_db_path=":memory:",
        audit_db_path=":memory:",
        adapters_package="definitely.not.a.real.package",
        system_widgets_package="apps.athena.widgets.system",
        fail_on_discovery_failure=True,
    )
    with pytest.raises(RuntimeError) as exc_info:
        create_app(cfg)
    assert "fail_on_discovery_failure" in str(exc_info.value)


def test_fail_on_discovery_failure_default_keeps_going() -> None:
    """Default behavior: log + continue. Production sets the flag for staging."""
    cfg = OctoConfig(
        registry_db_path=":memory:",
        audit_db_path=":memory:",
        adapters_package="definitely.not.a.real.package",
        system_widgets_package="apps.athena.widgets.system",
        fail_on_discovery_failure=False,
    )
    # Does not raise
    app = create_app(cfg)
    assert app is not None


# ---------------------------------------------------------------------------
# Lazy module-level app
# ---------------------------------------------------------------------------

def test_module_app_attribute_lazy_constructed(monkeypatch) -> None:
    """Importing apps.octo.main does NOT trigger app construction;
    accessing main.app does. This means tests that just want create_app()
    don't pay the boot cost on import."""
    # Override default paths so we don't try to write to /var/lib/octo
    monkeypatch.setenv("OCTO_REGISTRY_DB_PATH", ":memory:")
    monkeypatch.setenv("OCTO_AUDIT_DB_PATH", ":memory:")
    # Keep the boot hermetic: the developer's own OCTO_* settings must not
    # leak into (or, e.g. with a weak bootstrap token, abort) this test.
    for name in (
        "OCTO_BOOTSTRAP_TOKENS",
        "OCTO_STATE_DIR",
        "OCTO_ADAPTERS_PACKAGE",
        "OCTO_SYSTEM_WIDGETS_PACKAGE",
        "OCTO_FAIL_ON_DISCOVERY_FAILURE",
    ):
        monkeypatch.delenv(name, raising=False)

    # Execute a PRIVATE copy of apps/octo/main.py instead of
    # importlib.reload(apps.octo.main): a reload re-creates every class in
    # the shared module (BootstrapTokenConfigError included), so any test
    # that ran after it and caught the class imported at the top of this
    # file would no longer match what the parser raises.
    import importlib.util
    import sys

    import apps.octo.main as octo_main

    probe_name = "apps.octo._main_lazy_app_probe"
    spec = importlib.util.spec_from_file_location(probe_name, octo_main.__file__)
    assert spec is not None and spec.loader is not None
    probe = importlib.util.module_from_spec(spec)
    # dataclasses resolve string annotations through sys.modules[__module__]
    monkeypatch.setitem(sys.modules, probe_name, probe)
    spec.loader.exec_module(probe)

    # Import alone builds nothing
    assert probe._cached_app is None
    # Access app via getattr so the lazy hook fires
    app = getattr(probe, "app")
    assert app is not None
    # Second access returns the cached instance
    assert getattr(probe, "app") is app
    # The shared module (and the error class other tests catch) is untouched
    assert sys.modules["apps.octo.main"] is octo_main
    assert octo_main.BootstrapTokenConfigError is BootstrapTokenConfigError
