"""WazuhSourceAdapter — extract_event, severity, routing, deep-link tests.

Covers the pure-function surface that doesn't require a live Wazuh
manager. The `start()` / `stop()` / `smoke_test()` paths are exercised
in integration tests once the manager-client lands.
"""
from __future__ import annotations

from apps.octo.adapters.wazuh import WazuhSourceAdapter
from apps.octo.adapters.wazuh.adapter import (
    _is_routable_ioc,
    _severity_from_level,
    _short_category,
)

# Non-routable samples: RFC 1918 and link-local ON PURPOSE — the IOC
# routability rule under test must reject exactly these ranges.
# scan-sensitive: allow[ip-private] synthetic RFC 1918 / link-local samples: the rejection under test
INTERNAL_A, INTERNAL_B, LINK_LOCAL = "10.0.0.5", "192.168.1.10", "169.254.1.1"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _minimal_envelope(level: int = 5, **overrides):
    """Build a Wazuh alert envelope with sensible defaults; overrides patch in."""
    env = {
        "id": "1740585600.12345",
        "timestamp": "2026-05-11T07:30:00.000+0000",
        "rule": {
            "id": "5503",
            "level": level,
            "description": "Failed sudo invocation",
            "groups": ["pam", "syslog", "authentication_failed"],
            "firedtimes": 1,
        },
        "agent": {
            "id": "001",
            "name": "buoy-acme",
            "ip": "192.0.2.5",
        },
        "data": {},
    }
    env.update(overrides)
    return env


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

def test_severity_from_level_boundary_table():
    """Boundary table per the original octo_admin Wazuh adapter."""
    assert _severity_from_level(0) == "info"
    assert _severity_from_level(3) == "info"
    assert _severity_from_level(4) == "low"
    assert _severity_from_level(6) == "low"
    assert _severity_from_level(7) == "medium"
    assert _severity_from_level(9) == "medium"
    assert _severity_from_level(10) == "high"
    assert _severity_from_level(12) == "high"
    assert _severity_from_level(13) == "critical"
    assert _severity_from_level(15) == "critical"


def test_severity_map_uses_rule_level():
    adapter = WazuhSourceAdapter()
    assert adapter.severity_map(_minimal_envelope(level=2)) == "info"
    assert adapter.severity_map(_minimal_envelope(level=8)) == "medium"
    assert adapter.severity_map(_minimal_envelope(level=14)) == "critical"


# ---------------------------------------------------------------------------
# IOC routability
# ---------------------------------------------------------------------------

def test_routable_ioc_rejects_internal_and_loopback():
    assert not _is_routable_ioc("127.0.0.1")
    assert not _is_routable_ioc(INTERNAL_A)
    assert not _is_routable_ioc(INTERNAL_B)
    assert not _is_routable_ioc(LINK_LOCAL)     # link-local
    assert not _is_routable_ioc("224.0.0.1")    # multicast


def test_routable_ioc_accepts_public_addresses():
    assert _is_routable_ioc("8.8.8.8")
    assert _is_routable_ioc("1.1.1.1")
    assert _is_routable_ioc("9.9.9.9")


def test_routable_ioc_rejects_invalid_strings():
    assert not _is_routable_ioc("")
    assert not _is_routable_ioc("not-an-ip")
    assert not _is_routable_ioc("999.999.999.999")


# ---------------------------------------------------------------------------
# Category selection
# ---------------------------------------------------------------------------

def test_short_category_prefers_high_priority_tag():
    # `authentication_failed` is earlier than `pam` in the priority list,
    # so it wins when both are present.
    assert _short_category(["pam", "syslog", "authentication_failed"]) == "authentication_failed"
    assert _short_category(["syscollector", "syslog"]) == "syscollector"
    assert _short_category(["fim"]) == "FIM"
    # PAM wins when authentication_failed isn't present.
    assert _short_category(["pam", "syslog"]) == "PAM"


def test_short_category_falls_back_to_wazuh():
    assert _short_category([]) == "wazuh"
    assert _short_category(["unknown_group_x"]) == "wazuh"


# ---------------------------------------------------------------------------
# extract_event determinism + field mapping
# ---------------------------------------------------------------------------

def test_extract_event_is_deterministic():
    """Same envelope in → byte-equivalent CanonicalEvent out (same payload_sha256)."""
    adapter = WazuhSourceAdapter()
    env = _minimal_envelope()
    e1 = adapter.extract_event(env)
    e2 = adapter.extract_event(env)
    assert e1 == e2
    assert e1.payload_sha256 == e2.payload_sha256


def test_extract_event_basic_fields():
    adapter = WazuhSourceAdapter()
    env = _minimal_envelope()
    e = adapter.extract_event(env)
    assert e.vendor_event_id == "1740585600.12345"
    # colon-less offset normalized to canonical UTC 'Z' (SQLite-parseable)
    assert e.received_at == "2026-05-11T07:30:00.000Z"
    assert e.severity == "low"  # level 5 → low
    assert e.source_host == "buoy-acme"
    # `authentication_failed` beats `pam` in priority ordering
    assert "[authentication_failed] Failed sudo invocation" in e.summary


def test_extract_event_promotes_routable_srcip_to_indicator():
    adapter = WazuhSourceAdapter()
    env = _minimal_envelope(data={"srcip": "8.8.8.8", "dstip": INTERNAL_A})
    e = adapter.extract_event(env)
    assert e.indicator == "8.8.8.8"
    assert e.indicator_type == "ip"


def test_extract_event_drops_internal_srcip_falls_back_to_routable_dstip():
    adapter = WazuhSourceAdapter()
    env = _minimal_envelope(data={"srcip": INTERNAL_A, "dstip": "1.1.1.1"})
    e = adapter.extract_event(env)
    assert e.indicator == "1.1.1.1"


def test_extract_event_no_routable_ips_means_no_indicator():
    adapter = WazuhSourceAdapter()
    env = _minimal_envelope(data={"srcip": INTERNAL_A, "dstip": INTERNAL_B})
    e = adapter.extract_event(env)
    assert e.indicator is None
    assert e.indicator_type is None


def test_extract_event_preserves_full_payload():
    """Full envelope (including vendor-added fields) lives in `payload`
    for forensic value."""
    adapter = WazuhSourceAdapter()
    env = _minimal_envelope()
    env["future_wazuh_field"] = {"nested": "structure"}
    e = adapter.extract_event(env)
    assert e.payload["future_wazuh_field"] == {"nested": "structure"}


# ---------------------------------------------------------------------------
# route_to_tenant
# ---------------------------------------------------------------------------

def test_route_to_tenant_prefers_explicit_label():
    adapter = WazuhSourceAdapter()
    env = _minimal_envelope()
    env["agent"]["labels"] = {"_octo_tenant_slug": "acme-msp"}
    env["agent"]["group"] = "other-group"
    assert adapter.route_to_tenant(env) == "acme-msp"


def test_route_to_tenant_falls_back_to_agent_group_string():
    adapter = WazuhSourceAdapter()
    env = _minimal_envelope()
    env["agent"]["group"] = "acme-msp"
    assert adapter.route_to_tenant(env) == "acme-msp"


def test_route_to_tenant_falls_back_to_agent_group_list_first():
    adapter = WazuhSourceAdapter()
    env = _minimal_envelope()
    env["agent"]["group"] = ["primary-group", "secondary"]
    assert adapter.route_to_tenant(env) == "primary-group"


def test_route_to_tenant_returns_none_when_no_tenant_signal():
    adapter = WazuhSourceAdapter()
    env = _minimal_envelope()
    assert adapter.route_to_tenant(env) is None


# ---------------------------------------------------------------------------
# Deep link
# ---------------------------------------------------------------------------

def test_deep_link_returns_none_when_no_dashboard_configured(monkeypatch):
    monkeypatch.delenv("WAZUH_DASHBOARD_URL", raising=False)
    adapter = WazuhSourceAdapter()
    env = _minimal_envelope()
    e = adapter.extract_event(env)
    assert adapter.deep_link(e, "alert") is None
    assert adapter.deep_link(e, "host") is None


def test_deep_link_alert_uses_dashboard_url(monkeypatch):
    monkeypatch.setenv("WAZUH_DASHBOARD_URL", "https://wazuh.example.test/")
    adapter = WazuhSourceAdapter()
    env = _minimal_envelope()
    e = adapter.extract_event(env)
    link = adapter.deep_link(e, "alert")
    assert link is not None
    assert link.startswith("https://wazuh.example.test/app/wazuh")
    assert e.vendor_event_id in link


# ---------------------------------------------------------------------------
# Smoke test + onboarding shape
# ---------------------------------------------------------------------------

def test_smoke_test_requires_manager_url():
    adapter = WazuhSourceAdapter()
    r = adapter.smoke_test({})
    assert r.ok is False
    assert "MANAGER_URL" in r.message


def test_credential_shape_includes_required_fields():
    adapter = WazuhSourceAdapter()
    fields = adapter.credential_shape()
    names = {f.name for f in fields}
    assert "WAZUH_MANAGER_URL" in names
    assert "WAZUH_API_KEY" in names
    # API key field must be of `password` kind so the wizard masks it
    key_field = next(f for f in fields if f.name == "WAZUH_API_KEY")
    assert key_field.kind == "password"


def test_tenant_mapping_shape_uses_agent_groups():
    adapter = WazuhSourceAdapter()
    m = adapter.tenant_mapping_shape()
    assert m.fetch_method == "api"
    assert m.fetch_endpoint == "/agents/groups"


def test_widget_definition_declared():
    """Adapter declares a widget — the full definition lives in
    shared_widget_contract and is resolved by the framework's
    widget-discovery scan."""
    adapter = WazuhSourceAdapter()
    w = adapter.widget_definition()
    assert w is not None
    assert w.widget_id == "wazuh.alerts-feed"


# ---------------------------------------------------------------------------
# Adapter conforms to the Protocol
# ---------------------------------------------------------------------------

def test_adapter_satisfies_source_adapter_protocol():
    """Structural test — every method on the contract is implemented."""
    from shared_adapter_contract import SourceAdapter
    adapter: SourceAdapter = WazuhSourceAdapter()  # type: ignore[assignment]
    assert adapter.vendor_slug == "wazuh"
    assert adapter.contract_version == "1.0"
    assert adapter.auth_model == "api-key"


def test_received_at_normalization_converts_offset_and_never_raises():
    from apps.octo.adapters.wazuh.adapter import _normalize_timestamp as norm

    # non-UTC manager zone is CONVERTED, not re-labelled
    assert norm("2026-05-11T02:30:00.000-0500") == "2026-05-11T07:30:00.000Z"
    assert norm("2026-05-11T07:30:00+00:00") == "2026-05-11T07:30:00.000Z"
    assert norm("2026-05-11T07:30:00.000Z") == "2026-05-11T07:30:00.000Z"
    # deterministic → replay dedup keeps matching
    assert norm("2026-05-11T07:30:00.000+0000") == norm("2026-05-11T07:30:00.000+0000")
    # unparseable / naive / empty: keep verbatim, never raise (a raise = 422
    # = wedged shim cursor)
    assert norm("not-a-timestamp") == "not-a-timestamp"
    assert norm("2026-05-11T07:30:00") == "2026-05-11T07:30:00"
    assert norm("") == ""
    assert norm(None) == ""

