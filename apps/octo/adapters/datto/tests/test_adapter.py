"""DattoSourceAdapter — extraction, severity, routing, deep-link tests.

Pure-function surface only. Lifecycle (start/stop/smoke) lives in
test_lifecycle.py; poller behavior lives in test_poller.py.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.adapters.datto.adapter import (
    _severity_from_priority,
    _to_iso,
)
from apps.octo.ingest.timestamps import utcnow_iso as _utcnow_iso

_ISO_MS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _datto_alert(
    *,
    priority: str = "High",
    category: str = "perf_threshold",
    message: str = "CPU > 95% for 5 min",
    timestamp: int | float | str = 1700000000,
    site_uid: str | None = "site-acme-uid",
    hostname: str = "ACME-WS-01",
    uid: str = "alert-123",
):
    return {
        "alertUid": uid,
        "alertPriority": priority,
        "alertCategory": category,
        "alertContext": {"message": message},
        "timestamp": timestamp,
        "device": {"hostname": hostname, "deviceUid": "dev-1"},
        "siteUid": site_uid,
    }


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

def test_severity_from_priority_known_strings():
    assert _severity_from_priority("Critical") == "critical"
    assert _severity_from_priority("HIGH") == "high"
    assert _severity_from_priority("moderate") == "medium"
    assert _severity_from_priority("Low") == "low"
    assert _severity_from_priority("Information") == "info"


def test_severity_from_priority_unknown_falls_back_to_info():
    assert _severity_from_priority("") == "info"
    assert _severity_from_priority("Bonkers") == "info"
    assert _severity_from_priority(None) == "info"


def test_severity_map_through_adapter():
    adapter = DattoSourceAdapter()
    assert adapter.severity_map(_datto_alert(priority="Critical")) == "critical"
    assert adapter.severity_map(_datto_alert(priority="Information")) == "info"


# ---------------------------------------------------------------------------
# Timestamp normalization
# ---------------------------------------------------------------------------

def test_to_iso_epoch_seconds_int():
    iso = _to_iso(1700000000)
    assert iso.startswith("2023-11-14T")
    assert iso.endswith("Z")


def test_to_iso_epoch_seconds_float_preserves_ms():
    iso = _to_iso(1700000000.5)
    # Millisecond precision in the output
    assert ".500Z" in iso


def test_to_iso_string_passes_through():
    assert _to_iso("2026-05-11T08:00:00.000Z") == "2026-05-11T08:00:00.000Z"


def test_to_iso_other_returns_empty():
    assert _to_iso(None) == ""
    assert _to_iso({"weird": "shape"}) == ""


# ---------------------------------------------------------------------------
# extract_event
# ---------------------------------------------------------------------------

def test_extract_event_is_deterministic():
    adapter = DattoSourceAdapter()
    raw = _datto_alert()
    e1 = adapter.extract_event(raw)
    e2 = adapter.extract_event(raw)
    assert e1 == e2
    assert e1.payload_sha256 == e2.payload_sha256


def test_extract_event_basic_fields():
    adapter = DattoSourceAdapter()
    e = adapter.extract_event(_datto_alert(
        priority="High",
        category="perf_threshold",
        message="CPU > 95%",
        uid="alert-X",
        hostname="ACME-WS-7",
    ))
    assert e.vendor_event_id == "alert-X"
    assert e.severity == "high"
    assert e.source_host == "ACME-WS-7"
    assert e.summary == "perf_threshold — CPU > 95%"
    assert e.event_type == "datto.perf_threshold"


def test_extract_event_falls_back_when_no_context_message():
    adapter = DattoSourceAdapter()
    e = adapter.extract_event({
        "alertUid": "alert-9",
        "alertPriority": "Low",
        "alertCategory": "unknown_category",
        "alertContext": {},
        "timestamp": 1700000000,
        "device": {},
        "siteUid": "x",
    })
    # No message anywhere: still a sentence, never blank, never the raw uid.
    assert e.summary == "unknown_category alert"


def test_extract_event_indicator_is_none_by_default():
    """Datto rarely carries IOCs; adapter doesn't extract from message text."""
    adapter = DattoSourceAdapter()
    e = adapter.extract_event(_datto_alert())
    assert e.indicator is None
    assert e.indicator_type is None


def test_extract_event_preserves_full_payload():
    adapter = DattoSourceAdapter()
    raw = _datto_alert()
    raw["extraDattoField"] = {"nested": "value"}
    e = adapter.extract_event(raw)
    assert e.payload["extraDattoField"] == {"nested": "value"}


def test_extract_event_normalizes_epoch_to_iso():
    adapter = DattoSourceAdapter()
    e = adapter.extract_event(_datto_alert(timestamp=1700000000))
    assert e.received_at.startswith("2023-11-14T")


# ---------------------------------------------------------------------------
# route_to_tenant
# ---------------------------------------------------------------------------

def test_route_to_tenant_prefers_explicit_label():
    adapter = DattoSourceAdapter()
    raw = _datto_alert(site_uid="site-x")
    raw["_octo_tenant_slug"] = "acme-msp"
    assert adapter.route_to_tenant(raw) == "acme-msp"


def test_route_to_tenant_falls_back_to_site_uid():
    adapter = DattoSourceAdapter()
    raw = _datto_alert(site_uid="site-acme-uid")
    assert adapter.route_to_tenant(raw) == "site-acme-uid"


def test_route_to_tenant_returns_none_when_no_signal():
    adapter = DattoSourceAdapter()
    raw = _datto_alert(site_uid=None)
    raw.pop("siteUid", None)
    assert adapter.route_to_tenant(raw) is None


# ---------------------------------------------------------------------------
# Deep link
# ---------------------------------------------------------------------------

def test_deep_link_never_guesses(monkeypatch):
    """The contract method has no instance context. It used to build a link
    from an env-wide URL + a legacy path (and a device link from a host NAME);
    links now come from the per-instance builder — see test_links.py."""
    monkeypatch.setenv("DATTO_WEB_URL", "https://portal.example.test")
    adapter = DattoSourceAdapter()
    e = adapter.extract_event(_datto_alert(uid="alert-X"))
    assert adapter.deep_link(e, "alert") is None
    assert adapter.deep_link(e, "host") is None


# ---------------------------------------------------------------------------
# Onboarding shape + protocol conformance
# ---------------------------------------------------------------------------

def test_credential_shape_has_three_required_fields():
    """API URL, key, and secret — all three are needed; the wizard must
    collect all three before smoke_test can succeed."""
    adapter = DattoSourceAdapter()
    fields = adapter.credential_shape()
    names = {f.name for f in fields}
    assert "DATTO_API_URL" in names
    assert "DATTO_API_KEY" in names
    assert "DATTO_API_SECRET_KEY" in names


def test_secret_fields_are_password_kind():
    """Wizard must mask both key + secret as password fields."""
    adapter = DattoSourceAdapter()
    fields = {f.name: f for f in adapter.credential_shape()}
    assert fields["DATTO_API_KEY"].kind == "password"
    assert fields["DATTO_API_SECRET_KEY"].kind == "password"


def test_tenant_mapping_shape_uses_account_sites():
    adapter = DattoSourceAdapter()
    m = adapter.tenant_mapping_shape()
    assert m.fetch_method == "api"
    assert "sites" in m.fetch_endpoint


def test_widget_definition_declared():
    adapter = DattoSourceAdapter()
    w = adapter.widget_definition()
    assert w is not None
    assert w.widget_id == "datto.alerts-feed"


def test_adapter_satisfies_source_adapter_protocol():
    from shared_adapter_contract import SourceAdapter
    adapter: SourceAdapter = DattoSourceAdapter()  # type: ignore[assignment]
    assert adapter.vendor_slug == "datto"
    assert adapter.contract_version == "1.0"
    assert adapter.auth_model == "api-key"


# ---------------------------------------------------------------------------
# API/POLL shape (raw /api/v2 alert object) — the poller feeds these verbatim.
# Regression guard: before the alias table these silently degraded to
# severity=info, source_host=None, tenant=_unmapped.
# ---------------------------------------------------------------------------

def _datto_api_alert(
    *,
    priority: str = "Critical",
    site_uid: str | None = "site-acme-uid",
    device_name: str = "ACME-API-01",
    uid: str = "api-alert-1",
    at_class: str = "perf_resource_usage_ctx",
    message: str = "CPU 98% for 15m",
    timestamp: int | float | str = 1700000000,
):
    """The nested /api/v2/account/alerts object shape: `priority` (not
    alertPriority) and `alertSourceInfo.*` (not device/siteUid)."""
    return {
        "alertUid": uid,
        "priority": priority,
        "alertContext": {"@class": at_class, "message": message},
        "alertSourceInfo": {
            "siteUid": site_uid,
            "siteName": "Acme Dental",
            "deviceName": device_name,
            "deviceUid": "dev-api-1",
        },
        "resolved": False,
        "timestamp": timestamp,
    }


def test_extract_event_api_shape_severity_and_host():
    adapter = DattoSourceAdapter()
    e = adapter.extract_event(
        _datto_api_alert(priority="Critical", device_name="ACME-API-9")
    )
    assert e.severity == "critical"       # from `priority`, not default info
    assert e.source_host == "ACME-API-9"  # from alertSourceInfo.deviceName
    assert "CPU 98% for 15m" in e.summary


def test_route_to_tenant_api_shape_uses_alert_source_info_site_uid():
    adapter = DattoSourceAdapter()
    raw = _datto_api_alert(site_uid="site-api-77")
    raw.pop("siteUid", None)  # only the nested id is present
    assert adapter.route_to_tenant(raw) == "site-api-77"


def test_severity_map_api_shape_uses_priority_key():
    adapter = DattoSourceAdapter()
    assert adapter.severity_map(_datto_api_alert(priority="Low")) == "low"


def test_extract_event_api_shape_category_from_at_class():
    adapter = DattoSourceAdapter()
    e = adapter.extract_event(
        _datto_api_alert(at_class="patch_ctx", message="patch failed")
    )
    assert e.event_type == "datto.patch"
    assert e.summary == "Patch — patch failed"


def test_extract_event_resolved_flag_api_shape():
    adapter = DattoSourceAdapter()
    raw = _datto_api_alert()
    raw["resolved"] = True
    e = adapter.extract_event(raw)
    assert e.summary.startswith("[resolved]")


def test_webhook_and_api_shapes_normalize_identically():
    adapter = DattoSourceAdapter()
    web = adapter.extract_event(
        _datto_alert(priority="Critical", hostname="H1", uid="u1")
    )
    api = adapter.extract_event(
        _datto_api_alert(priority="Critical", device_name="H1", uid="u1")
    )
    assert web.severity == api.severity == "critical"
    assert web.source_host == api.source_host == "H1"
    assert web.vendor_event_id == api.vendor_event_id == "u1"


# ---------------------------------------------------------------------------
# Hardening: non-colliding event id, unsubstituted tokens, epoch-ms
# ---------------------------------------------------------------------------

def test_extract_event_blank_uid_falls_back_to_sha_prefix():
    adapter = DattoSourceAdapter()
    raw = _datto_alert()
    raw["alertUid"] = ""
    e = adapter.extract_event(raw)
    assert e.vendor_event_id  # never empty
    assert e.vendor_event_id == e.payload_sha256[:16]


def test_extract_event_missing_uid_falls_back_to_sha_prefix():
    adapter = DattoSourceAdapter()
    raw = _datto_alert()
    raw.pop("alertUid", None)
    e = adapter.extract_event(raw)
    assert e.vendor_event_id == e.payload_sha256[:16]


def test_two_uidless_alerts_get_distinct_event_ids():
    """The old str(get('alertUid','')) collapsed all uid-less alerts to ''."""
    adapter = DattoSourceAdapter()
    a = adapter.extract_event(_datto_alert(uid="", message="one"))
    b = adapter.extract_event(_datto_alert(uid="", message="two"))
    assert a.vendor_event_id != b.vendor_event_id


def test_extract_event_unsubstituted_tokens_treated_as_missing():
    """A wrong $variable name arrives literally; never ingest '$AlertUID'."""
    adapter = DattoSourceAdapter()
    raw = {
        "event": "alert_raised",
        "alertUid": "$AlertUID",
        "alertPriority": "$AlertPriority",
        "alertCategory": "$AlertType",
        "alertContext": {"message": "$AlertMessage"},
        "device": {"hostname": "$DeviceName"},
        "siteUid": "$SiteUID",
        "timestamp": "$Timestamp",
    }
    e = adapter.extract_event(raw)
    assert e.vendor_event_id == e.payload_sha256[:16]  # not "$AlertUID"
    assert e.severity == "info"                         # priority token -> default
    assert e.source_host is None                        # host token -> None
    assert adapter.route_to_tenant(raw) is None         # siteUid token -> unrouted
    # "$Timestamp" is not a timestamp: received_at stays "" and the SINK
    # stamps receive-time (and dedups such events on payload identity)
    assert e.received_at == ""
    assert "$" not in e.summary                          # tokens scrubbed from summary


def test_to_iso_epoch_milliseconds_scaled():
    # 1_700_000_000_000 ms == 1_700_000_000 s == 2023-11-14
    assert _to_iso(1700000000000).startswith("2023-11-14T")


def test_to_iso_unsubstituted_token_is_empty():
    assert _to_iso("$Timestamp") == ""
    assert _to_iso("[alert_timestamp]") == ""


def test_extract_event_unsubstituted_bracket_tokens_treated_as_missing():
    """Datto's own variable form: '[name]' left in place (unknown variable for
    this alert type) is MISSING — never a tenant id, host or event id."""
    adapter = DattoSourceAdapter()
    raw = {
        "event": "alert_raised",
        "alertUid": "[alert_uid]",
        "alertPriority": "[alert_priority]",     # not a variable Datto knows
        "alertCategory": "[alert_category]",
        "alertContext": {"message": "[alert_message]"},
        "device": {"hostname": "[device_hostname]"},
        "siteUid": "[site_uid]",
    }
    e = adapter.extract_event(raw)
    assert e.vendor_event_id == e.payload_sha256[:16]
    assert e.severity == "info" and e.source_host is None
    assert adapter.route_to_tenant(raw) is None
    assert e.summary == "Datto alert" and e.event_type == "datto.alert"


def test_to_iso_out_of_range_epoch_is_empty():
    # A wildly out-of-range value must not raise — returns "" so the caller
    # defaults to receive-time.
    assert _to_iso(10**18) == ""


# ---------------------------------------------------------------------------
# Review-hardening regressions (2026-09-16 adversarial review)
# ---------------------------------------------------------------------------

def test_free_text_dollar_message_is_kept():
    """A monitor message beginning with '$Letter' is real text, not a token —
    only the WHOLE known token set is scrubbed."""
    adapter = DattoSourceAdapter()
    e = adapter.extract_event(_datto_alert(message="$LASTEXITCODE was 1 on backup job"))
    assert "$LASTEXITCODE was 1 on backup job" in e.summary


def test_non_string_priority_does_not_crash():
    """A contract-violating numeric priority must degrade to info, not 500."""
    adapter = DattoSourceAdapter()
    assert adapter.severity_map({"priority": 3}) == "info"
    e = adapter.extract_event({
        "alertUid": "u", "priority": 3,
        "alertContext": {"message": "m"}, "timestamp": 1700000000,
    })
    assert e.severity == "info"


def test_non_string_site_uid_routes_to_none():
    """A non-string siteUid must not leak downstream (was an unhandled 500)."""
    adapter = DattoSourceAdapter()
    assert adapter.route_to_tenant({"siteUid": {"x": 1}}) is None
    assert adapter.route_to_tenant({"siteUid": 999}) is None
    assert adapter.route_to_tenant({"siteUid": True}) is None


def test_to_iso_epoch_ms_preserves_milliseconds():
    assert _to_iso(1700000000123).endswith(".123Z")


def test_to_iso_epoch_exactly_1e12_is_ms_not_dead_zone():
    # 1e12 ms == 1e9 s == 2001-09-09 — must not overflow to "".
    assert _to_iso(1000000000000).startswith("2001-09-09T")


def test_to_iso_numeric_string_is_normalized():
    assert _to_iso("1700000000").startswith("2023-11-14T")
    assert _to_iso("1700000000123").startswith("2023-11-14T")


def test_category_from_top_level_alert_type():
    adapter = DattoSourceAdapter()
    e = adapter.extract_event({
        "alertUid": "u", "alertPriority": "Low", "alertType": "disk_ctx",
        "alertContext": {"message": "low disk"}, "timestamp": 1700000000,
    })
    assert e.event_type == "datto.disk"
    assert e.summary == "Disk — low disk"


def test_host_from_top_level_device_name():
    adapter = DattoSourceAdapter()
    e = adapter.extract_event({
        "alertUid": "u", "alertPriority": "Low", "deviceName": "TOP-LEVEL-HOST",
        "alertContext": {"message": "x"}, "timestamp": 1700000000,
    })
    assert e.source_host == "TOP-LEVEL-HOST"


def test_received_at_is_empty_when_timestamp_absent():
    """No vendor timestamp → "" (NOT receive-time). Receive-time in the event
    would become part of its dedup identity and every re-poll would store a
    new row; the sink stamps the stored timestamp instead."""
    adapter = DattoSourceAdapter()
    raw = _datto_alert()
    raw.pop("timestamp", None)
    assert adapter.extract_event(raw).received_at == ""


def test_received_at_is_empty_when_timestamp_none():
    adapter = DattoSourceAdapter()
    raw = _datto_alert()
    raw["timestamp"] = None
    assert adapter.extract_event(raw).received_at == ""


def test_utcnow_iso_is_strict_iso_ms():
    val = _utcnow_iso()
    assert _ISO_MS_RE.fullmatch(val)
    parsed = datetime.strptime(val, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    assert abs((datetime.now(timezone.utc) - parsed).total_seconds()) < 5


def test_poller_latest_timestamp_handles_epoch_ms():
    """The poller cursor normalizer must survive epoch-ms (else it wedges and
    re-ingests forever) — it now shares the adapter's _to_iso."""
    from apps.octo.adapters.datto.poller import DattoPoller
    got = DattoPoller._latest_timestamp([{"timestamp": 1700000000000}])
    assert got and got.startswith("2023-11-14T")


# ---------------------------------------------------------------------------
# received_at is ALWAYS canonical UTC ms — strings are parsed, not passed through
# ---------------------------------------------------------------------------

def test_to_iso_offset_string_is_converted_to_utc():
    assert _to_iso("2026-09-19T07:00:00-05:00") == "2026-09-19T12:00:00.000Z"


def test_to_iso_string_without_ms_gains_ms():
    assert _to_iso("2026-09-19T12:00:00Z") == "2026-09-19T12:00:00.000Z"


def test_to_iso_zone_less_string_is_read_as_utc():
    # Deterministic (so replay dedup matches) — see _to_iso docstring.
    assert _to_iso("2026-09-19T12:00:00") == "2026-09-19T12:00:00.000Z"


def test_to_iso_garbage_bool_and_negative_are_empty():
    for bad in ("x", "Sat Sep 19 12:00:00 2026", True, False, -5, -5.0, "-5"):
        assert _to_iso(bad) == "", bad


def test_extract_event_garbage_timestamp_is_never_stored_verbatim():
    """A bad vendor string must never reach received_at — it becomes ""
    (the sink stamps receive-time) and can never become the poller cursor."""
    adapter = DattoSourceAdapter()
    for bad in ("x", "Sat Sep 19 12:00:00 2026", True, -5, "$Timestamp"):
        e = adapter.extract_event({"alertUid": "a-1", "timestamp": bad})
        assert e.received_at == "", bad


def test_extract_event_offset_timestamp_is_stored_as_utc():
    e = DattoSourceAdapter().extract_event(
        {"alertUid": "a-1", "timestamp": "2026-09-19T07:00:00-05:00"},
    )
    assert e.received_at == "2026-09-19T12:00:00.000Z"


# ---------------------------------------------------------------------------
# Initial cursor — a new instance does not backfill from 1970
# ---------------------------------------------------------------------------

def _hours_ago(iso: str) -> float:
    parsed = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - parsed).total_seconds() / 3600.0


def test_initial_cursor_defaults_to_a_short_lookback():
    from apps.octo.adapters.datto.adapter import _initial_cursor
    assert abs(_hours_ago(_initial_cursor({})) - 24.0) < 0.01


def test_initial_cursor_lookback_is_configurable():
    from apps.octo.adapters.datto.adapter import _initial_cursor
    assert abs(_hours_ago(_initial_cursor({"initial_lookback_hours": 2})) - 2.0) < 0.01
    assert abs(_hours_ago(_initial_cursor({"initial_lookback_hours": 0}))) < 0.01


def test_initial_cursor_explicit_value_wins_and_is_normalized():
    from apps.octo.adapters.datto.adapter import _initial_cursor
    got = _initial_cursor({"initial_cursor": "2026-09-19T07:00:00-05:00",
                           "initial_lookback_hours": 2})
    assert got == "2026-09-19T12:00:00.000Z"


def test_initial_cursor_bad_config_falls_back_to_default():
    from apps.octo.adapters.datto.adapter import _initial_cursor
    for cfg in ({"initial_cursor": "zzz"}, {"initial_lookback_hours": "soon"},
                {"initial_lookback_hours": -3}, {"initial_lookback_hours": float("nan")}):
        assert abs(_hours_ago(_initial_cursor(cfg)) - 24.0) < 0.01, cfg
