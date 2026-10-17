"""Datto webhook receiver + guided onboarding (URL + payload templates)."""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.api.errors import APIError
from apps.octo.api.routers import webhooks

SECRET = "datto-shared-token"


class _FakeRequest:
    def __init__(self, body: bytes, headers=None, query=None):
        self._body = body
        self.headers = headers or {}
        self.query_params = query or {}

    async def body(self) -> bytes:
        return self._body


def _record(*, default_tenant_slug=None, cred_ref="ref-1"):
    return SimpleNamespace(
        vendor_slug="datto", cred_ref=cred_ref, default_tenant_slug=default_tenant_slug
    )


def _patch(monkeypatch, *, instance, creds, sink_records, sink_error=None):
    monkeypatch.setattr(
        webhooks, "list_instances", lambda **k: ([instance] if instance else [])
    )
    monkeypatch.setattr(webhooks, "credentials", SimpleNamespace(load=lambda ref: creds))

    class _FakeSink:
        def ingest(self, tenant, source, event):
            if sink_error is not None:
                raise sink_error
            sink_records.append((tenant, source, event))

    monkeypatch.setattr(webhooks, "SqliteIngestSink", _FakeSink)


def _run(coro):
    return asyncio.run(coro)


def _alert(event="alert_raised", resolved=False):
    body = {
        "event": event,
        "alertUid": "a1",
        "alertPriority": "High",
        "alertCategory": "perf",
        "alertContext": {"message": "CPU high"},
        "device": {"hostname": "WS1"},
        "siteUid": "site-1",
        "timestamp": "2026-06-04T12:00:00Z",
    }
    if resolved:
        body["resolved"] = True
    return json.dumps(body).encode()


# --- onboarding ---

def test_onboarding_returns_url_and_templates():
    ob = DattoSourceAdapter().onboarding("https://octo.example/api/v1/webhooks/datto")
    assert ob is not None
    assert ob.webhook_url.endswith("/api/v1/webhooks/datto")
    # Real task order: save → map sites → vendor URL/header → raised →
    # resolved → attach to one monitor → reading Datto's test result.
    assert len(ob.steps) == 7
    assert [s.title[0] for s in ob.steps] == list("1234567")
    assert "save" in ob.steps[0].title and "Map" in ob.steps[1].title
    assert ob.steps[2].copy_value == ob.webhook_url
    assert "ONE monitor" in ob.steps[5].title
    raised = json.loads(ob.steps[3].code_sample)
    resolved = json.loads(ob.steps[4].code_sample)
    assert raised["event"] == "alert_raised"
    assert resolved["event"] == "alert_resolved" and resolved["resolved"] is True
    assert raised["alertUid"] == "[alert_uid]"  # Datto RMM variable placeholder


def _leaves(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from _leaves(value)
    else:
        yield node


def test_templates_use_only_known_bracketed_variables():
    """The shipped templates used "$AlertUID"-style tokens, which Datto does
    not substitute: every webhook arrived with literal tokens and no siteUid,
    and was dropped as unroutable — site mappings were never even consulted."""
    import re

    from apps.octo.adapters.datto.adapter import WEBHOOK_TEMPLATE_VARIABLES

    ob = DattoSourceAdapter().onboarding("https://octo.example/api/v1/webhooks/datto")
    for step in (ob.steps[3], ob.steps[4]):
        assert "$" not in step.code_sample
        template = json.loads(step.code_sample)
        used = {
            m for leaf in _leaves(template) if isinstance(leaf, str)
            for m in re.findall(r"\[([^\]]*)\]", leaf)
        }
        assert used and used <= WEBHOOK_TEMPLATE_VARIABLES
        assert template["siteUid"] == "[site_uid]"      # the routing key
        # No variable exists for these; a literal would only ever be noise.
        assert "timestamp" not in template and "alertPriority" not in template
    assert "[bracketed]" in ob.steps[3].body and "$variables" not in ob.steps[3].body


def test_a_template_pasted_as_is_is_never_ingested_as_values():
    """Whatever Datto leaves unsubstituted must read as MISSING — a literal
    '[site_uid]' must not become a tenant id or a hostname."""
    adapter = DattoSourceAdapter()
    ob = adapter.onboarding("https://octo.example/api/v1/webhooks/datto")
    literal = json.loads(ob.steps[3].code_sample)
    assert adapter.route_to_tenant(literal) is None
    event = adapter.extract_event(literal)
    assert event.source_host is None and "[" not in event.summary
    # Substituted, the same template routes and carries its fields — this is
    # the FALLBACK path (the body stored as sent when the doorbell fetch is
    # not possible), so it must still be routable and readable on its own.
    filled = json.loads(
        ob.steps[3].code_sample
        .replace("[site_uid]", "site-1").replace("[alert_uid]", "a-1")
        .replace("[device_hostname]", "host-1")
        .replace("[alert_category]", "Disk").replace("[alert_type]", "Disk Usage")
        .replace("[site_name]", "Example Site").replace("[device_uid]", "d-1")
    )
    assert adapter.route_to_tenant(filled) == "site-1"
    event = adapter.extract_event(filled)
    assert (event.vendor_event_id, event.source_host) == ("a-1", "host-1")
    assert event.summary == "Disk alert on host-1"    # the category label, the host
    # From [alert_type] — mapped onto the SAME class slug the poll path
    # stores for a disk-usage alert, so the two doors agree.
    assert event.event_type == "datto.perf_disk_usage"
    # The template carries the device uid, so a webhook-ingested row can offer
    # "Open device" (the portal page is looked up by it); unsubstituted, it is
    # simply absent.
    from apps.octo.adapters.datto.links import link_ids
    assert link_ids(filled)["device_uid"] == "d-1"
    assert "device_uid" not in link_ids(literal)
    # The OLD rich template (with [alert_message]) is still accepted whenever
    # it parses, and free text that merely contains brackets is NOT a token.
    assert adapter.extract_event(
        {**filled, "alertContext": {"message": "[WARN] disk [C:] full"}},
    ).summary == "Disk — [WARN] disk [C:] full"


def test_templates_are_id_only_and_the_guide_says_why():
    """4 of 9 real webhooks in one night were 422 'malformed': Datto put
    multi-line Windows event text (with quotes) into [alert_message] without
    JSON-escaping it. The webhook is a doorbell now — the body must carry ids
    and short labels only, and the operator must be told why."""
    ob = DattoSourceAdapter().onboarding("https://octo.example/api/v1/webhooks/datto")
    raised_step, resolved_step = ob.steps[3], ob.steps[4]
    for step in (raised_step, resolved_step):
        assert "ID-only" in step.title
        assert "[alert_message]" not in step.code_sample
        assert "alertContext" not in step.code_sample
        template = json.loads(step.code_sample)
        assert template["alertUid"] == "[alert_uid]" and template["siteUid"] == "[site_uid]"
        assert template["device"] == {"hostname": "[device_hostname]", "uid": "[device_uid]"}
    raised = json.loads(raised_step.code_sample)
    resolved = json.loads(resolved_step.code_sample)
    assert raised == {
        "event": "alert_raised", "alertUid": "[alert_uid]", "siteUid": "[site_uid]",
        "siteName": "[site_name]",
        "device": {"hostname": "[device_hostname]", "uid": "[device_uid]"},
        "alertCategory": "[alert_category]", "alertType": "[alert_type]",
    }
    assert resolved == {**raised, "event": "alert_resolved", "resolved": True}
    body = raised_step.body
    assert "does not JSON-escape" in body and "[alert_message]" in body
    assert "DOORBELL" in body and "fetches the complete alert" in body
    assert "identical to what polling stores" in body
    assert "never a free-text variable" in body
    assert "older, richer template is still accepted" in body
    assert "ID-only template" in ob.steps[6].body and "unresolvable" in ob.steps[6].body
    assert '"via": "api"' in ob.steps[6].body and '"via": "template"' in ob.steps[6].body
    assert "doorbell" in ob.summary


def test_guide_says_a_403_on_the_webhook_test_never_comes_from_athena():
    """Reported in production: Datto's Test Webhook showed 403. This app
    answers 2xx / 401 / 422 / 429 on that URL and nothing else, so a 403 was
    produced in front of it — and the operator had no way to learn that."""
    step = DattoSourceAdapter().onboarding("https://octo.example/api/v1/webhooks/datto").steps[6]
    assert "Test Webhook" in step.title
    for needle in ("401", "422", "429", "403", "no-tenant-id", "name-unknown", "quarantine_reason"):
        assert needle in step.body
    assert "Athena never answers 403 on this URL" in step.body
    assert "BEFORE it reached Athena" in step.body


def test_onboarding_without_base_url_still_renders_steps():
    ob = DattoSourceAdapter().onboarding(None)
    assert ob is not None and ob.webhook_url is None
    assert all(s.copy_value is None for s in ob.steps) and len(ob.steps) == 7
    # No URL exists, so nothing may claim there is one "below".
    assert "URL below" not in " ".join(s.body for s in ob.steps)


def test_onboarding_states_the_api_user_security_level_prerequisite():
    """Where the operator enters the keys: a Datto API user with no access
    still gets keys (and a token) — every read then answers 403."""
    adapter = DattoSourceAdapter()
    step_one = adapter.onboarding(None).steps[0].body
    assert "API Security Level" in step_one and "Setup > Users" in step_one
    assert "Generate API Keys" in step_one and "Enable API Access" in step_one
    assert "HTTP 403" in step_one
    key_field = next(f for f in adapter.credential_shape() if f.name == "DATTO_API_KEY")
    assert "API Security Level" in key_field.description
    assert "Generate API Keys" in key_field.description
    assert "API Tokens" not in key_field.description   # not a Datto label


def test_extract_event_marks_resolved():
    adapter = DattoSourceAdapter()
    raised = adapter.extract_event(json.loads(_alert()))
    resolved = adapter.extract_event(json.loads(_alert(event="alert_resolved", resolved=True)))
    assert not raised.summary.startswith("[resolved]")
    assert resolved.summary.startswith("[resolved]")


def test_delivery_mode_is_hybrid():
    assert DattoSourceAdapter().delivery_mode == "hybrid"


# --- webhook handler ---

def test_datto_handler_header_token_ingests(monkeypatch):
    sink: list = []
    _patch(monkeypatch, instance=_record(), creds={"DATTO_WEBHOOK_SECRET": SECRET}, sink_records=sink)
    res = _run(webhooks.datto_webhook(_FakeRequest(_alert(), headers={"x-webhook-token": SECRET})))
    assert res["ingested"] is True and res["tenant"] == "site-1"
    assert sink and sink[0][1] == "datto"


def test_datto_handler_query_token_not_accepted(monkeypatch):
    # The ?token= form put the secret in URLs / access logs; header only now.
    sink: list = []
    _patch(monkeypatch, instance=_record(), creds={"DATTO_WEBHOOK_SECRET": SECRET}, sink_records=sink)
    with pytest.raises(APIError) as ei:
        _run(webhooks.datto_webhook(_FakeRequest(_alert(), query={"token": SECRET})))
    assert ei.value.code == "AUTH_INVALID" and sink == []


def test_datto_handler_missing_token_rejected(monkeypatch):
    sink: list = []
    _patch(monkeypatch, instance=_record(), creds={"DATTO_WEBHOOK_SECRET": SECRET}, sink_records=sink)
    with pytest.raises(APIError) as ei:
        _run(webhooks.datto_webhook(_FakeRequest(_alert())))
    assert ei.value.code == "AUTH_INVALID" and sink == []


def test_datto_handler_non_ascii_token_is_clean_401(monkeypatch):
    # str compare_digest raises TypeError on non-ASCII → would be a 500.
    _patch(monkeypatch, instance=_record(), creds={"DATTO_WEBHOOK_SECRET": SECRET}, sink_records=[])
    with pytest.raises(APIError) as ei:
        _run(webhooks.datto_webhook(_FakeRequest(_alert(), headers={"x-webhook-token": "t\u00f6ken"})))
    assert ei.value.code == "AUTH_INVALID"


def test_datto_handler_bad_token_rejected(monkeypatch):
    _patch(monkeypatch, instance=_record(), creds={"DATTO_WEBHOOK_SECRET": SECRET}, sink_records=[])
    with pytest.raises(APIError) as ei:
        _run(webhooks.datto_webhook(_FakeRequest(_alert(), headers={"x-webhook-token": "wrong"})))
    assert ei.value.code == "AUTH_INVALID"


def test_datto_handler_no_instance_is_the_generic_401_not_a_404(monkeypatch, caplog):
    # A 404 told an unauthenticated caller whether this deploy has Datto wired.
    _patch(monkeypatch, instance=None, creds={}, sink_records=[])
    with caplog.at_level("WARNING", logger=webhooks.logger.name):
        with pytest.raises(APIError) as ei:
            _run(webhooks.datto_webhook(_FakeRequest(_alert())))
    assert ei.value.code == "AUTH_INVALID"
    assert "no active datto integration" in caplog.text


def test_datto_handler_vault_read_failure_fails_closed_with_actionable_log(monkeypatch, caplog):
    """credentials.load raising used to surface as a bare text 500."""
    sink: list = []
    _patch(monkeypatch, instance=_record(), creds={}, sink_records=sink)

    def _boom(ref):
        raise ValueError("cred_ref key version v9 has no matching key")

    monkeypatch.setattr(webhooks, "credentials", SimpleNamespace(load=_boom))
    with caplog.at_level("ERROR", logger=webhooks.logger.name):
        with pytest.raises(APIError) as ei:
            _run(webhooks.datto_webhook(
                _FakeRequest(_alert(), headers={"x-webhook-token": SECRET})))
    assert ei.value.code == "AUTH_INVALID" and sink == []
    assert "[webhook:datto] REJECTED" in caplog.text
    assert "could not be read from the vault" in caplog.text
    assert "key version v9" in caplog.text          # the cause, for the operator
    assert "Disable, then Add integration again" in caplog.text  # …and a way out


@pytest.mark.parametrize("creds", [{}, {"DATTO_WEBHOOK_SECRET": ""}, {"DATTO_WEBHOOK_SECRET": "   "},
                                   {"DATTO_WEBHOOK_SECRET": None}])
@pytest.mark.parametrize("headers", [{}, {"x-webhook-token": ""}, {"x-webhook-token": "guess"}])
def test_datto_handler_no_secret_fails_closed(monkeypatch, caplog, creds, headers):
    sink: list = []
    _patch(monkeypatch, instance=_record(), creds=creds, sink_records=sink)
    with caplog.at_level("ERROR", logger=webhooks.logger.name):
        with pytest.raises(APIError) as ei:
            _run(webhooks.datto_webhook(_FakeRequest(_alert(), headers=headers)))
    assert ei.value.code == "AUTH_INVALID" and sink == []
    # The operator-visible line names the exact field to configure.
    assert "DATTO_WEBHOOK_SECRET is not set" in caplog.text


def test_datto_handler_has_no_dev_bypass(monkeypatch, tmp_path):
    # The synthetic-traffic dev gate must NOT double as a webhook auth bypass.
    monkeypatch.setenv("OCTO_DEV_SYNTHETIC", "1")
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path / "octo-dev"))
    sink: list = []
    _patch(monkeypatch, instance=_record(), creds={}, sink_records=sink)
    with pytest.raises(APIError) as ei:
        _run(webhooks.datto_webhook(_FakeRequest(_alert())))
    assert ei.value.code == "AUTH_INVALID" and sink == []


def test_onboarding_text_never_offers_query_token():
    adapter = DattoSourceAdapter()
    ob = adapter.onboarding("https://octo.example/api/v1/webhooks/datto")
    text = " ".join(s.body for s in ob.steps)
    text += " ".join(f.description or "" for f in adapter.credential_shape())
    assert "?token=" not in text and "X-Webhook-Token" in text


# --- unmapped vendor tenants are HELD, never dropped ---

def test_onboarding_says_unmapped_sites_are_dropped_not_defaulted():
    step = DattoSourceAdapter().onboarding(None).steps[1]
    assert "BEFORE" in step.title
    assert "unmapped sites use the instance default" not in step.body
    # Honest about the new behaviour: an unmapped site becomes a tenant or is held.
    assert "quarantine" in step.body.lower()
    assert "DROPPED" not in step.body


def test_unmapped_site_webhook_without_instance_is_pass_through(monkeypatch):
    """A record with no persisted instance id (built outside the registry)
    keeps the legacy pass-through: the sink decides, and an unprovisioned
    tenant is answered 202 'tenant-not-provisioned'."""
    record = _record()
    monkeypatch.setattr(webhooks.tenant_map, "resolve", lambda iid, tid: None)
    _patch(monkeypatch, instance=record, creds={"DATTO_WEBHOOK_SECRET": SECRET},
           sink_records=[], sink_error=FileNotFoundError("events.db missing"))
    res = _run(webhooks.datto_webhook(
        _FakeRequest(_alert(), headers={"x-webhook-token": SECRET})))
    assert res == {"status": "accepted", "ingested": False,
                   "reason": "tenant-not-provisioned", "via": "template"}


def test_unmapped_tenant_id_list_is_bounded():
    from apps.octo.instances import unmapped

    unmapped.reset()
    for i in range(unmapped.MAX_TENANT_IDS + 25):
        unmapped.record_drop(1, f"site-{i}" + "x" * 500)
    snap = unmapped.snapshot(1)
    assert snap["dropped"] == unmapped.MAX_TENANT_IDS + 25
    assert len(snap["vendor_tenant_ids"]) == unmapped.MAX_TENANT_IDS
    assert all(len(t) <= 64 for t in snap["vendor_tenant_ids"])
    unmapped.reset()


def test_webhook_replay_reports_idempotent(monkeypatch):
    from apps.octo.ingest import IngestOutcome

    _patch(monkeypatch, instance=_record(), creds={"DATTO_WEBHOOK_SECRET": SECRET},
           sink_records=[])

    class _DupSink:
        def ingest(self, tenant, source, event):
            return IngestOutcome(event_id=9, duplicate=True)

    monkeypatch.setattr(webhooks, "SqliteIngestSink", _DupSink)
    res = _run(webhooks.datto_webhook(
        _FakeRequest(_alert(), headers={"x-webhook-token": SECRET})))
    assert res["ingested"] is True and res["idempotent"] is True
