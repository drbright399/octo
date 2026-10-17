"""ResendSourceAdapter — severity, extraction, routing, smoke, onboarding shape."""
from __future__ import annotations

from typing import Any

from shared_adapter_contract.types import CanonicalEvent

from apps.octo.adapters.resend import ResendSourceAdapter
from apps.octo.adapters.resend.adapter import _severity_from_event
from apps.octo.adapters.resend.client import (
    ResendAuthError,
    ResendClientError,
    ResendConfig,
)

VALID_CREDS = {
    "RESEND_API_KEY": "re_test_key",
    "RESEND_DOMAIN": "example.com",
    "RESEND_FROM": "Acme Security <security@example.com>",
}


class _FakeClient:
    """Stand-in for ResendClient — list_domains() returns/raises as configured."""

    def __init__(self, config: ResendConfig, *, domains=None, error=None) -> None:
        self.config = config
        self._domains = domains if domains is not None else []
        self._error = error

    def list_domains(self) -> list[dict[str, Any]]:
        if self._error is not None:
            raise self._error
        return self._domains


def _factory(*, domains=None, error=None):
    return lambda config: _FakeClient(config, domains=domains, error=error)


def _webhook(event_type="email.bounced", email_id="em-1", to="user@client.com",
             created_at="2026-06-04T12:00:00.000Z", tags=None):
    data: dict[str, Any] = {"email_id": email_id, "to": [to], "created_at": created_at}
    if tags is not None:
        data["tags"] = tags
    return {"type": event_type, "created_at": created_at, "data": data}


# --- severity ---

def test_severity_known_events():
    assert _severity_from_event("email.complained") == "high"
    assert _severity_from_event("email.bounced") == "medium"
    assert _severity_from_event("email.delivery_delayed") == "low"
    assert _severity_from_event("email.delivered") == "info"
    assert _severity_from_event("email.sent") == "info"


def test_severity_unknown_falls_back_to_info():
    assert _severity_from_event("") == "info"
    assert _severity_from_event("email.nonsense") == "info"


# --- extraction ---

def test_extract_event_maps_fields():
    adapter = ResendSourceAdapter()
    event = adapter.extract_event(_webhook(event_type="email.complained", email_id="em-9"))
    assert isinstance(event, CanonicalEvent)
    assert event.vendor_event_id == "em-9"
    assert event.severity == "high"
    assert event.received_at == "2026-06-04T12:00:00.000Z"
    assert "user@client.com" in event.summary
    assert event.payload_sha256  # deterministic hash populated


def test_extract_event_is_deterministic():
    adapter = ResendSourceAdapter()
    env = _webhook()
    assert adapter.extract_event(env).payload_sha256 == adapter.extract_event(env).payload_sha256


# --- tenant routing ---

def test_route_to_tenant_from_tag():
    adapter = ResendSourceAdapter()
    env = _webhook(tags=[{"name": "octo_tenant", "value": "acme-co"}])
    assert adapter.route_to_tenant(env) == "acme-co"


def test_route_to_tenant_explicit_override_wins():
    adapter = ResendSourceAdapter()
    env = _webhook(tags=[{"name": "octo_tenant", "value": "tagged"}])
    env["_octo_tenant_slug"] = "override"
    assert adapter.route_to_tenant(env) == "override"


def test_route_to_tenant_none_when_unmapped():
    adapter = ResendSourceAdapter()
    assert adapter.route_to_tenant(_webhook()) is None


def test_vendor_tenant_label_is_the_tag_itself():
    # No tenant directory at Resend: the tag is the only name there is, so the
    # platform's auto-create names the tenant after it instead of a placeholder.
    adapter = ResendSourceAdapter()
    env = _webhook(tags=[{"name": "octo_tenant", "value": "acme-co"}])
    assert adapter.vendor_tenant_label(env) == "acme-co"
    assert adapter.vendor_tenant_label(_webhook()) is None


# --- smoke test ---

def test_smoke_ok_when_domain_verified():
    adapter = ResendSourceAdapter(
        client_factory=_factory(domains=[{"name": "example.com", "status": "verified"}])
    )
    result = adapter.smoke_test(VALID_CREDS)
    assert result.ok is True
    assert "verified" in result.message.lower()


def test_smoke_fails_when_key_rejected():
    adapter = ResendSourceAdapter(
        client_factory=_factory(error=ResendAuthError("HTTP 401"))
    )
    result = adapter.smoke_test(VALID_CREDS)
    assert result.ok is False
    assert "rejected" in result.message.lower()


def test_smoke_fails_when_unreachable():
    adapter = ResendSourceAdapter(
        client_factory=_factory(error=ResendClientError("ConnectionError"))
    )
    result = adapter.smoke_test(VALID_CREDS)
    assert result.ok is False
    assert "reach" in result.message.lower()


def test_smoke_fails_when_domain_absent():
    adapter = ResendSourceAdapter(
        client_factory=_factory(domains=[{"name": "other.com", "status": "verified"}])
    )
    result = adapter.smoke_test(VALID_CREDS)
    assert result.ok is False
    assert "not on this resend account" in result.message.lower()


def test_smoke_fails_when_domain_not_verified():
    adapter = ResendSourceAdapter(
        client_factory=_factory(domains=[{"name": "example.com", "status": "pending"}])
    )
    result = adapter.smoke_test(VALID_CREDS)
    assert result.ok is False
    assert "not verified" in result.message.lower()


def test_smoke_missing_api_key():
    adapter = ResendSourceAdapter(client_factory=_factory(domains=[]))
    result = adapter.smoke_test({"RESEND_DOMAIN": "example.com"})
    assert result.ok is False
    assert "RESEND_API_KEY" in result.message


def test_smoke_ok_without_domain_specified():
    adapter = ResendSourceAdapter(client_factory=_factory(domains=[{"name": "x.com"}]))
    result = adapter.smoke_test({"RESEND_API_KEY": "re_test"})
    assert result.ok is True


# --- onboarding shape + metadata ---

def test_credential_shape_has_expected_fields():
    adapter = ResendSourceAdapter()
    names = {f.name for f in adapter.credential_shape()}
    assert {"RESEND_API_KEY", "RESEND_DOMAIN", "RESEND_FROM"} <= names
    # webhook secret is optional
    secret = next(f for f in adapter.credential_shape() if f.name == "RESEND_WEBHOOK_SECRET")
    assert secret.required is False


def test_adapter_metadata():
    adapter = ResendSourceAdapter()
    assert adapter.vendor_slug == "resend"
    assert adapter.auth_model == "api-key"
    assert adapter.delivery_mode == "push"


def test_deep_link_to_resend_console(monkeypatch):
    monkeypatch.delenv("RESEND_WEB_URL", raising=False)
    adapter = ResendSourceAdapter()
    event = adapter.extract_event(_webhook(email_id="em-42"))
    assert adapter.deep_link(event, "alert") == "https://resend.com/emails/em-42"
    assert adapter.deep_link(event, "device") is None
