"""ResendSourceAdapter — Resend (resend.com) → OCTO.

Resend is primarily the platform's **outbound** email provider (account
notifications, threat-resolution alerts, MSP alerts). The actual sending path
lives in ``apps.octo.auth.email_sender`` (provider switch); this adapter exists
so an operator can **onboard Resend in the Integrations tab** — supplying their
own API key + sending domain (BYOK) — with the same catalog / credential-wizard
/ encrypted-storage / smoke-test machinery every other adapter uses.

The modeled *inbound* source is Resend's delivery webhooks (``email.bounced``,
``email.complained``, ``email.delivery_delayed``, …) — legitimate deliverability
telemetry. The webhook receiver wiring is a future slice; ``extract_event`` /
``severity_map`` / ``route_to_tenant`` are ready for whatever feeds them.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Optional

from shared_adapter_contract.base import BaseSourceAdapter
from shared_adapter_contract.types import (
    CanonicalEvent,
    ComplianceCategory,
    CredentialField,
    DeepLinkType,
    Onboarding,
    OnboardingStep,
    Severity,
    SmokeResult,
    TenantMappingShape,
)

from apps.octo.adapters.resend.client import (
    ResendAuthError,
    ResendClient,
    ResendClientError,
    ResendConfig,
)

logger = logging.getLogger(__name__)


# Resend webhook event type → OCTO 5-tier severity. A spam complaint is the
# most reputation-damaging signal, so it ranks highest.
_SEVERITY_BY_EVENT: dict[str, Severity] = {
    "email.complained": "high",
    "email.bounced": "medium",
    "email.failed": "medium",
    "email.delivery_delayed": "low",
    "email.sent": "info",
    "email.delivered": "info",
    "email.opened": "info",
    "email.clicked": "info",
}


def _severity_from_event(event_type: str) -> Severity:
    return _SEVERITY_BY_EVENT.get((event_type or "").strip().lower(), "info")


def _config_from_credentials(creds: dict[str, Any]) -> ResendConfig:
    api_key = (creds.get("RESEND_API_KEY") or "").strip()
    if not api_key:
        raise ValueError("RESEND_API_KEY is required (a Resend key, re_...)")
    return ResendConfig(
        api_key=api_key,
        from_addr=(creds.get("RESEND_FROM") or "").strip(),
        domain=(creds.get("RESEND_DOMAIN") or "").strip(),
        timeout_seconds=float(creds.get("RESEND_TIMEOUT_SECONDS", "20")),
        web_url=(creds.get("RESEND_WEB_URL") or "https://resend.com").rstrip("/"),
    )


def _recipients(envelope: dict[str, Any]) -> str:
    data = envelope.get("data", {}) or {}
    to = data.get("to") or envelope.get("to")
    if isinstance(to, list):
        return ", ".join(str(x) for x in to)
    return str(to) if to else ""


class ResendSourceAdapter(BaseSourceAdapter):
    """Resend → OCTO. Outbound email provider + delivery-event telemetry."""

    vendor_slug = "resend"
    vendor_display_name = "Resend"
    vendor_logo_path = "/logos/resend.svg"
    vendor_category = "email"
    auth_model = "api-key"
    delivery_mode = "push"
    availability = "available"
    compliance_categories: list[ComplianceCategory] = ["general"]

    def __init__(
        self,
        *,
        client_factory: Optional[Callable[[ResendConfig], ResendClient]] = None,
    ) -> None:
        self._client_factory = client_factory or ResendClient

    # ----- Onboarding -----

    def credential_shape(self) -> list[CredentialField]:
        return [
            CredentialField(
                name="RESEND_API_KEY",
                label="Resend API Key",
                kind="password",
                description=(
                    "A Resend API key (re_...) from your Resend dashboard "
                    "under API Keys. A sending-only scoped key is recommended."
                ),
            ),
            CredentialField(
                name="RESEND_DOMAIN",
                label="Sending Domain",
                kind="text",
                description=(
                    "The domain you send from (e.g. example.com). It must be "
                    "added and verified in Resend — the connection test confirms "
                    "its SPF/DKIM/DMARC records are in place."
                ),
            ),
            CredentialField(
                name="RESEND_FROM",
                label="Default From Address",
                kind="text",
                description=(
                    "Default sender, e.g. 'Acme Security <security@example.com>'. "
                    "The address must be on the verified sending domain above."
                ),
            ),
            CredentialField(
                name="RESEND_WEBHOOK_SECRET",
                label="Webhook Signing Secret",
                kind="password",
                description=(
                    "Required for inbound events. The signing secret (whsec_…) "
                    "that RESEND issues when you add the webhook endpoint in "
                    "its dashboard — paste it here exactly as shown. It is "
                    "generated on Resend's side, so this platform cannot "
                    "create it for you. Used to verify delivery/bounce "
                    "events. Leave blank only for send-only use: without it "
                    "every inbound webhook is rejected."
                ),
                required=False,
            ),
        ]

    def tenant_mapping_shape(self) -> TenantMappingShape:
        # Resend has no tenant API. Delivery events are routed to an OCTO client
        # via an "octo_tenant" tag on the outbound email (or the instance default).
        return TenantMappingShape(
            fetch_method="manual",
            fetch_endpoint=None,
            vendor_tenant_id_field="tag:octo_tenant",
            vendor_tenant_label_field="tag:octo_tenant",
        )

    def smoke_test(self, credentials: dict[str, Any]) -> SmokeResult:
        try:
            config = _config_from_credentials(credentials)
        except ValueError as exc:
            return SmokeResult(ok=False, message=str(exc))
        client = self._client_factory(config)
        try:
            domains = client.list_domains()
        except ResendAuthError as exc:
            return SmokeResult(ok=False, message=f"Resend rejected the API key: {exc}")
        except ResendClientError as exc:
            return SmokeResult(ok=False, message=f"Could not reach Resend: {exc}")

        if not config.domain:
            return SmokeResult(
                ok=True,
                message=(
                    f"Resend reachable and key valid ({len(domains)} domain(s) "
                    "on the account). No sending domain specified to verify."
                ),
            )

        match = next(
            (d for d in domains if str(d.get("name", "")).strip().lower()
             == config.domain.lower()),
            None,
        )
        if match is None:
            return SmokeResult(
                ok=False,
                message=(
                    f"Key valid, but '{config.domain}' is not on this Resend "
                    "account. Add it in Resend → Domains, then verify its DNS."
                ),
            )
        status = str(match.get("status", "")).lower()
        if status != "verified":
            return SmokeResult(
                ok=False,
                message=(
                    f"'{config.domain}' is added but not verified (status: "
                    f"{status or 'unknown'}). Add the SPF/DKIM/DMARC records "
                    "Resend lists for it, then re-test."
                ),
                sample_payload=match,
            )
        return SmokeResult(
            ok=True,
            message=f"Resend reachable; '{config.domain}' is verified and ready to send.",
            sample_payload=match,
        )

    def onboarding(self, webhook_url: str | None = None) -> Onboarding | None:
        return Onboarding(
            summary=(
                "Resend sends your platform email — account notices, threat-resolution "
                "alerts, and reports. Connect your own Resend account: an API key, a "
                "verified sending domain, and a webhook so OCTO sees delivery results."
            ),
            webhook_url=webhook_url,
            steps=[
                OnboardingStep(
                    title="1 · Create a Resend API key",
                    body=(
                        "In your Resend dashboard → API Keys, create a sending-only "
                        "key (re_…) and paste it into the API key field."
                    ),
                ),
                OnboardingStep(
                    title="2 · Add and verify your sending domain",
                    body=(
                        "In Resend → Domains, add the domain you'll send from and "
                        "publish the SPF/DKIM/DMARC records Resend lists for it. The "
                        "connection test confirms it's verified before any send."
                    ),
                ),
                OnboardingStep(
                    title="3 · Add the delivery webhook",
                    body=(
                        "In Resend → Webhooks, add an endpoint pointing at the URL "
                        "below, then copy its signing secret (whsec_…) into the "
                        "Webhook signing secret field so OCTO can verify inbound "
                        "delivery and bounce events."
                    ),
                    copy_value=webhook_url,
                ),
                OnboardingStep(
                    title="4 · Set your from address",
                    body=(
                        "Use an address on the verified domain (e.g. "
                        "'Acme Security <security@example.com>'). This is the "
                        "default sender for the email OCTO sends on your behalf."
                    ),
                ),
            ],
        )

    # ----- Data side (delivery-webhook telemetry) -----

    def extract_event(self, raw_envelope: dict[str, Any]) -> CanonicalEvent:
        event_type = str(raw_envelope.get("type") or "").strip()
        data = raw_envelope.get("data", {}) or {}
        email_id = str(data.get("email_id") or data.get("id") or "")
        received_at = str(
            raw_envelope.get("created_at")
            or data.get("created_at")
            or ""
        )
        return CanonicalEvent(
            vendor_event_id=email_id,
            received_at=received_at,
            severity=_severity_from_event(event_type),
            indicator=None,
            indicator_type=None,
            source_host=None,
            summary=self._summarize(event_type, raw_envelope),
            payload=raw_envelope,
            payload_sha256=self.compute_payload_sha256(raw_envelope),
        )

    def route_to_tenant(self, raw_envelope: dict[str, Any]) -> str | None:
        explicit = raw_envelope.get("_octo_tenant_slug")
        if isinstance(explicit, str) and explicit:
            return explicit
        data = raw_envelope.get("data", {}) or {}
        tags = data.get("tags") or []
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, dict) and tag.get("name") == "octo_tenant":
                    value = str(tag.get("value") or "")
                    if value:
                        return value
        return None

    def vendor_tenant_label(self, raw_envelope: dict[str, Any]) -> str | None:
        """Resend has no tenant directory: the `octo_tenant` tag IS the name
        the sender chose, so an unknown tag becomes a tenant named after it
        (pending review) rather than a '<vendor> site …' placeholder."""
        return self.route_to_tenant(raw_envelope)

    def severity_map(self, raw_envelope: dict[str, Any]) -> Severity:
        return _severity_from_event(str(raw_envelope.get("type") or ""))

    @staticmethod
    def _summarize(event_type: str, envelope: dict[str, Any]) -> str:
        recipients = _recipients(envelope)
        verb = {
            "email.complained": "marked as spam by",
            "email.bounced": "bounced for",
            "email.failed": "failed to send to",
            "email.delivery_delayed": "delayed to",
            "email.sent": "sent to",
            "email.delivered": "delivered to",
            "email.opened": "opened by",
            "email.clicked": "link clicked by",
        }.get((event_type or "").strip().lower(), f"{event_type or 'event'} for")
        tail = recipients or "recipient"
        return f"Email {verb} {tail}"

    def human_summary(self, event: CanonicalEvent) -> str:
        return event.summary

    def deep_link(self, event: CanonicalEvent, link_type: DeepLinkType) -> str | None:
        web_base = os.environ.get("RESEND_WEB_URL", "https://resend.com").rstrip("/")
        if link_type == "alert" and event.vendor_event_id:
            return f"{web_base}/emails/{event.vendor_event_id}"
        return None
