"""DattoSourceAdapter — Datto RMM → OCTO.

Implements the Phase 2 SourceAdapter Protocol for Datto RMM alerts.
Same shape as the Wazuh adapter; Datto-specific bits are:
  - severity mapping from Datto's `alertPriority` (Critical / High /
    Moderate / Low / Information) → 5-tier OCTO severity
  - tenant routing from `siteUid` (mapped to OCTO client slug at
    onboarding via the tenant_mapping wizard step)
  - headline/detail/event_type built from `alertContext` (presentation.py)
  - alert portal links built per instance from Datto's own ids, device
    portal links resolved through the API on demand (links.py)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from shared_adapter_contract.base import BaseSourceAdapter
from shared_adapter_contract.types import (
    CanonicalEvent,
    ComplianceCategory,
    CredentialField,
    DeepLinkType,
    HealthStatus,
    Onboarding,
    OnboardingStep,
    Severity,
    SmokeResult,
    TenantMappingShape,
    VendorTenant,
    VendorTenantListError,
    VendorTenantListing,
    WidgetDefinitionRef,
)

from apps.octo.adapters.datto.client import (
    DattoAuthError,
    DattoClient,
    DattoClientError,
    DattoConfig,
    DattoForbiddenError,
    DattoNotFoundError,
    forbidden_guidance,
)
from apps.octo.adapters.datto.fields import (  # noqa: F401 — re-exported names
    WEBHOOK_TEMPLATE_VARIABLES,
    _alert_category,
    _alert_host,
    _alert_message,
    _alert_priority,
    _alert_site_name,
    _alert_site_uid,
    _as_dict,
    _first,
    _is_unsubstituted_token,
)
from apps.octo.adapters.datto.links import (
    LINK_SPEC,
    derive_portal_base,
    device_portal_url,
    link_ids,
)
from apps.octo.adapters.datto.poller import DattoPoller
from apps.octo.adapters.datto.presentation import present_alert
from apps.octo.ingest import IngestSink, SqliteIngestSink
from apps.octo.ingest.presentation import EventPresentation, TypedCanonicalEvent
from apps.octo.ingest.timestamps import format_utc_ms, normalize_timestamp, utcnow_iso
from apps.octo.instances.device_links import DeviceLookupError, DevicePortalLookup
from apps.octo.instances.doorbell import AlertFetchError
from apps.octo.instances.poller_lifecycle import start_on_running_loop, stop_poller
from apps.octo.instances.vendor_links import VendorLinkSpec

logger = logging.getLogger(__name__)


# Datto's alertPriority strings → OCTO severity. Datto sometimes returns
# title-case, sometimes upper, sometimes lower across API versions —
# lowercase comparison handles all.
_PRIORITY_MAP: dict[str, Severity] = {
    "critical":    "critical",
    "high":        "high",
    "moderate":    "medium",
    "medium":      "medium",
    "low":         "low",
    "information": "info",
    "info":        "info",
}


def _severity_from_priority(priority: str) -> Severity:
    return _PRIORITY_MAP.get((priority or "").strip().lower(), "info")


def _to_iso(value: Any) -> str:
    """Normalize a Datto timestamp to canonical UTC 'YYYY-MM-DDTHH:MM:SS.mmmZ'.

    Datto sends epoch SECONDS or MILLISECONDS (int/float) on the API/poll
    path, or a string on webhook templates (ISO with `Z`/an offset, or an
    all-digit epoch if a timestamp variable substitutes to one). Offsets are CONVERTED
    to UTC. A zone-less ISO string is read as UTC: Datto's API timestamps are
    UTC, and a deterministic value keeps the sink's replay dedup matching
    (receive-time would differ on every re-poll).

    Returns "" for anything unusable — None, bool, non-scalar, blank or
    unsubstituted $token, free text, negative/out-of-range epoch — so the
    caller defaults to receive-time and the poller never adopts it as a
    cursor. Never raises (shared helper contract).
    """
    if isinstance(value, str) and _is_unsubstituted_token(value.strip()):
        return ""
    return normalize_timestamp(value, allow_epoch=True, naive_is_utc=True)


# A brand-new instance must not backfill from 1970: /alerts/open would hand
# back every alert still open on the fleet, however old, as "new" traffic for
# triage. 24h covers an overnight outage/redeploy gap with margin, and
# re-reading that window on each restart is safe because the sink dedups on
# (source, payload_sha256, received_at). Override per instance with
# instance_config `initial_lookback_hours` (0 = only alerts from now on) or an
# explicit ISO `initial_cursor` (wins when parseable).
DEFAULT_INITIAL_LOOKBACK_HOURS = 24.0


def _initial_cursor(instance_config: dict[str, Any]) -> str:
    explicit = _to_iso(instance_config.get("initial_cursor"))
    if explicit:
        return explicit
    try:
        hours = float(instance_config.get(
            "initial_lookback_hours", DEFAULT_INITIAL_LOOKBACK_HOURS,
        ))
    except (TypeError, ValueError):
        hours = DEFAULT_INITIAL_LOOKBACK_HOURS
    if not (0 <= hours <= 24 * 365):  # also rejects nan
        hours = DEFAULT_INITIAL_LOOKBACK_HOURS
    return format_utc_ms(datetime.now(timezone.utc) - timedelta(hours=hours))


def _config_from_credentials(creds: dict[str, Any]) -> DattoConfig:
    """Translate wizard credentials into a DattoConfig. Raises ValueError
    with operator-actionable messages if required fields are missing."""
    api_url = creds.get("DATTO_API_URL", "").strip()
    if not api_url:
        raise ValueError(
            "DATTO_API_URL is required (pick the regional endpoint matching "
            "your Datto account, e.g., https://merlot-api.centrastage.net)"
        )
    api_key = creds.get("DATTO_API_KEY", "").strip()
    if not api_key:
        raise ValueError("DATTO_API_KEY is required")
    api_secret = creds.get("DATTO_API_SECRET_KEY", "").strip()
    if not api_secret:
        raise ValueError("DATTO_API_SECRET_KEY is required")
    return DattoConfig(
        api_url=api_url,
        api_key=api_key,
        api_secret_key=api_secret,
        verify_tls=str(creds.get("DATTO_TLS_VERIFY", "1")) not in (
            "0", "false", "no", "False",
        ),
        timeout_seconds=float(creds.get("DATTO_TIMEOUT_SECONDS", "15")),
    )


class DattoSourceAdapter(BaseSourceAdapter):
    """Datto RMM → OCTO normalization."""

    vendor_slug = "datto"
    vendor_display_name = "Datto RMM"
    vendor_logo_path = "/logos/datto.svg"
    vendor_category = "rmm"
    auth_model = "api-key"
    delivery_mode = "hybrid"  # poll the API + receive alert raised/resolved webhooks
    availability = "available"
    compliance_categories: list[ComplianceCategory] = [
        "hipaa-friendly",
        "general",
    ]
    supports_tenant_discovery = True
    reports_vendor_contact = True   # DattoPoller owns a ContactReporter
    default_poll_interval_sec = 30.0

    def __init__(
        self,
        *,
        sink: Optional[IngestSink] = None,
        client_factory: Optional[Callable[[DattoConfig], DattoClient]] = None,
    ) -> None:
        super().__init__() if hasattr(BaseSourceAdapter, "__init__") else None
        self._sink: Optional[IngestSink] = sink
        self._client_factory = client_factory or DattoClient
        self._client: Optional[DattoClient] = None
        self._poller: Optional[DattoPoller] = None
        self._started_at: Optional[float] = None
        self._default_tenant_slug: str = "_unmapped"
        self._initial_cursor: Optional[str] = None
        self._inventory: Optional[Any] = None
        self._inventory_loop = None

    # ----- Onboarding -----

    def credential_shape(self) -> list[CredentialField]:
        return [
            CredentialField(
                name="DATTO_API_URL",
                label="Datto API Base URL",
                kind="text",
                description=(
                    "Regional Datto API host for your account. Common values: "
                    "US 'merlot' cluster → https://merlot-api.centrastage.net, "
                    "EU 'pinotage' → https://pinotage-api.centrastage.net. "
                    "Datto shows your API URL next to the keys when you "
                    "generate them (Setup > Users > the API user)."
                ),
            ),
            CredentialField(
                name="DATTO_API_KEY",
                label="Datto API Key",
                kind="password",
                description=(
                    "Generated in Datto Web RMM under Setup > Users > the API "
                    "user > Generate API Keys. The PUBLIC half of the pair. "
                    "In the same place, the user's API Security Level (and "
                    "API Component Level) must cover the sites, devices and "
                    "alerts Athena should read — a key whose user has no "
                    "such access is refused here (HTTP 403)."
                ),
            ),
            CredentialField(
                name="DATTO_API_SECRET_KEY",
                label="Datto API Secret Key",
                kind="password",
                description=(
                    "The PRIVATE half of the API key pair. Shown only once "
                    "when generated in Datto Web RMM — paste it here now. "
                    "(Regenerating replaces BOTH halves, so only do that "
                    "before the integration is saved.)"
                ),
            ),
            CredentialField(
                name="DATTO_WEBHOOK_SECRET",
                label="Webhook Token",
                kind="password",
                description=(
                    "Optional. Leave blank to have Athena generate it. Own "
                    "token: 32+ random characters."
                ),
                required=False,
            ),
        ]

    def tenant_mapping_shape(self) -> TenantMappingShape:
        """Datto's MSP account contains Sites; each Site maps to one
        OCTO client slug. The wizard fetches the Site list via the
        client's list_sites() call and lets the operator pick mappings."""
        return TenantMappingShape(
            fetch_method="api",
            fetch_endpoint="/api/v2/account/sites",
            vendor_tenant_id_field="uid",
            vendor_tenant_label_field="name",
            tenant_noun="site",
            id_help=(
                "The Datto site's UID (API field 'uid', e.g. "
                "0a1b2c3d-1111-2222-3333-444455556666) — the value alerts "
                "carry as siteUid. The site NAME never matches."
            ),
        )

    def list_vendor_tenants(self, credentials: dict[str, Any]) -> VendorTenantListing:
        """Every Datto Site as (uid, name) for the mapping picker. Failures
        carry the same operator text as test-connection and the poller."""
        try:
            config = _config_from_credentials(credentials)
        except ValueError as exc:
            raise VendorTenantListError("transport", str(exc)) from exc
        try:
            listing = self._client_factory(config).list_sites_drained()
        except DattoAuthError as exc:
            raise VendorTenantListError(
                "auth", f"Datto rejected credentials: {exc}",
            ) from exc
        except DattoForbiddenError as exc:
            raise VendorTenantListError(
                # Discovery only runs for a SAVED instance.
                "forbidden", forbidden_guidance(exc.vendor_error, saved=True),
            ) from exc
        except DattoClientError as exc:
            raise VendorTenantListError(
                "transport", f"Could not reach Datto: {exc}",
            ) from exc
        tenants = [
            VendorTenant(id=uid, label=_first(site.get("name")) or uid)
            for site in listing.sites
            if (uid := _first(site.get("uid")))
        ]
        return VendorTenantListing(tenants=tenants, truncated=listing.truncated)

    def smoke_test(self, credentials: dict[str, Any]) -> SmokeResult:
        try:
            config = _config_from_credentials(credentials)
        except ValueError as exc:
            return SmokeResult(ok=False, message=str(exc))
        # check_access() performs real data reads: Datto issues a token to an
        # API user whose security level grants nothing, so a passing
        # authenticate() alone let a key that can read NOTHING be saved as
        # "connected".
        check = self._client_factory(config).check_access()
        if check.outcome == "credentials_rejected":
            return SmokeResult(
                ok=False,
                message=f"Datto rejected credentials: {check.detail}",
            )
        if check.outcome == "forbidden":
            return SmokeResult(ok=False, message=check.detail)
        if not check.ok:
            return SmokeResult(
                ok=False,
                message=f"Could not reach Datto: {check.detail}",
            )
        return SmokeResult(ok=True, message=check.detail)

    def onboarding(self, webhook_url: str | None = None) -> Onboarding | None:
        # Datto's variables are [bracketed]. The earlier "$AlertUID" style is
        # not substituted: every webhook arrived with literal tokens, no
        # siteUid, and was dropped as unroutable. No timestamp (Athena stamps
        # receive time) and no priority variable exists — see step 4.
        #
        # ID-ONLY, on purpose. Datto substitutes variables without JSON-
        # escaping them: [alert_message] (multi-line Windows event text, with
        # quotes) broke 4 of 9 real webhooks in one night (422 'malformed').
        # The webhook is a DOORBELL — Athena fetches the full alert by
        # alertUid from Datto's API (see `doorbell.py`), so no free-text
        # variable belongs in the body. What IS kept are Datto's own ids and
        # short labels, which make the body routable and readable on its own
        # when the fetch is not possible and the body is stored as sent:
        # siteUid (routing), device uid ("Open device"), hostname, site name,
        # and the monitor type/category — mapped onto the same event_type
        # class the API shape yields, so even the fallback row agrees with
        # the polled one.
        template = {
            "alertUid": "[alert_uid]",
            "siteUid": "[site_uid]",
            "siteName": "[site_name]",
            "device": {"hostname": "[device_hostname]", "uid": "[device_uid]"},
            "alertCategory": "[alert_category]",
            "alertType": "[alert_type]",
        }
        raised = json.dumps({"event": "alert_raised", **template}, indent=2)
        resolved = json.dumps(
            {"event": "alert_resolved", **template, "resolved": True}, indent=2,
        )
        recover = (
            "Settings → Integrations → Datto RMM → Disable, then Add "
            "integration again"
        )
        if webhook_url is None:
            vendor_step_body = (
                "This deployment has no public ingest hostname, so there is no "
                "webhook URL to give Datto yet — start poll-only. Once an "
                "ingest hostname is set, the URL appears here (this guide stays "
                "reachable from the integration's card: 'Setup guide'). Then, "
                "in Datto Web RMM, add a Webhook response to the monitor you "
                "want forwarded, target that URL, and add a custom header "
                "'X-Webhook-Token' set to this integration's Webhook Token. "
                "The token is accepted in that header only, never in the URL."
            )
        else:
            vendor_step_body = (
                "In Datto Web RMM, open the monitor you want forwarded and add "
                "a Webhook response targeting the URL below. Add a custom "
                "header 'X-Webhook-Token' set to this integration's Webhook "
                "Token (the value you copied after saving). The token is "
                "accepted in that header only, never in the URL, and webhooks "
                "are rejected if the integration has no Webhook Token."
            )
        return Onboarding(
            summary=(
                "Datto RMM connects in two parts: the API keys below let Athena "
                "query devices/sites and poll alerts; the optional webhook "
                "pushes alerts in real time and signals when they're resolved. "
                "The webhook is a doorbell: it names the alert, and Athena "
                "fetches the full alert from Datto's API by that id, so the "
                "stored alert is the same whichever way it arrived. "
                "Follow the steps in order — sites are mapped BEFORE the "
                "webhook is attached to anything in Datto."
            ),
            webhook_url=webhook_url,
            steps=[
                OnboardingStep(
                    title="1 · Fill in the API keys and save",
                    body=(
                        "Prerequisite, in Datto RMM: API access is enabled "
                        "for the account (Setup > Global Settings > Access "
                        "Control > Enable API Access), and the API user whose "
                        "keys you enter has an API Security Level (and API "
                        "Component Level) covering the sites, devices and "
                        "alerts Athena should read — set next to Generate API "
                        "Keys under Setup > Users > the user, then Save User. "
                        "The user's ordinary security level does not grant "
                        "API access. Datto issues keys to a user with no such "
                        "access and then answers every request with HTTP 403 "
                        "— 'Test connection' checks for exactly that, and "
                        "saving is refused until the reads succeed. Labels "
                        "vary slightly between Datto RMM versions. "
                        "Enter the Datto API URL and key pair below and save. "
                        "With real-time webhooks enabled and the Webhook Token "
                        "left blank, Athena creates the token and shows it "
                        "ONCE, with a copy button, right after saving — store "
                        "it somewhere safe (a password manager). It cannot be "
                        f"displayed again; if it is lost: {recover}."
                    ),
                ),
                OnboardingStep(
                    title="2 · Map Datto sites to clients — BEFORE attaching the webhook",
                    body=(
                        "On the screen after saving, map each Datto Site to a "
                        "client, and do it before you attach the webhook to "
                        "any monitor. Pick each site from the list Athena "
                        "loads from Datto: the routing key is the site's UID, "
                        "never its name. The same screen is on this "
                        "integration's card afterwards ('Tenant mapping'). "
                        "Alerts route by siteUid. An alert from a site you "
                        "have NOT mapped is never dropped: when the site's "
                        "name matches exactly one existing client it is "
                        "linked to it; otherwise Athena creates a tenant for "
                        "the site (marked 'pending review' under Settings → "
                        "Tenants, where you tag what it is); and anything it "
                        "cannot attribute — no siteUid, a name that matches "
                        "two clients, a site of an offboarded tenant — is "
                        "held in quarantine for you to route. The instance "
                        "default only applies to alerts that carry no siteUid "
                        "at all. Pending and held counts show on this "
                        "integration's card."
                    ),
                ),
                OnboardingStep(
                    title="3 · In Datto RMM: webhook URL + X-Webhook-Token header",
                    body=vendor_step_body,
                    copy_value=webhook_url,
                ),
                OnboardingStep(
                    title="4 · Alert-raised payload template (ID-only)",
                    body=(
                        "Set the webhook body for alert-raised events to this "
                        "ID-only template. Datto RMM replaces the [bracketed] "
                        "variables at send time — check each name against the "
                        "variable list shown in Datto's webhook editor before "
                        "relying on it. A variable Datto does not know arrives "
                        "as literal text; Athena then treats that field as "
                        "missing rather than storing '[site_uid]' as a value. "
                        "WHY no message variable: Datto does not JSON-escape "
                        "what it substitutes, so a body carrying "
                        "[alert_message] (multi-line event text, with quotes) "
                        "arrives as invalid JSON and is rejected as "
                        "'malformed' — and even when it parses, a templated "
                        "body is not the alert Datto's API holds. Athena "
                        "treats the webhook as a DOORBELL instead: it reads "
                        "the alertUid and fetches the complete alert from "
                        "Datto's API by that id, so the stored alert is "
                        "always complete and identical to what polling "
                        "stores (same headline, type and severity). Keep only "
                        "Datto's own ids and short labels in the body, as "
                        "here — never a free-text variable. They make the "
                        "webhook routable and readable on its own if the "
                        "fetch is not possible (integration not running, "
                        "Datto unreachable, fetch budget spent), in which "
                        "case the body is stored as sent; for that case only, "
                        "a fixed \"alertPriority\": \"High\" (Critical / High / "
                        "Moderate / Low / Information) per monitor sets its "
                        "severity, since Datto offers no priority or "
                        "timestamp variable. An older, richer template is "
                        "still accepted whenever it parses; a body that does "
                        "not parse is still used as a doorbell if it carries "
                        "a valid alertUid."
                    ),
                    code_sample=raised,
                ),
                OnboardingStep(
                    title="5 · Alert-resolved payload template (ID-only)",
                    body=(
                        "For alert-resolved events use this template. Athena "
                        "reads the 'event' field: the fetched alert is stored "
                        "as resolved (a '[resolved]' row) so the agent can "
                        "round-trip the closure back to your tickets. Same "
                        "rule as step 4 — ids and short labels only."
                    ),
                    code_sample=resolved,
                ),
                OnboardingStep(
                    title="6 · Attach to ONE monitor first, verify, then widen",
                    body=(
                        "Attach the webhook response to a single monitor on a "
                        "mapped site and trigger (or wait for) one alert. "
                        "Confirm it arrives in Athena under the right client "
                        "and that this integration's card shows nothing held "
                        "in quarantine. Only then attach it to the rest of "
                        "your monitors."
                    ),
                ),
                OnboardingStep(
                    title="7 · Reading Datto's 'Test Webhook' result",
                    body=(
                        "Datto shows the HTTP status its cloud received. "
                        "2xx with \"ingested\": true — stored; \"via\": \"api\" "
                        "means the alert was fetched from Datto by its id "
                        "(the normal case), \"via\": \"template\" means the "
                        "body was stored as sent because the fetch was not "
                        "possible (see the server log). "
                        "2xx with \"ingested\": false and \"reason\": "
                        "\"quarantined\" — accepted and HELD in quarantine, "
                        "with \"quarantine_reason\" saying why: "
                        "'no-tenant-id' means no siteUid arrived (a variable "
                        "was not substituted) and there is no instance "
                        "default; 'name-unknown' means the site is unmapped "
                        "and no site name arrived — open Tenant mapping "
                        "(Reload) so Athena learns the site names. "
                        "2xx with \"reason\": \"unresolvable\" — the body was "
                        "not valid JSON and the alert it named could not be "
                        "fetched from Datto, so it was DROPPED — switch to "
                        "the ID-only template (step 4) so the body always "
                        "parses. Datto's test may send the template with no "
                        "real alert behind it, so a real alert (step 6) is "
                        "the proof. "
                        "401 — the request reached Athena but the "
                        "X-Webhook-Token header is missing or wrong (or this "
                        "integration has no token / is disabled). "
                        "422 — the body is not a JSON object and names no "
                        "alertUid: a free-text variable such as [alert_message] "
                        "broke it — switch to the ID-only template (step 4). "
                        "429 — rate limited; wait a minute. "
                        "403, or an HTML error page — the request was blocked "
                        "BEFORE it reached Athena: Athena never answers 403 on "
                        "this URL. Look at whatever fronts the ingest hostname "
                        "in your deployment (WAF or bot protection, an access "
                        "policy, a reverse-proxy path or method rule, an IP "
                        "allow-list) — a request from inside your network "
                        "proves nothing about what Datto's cloud is allowed "
                        "to reach."
                    ),
                ),
            ],
        )

    # ----- Lifecycle -----

    def start(self, instance_config: dict[str, Any]) -> None:
        if self._poller is not None:
            return None
        try:
            config = _config_from_credentials(instance_config)
        except ValueError as exc:
            logger.error("[datto] start failed: invalid config: %s", exc)
            raise

        self._client = self._client_factory(config)
        if self._sink is None:
            from apps.octo.instances.tenant_map import MappingIngestSink
            self._sink = MappingIngestSink(
                SqliteIngestSink(), instance_config.get("_instance_id")
            )

        self._default_tenant_slug = instance_config.get(
            "default_tenant_slug", "_unmapped",
        )
        initial_cursor = _initial_cursor(instance_config)
        poll_interval = float(instance_config.get(
            "poll_interval_sec", self.default_poll_interval_sec,
        ))

        self._poller = DattoPoller(
            adapter=self,
            client=self._client,
            sink=self._sink,
            default_tenant_slug=self._default_tenant_slug,
            initial_cursor=initial_cursor,
            poll_interval_sec=poll_interval,
            instance_id=instance_config.get("_instance_id"),
        )
        self._initial_cursor = initial_cursor
        self._started_at = time.time()
        self._poller_loop = start_on_running_loop(
            self._poller.start, what="datto",
        )
        # The read-only inventory feed (entity resolution): its own task,
        # its own pace; it never holds the alerts poller.
        from apps.octo.adapters.datto.inventory import DEFAULT_INTERVAL_SEC, InventoryPoller

        try:
            inventory_every = float(instance_config.get("inventory_interval_sec",
                                                        DEFAULT_INTERVAL_SEC))
        except (TypeError, ValueError):
            inventory_every = DEFAULT_INTERVAL_SEC
        self._inventory = InventoryPoller(
            client=self._client,
            instance_id=instance_config.get("_instance_id"),
            interval_sec=inventory_every,
        )
        self._inventory_loop = start_on_running_loop(self._inventory.start,
                                                     what="datto-inventory")
        return None

    def stop(self) -> None:
        if self._poller is None:
            return None
        inventory = getattr(self, "_inventory", None)
        if inventory is not None:
            stop_poller(inventory.stop, getattr(self, "_inventory_loop", None),
                        what="datto-inventory")
            self._inventory = None
            self._inventory_loop = None
        stop_poller(
            self._poller.stop, getattr(self, "_poller_loop", None), what="datto",
        )
        self._poller_loop = None
        self._poller = None
        self._client = None
        self._started_at = None
        return None

    @property
    def inventory(self) -> Optional[Any]:
        return self._inventory

    def poll_now(self) -> None:
        """Ask the poller to poll again now instead of finishing its wait."""
        if self._poller is not None:
            self._poller.poll_now()

    def health(self) -> HealthStatus:
        if self._poller is None:
            return HealthStatus(
                alive=False,
                last_event_at=None,
                lag_seconds=0.0,
                errors_last_hour=0,
            )
        cursor = self._poller.cursor
        return HealthStatus(
            alive=True,
            # The cursor only moves when an alert is seen; still sitting on
            # the start value means "nothing received yet", not an event time.
            last_event_at=cursor if cursor != self._initial_cursor else None,
            lag_seconds=0.0,
            errors_last_hour=0,
        )

    # ----- Core extraction -----

    def extract_event(self, raw_envelope: dict[str, Any]) -> CanonicalEvent:
        """Map a Datto alert envelope onto a CanonicalEvent.

        Handles BOTH inbound shapes identically via field aliases (see the
        module-level `_alert_*` helpers):
          * WEBHOOK  — flat operator-templated body
            (alertPriority / device.hostname / siteUid / alertContext.message)
          * API/POLL — nested /api/v2 alert object the poller feeds verbatim
            (priority / alertSourceInfo.deviceName / alertSourceInfo.siteUid /
             alertContext.@class)
        Datto alerts rarely carry IOCs — indicator stays None.
        """
        payload_sha = self.compute_payload_sha256(raw_envelope)

        severity = _severity_from_priority(_alert_priority(raw_envelope))
        uid = _first(raw_envelope.get("alertUid"))
        # The stored summary is the HEADLINE ("Event log · Security 4625 — An
        # account failed to log on"); "[resolved] " is prefixed for
        # alert-resolved events so the triage agent can round-trip the
        # closure. The longer detail has no column: readers derive it from
        # the stored payload with present_event().
        shown = present_alert(raw_envelope)

        # No usable vendor timestamp → leave received_at "". The SINK stamps
        # receive-time at write and then dedups such events on
        # (source, payload_sha256) alone. Defaulting to receive-time HERE made
        # the timestamp part of the identity, so every re-poll / retry of a
        # timestamp-less alert (or one carrying a literal "$Timestamp") stored
        # a new row. "" also never becomes the poller cursor.
        received_at = _to_iso(
            raw_envelope.get("timestamp") or raw_envelope.get("alertTimestamp")
        )

        return TypedCanonicalEvent(
            # Never "" — an empty vendor_event_id collides every uid-less alert
            # into one row. Fall back to a stable slice of the payload sha.
            vendor_event_id=str(uid or payload_sha[:16]),
            received_at=received_at,
            severity=severity,
            indicator=None,
            indicator_type=None,
            source_host=_alert_host(raw_envelope),
            summary=shown.headline,
            payload=raw_envelope,
            payload_sha256=payload_sha,
            # A stable label per alert class ("datto.eventlog") instead of the
            # sink's constant "alert": triage recurrence and the devices
            # widget key on it, and nothing matches the literal "alert".
            event_type=shown.event_type,
        )

    @staticmethod
    def present_event(payload: dict[str, Any]) -> EventPresentation:
        """OPTIONAL capability (looked up on the CLASS by the API layer):
        headline + detail + device + site for a STORED payload. Read-time, so
        rows ingested before this existed are readable too."""
        return present_alert(payload)

    def route_to_tenant(self, raw_envelope: dict[str, Any]) -> str | None:
        """Resolution order:
          1. Explicit `_octo_tenant_slug` on the alert (if a forwarder
             stamped it before reaching the indexer)
          2. siteUid (mapped to OCTO client slug at onboarding)
          3. None → poller falls back to default_tenant_slug
        """
        explicit = _first(raw_envelope.get("_octo_tenant_slug"))
        if explicit:
            return explicit
        # siteUid aliased across the webhook (top-level) and /api/v2 object
        # (alertSourceInfo.siteUid) shapes. _first() yields only a non-empty
        # string or None, so a non-string siteUid can't leak downstream.
        return _alert_site_uid(raw_envelope)

    def vendor_tenant_label(self, raw_envelope: dict[str, Any]) -> str | None:
        """The Datto site NAME for the site `route_to_tenant()` returns —
        `alertSourceInfo.siteName` on the API object, top-level `siteName`
        on the webhook template ([site_name]). None when absent or left
        unsubstituted; the platform then uses its cached site discovery."""
        return _alert_site_name(raw_envelope)

    def severity_map(self, raw_envelope: dict[str, Any]) -> Severity:
        return _severity_from_priority(_alert_priority(raw_envelope))

    def human_summary(self, event: CanonicalEvent) -> str:
        return event.summary

    def deep_link(
        self,
        event: CanonicalEvent,
        link_type: DeepLinkType,
    ) -> str | None:
        """Always None. This contract method has no instance context, and the
        old body guessed: an env-wide portal URL, a legacy '/web/?#alert/'
        path and a device link built from a HOST NAME. Datto links are built
        per instance, from Datto's own ids — see the vendor_link_* capability
        below and `apps.octo.instances.vendor_links`."""
        return None

    # ----- Vendor portal links (optional capability, read on the CLASS) -----

    @staticmethod
    def vendor_link_spec() -> VendorLinkSpec:
        return LINK_SPEC

    @staticmethod
    def vendor_link_ids(payload: dict[str, Any]) -> dict[str, str]:
        return link_ids(payload)

    @staticmethod
    def derive_portal_base(config: dict[str, Any]) -> str | None:
        """Portal base for this instance's API URL, or None when the URL is
        not Datto's documented '<platform>-api' form (then: no links)."""
        return derive_portal_base(config.get("DATTO_API_URL"))

    def resolve_device_portal(
        self, device_uid: str, portal_base: str,
    ) -> DevicePortalLookup:
        """OPTIONAL capability, on a RUNNING instance: the portal address of
        one device, through this instance's own client (no credential is
        decrypted for it). ONE vendor read — callers invoke it only when an
        operator clicks Open, and cache the answer.

        The portal addresses devices by a numeric id that alerts do not
        carry; the API's device object has a ready-made `portalUrl`. That
        value is vendor data: it is returned only after `device_portal_url()`
        accepted it for `portal_base`. Nothing else of the device object is
        read — in particular not `webRemoteUrl` (a remote-control session),
        which the client drops before returning.

        Raises DeviceLookupError with operator-safe text."""
        client = self._client
        if client is None:
            raise DeviceLookupError(
                "transport", "The Datto RMM integration is not running.",
            )
        try:
            device = client.get_device_portal(device_uid)
        except ValueError:
            raise DeviceLookupError(
                "invalid", "This alert does not carry a usable Datto device id.",
            ) from None
        except DattoAuthError:
            raise DeviceLookupError(
                "auth", "Datto rejected the stored credentials.",
            ) from None
        except DattoForbiddenError:
            # Not asserted as a cause: Datto also answers 403 while it
            # temporarily blocks this server's address after rate limiting
            # (see forbidden_guidance) — an admin must not be sent to change
            # the API user for a block that lifts by itself.
            raise DeviceLookupError(
                "forbidden",
                "Datto answered HTTP 403 to the device lookup without saying "
                "why: either this API user's security level, or a temporary "
                "block of this server's address after rate limiting (it lifts "
                "by itself). If it persists, check the API user's security "
                "level in Datto RMM.",
            ) from None
        except DattoNotFoundError:
            raise DeviceLookupError(
                "not_found", "Datto RMM does not know this device (any more).",
            ) from None
        except DattoClientError as exc:
            # Client messages are static text + status codes (see client.py).
            raise DeviceLookupError("transport", f"Could not reach Datto: {exc}") from None
        if _first(device.get("uid")) != device_uid:
            raise DeviceLookupError(
                "invalid", "Datto answered with a different device; no link was opened.",
            )
        url = device_portal_url(device.get("portalUrl"), portal_base)
        if url is None:
            raise DeviceLookupError(
                "invalid",
                "Datto returned a device page address that did not pass "
                "validation; no link was opened.",
            )
        return DevicePortalLookup(
            portal_url=url, vendor_tenant_id=_first(device.get("siteUid")),
        )

    # ----- The webhook doorbell's fetch (optional capability, RUNNING instance) -----

    def fetch_alert(
        self, alert_uid: str, *, timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """OPTIONAL capability, on a RUNNING instance: ONE alert by uid,
        through this instance's own client (no credential is decrypted for
        it) — what the webhook receiver stores instead of the templated body
        (see `doorbell.py`). The object is returned exactly as Datto answered
        it: fed to `extract_event` it yields the poller's event_type,
        headline and severity, and the same payload sha, so the sink
        collapses it with the polled copy.

        Called by the receiver only: once per uid per minute, within an
        instance budget, and never past its deadline — the bounds live in
        `instances.doorbell`. Raises AlertFetchError with operator-safe text."""
        client = self._client
        if client is None:
            raise AlertFetchError(
                "not_running", "The Datto RMM integration is not running.",
            )
        try:
            return client.get_alert(alert_uid, timeout_seconds=timeout_seconds)
        except ValueError:
            raise AlertFetchError(
                "invalid", "The webhook did not carry a usable Datto alert id.",
            ) from None
        except DattoAuthError:
            raise AlertFetchError(
                "auth", "Datto rejected the stored credentials.",
            ) from None
        except DattoForbiddenError:
            # Same caution as the device lookup: a 403 is also what Datto
            # answers while it temporarily blocks this address.
            raise AlertFetchError(
                "forbidden",
                "Datto answered HTTP 403 to the alert lookup (the API user's "
                "security level, or a temporary block after rate limiting).",
            ) from None
        except DattoNotFoundError:
            raise AlertFetchError(
                "not_found", "Datto RMM does not know this alert (any more).",
            ) from None
        except DattoClientError as exc:
            # Client messages are static text + status codes (see client.py).
            raise AlertFetchError("transport", f"Could not reach Datto: {exc}") from None

    def widget_definition(self) -> WidgetDefinitionRef | None:
        return WidgetDefinitionRef(widget_id="datto.alerts-feed")
