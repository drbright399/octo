"""RocketCyberSourceAdapter — RocketCyber (Kaseya Managed SOC) → OCTO.

Implements the SourceAdapter contract against RocketCyber's real v3 API (see
client.py for what exists and what does not):

  - ONE credential: a read-only API key. The provider account is read from the
    key (GET /v3/account); the API base URL defaults to the US endpoint. Both
    stay overridable, and instances saved with the old required
    RC_API_URL / RC_ACCOUNT_ID keys keep working — those values are read.
  - poll only (no webhooks exist): open incidents plus a rolling createdAt
    window of closed ones, with change detection, so resolutions and
    suppressions arrive as their own events however long an incident stayed
    open (poller.py)
  - tenant = the incident's CUSTOMER (`accountId`), labelled by `accountName`;
    customers are discoverable for the mapping picker. The numeric id is
    never taken as a client slug (`tenant_ids_are_slugs = False`)
  - severity from status (RocketCyber has none): open → high, resolved /
    suppressed → medium (presentation.py)
  - no vendor deep link: no documented or derivable portal URL is known, and
    a guessed one is worse than none
"""

from __future__ import annotations

import asyncio
import logging
import time
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
    RateLimitHints,
    Severity,
    SmokeResult,
    TenantMappingShape,
    VendorTenant,
    VendorTenantListError,
    VendorTenantListing,
    WidgetDefinitionRef,
)

from apps.octo.adapters.rocketcyber.client import (
    DEFAULT_API_URL,
    DEFAULT_OPEN_LOOKBACK_DAYS,
    MAX_OPEN_LOOKBACK_DAYS,
    RocketCyberAuthError,
    RocketCyberClient,
    RocketCyberClientError,
    RocketCyberConfig,
    RocketCyberForbiddenError,
    forbidden_guidance,
    normalize_api_url,
    parse_account_id,
)
from apps.octo.adapters.rocketcyber.poller import (
    DEFAULT_FIRST_IMPORT_GRACE_SEC,
    DEFAULT_INITIAL_LOOKBACK_DAYS,
    MAX_FIRST_IMPORT_GRACE_SEC,
    DEFAULT_POLL_INTERVAL_SEC,
    DEFAULT_WINDOW_DAYS,
    MAX_WINDOW_DAYS,
    RocketCyberPoller,
)
from apps.octo.adapters.rocketcyber.presentation import (
    incident_status,
    present_incident,
    severity_for_status,
)
from apps.octo.adapters.rocketcyber.presentation import psa_ticket as _psa_ticket
from apps.octo.ingest import IngestSink, SqliteIngestSink
from apps.octo.ingest.presentation import EventPresentation, TypedCanonicalEvent, clean_line
from apps.octo.ingest.timestamps import normalize_timestamp
from apps.octo.instances.poller_lifecycle import start_on_running_loop, stop_poller

logger = logging.getLogger(__name__)

# Wizard / vault keys. The names are the ones instances were saved with before
# (then RC_API_URL and RC_ACCOUNT_ID were required); only RC_API_KEY still is.
KEY_FIELD = "RC_API_KEY"
URL_FIELD = "RC_API_URL"
ACCOUNT_FIELD = "RC_ACCOUNT_ID"


def _config_from_credentials(creds: dict[str, Any], *, strict: bool = True) -> RocketCyberConfig:
    """Wizard / vault values → RocketCyberConfig. Raises ValueError with an
    operator-actionable message (never echoing a value).

    `strict=False` (a SAVED instance starting, or discovery for one): an
    unusable provider-account override is ignored with a warning — the key's
    own account is used — instead of bricking an instance saved by the old
    wizard, whose value cannot be edited any more. New input (Test
    connection, save) is always strict."""
    api_key = creds.get(KEY_FIELD)
    api_key = api_key.strip() if isinstance(api_key, str) else ""
    if not api_key:
        raise ValueError(f"{KEY_FIELD} is required (the RocketCyber API key)")
    if any(not ("!" <= ch <= "~") for ch in api_key):
        # It goes into an HTTP header: a pasted line break makes the request
        # fail as "unreachable" (with the key inside the library's error),
        # a typographic quote from a document cannot be sent at all.
        raise ValueError(
            f"{KEY_FIELD} contains a space, a line break or an unusual "
            "character — paste the key again as one line, exactly as the "
            "RocketCyber console shows it"
        )
    api_url = normalize_api_url(creds.get(URL_FIELD))
    try:
        account_id = parse_account_id(creds.get(ACCOUNT_FIELD))
    except ValueError:
        if strict:
            raise
        logger.warning(
            "[rocketcyber] stored %s is not a numeric account id; ignored — the "
            "API key's own account is used", ACCOUNT_FIELD,
        )
        account_id = None
    try:
        timeout = float(creds.get("RC_TIMEOUT_SECONDS", "15"))
    except (TypeError, ValueError):
        timeout = 15.0
    return RocketCyberConfig(
        api_key=api_key,
        api_url=api_url,
        account_id=account_id,
        verify_tls=str(creds.get("RC_TLS_VERIFY", "1")) not in ("0", "false", "no", "False"),
        timeout_seconds=timeout if 0 < timeout <= 120 else 15.0,
    )


def _bounded(value: Any, default: float, low: float, high: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if not (low <= number <= high):  # also rejects nan
        return default
    return number


def _incident_account_id(raw: dict[str, Any]) -> Optional[str]:
    value = raw.get("accountId")
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return str(value)
    if isinstance(value, str):
        text = value.strip()
        if text.isascii() and text.isdigit() and 0 < len(text) <= 12 and int(text) > 0:
            return str(int(text))
    return None


def _received_at(raw: dict[str, Any]) -> str:
    """The version's own time: updatedAt (when it last changed), else
    publishedAt, else createdAt. A pure function of the payload, so a
    re-delivered unchanged incident has the same (payload, timestamp)
    identity and the sink collapses it. "" when none is usable (the sink then
    stamps receive time and dedups on the payload alone)."""
    for key in ("updatedAt", "publishedAt", "createdAt"):
        ts = normalize_timestamp(raw.get(key), naive_is_utc=True)
        if ts:
            return ts
    return ""


def _customer_label(customer: dict[str, Any]) -> str:
    cid = customer.get("accountId")
    name = customer.get("accountName")
    name = name.strip() if isinstance(name, str) and name.strip() else f"Customer {cid}"
    status = customer.get("status")
    status = clean_line(status, 24) if isinstance(status, str) else ""
    if status and status.lower() != "active":
        return f"{name} ({status.lower()})"
    return name


class RocketCyberSourceAdapter(BaseSourceAdapter):
    """RocketCyber → OCTO."""

    vendor_slug = "rocketcyber"
    vendor_display_name = "RocketCyber"
    vendor_logo_path = "/logos/rocketcyber.svg"
    vendor_category = "soc"
    auth_model = "api-key"
    delivery_mode = "poll"           # the API has no webhooks
    availability = "available"
    compliance_categories: list[ComplianceCategory] = [
        "hipaa-friendly",
        "general",
    ]
    supports_tenant_discovery = True
    # Customer ids are numbers, and "2002" is also a valid client slug: an
    # unmapped customer must never land in a client that happens to be named
    # by a number (tenant_autocreate skips pass-through for this adapter).
    tenant_ids_are_slugs = False
    reports_vendor_contact = True    # RocketCyberPoller owns a ContactReporter
    default_poll_interval_sec = DEFAULT_POLL_INTERVAL_SEC

    def __init__(
        self,
        *,
        sink: Optional[IngestSink] = None,
        client_factory: Optional[Callable[[RocketCyberConfig], RocketCyberClient]] = None,
    ) -> None:
        super().__init__() if hasattr(BaseSourceAdapter, "__init__") else None
        self._sink = sink
        self._client_factory = client_factory or RocketCyberClient
        self._client: Optional[RocketCyberClient] = None
        self._poller: Optional[RocketCyberPoller] = None
        self._poller_loop: Optional[asyncio.AbstractEventLoop] = None
        self._started_at: Optional[float] = None
        self._default_tenant_slug: str = "_unmapped"

    # ----- Onboarding -----

    def credential_shape(self) -> list[CredentialField]:
        return [
            CredentialField(
                name=KEY_FIELD,
                label="RocketCyber API key",
                kind="password",
                description=(
                    "Created in the RocketCyber console at the PROVIDER (MSP) "
                    "account level — not inside one customer — on its API "
                    "settings page (the menu label varies between console "
                    "versions). RocketCyber's API is read-only: this key cannot "
                    "change anything there."
                ),
            ),
            CredentialField(
                name=URL_FIELD,
                label="API base URL (optional)",
                kind="text",
                required=False,
                description=(
                    f"Leave blank for RocketCyber's US endpoint, {DEFAULT_API_URL}. "
                    "Only set it if your RocketCyber account is hosted in another "
                    "region: that region's API base URL, https, ending in /v3."
                ),
            ),
            CredentialField(
                name=ACCOUNT_FIELD,
                label="Provider account ID (optional)",
                kind="text",
                required=False,
                description=(
                    "Leave blank: Athena reads the account the API key belongs "
                    "to. Only needed if Test connection says it cannot tell — "
                    "then enter your provider (MSP) account's numeric ID."
                ),
            ),
        ]

    def tenant_mapping_shape(self) -> TenantMappingShape:
        return TenantMappingShape(
            fetch_method="api",
            fetch_endpoint="/v3/account?accountId={provider}&details=true",
            vendor_tenant_id_field="accountId",
            vendor_tenant_label_field="accountName",
            tenant_noun="customer",
            id_help=(
                "The RocketCyber customer's numeric account ID (API field "
                "'accountId', e.g. 2001) — the value every incident carries as "
                "accountId. Your provider account's own ID is a valid choice too "
                "(incidents about your own MSP environment carry it). The "
                "customer NAME never matches."
            ),
        )

    def list_vendor_tenants(self, credentials: dict[str, Any]) -> VendorTenantListing:
        """Every customer of the provider account as (accountId, name) — all
        of them, whatever their status: a non-active customer can still have
        incidents in the window, and hiding it would make its saved mapping
        look orphaned; its status is shown in the label instead. The provider
        account itself is listed first-class too (MSP-internal incidents
        carry its id)."""
        try:
            config = _config_from_credentials(credentials, strict=False)
        except ValueError as exc:
            raise VendorTenantListError("transport", str(exc)) from exc
        client = self._client_factory(config)
        try:
            account = client.provider_account()
            listing = client.list_customers()
        except RocketCyberAuthError as exc:
            raise VendorTenantListError(
                "auth", f"RocketCyber rejected the stored API key: {exc}",
            ) from exc
        except RocketCyberForbiddenError as exc:
            raise VendorTenantListError(
                "forbidden",
                forbidden_guidance(
                    exc.vendor_error, account_id=exc.account_id,
                    overridden=bool(client.account and client.account.overridden),
                    saved=True,
                ),
            ) from exc
        except RocketCyberClientError as exc:
            raise VendorTenantListError(
                "transport", f"Could not read customers from RocketCyber: {exc}",
            ) from exc
        tenants: list[VendorTenant] = []
        listed_ids = {c["accountId"] for c in listing.customers}
        if account.account_id not in listed_ids:
            if account.derived_id == account.account_id:
                name = account.name.strip()
                label = f"{name} (provider account)" if name else "Provider account"
            else:
                # The override names an account other than the key's own:
                # its name is not known from this answer.
                label = f"Account {account.account_id} (configured account)"
            tenants.append(VendorTenant(id=str(account.account_id), label=label))
        tenants.extend(
            VendorTenant(id=str(c["accountId"]), label=_customer_label(c))
            for c in listing.customers
        )
        return VendorTenantListing(tenants=tenants, truncated=listing.truncated)

    def smoke_test(self, credentials: dict[str, Any]) -> SmokeResult:
        try:
            config = _config_from_credentials(credentials, strict=True)
        except ValueError as exc:
            return SmokeResult(ok=False, message=str(exc))
        # Real authorised reads — the account, its customers and page 1 of
        # each incidents read in the poller's own request shape — not a bare
        # key check.
        client = self._client_factory(config)
        check = client.check_access(
            window_days=DEFAULT_WINDOW_DAYS, open_lookback_days=DEFAULT_OPEN_LOOKBACK_DAYS,
        )
        if check.outcome == "credentials_rejected":
            return SmokeResult(
                ok=False,
                message=(
                    f"{check.detail}. Check that the key was copied whole and is "
                    "still enabled in the RocketCyber console. A key is only "
                    "valid in its own region: if your RocketCyber account is "
                    "hosted outside the US, set 'API base URL' to your region's "
                    f"API endpoint (Athena used {client.origin})."
                ),
            )
        if check.outcome == "forbidden":
            return SmokeResult(ok=False, message=check.detail)
        if not check.ok:
            return SmokeResult(ok=False, message=f"Could not read from RocketCyber: {check.detail}")
        return SmokeResult(ok=True, message=check.detail)

    def onboarding(self, webhook_url: str | None = None) -> Onboarding | None:
        interval_min = int(DEFAULT_POLL_INTERVAL_SEC // 60)
        grace_min = int(DEFAULT_FIRST_IMPORT_GRACE_SEC // 60)
        return Onboarding(
            summary=(
                "RocketCyber (Kaseya Managed SOC) forwards its incidents into "
                "Athena. It needs ONE read-only API key: Athena finds your "
                "provider account and its customers from the key, polls "
                f"incidents every {interval_min} minutes and routes each one to "
                "the client its RocketCyber customer maps to."
            ),
            webhook_url=None,  # RocketCyber offers no webhooks — polled only
            steps=[
                OnboardingStep(
                    title="1 · Create an API key in RocketCyber",
                    body=(
                        "Sign in to the RocketCyber console at your PROVIDER "
                        "(MSP) account — not inside a customer — and create an "
                        "API key on its API settings page (the menu label "
                        "varies between console versions). Paste it into "
                        "'RocketCyber API key'. Leave the two optional fields "
                        f"blank: the API URL defaults to {DEFAULT_API_URL} (US), "
                        "and the provider account is read from the key itself. "
                        "Press Test connection: it reads your account, its "
                        "customer list and the incidents Athena will poll, and "
                        "saving is refused until those reads succeed (and "
                        "while the key turns out to belong to one customer)."
                    ),
                ),
                OnboardingStep(
                    title="2 · What Athena reads — and cannot do",
                    body=(
                        "Read-only. Athena reads your provider account (its "
                        "customer list, for the mapping step) and your "
                        "customers' incidents: title, description, "
                        "remediation, status, event count, customer, and the "
                        "PSA ticket number RocketCyber attached. RocketCyber's "
                        "API offers no write of any kind: resolving or "
                        "suppressing an incident stays a click in the "
                        "RocketCyber console, and Athena sees the change on "
                        "its next poll — however long the incident was open "
                        f"(up to {int(DEFAULT_OPEN_LOOKBACK_DAYS)} days)."
                    ),
                ),
                OnboardingStep(
                    title="3 · Polled, not pushed",
                    body=(
                        "RocketCyber has no webhooks. Every "
                        f"{interval_min} minutes Athena reads every open "
                        f"incident (created in the last "
                        f"{int(DEFAULT_OPEN_LOOKBACK_DAYS)} days) and the "
                        "incidents resolved or suppressed among those created "
                        f"in the last {int(DEFAULT_WINDOW_DAYS)} days; an "
                        "incident that was open and has left that list is "
                        "looked up by its creation date. An incident is stored "
                        "when it first appears, and again — as its own row, "
                        "e.g. 'RocketCyber · <title> — resolved' — when its "
                        "status or resolution time changes. A growing event "
                        "count or a PSA ticket being attached is not a new "
                        "row. On first connect, incidents created or updated "
                        f"in the last {int(DEFAULT_INITIAL_LOOKBACK_DAYS)} days "
                        "are imported; older ones are not (a later status "
                        "change to one is). Severity follows status, since "
                        "RocketCyber assigns none: open → high; resolved or "
                        "suppressed → medium, so a closure shows next to the "
                        "open row in the default feed. Errors and rate "
                        "limiting back off on their own (up to 15 minutes; "
                        "RocketCyber's Retry-After is honoured)."
                    ),
                ),
                OnboardingStep(
                    title="4 · Map RocketCyber customers to clients",
                    body=(
                        "Incidents route by the RocketCyber customer's numeric "
                        "account ID (accountId) — never its name. Athena "
                        "WAITS for this step before its first import: nothing "
                        "is imported until you save the tenant mapping, or "
                        f"for {grace_min} minutes after saving the "
                        "integration, whichever comes first. The picker lists "
                        "every customer (non-active ones are marked) and your "
                        "provider account itself — incidents about your own "
                        "MSP environment carry its ID, so map it to your "
                        "internal tenant. Map every customer whose RocketCyber "
                        "name differs from the client's name in Athena. A "
                        "customer you have NOT mapped is never dropped: when "
                        "its name matches exactly one existing client it is "
                        "linked to it; otherwise Athena creates a tenant for "
                        "it (marked 'pending review' under Settings → "
                        "Tenants); anything it cannot attribute is held in "
                        "quarantine for you to route. Changing a mapping later "
                        "routes NEW rows only — rows already stored stay where "
                        "they are. Pending and held counts show on this "
                        "integration's card."
                    ),
                ),
            ],
        )

    # ----- Lifecycle -----

    def start(self, instance_config: dict[str, Any]) -> None:
        if self._poller is not None:
            return None
        try:
            config = _config_from_credentials(instance_config, strict=False)
        except ValueError as exc:
            logger.error("[rocketcyber] start failed: invalid config: %s", exc)
            raise

        self._client = self._client_factory(config)
        if self._sink is None:
            from apps.octo.instances.tenant_map import MappingIngestSink
            self._sink = MappingIngestSink(
                SqliteIngestSink(), instance_config.get("_instance_id")
            )

        self._default_tenant_slug = instance_config.get("default_tenant_slug", "_unmapped")
        poll_interval = _bounded(
            instance_config.get("poll_interval_sec", self.default_poll_interval_sec),
            self.default_poll_interval_sec, 0.0, 86_400.0,
        ) or self.default_poll_interval_sec
        window_days = _bounded(
            instance_config.get("window_days", DEFAULT_WINDOW_DAYS),
            DEFAULT_WINDOW_DAYS, 1.0, MAX_WINDOW_DAYS,
        )
        lookback_days = _bounded(
            instance_config.get("initial_lookback_days", DEFAULT_INITIAL_LOOKBACK_DAYS),
            min(DEFAULT_INITIAL_LOOKBACK_DAYS, window_days), 0.0, window_days,
        )
        open_lookback_days = _bounded(
            instance_config.get("open_lookback_days", DEFAULT_OPEN_LOOKBACK_DAYS),
            DEFAULT_OPEN_LOOKBACK_DAYS, window_days, MAX_OPEN_LOOKBACK_DAYS,
        )
        first_import_grace_sec = _bounded(
            instance_config.get("first_import_grace_sec", DEFAULT_FIRST_IMPORT_GRACE_SEC),
            DEFAULT_FIRST_IMPORT_GRACE_SEC, 0.0, MAX_FIRST_IMPORT_GRACE_SEC,
        )

        self._poller = RocketCyberPoller(
            adapter=self,
            client=self._client,
            sink=self._sink,
            default_tenant_slug=self._default_tenant_slug,
            poll_interval_sec=poll_interval,
            window_days=window_days,
            initial_lookback_days=lookback_days,
            open_lookback_days=open_lookback_days,
            first_import_grace_sec=first_import_grace_sec,
            instance_id=instance_config.get("_instance_id"),
        )
        self._started_at = time.time()
        self._poller_loop = start_on_running_loop(
            self._poller.start, what="rocketcyber",
        )
        return None

    def stop(self) -> None:
        if self._poller is None:
            return None
        stop_poller(self._poller.stop, self._poller_loop, what="rocketcyber")
        self._poller_loop = None
        self._poller = None
        self._client = None
        self._started_at = None
        return None

    def poll_now(self) -> None:
        """Ask the poller to poll again now instead of finishing its wait."""
        if self._poller is not None:
            self._poller.poll_now()

    def health(self) -> HealthStatus:
        if self._poller is None:
            return HealthStatus(
                alive=False, last_event_at=None, lag_seconds=0.0, errors_last_hour=0,
            )
        return HealthStatus(
            alive=True,
            last_event_at=self._poller.last_event_at,
            lag_seconds=0.0,
            errors_last_hour=0,
            detail={
                "tracked_incidents": self._poller.tracked,
                "waiting_for_tenant_mapping": self._poller.holding_first_import,
                # When the waiting first import starts on its own (None when
                # not waiting) — the integration card says so.
                "first_import_at": self._poller.first_import_at,
            },
        )

    def rate_limit_hints(self) -> RateLimitHints:
        return RateLimitHints(retry_after_header="Retry-After")

    # ----- Core extraction -----

    def extract_event(self, raw_envelope: dict[str, Any]) -> CanonicalEvent:
        """One VERSION of a RocketCyber incident → CanonicalEvent.

          id                         → vendor_event_id (the same for every
                                       version of one incident)
          updatedAt | publishedAt |
          createdAt                  → received_at (when this version happened)
          status                     → severity (see presentation.py)
          title / status             → summary (the headline)
          accountId                  → route_to_tenant()
        Incidents name no host and carry no structured IOC."""
        payload_sha = self.compute_payload_sha256(raw_envelope)
        shown = present_incident(raw_envelope)
        iid = raw_envelope.get("id")
        iid_ok = isinstance(iid, int) and not isinstance(iid, bool) and iid > 0
        return TypedCanonicalEvent(
            # Never "" — an empty id would collide every id-less incident.
            vendor_event_id=str(iid) if iid_ok else payload_sha[:16],
            received_at=_received_at(raw_envelope),
            severity=severity_for_status(incident_status(raw_envelope)),
            indicator=None,
            indicator_type=None,
            source_host=None,
            summary=shown.headline,
            payload=raw_envelope,
            payload_sha256=payload_sha,
            event_type=shown.event_type,
        )

    @staticmethod
    def present_event(payload: dict[str, Any]) -> EventPresentation:
        """OPTIONAL capability (read on the CLASS by the API layer): headline +
        detail + site for a STORED payload."""
        return present_incident(payload)

    @staticmethod
    def psa_ticket(payload: dict[str, Any]) -> Optional[str]:
        """The PSA ticket number RocketCyber attached to this incident, if any
        (for a later ticket link-back)."""
        return _psa_ticket(payload)

    def route_to_tenant(self, raw_envelope: dict[str, Any]) -> str | None:
        """The incident's CUSTOMER account id, as a string — the mapping key.
        The provider's own id routes like any customer's. None when absent
        (the platform then uses the instance default, else quarantine)."""
        return _incident_account_id(raw_envelope)

    def vendor_tenant_label(self, raw_envelope: dict[str, Any]) -> str | None:
        """The customer NAME for `route_to_tenant()`'s id (vendor text — the
        caller cleans and bounds it)."""
        name = raw_envelope.get("accountName")
        return name if isinstance(name, str) and name.strip() else None

    def severity_map(self, raw_envelope: dict[str, Any]) -> Severity:
        return severity_for_status(incident_status(raw_envelope))

    def human_summary(self, event: CanonicalEvent) -> str:
        return event.summary

    def deep_link(
        self,
        event: CanonicalEvent,
        link_type: DeepLinkType,
    ) -> str | None:
        """Always None: RocketCyber documents no portal URL for an incident and
        none can be derived from the API's answers. The previous body built one
        from an env var and a guessed path."""
        return None

    def widget_definition(self) -> WidgetDefinitionRef | None:
        return WidgetDefinitionRef(widget_id="rocketcyber.incidents-feed")
