"""UniFiSourceAdapter — the UniFi fleet → OCTO through the cloud connector.

  - ONE credential: a Site Manager API key (unifi.ui.com → API), sent as
    `X-API-KEY` to api.ui.com only. Never logged, never in a health detail,
    an audit row or an error message.
  - Tenant unit: the UniFi SITE, keyed "<hostId>/<siteId>" — site ids collide
    across consoles (verified on a production fleet), so the console is part
    of the key everywhere. Many sites may map to one tenant; a site may be
    IGNORED (personal and non-client consoles). Discovery is TWO calls for
    the whole fleet (/v1/hosts + /v1/sites).
  - Unmapped and ignored sites are never polled beyond the fleet list, and
    there is NO default tenant: a signal lands in its site's mapped tenant or
    nowhere (`tenant_ids_are_slugs = False` keeps the platform from ever taking
    a vendor id for a slug). A name never maps a site.
  - Signals (events.db): IPS (HIGH), rogue AP (MEDIUM), admin access / config
    changes (audit), WAN failed / failover / restored and site-to-site VPN
    down (availability) — each with its OCSF class (ocsf.py), coalesced per
    site + subject per clock hour. Firewall blocks and client connect / roam
    are hourly roll-ups only (telemetry.db).
  - Feeds for entity resolution (feed.py): per mapped site, the fleet report
    (egress IPs + ASN, location, time zone), the client snapshots, the lease /
    WAN boundaries of the system log, the networks.
  - MIGRATION from the retired local-controller adapter (same vendor slug
    'unifi'): an instance saved with a controller URL is refused at start with
    what to do (Disable it, Add UniFi again with a Site Manager API key, map
    the sites); its stored events stay where they are and still read (the
    presenter knows their shape); its old site mappings (bare site ids, which
    collide across consoles) are never polled.
"""
from __future__ import annotations

import logging
import re
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

from apps.octo.adapters.unifi import store
from apps.octo.adapters.unifi.client import (
    DEFAULT_API_URL,
    PORTAL_URL,
    UniFiAuthError,
    UniFiBusyError,
    UniFiClient,
    UniFiClientError,
    UniFiConfig,
    UniFiThrottledError,
    valid_host_id,
    valid_internal_ref,
)
from apps.octo.adapters.unifi.limiter import (
    DEFAULT_MIN_SPACING_SEC,
    PRIORITY_DISCOVERY,
    bounded_spacing,
)
from apps.octo.adapters.unifi.poller import (
    DEFAULT_CLIENTS_INTERVAL_SEC,
    DEFAULT_FLEET_INTERVAL_SEC,
    DEFAULT_SYSLOG_INTERVAL_SEC,
    MAX_SYSLOG_INTERVAL_SEC,
    MIN_SYSLOG_INTERVAL_SEC,
    UniFiPoller,
    build_fleet,
    split_scope,
    tenant_label,
)
from apps.octo.adapters.unifi.presentation import (
    EVENT_TYPES,
    event_type_of,
    indicator_of,
    present,
)
from apps.octo.ingest import IngestSink, SqliteIngestSink
from apps.octo.ingest.presentation import EventPresentation, TypedCanonicalEvent
from apps.octo.ingest.timestamps import normalize_timestamp
from apps.octo.instances.poller_lifecycle import start_on_running_loop, stop_poller
from apps.octo.instances import vendor_links
from apps.octo.instances.vendor_links import KeptIdChars, VendorLinkSpec

logger = logging.getLogger(__name__)

KEY_FIELD = "UNIFI_API_KEY"
LEGACY_URL_FIELD = "UNIFI_CONTROLLER_URL"
API_MAX_WAIT_SEC = 20.0
LEGACY_MESSAGE = (
    "This UniFi integration was saved for the RETIRED local-controller API (it has a "
    "controller URL). UniFi now connects through the cloud Site Manager API: Disable this "
    "integration, then Add UniFi again with a Site Manager API key from unifi.ui.com → API, "
    "and map each site to its client. The events it stored are kept and still shown."
)

# A console's host id as the Site Manager API gives it — and as the portal's
# own address bar shows it: hex, a colon, digits. Only an id of exactly this
# shape keeps its colon in a link (`vendor_links.KeptIdChars`).
PORTAL_HOST_ID_RE = re.compile(r"[0-9A-Fa-f]{20,120}:[0-9]{1,12}")

LINK_SPEC = VendorLinkSpec(
    portal_name="UniFi Site Manager",
    allowed_domain="ui.com",
    # The site's dashboard on its console: the alert placeholder carries the
    # console's hostId, the site placeholder its internal reference
    # ('default' for a console's only site). VERIFIED 2026-10-08 against a
    # live portal address copied from the browser —
    #   https://unifi.ui.com/consoles/<hex>:<digits>/network/default/settings/…
    # — the hostId's ':' as it is: the same address with '%3A' (what an id
    # encoded whole gave until v0.17.4) opens "Access denied".
    default_alert_path="/consoles/{alert_uid}/network/{site_uid}/dashboard",
    paths_verified=True,
    keep_unencoded=(KeptIdChars("alert_uid", ":", PORTAL_HOST_ID_RE),),
)

_SEVERITIES = ("low", "medium", "high", "critical")


def _config_from_credentials(creds: dict[str, Any]) -> UniFiConfig:
    if creds.get(LEGACY_URL_FIELD):
        raise ValueError(LEGACY_MESSAGE)
    api_key = creds.get(KEY_FIELD)
    api_key = api_key.strip() if isinstance(api_key, str) else ""
    if not api_key:
        raise ValueError(f"{KEY_FIELD} is required (a Site Manager API key from unifi.ui.com → API)")
    if any(not ("!" <= ch <= "~") for ch in api_key) or len(api_key) > 256:
        raise ValueError(
            f"{KEY_FIELD} contains a space, a line break or an unusual character — paste the "
            "key again as one line, exactly as unifi.ui.com → API shows it"
        )
    return UniFiConfig(
        api_key=api_key, api_url=DEFAULT_API_URL,
        min_spacing_sec=bounded_spacing(creds.get("min_spacing_sec", DEFAULT_MIN_SPACING_SEC)),
    )


def _bounded(value: Any, default: float, low: float, high: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if low <= number <= high else default


def _m(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _severity(payload: dict[str, Any]) -> Severity:
    level = _m(payload.get("signal")).get("level")
    return level if level in _SEVERITIES else "info"  # type: ignore[return-value]


def _received_at(payload: dict[str, Any]) -> str:
    """The event's OWN time (the console's), a pure function of the payload."""
    for value in (_m(payload.get("event")).get("timestamp"), payload.get("timestamp"),
                  payload.get("time")):
        ts = normalize_timestamp(value, naive_is_utc=True)
        if ts:
            return ts
    return ""


class UniFiSourceAdapter(BaseSourceAdapter):
    """UniFi fleet (Site Manager connector) → OCTO."""

    vendor_slug = "unifi"
    vendor_display_name = "UniFi Network"
    vendor_logo_path = "/logos/unifi.svg"
    vendor_category = "network"
    auth_model = "api-key"
    delivery_mode = "poll"
    availability = "available"
    compliance_categories: list[ComplianceCategory] = ["general"]
    supports_tenant_discovery = True
    tenant_ids_are_slugs = False
    reports_vendor_contact = True
    default_poll_interval_sec = DEFAULT_SYSLOG_INTERVAL_SEC
    first_import_auto_start = False

    def __init__(
        self,
        *,
        sink: Optional[IngestSink] = None,
        client_factory: Optional[Callable[[UniFiConfig], UniFiClient]] = None,
        now: Optional[Callable[[], Any]] = None,
        consumer: Optional[Any] = None,
    ) -> None:
        super().__init__() if hasattr(BaseSourceAdapter, "__init__") else None
        self._sink = sink
        self._client_factory = client_factory or UniFiClient
        self._now = now
        self._consumer = consumer
        self._client: Optional[UniFiClient] = None
        self._poller: Optional[UniFiPoller] = None
        self._poller_loop = None
        self._started_at: Optional[float] = None
        self._instance_id: Optional[int] = None

    # ----- Onboarding -----

    def credential_shape(self) -> list[CredentialField]:
        return [
            CredentialField(
                name=KEY_FIELD,
                label="UniFi Site Manager API key",
                kind="password",
                description=(
                    "From unifi.ui.com → API: ONE key sees every console of the account "
                    "(through UniFi's cloud connector — no port forward, no local "
                    "controller URL). Each site is mapped to a client in the next step. "
                    "Athena only reads."
                ),
            ),
        ]

    def tenant_mapping_shape(self) -> TenantMappingShape:
        return TenantMappingShape(
            fetch_method="api",
            fetch_endpoint="/v1/sites",
            vendor_tenant_id_field="hostId/siteId",
            vendor_tenant_label_field="meta.desc",
            tenant_noun="site",
            id_help=(
                "The console and the site together — '<hostId>/<siteId>' as UniFi's site "
                "list gives them. A site id alone is NOT unique (every single-site console "
                "has the same one), and the site NAME never matches. Pick the site from the "
                "list; its console and location are shown next to it."
            ),
        )

    def _api_client(self, credentials: dict[str, Any]) -> UniFiClient:
        return self._client_factory(_config_from_credentials(credentials))

    def list_vendor_tenants(self, credentials: dict[str, Any]) -> VendorTenantListing:
        """Every site of every console — TWO calls through the shared limiter
        at discovery priority."""
        try:
            client = self._api_client(credentials)
        except ValueError as exc:
            raise VendorTenantListError("transport", str(exc)) from exc
        try:
            hosts = client.list_hosts(priority=PRIORITY_DISCOVERY, max_wait_sec=API_MAX_WAIT_SEC)
            sites = client.list_sites(priority=PRIORITY_DISCOVERY, max_wait_sec=API_MAX_WAIT_SEC)
        except UniFiAuthError as exc:
            raise VendorTenantListError("auth", f"UniFi rejected the stored API key: {exc}") from exc
        except (UniFiThrottledError, UniFiBusyError) as exc:
            raise VendorTenantListError(
                "transport", f"{exc}. The list is asked again when you press Reload.") from exc
        except UniFiClientError as exc:
            raise VendorTenantListError(
                "transport", f"Could not read the sites from UniFi: {exc}") from exc
        fleet = build_fleet(hosts.items, sites.items)
        return VendorTenantListing(
            tenants=[VendorTenant(id=scope, label=tenant_label(info))
                     for scope, info in sorted(fleet.items())],
            truncated=hosts.truncated or sites.truncated,
        )

    def smoke_test(self, credentials: dict[str, Any]) -> SmokeResult:
        try:
            client = self._api_client(credentials)
        except ValueError as exc:
            return SmokeResult(ok=False, message=str(exc))
        ok, detail, _n = client.check_access(max_wait_sec=API_MAX_WAIT_SEC)
        return SmokeResult(ok=ok, message=detail)

    def onboarding(self, webhook_url: str | None = None) -> Onboarding | None:
        return Onboarding(
            summary=(
                "UniFi tells Athena, for every console of the account, where each site is, "
                "which public address is its internet connection, which LAN device had which "
                "address when, and what its gateway's IPS, firewall and administrators did. "
                "One cloud API key; Athena only reads, about one call a second at most."
            ),
            webhook_url=None,
            steps=[
                OnboardingStep(
                    title="1 · Paste a Site Manager API key",
                    body=(
                        "At unifi.ui.com → API, create a key and paste it into 'UniFi Site "
                        "Manager API key'. Test connection reads the console list (ONE call)."
                    ),
                ),
                OnboardingStep(
                    title="2 · Map each site to its client — or ignore it",
                    body=(
                        "Every site of every console is listed with its console and its "
                        "location. Pick the client for each site, one at a time (several "
                        "sites may belong to one client). There is no bulk accept: two "
                        "businesses can share a name, so a matching name is only a hint — "
                        "check the location. Mark personal and non-client consoles 'Ignore'. "
                        "Nothing is read from a site until it is mapped, and Athena never "
                        "creates a client from a UniFi site."
                    ),
                ),
                OnboardingStep(
                    title="3 · What becomes an alert",
                    body=(
                        "IPS detections and blocks (high — 'detected, NOT blocked' first), a "
                        "rogue access point (medium), administrator access and configuration "
                        "changes on a client's console (audit), an internet connection that "
                        "failed, failed over or came back, and a site-to-site VPN that went "
                        "down (availability). Repeats within an hour are counted on the first "
                        "alert. Firewall blocks and client connects / roams are only counted "
                        "per hour. A newly mapped site back-fills its last 24 hours."
                    ),
                ),
                OnboardingStep(
                    title="4 · Gentle on UniFi",
                    body=(
                        "Every call with this key — the 5-minute fleet poll (two calls for "
                        "every console), each mapped site's system log and client list every 5 "
                        "minutes, discovery — goes through ONE limiter, at least 1 s apart, "
                        "security first. An HTTP 429 is read as rate limiting (calls wait, "
                        "15 s doubling to 10 min), never as a broken key."
                    ),
                ),
            ],
        )

    # ----- Lifecycle -----

    def start(self, instance_config: dict[str, Any]) -> None:
        if self._poller is not None:
            return None
        config = _config_from_credentials(instance_config)
        self._client = self._client_factory(config)
        if self._sink is None:
            self._sink = SqliteIngestSink(publish_to_stream=False)
        kwargs: dict[str, Any] = {}
        if self._now is not None:
            kwargs["now"] = self._now
        self._instance_id = instance_config.get("_instance_id")
        self._poller = UniFiPoller(
            adapter=self, client=self._client, sink=self._sink, instance_id=self._instance_id,
            fleet_interval_sec=_bounded(instance_config.get("fleet_interval_sec"),
                                        DEFAULT_FLEET_INTERVAL_SEC, 60.0, 3600.0),
            syslog_interval_sec=_bounded(instance_config.get("syslog_interval_sec"),
                                         DEFAULT_SYSLOG_INTERVAL_SEC, MIN_SYSLOG_INTERVAL_SEC,
                                         MAX_SYSLOG_INTERVAL_SEC),
            clients_interval_sec=_bounded(instance_config.get("clients_interval_sec"),
                                          DEFAULT_CLIENTS_INTERVAL_SEC, 60.0, 3600.0),
            consumer=self._consumer, **kwargs,
        )
        self._started_at = time.time()
        self._poller_loop = start_on_running_loop(self._poller.start, what="unifi")
        return None

    def stop(self) -> None:
        if self._poller is None:
            return None
        stop_poller(self._poller.stop, self._poller_loop, what="unifi")
        self._poller_loop = None
        self._poller = None
        self._client = None
        self._started_at = None
        return None

    def poll_now(self) -> None:
        if self._poller is not None:
            self._poller.poll_now()

    @property
    def poller(self) -> Optional[UniFiPoller]:
        return self._poller

    def health(self) -> HealthStatus:
        if self._poller is None:
            return HealthStatus(alive=False, last_event_at=None, lag_seconds=0.0,
                                errors_last_hour=0)
        snap = self._poller.snapshot()
        mapped = int(snap.get("mapped") or 0)
        if not mapped and self._instance_id is not None:
            mapped = len(self._valid_mappings(self._instance_id))
        return HealthStatus(
            alive=True, last_event_at=self._poller.last_event_at, lag_seconds=0.0,
            errors_last_hour=0,
            detail={"waiting_for_tenant_mapping": mapped == 0, "first_import_at": None,
                    "unifi": snap},
        )

    @staticmethod
    def _valid_mappings(instance_id: int) -> list[Any]:
        from apps.octo.instances import tenant_map

        try:
            return [m for m in tenant_map.get_mappings(instance_id)
                    if split_scope(m.vendor_tenant_id)]
        except Exception:  # noqa: BLE001
            return []

    def site_summary(self, instance_id: int) -> dict[str, Any]:
        """The Integrations card's counts — local state only (the poller's
        last fleet poll, the tenant map, the ignore list)."""
        from apps.octo.instances import ignored_tenants, tenant_map

        snap = self._poller.snapshot() if self._poller is not None else {}
        try:
            all_mappings = tenant_map.get_mappings(instance_id)
        except Exception:  # noqa: BLE001 — a card never fails
            all_mappings = []
        mapped_ids = {m.vendor_tenant_id for m in all_mappings if split_scope(m.vendor_tenant_id)}
        legacy = sum(1 for m in all_mappings if not split_scope(m.vendor_tenant_id))
        ignored = ignored_tenants.ignored_ids(instance_id) - mapped_ids
        known_ids = snap.get("known_ids")
        unmapped = (len(set(known_ids) - mapped_ids - ignored)
                    if isinstance(known_ids, list) else None)
        return {
            "known": snap.get("known"),
            "known_at": snap.get("known_at"),
            "consoles": int(snap.get("consoles") or 0),
            "consoles_offline": int(snap.get("consoles_offline") or 0),
            "mapped": len(mapped_ids),
            "ignored": len(ignored),
            "unmapped": unmapped,
            "gateways_offline": int(snap.get("gateways_offline") or 0),
            "problems": int(snap.get("problems") or 0),
            "legacy_mappings": legacy,
            "throttled": bool(snap.get("throttled")),
            "throttled_for_sec": int(snap.get("throttled_for_sec") or 0),
            "calls_per_hour_planned": snap.get("calls_per_hour_planned"),
        }

    def rate_limit_hints(self) -> RateLimitHints:
        return RateLimitHints(requests_per_second=1.0 / DEFAULT_MIN_SPACING_SEC)

    # ----- Core extraction -----

    def extract_event(self, raw_envelope: dict[str, Any]) -> CanonicalEvent:
        """One UniFi signal (built by the poller) → CanonicalEvent. The
        public remote address of an IPS event is the indicator."""
        payload_sha = self.compute_payload_sha256(raw_envelope)
        shown = present(raw_envelope)
        vid = raw_envelope.get("vendor_event_id")
        if not (isinstance(vid, str) and vid and len(vid) <= 128):
            legacy = raw_envelope.get("_id") or raw_envelope.get("id")
            vid = str(legacy)[:128] if legacy else payload_sha[:32]
        indicator = indicator_of(raw_envelope)
        return TypedCanonicalEvent(
            vendor_event_id=vid,
            received_at=_received_at(raw_envelope),
            severity=_severity(raw_envelope),
            indicator=indicator,
            indicator_type="ip" if indicator else None,
            source_host=shown.device or shown.site,
            summary=shown.headline,
            payload=raw_envelope,
            payload_sha256=payload_sha,
            event_type=shown.event_type,
        )

    @staticmethod
    def present_event(payload: dict[str, Any]) -> EventPresentation:
        return present(payload)

    @staticmethod
    def presentation_suffixes(client_slug: str, rows: list[tuple[int, dict]]) -> dict[int, str]:
        """"Seen N times this hour" from the tenant's coalescing ledger
        (telemetry.db; never a vendor call)."""
        ids = [eid for eid, payload in rows if event_type_of(payload) in EVENT_TYPES]
        out: dict[int, str] = {}
        for eid, h in store.hits_for_events(client_slug, ids).items():
            if h.hits > 1:
                out[eid] = (f"Seen {h.hits} times in the hour from {h.hour[11:16]} UTC — only "
                            "the first raised this alert.")
        return out

    def route_to_tenant(self, raw_envelope: dict[str, Any]) -> str | None:
        """The SITE (console + site) — never a default tenant."""
        scope = raw_envelope.get("scope")
        return scope if split_scope(scope) else None

    def vendor_tenant_label(self, raw_envelope: dict[str, Any]) -> str | None:
        name = raw_envelope.get("site_name")
        return name if isinstance(name, str) and name.strip() else None

    def severity_map(self, raw_envelope: dict[str, Any]) -> Severity:
        return _severity(raw_envelope)

    def human_summary(self, event: CanonicalEvent) -> str:
        return event.summary

    def deep_link(self, event: CanonicalEvent, link_type: DeepLinkType) -> str | None:
        """The site's dashboard on its console — built like every "Open in"
        link (`vendor_links.build_url`: the hostId keeps its ':')."""
        ids = self.vendor_link_ids(event.payload or {})
        if not ids or link_type not in ("alert", "tenant"):
            return None
        return vendor_links.build_url(PORTAL_URL, LINK_SPEC.default_alert_path, ids,
                                      spec=LINK_SPEC)

    @staticmethod
    def vendor_link_spec() -> VendorLinkSpec:
        return LINK_SPEC

    @staticmethod
    def vendor_link_ids(payload: dict[str, Any]) -> dict[str, str]:
        p = payload if isinstance(payload, dict) else {}
        host = valid_host_id(p.get("host_id"))
        ref = valid_internal_ref(p.get("site_ref"))
        return {"alert_uid": host, "site_uid": ref} if host and ref else {}

    @staticmethod
    def derive_portal_base(config: dict[str, Any]) -> str | None:
        return PORTAL_URL

    def widget_definition(self) -> WidgetDefinitionRef | None:
        return None
