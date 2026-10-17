"""NextDNSSourceAdapter — NextDNS → OCTO, the cheap question first.

  - ONE credential: the account API key (`X-Api-Key`), entered in the
    wizard, stored in the platform credential store. Never logged, never in
    a health detail, an audit row or an error message.
  - Tenant unit: the NextDNS PROFILE. Many profiles may map to one tenant (a
    client with several sites). Discovery is ONE call (GET /profiles).
  - Unmapped profiles are never polled; NO tenant auto-create — a signal
    lands in its profile's mapped tenant or nowhere
    (`tenant_ids_are_slugs = False` also keeps the platform's generic
    delivery from ever taking a 6-character profile id for a client slug).
  - Poll only (NextDNS has no webhooks): poller.py.
  - Signals: security blocks (coalesced), protection lapsed / restored, and
    ONE fleet-wide outage signal in the operator's own (internal) tenant.
    Everything else stays at NextDNS; hourly counts go to telemetry.db.
  - Deep link: the profile's logs page, https://my.nextdns.io/<profile>/logs.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
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

from apps.octo.adapters.nextdns.client import (
    DEFAULT_API_URL,
    PORTAL_URL,
    NextDNSAuthError,
    NextDNSBusyError,
    NextDNSClient,
    NextDNSClientError,
    NextDNSConfig,
    NextDNSThrottledError,
    valid_profile_id,
)
from apps.octo.adapters.nextdns.limiter import (
    DEFAULT_MIN_SPACING_SEC,
    PRIORITY_DISCOVERY,
    bounded_spacing,
)
from apps.octo.adapters.nextdns.poller import (
    ACTIVE_THRESHOLD,
    DEFAULT_OVERLAP_SEC,
    DEFAULT_PENDING_CHECK_SEC,
    DEFAULT_POLL_INTERVAL_SEC,
    MAX_POLL_INTERVAL_SEC,
    MIN_POLL_INTERVAL_SEC,
    NextDNSPoller,
)
from apps.octo.adapters.nextdns.presentation import (
    EVENT_BLOCK,
    event_type_of,
    indicator_of,
    present,
)
from apps.octo.adapters.nextdns import store
from apps.octo.ingest import IngestSink, SqliteIngestSink
from apps.octo.ingest.presentation import EventPresentation, TypedCanonicalEvent
from apps.octo.ingest.timestamps import normalize_timestamp
from apps.octo.instances.poller_lifecycle import start_on_running_loop, stop_poller
from apps.octo.instances.vendor_links import VendorLinkSpec

logger = logging.getLogger(__name__)

KEY_FIELD = "NEXTDNS_API_KEY"
# An API request waits at most this long for the shared limiter (discovery,
# Test connection); the poller is never made to wait by it.
API_MAX_WAIT_SEC = 20.0
# On-demand investigation budget per running instance: one search at a time,
# at most this many NextDNS calls per rolling hour (≈ 2 minutes of the
# limiter), and a whole search never runs longer than the deadline. An
# analyst looping searches can therefore never hold the poller back.
INVESTIGATION_CALLS_PER_HOUR = 60
INVESTIGATION_DEADLINE_SEC = 60.0

LINK_SPEC = VendorLinkSpec(
    portal_name="NextDNS",
    allowed_domain="nextdns.io",
    # The profile's logs page (verified live 2026-09-30). The link system's
    # alert placeholder carries the PROFILE id: NextDNS has no per-query page.
    default_alert_path="/{alert_uid}/logs",
    paths_verified=True,
)

_SEVERITY_BY_KIND: dict[str, Severity] = {
    "protection_lapsed": "medium",
    "protection_restored": "low",
    "fleet_dns_outage": "high",
    "device_silent": "medium",
    "device_restored": "low",
}


def _config_from_credentials(creds: dict[str, Any]) -> NextDNSConfig:
    api_key = creds.get(KEY_FIELD)
    api_key = api_key.strip() if isinstance(api_key, str) else ""
    if not api_key:
        raise ValueError(f"{KEY_FIELD} is required (the NextDNS account API key)")
    if any(not ("!" <= ch <= "~") for ch in api_key) or len(api_key) > 256:
        raise ValueError(
            f"{KEY_FIELD} contains a space, a line break or an unusual character — "
            "paste the key again as one line, exactly as my.nextdns.io → Account → "
            "API shows it"
        )
    return NextDNSConfig(
        api_key=api_key,
        api_url=DEFAULT_API_URL,
        min_spacing_sec=bounded_spacing(creds.get("min_spacing_sec", DEFAULT_MIN_SPACING_SEC)),
    )


def _bounded(value: Any, default: float, low: float, high: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if not (low <= number <= high):
        return default
    return number


def _severity(payload: dict[str, Any]) -> Severity:
    kind = payload.get("kind")
    if isinstance(kind, str) and kind in _SEVERITY_BY_KIND:
        return _SEVERITY_BY_KIND[kind]
    signal = payload.get("signal") if isinstance(payload.get("signal"), dict) else {}
    level = signal.get("level")
    return level if level in ("high", "medium", "low") else "low"   # type: ignore[return-value]


def _received_at(payload: dict[str, Any]) -> str:
    """The record's own time: the blocked line's timestamp, or the hour a
    lapse / restoration was detected — a pure function of the payload, so a
    re-read record has the same (payload, time) identity."""
    log = payload.get("log") if isinstance(payload.get("log"), dict) else {}
    for value in (log.get("timestamp"), payload.get("detected_at")):
        ts = normalize_timestamp(value, naive_is_utc=True)
        if ts:
            return ts
    return ""


class NextDNSSourceAdapter(BaseSourceAdapter):
    """NextDNS → OCTO (DNS security blocks + protection health per profile)."""

    vendor_slug = "nextdns"
    vendor_display_name = "NextDNS"
    vendor_logo_path = "/logos/nextdns.svg"
    vendor_category = "network"
    auth_model = "api-key"
    delivery_mode = "poll"
    availability = "available"
    compliance_categories: list[ComplianceCategory] = ["hipaa-friendly", "general"]
    supports_tenant_discovery = True
    tenant_ids_are_slugs = False
    reports_vendor_contact = True
    default_poll_interval_sec = DEFAULT_POLL_INTERVAL_SEC
    # The card's first-import wait has no deadline here: nothing is imported
    # until a profile is mapped (no auto-create), so it never "starts on its
    # own".
    first_import_auto_start = False

    def __init__(
        self,
        *,
        sink: Optional[IngestSink] = None,
        client_factory: Optional[Callable[[NextDNSConfig], NextDNSClient]] = None,
        now: Optional[Callable[[], Any]] = None,
    ) -> None:
        super().__init__() if hasattr(BaseSourceAdapter, "__init__") else None
        self._sink = sink
        self._client_factory = client_factory or NextDNSClient
        self._now = now
        self._client: Optional[NextDNSClient] = None
        self._poller: Optional[NextDNSPoller] = None
        self._poller_loop = None
        self._started_at: Optional[float] = None
        self._instance_id: Optional[int] = None
        self._investigating = threading.Lock()
        self._investigation_calls: deque[float] = deque()

    # ----- Onboarding -----

    def credential_shape(self) -> list[CredentialField]:
        return [
            CredentialField(
                name=KEY_FIELD,
                label="NextDNS API key",
                kind="password",
                description=(
                    "The ACCOUNT API key from my.nextdns.io → Account → API. One key "
                    "sees every profile of the account; each profile is mapped to a "
                    "client in the next step. Athena only reads."
                ),
            ),
        ]

    def tenant_mapping_shape(self) -> TenantMappingShape:
        return TenantMappingShape(
            fetch_method="api",
            fetch_endpoint="/profiles",
            vendor_tenant_id_field="id",
            vendor_tenant_label_field="name",
            tenant_noun="profile",
            id_help=(
                "The NextDNS profile ID — the short code in the address "
                "my.nextdns.io/<profile>/setup (e.g. abc123). The profile NAME never "
                "matches. Several profiles may map to one client (one per site)."
            ),
        )

    def _api_client(self, credentials: dict[str, Any]) -> NextDNSClient:
        return self._client_factory(_config_from_credentials(credentials))

    def list_vendor_tenants(self, credentials: dict[str, Any]) -> VendorTenantListing:
        """Every profile of the account — ONE call, through the key's shared
        limiter at discovery priority (never per-profile reads)."""
        try:
            client = self._api_client(credentials)
        except ValueError as exc:
            raise VendorTenantListError("transport", str(exc)) from exc
        try:
            profiles = client.list_profiles(priority=PRIORITY_DISCOVERY,
                                            max_wait_sec=API_MAX_WAIT_SEC)
        except NextDNSAuthError as exc:
            raise VendorTenantListError(
                "auth", f"NextDNS rejected the stored API key: {exc}",
            ) from exc
        except (NextDNSThrottledError, NextDNSBusyError) as exc:
            raise VendorTenantListError(
                "transport", f"{exc}. The list is asked again when you press Reload.",
            ) from exc
        except NextDNSClientError as exc:
            raise VendorTenantListError(
                "transport", f"Could not read profiles from NextDNS: {exc}",
            ) from exc
        tenants = [VendorTenant(id=p.id, label=p.name or f"Profile {p.id}") for p in profiles]
        return VendorTenantListing(tenants=tenants, truncated=False)

    def smoke_test(self, credentials: dict[str, Any]) -> SmokeResult:
        try:
            client = self._api_client(credentials)
        except ValueError as exc:
            return SmokeResult(ok=False, message=str(exc))
        ok, detail, _count = client.check_access(max_wait_sec=API_MAX_WAIT_SEC)
        return SmokeResult(ok=ok, message=detail)

    def onboarding(self, webhook_url: str | None = None) -> Onboarding | None:
        minutes = int(DEFAULT_POLL_INTERVAL_SEC // 60)
        return Onboarding(
            summary=(
                "NextDNS filters each site's DNS. Athena asks NextDNS the cheap "
                "question first: every "
                f"{minutes} minutes, per MAPPED profile, 'were any SECURITY blocks "
                "in this window?' — and only then reads those blocked lookups. The "
                "full DNS log never comes into Athena. It needs ONE read-only use of "
                "your account API key."
            ),
            webhook_url=None,
            steps=[
                OnboardingStep(
                    title="1 · Paste the account API key",
                    body=(
                        "At my.nextdns.io → Account → API, copy the API key and paste it "
                        "into 'NextDNS API key'. Test connection reads your profile list "
                        "(ONE call) — never each profile."
                    ),
                ),
                OnboardingStep(
                    title="2 · Map profiles to clients — or ignore them",
                    body=(
                        "Nothing is polled until you map a profile to a client: Athena "
                        "WAITS for this step, and an unmapped profile is never polled "
                        "(personal and test profiles stay out of Athena). Athena suggests "
                        "the client whose name matches each profile; several profiles "
                        "may map to one client (one per site). Mark a profile 'Ignore' so "
                        "it stops being listed as needing attention. Athena never creates "
                        "a client from a NextDNS profile."
                    ),
                ),
                OnboardingStep(
                    title="3 · What becomes an alert",
                    body=(
                        "Only SECURITY blocks: threat intelligence, Google Safe Browsing, "
                        "cryptojacking, DGA, CSAM, DNS tunnelling / exfiltration (high); "
                        "AI threat detection, typosquatting, homographs, new / dynamic / "
                        "parked / free-hosting domains, and filter-evasion attempts "
                        "(VPN / proxy / Tor) (medium); DNS-rebinding protection (low). "
                        "Ad, tracker, TLD, denylist and parental-control blocks are only "
                        "counted. High: the first block per device, domain and reason in "
                        "each clock hour is an alert (DGA: per device, whatever the "
                        "domain). Medium and low: ONE alert per device and reason per day, "
                        "whatever the domain. Repeats are counted on it — lookups and "
                        "distinct domains. A newly mapped profile back-fills the last 24 "
                        "hours of security blocks."
                    ),
                ),
                OnboardingStep(
                    title="4 · Protection health",
                    body=(
                        "A profile that has had at least "
                        f"{ACTIVE_THRESHOLD} queries in 24 hours is ACTIVE; one with fewer "
                        "is PENDING (rollout not done — silent, checked every 6 hours). "
                        "Athena learns each site's week — the same hours of the previous 3 "
                        "weeks, read once from the profile's own NextDNS history, so from "
                        "the first day — and an active profile raises ONE alert ('DNS "
                        "filtering stopped reporting — check the site's UniFi DNS/NextDNS "
                        "setup') only when it is silent while it normally has traffic: 2 "
                        "silent hours in a row at hours it is normally busy, or a whole "
                        "silent day it normally has queries in. Nights, weekends and closed "
                        "days a site is always silent in never count (a public holiday on "
                        "a normally busy day may). Athena says so again when queries "
                        "resume. A site silent for 24 hours at a time it normally has "
                        "queries, with at least 100 in the 7 days before it was mapped, "
                        "starts as stopped. When half the sites stop at once, Athena "
                        "raises ONE fleet-wide alert in your own (internal) tenant and "
                        "groups the sites under it."
                    ),
                ),
                OnboardingStep(
                    title="5 · Gentle on NextDNS",
                    body=(
                        "NextDNS answers a burst of requests with HTTP 403. Every call "
                        "Athena makes with this key — polling, discovery, an analyst's "
                        "investigation search — is spaced at least 2 seconds apart; a "
                        "403 from a key that has worked is read as rate limiting (the "
                        "card shows 'throttled', and Athena backs off from 15 s to 10 min "
                        "for as long as it lasts), never as a broken key."
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
        interval = _bounded(
            instance_config.get("poll_interval_sec", DEFAULT_POLL_INTERVAL_SEC),
            DEFAULT_POLL_INTERVAL_SEC, MIN_POLL_INTERVAL_SEC, MAX_POLL_INTERVAL_SEC,
        )
        overlap = _bounded(instance_config.get("overlap_sec", DEFAULT_OVERLAP_SEC),
                           DEFAULT_OVERLAP_SEC, 0.0, 3600.0)
        pending = _bounded(instance_config.get("pending_check_sec", DEFAULT_PENDING_CHECK_SEC),
                           DEFAULT_PENDING_CHECK_SEC, 600.0, 7 * 86400.0)
        kwargs: dict[str, Any] = {}
        if self._now is not None:
            kwargs["now"] = self._now
        self._instance_id = instance_config.get("_instance_id")
        self._poller = NextDNSPoller(
            adapter=self,
            client=self._client,
            sink=self._sink,
            instance_id=instance_config.get("_instance_id"),
            poll_interval_sec=interval,
            overlap_sec=overlap,
            pending_check_sec=pending,
            **kwargs,
        )
        self._started_at = time.time()
        self._poller_loop = start_on_running_loop(self._poller.start, what="nextdns")
        return None

    def stop(self) -> None:
        if self._poller is None:
            return None
        stop_poller(self._poller.stop, self._poller_loop, what="nextdns")
        self._poller_loop = None
        self._poller = None
        self._client = None
        self._started_at = None
        return None

    def poll_now(self) -> None:
        if self._poller is not None:
            self._poller.poll_now()

    @property
    def poller(self) -> Optional[NextDNSPoller]:
        return self._poller

    def health(self) -> HealthStatus:
        if self._poller is None:
            return HealthStatus(alive=False, last_event_at=None, lag_seconds=0.0,
                                errors_last_hour=0)
        snap = self._poller.snapshot()
        mapped = int(snap.get("mapped") or 0)
        if not mapped and self._instance_id is not None:
            # Saved a moment ago, before the poller's next cycle: the map
            # itself answers (a local read, never a vendor call).
            from apps.octo.instances import tenant_map

            try:
                mapped = len(tenant_map.get_mappings(self._instance_id))
            except Exception:  # noqa: BLE001
                mapped = 0
        return HealthStatus(
            alive=True,
            last_event_at=self._poller.last_event_at,
            lag_seconds=0.0,
            errors_last_hour=0,
            detail={
                # R1: nothing is imported until a profile is mapped — and it
                # never starts on its own (no deadline).
                "waiting_for_tenant_mapping": mapped == 0,
                "first_import_at": None,
                "nextdns": snap,
            },
        )

    # ----- read-side capabilities of a RUNNING instance (never a vendor call
    # except `investigate`, which is an analyst's explicit request) -----

    def card_summary(self, instance_id: int) -> dict[str, Any]:
        """Counts for the Integrations card: known / mapped / ignored /
        unmapped profiles, active / pending / lapsed, throttle state. Local
        state only (the poller's last discovery, the tenant map, the ignore
        list)."""
        from apps.octo.instances import ignored_tenants, tenant_map

        snap = self._poller.snapshot() if self._poller is not None else {}
        try:
            mapped_ids = {m.vendor_tenant_id for m in tenant_map.get_mappings(instance_id)}
        except Exception:  # noqa: BLE001 — a card never fails
            mapped_ids = set()
        ignored = ignored_tenants.ignored_ids(instance_id) - mapped_ids
        known_ids = snap.get("known_ids")
        unmapped: Optional[int] = None
        if isinstance(known_ids, list):
            unmapped = len(set(known_ids) - mapped_ids - ignored)
        counts = snap.get("counts") or {}
        return {
            "known": snap.get("known"),
            "known_at": snap.get("known_at"),
            "mapped": len(mapped_ids),
            "ignored": len(ignored),
            "unmapped": unmapped,
            "active": int(counts.get("active", 0)),
            "pending": int(counts.get("pending", 0)),
            "lapsed": int(counts.get("lapsed", 0)),
            "checking": int(counts.get("new", 0)),
            "missing": int(snap.get("missing") or 0),
            "problems": int(snap.get("problems") or 0),
            "rollup_lag_hours": int(snap.get("rollup_lag_hours") or 0),
            "analytics_gaps": len(snap.get("analytics_gaps") or []),
            "fleet_outage_sites": int((snap.get("fleet_outage") or {}).get("sites") or 0),
            "fleet_outage_watched": int((snap.get("fleet_outage") or {}).get("watched") or 0),
            "fleet_outage_tenant": (snap.get("fleet_outage") or {}).get("tenant"),
            "throttled": bool(snap.get("throttled")),
            "throttled_for_sec": int(snap.get("throttled_for_sec") or 0),
            "stretched": bool(snap.get("stretched")),
            "calls_per_hour_planned": snap.get("calls_per_hour_planned"),
        }

    def protection(self, allowed_slugs: Optional[set[str]] = None) -> dict[str, Any]:
        """Per-profile protection state for source health, limited to the
        profiles whose tenant is in `allowed_slugs` (None = all)."""
        snap = self._poller.snapshot() if self._poller is not None else {}
        states = snap.get("states") or {}
        fleet = snap.get("fleet_outage") if isinstance(snap.get("fleet_outage"), dict) else None
        rows = [
            {
                "profile_id": s.get("profile_id"),
                "name": s.get("name") or "",
                "tenant_slug": s.get("tenant_slug"),
                "state": s.get("state"),
                "since": s.get("since"),
                "queries_24h": s.get("queries_24h"),
                "missing": bool(s.get("missing")),
                "problem": s.get("problem"),
                "problem_kind": s.get("problem_kind"),
                "lapse_cause": s.get("lapse_cause"),
            }
            for s in states.values()
            if allowed_slugs is None or s.get("tenant_slug") in allowed_slugs
        ]
        rows.sort(key=lambda r: (
            0 if r["missing"] else 1,
            {"lapsed": 0, "new": 1, "active": 2, "pending": 3}.get(r["state"], 4),
            0 if r["problem"] else 1, r["name"].lower(), r["profile_id"] or ""))
        count = {k: sum(1 for r in rows if r["state"] == k) for k in ("active", "pending", "lapsed")}
        return {
            **count,
            "missing": sum(1 for r in rows if r["missing"]),
            "problems": sum(1 for r in rows if r["problem"] and not r["missing"]),
            "profiles": rows,
            "throttled": bool(snap.get("throttled")),
            "throttled_for_sec": int(snap.get("throttled_for_sec") or 0),
            "rollup_lag_hours": int(snap.get("rollup_lag_hours") or 0),
            "analytics_gaps": list(snap.get("analytics_gaps") or []),
            # Fleet-wide: only for a view that sees the tenant it went to.
            "fleet_outage": fleet if fleet and (
                allowed_slugs is None or fleet.get("tenant") in allowed_slugs) else None,
        }

    def investigate(
        self,
        profiles: list[tuple[str, str]],
        *,
        since: Any,
        until: Any,
        domain: Optional[str],
        device: Optional[str],
        status: Optional[str],
        limit: int,
        max_pages_per_profile: int = 5,
        max_wait_sec: float = 30.0,
    ) -> tuple[list[tuple[str, str, dict[str, Any]]], bool, int]:
        """An analyst's live logs query (POST /search/nextdns): the given
        (profile id, name) pairs, newest first, through the SAME limiter at
        investigation priority, bounded pages. `domain` matches the name or
        its subdomains (NextDNS `search` narrows server-side); `device`
        matches a device id or name (no case) or the client IP. Returns
        ([(profile id, name, line)], truncated, vendor calls). Raises the
        client's errors. Nothing is stored.

        BUDGET (per running instance): one search at a time
        (NextDNSBusyError otherwise), INVESTIGATION_CALLS_PER_HOUR calls per
        rolling hour, INVESTIGATION_DEADLINE_SEC for the whole search — a
        search that hits the budget or the deadline returns what it has,
        truncated."""
        from apps.octo.adapters.nextdns.limiter import PRIORITY_INVESTIGATION

        client = self._client
        if client is None:
            raise NextDNSClientError("the NextDNS integration is not running")
        if not self._investigating.acquire(blocking=False):
            raise NextDNSBusyError(
                "Another NextDNS search is running for this integration; try again when "
                "it finishes", 5.0,
            )
        try:
            clock = client.limiter.now
            started = clock()
            calls_log = self._investigation_calls
            while calls_log and started - calls_log[0] >= 3600.0:
                calls_log.popleft()
            if len(calls_log) >= INVESTIGATION_CALLS_PER_HOUR:
                wait = 3600.0 - (started - calls_log[0])
                raise NextDNSBusyError(
                    f"The hourly NextDNS search budget ({INVESTIGATION_CALLS_PER_HOUR} calls) "
                    f"is used up — it keeps the poller's security checks on time; try again "
                    f"in {int(wait + 0.999)} s", wait,
                )
            want_dev = device.strip().lower() if device else None
            out: list[tuple[str, str, dict[str, Any]]] = []
            calls = 0
            truncated = False
            for pid, name in profiles:
                cursor: Optional[str] = None
                for _ in range(max_pages_per_profile):
                    left = INVESTIGATION_DEADLINE_SEC - (clock() - started)
                    if left <= 0 or len(calls_log) >= INVESTIGATION_CALLS_PER_HOUR:
                        return out, True, calls
                    wait_cap = min(max_wait_sec, left)
                    try:
                        page = client.logs(
                            pid, from_=since, to=until, status=status, cursor=cursor,
                            sort="desc", limit=1000, search=domain or None,
                            priority=PRIORITY_INVESTIGATION, max_wait_sec=wait_cap,
                        )
                    except NextDNSBusyError:
                        if wait_cap < max_wait_sec:
                            return out, True, calls     # the deadline, not the queue
                        raise
                    calls += 1
                    calls_log.append(clock())
                    for line in page.lines:
                        if domain:
                            d = str(line.get("domain") or "").lower().rstrip(".")
                            if d != domain and not d.endswith("." + domain):
                                continue
                        if want_dev:
                            dev = line.get("device") if isinstance(line.get("device"), dict) else {}
                            keys = {str(dev.get("id") or "").lower(),
                                    str(dev.get("name") or "").lower(),
                                    str(line.get("clientIp") or "").lower()}
                            if want_dev not in keys:
                                continue
                        out.append((pid, name, line))
                        if len(out) >= limit:
                            return out, True, calls
                    cursor = page.cursor
                    if not cursor:
                        break
                else:
                    truncated = True
            return out, truncated, calls
        finally:
            self._investigating.release()

    def rate_limit_hints(self) -> RateLimitHints:
        return RateLimitHints(requests_per_second=1.0 / DEFAULT_MIN_SPACING_SEC)

    # ----- Core extraction -----

    def extract_event(self, raw_envelope: dict[str, Any]) -> CanonicalEvent:
        """One NextDNS record (built by the poller) → CanonicalEvent. The
        blocked domain is the indicator (type domain)."""
        payload_sha = self.compute_payload_sha256(raw_envelope)
        shown = present(raw_envelope)
        vid = raw_envelope.get("vendor_event_id")
        vid = vid if isinstance(vid, str) and vid and len(vid) <= 128 else payload_sha[:32]
        indicator = indicator_of(raw_envelope)
        return TypedCanonicalEvent(
            vendor_event_id=vid,
            received_at=_received_at(raw_envelope),
            severity=_severity(raw_envelope),
            indicator=indicator,
            indicator_type="domain" if indicator else None,
            source_host=shown.device,
            summary=shown.headline,
            payload=raw_envelope,
            payload_sha256=payload_sha,
            event_type=event_type_of(raw_envelope),
        )

    @staticmethod
    def present_event(payload: dict[str, Any]) -> EventPresentation:
        return present(payload)

    @staticmethod
    def presentation_suffixes(client_slug: str, rows: list[tuple[int, dict]]) -> dict[int, str]:
        """OPTIONAL capability (read on the CLASS by the alerts feed): extra
        text for stored rows — here the coalescing count, "Seen N times this
        hour", from the tenant's telemetry.db (never a vendor call)."""
        ids = [eid for eid, payload in rows if event_type_of(payload) == EVENT_BLOCK]
        counts = store.hits_for_events(client_slug, ids)
        out: dict[int, str] = {}
        for eid, h in counts.items():
            if h.hits <= 1:
                continue
            when = (f"on {h.hour[:10]} (UTC)" if h.span == store.SPAN_DAY
                    else f"in the hour from {h.hour[11:16]} UTC")
            seen = (f"{h.hits} lookups across {'at least ' if h.distinct_roots >= store.MAX_ROOTS else ''}"
                    f"{h.distinct_roots} domains {when}" if h.distinct_roots > 1
                    else f"Seen {h.hits} times {when}")
            out[eid] = f"{seen} — every one blocked; only the first raised this alert."
        return out

    def route_to_tenant(self, raw_envelope: dict[str, Any]) -> str | None:
        return valid_profile_id(raw_envelope.get("profile_id"))

    def vendor_tenant_label(self, raw_envelope: dict[str, Any]) -> str | None:
        name = raw_envelope.get("profile_name")
        return name if isinstance(name, str) and name.strip() else None

    def severity_map(self, raw_envelope: dict[str, Any]) -> Severity:
        return _severity(raw_envelope)

    def human_summary(self, event: CanonicalEvent) -> str:
        return event.summary

    def deep_link(self, event: CanonicalEvent, link_type: DeepLinkType) -> str | None:
        """The profile's logs page — NextDNS has no per-query page."""
        pid = valid_profile_id((event.payload or {}).get("profile_id"))
        if pid is None or link_type not in ("alert", "tenant"):
            return None
        return f"{PORTAL_URL}/{pid}/logs"

    # "Open in NextDNS" on the alerts feed (instances.vendor_links).
    @staticmethod
    def vendor_link_spec() -> VendorLinkSpec:
        return LINK_SPEC

    @staticmethod
    def vendor_link_ids(payload: dict[str, Any]) -> dict[str, str]:
        pid = valid_profile_id(payload.get("profile_id") if isinstance(payload, dict) else None)
        return {"alert_uid": pid, "site_uid": pid} if pid else {}

    @staticmethod
    def derive_portal_base(config: dict[str, Any]) -> str | None:
        return PORTAL_URL

    def widget_definition(self) -> WidgetDefinitionRef | None:
        return None

