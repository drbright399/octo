"""AutotaskSourceAdapter — Autotask PSA → OCTO (P4 first PSA adapter).

P4-a scope: scaffold, credential declaration, tenant mapping shape,
smoke-test (zone-resolve + health-check). NO polling, NO writes yet.

Polling lives in `poller.py` (added in P4-c1). Outbound writes route
through a separate `adapter_outbound_queue` (added in P4-c2) and reuse
this adapter's `AutotaskClient` for HTTP.

Writes are behind the PSA kill switch (`writes_switch.py`, slice 0 of the
PSA write design): the instance key `writes_enabled`, default OFF. While it
is off `start()` never constructs the write-back pusher.

Note: the BaseSourceAdapter abstract methods on the data side
(`extract_event`, `route_to_tenant`, `severity_map`, `human_summary`)
exist because the framework was originally designed for telemetry-
source adapters (SIEMs, RMMs, EDRs). PSAs don't emit "events" in that
sense — they emit TICKETS, which our ingest path treats as a different
shape. For P4-a these methods land as well-defined stubs that raise
NotImplementedError; P4-c1 will wire them to the ticket-ingest path
when that arrives.
"""
from __future__ import annotations

import asyncio
import logging
import threading
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
    Severity,
    SmokeResult,
    TenantMappingShape,
)

from apps.octo.adapters.autotask.client import (
    AutotaskAuthError,
    AutotaskClient,
    AutotaskClientError,
    AutotaskConfig,
    AutotaskZoneError,
    resolve_zone,
)
from apps.octo.adapters.autotask.poller import PROPOSALS_EVERY_SEC, AutotaskPoller
from apps.octo.adapters.autotask.writeback import AutotaskPusher
from apps.octo.adapters.autotask.writes_switch import (
    instance_writes_enabled,
    writes_enabled_in,
)
from apps.octo.instances.poller_lifecycle import stop_poller

logger = logging.getLogger(__name__)

# How long a switch change (or a stop) waits for one already in progress — a
# little over the pusher's own 20 s start / stop waits.
_SWITCH_LOCK_TIMEOUT_SEC = 30.0


def _config_from_credentials(creds: dict[str, Any]) -> AutotaskConfig:
    """Translate wizard credentials → AutotaskConfig. Resolves zone as
    part of validation so the operator sees zone-discovery failures
    surfaced at the wizard step that supplied the username.

    Raises ValueError with operator-actionable messages on any missing
    or malformed credential."""
    username = (creds.get("AUTOTASK_USERNAME") or "").strip()
    if not username:
        raise ValueError(
            "AUTOTASK_USERNAME is required (the API user's Username (Key) — "
            "the generated value under Admin → Resources/Users → your API "
            "user → Credentials; NOT a login e-mail)"
        )
    secret = creds.get("AUTOTASK_SECRET") or ""
    if not secret:
        raise ValueError("AUTOTASK_SECRET is required (the API user's Password (Secret))")
    # A pasted secret with a space or line break at either end is the most
    # common 401 — say so instead of sending it (never stripped silently:
    # the operator should know what was pasted).
    if secret != secret.strip():
        raise ValueError(
            "AUTOTASK_SECRET has a space or line break at the start or end — "
            "paste the Password (Secret) again, exactly as Autotask shows it"
        )
    integration_code = (creds.get("AUTOTASK_INTEGRATION_CODE") or "").strip()
    if not integration_code:
        raise ValueError(
            "AUTOTASK_INTEGRATION_CODE is required (the API user's API "
            "Tracking Identifier — Security tab → Custom (Internal Integration))"
        )

    # Zone may be pre-supplied (test fixtures, manual override). If not,
    # resolve it via the unauthenticated discovery endpoint.
    zone_url = (creds.get("AUTOTASK_ZONE_URL") or "").strip()
    if not zone_url:
        zone_url = resolve_zone(username)

    return AutotaskConfig(
        username=username,
        secret=secret,
        integration_code=integration_code,
        zone_url=zone_url,
        timeout_seconds=float(creds.get("AUTOTASK_TIMEOUT_SECONDS", "15")),
        verify_tls=str(creds.get("AUTOTASK_TLS_VERIFY", "1")) not in (
            "0", "false", "no", "False",
        ),
    )


class AutotaskSourceAdapter(BaseSourceAdapter):
    """Autotask PSA → OCTO. P4-a groundwork: scaffold + zone + health."""

    vendor_slug = "autotask"
    vendor_display_name = "Autotask PSA"
    vendor_logo_path = "/logos/autotask.svg"
    vendor_category = "psa"
    auth_model = "api-key"
    delivery_mode = "poll"
    availability = "preview"  # bumped to "available" once P4-c1 ships
    reports_vendor_contact = True   # AutotaskPoller owns a ContactReporter
    default_poll_interval_sec = 30.0
    compliance_categories: list[ComplianceCategory] = [
        "hipaa-friendly",
        "general",
    ]

    def __init__(
        self,
        *,
        client_factory: Optional[Callable[[AutotaskConfig], AutotaskClient]] = None,
        zone_resolver: Optional[Callable[[str], str]] = None,
        poller_factory: Optional[Callable[..., AutotaskPoller]] = None,
        pusher_factory: Optional[Callable[..., AutotaskPusher]] = None,
        start_poller: bool = True,
        start_pusher: bool = True,
    ) -> None:
        super().__init__() if hasattr(BaseSourceAdapter, "__init__") else None
        self._client_factory = client_factory or AutotaskClient
        # zone_resolver injection lets tests skip real zone discovery
        # without monkey-patching the module-level helper.
        self._zone_resolver = zone_resolver
        self._poller_factory = poller_factory or AutotaskPoller
        self._pusher_factory = pusher_factory or AutotaskPusher
        self._start_poller = start_poller
        self._start_pusher = start_pusher
        self._client: Optional[AutotaskClient] = None
        self._poller: Optional[AutotaskPoller] = None
        self._pusher: Optional[AutotaskPusher] = None
        self._started_at: Optional[float] = None
        self._writes_enabled = False
        self._adapter_instance_id = 0
        self._workers_loop: Optional[asyncio.AbstractEventLoop] = None
        # Serialises every change of the pusher slot (switch on / off, stop):
        # two concurrent "switch on" calls must never build two pushers (the
        # first would be orphaned — unstoppable — and both would send).
        self._writes_lock = threading.Lock()

    # ----- Onboarding -----

    def credential_shape(self) -> list[CredentialField]:
        return [
            CredentialField(
                name="AUTOTASK_USERNAME",
                label="API User email",
                kind="text",
                description=(
                    "The email address of the Autotask Resource flagged "
                    "as an API User (Admin → Resources/Users → New API "
                    "User). Used for zone discovery + every API call."
                ),
            ),
            CredentialField(
                name="AUTOTASK_SECRET",
                label="API User password",
                kind="password",
                description=(
                    "The password set on the API User. Rotatable — re-"
                    "enter here whenever you rotate it on the Autotask "
                    "side. Stored encrypted at rest in the bundle vault."
                ),
            ),
            CredentialField(
                name="AUTOTASK_INTEGRATION_CODE",
                label="Integration Code",
                kind="password",
                description=(
                    "The unique integration code Autotask issued for "
                    "this integration. Found in Admin → Resources/Users "
                    "→ API User detail. NOT the same as the API User's "
                    "password — both are required."
                ),
            ),
        ]

    def tenant_mapping_shape(self) -> TenantMappingShape:
        """Autotask Companies map 1:1 to OCTO tenant slugs. The wizard
        fetches the Companies list via `/Companies/query` and lets the
        operator pick mappings + the Autotask web-UI homepage URL per
        tenant (used for the "Open in Autotask →" quick-link). The
        mapping table itself is populated in P4-b — for now we declare
        the shape so the wizard knows where to fetch from."""
        return TenantMappingShape(
            fetch_method="api",
            fetch_endpoint="/V1.0/Companies/query",
            vendor_tenant_id_field="id",
            vendor_tenant_label_field="companyName",
        )

    def smoke_test(self, credentials: dict[str, Any]) -> SmokeResult:
        """Two-step probe:
          1. Zone resolution (unauthenticated) — confirms the username
             is recognized by Autotask + the network path is open.
          2. Health check (authenticated) — confirms the full
             credential trio works against the resolved zone.

        Either step's failure surfaces as a non-ok SmokeResult with the
        underlying error message verbatim (Autotask's are actionable)."""
        try:
            cfg = _config_from_credentials(credentials)
        except AutotaskZoneError as e:
            return SmokeResult(
                ok=False,
                message=f"Zone discovery failed: {e}",
            )
        except ValueError as e:
            return SmokeResult(
                ok=False,
                message=str(e),
            )

        client = self._client_factory(cfg)
        try:
            envelope = client.health_check()
        except AutotaskAuthError as e:
            return SmokeResult(ok=False, message=str(e))
        except AutotaskClientError as e:
            return SmokeResult(ok=False, message=f"Health check failed: {e}")

        # Surface a tiny sample so the wizard's preview step has
        # something real to show. Autotask Companies/query returns
        # {"items": [...], "pageDetails": {...}} — we lift the first
        # item if present.
        items = envelope.get("items") if isinstance(envelope, dict) else None
        sample = items[0] if items and isinstance(items, list) else None

        return SmokeResult(
            ok=True,
            message=(
                f"Connected to Autotask at {cfg.zone_url} — "
                f"credentials accepted, Companies endpoint reachable."
            ),
            sample_payload=sample if isinstance(sample, dict) else None,
        )

    def onboarding(self, webhook_url: str | None = None) -> Onboarding | None:
        return Onboarding(
            summary=(
                "Autotask is your PSA — OCTO reads tickets and (soon) writes findings "
                "back. Connect it with a dedicated Autotask API user; the API zone is "
                "discovered automatically from the username, so there's no URL to set."
            ),
            webhook_url=None,  # Autotask is polled; binds via the PSA MCP boundary
            steps=[
                OnboardingStep(
                    title="1 · Create a dedicated API user",
                    body=(
                        "In Autotask → Admin → Resources/Users, create a NEW API user "
                        "(security level API User (system)) with its own e-mail (e.g. "
                        "athena@yourdomain — not a person's login). Under Credentials, "
                        "generate the Username (Key) and Password (Secret): the Key goes "
                        "in Username (it looks like an e-mail but is NOT your login "
                        "e-mail), the Secret goes in Secret."
                    ),
                ),
                OnboardingStep(
                    title="2 · Add the integration code",
                    body=(
                        "On the same API user, set API Tracking Identifier → Custom "
                        "(Internal Integration) (e.g. 'Athena OCTO') and paste the "
                        "identifier Autotask shows into the Integration code field. The "
                        "API zone is auto-discovered from the Username (Key)."
                    ),
                ),
                OnboardingStep(
                    title="3 · Map companies to clients",
                    body=(
                        "After connecting, map each Autotask Company to an OCTO client "
                        "in the tenant-mapping step so tickets route to the right client."
                    ),
                ),
                OnboardingStep(
                    title="Note · Preview integration",
                    body=(
                        "Autotask is in preview: credential capture + zone discovery "
                        "work now; ticket sync and write-back land with the PSA "
                        "MCP-boundary slice."
                    ),
                ),
            ],
        )

    @property
    def client(self) -> Optional[AutotaskClient]:
        """The running instance's own client (None until started) — for
        on-demand reads that must not decrypt the credentials again (the
        "Refresh from Autotask" of the location proposals)."""
        return self._client

    # ----- Lifecycle -----

    def start(self, instance_config: dict[str, Any]) -> None:
        """Build the client + spawn the read-only ingest poller (P4-c1).

        The poller is best-effort kicked off here; if there's no
        running asyncio loop in the caller's context (= we're being
        constructed from a sync code path like a test or a bootstrap
        validator), we just leave the poller un-started and let the
        framework lifecycle bring it up via start_async() later. The
        `start_poller=False` constructor flag lets tests opt out
        entirely."""
        cfg = _config_from_credentials(instance_config)
        self._client = self._client_factory(cfg)
        # The InstanceManager injects `_instance_id`; this read
        # `_adapter_instance_id`, which nothing sets, so every running
        # instance polled (and routed) as instance 0. The old key is still
        # honoured for callers that pass it.
        adapter_instance_id = int(
            instance_config.get("_instance_id")
            or instance_config.get("_adapter_instance_id", 0)
        )
        self._adapter_instance_id = adapter_instance_id
        self._poller = self._poller_factory(
            client=self._client,
            adapter_instance_id=adapter_instance_id,
            initial_ticket_cursor=instance_config.get("ticket_cursor"),
            initial_note_cursor=instance_config.get("note_cursor"),
            poll_interval_sec=float(instance_config.get(
                "poll_interval_sec", self.default_poll_interval_sec,
            )),
            # The daily site-location proposals; 0 turns them off.
            proposals_every_sec=float(instance_config.get(
                "location_proposals_every_sec", PROPOSALS_EVERY_SEC,
            )),
        )
        # The PSA writes kill switch (writes_switch.py): default OFF. While
        # it is off the pusher is never even constructed — no worker exists
        # that could write to Autotask.
        self._writes_enabled = self._writes_switch_on(instance_config, adapter_instance_id)
        self._pusher = (
            self._pusher_factory(client=self._client, adapter_instance_id=adapter_instance_id)
            if self._writes_enabled else None
        )
        if not self._writes_enabled:
            logger.info(
                "Autotask writes are OFF for instance %s — the write-back pusher "
                "is not started", adapter_instance_id,
            )
        self._started_at = time.time()

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop — that's fine, the framework's
            # InstanceManager will call us back from one.
            logger.info(
                "Autotask adapter constructed for zone=%s — no asyncio "
                "loop yet; workers will start when one's available",
                cfg.zone_url,
            )
            return

        self._workers_loop = loop
        if self._start_poller:
            loop.create_task(self._poller.start())
        if self._start_pusher and self._pusher is not None:
            loop.create_task(self._pusher.start())
        logger.info(
            "Autotask adapter started, zone=%s — poller scheduled; pusher %s",
            cfg.zone_url,
            "scheduled" if (self._start_pusher and self._pusher is not None) else "OFF",
        )

    @staticmethod
    def _writes_switch_on(instance_config: dict[str, Any], adapter_instance_id: int) -> bool:
        """The switch as this start sees it. Both must say ON: the start
        config (the instance row merged with the credentials) AND, for a
        persisted instance, the registry row itself — so a key smuggled in
        through the credential blob (which wins on a merge collision) cannot
        turn writes on. Fails closed."""
        if not writes_enabled_in(instance_config):
            return False
        if adapter_instance_id > 0:
            return instance_writes_enabled(adapter_instance_id)
        return True

    @property
    def writes_enabled(self) -> bool:
        return bool(getattr(self, "_writes_enabled", False))

    @property
    def pusher_running(self) -> bool:
        return getattr(self, "_pusher", None) is not None

    def apply_writes_enabled(self, enabled: bool) -> bool:
        """Apply a flipped switch to the RUNNING adapter (the registry row is
        already written by the caller). OFF stops and drops the pusher; ON
        constructs and starts one on the workers' loop. True when the running
        state now matches. Never raises.

        Serialised (`_writes_lock`): concurrent calls cannot build a second
        pusher, and a pusher whose stop could not be confirmed stays in the
        slot (it may still be running — a later ON reuses it instead of
        starting a twin).

        Off-path safety does not depend on this: a pusher re-reads the
        persisted switch before every send."""
        if not self._writes_lock.acquire(timeout=_SWITCH_LOCK_TIMEOUT_SEC):
            logger.error("Autotask writes: switch change not applied live — another "
                         "change is still in progress")
            return False
        try:
            return self._apply_writes_enabled_locked(bool(enabled))
        finally:
            self._writes_lock.release()

    def _apply_writes_enabled_locked(self, enabled: bool) -> bool:
        if self._client is None:                     # not started: nothing to apply
            return True
        if not enabled:
            self._writes_enabled = False
            pusher = self._pusher
            if pusher is None:
                return True
            owner = getattr(self, "_workers_loop", None)
            stopped = stop_poller(pusher.stop, owner, what="autotask pusher")
            if stopped:
                self._pusher = None
            else:
                # Not confirmed stopped: keep it in the slot so nothing can
                # start a second one beside it. It sends nothing while the
                # persisted switch is off.
                logger.error("Autotask pusher stop not confirmed — kept in its slot; "
                             "it refuses every send while writes are off")
            return stopped
        # ON only when the persisted row says so (the route writes it first).
        iid = getattr(self, "_adapter_instance_id", 0)
        if iid > 0 and not instance_writes_enabled(iid):
            logger.error("Autotask writes: asked to switch on, but instance %s's "
                         "persisted switch is off — not starting a pusher", iid)
            return False
        self._writes_enabled = True
        if self._pusher is not None:
            return True
        try:
            pusher = self._pusher_factory(
                client=self._client, adapter_instance_id=iid,
            )
        except Exception:  # noqa: BLE001
            logger.exception("Autotask pusher could not be constructed")
            return False
        self._pusher = pusher
        if not self._start_pusher:                   # tests: built, never run
            return True
        loop = getattr(self, "_workers_loop", None)
        if loop is None or loop.is_closed() or not loop.is_running():
            logger.error("Autotask pusher built but not started: no running workers loop")
            return False
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        try:
            if running is loop:
                loop.create_task(pusher.start())
            else:
                asyncio.run_coroutine_threadsafe(pusher.start(), loop).result(timeout=20.0)
        except Exception:  # noqa: BLE001
            logger.exception("Autotask pusher could not be started")
            return False
        return True

    def stop(self) -> None:
        # Best effort under the switch lock: a switch change in flight
        # finishes first (or, past the timeout, the stop goes ahead anyway —
        # a stop must never be refused).
        locked = self._writes_lock.acquire(timeout=_SWITCH_LOCK_TIMEOUT_SEC)
        try:
            owner = getattr(self, "_workers_loop", None)
            if self._poller is not None:
                stop_poller(self._poller.stop, owner, what="autotask poller")
            if self._pusher is not None:
                stop_poller(self._pusher.stop, owner, what="autotask pusher")
            self._workers_loop = None
            self._client = None
            self._poller = None
            self._pusher = None
            self._writes_enabled = False
            self._started_at = None
        finally:
            if locked:
                self._writes_lock.release()

    def health(self) -> HealthStatus:
        """For P4-a we report `alive=True` whenever the client has been
        successfully constructed (=zone known + creds passed validation
        at start time). The polling-aware health metrics
        (last_event_at, lag_seconds) come in P4-c1 once the poller is
        actually pulling."""
        if self._client is None:
            return HealthStatus(
                alive=False, last_event_at=None,
                lag_seconds=0.0, errors_last_hour=0,
            )
        return HealthStatus(
            alive=True, last_event_at=None,
            lag_seconds=0.0, errors_last_hour=0,
        )

    # ----- Data side: stubs for P4-a -----
    # These get real implementations in P4-c1 when the ticket-ingest
    # poller arrives. Until then they raise NotImplementedError with a
    # clear pointer to the gating slice.

    def extract_event(self, raw_envelope: dict[str, Any]) -> CanonicalEvent:
        raise NotImplementedError(
            "Autotask event extraction lands in P4-c1 (read-only ingest). "
            "P4-a registers the adapter scaffold only."
        )

    def route_to_tenant(self, raw_envelope: dict[str, Any]) -> str | None:
        raise NotImplementedError(
            "Autotask tenant routing lands in P4-c1 (uses the at-setup "
            "tenant↔companyID mapping table from P4-b)."
        )

    def severity_map(self, raw_envelope: dict[str, Any]) -> Severity:
        raise NotImplementedError(
            "Autotask severity mapping lands in P4-c1 — maps "
            "Tickets.priority picklist → 5-tier OCTO severity via the "
            "picklist cache from P4-b."
        )

    def human_summary(self, event: CanonicalEvent) -> str:
        raise NotImplementedError("Autotask summary builder lands in P4-c1.")

    # ----- Deep linking -----

    def deep_link(self, event: CanonicalEvent, link_type: DeepLinkType) -> str | None:
        """Build a URL into Autotask's web UI for the given event ref.
        For tickets the URL pattern is:
            <https-base>/Mvc/ServiceDesk/TicketDetail.mvc?ticketId=<id>

        The web-UI host is derived from the zone URL (replacing
        `webservices[n].autotask.net/atservicesrest/v1.0/` with
        `ww[n].autotask.net`). When `self._client` is None (adapter
        not yet started) we return None — the caller renders a "no
        deep link available" badge in that case."""
        if self._client is None:
            return None
        if link_type != "alert":
            # Other link types (device, tenant, host) aren't meaningful
            # for an Autotask ticket reference. Return None and the UI
            # falls back to the generic vendor-deep-link slot.
            return None
        ticket_id = event.vendor_event_id
        if not ticket_id:
            return None
        # Zone URL shape: https://webservices12.autotask.net/atservicesrest/v1.0/
        # Web UI shape:   https://ww12.autotask.net/Mvc/ServiceDesk/TicketDetail.mvc?ticketId=N
        # Strip the path + swap subdomain.
        from urllib.parse import urlparse
        parsed = urlparse(self._client.config.zone_url)
        host = parsed.hostname or ""
        # webservices12.autotask.net → ww12.autotask.net
        if host.startswith("webservices"):
            ui_host = "ww" + host[len("webservices"):]
        else:
            ui_host = host
        return f"https://{ui_host}/Mvc/ServiceDesk/TicketDetail.mvc?ticketId={ticket_id}"
