"""WazuhSourceAdapter — first concrete Phase 2 adapter.

Maps Wazuh manager alert envelopes (4.x JSON shape) onto the framework's
`CanonicalEvent` contract. Severity boundary, IOC extraction, and
human-summary text are ported verbatim from the working octo_admin Wazuh
adapter so behavior is preserved.

Initial scope:
  - `extract_event()` / `route_to_tenant()` / `severity_map()` /
    `human_summary()` / `deep_link()` — pure functions, fully testable
  - `credential_shape()` / `tenant_mapping_shape()` / `smoke_test()` —
    onboarding wizard hooks
  - `start()` / `stop()` / `health()` — lifecycle stubs (poll loop
    lands in a follow-up — this scaffold is the contract surface)

The actual pull-from-manager loop is intentionally deferred to a
separate `poller.py` module so the contract surface stays small +
testable.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
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
    WidgetDefinitionRef,
)

from apps.octo.adapters.wazuh.client import (
    WazuhAuthError,
    WazuhClient,
    WazuhClientError,
    WazuhConfig,
)
from apps.octo.adapters.wazuh.poller import WazuhPoller
from apps.octo.ingest import IngestSink, SqliteIngestSink
from apps.octo.ingest.timestamps import normalize_timestamp
from apps.octo.instances.poller_lifecycle import start_on_running_loop, stop_poller

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity mapping — Wazuh rule.level (0-15) → OCTO 5-level
# Ported verbatim from the octo_admin Wazuh adapter (proven boundaries).
# ---------------------------------------------------------------------------

#  Connection modes — how OCTO attaches to Wazuh:
#    existing  — connect to a Wazuh server the MSP already runs
#    import    — import an existing Wazuh deployment via its standard profile
#    bundled   — provision + manage OCTO's own built-in Wazuh engine
WAZUH_MODES = ("existing", "import", "bundled")


def _mode(creds: dict[str, Any]) -> str:
    m = (creds.get("WAZUH_MODE") or "existing").strip().lower()
    return m if m in WAZUH_MODES else "existing"


def _normalize_timestamp(raw: Any) -> str:
    """Wazuh stamps alerts in the MANAGER's local zone with a colon-less
    offset ('2026-09-12T13:00:00.000+0000'). SQLite's date functions only
    accept [+-]HH:MM, so that form buckets to NULL (dashboard throughput
    silently dropped every wazuh row) and sorts wrong against UTC rows.
    Store canonical UTC 'YYYY-MM-DDTHH:MM:SS.mmmZ' — the same shape the
    ingest router stamps. Deterministic, so replay dedup still matches.
    Never raises: an unparseable value is kept verbatim (a normalizer
    exception becomes a 422, which would wedge the shim's cursor)."""
    ts = str(raw or "")
    # Parsing/formatting is the shared ingest helper (one canonical form for
    # every adapter); the verbatim fallback for unparseable / zone-less values
    # is wazuh-specific — the manager's zone is unknown, so don't guess.
    return normalize_timestamp(ts) or ts


def _severity_from_level(level: int) -> Severity:
    if level <= 3:
        return "info"
    if level <= 6:
        return "low"
    if level <= 9:
        return "medium"
    if level <= 12:
        return "high"
    return "critical"


# ---------------------------------------------------------------------------
# IOC routability — don't flood the indicators table with internal traffic.
# Ported from octo_admin Wazuh adapter.
# ---------------------------------------------------------------------------

def _is_routable_ioc(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


_GROUP_PRIORITY = (
    "rootcheck", "policy_monitoring", "fim", "syscollector",
    "vulnerability-detector", "windows", "sshd", "ssh",
    "authentication_success", "authentication_failed",
    "invalid_login", "sudo", "pam", "audit", "syslog",
)


def _short_category(rule_groups: list[str]) -> str:
    """Operator-meaningful tag from rule.groups for the summary prefix."""
    available = set(rule_groups or [])
    for tag in _GROUP_PRIORITY:
        if tag in available:
            return tag.upper() if tag in ("fim", "pam") else tag
    return "wazuh"


def _config_from_credentials(creds: dict[str, Any]) -> WazuhConfig:
    """Translate wizard credentials + (optional) instance config into a
    WazuhConfig. Raises ValueError with operator-actionable messages if
    required fields are missing."""
    manager_url = creds.get("WAZUH_MANAGER_URL", "").strip()
    if not manager_url:
        raise ValueError("WAZUH_MANAGER_URL is required")
    api_password = creds.get("WAZUH_API_KEY", "").strip()
    if not api_password:
        raise ValueError("WAZUH_API_KEY is required")

    # Manager + indexer can be the same host (bundled mode) or different
    # (external mode). Default indexer URL derives from manager URL with
    # port swap; operator can override.
    indexer_url = creds.get("WAZUH_INDEXER_URL", "").strip()
    if not indexer_url:
        # Heuristic: swap :55000 → :9200, or fall back to same host
        indexer_url = manager_url.replace(":55000", ":9200")
        if indexer_url == manager_url:
            indexer_url = manager_url  # honest about not being able to derive

    return WazuhConfig(
        manager_url=manager_url,
        indexer_url=indexer_url,
        api_username=creds.get("WAZUH_API_USER", "wazuh"),
        api_password=api_password,
        indexer_username=creds.get("WAZUH_INDEXER_USER", "admin"),
        indexer_password=creds.get(
            "WAZUH_INDEXER_PASSWORD", api_password,
        ),  # bundled mode often shares; external mode wizard collects both
        verify_tls=str(creds.get("WAZUH_TLS_VERIFY", "1")) not in (
            "0", "false", "no", "False",
        ),
        timeout_seconds=float(creds.get("WAZUH_TIMEOUT_SECONDS", "10")),
    )


# ---------------------------------------------------------------------------
# WazuhSourceAdapter
# ---------------------------------------------------------------------------

class WazuhSourceAdapter(BaseSourceAdapter):
    """Wazuh manager → OCTO normalization.

    Same adapter handles bundled + external deploy modes — the difference
    is only in `instance_config['mode']` and the manager URL/API key the
    operator provides via the wizard.

    Instance state (poller + client + last-event timestamp) is stored
    per-adapter-instance; one adapter object handles ONE configured
    Wazuh upstream. To watch multiple Wazuh instances, the framework
    creates multiple adapter instances (each gets its own state).
    """

    vendor_slug = "wazuh"
    vendor_display_name = "Wazuh"
    vendor_logo_path = "/logos/wazuh.svg"
    vendor_category = "siem"
    auth_model = "api-key"
    delivery_mode = "poll"  # initial; switches to "hybrid" once push lands
    availability = "available"
    reports_vendor_contact = True   # WazuhPoller owns a ContactReporter
    default_poll_interval_sec = 10.0
    compliance_categories: list[ComplianceCategory] = [
        "hipaa-friendly",
        "cjis-friendly",
        "glba-friendly",
        "general",
    ]

    def __init__(
        self,
        *,
        sink: Optional[IngestSink] = None,
        client_factory: Optional[Callable[[WazuhConfig], WazuhClient]] = None,
    ) -> None:
        """`sink` and `client_factory` are injectable for tests; production
        construction calls the default constructor and gets:
          - SqliteIngestSink reading from the bundle's data_root
          - WazuhClient built from the WazuhConfig the wizard captured
        """
        super().__init__() if hasattr(BaseSourceAdapter, "__init__") else None
        self._sink: Optional[IngestSink] = sink
        self._client_factory = client_factory or WazuhClient
        # Per-instance runtime state — None until start() runs.
        self._client: Optional[WazuhClient] = None
        self._poller: Optional[WazuhPoller] = None
        self._started_at: Optional[float] = None
        self._default_tenant_slug: str = "_unmapped"

    # ----- Onboarding -----

    def credential_shape(self) -> list[CredentialField]:
        """Form fields the wizard renders for first-time setup.

        For bundled mode, the wizard pre-fills these with the bundle's
        internal manager URL + an auto-generated API key. For external
        mode, the operator enters their own values.
        """
        return [
            CredentialField(
                name="WAZUH_MODE",
                label="Connection mode",
                kind="enum",
                choices=["existing", "import", "bundled"],
                description=(
                    "How OCTO connects to Wazuh. 'existing' — connect to a Wazuh "
                    "server you already run. 'import' — import an existing Wazuh "
                    "deployment via its standard API profile. 'bundled' — let "
                    "OCTO provision and manage its own built-in Wazuh engine "
                    "(no external server needed)."
                ),
            ),
            CredentialField(
                name="WAZUH_MANAGER_URL",
                label="Wazuh Manager URL",
                kind="text",
                required=False,
                show_when={"WAZUH_MODE": ["existing", "import"]},
                required_when={"WAZUH_MODE": ["existing", "import"]},
                description=(
                    "Full URL of the Wazuh manager API (typically "
                    "https://<host>:55000). Required for 'existing' and 'import' "
                    "modes; for 'bundled', OCTO pre-fills its internal URL."
                ),
            ),
            CredentialField(
                name="WAZUH_API_KEY",
                label="Wazuh API Key",
                kind="password",
                required=False,
                show_when={"WAZUH_MODE": ["existing", "import"]},
                required_when={"WAZUH_MODE": ["existing", "import"]},
                description=(
                    "API user with read access to /security/user/authenticate. "
                    "Required for 'existing'/'import'; for 'bundled', OCTO "
                    "generates it automatically."
                ),
            ),
        ]

    def tenant_mapping_shape(self) -> TenantMappingShape:
        """Wazuh's tenancy model is per-agent-group. The wizard reads the
        agent groups from the manager and lets the operator map each group
        to an OCTO client slug."""
        return TenantMappingShape(
            fetch_method="api",
            fetch_endpoint="/agents/groups",
            vendor_tenant_id_field="name",
            vendor_tenant_label_field="name",
        )

    def smoke_test(self, credentials: dict[str, Any]) -> SmokeResult:
        """Confirm the adapter can reach the configured Wazuh manager.

        Authenticates against /security/user/authenticate. Returns ok=True
        when a JWT is acquired successfully; ok=False with the reason
        otherwise. Never raises — the wizard relies on the result body
        to render the right user-facing message.
        """
        mode = _mode(credentials)
        url = credentials.get("WAZUH_MANAGER_URL", "").strip()

        if mode == "bundled" and not url:
            # Nothing to probe yet — the built-in engine is provisioned on save.
            return SmokeResult(
                ok=True,
                message=(
                    "Built-in Wazuh engine will be provisioned and connected "
                    "when you save this integration."
                ),
            )
        if not url:
            label = "import" if mode == "import" else "existing-server"
            return SmokeResult(
                ok=False,
                message=f"WAZUH_MANAGER_URL is required for {label} mode",
            )
        try:
            config = _config_from_credentials(credentials)
        except ValueError as exc:
            return SmokeResult(ok=False, message=str(exc))

        client = self._client_factory(config)
        try:
            client.authenticate()
        except WazuhAuthError as exc:
            return SmokeResult(
                ok=False,
                message=f"Wazuh rejected credentials: {exc}",
            )
        except WazuhClientError as exc:
            return SmokeResult(
                ok=False,
                message=f"Could not reach Wazuh manager: {exc}",
            )
        return SmokeResult(
            ok=True,
            message="Wazuh manager reachable and credentials valid.",
        )

    def onboarding(self, webhook_url: str | None = None) -> Onboarding | None:
        return Onboarding(
            summary=(
                "Choose how OCTO connects to Wazuh: use a server you already run, "
                "import an existing Wazuh deployment, or have OCTO provision its "
                "own built-in Wazuh engine."
            ),
            webhook_url=None,  # Wazuh is poll-based; no inbound webhook URL
            steps=[
                OnboardingStep(
                    title="Option A · Use an existing Wazuh server",
                    body=(
                        "Set Connection mode = existing, then enter your Wazuh "
                        "manager URL (https://<host>:55000) and an API key for a "
                        "read-only OCTO user."
                    ),
                ),
                OnboardingStep(
                    title="Option B · Import a Wazuh deployment",
                    body=(
                        "Set Connection mode = import to bring in an existing "
                        "Wazuh deployment via its standard API profile (manager + "
                        "indexer URLs + API user). OCTO applies the Wazuh-standard "
                        "indexer/user defaults where the profile implies them."
                    ),
                ),
                OnboardingStep(
                    title="Option C · Provision OCTO's built-in Wazuh",
                    body=(
                        "Set Connection mode = bundled to have OCTO deploy and "
                        "manage its own Wazuh engine — no external server needed. "
                        "OCTO pre-fills the internal URL and generates the API key."
                    ),
                ),
                OnboardingStep(
                    title="Map agent groups to clients",
                    body=(
                        "After connecting, map each Wazuh agent group to an OCTO "
                        "client in the tenant-mapping step — group membership "
                        "routes each alert to the right client."
                    ),
                ),
            ],
        )

    # ----- Lifecycle -----

    def start(self, instance_config: dict[str, Any]) -> None:
        """Construct the client + poller for this instance and schedule
        the poll loop on the running event loop.

        `instance_config` shape (set by the wizard, persisted in
        AdapterRegistry):
          - WAZUH_MANAGER_URL, WAZUH_API_KEY, etc. (credential_shape)
          - default_tenant_slug:    str  — where unrouted events land
          - initial_cursor:         str  — resume from a saved timestamp
          - poll_interval_sec:      float (optional, default 10.0)

        If there's no running asyncio loop yet (e.g., process-level
        construction before app startup), state is set up but the
        poller isn't scheduled — the next start() call from within an
        async context will pick up the existing poller and schedule it.
        """
        if self._poller is not None:
            # Already started — idempotent.
            return None

        try:
            config = _config_from_credentials(instance_config)
        except ValueError as exc:
            logger.error("[wazuh] start failed: invalid config: %s", exc)
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
        initial_cursor = instance_config.get(
            "initial_cursor", "1970-01-01T00:00:00.000Z",
        )
        poll_interval = float(instance_config.get(
            "poll_interval_sec", self.default_poll_interval_sec,
        ))

        self._poller = WazuhPoller(
            adapter=self,
            client=self._client,
            sink=self._sink,
            default_tenant_slug=self._default_tenant_slug,
            initial_cursor=initial_cursor,
            poll_interval_sec=poll_interval,
            instance_id=instance_config.get("_instance_id"),
        )
        self._started_at = time.time()

        # Schedule the poll loop on whatever event loop is running.
        # If we're not yet inside one (e.g., pre-startup wiring), the
        # framework's startup hook will await start() later from an
        # async context; in that case the start() coroutine is what
        # actually schedules the task.
        self._poller_loop = start_on_running_loop(
            self._poller.start, what="wazuh",
        )
        return None

    def stop(self) -> None:
        """Stop the poll loop. Idempotent."""
        if self._poller is None:
            return None
        stop_poller(
            self._poller.stop, getattr(self, "_poller_loop", None), what="wazuh",
        )
        self._poller_loop = None
        self._poller = None
        self._client = None
        self._started_at = None
        return None

    def health(self) -> HealthStatus:
        """Surface the poller's runtime state.

        - alive=False when no poller is configured (REGISTERED / CONFIGURED state)
        - last_event_at: the poller's cursor (most-recent timestamp seen)
        - lag_seconds: 0 when no events yet; otherwise approximate wall-
          clock seconds since the last cursor advance (not the alert
          timestamp itself — that requires sub-second clock sync we don't
          assume across hosts).
        """
        if self._poller is None:
            return HealthStatus(
                alive=False,
                last_event_at=None,
                lag_seconds=0.0,
                errors_last_hour=0,
            )
        cursor = self._poller.cursor
        # cursor is the ISO timestamp of the most-recent alert seen.
        # Lag is wall-clock seconds since *we* observed that event.
        # For v1 we approximate "0 if cursor advanced this poll cycle";
        # the poller doesn't track that yet, so use 0 + a TODO.
        return HealthStatus(
            alive=True,
            last_event_at=cursor if cursor != "1970-01-01T00:00:00.000Z" else None,
            lag_seconds=0.0,  # TODO: track per-cycle observed lag in poller
            errors_last_hour=0,  # TODO: increment from poller error log
        )

    # ----- Core extraction -----

    def extract_event(self, raw_envelope: dict[str, Any]) -> CanonicalEvent:
        """Map a Wazuh alert envelope onto a CanonicalEvent.

        Wazuh schema fields used:
          envelope.id            → vendor_event_id
          envelope.timestamp     → received_at (normalized to UTC 'Z' form)
          envelope.rule.level    → severity (via _severity_from_level)
          envelope.rule.groups   → category prefix in summary
          envelope.rule.description → primary summary text
          envelope.agent.name    → source_host
          envelope.data.srcip    → indicator (if routable)
          envelope.data.dstip    → fallback indicator

        Wazuh adds fields between minor versions; the entire payload is
        preserved in `payload` for forensic value. Layer 1 enrichment and
        Layer 2 LLM can inspect any field beyond what's normalized.
        """
        rule = raw_envelope.get("rule", {}) or {}
        agent = raw_envelope.get("agent", {}) or {}
        data = raw_envelope.get("data", {}) or {}

        level = int(rule.get("level", 0))
        severity = _severity_from_level(level)

        indicator: str | None = None
        indicator_type: str | None = None
        for ip_field in ("srcip", "dstip"):
            candidate = data.get(ip_field)
            if isinstance(candidate, str) and _is_routable_ioc(candidate):
                indicator = candidate
                indicator_type = "ip"
                break

        category = _short_category(rule.get("groups", []) or [])
        description = rule.get("description", "") or ""
        summary = f"[{category}] {description}".strip()
        if not summary or summary == "[wazuh]":
            summary = f"Wazuh alert (rule {rule.get('id', '?')})"

        event = CanonicalEvent(
            vendor_event_id=str(raw_envelope.get("id", "")),
            received_at=_normalize_timestamp(raw_envelope.get("timestamp", "")),
            severity=severity,
            indicator=indicator,
            indicator_type=indicator_type,  # type: ignore[arg-type]
            source_host=agent.get("name"),
            summary=summary,
            payload=raw_envelope,
            payload_sha256=self.compute_payload_sha256(raw_envelope),
        )
        return event

    def route_to_tenant(self, raw_envelope: dict[str, Any]) -> str | None:
        """Determine which OCTO client slug this alert belongs to.

        Resolution order:
          1. Explicit `_octo_tenant_slug` label on agent.labels (set when
             the bundle enrolls agents with a pre-assigned tenant).
          2. Agent group name (per tenant_mapping_shape).
          3. None → caller falls back to the wizard-configured default
             tenant for unmapped agents.
        """
        agent = raw_envelope.get("agent", {}) or {}
        labels = agent.get("labels", {}) or {}
        if isinstance(labels, dict):
            explicit = labels.get("_octo_tenant_slug")
            if isinstance(explicit, str) and explicit:
                return explicit
        # Agent group fallback — Wazuh attaches `group` to agents via
        # /agents/{id}/group and surfaces it inconsistently. The framework
        # resolves group → slug via the configured tenant_mapping.
        group = agent.get("group")
        if isinstance(group, list) and group:
            return str(group[0])
        if isinstance(group, str) and group:
            return group
        return None

    def severity_map(self, raw_envelope: dict[str, Any]) -> Severity:
        rule = raw_envelope.get("rule", {}) or {}
        return _severity_from_level(int(rule.get("level", 0)))

    def human_summary(self, event: CanonicalEvent) -> str:
        return event.summary

    def deep_link(
        self,
        event: CanonicalEvent,
        link_type: DeepLinkType,
    ) -> str | None:
        """Return URL to the corresponding page in Wazuh's native UI.

        Operators with the Wazuh dashboard sidecar can click through for
        deep forensics. Returns None for link types Wazuh doesn't expose.
        """
        base_url = os.environ.get("WAZUH_DASHBOARD_URL", "").rstrip("/")
        if not base_url:
            return None
        if link_type == "alert":
            return f"{base_url}/app/wazuh#/overview?tab=general&id={event.vendor_event_id}"
        if link_type == "host" and event.source_host:
            return f"{base_url}/app/wazuh#/agents?agent={event.source_host}"
        return None

    def widget_definition(self) -> WidgetDefinitionRef | None:
        """Declare the dashboard widget that pairs with this adapter.

        Per framework-is-the-product: adapters ship as vertical slices.
        Adding the Wazuh adapter via the wizard auto-populates a "Wazuh
        Alerts" widget on operator dashboards.
        """
        return WidgetDefinitionRef(widget_id="wazuh.alerts-feed")
