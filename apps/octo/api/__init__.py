"""FastAPI app for OCTO admin + ingestion surface.

The app is built via `create_app()` rather than a module-level singleton so
tests can spin up a fresh app against a sandbox data root via the
OCTO_DATA_ROOT env override.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI

from apps.octo.api.errors import install_exception_handlers
from apps.octo.api.rate_limit import install_rate_limit_middleware
from apps.octo.api.setup_gate import install_setup_gate_middleware
from apps.octo.api.event_stream import router as event_stream_router
from apps.octo.api.routers import (
    adapters as adapters_router,
    admin_clients,
    admin_data as admin_data_router,
    admin_ops,
    account_preferences as account_preferences_router,
    admin_bundle_config as admin_bundle_config_router,
    admin_llm_grants as admin_llm_grants_router,
    admin_llm_models as admin_llm_models_router,
    admin_notices as admin_notices_router,
    admin_psa as admin_psa_router,
    admin_tenants as admin_tenants_router,
    agent_activity as agent_activity_router,
    alert_verdicts as alert_verdicts_router,
    agent_query as agent_query_router,
    auth as auth_router,
    autotask_mappings as autotask_mappings_router,
    buoy as buoy_router,
    buoy_notes as buoy_notes_router,
    dashboard as dashboard_router,
    dns_summary as dns_summary_router,
    entity as entity_router,
    fleet as fleet_router,
    incidents as incidents_router,
    ingest as ingest_router,
    integration_mappings as integration_mappings_router,
    integration_vendor_links as integration_vendor_links_router,
    integrations as integrations_router,
    known_benign as known_benign_router,
    nextdns as nextdns_router,
    proposals as proposals_router,
    sanitization as sanitization_router,
    search as search_router,
    vendor_device_links as vendor_device_links_router,
    search_export as search_export_router,
    source_health as source_health_router,
    tenant_compliance as tenant_compliance_router,
    tickets as tickets_router,
    tiers as tiers_router,
    tiles as tiles_router,
    unifi as unifi_router,
    webhooks as webhooks_router,
    whoami,
)

logger = logging.getLogger(__name__)

# NOTE 2026-05-11 (Phase 2 port):
# The following octo_admin routers are NOT yet ported into the framework:
#   audit, clients, events, indicators, ingestion, legacy_report, patterns,
#   source_admin, source_ingest, tokens
# They will be re-implemented against the new adapter framework + bridge
# contract rather than ported verbatim, since their data access pattern
# (direct SQLite queries) needs to flow through the bridge.

API_TITLE = "OCTO Admin + Query API"
API_VERSION = "1.0.0"
API_DESCRIPTION = """\
Admin and ingestion surface for the per-client OCTO data layer.

Implements the endpoints declared in spec §6.2 of
`octo-multi-tenancy-per-database.md` (v1.1).

**Auth model**

- Admin endpoints (`/api/v1/clients`, `/api/v1/audit`, `/api/v1/patterns`):
  `Authorization: Bearer <admin-token>` resolving to a row in
  `registry.db::operators`. Middleware enforces `scope_slugs` — callers see
  only the clients their role is scoped to.
- Ingestion endpoints (`/api/v1/ingest/{slug}/...`): `Authorization: Bearer
  <buoy-token>` resolving to exactly one slug via `client_tokens`. Middleware
  refuses if the URL slug does not match the token slug
  (`ISOLATION_VIOLATION`).

**Error model**

Every error is a structured JSON body: `{code, message, request_id}`.
Codes are stable strings — clients may pattern-match on them. The list is
enumerated in `ERROR_CODES`.

**Rate limiting**

Every route is subject to a per-(caller, route) fixed-window limit. Limits are
generous by default and configurable per route class in `config.py`. Breaches
return `429 RATE_LIMITED`.
"""


def create_app() -> FastAPI:
    # Auto-apply any pending registry-touching migrations before the
    # routers attach. This is the production entrypoint (a systemd-unit
    # deploy runs `apps.octo.api:create_app`, NOT
    # `apps.octo.main:create_app`); without this hook a deployed
    # bundle's registry.db silently lags the code, surfacing as opaque
    # `no such column` 500s on dashboard / fleet endpoints. Idempotent:
    # no-op when the DB is already at the latest user_version.
    # Caught 2026-05-20 on the legacy host, where migration 021
    # (lat/lng cols) was sitting unapplied for hours after the rollout.
    from apps.octo.auth.bootstrap import (
        ensure_registry_migrations_applied,
        ensure_patterns_migrations_applied,
    )
    from apps.octo import paths
    try:
        ensure_registry_migrations_applied(paths.registry_db_path())
    except Exception as e:  # noqa: BLE001 — never block app boot on this
        import logging
        logging.getLogger("octo.bootstrap").error(
            "registry auto-migrate failed at boot: %s", e, exc_info=True,
        )
    # Same self-heal posture for the global patterns.db (sanitized
    # cross-tenant pool). Added 2026-05-21 with M3 migration 023; the
    # safety substrate needs the pool schema current before any pool
    # write path is taken.
    try:
        if paths.patterns_db_path().exists():
            ensure_patterns_migrations_applied(paths.patterns_db_path())
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger("octo.bootstrap").error(
            "patterns auto-migrate failed at boot: %s", e, exc_info=True,
        )

    app = FastAPI(
        title=API_TITLE,
        version=API_VERSION,
        description=API_DESCRIPTION,
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    install_exception_handlers(app)
    install_rate_limit_middleware(app)
    install_setup_gate_middleware(app)

    app.include_router(whoami.router, prefix="/api/v1", tags=["whoami"])
    app.include_router(auth_router.router, prefix="/api/v1", tags=["auth"])
    app.include_router(admin_ops.router, prefix="/api/v1",
                        tags=["admin-operators"])
    app.include_router(admin_data_router.router, prefix="/api/v1",
                        tags=["admin-data"])
    app.include_router(admin_clients.router, prefix="/api/v1",
                        tags=["admin-clients"])
    app.include_router(admin_tenants_router.router, prefix="/api/v1",
                        tags=["admin-tenants"])
    app.include_router(admin_tenants_router.quarantine_router, prefix="/api/v1",
                        tags=["admin-quarantine"])
    app.include_router(admin_notices_router.router, prefix="/api/v1",
                        tags=["admin-notices"])
    app.include_router(tenant_compliance_router.router, prefix="/api/v1",
                        tags=["admin-tenants"])
    app.include_router(adapters_router.router, prefix="/api/v1",
                        tags=["admin-adapters"])
    app.include_router(integrations_router.router, prefix="/api/v1",
                        tags=["integrations"])
    app.include_router(ingest_router.router, prefix="/api/v1",
                       tags=["ingest"])
    app.include_router(dashboard_router.router, prefix="/api/v1",
                        tags=["dashboard"])
    app.include_router(source_health_router.router, prefix="/api/v1",
                        tags=["dashboard"])
    app.include_router(dns_summary_router.router, prefix="/api/v1",
                        tags=["dashboard"])
    app.include_router(dns_summary_router.search_router, prefix="/api/v1",
                        tags=["search"])
    app.include_router(nextdns_router.search_router, prefix="/api/v1",
                        tags=["search"])
    app.include_router(nextdns_router.router, prefix="/api/v1",
                        tags=["integrations"])
    app.include_router(unifi_router.router, prefix="/api/v1",
                        tags=["integrations"])
    app.include_router(entity_router.router, prefix="/api/v1", tags=["entity"])
    app.include_router(fleet_router.router, prefix="/api/v1", tags=["fleet"])
    app.include_router(alert_verdicts_router.router, prefix="/api/v1", tags=["alerts"])
    app.include_router(proposals_router.router, prefix="/api/v1", tags=["proposals"])
    app.include_router(incidents_router.router, prefix="/api/v1", tags=["incidents"])
    app.include_router(incidents_router.signals_router, prefix="/api/v1", tags=["incidents"])
    app.include_router(tiers_router.router, prefix="/api/v1", tags=["tiers"])
    app.include_router(known_benign_router.router, prefix="/api/v1", tags=["admin"])
    app.include_router(search_router.router, prefix="/api/v1",
                        tags=["search"])
    app.include_router(search_export_router.router, prefix="/api/v1",
                        tags=["search-export"])
    app.include_router(tickets_router.router, prefix="/api/v1",
                        tags=["tickets"])
    app.include_router(agent_activity_router.router, prefix="/api/v1",
                        tags=["agent"])
    app.include_router(agent_query_router.router, prefix="/api/v1",
                        tags=["agent", "llm"])
    app.include_router(agent_query_router.notes_router, prefix="/api/v1",
                        tags=["agent"])
    app.include_router(account_preferences_router.router, prefix="/api/v1",
                        tags=["account"])
    app.include_router(admin_llm_models_router.router, prefix="/api/v1",
                        tags=["admin", "llm"])
    app.include_router(admin_llm_grants_router.router, prefix="/api/v1",
                        tags=["admin", "llm"])
    app.include_router(admin_bundle_config_router.router, prefix="/api/v1",
                        tags=["admin", "llm"])
    app.include_router(autotask_mappings_router.router, prefix="/api/v1",
                        tags=["integrations-autotask"])
    app.include_router(admin_psa_router.router, prefix="/api/v1",
                        tags=["admin", "psa"])
    app.include_router(buoy_router.router, prefix="/api/v1", tags=["buoy"])
    app.include_router(buoy_notes_router.router, prefix="/api/v1",
                        tags=["buoy", "notes"])
    app.include_router(tiles_router.router, prefix="/api/v1", tags=["tiles"])
    app.include_router(sanitization_router.router, prefix="/api/v1",
                        tags=["sanitization"])
    app.include_router(event_stream_router, prefix="/api/v1", tags=["events"])
    app.include_router(webhooks_router.router, prefix="/api/v1", tags=["webhooks"])
    app.include_router(integration_mappings_router.router, prefix="/api/v1",
                        tags=["integration-mappings"])
    app.include_router(integration_vendor_links_router.router, prefix="/api/v1",
                        tags=["integration-vendor-links"])
    app.include_router(vendor_device_links_router.router, prefix="/api/v1",
                        tags=["dashboard"])
    # NOTE: there is intentionally NO dev auto-login route. This is a
    # security platform — auth bypasses don't get to exist, even gated.
    # Use the real /login flow (`dev-admin` operator + provisioned TOTP)
    # for local-dev sign-in.
    # NOTE 2026-05-11: legacy /report + ingestion + clients + etc. routers
    # land in a follow-up port pass against the new adapter framework.

    @app.get("/healthz", tags=["meta"])
    def healthz():
        return {"ok": True}

    from apps.octo.api.readiness import install_readiness_route
    install_readiness_route(app)

    _wire_adapter_runtime(app)
    _wire_polled_read_audit(app)
    _wire_webhook_receipts(app)
    _wire_host_metrics(app)
    _wire_triage_worker(app)
    _wire_entity_resolution(app)
    _wire_evidence_window_restore(app)
    _wire_tier_worker(app)
    _wire_enrichment_worker(app)
    _wire_retention_scheduler(app)
    _wire_synthetic_traffic(app)
    _wire_mapping_review(app)
    return app


def _wire_enrichment_worker(app: FastAPI) -> None:
    """Remote-IP enrichment (v0.17.2, C): ONE background worker looks queued
    addresses up (PTR over DNS-over-HTTPS to a public resolver, the owner
    over RDAP — never the local resolver, never the address itself) and
    caches the answers; a page never waits for it. OCTO_IP_ENRICHMENT=off:
    no worker, nothing leaves the box (`apps.octo.enrich`)."""
    from apps.octo.enrich import worker as enrich_worker

    if not enrich_worker.enabled():
        logger.info("ip enrichment disabled (OCTO_IP_ENRICHMENT=off)")
        return
    w = enrich_worker.EnrichmentWorker()
    app.state.enrichment_worker = w
    enrich_worker.set_current(w)

    @app.on_event("startup")
    async def _start_enrichment_worker() -> None:  # pyright: ignore
        try:
            w.start()
        except Exception:  # noqa: BLE001
            logger.exception("enrichment worker failed to start")

    @app.on_event("shutdown")
    async def _stop_enrichment_worker() -> None:  # pyright: ignore
        import asyncio

        try:
            await asyncio.to_thread(w.stop)
        except Exception:  # noqa: BLE001
            logger.exception("enrichment worker failed to stop cleanly")


def _wire_retention_scheduler(app: FastAPI) -> None:
    """The nightly retention job (`apps.octo.retention`), in-process. Off
    unless OCTO_RETENTION_SCHEDULE is truthy (the bundle's compose ships it
    "0": the operator switches it on after the upgrade order; tests and dev
    never prune). Stored on app.state for Settings → System."""
    from apps.octo import paths
    from apps.octo.retention.scheduler import (
        RetentionScheduler, schedule_enabled, schedule_hour,
    )

    if not schedule_enabled():
        logger.info("retention scheduler disabled (OCTO_RETENTION_SCHEDULE unset)")
        return
    scheduler = RetentionScheduler(
        hour_utc=schedule_hour(), registry_db=paths.registry_db_path(),
    )
    app.state.retention_scheduler = scheduler

    @app.on_event("startup")
    async def _start_retention() -> None:  # pyright: ignore
        try:
            scheduler.start()
        except Exception:  # noqa: BLE001
            logger.exception("retention scheduler failed to start")

    @app.on_event("shutdown")
    async def _stop_retention() -> None:  # pyright: ignore
        try:
            scheduler.stop()
        except Exception:  # noqa: BLE001
            logger.exception("retention scheduler failed to stop cleanly")


def _wire_entity_resolution(app: FastAPI) -> None:
    """Entity resolution (migration 040): the feed consumers (UniFi sites /
    leases, Datto inventory, NextDNS device presence) are registered for the
    pollers, and the one-minute worker runs. Each does nothing for a tenant
    whose switch is 'off' (the default). OCTO_ENTITY_WORKER=0 disables the
    worker (the feeds still record for shadow / on tenants)."""
    from apps.octo.entity import feeders
    from apps.octo.entity.worker import EntityWorker, enabled

    try:
        feeders.register_all()
    except Exception:  # noqa: BLE001 — never block app boot
        logger.exception("entity feed consumers failed to register")
    if not enabled():
        logger.info("entity worker disabled (OCTO_ENTITY_WORKER=0)")
        return
    worker = EntityWorker()
    app.state.entity_worker = worker

    @app.on_event("startup")
    async def _start_entity_worker() -> None:  # pyright: ignore
        try:
            await worker.start()
        except Exception:  # noqa: BLE001
            logger.exception("entity worker failed to start")

    @app.on_event("shutdown")
    async def _stop_entity_worker() -> None:  # pyright: ignore
        try:
            await worker.stop()
        except Exception:  # noqa: BLE001
            logger.exception("entity worker failed to stop cleanly")


def _wire_evidence_window_restore(app: FastAPI) -> None:
    """On startup, every tenant (whatever its status) whose events.db holds
    evidence windows a 044 rollback parked gets 044 again, so a re-upgrade
    shows them and an admin can release them (`threat.store.
    restore_parked_windows`). Independent of OCTO_TIER_WORKER; off the event
    loop, never fatal."""
    from apps.octo.threat import store as incident_store

    @app.on_event("startup")
    async def _restore_parked_windows() -> None:  # pyright: ignore
        import asyncio

        try:
            await asyncio.to_thread(incident_store.restore_parked_windows)
        except Exception:  # noqa: BLE001
            logger.exception("parked evidence windows not restored")


def _wire_tier_worker(app: FastAPI) -> None:
    """The tier engine (Tier Black slice 1, `apps.octo.threat.engine`): a
    30-second pass — slice 1's shadow rules, the paging ladder, client
    visibility, the FR2 coverage notices and the heartbeat the threat layer
    reads. OCTO_TIER_WORKER=0 disables it (every site's threat layer then
    reads "threat correlator not running" — unknown — unless an incident is
    open: stale never reads ok)."""
    from apps.octo.threat import engine

    if not engine.enabled():
        logger.info("tier worker disabled (OCTO_TIER_WORKER=0)")
        return
    worker = engine.TierWorker(manager=getattr(app.state, "instance_manager", None))
    app.state.tier_worker = worker
    engine.set_current(worker)

    @app.on_event("startup")
    async def _start_tier_worker() -> None:  # pyright: ignore
        try:
            worker.manager = getattr(app.state, "instance_manager", None)
            await worker.start()
        except Exception:  # noqa: BLE001
            logger.exception("tier worker failed to start")

    @app.on_event("shutdown")
    async def _stop_tier_worker() -> None:  # pyright: ignore
        try:
            await worker.stop()
        except Exception:  # noqa: BLE001
            logger.exception("tier worker failed to stop cleanly")


def _wire_mapping_review(app: FastAPI) -> None:
    """The same-name fix (Phase 0, 2026-10-01): on startup, tenant mappings
    an earlier version made from a NAME alone are listed for every admin+ in
    one `mapping_review` notice (once per mapping; `instances.mapping_review`).
    Off the event loop, never fatal."""
    from apps.octo.instances import mapping_review

    @app.on_event("startup")
    async def _mapping_review_notice() -> None:  # pyright: ignore
        import asyncio

        try:
            await asyncio.to_thread(mapping_review.notify)
        except Exception:  # noqa: BLE001
            logger.exception("mapping review notice failed")


def _wire_polled_read_audit(app: FastAPI) -> None:
    """The hourly roll-up for polled reads (`auth.audit_rollup`): one per
    app, and on shutdown every open window gets its close row (marked
    partial) so a deploy does not drop the counts of the current hour."""
    from apps.octo.auth.audit_rollup import PolledReadAudit

    rollup = PolledReadAudit.for_app(app)

    @app.on_event("shutdown")
    async def _flush_polled_read_audit() -> None:  # pyright: ignore
        try:
            rollup.flush()
        except Exception:  # noqa: BLE001
            logger.exception("polled-read audit roll-up failed to flush")


def _wire_webhook_receipts(app: FastAPI) -> None:
    """Start the webhook-receipt flusher on startup, stop it (writing what is
    pending) on shutdown. The webhook routes only note receipts in memory;
    this is what persists them — at most once per interval, off the request
    path — so an integration card can still say "never" or "last received …"
    truthfully after a restart."""
    from apps.octo import paths
    from apps.octo.instances import webhook_receipt

    @app.on_event("startup")
    async def _start_webhook_receipts() -> None:  # pyright: ignore
        try:
            webhook_receipt.start_flusher(paths.registry_db_path())
        except Exception:  # noqa: BLE001
            logger.exception("webhook receipt flusher failed to start")

    @app.on_event("shutdown")
    async def _stop_webhook_receipts() -> None:  # pyright: ignore
        try:
            webhook_receipt.stop_flusher()
        except Exception:  # noqa: BLE001
            logger.exception("webhook receipt flusher failed to stop cleanly")


def _wire_host_metrics(app: FastAPI) -> None:
    """Spin up the host metrics sampler on startup, stop on shutdown.
    Stored on app.state.host_metrics_sampler for the
    /dashboard/host-metrics endpoint to read."""
    from apps.octo.runtime.host_metrics import HostMetricsSampler

    sampler = HostMetricsSampler()
    app.state.host_metrics_sampler = sampler

    @app.on_event("startup")
    async def _start_host_metrics() -> None:  # pyright: ignore
        try:
            await sampler.start()
            logger.info("host metrics sampler started")
        except Exception:  # noqa: BLE001
            logger.exception("host metrics sampler failed to start")

    @app.on_event("shutdown")
    async def _stop_host_metrics() -> None:  # pyright: ignore
        try:
            await sampler.stop()
        except Exception:  # noqa: BLE001
            logger.exception("host metrics sampler failed to stop cleanly")


def _wire_triage_worker(app: FastAPI) -> None:
    """Start the autonomous Triage L1 worker on startup, stop on shutdown.
    Disabled by setting OCTO_TRIAGE_WORKER=0. Stored on app.state for
    diagnostics. The default decider is heuristic-only (119b); 119c swaps
    in the LLM-on-uncertain decider."""
    from apps.octo.agent.llm_escalation import make_llm_decider
    from apps.octo.agent.worker import AutonomousTriageWorker

    if not AutonomousTriageWorker.is_enabled():
        logger.info("autonomous triage worker disabled (OCTO_TRIAGE_WORKER=0)")
        return

    # Heuristic-first + LLM-on-uncertain (119c). The decider checks the LLM
    # gates per-decision, so a runtime bundle-config toggle takes effect
    # without restart; with the bundle LLM off it's pure heuristic.
    worker = AutonomousTriageWorker(decide=make_llm_decider())
    app.state.triage_worker = worker

    @app.on_event("startup")
    async def _start_triage_worker() -> None:  # pyright: ignore
        try:
            await worker.start()
        except Exception:  # noqa: BLE001
            logger.exception("triage worker failed to start")

    @app.on_event("shutdown")
    async def _stop_triage_worker() -> None:  # pyright: ignore
        try:
            await worker.stop()
        except Exception:  # noqa: BLE001
            logger.exception("triage worker failed to stop cleanly")


def _wire_synthetic_traffic(app: FastAPI) -> None:
    """Dev-only: mount the synthetic-traffic control router + arm the
    generator. No-op unless synthetic_allowed() (OCTO_DEV_SYNTHETIC=1 on a
    dev data-root), so production never sees the route or the task."""
    from apps.octo.dev.synthetic_traffic import (
        SyntheticTrafficGenerator, synthetic_allowed,
    )

    if not synthetic_allowed():
        return

    from apps.octo.api.routers import dev_synthetic

    app.include_router(dev_synthetic.router, prefix="/api/v1", tags=["dev"])
    gen = SyntheticTrafficGenerator()
    app.state.synthetic_traffic = gen
    logger.info("dev synthetic-traffic control mounted at /api/v1/dev/synthetic-traffic")

    @app.on_event("startup")
    async def _start_synthetic() -> None:  # pyright: ignore
        try:
            await gen.start()
        except Exception:  # noqa: BLE001
            logger.exception("synthetic traffic generator failed to start")

    @app.on_event("shutdown")
    async def _stop_synthetic() -> None:  # pyright: ignore
        try:
            await gen.stop()
        except Exception:  # noqa: BLE001
            logger.exception("synthetic traffic generator failed to stop cleanly")


def _wire_adapter_runtime(app: FastAPI) -> None:
    """Best-effort: build an AdapterRegistry, discover apps.octo.adapters,
    construct an InstanceManager, and auto-start every persisted instance.

    Failures here log a warning but do NOT prevent the app from coming up —
    the admin/catalog endpoints surface an empty list and the operator can
    fix the underlying issue (e.g., missing credentials key file) via the
    UI. The adapter runtime is best-effort because the auth surface
    (/login, /whoami, etc.) must remain reachable even if the framework
    can't initialize.

    Tests that need control over the registry overwrite
    `app.state.adapter_registry` after create_app() returns.
    """
    try:
        from apps.octo import credentials
        from apps.octo.framework import AdapterRegistry, InMemoryRegistryBackend
        from apps.octo.framework.discovery import discover_adapters
        from apps.octo.instances import InstanceManager

        credentials.ensure_key_file()
        registry = AdapterRegistry(backend=InMemoryRegistryBackend())
        report = discover_adapters("apps.octo.adapters", registry=registry)
        if report.failed:
            logger.warning(
                "[octo-api] adapter discovery had %d failure(s): %s",
                len(report.failed), report.failed,
            )
        manager = InstanceManager(adapter_registry=registry)
        summary = manager.start_all_persisted()
        if summary["failed"]:
            logger.warning(
                "[octo-api] %d persisted instance(s) failed to auto-start: %s",
                len(summary["failed"]), summary["failed"],
            )
        app.state.adapter_registry = registry
        app.state.instance_manager = manager
    except Exception as exc:
        logger.warning("[octo-api] adapter runtime wire-up failed: %s", exc)
