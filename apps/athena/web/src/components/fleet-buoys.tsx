/**
 * BuoyFleetView — the buoy fleet (the Fleet tab's "buoys" mode; before Fleet
 * v2 this WAS the Fleet tab). One card per buoy with health chip, uptime,
 * load + memory + disk, services, last heartbeat; or the buoys on the map
 * with the radar sweep and signal traces; the per-service rollup; the buoy
 * drawer (management, step-up gated commands). Unchanged by Fleet v2 — the
 * site-centric view (pages/fleet.tsx) shows buoys as a toggleable layer.
 *
 * Polls every 30 s. Scope-aware: rows are filtered by the operator's
 * scope_slugs (server enforces).
 */
import { type FC, lazy, Suspense, useEffect, useMemo, useState } from "react";

import {
  fetchBuoyFleet,
  fetchOctoLocation,
  formatDuration,
  isRetiredService,
  type BuoyFleetResponse,
  type BuoyFleetRow,
  type BuoyHealth,
  type OctoLocationResponse,
} from "@/lib/buoy";
import { ApiError, fetchStepUpStatus, getMe } from "@/lib/api";
import HelpTip from "@/components/help-tip";
import BuoyDrawer from "@/components/buoy-drawer";
import type { BuoyMarker, OctoNode } from "@/components/fleet-map-overlay";
import FleetRollup from "@/components/fleet-rollup";
import FleetSearch, { matchesBuoy, type HealthFilter } from "@/components/fleet-search";
import StepUpModal, { type StepUpReason } from "@/components/step-up-modal";

// Lazy: maplibre-gl is ~1.5MB and only needed in map view. CSS is
// eager-imported from main.tsx (see note there) so MapLibre's canvas
// styles are present at init regardless of when the JS lands.
const FleetMapView = lazy(() => import("@/components/fleet-map-view"));

const POLL_MS = 30_000;
const VIEW_STORAGE_KEY = "athena.fleet.view.v1";

type FleetView = "cards" | "map";

// Fallback OCTO node used only until `fetchOctoLocation()` returns. The
// real value comes from /api/v1/dashboard/octo-location which reads the
// `bundle_config.octo_location` row (migration 022) — that's how each
// MSP bundle's hub location stays configurable without a code change.
//
// The fallback is deliberately NOT anyone's location: the geographic centre
// of the contiguous US (a public survey landmark), unlabelled, shown only
// for the instant before the real hub location arrives.
export const FALLBACK_OCTO: OctoNode = {
  slug: "primary",
  display: "Primary",
  city: "Loading…",
  msp: "",
  lat: 39.828,
  lng: -98.579,
};

const HEALTH_LABEL: Record<BuoyHealth, string> = {
  green: "OK",
  yellow: "DEGRADED",
  red: "DOWN",
  stale: "STALE",
  unknown: "—",
};

const HEALTH_TONE: Record<BuoyHealth, string> = {
  green: "bg-success/10 text-success border-success/40",
  yellow: "bg-warning/10 text-warning border-warning/40",
  red: "bg-critical/10 text-critical border-critical/50",
  stale: "bg-text-dim/10 text-text-dim border-text-dim/40",
  unknown: "bg-text-dim/5 text-text-dim border-border",
};

const BuoyFleetView: FC = () => {
  const [resp, setResp] = useState<BuoyFleetResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Caller's max-tier role — drives client-side affordance hiding on
  // the buoy command drawer. Server is still the load-bearing check.
  const [callerRole, setCallerRole] = useState<string | null>(null);
  useEffect(() => {
    void getMe().then((me) => {
      if (!me || !Array.isArray(me.role)) return;
      const order = ["super_admin", "admin", "analyst", "viewer"];
      const max = order.find((r) => (me.role as string[]).includes(r));
      setCallerRole(max ?? null);
    }).catch(() => undefined);
  }, []);

  // Buoy drawer state — opening on card click.
  const [openBuoy, setOpenBuoy] = useState<BuoyFleetRow | null>(null);
  const [stepUpModalOpen, setStepUpModalOpen] = useState(false);
  const [stepUpReason, setStepUpReason] = useState<StepUpReason>("required");

  // View toggle — cards (default) vs map. Persisted per-operator.
  const [view, setView] = useState<FleetView>(() => {
    try {
      const saved = localStorage.getItem(VIEW_STORAGE_KEY);
      return saved === "map" ? "map" : "cards";
    } catch {
      return "cards";
    }
  });
  useEffect(() => {
    try { localStorage.setItem(VIEW_STORAGE_KEY, view); } catch { /* noop */ }
  }, [view]);

  // Search + tier-filter state. Both reset on page reload — they're
  // ephemeral "I'm narrowing my view right now" state, not preferences.
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [healthFilter, setHealthFilter] = useState<HealthFilter>(null);

  // OCTO hub location — fetched once on mount from bundle_config. The
  // map renders with FALLBACK_OCTO until this lands; tiny visual blip
  // for a few hundred ms but no missing hub icon at any point.
  const [octoLocation, setOctoLocation] = useState<OctoLocationResponse | null>(null);
  useEffect(() => {
    let cancelled = false;
    void fetchOctoLocation()
      .then((r) => { if (!cancelled) setOctoLocation(r); })
      .catch(() => { /* keep FALLBACK_OCTO */ });
    return () => { cancelled = true; };
  }, []);
  const octoNode: OctoNode = octoLocation
    ? {
      slug: octoLocation.slug,
      display: octoLocation.display,
      city: octoLocation.city,
      msp: octoLocation.msp,
      lat: octoLocation.lat,
      lng: octoLocation.lng,
    }
    : FALLBACK_OCTO;

  useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        const r = await fetchBuoyFleet();
        if (cancelled) return;
        setResp(r);
        setError(null);
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof ApiError ? e.message : "Failed to load fleet");
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void load();
    const id = setInterval(() => { void load(); }, POLL_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  const rows = resp?.buoys ?? [];

  // Deep-link from /dashboard → Source Health rotator "Manage →".
  // The dashboard navigates to `/fleet?focus=<slug>` and dispatches
  // `athena:navigate`; we read the slug, find the matching buoy, open
  // its drawer, and clear the param so a later refresh doesn't re-open
  // it. Bridge for the operator's "I see a problem on the dashboard →
  // jump straight into managing that buoy" flow (step-up + remote
  // terminal lives in the BuoyDrawer).
  useEffect(() => {
    if (rows.length === 0) return;        // wait for first fetch
    const readFocus = (): void => {
      const params = new URLSearchParams(window.location.search);
      const focus = params.get("focus");
      if (!focus) return;
      const match = rows.find((b) => b.slug === focus);
      if (match) {
        setOpenBuoy(match);
        // Clear the param so reloading the page doesn't re-pop the
        // drawer — the operator may have closed it intentionally.
        params.delete("focus");
        const search = params.toString();
        const url = window.location.pathname + (search ? `?${search}` : "");
        window.history.replaceState({}, "", url);
      }
    };
    readFocus();
    window.addEventListener("athena:navigate", readFocus);
    return () => window.removeEventListener("athena:navigate", readFocus);
  }, [rows]);

  // Sort: red/stale first (operator needs to see these), then yellow,
  // then green. Within each tier, alphabetical by slug.
  const sorted = useMemo(() => {
    const tierOrder: Record<BuoyHealth, number> = {
      red: 0, stale: 1, yellow: 2, unknown: 3, green: 4,
    };
    return [...rows].sort((a, b) => {
      const t = tierOrder[a.health] - tierOrder[b.health];
      if (t !== 0) return t;
      return a.slug.localeCompare(b.slug);
    });
  }, [rows]);

  // Apply search + tier filters to the sorted list. Both views (cards
  // + map) read from `filtered` so the filter state is consistent
  // across them.
  const filtered = useMemo(() => sorted.filter((b) => {
    if (healthFilter !== null && b.health !== healthFilter) return false;
    if (!matchesBuoy(b, searchQuery)) return false;
    return true;
  }), [sorted, searchQuery, healthFilter]);

  // Project filtered BuoyFleetRow → BuoyMarker for the map view. The
  // map only sees what survived the filter — so the rollup + the markers
  // tell the same story.
  const mapBuoys = useMemo<ReadonlyArray<BuoyMarker>>(() => filtered.map((b) => ({
    slug:     b.slug,
    hostname: b.hostname,
    city:     b.city ?? undefined,
    lat:      b.lat  ?? Number.NaN,
    lng:      b.lng  ?? Number.NaN,
    health:   b.health,
    octo:     b.octo ?? octoNode.slug,
  })), [filtered]);

  return (
    <section className="flex flex-col gap-5" aria-labelledby="fleet-title">
      {/* Status strip */}
      <div className="flex items-center justify-between gap-3 rounded-sm border border-border bg-bg-surface px-3 py-1.5 text-[11px] font-mono">
        <div className="flex items-center gap-2 text-text-secondary">
          <span aria-hidden="true" className="text-accent">▸</span>
          <span id="fleet-title" className="uppercase tracking-wider">fleet</span>
          <span aria-hidden="true" className="text-text-dim">·</span>
          <span>
            {rows.length === 0 && loading ? "loading…" : `${rows.length} buoy${rows.length === 1 ? "" : "s"} in scope`}
          </span>
          <HelpTip>
            One card per buoy reporting to OCTO. Heartbeats arrive every
            60s. Health = rollup of services + heartbeat staleness;
            stale/red rows float to the top so attention rows aren't
            buried.
          </HelpTip>
        </div>
        <div className="flex items-center gap-3 font-mono text-[10px] uppercase tracking-widest text-text-dim">
          <div className="flex items-center gap-1 rounded-sm border border-border bg-bg-card p-0.5">
            <button
              type="button"
              aria-pressed={view === "cards"}
              onClick={() => setView("cards")}
              className={[
                "rounded-sm px-2 py-0.5 transition-colors",
                view === "cards"
                  ? "bg-accent text-text-on-accent"
                  : "text-text-secondary hover:text-accent",
              ].join(" ")}
            >cards</button>
            <button
              type="button"
              aria-pressed={view === "map"}
              onClick={() => setView("map")}
              className={[
                "rounded-sm px-2 py-0.5 transition-colors",
                view === "map"
                  ? "bg-accent text-text-on-accent"
                  : "text-text-secondary hover:text-accent",
              ].join(" ")}
            >map</button>
          </div>
          <span>heartbeats 60s · ui poll {POLL_MS / 1000}s</span>
        </div>
      </div>

      {error && (
        <div className="rounded-sm border border-critical/40 bg-critical/10 px-3 py-2 text-[12px] text-critical">
          {error}
        </div>
      )}

      {rows.length === 0 && !loading && !error && (
        <div className="rounded-sm border border-border bg-bg-surface px-4 py-8 text-center text-[12px] text-text-dim">
          No buoys are reporting heartbeats yet. Install the{" "}
          <code className="font-mono text-text-secondary">buoy-heartbeat</code>{" "}
          daemon on a provisioned buoy and it will appear here within a minute.
        </div>
      )}

      {sorted.length > 0 && (
        <FleetSearch
          value={searchQuery}
          onChange={setSearchQuery}
          healthFilter={healthFilter}
          onHealthFilter={setHealthFilter}
          resultCount={filtered.length}
          totalCount={sorted.length}
        />
      )}

      {sorted.length > 0 && view === "cards" && filtered.length === 0 && (
        <div className="rounded-sm border border-border bg-bg-surface px-4 py-6 text-center text-[12px] text-text-dim">
          No buoys match the current search + filter.
        </div>
      )}

      {filtered.length > 0 && view === "cards" && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {filtered.map((b) => (
            <BuoyCard
              key={b.slug}
              buoy={b}
              onOpen={() => setOpenBuoy(b)}
            />
          ))}
        </div>
      )}

      {sorted.length > 0 && view === "map" && (
        <Suspense
          fallback={
            <div className="flex h-[640px] items-center justify-center rounded-sm border border-border bg-bg-surface font-mono text-[11px] uppercase tracking-widest text-text-dim">
              ·· loading map ··
            </div>
          }
        >
          <FleetMapView
            octos={[octoNode]}
            buoys={mapBuoys}
            selectedSlug={openBuoy?.slug ?? null}
            onBuoyClick={(b) => {
              const row = rows.find((r) => r.slug === b.slug);
              if (row) setOpenBuoy(row);
            }}
          />
        </Suspense>
      )}

      {sorted.length > 0 && (
        <FleetRollup buoys={sorted} />
      )}

      {openBuoy && (
        <BuoyDrawer
          buoy={openBuoy}
          callerRole={callerRole}
          onClose={() => setOpenBuoy(null)}
          onStepUpRequired={() => {
            setStepUpReason("required");
            setStepUpModalOpen(true);
          }}
        />
      )}

      <StepUpModal
        open={stepUpModalOpen}
        reason={stepUpReason}
        onClose={() => setStepUpModalOpen(false)}
        onSuccess={async () => {
          // Step-up succeeded → modal closes. Drawer stays open; the
          // next command-button click will succeed because the
          // window is now active server-side.
          setStepUpModalOpen(false);
          await fetchStepUpStatus().catch(() => null);
        }}
      />
    </section>
  );
};


// ---------------------------------------------------------------------------
// One card per buoy.
// ---------------------------------------------------------------------------

const BuoyCard: FC<{ buoy: BuoyFleetRow; onOpen?: () => void }> = ({
  buoy, onOpen,
}) => {
  const memPct = buoy.mem_used_mb !== null && buoy.mem_total_mb !== null && buoy.mem_total_mb > 0
    ? Math.round((buoy.mem_used_mb / buoy.mem_total_mb) * 100)
    : null;

  // Any non-active service flags the buoy for operator inspection,
  // independent of the overall health chip. Catches degraded ('failed',
  // 'inactive') AND service-discovery gaps ('missing'). Distinct from
  // the staleness-driven 'red'/'stale' tier — those signal heartbeat
  // pipe issues; this signals "service is reporting but in a bad state".
  // A unit DISABLED on purpose (retired) is not flagged — only a unit the
  // buoy should be running.
  const flaggedServices = Object.entries(buoy.services).filter(
    ([unit, info]) =>
      info.state !== "active" && !isRetiredService(unit, info, buoy.retired_services),
  );
  const needsInspection = flaggedServices.length > 0;

  // Format last_heartbeat_at as HH:MM:SS local time. Absolute clock
  // beats "23s ago" when the operator is comparing across many cards.
  const lastHbLocal = (() => {
    try {
      const d = new Date(buoy.last_heartbeat_at);
      return d.toLocaleTimeString(undefined, { hour12: false });
    } catch {
      return "—";
    }
  })();

  return (
    <article
      className={[
        "flex flex-col gap-2 rounded-sm border px-3 py-2.5 text-[11px]",
        needsInspection
          ? "border-warning/60 bg-warning/[0.04]"
          : "border-border bg-bg-card",
        onOpen
          ? "cursor-pointer transition-colors hover:border-accent"
          : "",
      ].filter(Boolean).join(" ")}
      aria-label={`buoy ${buoy.slug}`}
      onClick={onOpen}
      tabIndex={onOpen ? 0 : undefined}
      onKeyDown={onOpen ? (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpen();
        }
      } : undefined}
    >
      {/* Header — slug + health chip */}
      <header className="flex items-center justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="truncate font-mono text-[12px] font-semibold text-text-primary">
            {buoy.slug}
          </div>
          <div className="truncate font-mono text-[10px] text-text-dim">
            {buoy.hostname}
          </div>
        </div>
        <span
          className={[
            "rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider",
            HEALTH_TONE[buoy.health],
          ].join(" ")}
        >
          {HEALTH_LABEL[buoy.health]}
        </span>
      </header>

      {/* Inspection-needed badge — visible when any service ≠ active */}
      {needsInspection && (
        <div
          className="flex items-center gap-2 rounded-sm border border-warning/40 bg-warning/10 px-2 py-1 font-mono text-[10px] text-warning"
          role="alert"
        >
          <span aria-hidden="true">⚑</span>
          <span className="uppercase tracking-widest">needs inspection</span>
          <span className="text-warning/80">
            · {flaggedServices.length} service{flaggedServices.length === 1 ? "" : "s"} flagged
          </span>
        </div>
      )}

      {/* Metrics row */}
      <div className="grid grid-cols-3 gap-2 font-mono text-[10px] text-text-secondary">
        <Metric label="uptime">{formatDuration(buoy.uptime_sec)}</Metric>
        <Metric label="load 1m">{buoy.load_1?.toFixed(2) ?? "—"}</Metric>
        <Metric label="last hb">
          <span title={buoy.last_heartbeat_at}>
            {lastHbLocal}
            <span className="ml-1 text-text-dim">
              ({formatDuration(buoy.staleness_sec)} ago)
            </span>
          </span>
        </Metric>
      </div>

      {/* Resource bars */}
      <div className="flex flex-col gap-1">
        {memPct !== null && (
          <ResourceBar
            label="ram"
            valueLabel={`${buoy.mem_used_mb}/${buoy.mem_total_mb} MB`}
            pct={memPct}
          />
        )}
        {buoy.disk_used_pct !== null && (
          <ResourceBar
            label="disk"
            valueLabel={`${buoy.disk_used_pct}%`}
            pct={buoy.disk_used_pct}
          />
        )}
      </div>

      {/* Services */}
      {Object.keys(buoy.services).length > 0 && (
        <div className="flex flex-wrap gap-1 pt-1">
          {Object.entries(buoy.services).map(([unit, info]) => (
            <ServiceChip
              key={unit}
              unit={unit}
              state={isRetiredService(unit, info, buoy.retired_services) ? "retired" : info.state}
            />
          ))}
        </div>
      )}
    </article>
  );
};


const Metric: FC<{ label: string; children: React.ReactNode }> = ({
  label, children,
}) => (
  <div className="flex flex-col">
    <span className="uppercase tracking-widest text-text-dim">{label}</span>
    <span className="text-text-primary">{children}</span>
  </div>
);


const ResourceBar: FC<{
  label: string; valueLabel: string; pct: number;
}> = ({ label, valueLabel, pct }) => {
  const clamped = Math.max(0, Math.min(100, pct));
  // Color tone: <60% accent, 60-85% warning, >85% critical.
  const tone =
    clamped >= 85 ? "bg-critical" :
    clamped >= 60 ? "bg-warning" :
    "bg-accent";
  return (
    <div className="flex flex-col gap-0.5">
      <div className="flex items-baseline justify-between font-mono text-[10px]">
        <span className="uppercase tracking-widest text-text-dim">{label}</span>
        <span className="text-text-secondary">{valueLabel}</span>
      </div>
      <div className="h-1 w-full rounded-sm bg-bg-surface" role="progressbar"
           aria-valuenow={clamped} aria-valuemin={0} aria-valuemax={100}>
        <div
          className={`h-full rounded-sm ${tone}`}
          style={{ width: `${clamped}%` }}
        />
      </div>
    </div>
  );
};


const ServiceChip: FC<{ unit: string; state: string }> = ({ unit, state }) => {
  const tone =
    state === "active"   ? "bg-success/10 text-success border-success/40" :
    state === "inactive" ? "bg-text-dim/10 text-text-dim border-text-dim/40" :
    state === "failed"   ? "bg-critical/10 text-critical border-critical/50" :
    state === "missing"  ? "bg-bg-surface text-text-dim border-border" :
    state === "retired"  ? "bg-bg-surface text-text-dim border-border line-through" :
                           "bg-warning/10 text-warning border-warning/40";
  return (
    <span
      className={[
        "rounded-sm border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider",
        tone,
      ].join(" ")}
      title={state === "retired" ? `${unit}: retired (disabled on purpose)` : `${unit}: ${state}`}
      data-testid={`service-chip-${unit}`}
      data-state={state}
    >
      {unit}
    </span>
  );
};


export default BuoyFleetView;
