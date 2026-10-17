import { useCallback, useEffect, useMemo, useState, type FC, type ReactNode } from "react";
import GridLayout, { type Layout } from "react-grid-layout";
import "react-grid-layout/css/styles.css";
import "./dashboard.css";
import HeroPanel, { type HeroTab } from "@/components/hero-panel";
import WidgetCard, { MinimizedPill } from "@/components/widget-card";
import { DefaultAlertFeed } from "@widgets/default-alert-feed";
import { DefaultCounterGrid } from "@widgets/default-counter-grid";
import { DefaultStatusPanel } from "@widgets/default-status-panel";
import Oscilloscope, { PERCENT_THRESHOLDS } from "@/components/oscilloscope";
import { DefaultListWithActions } from "@widgets/default-list-with-actions";
import {
  ApiError,
  fetchDevicesAttention,
  fetchHostMetrics,
  fetchIntegrationHealth,
  fetchRecentEvents,
  fetchThroughput,
  fetchTiPulse,
  fetchDnsSummary,
  resolveVendorDeviceLink,
  type DeviceAttentionRow,
  type IntegrationHealthRow,
  type RecentEventRow,
  type ThroughputPoint,
} from "@/lib/api";
import { listTickets, getTicket, type TicketDetail } from "@/lib/tickets";
import SourceHealthPanel from "@/components/source-health-panel";
import { type AlertRow, vendorSessionNote } from "@/contracts/alert";
import {
  FloatingTicketWindow,
} from "@/components/floating-ticket-window";
import AlertDrawer from "@/components/alert-drawer";
import NeedsReviewNotice from "@/components/needs-review-notice";
import TiPulsePanel, { type TiPulseState } from "@/components/ti-pulse-panel";
import DnsSummaryPanel, { type DnsSummaryState } from "@/components/dns-summary-panel";
import { indicatorSearchHref, type TiPulseItem } from "@/contracts/indicator";
import type { MeResponse } from "@/contracts/operator";
import { navigateTo } from "@/lib/router";
import {
  useWidgetLayout,
} from "@/lib/widget-layout";

// Grid sizing. RGL uses a 12-column grid. Widget defaults are
// per-widget — alerts + throughput are wider; misc tiles are compact.
// h is in row units (default rowHeight=80 → h=3 ≈ 240px tall).
const GRID_COLS = 12;
const GRID_ROW_HEIGHT = 80;
// More generous gap (was [16,16]) — matches Micro-IT's airy whitespace
// rhythm (the visual-inspiration design notes).
const GRID_GAP: [number, number] = [20, 20];
// Uniform defaults — every widget is 4-wide × 3-tall, giving the same
// "three across" layout as the original CSS grid (grid-cols-3 at xl).
// Operators resize per-widget during Customize; whatever they save wins.
const WIDGET_DEFAULT_SIZE: Record<string, { w: number; h: number }> = {
  "current-alerts":    { w: 4, h: 3 },
  "open-tickets":      { w: 4, h: 3 },
  "devices-attention": { w: 4, h: 3 },
  "ti-pulse":          { w: 4, h: 3 },
  "dns-summary":       { w: 4, h: 3 },
  // 2026-05-20: Source Health now carries the tier-count header on top
  // of the rotator (the former Buoy Heartbeat counter widget was merged
  // in — its data was hardcoded; merging eliminated dead UI and freed a
  // grid cell). Bumped to h:4 to comfortably fit both pieces.
  "source-health":     { w: 4, h: 4 },
  "throughput":        { w: 4, h: 3 },
};
const WIDGET_FALLBACK_SIZE = { w: 4, h: 3 };
const WIDGET_MIN_SIZE = { w: 3, h: 2 };

// Throughput preset matrix. Each entry is tuned to give ~30-60 buckets
// of resolution within its window so spikes stay visible across all
// time scales. refreshMs is paced so short windows feel "live" while
// long windows don't beat on the backend.
type ThroughputPresetId = "15m" | "1h" | "5h" | "24h" | "7d";
const THROUGHPUT_PRESETS: Record<
  ThroughputPresetId,
  {
    label: string;
    windowMinutes: number;
    bucketMinutes: number;
    refreshMs: number;
    rateUnit: string;  // "/min" | "/hr" — what the rate-per-X uses
  }
> = {
  "15m": { label: "15m", windowMinutes: 15,    bucketMinutes: 1,  refreshMs: 10_000,  rateUnit: "/min" },
  "1h":  { label: "1h",  windowMinutes: 60,    bucketMinutes: 1,  refreshMs: 15_000,  rateUnit: "/min" },
  "5h":  { label: "5h",  windowMinutes: 300,   bucketMinutes: 5,  refreshMs: 30_000,  rateUnit: "/min" },
  "24h": { label: "24h", windowMinutes: 1440,  bucketMinutes: 15, refreshMs: 60_000,  rateUnit: "/hr"  },
  "7d":  { label: "7d",  windowMinutes: 10080, bucketMinutes: 60, refreshMs: 300_000, rateUnit: "/hr"  },
};
const THROUGHPUT_PRESET_ORDER: ThroughputPresetId[] = ["15m", "1h", "5h", "24h", "7d"];

/** Sum + per-unit rate for the counter overlay. */
function summarizeThroughput(
  points: ReadonlyArray<{ v: number }>,
  preset: ThroughputPresetId,
): { total: number; rate: number; rateUnit: string } {
  const cfg = THROUGHPUT_PRESETS[preset];
  const total = points.reduce((acc, p) => acc + p.v, 0);
  // rate = events per minute (or hour, depending on preset) averaged
  // across the window. Simple + honest — not "current bucket" which
  // would swing wildly on low-volume tail.
  let rate: number;
  if (cfg.rateUnit === "/min") {
    rate = total / cfg.windowMinutes;
  } else {
    rate = (total / cfg.windowMinutes) * 60;
  }
  return { total, rate: Math.round(rate), rateUnit: cfg.rateUnit };
}

function formatThroughputCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 10_000) return `${Math.round(n / 1_000)}k`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

interface WidgetDef {
  readonly id: string;
  readonly title: string;
  readonly subtitle?: string;
  readonly help: ReactNode;
  readonly render: () => ReactNode;
}

interface DashboardPageProps {
  readonly username: string | null;
  /** The signed-in operator — the "needs review" notice renders for admin+
   *  only (and fetches nothing for anyone else). */
  readonly me?: MeResponse | null;
}

const DashboardPage: FC<DashboardPageProps> = ({ username, me = null }) => {
  // Real fleet-wide throughput from OCTO events.db. Refresh cadence +
  // bucket granularity vary by preset — short windows poll faster so
  // the curve appears to move; longer windows poll slowly since their
  // shape changes much less per tick.
  const [throughputPreset, setThroughputPreset] =
    useState<ThroughputPresetId>("1h");
  const [throughputPoints, setThroughputPoints] = useState<ThroughputPoint[]>([]);
  const [throughputError, setThroughputError] = useState<string | null>(null);
  const [throughputLoaded, setThroughputLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const preset = THROUGHPUT_PRESETS[throughputPreset];
    setThroughputLoaded(false);  // Re-loading on preset change
    const load = async (): Promise<void> => {
      try {
        const r = await fetchThroughput({
          windowMinutes: preset.windowMinutes,
          bucketMinutes: preset.bucketMinutes,
        });
        if (cancelled) return;
        setThroughputPoints(r.points);
        setThroughputError(null);
        setThroughputLoaded(true);
      } catch (e) {
        if (cancelled) return;
        const msg = e instanceof ApiError ? e.message : "Failed to load throughput";
        setThroughputError(msg);
        setThroughputLoaded(true);
      }
    };
    void load();
    const id = setInterval(() => { void load(); }, preset.refreshMs);
    return () => { cancelled = true; clearInterval(id); };
  }, [throughputPreset]);

  // Live-only — no synthetic fallback. The Oscilloscope renders an
  // empty trace until the first real bucket lands; flicker is preferable
  // to fabricated curves on a production dashboard.
  const throughputDisplayPoints = useMemo(
    () => (throughputLoaded && !throughputError ? throughputPoints : []),
    [throughputLoaded, throughputError, throughputPoints],
  );

  // W13: live container/host metrics feed. Pulls from
  // /dashboard/host-metrics — the OCTO container's actual CPU + RAM
  // utilization. Same shape as throughput points; the Oscilloscope
  // component doesn't care where the data came from. Polls every
  // 30s to match the backend sampler's 60s cadence.
  const [cpuPoints, setCpuPoints] = useState<ThroughputPoint[]>([]);
  const [ramPoints, setRamPoints] = useState<ThroughputPoint[]>([]);
  useEffect(() => {
    const preset = THROUGHPUT_PRESETS[throughputPreset];
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        const r = await fetchHostMetrics({
          windowMinutes: preset.windowMinutes,
          bucketMinutes: preset.bucketMinutes,
        });
        if (cancelled) return;
        setCpuPoints(r.cpu_points);
        setRamPoints(r.mem_points);
      } catch {
        // Quiet fail — leaves the mini rows on stale data. The
        // throughput error banner is the loud surface.
      }
    };
    void load();
    const id = setInterval(() => { void load(); }, 30_000);
    return () => { cancelled = true; clearInterval(id); };
  }, [throughputPreset]);

  // Latest values for the row labels — uses the rightmost (newest)
  // bucket. NaN-safe.
  const cpuLatest = cpuPoints.length > 0
    ? cpuPoints[cpuPoints.length - 1]!.v
    : 0;
  const ramLatest = ramPoints.length > 0
    ? ramPoints[ramPoints.length - 1]!.v
    : 0;

  // W1: live integration health for the source-health panel +
  // integrations-up counter tile. Polls every 30s; on failure, falls
  // through to the mock so the widget stays populated.
  const [integrationHealth, setIntegrationHealth] = useState<
    IntegrationHealthRow[] | null
  >(null);
  useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        const items = await fetchIntegrationHealth();
        if (!cancelled) setIntegrationHealth(items);
      } catch {
        if (!cancelled) setIntegrationHealth(null);
      }
    };
    void load();
    const id = setInterval(() => { void load(); }, 30_000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  const integrationStatusRows = useMemo(() => {
    if (integrationHealth && integrationHealth.length > 0) {
      return integrationHealth.map((row) => {
        // exactOptionalPropertyTypes: omit `detail` rather than send
        // `undefined`. Conditional-spread keeps the type clean.
        const base = {
          id: row.slug,
          name: row.name,
          status: row.health as "ok" | "degraded" | "down" | "pending" | "unknown",
        };
        return row.detail ? { ...base, detail: row.detail } : base;
      });
    }
    return [];
  }, [integrationHealth]);

  // Source health (integrations + ingest tokens + buoys) is its own
  // component with its own polling: see SourceHealthPanel.

  // W2: ticket counter tiles. Three parallel total-only fetches every
  // 30s. In Athena, tickets ARE the operator's open-alert queue (the
  // noise-dismissal-then-promote design), so we use ticket
  // totals as the "open alerts" / P1 / P2 numerics directly. Mock
  // counts hold as fallback until first load lands.
  const [ticketCounts, setTicketCounts] = useState<{
    open: number | null;
    p1: number | null;
    p2: number | null;
  }>({ open: null, p1: null, p2: null });
  useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        const [openRes, p1Res, p2Res] = await Promise.all([
          listTickets({ status: "open", pageSize: 1 }),
          listTickets({ status: "open", severity: "critical", pageSize: 1 }),
          listTickets({ status: "open", severity: "high", pageSize: 1 }),
        ]);
        if (cancelled) return;
        setTicketCounts({
          open: openRes.total,
          p1: p1Res.total,
          p2: p2Res.total,
        });
      } catch {
        // Quietly fall through to mock counts; the integrations error
        // banner is the loud surface for backend issues.
      }
    };
    void load();
    const id = setInterval(() => { void load(); }, 30_000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  const openAlertsCount = ticketCounts.open ?? 0;
  const p1Count = ticketCounts.p1 ?? 0;
  const p2Count = ticketCounts.p2 ?? 0;

  // W3: live recent-events feed across the operator's in-scope tenants.
  // Polls every 20s. Mapped to AlertRow shape so the existing
  // DefaultAlertFeed widget can render it unchanged. Mock fallback
  // until the first real load lands.
  const [recentEvents, setRecentEvents] = useState<RecentEventRow[] | null>(
    null,
  );
  useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        const items = await fetchRecentEvents({ limit: 30 });
        if (!cancelled) setRecentEvents(items);
      } catch {
        if (!cancelled) setRecentEvents(null);
      }
    };
    void load();
    const id = setInterval(() => { void load(); }, 20_000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  // W6: live Devices Needing Attention feed. Ranks source_hosts by
  // recent high+critical event volume per the new
  // /dashboard/devices-attention endpoint. Polls every 30s.
  const [devicesAttention, setDevicesAttention] = useState<
    DeviceAttentionRow[] | null
  >(null);
  useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        const items = await fetchDevicesAttention({ limit: 20 });
        if (!cancelled) setDevicesAttention(items);
      } catch {
        if (!cancelled) setDevicesAttention(null);
      }
    };
    void load();
    const id = setInterval(() => { void load(); }, 30_000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  // Map DeviceAttentionRow → ListRow shape consumed by the widget.
  // The host gets the title slot, tenant + severity into subtitle,
  // and the one-line reason goes to meta (right column on each row).
  const devicesAttentionRows = useMemo(() => {
    if (!devicesAttention) return [];
    return devicesAttention.map((d) => ({
      id: `${d.tenant}:${d.host}`,
      title: d.host,
      subtitle: `${d.tenant} · ${d.severity}`,
      meta: d.reason,
      // "open" target: a reference the server resolves ON CLICK (the vendor
      // portal addresses a device by an id only its API knows). Null when
      // no lookup could succeed.
      deviceRef: d.vendor_device_ref ?? null,
    }));
  }, [devicesAttention]);

  // W4: live open-tickets feed surfaced as a dashboard widget. Same
  // data the /tickets list shows, capped to the 20 most-recently-
  // updated. Click-through stashes the focus key + navigates to
  // /tickets so the operator lands in the same ticket window flow
  // they'd get from the /search drawer.
  const [openTicketRows, setOpenTicketRows] = useState<readonly AlertRow[]>([]);
  useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        const r = await listTickets({ status: "open", pageSize: 20 });
        if (cancelled) return;
        // Map TicketSummary → AlertRow so DefaultAlertFeed can render
        // it unchanged. Ticket statuses collapse to alert statuses:
        //   new, reopened          → open
        //   in_progress, waiting_* → acknowledged
        //   resolved, closed       → resolved
        const mapStatus = (s: string): AlertRow["status"] => {
          if (s === "new" || s === "reopened") return "open";
          if (s === "resolved" || s === "closed") return "resolved";
          return "acknowledged";
        };
        const rows: AlertRow[] = r.tickets.map((t) => ({
          id: `ticket:${t.client_slug}:${t.id}`,
          severity: t.severity,
          status: mapStatus(t.status),
          source: t.queue || "ticket",
          tenant: t.client_slug,
          title: t.title,
          summary: t.assignee_operator_id !== null
            ? `assigned to operator #${t.assignee_operator_id}`
            : (t.queue ? `in queue: ${t.queue}` : "unassigned"),
          occurred_at: t.updated_at,
        }));
        setOpenTicketRows(rows);
      } catch {
        // Quiet fail; mock isn't a sensible fallback for tickets.
      }
    };
    void load();
    const id = setInterval(() => { void load(); }, 20_000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  // W5: inline ticket window — clicking an Open Tickets row opens the
  // FloatingTicketWindow on the dashboard instead of navigating to
  // /tickets. Same component, same behavior (status/severity/notes
  // edit), just mounted here.
  const [openTicketDetail, setOpenTicketDetail] = useState<TicketDetail | null>(null);
  const [openTicketLoading, setOpenTicketLoading] = useState(false);
  const [openTicketError, setOpenTicketError] = useState<string | null>(null);

  const openTicketFromAlertRow = useCallback(async (row: AlertRow): Promise<void> => {
    if (!row.id.startsWith("ticket:")) return;
    // id shape "ticket:<slug>:<num>"
    const rest = row.id.slice("ticket:".length);
    const idx = rest.lastIndexOf(":");
    if (idx <= 0) return;
    const slug = rest.slice(0, idx);
    const tid = Number(rest.slice(idx + 1));
    if (!Number.isFinite(tid)) return;

    // Skeleton from the row so the window mounts immediately with
    // something meaningful. Real detail fetches in parallel.
    const mapStatus = (s: AlertRow["status"]): TicketDetail["status"] => {
      if (s === "open") return "new";
      if (s === "resolved") return "resolved";
      return "in_progress";
    };
    setOpenTicketLoading(true);
    setOpenTicketError(null);
    setOpenTicketDetail({
      id: tid, client_slug: slug, autotask_id: null,
      title: row.title, severity: row.severity, status: mapStatus(row.status),
      assignee_operator_id: null, queue: null, source_event_id: null,
      opened_at: row.occurred_at, updated_at: row.occurred_at,
      agent_note_count: 0,
      description: "", closed_at: null, last_autotask_sync_at: null,
      due_at: null, push_to_autotask: false, is_billable: true,
      billing_code_id: null, contract_id: null, charges: [],
      push_state: null, status_history: [],
      agent_insights: [], agent_pattern_links: [],
    });
    try {
      const t = await getTicket(slug, tid);
      setOpenTicketDetail(t);
    } catch (e) {
      setOpenTicketError(e instanceof Error ? e.message : String(e));
    } finally {
      setOpenTicketLoading(false);
    }
  }, []);

  // W5: inline alert drawer — clicking an alert row opens an
  // AlertDrawer with the metadata we have + a "View payload in
  // /search" affordance (the only path to the gated full payload).
  const [openAlertRow, setOpenAlertRow] = useState<AlertRow | null>(null);
  const openAlert = useCallback((row: AlertRow): void => {
    setOpenAlertRow(row);
  }, []);

  // Threat-intel pulse: recently sighted indicators, values MASKED by the
  // server. Analyst+ — a Viewer's 403 renders as "not for your role". A row
  // opens the step-up-gated indicator search for that one row (its
  // search_ref names the row, never the value). Polls every 60s.
  const [tiPulse, setTiPulse] = useState<TiPulseState>({ status: "loading" });
  useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        const data = await fetchTiPulse({ limit: 20 });
        if (!cancelled) setTiPulse({ status: "ready", data });
      } catch (e) {
        if (cancelled) return;
        setTiPulse(
          e instanceof ApiError && e.status === 403
            ? { status: "forbidden" }
            : { status: "error" },
        );
      }
    };
    void load();
    const id = setInterval(() => { void load(); }, 60_000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);
  const openPulseIndicator = useCallback((item: TiPulseItem): void => {
    navigateTo(indicatorSearchHref(item.search_ref));
  }, []);

  // DNS summary: buoy DNS telemetry (migration 036) over the last 24 h —
  // lookups, blocked, top domains, first-seen domains. Domains MASKED by the
  // server; analyst+ (a Viewer's 403 renders as "not for your role"). Polls
  // every 60s.
  const [dnsSummary, setDnsSummary] = useState<DnsSummaryState>({ status: "loading" });
  useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        const data = await fetchDnsSummary({ hours: 24, top: 5, firstSeenLimit: 10 });
        if (!cancelled) setDnsSummary({ status: "ready", data });
      } catch (e) {
        if (cancelled) return;
        setDnsSummary(
          e instanceof ApiError && e.status === 403
            ? { status: "forbidden" }
            : { status: "error" },
        );
      }
    };
    void load();
    const id = setInterval(() => { void load(); }, 60_000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  const liveAlerts: readonly AlertRow[] = useMemo(() => {
    if (!recentEvents) return [];
    return recentEvents.map((e) => ({
      // event_id is unique-per-tenant; prefix with slug to be globally
      // unique inside the AlertRow list.
      id: `${e.client_slug}:${e.event_id}`,
      severity: e.severity,
      status: e.status,
      source: e.source || "unknown",
      tenant: e.client_slug,
      // For sources that present their alerts (Datto): the headline and the
      // longer detail. For the rest: event type + stored summary, as before.
      title: e.title,
      summary: e.summary,
      occurred_at: e.occurred_at,
      device: e.device ?? null,
      site: e.site ?? null,
      vendor_links: e.vendor_links ?? [],
      vendor_device_ref: e.vendor_device_ref ?? null,
    }));
  }, [recentEvents]);
  // The "current alerts" hero tab + "recent alerts" widget consume
  // the same source. The TOAST surface (high-severity ambient
  // notifications) is wired separately and already pulls real events.
  const alertNowReference = new Date();

  const integrationsUpCount = useMemo(() => {
    const src = integrationHealth ?? [];
    if (src.length === 0) return "0/0";
    const up = src.filter((r) => r.health === "ok").length;
    return `${up}/${src.length}`;
  }, [integrationHealth]);
  const throughputStats = useMemo(
    () => summarizeThroughput(throughputPoints, throughputPreset),
    [throughputPoints, throughputPreset],
  );

  // Shared body used by BOTH the hero "Traffic flow" tab (large) and the
  // grid "Event throughput" widget (compact). They share the same state
  // so a preset change in one mirrors instantly in the other.
  const renderThroughputBlock = useCallback((
    chartHeight: number,
    mode: "widget" | "hero" = "widget",
  ): ReactNode => (
    // W12: full-height flex column. In widget mode the main
    // oscilloscope is flex-1 so it grows / shrinks with the card on
    // customize-mode resize. In hero mode the parent has no fixed
    // height so flex-fill would balloon — there we use a fixed pixel
    // height and let the block sit at its intrinsic height.
    <div className={
      mode === "widget"
        ? "flex h-full flex-col gap-2 min-h-0"
        : "flex flex-col gap-2"
    }>
      {/* Time window selector — moved above per Rick's feedback so
          the eye reads "I'm looking at X minutes" before the chart. */}
      <div
        role="tablist"
        aria-label="Throughput time window"
        className="flex items-center justify-center gap-3 font-mono text-[10px] uppercase tracking-wider"
      >
        {THROUGHPUT_PRESET_ORDER.map((id, i) => (
          <span key={id} className="flex items-center gap-3">
            {i > 0 && (
              <span aria-hidden="true" className="text-text-dim">·</span>
            )}
            <button
              type="button"
              role="tab"
              onClick={() => setThroughputPreset(id)}
              aria-selected={throughputPreset === id}
              className={
                throughputPreset === id
                  ? "text-accent underline underline-offset-4 decoration-accent/60"
                  : "text-text-dim hover:text-accent transition-colors"
              }
            >
              {THROUGHPUT_PRESETS[id].label}
            </button>
          </span>
        ))}
      </div>

      {/* Main oscilloscope — fills available height in widget mode,
       * fixed pixel height in hero mode (parent's flex context decides
       * whether flex-fill is safe). */}
      <div className={mode === "widget" ? "flex-1 min-h-0" : ""}>
        <Oscilloscope
          rate={throughputStats.rateUnit === "/hr"
                  ? throughputStats.rate / 60
                  : throughputStats.rate}
          // W8: real bucket points → peak envelope tracks actual spikes.
          points={throughputDisplayPoints}
          // W9: bucket size drives the left-scroll cadence.
          bucketSeconds={THROUGHPUT_PRESETS[throughputPreset].bucketMinutes * 60}
          // W10: window → ruler tick spacing + hover "T-<delta>" label.
          windowMinutes={THROUGHPUT_PRESETS[throughputPreset].windowMinutes}
          readoutLabel="events"
          // W12: flex-fill mode only when the parent has a fixed
          // height (= widget card). Hero variant gets a pinned px.
          fillHeight={mode === "widget"}
          height={chartHeight}
        />
      </div>

      <div className="flex items-center justify-center gap-3 font-mono text-[10px] text-text-secondary">
        <span title="Total events in window">
          Σ {formatThroughputCount(throughputStats.total)}
        </span>
        <span aria-hidden="true" className="text-text-dim">·</span>
        <span title="Average rate across window">
          {formatThroughputCount(throughputStats.rate)}{throughputStats.rateUnit}
        </span>
      </div>

      {/* W11: matching mini-oscilloscope rows for system load + RAM.
          Fixed height — they don't flex; the main one absorbs all
          extra space. TODO: real backend endpoints — these are
          client-side synthetic for the visual today. */}
      <div className="flex flex-col gap-2 pt-1 border-t border-border/40">
        <MiniMetricRow
          label="cpu"
          value={`${cpuLatest}%`}
          tone="text-accent"
        >
          <Oscilloscope
            rate={cpuLatest}
            points={cpuPoints}
            thresholds={PERCENT_THRESHOLDS}
            bucketSeconds={THROUGHPUT_PRESETS[throughputPreset].bucketMinutes * 60}
            readoutLabel="% cpu"
            height={36}
          />
        </MiniMetricRow>
        <MiniMetricRow
          label="ram"
          value={`${ramLatest}%`}
          tone="text-high"
        >
          <Oscilloscope
            rate={ramLatest}
            points={ramPoints}
            thresholds={PERCENT_THRESHOLDS}
            bucketSeconds={THROUGHPUT_PRESETS[throughputPreset].bucketMinutes * 60}
            readoutLabel="% ram"
            height={36}
          />
        </MiniMetricRow>
      </div>
    </div>
  ), [
    throughputPreset, throughputStats, throughputDisplayPoints,
    cpuPoints, ramPoints, cpuLatest, ramLatest,
  ]);

  const heroTabs: HeroTab[] = [
    {
      id: "alerts",
      label: "Current alerts",
      subtitle: "Shallow Layer 1 outputs · sorted by severity then recency",
      badge: <Badge tone="critical">{liveAlerts.filter((a) => a.severity === "critical").length}</Badge>,
      // Cap the hero tab to 4 visible rows + internal scroll. The
      // grid-mounted "Current alerts" widget already has its own
      // max-rows; this keeps the hero panel from growing unbounded
      // when there are 100+ open alerts in scope.
      content: (
        <div className="max-h-[320px] overflow-y-auto pr-1">
          <DefaultAlertFeed
            rows={liveAlerts}
            maxRows={4}
            now={alertNowReference}
            onSelect={openAlert}
          />
        </div>
      ),
      help: (
        <>
          Live feed of alerts produced by Shallow Layer 1 (the
          deterministic-rule pass over ingested events). Sorted by severity
          (P1 critical → P4 info) then by recency. Status filter defaults
          to <strong>open</strong>; resolved/suppressed alerts are excluded
          unless toggled.
        </>
      ),
    },
    {
      id: "traffic",
      label: "Traffic flow",
      subtitle: throughputError
        ? "real data — unavailable"
        : throughputLoaded
          ? `fleet-wide · last ${THROUGHPUT_PRESETS[throughputPreset].label} · live`
          : "loading…",
      content: renderThroughputBlock(180, "hero"),
      help: (
        <>
          Fleet-wide event throughput across every configured source —
          buoy sensors plus API-pull integrations, once configured.
          The window selector below the chart tunes both granularity
          and refresh rate: <strong>15m / 1h</strong> tick every 10-15s
          for a live feel; <strong>24h / 7d</strong> refresh slower
          since their shape changes much less per minute. The selector
          here is the same selector as the secondary widget below — they
          mirror each other.
        </>
      ),
    },
    {
      id: "status",
      label: "Status overview",
      subtitle: "Health snapshot across all integrations and the bridge layer",
      content: (
        <div className="flex flex-col gap-5">
          <DefaultCounterGrid
            counters={[
              { id: "alerts-open", label: "open alerts", value: openAlertsCount, tone: "accent" },
              { id: "p1", label: "P1 critical", value: p1Count, tone: "critical" },
              { id: "p2", label: "P2 high", value: p2Count, tone: "high" },
              { id: "ints-up", label: "integrations up", value: integrationsUpCount, tone: "success" },
            ]}
          />
          <DefaultStatusPanel rows={integrationStatusRows} />
        </div>
      ),
      help: (
        <>
          One-glance health snapshot. Counters: open alerts (across all
          tenants), P1 critical, P2 high, integrations connected vs total.
          Below: per-integration health rows showing connection state and
          last-success timestamp.
        </>
      ),
    },
  ];

  // Canonical widget definitions for the secondary grid. The layout
  // hook reconciles operator's stored preferences against this list.
  // Order here is the default layout; operator can reorder + close any
  // widget. (No pinned section anymore — every widget is movable +
  // closable per Rick 2026-05-12.)
  const widgets = useMemo<WidgetDef[]>(
    () => [
      {
        id: "current-alerts",
        title: "Current alerts",
        subtitle: "live · sorted by severity",
        help: (
          <>
            Live alert feed. Same data as the hero panel's Current alerts
            tab. Drag to reorder, click ▾ to minimize, or ✕ to hide via
            the Customize affordance — restore from the +Restore menu.
          </>
        ),
        render: () => (
          <DefaultAlertFeed
            rows={liveAlerts} maxRows={6} now={new Date()}
            onSelect={openAlert}
          />
        ),
      },
      // "Recent alerts" widget removed 2026-05-14 — it rendered the
      // same liveAlerts source through the same DefaultAlertFeed with
      // the same sort (severity desc, then recency desc) as Current
      // alerts. Existing operator layouts that referenced it drop the
      // id at load via the v2 schema's unknown-id filter.
      {
        id: "open-tickets",
        title: "Open tickets",
        subtitle: "your in-scope workload · click to open",
        help: (
          <>
            Live view into the /tickets queue — every open ticket in
            your visibility scope, ranked by severity then recency.
            Click a row to open the ticket in /tickets with the
            window/drawer already populated. Auto-refreshes every 20s
            so a colleague's status change shows up quickly.
          </>
        ),
        render: () => (
          <DefaultAlertFeed
            rows={openTicketRows}
            maxRows={8}
            now={new Date()}
            onSelect={(r) => void openTicketFromAlertRow(r)}
          />
        ),
      },
      {
        id: "devices-attention",
        title: "Devices needing attention",
        subtitle: "ranked by current priority",
        help: (
          <>
            Devices flagged across RMM/EDR sources with open issues —
            missing patches, agent offline, malware detection, etc.
            Ranked by composite priority (severity × age × asset
            criticality). <em>Open</em> looks the device's page up in the
            vendor portal and opens it in a new tab, when the device came
            from an integration that can link to it. <em>Isolate</em> is not
            available yet.
          </>
        ),
        render: () => (
          <DefaultListWithActions
            rows={devicesAttentionRows}
            actions={[
              {
                id: "open",
                label: "open",
                tone: "accent",
                resolveHref: (row) => {
                  const ref = row.deviceRef;
                  return ref ? () => resolveVendorDeviceLink(ref) : undefined;
                },
                // "Open device in Datto RMM — Opens in a new tab and needs an
                // active Datto RMM sign-in…": the portal's own sign-in is the
                // one reason an exact link still lands on its home page.
                title: (row) => {
                  const ref = row.deviceRef;
                  if (!ref) return undefined;
                  const portal = ref.label.replace(/^Open (device )?in /, "") || undefined;
                  return `${ref.label} — ${vendorSessionNote(portal)}`;
                },
                disabledReason: "no vendor portal link for this device",
              },
              // Isolation is governed by its own multi-step safety procedure
              // and is deliberately NOT wired to anything here.
              {
                id: "isolate",
                label: "isolate",
                tone: "danger",
                disabled: true,
                disabledReason: "not available yet",
              },
            ]}
          />
        ),
      },
      {
        id: "ti-pulse",
        title: "Threat-intel pulse",
        subtitle: tiPulse.status === "ready"
          ? `sighted in the last ${tiPulse.data.lookback_days}d · values masked`
          : "values masked · click for the full value",
        help: (
          <>
            Indicators (IPs, domains, hashes…) most recently sighted in
            your tenants&apos; own events, newest first. An indicator is
            recorded when an ingested event carries one, and not every
            integration&apos;s alerts do. No public threat-intel feed is
            connected and the cross-MSP pool is not running, so this
            shows your tenants&apos; own sightings only. Values are masked
            here; click a row to see the full value in Search, which asks
            you to re-authenticate. The filter box narrows the visible
            rows by tenant or type.
          </>
        ),
        render: () => (
          <TiPulsePanel state={tiPulse} onOpen={openPulseIndicator} />
        ),
      },
      {
        id: "dns-summary",
        title: "DNS summary",
        subtitle: dnsSummary.status === "ready"
          ? `last ${dnsSummary.data.window_hours}h · domains masked`
          : "buoy DNS · domains masked",
        help: (
          <>
            DNS lookups your tenants&apos; devices made, as seen by their
            buoys (Pi-hole and Suricata) over the last 24 hours: how many,
            how many were blocked, the most-looked-up domains and the domains
            a tenant had never looked up before (&quot;first-seen&quot; — worth a
            look when the baseline is established; reverse lookups and
            single-label names are left out). Lookups are counted by ONE
            sensor — Pi-hole&apos;s answered queries, or Suricata&apos;s query
            records where a buoy has no Pi-hole — never both. Domains are
            masked and devices are never named here; &quot;who looked this name
            up?&quot; has no console page yet — it is the API POST
            /api/v1/search/dns (re-authentication). Tenants without a
            reporting buoy have no DNS telemetry.
          </>
        ),
        render: () => <DnsSummaryPanel state={dnsSummary} />,
      },
      {
        id: "source-health",
        title: "Source health",
        subtitle: "integrations · ingest · buoys · problems first",
        help: (
          <>
            One view of every source feeding Athena: integrations (pollers
            and webhooks), ingest tokens such as a SIEM shim, and buoys. Each
            card shows its status and how long ago Athena last heard from it
            — the last successful poll for a poller, the last accepted event
            for a push source, the last heartbeat for a buoy — measured on
            Athena&apos;s own clock. A source is <em>stale</em> when that is
            older than expected for its kind; failing and stale sources float
            to the front, and the tenants they deliver into are listed below
            them. A tenant with no recent alerts is not a problem by itself.{" "}
            <strong>Manage →</strong> on a buoy opens it on the Fleet page.
            Client users see only when their own alerts were last received.
          </>
        ),
        render: () => <SourceHealthPanel />,
      },
      {
        id: "throughput",
        title: "Event throughput",
        subtitle: throughputError
          ? "real data — unavailable"
          : throughputLoaded
            ? `last ${THROUGHPUT_PRESETS[throughputPreset].label} · live`
            : "loading…",
        help: (
          <>
            Aggregated events across every source adapter (buoy + API
            integrations), one curve per selected window. A flat-line at
            zero indicates fleet-wide ingestion failure; spikes correlate
            with alerting bursts visible in the alert feed. Window
            selector tunes both bucket granularity + refresh cadence —
            <strong>15m/1h</strong> tick every 10-15s, <strong>24h/7d</strong>{" "}
            every minute or five.
          </>
        ),
        render: () => renderThroughputBlock(72),
      },
      // 2026-05-20: "Buoy heartbeat" counter widget retired — its
      // counters were hardcoded (online: 12, offline: 1, ...) and the
      // information is now surfaced live as the tier-count header strip
      // inside the Source Health widget. Single widget, glance + drill,
      // no redundancy. Operators that had `buoy-heartbeat` saved in
      // their dashboard layout will have it gracefully dropped on next
      // load (canonical-id reconciliation in dashboard layout v1.2).
    ],
    // EVERY value a widget's title/subtitle/help/render reads. A missing one
    // freezes that widget at whatever it showed when this list last changed
    // (every widget used to refresh only when throughput did). Source health
    // reads nothing from here: SourceHealthPanel owns and polls its state.
    [
      liveAlerts,
      openAlert,
      openTicketRows,
      openTicketFromAlertRow,
      devicesAttentionRows,
      tiPulse,
      openPulseIndicator,
      dnsSummary,
      throughputLoaded,
      throughputError,
      throughputPreset,
      renderThroughputBlock,
    ],
  );

  const widgetById = useMemo(() => {
    const m = new Map<string, WidgetDef>();
    for (const w of widgets) m.set(w.id, w);
    return m;
  }, [widgets]);

  const canonical = useMemo(
    () => widgets.map((w) => ({ id: w.id })),
    [widgets],
  );

  const { layout, toggleMinimized, hide, restore, resetToDefaults,
          setGridPlacement } = useWidgetLayout(canonical, username);

  const minimize = (id: string): void => {
    const e = layout.entries.find((x) => x.id === id);
    if (e && !e.minimized) toggleMinimized(id);
  };
  const restoreFromMinimized = (id: string): void => {
    const e = layout.entries.find((x) => x.id === id);
    if (e && e.minimized) toggleMinimized(id);
  };

  const [customizing, setCustomizing] = useState(false);

  /** Build the RGL layout array from stored entries + per-widget defaults.
   * Entries with stored x/y use them verbatim. Entries without stored
   * coords get auto-flowed left-to-right, top-to-bottom in widget order
   * — we compute explicit (x, y) ourselves rather than relying on RGL's
   * auto-placement, which doesn't compact y=Infinity entries cleanly. */
  const buildGridLayout = (visible: typeof layout.entries): Layout[] => {
    let flowX = 0;
    let flowY = 0;
    let rowMaxH = 0;
    return visible.map((e) => {
      const def = WIDGET_DEFAULT_SIZE[e.id] ?? WIDGET_FALLBACK_SIZE;
      const w = e.w ?? def.w;
      const h = e.h ?? def.h;
      // Stored coords win.
      if (e.x !== undefined && e.y !== undefined) {
        return {
          i: e.id, x: e.x, y: e.y, w, h,
          minW: WIDGET_MIN_SIZE.w, minH: WIDGET_MIN_SIZE.h,
        };
      }
      // Auto-flow: wrap to next row when current would overflow 12 cols.
      if (flowX + w > GRID_COLS) {
        flowX = 0;
        flowY += rowMaxH;
        rowMaxH = 0;
      }
      const item: Layout = {
        i: e.id, x: flowX, y: flowY, w, h,
        minW: WIDGET_MIN_SIZE.w, minH: WIDGET_MIN_SIZE.h,
      };
      flowX += w;
      rowMaxH = Math.max(rowMaxH, h);
      return item;
    });
  };

  const onLayoutChange = (next: Layout[]): void => {
    // Only persist when customizing — prevents accidental writes from
    // RGL's initial-mount layout reconciliation.
    if (!customizing) return;
    setGridPlacement(
      next.map((l) => ({ id: l.i, x: l.x, y: l.y, w: l.w, h: l.h })),
    );
  };

  // Two zones now: grid (reorderable, expanded) + tray (compact pills,
  // minimized). Hidden widgets live in the restore menu. (Earlier the
  // top two alert widgets were pinned-only-minimizable; reversed
  // 2026-05-12 per Rick — every widget is now movable + closable.)
  const gridEntries = layout.entries.filter(
    (e) => e.visible && !e.minimized,
  );
  const trayEntries = layout.entries.filter(
    (e) => e.visible && e.minimized,
  );
  const hiddenEntries = layout.entries.filter((e) => !e.visible);

  return (
    <>
      {/* Admin+ only; renders nothing while nothing needs a human. */}
      <NeedsReviewNotice me={me} />

      <HeroPanel tabs={heroTabs} />

      <section
        aria-label="secondary widgets"
        className="flex flex-col gap-3"
      >
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
            Widgets
            {customizing && (
              <span className="ml-2 rounded-full bg-accent/15 px-2 py-0.5 text-[10px] font-mono normal-case tracking-normal text-accent">
                customizing — drag to move, corner-handle to resize, ▾ minimize, ✕ hide
              </span>
            )}
          </h2>
          <div className="flex items-center gap-2">
            {customizing && hiddenEntries.length > 0 && (
              <RestoreMenu
                hidden={hiddenEntries.map((e) => ({
                  id: e.id,
                  title: widgetById.get(e.id)?.title ?? e.id,
                }))}
                onRestore={restore}
              />
            )}
            {customizing && (
              <button
                type="button"
                onClick={resetToDefaults}
                className="rounded-sm border border-border bg-bg-card px-2 py-1 text-[11px] text-text-secondary transition-colors hover:border-border-bright hover:text-text-primary"
                title="Restore default layout"
              >
                Reset layout
              </button>
            )}
            <button
              type="button"
              onClick={() => setCustomizing((v) => !v)}
              aria-pressed={customizing}
              className={[
                "inline-flex items-center gap-1.5 rounded-sm border px-2.5 py-1 text-[11px] transition-colors",
                customizing
                  ? "border-accent bg-accent text-text-on-accent"
                  : "border-border bg-bg-card text-text-secondary hover:border-border-bright hover:text-accent",
              ].join(" ")}
              title={customizing ? "Save layout + lock" : "Customize widgets"}
            >
              <span aria-hidden="true">{customizing ? "🔓" : "🔒"}</span>
              <span>{customizing ? "Done" : "Customize"}</span>
            </button>
          </div>
        </div>

        {/* react-grid-layout: drag + resize ONLY when Customize is on.
            Layout locks when toggled off. */}
        {gridEntries.length > 0 ? (
          <div className={customizing ? "dashboard-customizing" : ""}>
            <GridLayout
              className="layout"
              layout={buildGridLayout(gridEntries)}
              cols={GRID_COLS}
              rowHeight={GRID_ROW_HEIGHT}
              width={1448}
              margin={GRID_GAP}
              containerPadding={[0, 0]}
              isDraggable={customizing}
              isResizable={customizing}
              compactType="vertical"
              preventCollision={false}
              onLayoutChange={onLayoutChange}
              autoSize
            >
              {gridEntries.map((entry) => {
                const w = widgetById.get(entry.id);
                if (!w) return null;
                return (
                  <div key={entry.id}>
                    <WidgetCard
                      id={entry.id}
                      title={w.title}
                      {...(w.subtitle ? { subtitle: w.subtitle } : {})}
                      help={w.help}
                      customizing={customizing}
                      onMinimize={() => minimize(entry.id)}
                      onClose={() => hide(entry.id)}
                    >
                      {w.render()}
                    </WidgetCard>
                  </div>
                );
              })}
            </GridLayout>
          </div>
        ) : trayEntries.length === 0 && (
          <div className="rounded-lg border border-dashed border-border bg-bg-surface/50 p-8 text-center text-sm text-text-dim">
            All widgets hidden or minimized. Click{" "}
            <strong>Customize</strong> → <strong>+ Restore</strong> to
            bring hidden ones back, or click ▴ on a tray pill below
            to expand it.
          </div>
        )}

        {/* Minimized tray — compact pills below the grid */}
        {trayEntries.length > 0 && (
          <div className="mt-2 rounded-lg border border-dashed border-border bg-bg-surface/40 p-2.5">
            <div className="mb-1.5 px-1 text-[10px] font-mono uppercase tracking-wider text-text-dim">
              Minimized · click ▴ to restore
            </div>
            <div className="flex flex-wrap gap-2">
              {trayEntries.map((entry) => {
                const w = widgetById.get(entry.id);
                if (!w) return null;
                return (
                  <MinimizedPill
                    key={entry.id}
                    id={entry.id}
                    title={w.title}
                    customizing={customizing}
                    onRestore={() => restoreFromMinimized(entry.id)}
                    onClose={() => hide(entry.id)}
                  />
                );
              })}
            </div>
          </div>
        )}
      </section>

      {/* W5 popouts — both portal'd to document.body via their own
          components. Mounted at the dashboard level so they overlay
          all widgets regardless of grid position. */}
      {openTicketDetail !== null && (
        <FloatingTicketWindow
          ticket={openTicketDetail}
          loading={openTicketLoading}
          error={openTicketError}
          onClose={() => {
            setOpenTicketDetail(null);
            setOpenTicketError(null);
          }}
          onUpdated={(t) => setOpenTicketDetail(t)}
        />
      )}
      {openAlertRow !== null && (
        <AlertDrawer
          alert={openAlertRow}
          onClose={() => setOpenAlertRow(null)}
        />
      )}
    </>
  );
};

// W11: small label-on-left, oscilloscope-on-right row used to stack
// the CPU + RAM mini-feeds below the main throughput oscilloscope.
const MiniMetricRow: FC<{
  label: string;
  value: string;
  tone?: string;
  children: ReactNode;
}> = ({ label, value, tone = "text-accent", children }) => (
  <div className="flex items-center gap-2">
    <div className="flex w-14 shrink-0 flex-col items-end">
      <span className="font-mono text-[9px] uppercase tracking-widest text-text-dim">
        {label}
      </span>
      <span className={`font-mono text-[11px] ${tone}`}>{value}</span>
    </div>
    <div className="flex-1 min-w-0">{children}</div>
  </div>
);

const RestoreMenu: FC<{
  hidden: ReadonlyArray<{ id: string; title: string }>;
  onRestore: (id: string) => void;
}> = ({ hidden, onRestore }) => {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-1.5 rounded-sm border border-border bg-bg-card px-2.5 py-1 text-[11px] text-text-secondary transition-colors hover:border-border-bright hover:text-accent"
      >
        + Restore ({hidden.length})
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full z-30 mt-1 w-64 rounded-md border border-border bg-bg-elevated p-1 shadow-xl"
        >
          {hidden.map((h) => (
            <button
              key={h.id}
              type="button"
              role="menuitem"
              onClick={() => {
                onRestore(h.id);
                if (hidden.length === 1) setOpen(false);
              }}
              className="flex w-full items-center justify-between rounded px-3 py-2 text-left text-xs text-text-secondary hover:bg-accent-soft hover:text-accent"
            >
              <span>{h.title}</span>
              <span aria-hidden="true">+</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

const Badge: FC<{ tone: "critical" | "accent"; children: ReactNode }> = ({ tone, children }) => (
  <span
    className={[
      "rounded-full px-1.5 py-0.5 font-mono text-[10px]",
      tone === "critical" ? "bg-critical/15 text-critical" : "bg-accent-soft text-accent",
    ].join(" ")}
  >
    {children}
  </span>
);

export default DashboardPage;
