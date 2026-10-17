/**
 * FleetRollup — per-service N/M-healthy strip across the fleet.
 *
 * Per the 2026-05-19 Fleet redesign hand-off §1 (FleetRollup
 * row): six service chips below the map, each showing how many buoys
 * have that service reporting `active`. Buoys where the service is
 * `missing` (not bundled on that deploy) are excluded from the
 * denominator so we don't penalize buoys that legitimately don't run
 * a given daemon.
 *
 * Tone follows worst state across the fleet for that service:
 *   - dim:       0 buoys report → service not bundled anywhere
 *   - critical:  any failed     → at least one buoy is hard-down
 *   - warning:   any degraded   → at least one buoy is degraded
 *   - success:   all active     → fleet-wide green for that service
 *
 * v1 is read-only; clicking a chip to filter the map (kit's interaction)
 * lands when the FleetSearch tier-filter state is in place.
 */
import { type FC, useMemo } from "react";

import { isRetiredService, type BuoyFleetRow } from "@/lib/buoy";


interface ServiceRollupSpec {
  unit: string;
  label: string;
  sub: string;
}

/** Six services worth surfacing as a fleet-wide rollup. Order matches
 * the kit's recommended visual order — primary security stack first
 * (EDR/NIDS/DNS), then deception + transport last. */
const ROLLUP_SPECS: ReadonlyArray<ServiceRollupSpec> = [
  { unit: "wazuh-agent",    label: "Wazuh agent",   sub: "EDR" },
  { unit: "suricata",       label: "Suricata",      sub: "NIDS" },
  { unit: "pihole-FTL",     label: "Pi-hole",       sub: "DNS filter" },
  { unit: "opencanary",     label: "OpenCanary",    sub: "Deception" },
  { unit: "buoy-forwarder", label: "Buoy forwarder", sub: "Relay" },
  { unit: "tailscaled",     label: "Tailscale",     sub: "Mesh" },
];


interface RollupCell extends ServiceRollupSpec {
  active: number;
  total: number;
  degraded: number;
  failed: number;
  tone: "success" | "warning" | "critical" | "dim";
}


function computeRollup(buoys: ReadonlyArray<BuoyFleetRow>): RollupCell[] {
  return ROLLUP_SPECS.map((spec) => {
    let active = 0, total = 0, degraded = 0, failed = 0;
    for (const b of buoys) {
      // Staleness-aware counts: if we haven't heard from a buoy in 2×+
      // intervals (health = "stale" or "red"), its recorded service
      // states are no longer trustworthy — the daemon last reported
      // those values minutes ago and anything could have changed. Treat
      // such buoys as if they don't report this service at all, so the
      // rollup chips actually move as the fleet ages.
      if (b.health === "stale" || b.health === "red") continue;
      const info = b.services?.[spec.unit];
      if (!info) continue;
      const state = info.state;
      // Buoys that don't bundle this service at all → skip entirely
      // (legitimate omission, not a fleet-health red mark).
      if (!state || state === "missing") continue;
      // A unit an operator RETIRED (v0.11 B1) is grey on the card, not a
      // fault — nor is it one buoy short of healthy here.
      if (isRetiredService(spec.unit, info, b.retired_services)) continue;
      total += 1;
      if (state === "active")   active   += 1;
      if (state === "degraded") degraded += 1;
      if (state === "failed")   failed   += 1;
    }
    const tone: RollupCell["tone"] =
      total === 0          ? "dim"
      : failed > 0          ? "critical"
      : degraded > 0        ? "warning"
      : active === total    ? "success"
      :                       "warning";
    return { ...spec, active, total, degraded, failed, tone };
  });
}


/** Counts buoys by health tier — surfaced as a small row above the per-
 *  service chips so the fleet's overall posture is visible at a glance.
 *  Order: green / yellow / stale / red / unknown — same as the kit's
 *  recommended sort. */
export interface TierCounts {
  green: number;
  yellow: number;
  stale: number;
  red: number;
  unknown: number;
  total: number;
}

function computeTierCounts(buoys: ReadonlyArray<BuoyFleetRow>): TierCounts {
  const counts: TierCounts = {
    green: 0, yellow: 0, stale: 0, red: 0, unknown: 0, total: buoys.length,
  };
  for (const b of buoys) {
    if (b.health === "green") counts.green += 1;
    else if (b.health === "yellow") counts.yellow += 1;
    else if (b.health === "stale") counts.stale += 1;
    else if (b.health === "red") counts.red += 1;
    else counts.unknown += 1;
  }
  return counts;
}


// Internal helpers exported for tests.
export const __test__ = { computeRollup, computeTierCounts };


const TONE_STYLES: Record<RollupCell["tone"], { border: string; bg: string; dot: string; label: string }> = {
  success:  { border: "border-success/40",  bg: "bg-success/5",  dot: "bg-success",  label: "text-success" },
  warning:  { border: "border-warning/40",  bg: "bg-warning/5",  dot: "bg-warning",  label: "text-warning" },
  critical: { border: "border-critical/40", bg: "bg-critical/5", dot: "bg-critical", label: "text-critical" },
  dim:      { border: "border-border",      bg: "bg-bg-card",    dot: "bg-text-dim", label: "text-text-dim" },
};


interface FleetRollupProps {
  buoys: ReadonlyArray<BuoyFleetRow>;
}


const FleetRollup: FC<FleetRollupProps> = ({ buoys }) => {
  const rollups = useMemo(() => computeRollup(buoys), [buoys]);
  const tiers = useMemo(() => computeTierCounts(buoys), [buoys]);

  // Tier-row cells: only show tiers that actually have buoys in them so
  // an empty unknown/stale chip doesn't take up space. Order matches the
  // canonical sort priority — red first to draw the eye.
  type TierCell = {
    key: keyof TierCounts;
    label: string;
    count: number;
    tone: RollupCell["tone"];
  };
  const tierCells: TierCell[] = ([
    { key: "red",     label: "red",     count: tiers.red,     tone: "critical" },
    { key: "stale",   label: "stale",   count: tiers.stale,   tone: "warning" },
    { key: "yellow",  label: "yellow",  count: tiers.yellow,  tone: "warning" },
    { key: "green",   label: "green",   count: tiers.green,   tone: "success" },
    { key: "unknown", label: "unknown", count: tiers.unknown, tone: "dim" },
  ] as TierCell[]).filter((c) => c.count > 0);

  return (
    <section
      aria-labelledby="fleet-rollup-title"
      className="rounded-sm border border-border bg-bg-surface px-4 py-3"
    >
      <header className="mb-2 flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-text-dim">
        <span aria-hidden="true" className="text-accent">··</span>
        <span id="fleet-rollup-title">fleet-wide health</span>
        <span aria-hidden="true" className="text-accent">··</span>
        <span className="text-text-dim">
          across {buoys.length} buoy{buoys.length === 1 ? "" : "s"}
        </span>
        <span
          className="ml-1 cursor-help text-text-dim hover:text-text-secondary"
          title="Per-service count of buoys reporting that service as 'active'. Stale + red buoys are excluded (we don't trust their last-recorded state once their heartbeat ages out). Worst-state across the fleet drives the tint."
        >?</span>
      </header>

      {/* Tier row — health-tier counts across the fleet. Surfaces the
          green/yellow/stale/red breakdown at-a-glance so an operator can
          spot a regression even when individual service chips are
          stable. */}
      {tierCells.length > 0 && (
        <div
          role="list"
          aria-label="buoy health tier counts"
          className="mb-3 flex flex-wrap items-center gap-1.5 border-b border-border/40 pb-2 font-mono text-[11px]"
        >
          {tierCells.map((c) => {
            const t = TONE_STYLES[c.tone];
            return (
              <span
                key={c.key}
                role="listitem"
                className={`inline-flex items-center gap-1.5 rounded-sm border ${t.border} ${t.bg} px-1.5 py-0.5`}
              >
                <span
                  aria-hidden="true"
                  className={`h-1.5 w-1.5 rounded-full ${t.dot}`}
                />
                <span className={`font-semibold ${t.label}`}>{c.count}</span>
                <span className="text-[9px] uppercase tracking-wider text-text-dim">
                  {c.label}
                </span>
              </span>
            );
          })}
        </div>
      )}
      <ul role="list" className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        {rollups.map((r) => {
          const t = TONE_STYLES[r.tone];
          const ratio = r.total > 0 ? `${r.active}/${r.total}` : "—";
          return (
            <li
              key={r.unit}
              className={`rounded-sm border ${t.border} ${t.bg} px-2 py-2 transition-colors`}
            >
              <header className="mb-1 flex items-baseline justify-between gap-1">
                <span className="truncate text-[11px] font-semibold text-text-primary">
                  {r.label}
                </span>
                <span
                  aria-hidden="true"
                  className={`h-1.5 w-1.5 shrink-0 rounded-full ${t.dot}`}
                />
              </header>
              <div className="flex items-baseline justify-between font-mono">
                <span className={`text-base font-semibold ${t.label}`}>
                  {ratio}
                </span>
                <span className="text-[9px] uppercase tracking-wider text-text-dim">
                  {r.sub}
                </span>
              </div>
              {(r.failed > 0 || r.degraded > 0) && (
                <div className="mt-1 font-mono text-[9px] text-text-dim">
                  {r.failed > 0 && <span className="text-critical">{r.failed} failed</span>}
                  {r.failed > 0 && r.degraded > 0 && <span> · </span>}
                  {r.degraded > 0 && <span className="text-warning">{r.degraded} degraded</span>}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
};


export default FleetRollup;
