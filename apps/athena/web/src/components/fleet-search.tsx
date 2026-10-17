/**
 * FleetSearch — search box + health-tier filter chips above the fleet.
 *
 * Per the 2026-05-19 Fleet redesign hand-off §1: a search +
 * filter row sitting on top of the cards/map view. Both inputs are
 * controlled by the parent (so the map and the cards grid stay in
 * sync with the same filter state).
 *
 * Search query matches slug / hostname / city (case-insensitive,
 * substring). Tier chips dim non-matching buoys client-side. The
 * "clear" button resets both.
 */
import type { FC } from "react";

import type { BuoyHealth } from "@/lib/buoy";


export type HealthFilter = BuoyHealth | null;


export interface FleetSearchProps {
  value: string;
  onChange: (v: string) => void;
  healthFilter: HealthFilter;
  onHealthFilter: (h: HealthFilter) => void;
  resultCount: number;
  totalCount: number;
}


interface ChipSpec {
  id: BuoyHealth;
  label: string;
  tone: "success" | "warning" | "critical" | "dim";
}

const CHIPS: ReadonlyArray<ChipSpec> = [
  { id: "red",    label: "DOWN",     tone: "critical" },
  { id: "stale",  label: "STALE",    tone: "dim" },
  { id: "yellow", label: "DEGRADED", tone: "warning" },
  { id: "green",  label: "OK",       tone: "success" },
];

const CHIP_TONE: Record<ChipSpec["tone"], { off: string; on: string }> = {
  critical: {
    off: "border-critical/30 text-critical hover:border-critical hover:bg-critical/5",
    on:  "border-critical bg-critical/10 text-critical",
  },
  warning: {
    off: "border-warning/30 text-warning hover:border-warning hover:bg-warning/5",
    on:  "border-warning bg-warning/10 text-warning",
  },
  success: {
    off: "border-success/30 text-success hover:border-success hover:bg-success/5",
    on:  "border-success bg-success/10 text-success",
  },
  dim: {
    off: "border-border text-text-dim hover:border-border-bright hover:text-text-secondary",
    on:  "border-text-dim bg-text-dim/10 text-text-secondary",
  },
};


const FleetSearch: FC<FleetSearchProps> = ({
  value, onChange, healthFilter, onHealthFilter, resultCount, totalCount,
}) => {
  const isFiltered = Boolean(value) || healthFilter !== null;

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-sm border border-border bg-bg-surface px-3 py-2">
      {/* Search input */}
      <div className="relative flex min-w-[16rem] flex-1 items-center">
        <span aria-hidden="true" className="absolute left-2 font-mono text-[12px] text-text-dim">⌕</span>
        <input
          type="search"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="search slug / hostname / city · type to filter"
          aria-label="Search buoys"
          className="w-full rounded-sm border border-border bg-bg-card py-1 pl-7 pr-2 font-mono text-[11px] text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
        />
      </div>

      {/* Tier filter chips — click to toggle. */}
      <div role="group" aria-label="Filter by health" className="flex items-center gap-1">
        {CHIPS.map((chip) => {
          const active = healthFilter === chip.id;
          const tone = CHIP_TONE[chip.tone];
          return (
            <button
              key={chip.id}
              type="button"
              aria-pressed={active}
              onClick={() => onHealthFilter(active ? null : chip.id)}
              className={[
                "rounded-sm border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider transition-colors",
                active ? tone.on : tone.off,
              ].join(" ")}
              title={
                chip.id === "red"    ? "Heartbeat stale > 5× interval"
                : chip.id === "stale"  ? "Heartbeat stale 2–5× interval"
                : chip.id === "yellow" ? "At least one service non-active"
                : chip.id === "green"  ? "All services active + fresh heartbeat"
                : ""
              }
            >
              {chip.label}
            </button>
          );
        })}
      </div>

      {/* Result counter — visible only when filtering. */}
      {isFiltered && (
        <span className="font-mono text-[10px] uppercase tracking-wider text-text-dim">
          {resultCount} of {totalCount} match
        </span>
      )}

      {/* Clear-all button */}
      {isFiltered && (
        <button
          type="button"
          onClick={() => { onChange(""); onHealthFilter(null); }}
          className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-text-secondary transition-colors hover:border-border-bright hover:text-text-primary"
          title="Clear search + tier filter"
        >clear ✕</button>
      )}
    </div>
  );
};


/** Pure helper exported for tests + reuse in fleet.tsx's filter pipeline. */
export function matchesBuoy(
  buoy: { slug: string; hostname: string; city?: string | null },
  query: string,
): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return (
    buoy.slug.toLowerCase().includes(q)
    || buoy.hostname.toLowerCase().includes(q)
    || (buoy.city ?? "").toLowerCase().includes(q)
  );
}


export default FleetSearch;
