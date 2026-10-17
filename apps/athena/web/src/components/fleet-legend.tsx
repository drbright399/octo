/**
 * FleetLegend — what a pin's colour and shape mean. States use the theme's
 * semantic tokens (so Midas Touch, Ultra-black and light mode recolour them)
 * AND a shape cue, so the state reads without colour. Black is an octagon
 * with "!" (pulsing until acknowledged); Red a static halo — it never
 * pulses. Only incident records make Red or Black.
 */
import type { FC } from "react";

import type { SiteState } from "@/contracts/fleet";
import { octagonPoints } from "@/components/fleet-map-overlay";
import { STATE_COLOR } from "@/lib/fleet";

const ROWS: ReadonlyArray<{ state: SiteState; label: string; hint: string; client?: string }> = [
  { state: "black", label: "Black: active attack", hint: "octagon !, pulses until acknowledged",
    client: "octagon !" },
  { state: "bad", label: "Red: confirmed threat", hint: "static halo — never pulses" },
  { state: "warn", label: "Yellow: needs eyes", hint: "ring — outages, gaps, single alerts" },
  { state: "unknown", label: "Stale", hint: "hollow, dashed — never shown as normal" },
  { state: "notice", label: "Notice", hint: "grey dotted ring — seen, not a problem" },
  { state: "ok", label: "Normal", hint: "filled" },
];

export interface FleetLegendProps {
  /** Client users: no buoy row, no location-source row (they get no map). */
  view: "operator" | "client";
  showBuoys?: boolean;
}

const Swatch: FC<{ state: SiteState; manual?: boolean }> = ({ state, manual = false }) => {
  const color = STATE_COLOR[state];
  const hollow = state === "unknown";
  if (state === "black") {
    return (
      <svg width="22" height="22" viewBox="-11 -11 22 22" aria-hidden="true"
           data-testid="legend-swatch-black">
        <circle r={10} fill="none" stroke="var(--fleet-threat-ring)" strokeWidth={1.4} />
        <polygon points={octagonPoints(7.2)} fill="var(--fleet-threat)"
                 stroke="var(--fleet-threat-ring)" strokeWidth={1.6} />
        <text y={3.4} textAnchor="middle" fontFamily="var(--font-mono)" fontSize={9}
              fontWeight={700} fill="var(--fleet-threat-ring)">!</text>
      </svg>
    );
  }
  return (
    <svg width="22" height="22" viewBox="-11 -11 22 22" aria-hidden="true">
      {state === "warn" && <circle r={9} fill="none" stroke={color} strokeOpacity={0.7} strokeWidth={1.2} />}
      {state === "bad" && <circle r={9.5} fill="none" stroke={color} strokeWidth={1.6} />}
      {state === "notice" && (
        <circle r={8.5} fill="none" stroke="var(--text-dim)" strokeWidth={1} strokeDasharray="1.5 2" />
      )}
      {manual ? (
        <rect x={-5} y={-5} width={10} height={10} rx={1.5} transform="rotate(45)"
              fill={hollow ? "var(--bg-deep)" : color}
              stroke={hollow ? color : "var(--bg-deep)"}
              strokeDasharray={hollow ? "2 2" : undefined} />
      ) : (
        <circle r={5.5} fill={hollow ? "var(--bg-deep)" : color}
                stroke={hollow ? color : "var(--bg-deep)"} strokeWidth={1.4}
                strokeDasharray={hollow ? "2 2" : undefined} />
      )}
    </svg>
  );
};

const FleetLegend: FC<FleetLegendProps> = ({ view, showBuoys = false }) => (
  <section
    aria-label="Fleet legend"
    data-testid="fleet-legend"
    className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-sm border border-border bg-bg-surface px-3 py-2 font-mono text-[10px] text-text-secondary"
  >
    <span className="uppercase tracking-widest text-text-dim">legend</span>
    {ROWS.map((r) => (
      <span key={r.state} className="inline-flex items-center gap-1" data-testid={`legend-${r.state}`}>
        <Swatch state={r.state} />
        <span className="text-text-primary">{r.label}</span>
        <span className="text-text-dim">({view === "client" ? (r.client ?? r.hint) : r.hint})</span>
      </span>
    ))}
    {view === "operator" && (
      <span className="inline-flex items-center gap-1" data-testid="legend-manual">
        <Swatch state="ok" manual />
        <span className="text-text-primary">placed by hand</span>
        <span className="text-text-dim">(pinned in the site drawer, or the client&apos;s fallback)</span>
      </span>
    )}
    {view === "operator" && (
      <span className="inline-flex items-center gap-1" data-testid="legend-selected">
        <svg width="22" height="22" viewBox="-11 -11 22 22" aria-hidden="true">
          <rect x={-9} y={-9} width={18} height={18} fill="none" stroke="var(--text-primary)"
                strokeWidth={1.2} strokeDasharray="4 3" />
          <circle r={4} fill="var(--success)" stroke="var(--bg-deep)" strokeWidth={1.2} />
        </svg>
        <span className="text-text-primary">selected</span>
        <span className="text-text-dim">(dashed square)</span>
      </span>
    )}
    {view === "operator" && showBuoys && (
      <span className="inline-flex items-center gap-1" data-testid="legend-buoy">
        <svg width="22" height="22" viewBox="-11 -11 22 22" aria-hidden="true">
          <circle r={9} fill="rgba(34,197,94,0.18)" />
          <circle r={5.5} fill="var(--success)" stroke="var(--bg-deep)" strokeWidth={1.4} />
        </svg>
        <span className="text-text-primary">buoy</span>
        <span className="text-text-dim">(signal trace to the hub)</span>
      </span>
    )}
    <span className="ml-auto text-text-dim">
      colour = the site&apos;s worst layer · stale data is never shown as ok
    </span>
  </section>
);

export default FleetLegend;
