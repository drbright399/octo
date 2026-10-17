/**
 * The GLOBAL threat strip (Tier Black slice 1) — on every route, fed by
 * `/api/v1/incidents/summary` (polled by the App every 15 s).
 *
 *   operators   "BLACK 2 (1 unacknowledged) · RED 3" — the Black chip pulses
 *               while any Black is unacknowledged; a click opens the Fleet.
 *   a client    the neutral line only — the server's WORST line of what they
 *               may see ("…has been alerted", once acknowledged "…is
 *               responding", "…contained…", "…under investigation…") — no
 *               counts of anything they may not see, no pulse, no detail.
 * Nothing renders while there is no open Red or Black.
 *
 * `threatTitle` is the document-title prefix ("BLACK (2) · Athena"): an
 * unacknowledged Black is seen from another browser tab too.
 */
import type { FC } from "react";

import type { IncidentSummary } from "@/contracts/incidents";
import "./fleet.css";

export function threatTitle(base: string, s: IncidentSummary | null): string {
  const clean = base.replace(/^(BLACK|RED) \(\d+\) · /, "");
  if (!s) return clean;
  if (s.black > 0) return `BLACK (${s.black}) · ${clean}`;
  if (s.view === "operator" && s.red > 0) return `RED (${s.red}) · ${clean}`;
  return clean;
}

export interface ThreatStripProps {
  summary: IncidentSummary | null;
  onOpen?: () => void;
}

const ThreatStrip: FC<ThreatStripProps> = ({ summary, onOpen }) => {
  if (!summary || (summary.black === 0 && summary.red === 0)) return null;
  if (summary.view === "client") {
    const black = summary.black > 0;
    // The server's worst neutral line (it knows acknowledged / contained);
    // the fallback only covers an older server.
    const line = summary.status_neutral
      ?? (black ? "Urgent security incident: your IT provider has been alerted"
        : "Security issue under investigation by your IT provider");
    return (
      <div role="status" data-testid="threat-strip" data-view="client"
           className={[
             "mb-3 rounded-sm border px-3 py-2 text-[12px] font-semibold",
             black
               ? "border-[var(--fleet-threat-ring)] bg-[var(--fleet-threat)] text-[var(--fleet-threat-text)]"
               : "border-critical/50 bg-critical/10 text-critical",
           ].join(" ")}>
        {line}
      </div>
    );
  }
  const unacked = summary.black_unacked ?? 0;
  return (
    <div role="alert" data-testid="threat-strip" data-view="operator"
         className="mb-3 flex flex-wrap items-center gap-2 rounded-sm border border-[var(--fleet-threat-ring)] bg-[var(--fleet-threat)] px-3 py-1.5 font-mono text-[11px] text-[var(--fleet-threat-text)]">
      {summary.black > 0 && (
        <span data-testid="threat-strip-black"
              className={["inline-flex items-center gap-1 rounded-sm border border-[var(--fleet-threat-ring)] px-1.5 py-0.5 font-bold uppercase tracking-widest",
                          unacked > 0 ? "fleet-strip-black" : ""].join(" ")}>
          <span aria-hidden="true">⯃!</span> black {summary.black}
          {unacked > 0 ? ` (${unacked} unacknowledged)` : ""}
        </span>
      )}
      {summary.red > 0 && (
        <span data-testid="threat-strip-red"
              className="rounded-sm border border-critical/60 bg-critical/15 px-1.5 py-0.5 font-bold uppercase tracking-widest text-critical">
          red {summary.red}
        </span>
      )}
      <span className="text-[var(--fleet-threat-text)]">
        {summary.black > 0
          ? "An attack is in progress — acknowledge it on the Fleet page."
          : "A confirmed threat is open — it never fades on its own."}
      </span>
      {onOpen && (
        <button type="button" onClick={onOpen} data-testid="threat-strip-open"
                className="ml-auto rounded-sm border border-[var(--fleet-threat-ring)] px-2 py-0.5 uppercase tracking-widest hover:bg-[var(--fleet-threat-ring)] hover:text-[var(--fleet-threat)]">
          open fleet
        </button>
      )}
    </div>
  );
};

export default ThreatStrip;
