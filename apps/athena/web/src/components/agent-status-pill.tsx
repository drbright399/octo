/**
 * AgentStatusPill — live status of the autonomous Triage L1 worker
 * (Task #119e). Mirrors TopbarLlmStatus: polls /api/v1/agent/status
 * every ~10s, renders a small pill, holds last-known state on error.
 *
 * Two modes (Rick's 2026-06-01 placement call):
 *   - compact  → global topbar: coarse ONLINE / OFFLINE only.
 *   - detailed → /tickets triage-feed header: idle / triaging / error /
 *                disabled, with a tooltip showing last-run counts.
 *
 * States (detailed):
 *   ●  idle      — accent  — worker alive, waiting for next tick
 *   ◐  triaging  — accent  — actively processing a batch
 *   ○  error     — critical— last tick failed (see tooltip)
 *   ◌  disabled  — dim     — worker not running (OCTO_TRIAGE_WORKER off)
 */
import { type FC, useEffect, useState } from "react";

import { getAgentStatus, type AgentStatusResponse } from "@/lib/api";

interface Props {
  /** Compact = topbar online/offline; otherwise the detailed feed pill. */
  compact?: boolean;
  /** Clicking navigates here (compact pill → the triage feed). */
  onNavigate?: (path: string) => void;
}

const POLL_MS = 10_000;

const AgentStatusPill: FC<Props> = ({ compact = false, onNavigate }) => {
  const [status, setStatus] = useState<AgentStatusResponse | null>(null);

  useEffect(() => {
    let cancelled = false;
    const tick = (): void => {
      getAgentStatus()
        .then((r) => { if (!cancelled) setStatus(r); })
        .catch(() => { /* silent — hold last-known state */ });
    };
    tick();
    const id = window.setInterval(tick, POLL_MS);
    return () => { cancelled = true; window.clearInterval(id); };
  }, []);

  const base =
    "flex items-center gap-1.5 rounded-sm border px-2 py-0.5 font-mono " +
    "text-[10px] uppercase tracking-wider transition-colors";

  if (status === null) {
    return (
      <span title="Loading agent status…"
        className={`${base} border-border bg-bg-card text-text-dim`}>
        <span aria-hidden="true">◌</span>
        <span>agent</span>
      </span>
    );
  }

  // --- compact: coarse online/offline for the global topbar ---
  if (compact) {
    const online = status.online;
    const cls = online
      ? "border-accent/60 bg-accent/10 text-accent"
      : "border-border bg-bg-card text-text-dim";
    const pill = (
      <>
        <span aria-hidden="true">{online ? "●" : "○"}</span>
        <span>agent · {online ? "online" : "offline"}</span>
      </>
    );
    const title = `triage agent: ${online ? "online" : "offline"} (${status.state})`;
    return onNavigate ? (
      <button type="button" title={title}
        onClick={() => onNavigate("/tickets")}
        className={`${base} ${cls}`}>{pill}</button>
    ) : (
      <span title={title} className={`${base} ${cls}`}>{pill}</span>
    );
  }

  // --- detailed: idle / triaging / error / disabled for the feed ---
  const glyph =
    status.state === "idle" ? "●"
    : status.state === "triaging" ? "◐"
    : status.state === "error" ? "○"
    : "◌";
  const cls =
    status.state === "idle" ? "border-accent/60 bg-accent/10 text-accent"
    : status.state === "triaging" ? "border-accent/60 bg-accent/10 text-accent"
    : status.state === "error" ? "border-critical/60 bg-critical/5 text-critical"
    : "border-border bg-bg-card text-text-dim";

  const tip: string[] = [`triage agent: ${status.state}`];
  if (status.last_run) {
    const d = status.last_run.by_disposition;
    const parts = Object.keys(d).map((k) => `${k}:${d[k]}`).join(" ");
    tip.push(`last run: ${status.last_run.processed} events${parts ? ` (${parts})` : ""}`);
  }
  if (status.last_tick_at) tip.push(`last tick: ${status.last_tick_at}`);
  if (status.calibration_state && status.calibration_state !== "calibrated") {
    tip.push(`confidence: ${status.calibration_state} (advisory)`);
  }
  if (status.last_error) tip.push(`error: ${status.last_error}`);
  if (status.consecutive_errors > 0) {
    tip.push(`consecutive errors: ${status.consecutive_errors}`);
  }

  return (
    <span title={tip.join("\n")} className={`${base} ${cls}`}>
      <span aria-hidden="true">{glyph}</span>
      <span>{status.state}</span>
    </span>
  );
};

export default AgentStatusPill;
export { AgentStatusPill };
