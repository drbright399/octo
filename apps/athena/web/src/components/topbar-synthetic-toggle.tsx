/**
 * TopbarSyntheticToggle — DEV-ONLY topbar control (Task #119f).
 *
 * Lets the developer start/stop synthetic event generation so the
 * autonomous triage worker has live "incoming" traffic to annotate.
 *
 * Triple-gated so it can never appear in a real deployment:
 *   1. Only MOUNTED in Vite dev MODE (the topbar wraps it in a MODE
 *      check — kept at the call site so this component's hooks stay
 *      unconditional).
 *   2. Hides itself if the backend route 404s (prod backend / non-dev
 *      data root → status fetch fails → render nothing).
 *   3. Backend requires OCTO_DEV_SYNTHETIC=1 on a dev data-root.
 *
 * Visually distinct (dashed amber) so it reads as a dev affordance, not
 * a product control.
 */
import { type FC, useEffect, useState } from "react";

import {
  getSyntheticTraffic,
  setSyntheticTraffic,
  type SyntheticTrafficStatus,
} from "@/lib/api";

const POLL_MS = 10_000;

const TopbarSyntheticToggle: FC = () => {
  const [status, setStatus] = useState<SyntheticTrafficStatus | null>(null);
  const [available, setAvailable] = useState(true);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const tick = (): void => {
      getSyntheticTraffic()
        .then((r) => { if (!cancelled) { setStatus(r); setAvailable(true); } })
        .catch(() => { if (!cancelled) setAvailable(false); });  // gate #2
    };
    tick();
    const id = window.setInterval(tick, POLL_MS);
    return () => { cancelled = true; window.clearInterval(id); };
  }, []);

  if (!available) return null;

  const enabled = status?.enabled ?? false;
  const toggle = (): void => {
    if (busy) return;
    setBusy(true);
    setSyntheticTraffic(!enabled)
      .then((r) => setStatus(r))
      .catch(() => { /* keep last state */ })
      .finally(() => setBusy(false));
  };

  const cls = enabled
    ? "border-medium/70 bg-medium/10 text-medium"
    : "border-dashed border-border bg-bg-card text-text-dim";

  const tip = [
    "DEV synthetic traffic",
    enabled ? "emitting events" : "stopped",
    status ? `emitted: ${status.emitted_total}` : "",
    "click to toggle",
  ].filter(Boolean).join("\n");

  return (
    <button
      type="button"
      onClick={toggle}
      disabled={busy}
      title={tip}
      className={[
        "flex items-center gap-1.5 rounded-sm border px-2 py-0.5 font-mono",
        "text-[10px] uppercase tracking-wider transition-colors disabled:opacity-50",
        cls,
      ].join(" ")}
    >
      <span aria-hidden="true">{enabled ? "▶" : "■"}</span>
      <span>synth · {enabled ? "on" : "off"}</span>
    </button>
  );
};

export default TopbarSyntheticToggle;
export { TopbarSyntheticToggle };
