/**
 * TopbarLlmStatus — small live pill showing octo-llm health in the
 * topbar. Visible to every authenticated operator.
 *
 * Polls /api/v1/account/llm-status every ~10s. The endpoint already
 * does a healthz probe of octo-llm with a 1.5s timeout server-side,
 * so the pill reflects the actual sibling state rather than just
 * the configured-on flags.
 *
 * States:
 *   ●  ready          — green/accent — sibling up + model loaded +
 *                       all your gates green
 *   ◐  stub mode      — yellow/medium — sibling up running stub
 *                       (canned responses; not real LLM output)
 *   ◑  not granted    — text-dim — sibling ready but YOU don't have
 *                       grant or preference is off
 *   ○  down           — red/critical — sibling unreachable
 *
 * Click navigates to the appropriate place to fix:
 *   super_admin  → Settings → System (probe + restart there)
 *   others       → Settings → Account (toggle / status chip there)
 *
 * Slice 7l.
 */
import { type FC, useEffect, useState } from "react";

import { getLlmStatus, type LlmStatusResponse } from "@/lib/api";

interface Props {
  /** Super_admin gets a different click destination — sends them to
   * Settings → System where the model + restart controls live. */
  isSuperAdmin: boolean;
  onNavigate: (path: string) => void;
}

const POLL_MS = 10_000;

const TopbarLlmStatus: FC<Props> = ({ isSuperAdmin, onNavigate }) => {
  const [status, setStatus] = useState<LlmStatusResponse | null>(null);

  useEffect(() => {
    let cancelled = false;
    const tick = (): void => {
      getLlmStatus()
        .then((r) => { if (!cancelled) setStatus(r); })
        .catch(() => { /* silent — pill stays in last-known state */ });
    };
    tick();
    const id = window.setInterval(tick, POLL_MS);
    return () => { cancelled = true; window.clearInterval(id); };
  }, []);

  if (status === null) {
    return (
      <span
        title="Loading octo-llm status…"
        className="flex items-center gap-1.5 rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-text-dim"
      >
        <span aria-hidden="true">◌</span>
        <span>octo</span>
      </span>
    );
  }

  // Classify the state.
  type Kind = "ready" | "stub" | "no-access" | "down";
  let kind: Kind;
  let label: string;
  if (!status.sibling_healthy) {
    kind = "down";
    label = "down";
  } else if (status.sibling_backend === "stub") {
    kind = "stub";
    label = "stub";
  } else if (!status.effectively_active) {
    kind = "no-access";
    label = "off";
  } else {
    kind = "ready";
    label = "ready";
  }

  const glyph =
    kind === "ready" ? "●"
    : kind === "stub" ? "◐"
    : kind === "no-access" ? "◑"
    : "○";

  const cls = (
    kind === "ready" ? "border-accent/60 bg-accent/10 text-accent"
    : kind === "stub" ? "border-medium/60 bg-medium/5 text-medium"
    : kind === "no-access" ? "border-border bg-bg-card text-text-dim"
    : "border-critical/60 bg-critical/5 text-critical"
  );

  const tooltipLines: string[] = [];
  tooltipLines.push(`octo-llm: ${label}`);
  if (status.sibling_backend) {
    tooltipLines.push(`backend: ${status.sibling_backend}`);
  }
  if (status.sibling_model_version) {
    tooltipLines.push(`model: ${status.sibling_model_version}`);
  }
  if (!status.your_grant) tooltipLines.push("you are not granted access");
  if (!status.your_preference) tooltipLines.push("your preference is off");
  if (!status.bundle_enabled) tooltipLines.push("bundle-wide flag is off");
  tooltipLines.push(
    isSuperAdmin
      ? "click → Settings → System"
      : "click → Settings → Account"
  );

  return (
    <button
      type="button"
      onClick={() => onNavigate(
        isSuperAdmin ? "/settings#system" : "/settings#account",
      )}
      title={tooltipLines.join("\n")}
      className={[
        "flex items-center gap-1.5 rounded-sm border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider transition-colors",
        cls,
      ].join(" ")}
    >
      <span aria-hidden="true">{glyph}</span>
      <span>octo · {label}</span>
    </button>
  );
};

export default TopbarLlmStatus;
export { TopbarLlmStatus };
