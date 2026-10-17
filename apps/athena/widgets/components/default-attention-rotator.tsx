/**
 * `default-attention-rotator` — auto-rotating focus card for a priority-
 * sorted list. One item visible at a time; manual prev/next + pause; the
 * worst-status items always float to the top of the rotation.
 *
 * Designed for buoy fleet today, but generic over `RotatableSource` so it
 * can later host integration health, device queues, etc.
 *
 * Hook for the future Phase J auto-healer:
 *   - When the auto-healer resolves a degraded service, the source's
 *     status flips back to `ok` and it naturally rejoins the regular
 *     rotation cadence. No special code path here.
 *   - When the auto-healer can't resolve, the source stays at top — the
 *     rotator's behavior already matches the "needs attention" semantics.
 */

import { type FC, useEffect, useMemo, useState } from "react";

export type ServiceStatus = "ok" | "degraded" | "down" | "pending" | "unknown";

export interface ServiceState {
  readonly id: string;
  readonly name: string;
  readonly status: ServiceStatus;
  readonly detail?: string;
}

export interface RotatableSource {
  readonly id: string;
  readonly name: string;
  readonly tenant?: string;
  readonly tags?: readonly string[];
  readonly events_per_min?: number;
  readonly last_seen?: string;
  readonly services: readonly ServiceState[];
}

export interface DefaultAttentionRotatorProps {
  readonly sources: readonly RotatableSource[];
  readonly intervalMs?: number;
  readonly pauseOnHover?: boolean;
  readonly emptyLabel?: string;
  /** Optional click handler — when set, the rendered source card gains
   *  a "Manage →" button in its footer. Used by the dashboard's Source
   *  Health widget to deep-link into the Fleet page's drawer for the
   *  highlighted buoy (search + step-up + remote-terminal). Receives
   *  the full RotatableSource so the parent can map back to its
   *  underlying record (the `id` is typically `buoy:<slug>`). */
  readonly onSelect?: (source: RotatableSource) => void;
  /** Optional CTA label override for the onSelect button. Defaults to
   *  "Manage →" when onSelect is set. */
  readonly selectLabel?: string;
  /** Optional filter: the onSelect button renders only for sources this
   *  returns true for (e.g. only buoys have a Fleet page to open). Every
   *  source is selectable when omitted. */
  readonly canSelect?: (source: RotatableSource) => boolean;
}

const PRIORITY_RANK: Record<ServiceStatus, number> = {
  down: 0,
  degraded: 1,
  pending: 2,
  unknown: 3,
  ok: 4,
};

const STATUS_DOT: Record<ServiceStatus, string> = {
  down: "bg-critical animate-pulse shadow-[0_0_6px_var(--critical)]",
  degraded: "bg-medium",
  pending: "bg-medium",
  unknown: "bg-text-dim",
  ok: "bg-success shadow-[0_0_4px_var(--success)]",
};

const STATUS_LABEL: Record<ServiceStatus, string> = {
  down: "down",
  degraded: "degraded",
  pending: "pending",
  unknown: "unknown",
  ok: "ok",
};

const STATUS_TEXT: Record<ServiceStatus, string> = {
  down: "text-critical",
  degraded: "text-medium",
  pending: "text-medium",
  unknown: "text-text-dim",
  ok: "text-success",
};

function worstStatus(source: RotatableSource): ServiceStatus {
  let worst: ServiceStatus = "ok";
  for (const svc of source.services) {
    if (PRIORITY_RANK[svc.status] < PRIORITY_RANK[worst]) {
      worst = svc.status;
    }
  }
  return worst;
}

export const DefaultAttentionRotator: FC<DefaultAttentionRotatorProps> = ({
  sources,
  intervalMs = 4000,
  pauseOnHover = true,
  emptyLabel = "No sources.",
  onSelect,
  selectLabel = "Manage →",
  canSelect,
}) => {
  const sorted = useMemo(() => {
    return [...sources].sort((a, b) => {
      const aP = PRIORITY_RANK[worstStatus(a)];
      const bP = PRIORITY_RANK[worstStatus(b)];
      if (aP !== bP) return aP - bP;
      return a.name.localeCompare(b.name);
    });
  }, [sources]);

  const [index, setIndex] = useState(0);
  const [paused, setPaused] = useState(false);
  const [hovered, setHovered] = useState(false);

  // Reset index when the sorted order changes — keeps the
  // worst-status source visible immediately when something fails.
  const sortKey = sorted.map((s) => `${s.id}:${worstStatus(s)}`).join("|");
  useEffect(() => {
    setIndex(0);
  }, [sortKey]);

  useEffect(() => {
    if (paused || (pauseOnHover && hovered)) return;
    if (sorted.length <= 1) return;
    const id = window.setInterval(() => {
      setIndex((i) => (i + 1) % sorted.length);
    }, intervalMs);
    return () => window.clearInterval(id);
  }, [paused, hovered, pauseOnHover, intervalMs, sorted.length]);

  if (sorted.length === 0) {
    return (
      <div className="px-4 py-6 text-center text-sm italic text-text-dim">
        {emptyLabel}
      </div>
    );
  }

  const safeIndex = Math.min(index, sorted.length - 1);
  const current = sorted[safeIndex]!;
  const currentWorst = worstStatus(current);

  const prev = (): void => {
    setIndex((i) => (i - 1 + sorted.length) % sorted.length);
    setPaused(true);
  };
  const next = (): void => {
    setIndex((i) => (i + 1) % sorted.length);
    setPaused(true);
  };

  return (
    <div
      className="flex flex-col gap-3"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      aria-roledescription="carousel"
      aria-label="Source health rotator"
    >
      <div className="flex items-center justify-between text-[11px] text-text-dim">
        <span aria-live="polite">
          {safeIndex + 1} of {sorted.length}
          {paused || (pauseOnHover && hovered) ? " · paused" : ""}
        </span>
        <div className="flex items-center gap-1">
          <RotatorButton
            onClick={prev}
            label="Previous source"
            disabled={sorted.length <= 1}
          >
            ◀
          </RotatorButton>
          <RotatorButton
            onClick={() => setPaused((p) => !p)}
            label={paused ? "Resume rotation" : "Pause rotation"}
          >
            {paused ? "▶" : "⏸"}
          </RotatorButton>
          <RotatorButton
            onClick={next}
            label="Next source"
            disabled={sorted.length <= 1}
          >
            ▶
          </RotatorButton>
        </div>
      </div>

      <article
        className={[
          "flex flex-col gap-3 rounded border bg-bg-card p-3 transition-colors",
          currentWorst === "down"
            ? "border-critical shadow-[0_0_0_1px_var(--critical),0_0_14px_rgba(239,68,68,0.18)]"
            : currentWorst === "degraded"
              ? "border-medium"
              : "border-border",
        ].join(" ")}
        aria-label={`Source: ${current.name}, status ${STATUS_LABEL[currentWorst]}`}
      >
        <header className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 shrink-0 rounded-full ${STATUS_DOT[currentWorst]}`} />
              <h4 className="truncate text-sm font-semibold text-text-primary">
                {current.name}
              </h4>
              <span className={`font-mono text-[10px] uppercase tracking-wider ${STATUS_TEXT[currentWorst]}`}>
                {STATUS_LABEL[currentWorst]}
              </span>
            </div>
            {current.tenant ? (
              <div className="mt-0.5 font-mono text-[11px] text-text-dim">
                {current.tenant}
              </div>
            ) : null}
          </div>
          {current.tags && current.tags.length > 0 ? (
            <div className="flex shrink-0 flex-wrap gap-1">
              {current.tags.map((tag) => (
                <span
                  key={tag}
                  className="rounded-sm bg-bg-input px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-accent"
                >
                  {tag}
                </span>
              ))}
            </div>
          ) : null}
        </header>

        <ul className="flex flex-col gap-1" role="list">
          {[...current.services]
            .sort((a, b) => PRIORITY_RANK[a.status] - PRIORITY_RANK[b.status])
            .map((svc) => (
              <li
                key={svc.id}
                className="flex items-center gap-2 rounded-sm bg-bg-input px-2 py-1 font-mono text-[11px]"
              >
                <span
                  className={`h-1.5 w-1.5 shrink-0 rounded-full ${STATUS_DOT[svc.status]}`}
                />
                <span className="flex-1 truncate text-text-primary">{svc.name}</span>
                {svc.detail ? (
                  <span className="text-text-dim">{svc.detail}</span>
                ) : null}
                <span className={`uppercase tracking-wider ${STATUS_TEXT[svc.status]}`}>
                  {STATUS_LABEL[svc.status]}
                </span>
              </li>
            ))}
        </ul>

        {(current.events_per_min !== undefined || current.last_seen) ? (
          <footer className="flex flex-wrap justify-between gap-2 border-t border-border pt-2 font-mono text-[11px] text-text-dim">
            {current.events_per_min !== undefined ? (
              <span>
                events:{" "}
                <span className="text-text-secondary">{current.events_per_min}/min</span>
              </span>
            ) : <span />}
            {current.last_seen ? (
              <span>
                last seen:{" "}
                <span className="text-text-secondary">{current.last_seen}</span>
              </span>
            ) : null}
          </footer>
        ) : null}

        {onSelect && (canSelect ? canSelect(current) : true) ? (
          <div className="flex justify-end border-t border-border pt-2">
            <button
              type="button"
              onClick={() => onSelect(current)}
              className="rounded-sm border border-accent/40 bg-accent/10 px-2 py-1 font-mono text-[11px] uppercase tracking-wider text-accent hover:bg-accent/20 hover:border-accent/60 transition-colors"
              aria-label={`Manage ${current.name}`}
            >
              {selectLabel}
            </button>
          </div>
        ) : null}
      </article>

      <PageDots
        sources={sorted}
        activeIndex={safeIndex}
        onJump={(i) => {
          setIndex(i);
          setPaused(true);
        }}
      />
    </div>
  );
};

const RotatorButton: FC<{
  onClick: () => void;
  label: string;
  disabled?: boolean;
  children: React.ReactNode;
}> = ({ onClick, label, disabled = false, children }) => (
  <button
    type="button"
    onClick={onClick}
    disabled={disabled}
    aria-label={label}
    className="rounded-sm border border-border bg-bg-input px-2 py-0.5 text-text-secondary transition-colors hover:border-border-bright hover:text-accent disabled:cursor-not-allowed disabled:opacity-40"
  >
    {children}
  </button>
);

const PageDots: FC<{
  sources: readonly RotatableSource[];
  activeIndex: number;
  onJump: (i: number) => void;
}> = ({ sources, activeIndex, onJump }) => (
  <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Source pagination">
    {sources.map((s, i) => {
      const status = worstStatus(s);
      const active = i === activeIndex;
      const dotClass =
        status === "down"
          ? "bg-critical"
          : status === "degraded" || status === "pending"
            ? "bg-medium"
            : status === "unknown"
              ? "bg-text-dim"
              : "bg-success";
      return (
        <button
          key={s.id}
          type="button"
          role="tab"
          aria-selected={active}
          aria-label={`Show ${s.name}`}
          onClick={() => onJump(i)}
          className={[
            "h-1.5 rounded-full transition-all",
            active ? "w-5" : "w-1.5 opacity-50 hover:opacity-100",
            dotClass,
          ].join(" ")}
        />
      );
    })}
  </div>
);

export default DefaultAttentionRotator;
