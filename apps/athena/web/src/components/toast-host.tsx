/**
 * ToastHost — ambient P1/P2 notifications. Ported from Design's kit
 * (2026-05-13). Rules:
 *
 *   - Critical (P1) toasts NEVER auto-dismiss; operator must acknowledge
 *   - High (P2) auto-dismiss after 12s (configurable)
 *   - Medium/low/info — not toasted by default; promote via filter
 *   - Up to 3 visible at a time; overflow shows as a "+N more" pill
 *   - Sorted by severity DESC, then ts DESC
 *   - Same severity stripe + sweep treatment as alert feed rows
 *
 * Wiring to the alert ingestion stream is pending. Hook `useToastQueue`
 * exposes `{queue, push, dismiss, dismissAll}` — the bridge client
 * calls `push()` when OCTO promotes an event to severity ≥ high.
 */
import { useCallback, useEffect, useState, type FC, type MouseEvent } from "react";

export type ToastSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface ToastItem {
  readonly id: string;
  readonly ts: number;
  readonly sev: ToastSeverity;
  readonly title: string;
  readonly tenant: string;
  readonly when: string;          // human-friendly ("just now", "3 min ago")
  readonly payload?: unknown;     // pass-through for the onOpen handler
}

interface ToastHostProps {
  readonly toasts: readonly ToastItem[];
  readonly onDismiss: (id: string) => void;
  readonly onOpen?: (t: ToastItem | { overflow: true }) => void;
  readonly visibleLimit?: number;
}

// Auto-dismiss timings per severity. `null` = never (operator must ack).
const AUTODISMISS_MS: Record<ToastSeverity, number | null> = {
  critical: null,
  high:     12_000,
  medium:    8_000,
  low:       6_000,
  info:      4_000,
};

const SEVERITY_RANK: Record<ToastSeverity, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0,
};

const SEV_EYEBROW_LABEL: Record<ToastSeverity, string> = {
  critical: "P1 CRITICAL",
  high:     "P2 HIGH",
  medium:   "P3 MEDIUM",
  low:      "P4 LOW",
  info:     "P5 INFO",
};

const ToastHost: FC<ToastHostProps> = ({
  toasts, onDismiss, onOpen, visibleLimit = 3,
}) => {
  const sorted = [...toasts].sort((a, b) => {
    const r = SEVERITY_RANK[b.sev] - SEVERITY_RANK[a.sev];
    if (r !== 0) return r;
    return b.ts - a.ts;
  });
  const visible = sorted.slice(0, visibleLimit);
  const overflow = sorted.length - visible.length;

  // Auto-dismiss timers per visible toast.
  useEffect(() => {
    const timers: number[] = [];
    for (const t of visible) {
      const ms = AUTODISMISS_MS[t.sev];
      if (ms !== null) {
        const id = window.setTimeout(() => onDismiss(t.id), ms);
        timers.push(id);
      }
    }
    return () => { for (const id of timers) window.clearTimeout(id); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible.map((t) => t.id).join(","), onDismiss]);

  if (visible.length === 0) return null;

  return (
    <div className="toast-host" role="region" aria-label="Alerts">
      {visible.map((t) => (
        <article
          key={t.id}
          className="toast nav-sweep row-stripe"
          data-sev={t.sev}
          role="alert"
          aria-live={t.sev === "critical" ? "assertive" : "polite"}
          onClick={() => onOpen?.(t)}
        >
          <div className="toast__head">
            <span className={`toast__eyebrow toast__eyebrow--${t.sev}`}>
              ·· {SEV_EYEBROW_LABEL[t.sev]} ··
            </span>
            <button
              type="button"
              className="toast__close"
              aria-label="Dismiss"
              onClick={(e: MouseEvent) => { e.stopPropagation(); onDismiss(t.id); }}
            >✕</button>
          </div>
          <div className="toast__title">{t.title}</div>
          <div className="toast__meta">
            <span>{t.tenant}</span>
            <span aria-hidden="true">·</span>
            <span>{t.when}</span>
          </div>
        </article>
      ))}
      {overflow > 0 && (
        <button
          type="button"
          className="toast-overflow nav-sweep"
          onClick={() => onOpen?.({ overflow: true })}
        >
          <span className="toast-overflow__label">·· + {overflow} more ··</span>
        </button>
      )}
    </div>
  );
};

// Convenience hook for managing the toast queue. Parents call `push()`
// when a high-sev event arrives; pass `queue` + `dismiss` into <ToastHost>.
export function useToastQueue() {
  const [queue, setQueue] = useState<ToastItem[]>([]);

  const push = useCallback((t: Omit<ToastItem, "id" | "ts"> & Partial<Pick<ToastItem, "id" | "ts">>): void => {
    const item: ToastItem = {
      id: t.id ?? `toast-${Math.random().toString(36).slice(2, 10)}`,
      ts: t.ts ?? Date.now(),
      sev: t.sev,
      title: t.title,
      tenant: t.tenant,
      when: t.when,
      payload: t.payload,
    };
    setQueue((q) => [item, ...q]);
  }, []);

  const dismiss = useCallback((id: string): void => {
    setQueue((q) => q.filter((t) => t.id !== id));
  }, []);

  const dismissAll = useCallback((): void => setQueue([]), []);

  return { queue, push, dismiss, dismissAll };
}

export default ToastHost;
