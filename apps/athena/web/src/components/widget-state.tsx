/**
 * WidgetState — canonical loading / empty / degraded / error rendering
 * for every widget surface in the console. Ported from Design's kit
 * (2026-05-13). The state CSS lives in src/index.css.
 *
 * Pattern:
 *   <WidgetState state="loading" rows={4} />
 *   <WidgetState state="empty" glyph="◯" title="No alerts in scope"
 *                hint="Adjust filters to widen the time window." />
 *   <WidgetState state="degraded" reason="queue lag 4s">...content...</WidgetState>
 *   <WidgetState state="error" code="AUTH_EXPIRED"
 *                message="Datto auth expired" onRetry={...} />
 *   <WidgetState state="ready">...content...</WidgetState>
 *
 * Rules (the console's visual language):
 *   loading  → 3–5 skeleton rows with shimmer (NEVER a centered spinner;
 *              spinners don't carry layout intent)
 *   empty    → centered glyph + sentence; no spinner; no apology
 *   degraded → small amber strip ABOVE content; content still renders so
 *              operators can act on stale data
 *   error    → critical-tinted body replacement w/ actionable copy and
 *              optional retry / fix-this CTA
 *   ready    → just children
 */
import type { FC, ReactNode } from "react";

export type WidgetStateValue = "loading" | "empty" | "degraded" | "error" | "ready";

interface SkeletonShape {
  readonly width: string;
  readonly height?: number;
}

interface WidgetStateProps {
  readonly state: WidgetStateValue;
  readonly rows?: number;
  readonly rowShape?: readonly SkeletonShape[];
  readonly glyph?: string;
  readonly title?: string;
  readonly hint?: string;
  readonly reason?: string;
  readonly detail?: string;
  readonly code?: string;
  readonly message?: string;
  readonly onRetry?: () => void;
  readonly retryLabel?: string;
  readonly fixLabel?: string;
  readonly onFix?: () => void;
  readonly children?: ReactNode;
}

const DEFAULT_SHAPES: readonly SkeletonShape[] = [
  { width: "30%" },
  { width: "80%" },
  { width: "60%" },
  { width: "70%" },
  { width: "45%" },
];

const SkeletonRow: FC<{ width: string; height: number }> = ({ width, height }) => (
  <div className="skel-row" style={{ width, height }} aria-hidden="true" />
);

const WidgetState: FC<WidgetStateProps> = ({
  state, rows = 4, rowShape, glyph = "◯", title, hint, reason, detail,
  code, message, onRetry, retryLabel = "Retry", fixLabel, onFix, children,
}) => {
  if (state === "loading") {
    const shape = rowShape ?? DEFAULT_SHAPES;
    return (
      <div className="state-loading" role="status" aria-live="polite">
        <span className="sr-only">Loading…</span>
        {Array.from({ length: rows }).map((_, i) => (
          <SkeletonRow
            key={i}
            width={shape[i % shape.length]!.width}
            height={shape[i % shape.length]!.height ?? 12}
          />
        ))}
      </div>
    );
  }

  if (state === "empty") {
    return (
      <div className="state-empty" role="status">
        <span aria-hidden="true" className="state-empty__glyph">{glyph}</span>
        {title && <div className="state-empty__title">{title}</div>}
        {hint && <div className="state-empty__hint">{hint}</div>}
      </div>
    );
  }

  if (state === "degraded") {
    return (
      <>
        <div className="state-degraded" role="status" aria-live="polite">
          <span className="state-degraded__glyph" aria-hidden="true">◐</span>
          <span className="state-degraded__msg">
            <strong>Degraded</strong>{reason ? ` · ${reason}` : ""}
          </span>
          {detail && <span className="state-degraded__detail">{detail}</span>}
        </div>
        {children}
      </>
    );
  }

  if (state === "error") {
    return (
      <div className="state-error" role="alert">
        <div className="state-error__head">
          <span className="state-error__glyph" aria-hidden="true">✕</span>
          <span className="state-error__msg">{message ?? "Something failed."}</span>
        </div>
        {code && <div className="state-error__code">{code}</div>}
        {(onRetry || onFix) && (
          <div className="state-error__actions">
            {onRetry && (
              <button
                type="button"
                onClick={onRetry}
                className="rounded-sm border border-border bg-bg-card px-2.5 py-1 text-[11px] font-mono uppercase tracking-wider text-text-secondary transition-colors hover:border-border-bright hover:text-text-primary"
              >·· {retryLabel} ··</button>
            )}
            {onFix && (
              <button
                type="button"
                onClick={onFix}
                className="nav-sweep rounded-sm border border-accent bg-bg-card px-2.5 py-1 text-[11px] font-mono uppercase tracking-wider text-accent transition-colors hover:bg-accent-soft"
              >·· {fixLabel ?? "Reconfigure"} ··</button>
            )}
          </div>
        )}
      </div>
    );
  }

  // ready
  return <>{children}</>;
};

export default WidgetState;
