/**
 * `default-alert-feed` — one of the 5 canonical render components shipped
 * by the widget framework (see ADR-006 §5 + shared_widget_contract).
 *
 * Contract:
 *   - Receives a list of AlertRow + display config; renders them.
 *   - Component is "dumb": no fetching, no auth, no mutation. Bridge
 *     wiring happens upstream and passes rows in. Server enforces; UI
 *     presents.
 *   - All text is rendered as text nodes (never innerHTML / dangerouslySetInnerHTML).
 *   - Visual language matches the OCTO dashboard's ticket pattern (dark
 *     violet, severity-colored priority badge, mono meta, status pill).
 *
 *   - Row = headline (title), source · tenant · device · site · status, then
 *     the detail clamped to two lines. The full detail is the paragraph's
 *     `title` (hover) and the caller's onSelect target (click → drawer).
 *   - `vendor_links` (optional) render as ONE new-tab icon link with
 *     rel="noopener noreferrer"; the URL comes from the server as-is and is
 *     only rendered when it is https.
 *
 * Contract version: 1.1 (device / site / vendor_links are optional — 1.0
 * rows render as before, with the summary now clamped to two lines)
 */

import { type CSSProperties, type FC, type KeyboardEvent, useMemo } from "react";
import {
  type AlertRow,
  type AlertSeverity,
  type AlertStatus,
  type AlertVendorLink,
  vendorSessionNote,
} from "@/contracts/alert";
import { formatRelative } from "@/lib/time";

export interface DefaultAlertFeedProps {
  readonly rows: readonly AlertRow[];
  readonly title?: string;
  readonly maxRows?: number;
  readonly loading?: boolean;
  readonly error?: string;
  readonly onSelect?: (row: AlertRow) => void;
  readonly now?: Date;
}

const SEVERITY_LABEL: Record<AlertSeverity, string> = {
  critical: "P1",
  high: "P2",
  medium: "P3",
  low: "P4",
  info: "P5",
};

const SEVERITY_LONG: Record<AlertSeverity, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

const STATUS_LABEL: Record<AlertStatus, string> = {
  open: "open",
  acknowledged: "ack'd",
  resolved: "resolved",
  suppressed: "suppressed",
};

const STATUS_TONE: Record<AlertStatus, string> = {
  open: "text-text-primary",
  acknowledged: "text-accent",
  resolved: "text-text-dim",
  suppressed: "text-text-dim italic",
};

const SEVERITY_RANK: Record<AlertSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const DefaultAlertFeed: FC<DefaultAlertFeedProps> = ({
  rows,
  title,
  maxRows = 25,
  loading = false,
  error,
  onSelect,
  now,
}) => {
  const visible = useMemo(() => {
    const sorted = [...rows].sort((a, b) => {
      const sev = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
      if (sev !== 0) return sev;
      return b.occurred_at.localeCompare(a.occurred_at);
    });
    return sorted.slice(0, maxRows);
  }, [rows, maxRows]);

  return (
    <div className="flex flex-col gap-2.5" aria-label={title ?? "Alert feed"}>
      <div className="flex items-baseline justify-between text-[11px] text-text-dim">
        <span data-testid="alert-feed-count">
          {rows.length} {rows.length === 1 ? "alert" : "alerts"}
          {rows.length > maxRows ? ` · showing top ${maxRows}` : ""}
        </span>
      </div>

      {error ? (
        <div role="alert" className="rounded border border-critical bg-critical/10 px-4 py-3 text-xs text-critical">
          {error}
        </div>
      ) : loading ? (
        <div className="px-4 py-8 text-center text-sm italic text-text-dim" aria-busy="true">
          Loading alerts…
        </div>
      ) : visible.length === 0 ? (
        <div className="px-4 py-8 text-center text-sm italic text-text-dim">
          No alerts.
        </div>
      ) : (
        <ul className="flex flex-col gap-2.5" role="list">
          {visible.map((row) => (
            <AlertItem key={row.id} row={row} onSelect={onSelect} now={now} />
          ))}
        </ul>
      )}
    </div>
  );
};

interface AlertItemProps {
  readonly row: AlertRow;
  readonly onSelect?: ((row: AlertRow) => void) | undefined;
  readonly now?: Date | undefined;
}

// Two lines of detail in the row; the whole text is the element's `title`
// (hover) and the drawer (click). Inline rather than a utility class so the
// clamp does not depend on the host's CSS build.
const CLAMP_TWO_LINES: CSSProperties = {
  display: "-webkit-box",
  WebkitLineClamp: 2,
  WebkitBoxOrient: "vertical",
  overflow: "hidden",
};

/** The row's one vendor link: the alert itself, else whatever came first.
 *  Anything that is not a plain https URL is not rendered at all. */
const primaryVendorLink = (row: AlertRow): AlertVendorLink | undefined => {
  const links = (row.vendor_links ?? []).filter((l) => l.url.startsWith("https://"));
  return links.find((l) => l.kind === "alert") ?? links[0];
};

/** A presented detail is a '\n'-joined list of facts. Inside a two-line
 *  clamp the newlines collapse to spaces and 'key: value' boundaries vanish,
 *  so the clamped excerpt joins them visibly; the whole text, line breaks
 *  and all, stays in the tooltip and the drawer. */
const SUMMARY_SEPARATOR = " · ";
export const clampedSummary = (summary: string): string =>
  summary.split("\n").filter((line) => line.trim() !== "").join(SUMMARY_SEPARATOR);

const AlertItem: FC<AlertItemProps> = ({ row, onSelect, now }) => {
  const interactive = Boolean(onSelect);
  const vendorLink = primaryVendorLink(row);

  const handleKey = (e: KeyboardEvent<HTMLLIElement>): void => {
    if (!onSelect) return;
    // Keys pressed ON the vendor link belong to the link, not the row.
    if (e.target !== e.currentTarget) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onSelect(row);
    }
  };

  return (
    <li
      data-sev={row.severity}
      className={[
        "nav-sweep row-stripe rounded border border-border bg-bg-card p-4 pl-12 transition-colors hover:border-border-bright",
        interactive ? "cursor-pointer" : "",
      ].join(" ")}
      {...(interactive
        ? {
            tabIndex: 0,
            role: "button",
            onClick: () => onSelect?.(row),
            onKeyDown: handleKey,
            "aria-label": `${SEVERITY_LONG[row.severity]} alert from ${row.source}: ${row.title}`,
          }
        : {})}
    >
      {/* P# label sits in the gutter to the left of the severity stripe. */}
      <span
        aria-hidden="true"
        data-testid={`severity-${row.severity}`}
        title={SEVERITY_LONG[row.severity]}
        className="absolute left-2 top-1/2 -translate-y-1/2 font-mono text-[10px] font-semibold tracking-wider"
        style={{ color: "var(--stripe-color)" }}
      >
        {SEVERITY_LABEL[row.severity]}
      </span>

      <div className="min-w-0">
        <div className="flex items-baseline justify-between gap-3">
          <h3 className="truncate text-sm font-semibold text-text-primary" title={row.title}>
            {row.title}
          </h3>
          <span className="flex shrink-0 items-baseline gap-2">
            {vendorLink ? (
              <a
                href={vendorLink.url}
                target="_blank"
                rel="noopener noreferrer"
                title={`${vendorLink.label} — ${vendorSessionNote(vendorLink.label.replace(/^Open in /, "") || undefined)}`}
                aria-label={vendorLink.label}
                data-testid="alert-vendor-link"
                // External nav: never also opens the drawer.
                onClick={(e) => e.stopPropagation()}
                className="vendor-link vendor-link--sm"
              >
                <span aria-hidden="true">↗</span>
              </a>
            ) : null}
            <time
              dateTime={row.occurred_at}
              className="font-mono text-[11px] text-text-dim"
              title={row.occurred_at}
            >
              {formatRelative(row.occurred_at, now)}
            </time>
          </span>
        </div>

        <div className="mt-1 flex flex-wrap items-center gap-x-1.5 font-mono text-[11px] text-text-secondary">
          <span>{row.source}</span>
          <span aria-hidden="true" className="text-text-dim">·</span>
          <span>{row.tenant}</span>
          {row.device ? (
            <>
              <span aria-hidden="true" className="text-text-dim">·</span>
              <span data-testid="alert-device" title="device">{row.device}</span>
            </>
          ) : null}
          {row.site ? (
            <>
              <span aria-hidden="true" className="text-text-dim">·</span>
              <span data-testid="alert-site" title="site">{row.site}</span>
            </>
          ) : null}
          <span aria-hidden="true" className="text-text-dim">·</span>
          <span className={STATUS_TONE[row.status]}>{STATUS_LABEL[row.status]}</span>
        </div>

        {row.summary ? (
          <p
            data-testid="alert-summary"
            className="mt-2 break-words text-[13px] text-text-primary"
            style={CLAMP_TWO_LINES}
            title={row.summary}
          >
            {clampedSummary(row.summary)}
          </p>
        ) : null}
      </div>
    </li>
  );
};

export default DefaultAlertFeed;
