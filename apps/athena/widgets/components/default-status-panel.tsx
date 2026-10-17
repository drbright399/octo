/**
 * `default-status-panel` — list of name → status pairs. Used for "is X
 * healthy?" surfaces (integration status, buoy stack lights, service
 * components, etc.).
 */

import type { FC } from "react";

export type StatusKind = "ok" | "degraded" | "down" | "pending" | "unknown";

export interface StatusRow {
  readonly id: string;
  readonly name: string;
  readonly status: StatusKind;
  readonly detail?: string;
}

export interface DefaultStatusPanelProps {
  readonly rows: readonly StatusRow[];
  readonly emptyLabel?: string;
}

const STATUS_LABEL: Record<StatusKind, string> = {
  ok: "ok",
  degraded: "degraded",
  down: "down",
  pending: "pending",
  unknown: "unknown",
};

const STATUS_DOT: Record<StatusKind, string> = {
  ok: "bg-success animate-pulse shadow-[0_0_6px_var(--success)]",
  degraded: "bg-medium",
  down: "bg-critical animate-pulse",
  pending: "bg-medium",
  unknown: "bg-text-dim",
};

const STATUS_TEXT: Record<StatusKind, string> = {
  ok: "text-success",
  degraded: "text-medium",
  down: "text-critical",
  pending: "text-medium",
  unknown: "text-text-dim",
};

export const DefaultStatusPanel: FC<DefaultStatusPanelProps> = ({
  rows,
  emptyLabel = "No items",
}) => {
  if (rows.length === 0) {
    return (
      <div className="px-4 py-6 text-center text-sm italic text-text-dim">
        {emptyLabel}
      </div>
    );
  }
  return (
    <ul className="flex flex-col gap-1.5" role="list">
      {rows.map((r) => (
        <li
          key={r.id}
          className="flex items-center gap-2.5 rounded border border-border bg-bg-card px-3 py-2"
        >
          <span
            className={`h-2 w-2 shrink-0 rounded-full ${STATUS_DOT[r.status]}`}
            aria-hidden="true"
          />
          <span className="flex-1 truncate text-sm text-text-primary">{r.name}</span>
          {r.detail ? (
            <span className="font-mono text-[11px] text-text-dim">{r.detail}</span>
          ) : null}
          <span
            className={`font-mono text-[10px] uppercase tracking-wider ${STATUS_TEXT[r.status]}`}
          >
            {STATUS_LABEL[r.status]}
          </span>
        </li>
      ))}
    </ul>
  );
};

export default DefaultStatusPanel;
