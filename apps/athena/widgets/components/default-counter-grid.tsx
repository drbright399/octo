/**
 * `default-counter-grid` — KPI tile grid. Each cell shows a label, a big
 * mono number, and optional delta vs prior period.
 *
 * Dumb component — receives counters, renders them.
 */

import type { FC } from "react";

export type CounterTone = "default" | "critical" | "high" | "medium" | "success" | "accent";

export interface CounterCell {
  readonly id: string;
  readonly label: string;
  readonly value: string | number;
  readonly tone?: CounterTone;
  readonly delta?: number;
  readonly deltaSuffix?: string;
}

export interface DefaultCounterGridProps {
  readonly counters: readonly CounterCell[];
  readonly columns?: 2 | 3 | 4;
}

const TONE_CLASS: Record<CounterTone, string> = {
  default: "text-text-primary",
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  success: "text-success",
  accent: "text-accent",
};

const COLUMNS_CLASS: Record<NonNullable<DefaultCounterGridProps["columns"]>, string> = {
  2: "grid-cols-2",
  3: "grid-cols-2 md:grid-cols-3",
  4: "grid-cols-2 md:grid-cols-4",
};

export const DefaultCounterGrid: FC<DefaultCounterGridProps> = ({
  counters,
  columns = 4,
}) => (
  <ul className={`grid gap-3 ${COLUMNS_CLASS[columns]}`} role="list">
    {counters.map((c) => (
      <li
        key={c.id}
        className="flex flex-col gap-1 rounded border border-border bg-bg-card p-3"
      >
        <span className="text-[10px] font-semibold uppercase tracking-wider text-text-dim">
          {c.label}
        </span>
        <span
          className={`font-mono text-2xl font-semibold ${TONE_CLASS[c.tone ?? "default"]}`}
        >
          {c.value}
        </span>
        {typeof c.delta === "number" ? (
          <span
            className={[
              "font-mono text-[11px]",
              c.delta > 0
                ? "text-high"
                : c.delta < 0
                  ? "text-success"
                  : "text-text-dim",
            ].join(" ")}
          >
            {c.delta > 0 ? "▲" : c.delta < 0 ? "▼" : "·"} {Math.abs(c.delta)}
            {c.deltaSuffix ?? ""}
          </span>
        ) : null}
      </li>
    ))}
  </ul>
);

export default DefaultCounterGrid;
