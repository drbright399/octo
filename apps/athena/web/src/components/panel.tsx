import type { FC, ReactNode } from "react";

/**
 * Panel = the OCTO dashboard's section container. Wraps a widget (or any
 * dashboard surface) with consistent chrome: title, subtitle, stats row,
 * body. Layout chrome is the framework's responsibility; widgets render
 * the body.
 */

export interface PanelProps {
  readonly title: string;
  readonly subtitle?: string;
  readonly stats?: ReactNode;
  readonly children: ReactNode;
}

export const Panel: FC<PanelProps> = ({ title, subtitle, stats, children }) => (
  <section className="mb-6 rounded-lg border border-border bg-bg-surface p-5">
    <header className="mb-4 flex flex-wrap items-baseline justify-between gap-4">
      <h1 className="text-lg font-semibold text-text-primary">
        {title}
        {subtitle ? (
          <span className="ml-2 text-sm font-normal text-text-dim">— {subtitle}</span>
        ) : null}
      </h1>
      {stats ? <div className="flex gap-5">{stats}</div> : null}
    </header>
    <div>{children}</div>
  </section>
);

export interface StatProps {
  readonly label: string;
  readonly value: ReactNode;
  readonly tone?: "default" | "critical" | "high" | "accent";
}

export const Stat: FC<StatProps> = ({ label, value, tone = "default" }) => {
  const toneClass =
    tone === "critical"
      ? "text-critical"
      : tone === "high"
        ? "text-high"
        : tone === "accent"
          ? "text-accent"
          : "text-text-primary";

  return (
    <span className="inline-flex items-baseline gap-1 text-xs text-text-secondary">
      <span className={`font-mono text-base font-semibold ${toneClass}`}>{value}</span>
      <span>{label}</span>
    </span>
  );
};

export default Panel;
