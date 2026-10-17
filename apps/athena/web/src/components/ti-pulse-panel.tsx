/**
 * TiPulsePanel — the dashboard's threat-intel pulse widget body.
 *
 * Renders GET /dashboard/ti-pulse: recently sighted indicators across the
 * operator's tenants, values MASKED by the server (the raw value never
 * reaches the console here). A row opens the step-up-gated indicator search
 * for that one row (its `search_ref`), where the full value is shown after
 * re-authentication.
 *
 * Every state says what it is — loading, not-for-your-role, failed, empty
 * (with the server's reason: no tenants / nothing that carries an IOC /
 * nothing recent), partial (a tenant's store couldn't be read) — and the
 * cross-MSP pool's status is always stated, so an empty or short pulse
 * never reads as "all clear".
 */
import { useMemo, useState, type FC } from "react";

import {
  INDICATOR_SOURCE_LABEL,
  INDICATOR_TYPE_LABEL,
  type TiPulseItem,
  type TiPulseResponse,
} from "@/contracts/indicator";
import { formatRelative } from "@/lib/time";

export type TiPulseState =
  | { readonly status: "loading" }
  | { readonly status: "forbidden" }
  | { readonly status: "error" }
  | { readonly status: "ready"; readonly data: TiPulseResponse };

interface Props {
  readonly state: TiPulseState;
  /** Open the row's full value in the step-up-gated search. */
  readonly onOpen: (item: TiPulseItem) => void;
  readonly now?: Date;
}

const SEVERITY_TONE: Record<TiPulseItem["severity"], string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-warning",
  low: "text-text-dim",
};

const Note: FC<{ children: string }> = ({ children }) => (
  <div className="px-2 py-4 text-center text-[11px] italic text-text-dim">
    {children}
  </div>
);

const TiPulsePanel: FC<Props> = ({ state, onOpen, now }) => {
  const [query, setQuery] = useState("");
  const items = state.status === "ready" ? state.data.items : [];
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((i) =>
      i.tenant.toLowerCase().includes(q) ||
      i.type.toLowerCase().includes(q) ||
      INDICATOR_TYPE_LABEL[i.type]?.toLowerCase().includes(q) ||
      i.masked_value.toLowerCase().includes(q),
    );
  }, [items, query]);

  if (state.status === "loading") return <Note>Loading indicators…</Note>;
  if (state.status === "forbidden") {
    return <Note>The threat-intel pulse is available to analysts and above.</Note>;
  }
  if (state.status === "error") {
    return <Note>Couldn't load the threat-intel pulse — retrying.</Note>;
  }

  const { data } = state;
  const reference = now ?? new Date();
  return (
    <div className="flex h-full flex-col gap-2">
      {items.length > 0 && (
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter by tenant or type…"
          aria-label="Filter threat-intel pulse"
          className="rounded-sm border border-border bg-bg-card px-2 py-1 text-[11px] text-text-primary focus:border-accent focus:outline-none"
        />
      )}
      {items.length === 0 ? (
        <Note>{data.empty_detail ?? "No indicators to show."}</Note>
      ) : filtered.length === 0 ? (
        <Note>{`No indicators match "${query}".`}</Note>
      ) : (
        <ul className="flex min-h-0 flex-1 flex-col gap-1.5 overflow-y-auto" role="list">
          {filtered.map((ind) => (
            <li key={ind.search_ref}>
              <button
                type="button"
                onClick={() => onOpen(ind)}
                title="Show the full value in Search (re-authentication required)"
                aria-label={`${INDICATOR_TYPE_LABEL[ind.type] ?? ind.type} ${ind.masked_value} in ${ind.tenant} — show full value in Search`}
                className="w-full rounded border border-border bg-bg-card px-3 py-2 text-left transition-colors hover:border-border-bright"
              >
                <div className="flex items-baseline justify-between gap-2">
                  <span className="truncate font-mono text-[11px] text-text-primary">
                    {ind.masked_value}
                  </span>
                  <span className="shrink-0 font-mono text-[10px] uppercase tracking-wider text-text-dim">
                    {formatRelative(ind.last_seen, reference)}
                  </span>
                </div>
                <div className="mt-0.5 flex flex-wrap items-baseline gap-x-2 font-mono text-[10px] text-text-dim">
                  <span className="uppercase tracking-widest text-accent">
                    {INDICATOR_TYPE_LABEL[ind.type] ?? ind.type}
                  </span>
                  <span aria-hidden="true">·</span>
                  <span>{ind.tenant}</span>
                  <span aria-hidden="true">·</span>
                  <span className={SEVERITY_TONE[ind.severity] ?? "text-text-dim"}>
                    {ind.severity}
                  </span>
                  <span aria-hidden="true">·</span>
                  <span>
                    {ind.count} sighting{ind.count === 1 ? "" : "s"}
                  </span>
                  <span aria-hidden="true">·</span>
                  <span>via {INDICATOR_SOURCE_LABEL[ind.source_kind] ?? ind.source_kind}</span>
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}
      {items.length > 0 && data.unreadable_tenants > 0 && (
        <p data-testid="ti-pulse-partial" className="text-[10px] text-warning">
          {data.unreadable_tenants === 1
            ? "1 tenant's indicators couldn't be read — retrying."
            : `${data.unreadable_tenants} tenants' indicators couldn't be read — retrying.`}
        </p>
      )}
      <p className="mt-auto border-t border-border/40 pt-1.5 text-[10px] text-text-dim">
        {data.pool_status === "running"
          ? "Cross-MSP pool running."
          : "Cross-MSP pool not running — your tenants' own sightings only."}
      </p>
    </div>
  );
};

export default TiPulsePanel;
