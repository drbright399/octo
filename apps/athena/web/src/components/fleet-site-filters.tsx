/**
 * FleetSiteFilters — the search box and the filters above the site map /
 * list: problems only, by layer (the pin then shows THAT layer's state and
 * sites without it are hidden), by tenant (operators), and the buoy layer
 * toggle (map view, operators). Controlled by the page so the map and the
 * list always show the same sites.
 */
import type { FC } from "react";

import type { LayerName } from "@/contracts/fleet";
import { LAYER_LABEL, type LayerFilter, type SiteFilters } from "@/lib/fleet";

export interface FleetSiteFiltersProps {
  view: "operator" | "client";
  filters: SiteFilters;
  onChange: (next: SiteFilters) => void;
  tenants: ReadonlyArray<{ slug: string; name: string }>;
  resultCount: number;
  totalCount: number;
  /** Map view (operators): the buoy layer toggle. Undefined = not shown. */
  showBuoys?: boolean | undefined;
  onShowBuoys?: ((v: boolean) => void) | undefined;
}

const LAYERS: readonly LayerName[] = ["network", "security", "endpoints", "buoy"];

const chip = (on: boolean): string => [
  "rounded-sm border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider transition-colors",
  on ? "border-accent bg-accent/15 text-accent"
    : "border-border bg-bg-card text-text-secondary hover:border-border-bright hover:text-text-primary",
].join(" ");

const FleetSiteFilters: FC<FleetSiteFiltersProps> = ({
  view, filters, onChange, tenants, resultCount, totalCount, showBuoys, onShowBuoys,
}) => {
  const labels = LAYER_LABEL[view];
  const filtered = Boolean(filters.query) || filters.problemsOnly || filters.layer !== "all"
    || filters.tenant !== null;
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-sm border border-border bg-bg-surface px-3 py-2"
         data-testid="fleet-site-filters">
      <div className="relative flex min-w-[14rem] flex-1 items-center">
        <span aria-hidden="true" className="absolute left-2 font-mono text-[12px] text-text-dim">⌕</span>
        <input
          type="search"
          value={filters.query}
          onChange={(e) => onChange({ ...filters, query: e.target.value })}
          placeholder={view === "operator" ? "search site / client / address / reason"
            : "search site / reason"}
          aria-label="Search sites"
          className="w-full rounded-sm border border-border bg-bg-card py-1 pl-7 pr-2 font-mono text-[11px] text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
        />
      </div>

      <button type="button" aria-pressed={filters.problemsOnly}
              className={chip(filters.problemsOnly)}
              onClick={() => onChange({ ...filters, problemsOnly: !filters.problemsOnly })}
              title="Only sites that are not ok (problem, attention, unknown)">
        problems only
      </button>

      <label className="flex items-center gap-1 font-mono text-[10px] uppercase tracking-wider text-text-dim">
        layer
        <select
          aria-label="Filter by layer"
          value={filters.layer}
          onChange={(e) => onChange({ ...filters, layer: e.target.value as LayerFilter })}
          className="rounded-sm border border-border bg-bg-card px-1.5 py-0.5 font-mono text-[11px] normal-case tracking-normal text-text-primary focus:border-accent focus:outline-none"
        >
          <option value="all">all layers (worst)</option>
          {LAYERS.map((l) => <option key={l} value={l}>{labels[l]}</option>)}
        </select>
      </label>

      {view === "operator" && tenants.length > 1 && (
        <label className="flex items-center gap-1 font-mono text-[10px] uppercase tracking-wider text-text-dim">
          client
          <select
            aria-label="Filter by client"
            value={filters.tenant ?? ""}
            onChange={(e) => onChange({ ...filters, tenant: e.target.value || null })}
            className="max-w-[14rem] rounded-sm border border-border bg-bg-card px-1.5 py-0.5 font-mono text-[11px] normal-case tracking-normal text-text-primary focus:border-accent focus:outline-none"
          >
            <option value="">all clients</option>
            {tenants.map((t) => <option key={t.slug} value={t.slug}>{t.name}</option>)}
          </select>
        </label>
      )}

      {showBuoys !== undefined && onShowBuoys && (
        <button type="button" aria-pressed={showBuoys} className={chip(showBuoys)}
                onClick={() => onShowBuoys(!showBuoys)}
                title="Show the buoys (and their signal traces) on the map">
          buoys {showBuoys ? "·" : "off"}
        </button>
      )}

      {filtered && (
        <>
          <span className="font-mono text-[10px] uppercase tracking-wider text-text-dim"
                data-testid="fleet-result-count">
            {resultCount} of {totalCount} match
          </span>
          <button type="button"
                  onClick={() => onChange({ query: "", problemsOnly: false, layer: "all", tenant: null })}
                  className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-text-secondary transition-colors hover:border-border-bright hover:text-text-primary">
            clear ✕
          </button>
        </>
      )}
    </div>
  );
};

export default FleetSiteFilters;
