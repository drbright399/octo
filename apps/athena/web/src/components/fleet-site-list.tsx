/**
 * FleetSiteList — sites as rows: the list view, and (under the map) the
 * sites that have no location (listed, never guessed onto the map). Each row
 * opens the site's drawer; the layer dots show each layer's state.
 *
 * A BLACK site reads Black here too — today most clients have no map pin, so
 * the row is where a Black must be seen: the octagon "!" chip, and (for
 * operators, until someone acknowledges it) the pulse. A client user never
 * gets a pulse.
 */
import type { FC } from "react";

import { LAYER_NAMES, type FleetSite, type LayerName, type SiteIncident } from "@/contracts/fleet";
import {
  LAYER_LABEL,
  STATE_LABEL,
  STATE_SHORT,
  STATE_TONE,
  effectiveState,
  type LayerFilter,
} from "@/lib/fleet";
import "./fleet.css";

export interface FleetSiteListProps {
  view: "operator" | "client";
  sites: readonly FleetSite[];
  layer: LayerFilter;
  title: string;
  /** Shown when the list is empty. */
  empty?: string;
  selectedKey?: string | null;
  onOpen: (site: FleetSite) => void;
}

const LayerDots: FC<{ site: FleetSite; view: "operator" | "client" }> = ({ site, view }) => (
  <span className="inline-flex items-center gap-1" aria-label="layers">
    {LAYER_NAMES.map((name: LayerName) => {
      const layer = site.layers[name];
      const present = layer && layer.present && layer.state !== "absent";
      const st = present ? layer.state as Exclude<typeof layer.state, "absent"> : null;
      return (
        <span
          key={name}
          title={`${LAYER_LABEL[view][name]}: ${st ? STATE_LABEL[st] : "not monitored"}`}
          data-testid={`layer-dot-${name}`}
          data-state={st ?? "absent"}
          className={[
            "inline-block h-2 w-2 rounded-full",
            st ? STATE_TONE[st].dot : "border border-border bg-transparent",
          ].join(" ")}
        />
      );
    })}
  </span>
);

const FleetSiteList: FC<FleetSiteListProps> = ({
  view, sites, layer, title, empty, selectedKey = null, onOpen,
}) => (
  <section
    aria-label={title}
    className="rounded-sm border border-border bg-bg-surface"
    data-testid="fleet-site-list"
  >
    <header className="flex items-center gap-2 border-b border-border px-3 py-1.5 font-mono text-[10px] uppercase tracking-widest text-text-dim">
      <span aria-hidden="true" className="text-accent">··</span>
      <span>{title}</span>
      <span className="text-text-dim">· {sites.length}</span>
    </header>
    {sites.length === 0 ? (
      <div className="px-3 py-4 text-center text-[12px] text-text-dim">{empty ?? "No sites."}</div>
    ) : (
      <ul role="list" className="divide-y divide-border">
        {sites.map((s) => {
          const st = effectiveState(s, layer) ?? "unknown";
          const tone = STATE_TONE[st];
          const inc = view === "operator" ? (s.incident as SiteIncident | null | undefined) : null;
          const pulse = st === "black" && view === "operator" && !!inc && !inc.acked
            && !inc.contained;
          return (
            <li key={s.key}>
              <button
                type="button"
                onClick={() => onOpen(s)}
                aria-pressed={s.key === selectedKey}
                data-testid={`site-row-${s.key}`}
                data-state={st}
                className={[
                  "grid w-full grid-cols-[6.5rem_minmax(0,1.3fr)_minmax(0,1fr)_auto] items-center gap-3 px-3 py-2 text-left text-[11px] transition-colors hover:bg-bg-card-hover",
                  s.key === selectedKey ? "bg-accent-soft" : "",
                ].join(" ")}
              >
                <span
                  title={STATE_LABEL[st]}
                  data-testid={st === "black" ? `row-black-chip-${s.key}` : undefined}
                  className={[
                    "inline-flex items-center justify-center gap-1 rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider",
                    tone.chip,
                    pulse ? "fleet-strip-black" : "",
                  ].join(" ")}
                >
                  {st === "black" && <span aria-hidden="true" data-testid="row-glyph">⯃!</span>}
                  {STATE_SHORT[st]}
                </span>
                <span className="min-w-0">
                  <span className="block truncate font-semibold text-text-primary">{s.name}</span>
                  <span className="block truncate font-mono text-[10px] text-text-dim">
                    {s.kind === "tenant" && view === "operator" ? "client-level · " : ""}
                    {view === "operator" ? s.tenant_name : ""}
                    {view === "operator" && s.location ? ` · ${s.location.label || "located"}` : ""}
                    {view === "operator" && !s.location ? " · no location" : ""}
                  </span>
                </span>
                <span className={`truncate ${st === "ok" ? "text-text-secondary" : tone.text}`} title={s.reason}>
                  {s.reason}
                </span>
                <LayerDots site={s} view={view} />
              </button>
            </li>
          );
        })}
      </ul>
    )}
  </section>
);

export default FleetSiteList;
