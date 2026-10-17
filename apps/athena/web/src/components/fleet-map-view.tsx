/**
 * FleetMapView — MapLibre GL JS basemap + fleet-map-overlay composite.
 *
 * Per the 2026-05-19 Fleet redesign hand-off + the basemap
 * handoff (2026-05-19-fleet-map-basemap.md):
 *
 *   - Basemap: MapLibre GL JS, vector tiles served from OCTO as PMTiles
 *     (single-file vector tiles, HTTP range-request). No external CDN,
 *     no customer lat/lng leaking off-prem.
 *   - Overlay: SVG, positioned over the map container; carries the
 *     radar sweep + signal traces + buoy heartbeat + hub hex.
 *   - Pan/zoom is owned by MapLibre. Every map `move`/`zoom` event
 *     triggers an overlay re-render via the project() callback wired
 *     to `map.project(lngLat)`.
 *
 * Graceful degradation:
 *   - If the PMTiles file isn't deployed yet, MapLibre still mounts —
 *     just renders against a flat dark canvas. The overlay still works,
 *     so operators can confirm the structure end-to-end before the
 *     basemap data lands.
 *   - Buoys without `lat`/`lng` are surfaced as a warning banner (the
 *     heartbeat contract extension is a separate slice).
 */
import {
  type FC, useEffect, useMemo, useRef, useState,
} from "react";
import maplibregl from "maplibre-gl";
import { Protocol } from "pmtiles";

// maplibre-gl.css is eager-imported from src/main.tsx — see the note
// there. Don't re-import it here; that would defeat the eager-load.
import "./fleet.css";

import FleetMapOverlay, {
  type BuoyMarker,
  type OctoNode,
  type ProjectFn,
  type RadarMotion,
  type SiteMarker,
} from "@/components/fleet-map-overlay";
import type { SiteState } from "@/contracts/fleet";
import { DEFAULT_SCHEME, SCHEME_IDS, resolveEnum, type Scheme } from "@/lib/appearance";
import { STATE_TONE } from "@/lib/fleet";


// Persist the motion preferences across page loads — two independent
// booleans (radar sweep + signal traces) per-operator. Maps to the
// overlay's RadarMotion enum at render time.
const RADAR_STORAGE_KEY = "athena.fleet.map.radar.v1";
const TRACES_STORAGE_KEY = "athena.fleet.map.traces.v1";
// Spotlight mode dims healthy (green) buoys so operators triaging an
// incident can focus on stale/red/yellow markers without losing the
// fleet context entirely. Same storage pattern.
const SPOTLIGHT_STORAGE_KEY = "athena.fleet.map.spotlight.v1";
function readBoolPreference(key: string, fallback: boolean): boolean {
  try {
    const v = localStorage.getItem(key);
    if (v === "0") return false;
    if (v === "1") return true;
  } catch { /* noop */ }
  return fallback;
}
function deriveMotion(radar: boolean, traces: boolean): RadarMotion {
  if (radar && traces) return "sweep";
  if (radar) return "spin";
  if (traces) return "signals";
  return "off";
}


export interface FleetMapViewProps {
  /** OCTO hubs (each carries lat/lng for the map). For v1 the demo
   *  defaults to a single primary hub; multi-OCTO is data-shape ready. */
  octos: ReadonlyArray<OctoNode>;
  /** Buoys with optional lat/lng. Ones missing coords are skipped on the
   *  map; FleetMapView surfaces a count via `coordsMissing` so the parent
   *  can render a status hint. */
  buoys: ReadonlyArray<BuoyMarker>;
  /** PMTiles filename to load from /api/v1/tiles/. Defaults to "us.pmtiles". */
  tilesFile?: string;
  /** Selected buoy slug — passed through to the overlay for the ring. */
  selectedSlug?: string | null;
  /** Click on a buoy marker → open the drawer. */
  onBuoyClick?: (buoy: BuoyMarker) => void;
  /** Fleet v2: site pins (coloured by worst state). */
  sites?: ReadonlyArray<SiteMarker>;
  selectedSiteKey?: string | null;
  onSiteClick?: (site: SiteMarker) => void;
  /** The buoy layer toggle (Fleet v2): false hides the buoy markers and
   *  their banner. Default true (the buoy view). */
  showBuoys?: boolean;
  /** Sites in the current filter that have no location (listed under the
   *  map, never guessed onto it). */
  unlocatedSites?: number;
  /** …how many of them need attention (bad / warn), and the worst state
   *  among them — the chip says so, tinted, so a red client without a pin is
   *  never only below the fold. */
  unlocatedProblems?: number;
  unlocatedWorst?: SiteState | null;
  /** Click on the "no location" chip (the page scrolls to the list). */
  onUnlocatedClick?: () => void;
  /** Click on the OCTO hub (super_admin: the host location editor). */
  onOctoClick?: ((octo: OctoNode) => void) | undefined;
}

/** Padding (px) and the closest zoom the map fits the pins with. */
export const FIT_PADDING_PX = 60;
export const FIT_MAX_ZOOM = 11;

/** [[west, south], [east, north]] around the pins with finite coordinates,
 *  or null when there is none. */
export function pinBounds(pins: ReadonlyArray<{ lat: number; lng: number }>):
    [[number, number], [number, number]] | null {
  let w = Infinity, s = Infinity, e = -Infinity, n = -Infinity;
  for (const p of pins) {
    if (!Number.isFinite(p.lat) || !Number.isFinite(p.lng)) continue;
    w = Math.min(w, p.lng); e = Math.max(e, p.lng);
    s = Math.min(s, p.lat); n = Math.max(n, p.lat);
  }
  return Number.isFinite(w) ? [[w, s], [e, n]] : null;
}


const NO_BUOYS: ReadonlyArray<BuoyMarker> = [];


// Register the pmtiles:// protocol with MapLibre once per page lifetime.
// (Multiple FleetMapView mounts share the registration — re-adding is a
// no-op per the pmtiles client.)
let _protocolRegistered = false;
function ensurePmtilesProtocol(): void {
  if (_protocolRegistered) return;
  const protocol = new Protocol();
  maplibregl.addProtocol("pmtiles", protocol.tile);
  _protocolRegistered = true;
}


// MapLibre style palettes per theme (+ per background scheme in dark
// mode). All target Protomaps Basemaps v4 vector tiles; only the colors
// differ. Default dark = phosphor-terminal violet, Light =
// parchment-neutral matching the rest of the light theme.
//
// Source-layer names match Protomaps Basemaps v4 schema:
//   https://docs.protomaps.com/basemaps/layers
interface MapPalette {
  background: string;
  earth: string;
  water: string;
  boundary_country: string;
  boundary_state: string;
  road_major: string;
  text_color: string;
  text_halo: string;
}

// One dark palette per background scheme (Appearance → Background).
// MapLibre paint properties need concrete colours — it can't resolve CSS
// custom properties — so the scheme surfaces are mirrored here by hand.
// Keep `background` / `text_halo` equal to that scheme's --bg-deep in
// src/index.css. The neutral schemes use grey linework: a violet border
// mesh on a true-grey / OLED-black console would defeat the scheme.
const DARK_PALETTES: Record<Scheme, MapPalette> = {
  twilight: {
    background:        "#0a0414",                       // --bg-deep
    earth:             "#150b29",                       // slightly lighter than bg
    water:             "#0a0420",                       // deeper blue-violet
    boundary_country:  "rgba(167, 139, 250, 0.40)",     // accent violet
    boundary_state:    "rgba(167, 139, 250, 0.22)",
    road_major:        "rgba(167, 139, 250, 0.18)",
    text_color:        "rgba(220, 215, 240, 0.78)",
    text_halo:         "#0a0414",
  },
  graphite: {
    background:        "#0c0c0c",                       // --bg-deep
    earth:             "#181818",
    water:             "#080808",
    boundary_country:  "rgba(255, 255, 255, 0.34)",
    boundary_state:    "rgba(255, 255, 255, 0.18)",
    road_major:        "rgba(255, 255, 255, 0.14)",
    text_color:        "rgba(228, 228, 228, 0.78)",
    text_halo:         "#0c0c0c",
  },
  "ultra-black": {
    background:        "#000000",                       // --bg-deep
    earth:             "#0e0e0e",                       // land lifts off true black
    water:             "#000000",
    boundary_country:  "rgba(255, 255, 255, 0.36)",
    boundary_state:    "rgba(255, 255, 255, 0.20)",
    road_major:        "rgba(255, 255, 255, 0.15)",
    text_color:        "rgba(235, 235, 235, 0.80)",
    text_halo:         "#000000",
  },
};

const LIGHT_PALETTE: MapPalette = {
  background:        "#f5f1ea",                       // warm paper
  earth:             "#ece6dc",                       // slightly darker than bg
  water:             "#d8e2eb",                       // muted blue-gray
  boundary_country:  "rgba(96, 64, 144, 0.45)",       // deeper violet for contrast
  boundary_state:    "rgba(96, 64, 144, 0.22)",
  road_major:        "rgba(120, 90, 160, 0.20)",
  text_color:        "rgba(40, 28, 64, 0.82)",
  text_halo:         "#f5f1ea",
};

function buildStyle(tilesUrl: string, palette: MapPalette): maplibregl.StyleSpecification {
  // No `glyphs` field — see place-labels layer removal below. Glyph
  // self-host is a follow-up slice. Without `glyphs`, MapLibre cannot
  // resolve any symbol layer; we drop place-labels accordingly.
  return {
    version: 8,
    sources: {
      protomaps: {
        type: "vector",
        url: `pmtiles://${tilesUrl}`,
        attribution: "&copy; OpenStreetMap, &copy; Protomaps",
      },
    },
    layers: [
      {
        id: "background",
        type: "background",
        paint: { "background-color": palette.background },
      },
      {
        id: "earth",
        type: "fill",
        source: "protomaps",
        "source-layer": "earth",
        paint: { "fill-color": palette.earth },
      },
      {
        id: "water",
        type: "fill",
        source: "protomaps",
        "source-layer": "water",
        paint: { "fill-color": palette.water },
      },
      {
        id: "boundaries-country",
        type: "line",
        source: "protomaps",
        "source-layer": "boundaries",
        filter: ["<=", ["get", "kind_detail"], 2],
        paint: {
          "line-color": palette.boundary_country,
          "line-width": ["interpolate", ["linear"], ["zoom"], 2, 0.4, 8, 1.2],
        },
      },
      {
        id: "boundaries-state",
        type: "line",
        source: "protomaps",
        "source-layer": "boundaries",
        minzoom: 4,
        filter: ["==", ["get", "kind_detail"], 3],
        paint: {
          "line-color": palette.boundary_state,
          "line-width": ["interpolate", ["linear"], ["zoom"], 4, 0.3, 10, 0.8],
        },
      },
      {
        id: "roads-major",
        type: "line",
        source: "protomaps",
        "source-layer": "roads",
        minzoom: 5,
        filter: ["in", ["get", "kind"], ["literal", ["highway", "major_road"]]],
        paint: {
          "line-color": palette.road_major,
          "line-width": ["interpolate", ["linear"], ["zoom"], 5, 0.3, 10, 1.0],
        },
      },
      // place-labels layer removed 2026-05-21. MapLibre couldn't load
      // glyphs from protomaps.github.io once strict CSP shipped — and
      // we don't want external glyph fetches anyway (privacy leak: every
      // viewer's IP hits a public CDN). Follow-up slice: self-host the
      // Protomaps glyph .pbf files under /v3/assets/fonts/ + restore
      // this symbol layer. Buoy callouts already carry company name +
      // lat/lng so city labels are aesthetic, not functional, for v1.
    ],
  };
}


/** Which map palette applies right now: "light", or — in dark mode — the
 * active background scheme. An unknown `data-scheme` falls back to the
 * default scheme (enum-only, same rule as the Appearance panel). */
type MapPaletteKey = "light" | Scheme;

function readMapPaletteKey(): MapPaletteKey {
  if (typeof document === "undefined") return DEFAULT_SCHEME;
  const root = document.documentElement;
  if (root.getAttribute("data-theme") === "light") return "light";
  return resolveEnum(root.getAttribute("data-scheme"), SCHEME_IDS) ?? DEFAULT_SCHEME;
}

function paletteFor(key: MapPaletteKey): MapPalette {
  return key === "light" ? LIGHT_PALETTE : DARK_PALETTES[key];
}

/** Watch `<html data-theme>` + `<html data-scheme>` for changes via
 * MutationObserver. The theme module (`lib/theme.ts`) and the Appearance
 * panel (`lib/appearance.ts`) own the attributes; we just need to react. */
function useMapPaletteKey(): MapPaletteKey {
  const [key, setKey] = useState<MapPaletteKey>(readMapPaletteKey);
  useEffect(() => {
    if (typeof document === "undefined") return;
    const observer = new MutationObserver(() => setKey(readMapPaletteKey()));
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme", "data-scheme"],
    });
    return () => observer.disconnect();
  }, []);
  return key;
}


const FleetMapView: FC<FleetMapViewProps> = ({
  octos, buoys, tilesFile = "us.pmtiles", selectedSlug = null, onBuoyClick,
  sites = [], selectedSiteKey = null, onSiteClick, showBuoys = true, unlocatedSites = 0,
  unlocatedProblems = 0, unlocatedWorst = null, onUnlocatedClick, onOctoClick,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  // `tick` increments on every map move/zoom so the overlay re-projects.
  const [tick, setTick] = useState(0);
  const [mapError, setMapError] = useState<string | null>(null);
  const [hoverSlug, setHoverSlug] = useState<string | null>(null);
  const [hoverSiteKey, setHoverSiteKey] = useState<string | null>(null);
  const [showRadar, setShowRadar] = useState<boolean>(() => readBoolPreference(RADAR_STORAGE_KEY, true));
  const [showTraces, setShowTraces] = useState<boolean>(() => readBoolPreference(TRACES_STORAGE_KEY, true));
  const [spotlight, setSpotlight] = useState<boolean>(() => readBoolPreference(SPOTLIGHT_STORAGE_KEY, false));
  useEffect(() => {
    try { localStorage.setItem(RADAR_STORAGE_KEY, showRadar ? "1" : "0"); } catch { /* noop */ }
  }, [showRadar]);
  useEffect(() => {
    try { localStorage.setItem(TRACES_STORAGE_KEY, showTraces ? "1" : "0"); } catch { /* noop */ }
  }, [showTraces]);
  useEffect(() => {
    try { localStorage.setItem(SPOTLIGHT_STORAGE_KEY, spotlight ? "1" : "0"); } catch { /* noop */ }
  }, [spotlight]);
  const motion = deriveMotion(showRadar, showTraces);
  const paletteKey = useMapPaletteKey();

  // Swap the map style when the theme or background scheme changes —
  // observe `<html data-theme>` / `<html data-scheme>` and re-apply the
  // matching palette. We use `setStyle({...}, {diff: true})`
  // so MapLibre patches just the paint properties rather than tearing
  // down the whole source (avoids a flicker + a re-download of headers).
  useEffect(() => {
    const map = mapRef.current;
    if (!map) return;
    map.setStyle(buildStyle(`/api/v1/tiles/${tilesFile}`, paletteFor(paletteKey)), { diff: true });
  }, [paletteKey, tilesFile]);

  // Initialize MapLibre once on mount.
  useEffect(() => {
    if (!containerRef.current || mapRef.current) return;
    ensurePmtilesProtocol();

    let cancelled = false;
    try {
      const initialPalette = paletteFor(paletteKey);
      const map = new maplibregl.Map({
        container: containerRef.current,
        style: buildStyle(`/api/v1/tiles/${tilesFile}`, initialPalette),
        center: [-95, 39],   // continental US center
        zoom: 3.6,
        attributionControl: false,
        // Animations off: keeps the SVG overlay in sync with the map
        // tiles (no "tweening drift" between SVG and tile positions).
        fadeDuration: 0,
      });

      map.on("move", () => { if (!cancelled) setTick((t) => t + 1); });
      map.on("zoom", () => { if (!cancelled) setTick((t) => t + 1); });
      map.on("resize", () => {
        if (cancelled) return;
        const c = map.getCanvas();
        setSize({ w: c.clientWidth, h: c.clientHeight });
      });
      map.on("error", (e) => {
        // Tile-load failures (missing PMTiles file, range request 404,
        // etc.) land here. Don't blow up the UI — just remember the
        // error so the parent can surface it.
        if (cancelled) return;
        setMapError(e?.error?.message ?? "Basemap load error");
      });
      map.on("load", () => {
        if (cancelled) return;
        const c = map.getCanvas();
        setSize({ w: c.clientWidth, h: c.clientHeight });
        // Initial tick so the overlay places markers on first paint.
        setTick((t) => t + 1);
      });

      mapRef.current = map;
    } catch (e) {
      setMapError(e instanceof Error ? e.message : "Failed to initialize map");
    }

    return () => {
      cancelled = true;
      if (mapRef.current) {
        try { mapRef.current.remove(); } catch { /* noop */ }
        mapRef.current = null;
      }
    };
  }, [tilesFile]);

  // Fit the map to the site pins — once, when the first located sites
  // arrive (the continental default view squeezes a regional fleet into one
  // ring of pins). Later polls never move the map the operator is using;
  // the "fit" button does it on demand.
  const fittedRef = useRef(false);
  const fitToPins = (): boolean => {
    const map = mapRef.current;
    const bounds = pinBounds(sites);
    if (!map || !bounds || typeof map.fitBounds !== "function") return false;
    try {
      map.fitBounds(bounds, { padding: FIT_PADDING_PX, maxZoom: FIT_MAX_ZOOM, duration: 0 });
      return true;
    } catch {
      return false;
    }
  };
  useEffect(() => {
    if (fittedRef.current) return;
    if (fitToPins()) fittedRef.current = true;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sites]);

  // Resize observer — keeps size state in sync if the container itself
  // changes size (e.g., sidebar collapse, window resize without map.resize
  // being called).
  useEffect(() => {
    if (!containerRef.current) return;
    const el = containerRef.current;
    const ro = new ResizeObserver(() => {
      if (mapRef.current) mapRef.current.resize();
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Projection callback for the overlay. Captures `tick` so React
  // re-runs the overlay on every map move/zoom. Returns null for
  // off-screen points (overlay then skips drawing those).
  const project: ProjectFn = useMemo(() => {
    // The function reference is recreated when tick or size changes,
    // forcing the overlay's internal useMemo to re-project. The
    // tick reference inside the body is unused — its purpose is to
    // be a dep.
    void tick;
    void size.w;
    return (lat: number, lng: number) => {
      const map = mapRef.current;
      if (!map) return null;
      const p = map.project([lng, lat]);
      if (!isFinite(p.x) || !isFinite(p.y)) return null;
      // Skip if WAY off-canvas (1000px margin = safe for label overflow).
      const c = map.getCanvas();
      if (p.x < -1000 || p.y < -1000) return null;
      if (p.x > c.clientWidth + 1000 || p.y > c.clientHeight + 1000) return null;
      return { x: p.x, y: p.y };
    };
  }, [tick, size.w, size.h]);

  // Surface count of buoys missing lat/lng — the heartbeat contract
  // extension is a separate slice, so for now operators may see "0/N
  // buoys mapped" until that ships.
  const shownBuoys = showBuoys ? buoys : NO_BUOYS;
  const buoysWithCoords = useMemo(
    () => shownBuoys.filter((b) => Number.isFinite(b.lat) && Number.isFinite(b.lng)),
    [shownBuoys],
  );
  const coordsMissing = shownBuoys.length - buoysWithCoords.length;

  return (
    <div className="relative h-[640px] w-full overflow-hidden rounded-sm border border-border bg-bg-surface">
      {/*
        Container is sized with `h-full w-full`, NOT `absolute inset-0`.
        Reason: maplibre-gl.css adds `.maplibregl-map { position: relative }`
        to whichever element we hand to `new Map({ container })`. That
        overrides our `position: absolute`, which makes `inset-0`
        (top/right/bottom/left: 0) silently do nothing — `inset` only
        applies under absolute/fixed/sticky. The container then collapses
        to its content (just the 300px-default MapLibre canvas), creating
        a stable layout feedback loop where the basemap shows at 300px
        forever. Root-caused 2026-05-20 with the lazy-load investigation
        diagnostic logs. `h-full w-full` sizes the container relative to
        the parent's explicit 640px height without depending on any
        particular `position` value.
      */}
      <div ref={containerRef} className="h-full w-full" />

      {/* Overlay sits on top, pointer-events: none on root */}
      <FleetMapOverlay
        containerSize={size}
        octos={octos}
        buoys={buoysWithCoords}
        project={project}
        selectedSlug={selectedSlug ?? null}
        hoverSlug={hoverSlug}
        motion={motion}
        spotlight={spotlight}
        onBuoyClick={onBuoyClick}
        onBuoyHover={setHoverSlug}
        sites={sites}
        selectedSiteKey={selectedSiteKey}
        hoverSiteKey={hoverSiteKey}
        onSiteClick={onSiteClick}
        onSiteHover={setHoverSiteKey}
        onOctoClick={onOctoClick}
      />

      {/* Motion toggles — top-right corner. Two independent buttons
          (radar sweep + signal traces) per operator request. Both
          persisted via localStorage so preference rides through
          refreshes. Operators in a focused-review session typically
          want the sweep off and traces on (or both off) so static
          positions stand out. */}
      <div className="pointer-events-auto absolute right-3 top-3 flex items-center gap-1.5 rounded-sm border border-border bg-bg-card/90 px-1.5 py-1 backdrop-blur-sm">
        <span
          aria-hidden="true"
          className="font-mono text-[9px] uppercase tracking-widest text-text-dim"
        >motion</span>
        <button
          type="button"
          aria-pressed={showRadar}
          onClick={() => setShowRadar((v) => !v)}
          className={[
            "rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider transition-colors",
            showRadar
              ? "border-accent/60 bg-accent/15 text-accent"
              : "border-border bg-bg-input text-text-secondary hover:border-border-bright hover:text-text-primary",
          ].join(" ")}
          title={showRadar
            ? "Radar sweep ON — click to hide the rotating sweep fan."
            : "Radar sweep OFF — click to re-enable."}
        >
          sweep {showRadar ? "·" : "off"}
        </button>
        <button
          type="button"
          aria-pressed={showTraces}
          onClick={() => setShowTraces((v) => !v)}
          className={[
            "rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider transition-colors",
            showTraces
              ? "border-accent/60 bg-accent/15 text-accent"
              : "border-border bg-bg-input text-text-secondary hover:border-border-bright hover:text-text-primary",
          ].join(" ")}
          title={showTraces
            ? "Signal traces ON — click to hide the buoy→OCTO data connection lines."
            : "Signal traces OFF — click to re-enable."}
        >
          links {showTraces ? "·" : "off"}
        </button>
        {sites.length > 0 && (
          <>
            <span aria-hidden="true" className="px-0.5 text-text-dim">·</span>
            <button
              type="button"
              onClick={() => { fitToPins(); }}
              data-testid="fleet-map-fit"
              className="rounded-sm border border-border bg-bg-input px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-text-secondary transition-colors hover:border-border-bright hover:text-text-primary"
              title="Zoom the map to every site pin."
            >
              fit
            </button>
          </>
        )}
        <span aria-hidden="true" className="px-0.5 text-text-dim">·</span>
        <button
          type="button"
          aria-pressed={spotlight}
          onClick={() => setSpotlight((v) => !v)}
          className={[
            "rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider transition-colors",
            spotlight
              ? "border-warning/60 bg-warning/15 text-warning"
              : "border-border bg-bg-input text-text-secondary hover:border-border-bright hover:text-text-primary",
          ].join(" ")}
          title={spotlight
            ? "Spotlight ON — green/healthy buoys dimmed to focus on triage. Click to disable."
            : "Spotlight mode dims healthy buoys to ~22%, so stale/red/yellow markers stand out during triage."}
        >
          spot {spotlight ? "·" : "off"}
        </button>
      </div>

      {/* Tile-load error banner (basemap fails gracefully — overlay still renders) */}
      {mapError && (
        <div className="pointer-events-none absolute left-3 top-3 max-w-md rounded-sm border border-warning/40 bg-warning/10 px-3 py-1.5 font-mono text-[10px] text-warning">
          <strong className="uppercase tracking-widest">basemap unavailable</strong>
          {" · "}
          {mapError}. Overlay still renders against the flat backdrop —
          drop a `.pmtiles` file at the OCTO data root&apos;s
          {" "}<code>tiles/</code> directory to enable the world map.
        </div>
      )}

      {/* Sites without a location: listed below the map, never guessed — the
          chip says how many need attention, tinted by the worst of them. */}
      {unlocatedSites > 0 && (
        <button
          type="button"
          data-testid="unlocated-sites-banner"
          data-state={unlocatedWorst ?? undefined}
          onClick={onUnlocatedClick}
          className={[
            "pointer-events-auto absolute bottom-3 right-3 max-w-xs rounded-sm border px-3 py-1.5 text-left font-mono text-[10px] backdrop-blur-sm",
            unlocatedProblems > 0 && unlocatedWorst
              ? STATE_TONE[unlocatedWorst].chip
              : "border-border bg-bg-elevated/90 text-text-secondary",
          ].join(" ")}
        >
          <strong className="uppercase tracking-widest">no location</strong>
          {" · "}
          {unlocatedSites} site{unlocatedSites === 1 ? "" : "s"}
          {unlocatedProblems > 0 ? ` (${unlocatedProblems} need${unlocatedProblems === 1 ? "s" : ""} attention)` : ""}
          {" listed below the map ↓"}
        </button>
      )}

      {/* Missing-coords banner — the heartbeat contract extension is its own slice. */}
      {coordsMissing > 0 && (
        <div className="pointer-events-none absolute bottom-3 left-3 max-w-md rounded-sm border border-border bg-bg-elevated/90 px-3 py-1.5 font-mono text-[10px] text-text-secondary">
          <strong className="uppercase tracking-widest text-text-dim">geo data missing</strong>
          {" · "}
          {coordsMissing} of {buoys.length} buoy{buoys.length === 1 ? "" : "s"} have no lat/lng yet.
          The heartbeat-services contract extension adds these fields; until then the map view
          shows only buoys with coords reported manually.
        </div>
      )}
    </div>
  );
};


export default FleetMapView;
