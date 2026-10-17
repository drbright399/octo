/**
 * FleetMapOverlay — SVG overlay layer for the Fleet map.
 *
 * Per the 2026-05-19 Fleet redesign hand-off, the fleet map is
 * a real-world tile basemap (production: MapLibre GL JS + self-hosted
 * PMTiles served from OCTO; design kit: Leaflet + CartoDB) with this
 * SVG overlay positioned over it. The overlay carries:
 *
 *   - OCTO hub marker (hexagon, accent-tinted, breathing pulse)
 *   - Radar sweep fan (70° wide, 10s revolution, fades toward trailing edge)
 *   - Oscilloscope-style signal trace from each buoy → its OCTO hub
 *     (5-harmonic sine sum + 10% grain, three stacked stroke layers,
 *      SMIL <animate> shifting phase)
 *   - Buoy markers (static colored dots; brief drop-shadow heartbeat the
 *     instant the radar bar crosses their azimuth; red buoys get an
 *     additional always-on ambient glow + triple-peak urgent heartbeat)
 *
 * Library-agnostic by design — the caller passes a `project(lat, lng) → {x,y} | null`
 * function (MapLibre's `map.project()` works directly; Leaflet's
 * `map.latLngToContainerPoint()` is a one-line adapter). When `project`
 * returns null (point outside the current viewport) the marker is
 * skipped, not drawn.
 *
 * Currently NOT mounted in `pages/fleet.tsx` — that integration happens
 * when the MapLibre + PMTiles basemap lands. The overlay component is
 * here so it can be unit-tested in isolation and wired up by a tighter
 * follow-up commit.
 *
 * Reference: kit at ui_kits/athena-console/fleet/map.jsx (Leaflet mock).
 */
import { type FC, type SVGAttributes, useMemo } from "react";

import type { SiteState } from "@/contracts/fleet";
import { STATE_COLOR, STATE_ORDER, handPlaced } from "@/lib/fleet";
import { useReducedMotion } from "@/lib/motion";

import "./fleet.css";


// ---------------------------------------------------------------------------
// Constants — shared with the kit so timing stays locked
// ---------------------------------------------------------------------------

/** Seconds per full radar revolution. Per-buoy heartbeat animation-delay
 * = azimuth/360 × RADAR_PERIOD, so the blip fires when the bar crosses. */
export const RADAR_PERIOD = 10;

/** Number of rays in the radar sweep fan. */
const FAN_RAYS = 24;

/** Fan width in degrees (trailing edge fades to 0 alpha). */
const FAN_DEG = 70;

/** Sweep ray length — large enough to reach the viewport edge at any zoom. */
const SWEEP_RADIUS = 4000;

/** Buoy marker dot radius in CSS px. Fixed regardless of map zoom. */
const MARKER_R = 7;

/** Vertical offset (px) from marker center to the slug label baseline. */
const LABEL_OFFSET = 14;

/** Health-tone RGB triples — shared with `lib/buoy.ts::BuoyHealth`. */
const HEALTH_RGB: Record<string, string> = {
  green:   "34,197,94",
  yellow:  "234,179,8",
  red:     "239,68,68",
  stale:   "107,101,137",
  unknown: "107,101,137",
};


// ---------------------------------------------------------------------------
// Types — caller-facing shapes
// ---------------------------------------------------------------------------

export interface OctoNode {
  /** Stable slug. Buoys reference their OCTO via this. */
  slug: string;
  /** Display name (e.g. "Primary"). */
  display: string;
  /** City label rendered under the hub. */
  city: string;
  /** MSP display name rendered as "MSP · {msp}" sub-label. */
  msp: string;
  lat: number;
  lng: number;
}

export interface BuoyMarker {
  slug: string;
  hostname?: string | undefined;
  city?: string | undefined;
  lat: number;
  lng: number;
  /** Maps to one of the keys in HEALTH_RGB. Anything else falls back to "unknown". */
  health: "green" | "yellow" | "red" | "stale" | "unknown";
  /** Slug of the OCTO this buoy reports to. Used to anchor the signal trace. */
  octo: string;
}

/** Fleet v2: one SITE pin, coloured by the site's worst state. */
export interface SiteMarker {
  /** The API's opaque site key. */
  key: string;
  name: string;
  /** Location label (address text or the manual override's label). */
  label?: string | undefined;
  tenant?: string | undefined;
  lat: number;
  lng: number;
  state: SiteState;
  /** "site" / "manual" = placed by an operator (this site's own pin / the
   *  client's fallback) — drawn as a diamond. */
  source?: "unifi" | "manual" | "site" | undefined;
  /** The reason behind the colour ("2 IPS blocks today"). */
  reason?: string | undefined;
  /** Black only: acknowledged (the pulse stops; the owner's initials show). */
  acked?: boolean | undefined;
  /** Black only: marked contained (a static double ring). */
  contained?: boolean | undefined;
  /** Black only: the initials of who acknowledged it. */
  owner?: string | undefined;
}

/** Map-library-agnostic projection. Returns null for off-screen points. */
export type ProjectFn = (lat: number, lng: number) => { x: number; y: number } | null;

/** Motion mode controls the radar fan + the signal traces independently.
 *  - "off":     no radar, no signal traces
 *  - "spin":    radar fan only
 *  - "signals": signal traces only (no radar)
 *  - "sweep":   radar + signal traces (full motion, default)
 *  In FleetMapView this maps to two independent operator toggles so
 *  operators can dial each animation on/off per preference. */
export type RadarMotion = "off" | "spin" | "signals" | "sweep";

export interface FleetMapOverlayProps {
  /** Container size in CSS px. Drives the SVG's intrinsic `<svg width height>` */
  containerSize: { w: number; h: number };
  /** OCTO hubs to draw. Empty list = nothing renders. */
  octos: ReadonlyArray<OctoNode>;
  /** Buoys to draw + signal-trace to their referenced OCTO. */
  buoys: ReadonlyArray<BuoyMarker>;
  /** Project lat/lng to container coordinates. */
  project: ProjectFn;
  /** Which buoy is currently selected (drawer open). */
  selectedSlug?: string | null;
  /** Hover halo target. */
  hoverSlug?: string | null;
  /** Show buoy slug + city under each marker (true when zoom ≥ ~4). */
  showLabels?: boolean;
  /** Hub label verbosity: "minimal" → just display name beside hex;
   *  "short" → display + city; "full" → adds eyebrow + MSP sub-label. */
  hubLabelTier?: "minimal" | "short" | "full";
  /** Animation mode. "off" disables all motion; "spin" runs radar +
   *  heartbeat only; "sweep" adds the oscilloscope signal trace. */
  motion?: RadarMotion;
  /** Spotlight mode: dim healthy (green) buoys to ~22% opacity so an
   *  operator triaging incidents can focus on stale/red/yellow markers
   *  without losing the spatial context entirely. Default false. */
  spotlight?: boolean;
  /** Click handler — fires on the buoy `<g>` only (rest of SVG ignores). */
  onBuoyClick?: ((buoy: BuoyMarker) => void) | undefined;
  onBuoyHover?: ((slug: string | null) => void) | undefined;
  /** Fleet v2 site pins (drawn above the buoys). */
  sites?: ReadonlyArray<SiteMarker> | undefined;
  selectedSiteKey?: string | null | undefined;
  hoverSiteKey?: string | null | undefined;
  onSiteClick?: ((site: SiteMarker) => void) | undefined;
  onSiteHover?: ((key: string | null) => void) | undefined;
  /** Click on an OCTO hub (super_admin: move the host pin). Absent: the hub
   *  is not clickable. */
  onOctoClick?: ((octo: OctoNode) => void) | undefined;
}


// ---------------------------------------------------------------------------
// Pure helpers — ports of map.jsx::signalPath + azimuth
// ---------------------------------------------------------------------------

interface Pt { x: number; y: number; }

/**
 * Bezier-curve signal-trace path with perpendicular sine-harmonic offset.
 * Five harmonics summed + 10% pseudo-random grain + endpoint taper.
 * Same recipe as the dashboard Oscilloscope widget so the visual reads
 * as the same CRT trace.
 *
 * @param from        — start point (buoy)
 * @param to          — end point (OCTO hub)
 * @param wavePhase   — 0..1 phase along the harmonics; SMIL animates this
 * @param amplitudeMul — scales the perpendicular displacement (0.22 = tight inner trace, 1 = body)
 */
function signalPath(from: Pt, to: Pt, wavePhase: number, amplitudeMul = 1): string {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const len = Math.hypot(dx, dy) || 1;
  const baseBow = Math.min(0.22, 60 / len + 0.06);
  const px = -dy / len;
  const py = dx / len;
  const cx1 = from.x + dx * 0.30 + px * len * baseBow;
  const cy1 = from.y + dy * 0.30 + py * len * baseBow;
  const cx2 = from.x + dx * 0.70 + px * len * baseBow;
  const cy2 = from.y + dy * 0.70 + py * len * baseBow;

  const N = 60;
  const amplitude = 5 * amplitudeMul;
  const phase = wavePhase * Math.PI * 2;
  const parts: string[] = [];
  for (let i = 0; i <= N; i++) {
    const t = i / N;
    const omt = 1 - t;
    const bx = omt * omt * omt * from.x + 3 * omt * omt * t * cx1 + 3 * omt * t * t * cx2 + t * t * t * to.x;
    const by = omt * omt * omt * from.y + 3 * omt * omt * t * cy1 + 3 * omt * t * t * cy2 + t * t * t * to.y;
    const tx = 3 * omt * omt * (cx1 - from.x) + 6 * omt * t * (cx2 - cx1) + 3 * t * t * (to.x - cx2);
    const ty = 3 * omt * omt * (cy1 - from.y) + 6 * omt * t * (cy2 - cy1) + 3 * t * t * (to.y - cy2);
    const tlen = Math.hypot(tx, ty) || 1;
    const nx = -ty / tlen;
    const ny = tx / tlen;

    const u = t * len;
    let v = 0;
    v += 0.45 * Math.sin(u * 0.040 - phase * 1.4);
    v += 0.30 * Math.sin(u * 0.090 - phase * 2.1 + 0.7);
    v += 0.18 * Math.sin(u * 0.150 - phase * 0.9 + 1.4);
    v += 0.10 * Math.sin(u * 0.240 - phase * 3.3 + 2.0);
    v += 0.06 * Math.sin(u * 0.405 - phase * 1.6 + 2.8);
    v /= 1.09;

    // Pseudo-random grain so the trace isn't pristine.
    const g = Math.sin(u * 12.9898 + wavePhase * 78.233) * 43758.5453;
    v += (g - Math.floor(g) - 0.5) * 0.10;

    // Endpoint taper so the trace meets the markers cleanly.
    const taper = Math.sin(t * Math.PI);
    const x = bx + nx * amplitude * v * taper;
    const y = by + ny * amplitude * v * taper;
    parts.push((i === 0 ? "M" : "L") + x.toFixed(1) + " " + y.toFixed(1));
  }
  return parts.join(" ");
}

/** Azimuth in degrees, 0..360, from `from` toward `to`. Used to phase
 * the buoy heartbeat with the radar sweep. */
function azimuth(from: Pt, to: Pt): number {
  const a = Math.atan2(to.y - from.y, to.x - from.x) * 180 / Math.PI;
  return (a + 360) % 360;
}

// Cluster-and-spread tuning.
// `SPREAD_THRESHOLD_PX` — two markers closer than this in screen space
//   are treated as overlapping. Roughly 2× the marker visual radius so
//   adjacent-but-not-overlapping markers don't get unnecessarily spread.
// `SPREAD_RADIUS_PX` — how far each cluster member sits from the
//   cluster centroid. Tuned so a 3-member ring is visually distinct but
//   still reads as one location group.
const SPREAD_THRESHOLD_PX = 24;
const SPREAD_RADIUS_PX = 14;
/** A site pin's radius (Fleet v2). */
const PIN_R = 6;

/**
 * Greedy clustering + circular spread to disambiguate buoys with
 * coincident projected positions (typically when multiple buoys
 * share the same geo-IP city-level lat/lng).
 *
 * Pass 1: cluster buoys whose projected screen positions fall within
 * `SPREAD_THRESHOLD_PX` of an existing cluster's first member. Greedy
 * — first-fit by iteration order. Sort by slug inside each cluster so
 * the same buoy lands in the same arc slot across re-renders (stable
 * visual identity; no flicker when projection ticks).
 *
 * Pass 2: any cluster with >1 member, replace each member's `xy` with
 * a point on a circle of radius `SPREAD_RADIUS_PX` around the cluster
 * centroid (the projected position of the first sorted member). Members
 * are placed evenly around the circle starting at the top (−π/2).
 *
 * Mutates `buoys` in place — the caller already holds the array as a
 * fresh `useMemo` value.
 *
 * As map zoom increases, the same lat/lng deltas project to more
 * screen pixels; once members of a cluster fall outside the threshold
 * the cluster splits naturally and members snap back to their true
 * projections. When per-buoy street addresses arrive (via Autotask),
 * this pass is effectively a no-op at any usable zoom.
 */
function spreadOverlappingBuoys(buoys: PositionedBuoy[]): void {
  if (buoys.length < 2) return;
  const clusters: PositionedBuoy[][] = [];
  for (const b of buoys) {
    let placed = false;
    for (const c of clusters) {
      const head = c[0]!;
      const dx = b.xy.x - head.xy.x;
      const dy = b.xy.y - head.xy.y;
      if (Math.hypot(dx, dy) < SPREAD_THRESHOLD_PX) {
        c.push(b);
        placed = true;
        break;
      }
    }
    if (!placed) clusters.push([b]);
  }
  for (const cluster of clusters) {
    if (cluster.length < 2) continue;
    // Stable order by slug → same arc slot across renders.
    cluster.sort((a, b) => a.slug.localeCompare(b.slug));
    const centroid = { ...cluster[0]!.xy };
    const step = (Math.PI * 2) / cluster.length;
    for (let i = 0; i < cluster.length; i++) {
      const angle = i * step - Math.PI / 2;
      cluster[i]!.xy = {
        x: centroid.x + SPREAD_RADIUS_PX * Math.cos(angle),
        y: centroid.y + SPREAD_RADIUS_PX * Math.sin(angle),
      };
    }
  }
}

interface PositionedOcto { slug: string; xy: Pt; node: OctoNode; }
interface PositionedBuoy { slug: string; xy: Pt; hub: PositionedOcto | null; az: number; marker: BuoyMarker; }
interface PositionedSite { slug: string; xy: Pt; marker: SiteMarker; }

/** The ring radius for a cluster of `n` site pins: the buoy ring's for a
 *  few, growing with the cluster so neighbours keep about a pin's width
 *  apart (40 pins in one ring stay 40 pins, not a solid donut). */
function siteRingRadius(n: number): number {
  return Math.max(SPREAD_RADIUS_PX, (n * (PIN_R * 2 + 3)) / (2 * Math.PI));
}

/** The same cluster-and-spread for site pins (keyed by site key): sites of
 *  one street, or a client's sites placed at one manual location, separate
 *  into a ring until the zoom pulls them apart — a ring that grows with the
 *  cluster. The caller paints them worst-last (`paintOrder`). */
function spreadOverlappingSites(sites: PositionedSite[]): void {
  if (sites.length < 2) return;
  const clusters: PositionedSite[][] = [];
  for (const s of sites) {
    const c = clusters.find((cl) => Math.hypot(s.xy.x - cl[0]!.xy.x, s.xy.y - cl[0]!.xy.y) < SPREAD_THRESHOLD_PX);
    if (c) c.push(s); else clusters.push([s]);
  }
  for (const cluster of clusters) {
    if (cluster.length < 2) continue;
    cluster.sort((a, b) => a.slug.localeCompare(b.slug));
    const centroid = { ...cluster[0]!.xy };
    const radius = siteRingRadius(cluster.length);
    const step = (Math.PI * 2) / cluster.length;
    for (let i = 0; i < cluster.length; i++) {
      const angle = i * step - Math.PI / 2;
      cluster[i]!.xy = { x: centroid.x + radius * Math.cos(angle), y: centroid.y + radius * Math.sin(angle) };
    }
  }
}


// (Spread helpers are added to the module's `__test__` export at the
// bottom of this file alongside signalPath + azimuth.)


// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

const FleetMapOverlay: FC<FleetMapOverlayProps> = ({
  containerSize, octos, buoys, project,
  selectedSlug = null, hoverSlug = null,
  showLabels = true, hubLabelTier = "short", motion = "sweep",
  spotlight = false,
  onBuoyClick, onBuoyHover,
  sites = [], selectedSiteKey = null, hoverSiteKey = null, onSiteClick, onSiteHover,
  onOctoClick,
}) => {
  const { w, h } = containerSize;

  const positions = useMemo(() => {
    const placedOctos: PositionedOcto[] = [];
    for (const o of octos) {
      const xy = project(o.lat, o.lng);
      if (xy) placedOctos.push({ slug: o.slug, xy, node: o });
    }
    const octoBySlug = new Map(placedOctos.map((o) => [o.slug, o]));
    const placedBuoys: PositionedBuoy[] = [];
    for (const b of buoys) {
      const xy = project(b.lat, b.lng);
      if (!xy) continue;
      placedBuoys.push({
        slug: b.slug,
        xy,
        hub: octoBySlug.get(b.octo) ?? null,
        az: 0,         // computed below after the spread pass
        marker: b,
      });
    }

    // Collision-aware spread: city-level geo-IP gives multiple buoys at
    // the EXACT same lat/lng (e.g. three buoys in one city behind the same
    // ISP CIDR). At low zoom their projected screen points coincide and
    // they stack into a single marker. Run a greedy clustering pass and
    // spread members of any cluster around its centroid. As the user
    // zooms in, projected distances grow naturally; once members fall
    // outside SPREAD_THRESHOLD_PX they stop clustering and sit at their
    // true positions. When Autotask integration brings exact street
    // addresses, members are far enough apart at any usable zoom that
    // this pass is effectively a no-op.
    spreadOverlappingBuoys(placedBuoys);

    // Compute the buoy→hub azimuth AFTER spreading so signal traces
    // depart the marker from its visible (spread) position.
    for (const b of placedBuoys) {
      b.az = b.hub ? azimuth(b.hub.xy, b.xy) : 0;
    }

    const placedSites: PositionedSite[] = [];
    for (const site of sites) {
      if (!Number.isFinite(site.lat) || !Number.isFinite(site.lng)) continue;
      const xy = project(site.lat, site.lng);
      if (!xy) continue;
      placedSites.push({ slug: site.key, xy, marker: site });
    }
    spreadOverlappingSites(placedSites);

    // Worst LAST: SVG paints later elements on top, so a problem pin is never
    // hidden under an ok one (whatever order the caller listed them in).
    return { octos: placedOctos, buoys: placedBuoys,
             sites: placedSites.sort((a, b) => STATE_ORDER[b.marker.state] - STATE_ORDER[a.marker.state]) };
  }, [octos, buoys, sites, project]);

  if (w <= 0 || h <= 0) return null;

  return (
    <svg
      className={[
        "fleet-map-overlay pointer-events-none absolute inset-0 h-full w-full",
        spotlight ? "fleet-map-overlay--spotlight" : "",
      ].join(" ")}
      width={w}
      height={h}
      viewBox={`0 0 ${w} ${h}`}
      aria-hidden="true"
    >
      <defs>
        <radialGradient id="fleet-hub-glow" cx="50%" cy="50%" r="50%">
          {/* Live accent (was hard-coded violet) — follows the bundle. */}
          <stop offset="0%"  style={{ stopColor: "var(--accent)", stopOpacity: 0.45 }} />
          <stop offset="100%" style={{ stopColor: "var(--accent)", stopOpacity: 0 }} />
        </radialGradient>
      </defs>

      {/* Hub ambient glow underlay */}
      {positions.octos.map((o) => (
        <circle key={`glow-${o.slug}`}
                cx={o.xy.x} cy={o.xy.y}
                r={MARKER_R * 26}
                fill="url(#fleet-hub-glow)" />
      ))}

      {/* Radar sweep fan per OCTO. Rendered for "spin" + "sweep"; not for
       *  "off" or "signals" (signals-only mode). */}
      {(motion === "spin" || motion === "sweep") && positions.octos.map((o) => (
        <RadarFan key={`radar-${o.slug}`} center={o.xy} />
      ))}

      {/* Oscilloscope signal traces — buoy → hub. Red buoys excluded
       *   (per design — they're not transmitting). Rendered for "sweep"
       *   + "signals"; not for "off" or "spin" (radar-only mode). */}
      {(motion === "sweep" || motion === "signals") && (
        <g className="fleet-map-overlay__signals">
          {positions.buoys.map((b) =>
            b.hub && b.marker.health !== "red"
              ? <SignalTrace key={`sig-${b.slug}`} from={b.xy} to={b.hub.xy} buoy={b.marker} />
              : null,
          )}
        </g>
      )}

      {/* OCTO hub markers */}
      {positions.octos.map((o) => (
        <OctoHubMarker key={o.slug} octo={o.node} xy={o.xy}
                       labelTier={hubLabelTier} motion={motion} onClick={onOctoClick} />
      ))}

      {/* Fleet v2 site pins — coloured by the site's worst state */}
      <g className="fleet-map-overlay__sites">
        {positions.sites.map((site) => (
          <SitePin
            key={site.slug}
            site={site}
            selected={site.slug === selectedSiteKey}
            hovered={site.slug === hoverSiteKey}
            motion={motion}
            onClick={onSiteClick}
            onHover={onSiteHover}
          />
        ))}
      </g>

      {/* Buoys — drawn last so they paint over the traces */}
      <g className="fleet-map-overlay__buoys">
        {positions.buoys.map((b) => (
          <BuoyMarkerNode
            key={b.slug}
            buoy={b}
            selected={b.slug === selectedSlug}
            hovered={b.slug === hoverSlug}
            showLabels={showLabels}
            motion={motion}
            onClick={onBuoyClick}
            onHover={onBuoyHover}
          />
        ))}
      </g>
    </svg>
  );
};


// ---------------------------------------------------------------------------
// Radar fan — 24 rays, 70° wide, trailing-edge fade. 10s revolution.
// ---------------------------------------------------------------------------

const RadarFan: FC<{ center: Pt }> = ({ center }) => (
  <g
    className="fleet-map-overlay__radar"
    style={{
      transformOrigin: `${center.x}px ${center.y}px`,
      animation: `fleet-radar-spin ${RADAR_PERIOD}s linear infinite`,
    }}
  >
    {Array.from({ length: FAN_RAYS }, (_, i) => {
      const frac = i / (FAN_RAYS - 1);
      const ang = -(frac * FAN_DEG) * Math.PI / 180;
      const x2 = center.x + Math.cos(ang) * SWEEP_RADIUS;
      const y2 = center.y + Math.sin(ang) * SWEEP_RADIUS;
      const op = (1 - frac) * 0.55;
      const strokeW = i === 0 ? 1.6 : 1;
      return (
        <line key={i}
              x1={center.x} y1={center.y}
              x2={x2} y2={y2}
              stroke="var(--accent)"
              strokeOpacity={op}
              strokeWidth={strokeW} />
      );
    })}
  </g>
);


// ---------------------------------------------------------------------------
// Signal trace — three stacked stroke layers per buoy, SMIL-animated.
// ---------------------------------------------------------------------------

const PHASES = Array.from({ length: 13 }, (_, i) => i / 12);

const SignalTrace: FC<{ from: Pt; to: Pt; buoy: BuoyMarker }> = ({ from, to, buoy }) => {
  const color = `rgb(${HEALTH_RGB[buoy.health] ?? HEALTH_RGB.unknown})`;
  const dMain  = PHASES.map((p) => signalPath(from, to, p)).join(";");
  const dInner = PHASES.map((p) => signalPath(from, to, p, 0.22)).join(";");
  const initialMain  = signalPath(from, to, 0);
  const initialInner = signalPath(from, to, 0, 0.22);
  // Vary duration per buoy so the traces don't tick in lockstep.
  const dur = 1.6 + (buoy.slug.length % 4) * 0.15;
  const bodyOpacity = buoy.health === "yellow" ? 0.92 : 0.78;
  return (
    <g>
      {/* (a) wide phosphor halo */}
      <path d={initialMain} fill="none"
            stroke={color} strokeOpacity={0.30}
            strokeWidth={4} strokeLinecap="round" strokeLinejoin="round"
            style={{ filter: `drop-shadow(0 0 8px ${color})` }}>
        <animate attributeName="d" values={dMain}
                 dur={`${dur}s`} repeatCount="indefinite" calcMode="linear" />
      </path>
      {/* (b) body trace */}
      <path d={initialMain} fill="none"
            stroke={color} strokeOpacity={bodyOpacity}
            strokeWidth={1.2} strokeLinecap="round" strokeLinejoin="round">
        <animate attributeName="d" values={dMain}
                 dur={`${dur}s`} repeatCount="indefinite" calcMode="linear" />
      </path>
      {/* (c) bright dense inner line — ~22% amplitude, white-ish */}
      <path d={initialInner} fill="none"
            stroke="rgba(255,255,255,0.78)"
            strokeWidth={0.6} strokeLinecap="round" strokeLinejoin="round">
        <animate attributeName="d" values={dInner}
                 dur={`${dur}s`} repeatCount="indefinite" calcMode="linear" />
      </path>
    </g>
  );
};


// ---------------------------------------------------------------------------
// OCTO hub marker — hexagon + label tiers
// ---------------------------------------------------------------------------

interface OctoHubMarkerProps {
  octo: OctoNode;
  xy: Pt;
  labelTier: "minimal" | "short" | "full";
  motion: RadarMotion;
  onClick?: ((octo: OctoNode) => void) | undefined;
}

const OctoHubMarker: FC<OctoHubMarkerProps> = ({ octo, xy, labelTier, motion, onClick }) => {
  const r = MARKER_R * 1.8;
  const hexPts = useMemo(() => {
    const pts: string[] = [];
    for (let k = 0; k < 6; k++) {
      const a = (Math.PI / 3) * k - Math.PI / 2;
      pts.push(`${(Math.cos(a) * r).toFixed(2)},${(Math.sin(a) * r).toFixed(2)}`);
    }
    return pts.join(" ");
  }, [r]);

  return (
    <g transform={`translate(${xy.x},${xy.y})`} className="fleet-map-overlay__hub"
       data-testid={`octo-hub-${octo.slug}`}
       style={onClick ? { cursor: "pointer", pointerEvents: "auto" } : undefined}
       onClick={onClick ? (e) => { e.stopPropagation(); onClick(octo); } : undefined}>
      {onClick && <title>{`${octo.display} — set the host location`}</title>}
      <circle r={MARKER_R * 2.6} fill="var(--accent)" fillOpacity={0.20} />
      <polygon points={hexPts}
               fill="var(--accent)"
               stroke="var(--bg-deep)"
               strokeWidth={1.5}
               style={{
                 filter: "drop-shadow(0 0 6px var(--accent))",
                 animation: motion !== "off" ? `fleet-hub-pulse ${RADAR_PERIOD}s ease-in-out infinite` : "none",
               }} />
      {labelTier === "full" && (
        <>
          <text y={-MARKER_R * 3.5} textAnchor="middle"
                fontFamily="var(--font-mono)" fontSize={9}
                fill="var(--accent)"
                style={{ letterSpacing: "0.18em", textTransform: "uppercase" }}>
            ·· octo host ··
          </text>
          <text y={-MARKER_R * 2.1} textAnchor="middle"
                fontFamily="var(--font-mono)" fontSize={11}
                fill="var(--text-primary)" style={{ fontWeight: 600 }}>
            {octo.display}
          </text>
          <text y={MARKER_R * 3.4} textAnchor="middle"
                fontFamily="var(--font-mono)" fontSize={9}
                fill="var(--text-dim)">
            {octo.city}
          </text>
          <text y={MARKER_R * 3.4 + 11} textAnchor="middle"
                fontFamily="var(--font-mono)" fontSize={9}
                fill="var(--text-dim)" style={{ letterSpacing: "0.1em" }}>
            MSP · {octo.msp}
          </text>
        </>
      )}
      {labelTier === "short" && (
        <>
          <text y={-MARKER_R * 2.4} textAnchor="middle"
                fontFamily="var(--font-mono)" fontSize={11}
                fill="var(--text-primary)" style={{ fontWeight: 600 }}>
            {octo.display}
          </text>
          <text y={MARKER_R * 3.0} textAnchor="middle"
                fontFamily="var(--font-mono)" fontSize={9}
                fill="var(--text-dim)">
            {octo.city}
          </text>
        </>
      )}
      {labelTier === "minimal" && (
        <text x={MARKER_R * 2.6} y={MARKER_R * 0.4} textAnchor="start"
              fontFamily="var(--font-mono)" fontSize={11}
              fill="var(--accent)"
              style={{ fontWeight: 600, letterSpacing: "0.1em" }}>
          {octo.display}
        </text>
      )}
    </g>
  );
};


// ---------------------------------------------------------------------------
// Buoy marker + heartbeat
// ---------------------------------------------------------------------------

interface BuoyMarkerNodeProps {
  buoy: PositionedBuoy;
  selected: boolean;
  hovered: boolean;
  showLabels: boolean;
  motion: RadarMotion;
  onClick?: ((b: BuoyMarker) => void) | undefined;
  onHover?: ((slug: string | null) => void) | undefined;
}

const BuoyMarkerNode: FC<BuoyMarkerNodeProps> = ({
  buoy, selected, hovered, showLabels, motion, onClick, onHover,
}) => {
  const b = buoy.marker;
  const blipDelay = (buoy.az / 360) * RADAR_PERIOD;
  const isRed = b.health === "red";
  const rgb = HEALTH_RGB[b.health] ?? HEALTH_RGB.unknown;

  // CSS-var trick: --throb-color is read by the @keyframes fleet-heartbeat[-urgent]
  // animations in fleet.css. Setting it inline keeps the keyframe color-agnostic.
  const innerStyle: SVGAttributes<SVGGElement>["style"] | undefined = motion === "off" ? undefined : {
    animation: `${isRed ? "fleet-heartbeat-urgent" : "fleet-heartbeat"} ${RADAR_PERIOD}s linear infinite`,
    animationDelay: `${blipDelay}s`,
    ["--throb-color" as string]: `rgb(${rgb})`,
  };
  const ambientStyle: SVGAttributes<SVGGElement>["style"] | undefined = (isRed && motion !== "off") ? {
    animation: "fleet-ambient-urgent 1.2s ease-in-out infinite",
    ["--throb-color" as string]: `rgb(${HEALTH_RGB.red})`,
  } : undefined;

  const markerInner = (
    <g style={innerStyle}>
      <circle r={MARKER_R * 1.6}
              fill={`rgba(${rgb},${isRed ? 0.28 : 0.18})`} />
      <circle r={MARKER_R}
              fill={`rgb(${rgb})`}
              stroke="var(--bg-deep)" strokeWidth={1.4} />
    </g>
  );

  return (
    <g transform={`translate(${buoy.xy.x},${buoy.xy.y})`}
       className="fleet-map-overlay__buoy"
       data-health={b.health}
       style={{ cursor: onClick ? "pointer" : undefined, pointerEvents: "auto" }}
       onClick={onClick ? (e) => { e.stopPropagation(); onClick(b); } : undefined}
       onMouseEnter={onHover ? () => onHover(b.slug) : undefined}
       onMouseLeave={onHover ? () => onHover(null) : undefined}>
      {/* Native hover tooltip — slug, hostname/city, health.
          SVG <title> is rendered by the browser as a tooltip after
          a short hover delay. Lightweight + accessible (screen
          readers read it). Future: richer portal'd tooltip with
          last-action context once the agent-notes UI is wired. */}
      <title>
        {`${b.slug}\n`}
        {b.hostname ? `host: ${b.hostname}\n` : ""}
        {b.city ? `${b.city}\n` : ""}
        {`status: ${b.health}`}
      </title>
      {(selected || hovered) && (
        <circle r={MARKER_R * 2.4} fill="none"
                stroke="var(--accent)" strokeOpacity={0.9}
                strokeWidth={1.5} />
      )}
      {ambientStyle ? <g style={ambientStyle}>{markerInner}</g> : markerInner}
      {showLabels && (
        <>
          <text y={MARKER_R + LABEL_OFFSET} textAnchor="middle"
                fontFamily="var(--font-mono)" fontSize={11}
                fill="var(--text-primary)"
                className="fleet-map-overlay__label-text"
                style={{ pointerEvents: "none" }}>
            {b.slug}
          </text>
          {b.city && (
            <text y={MARKER_R + LABEL_OFFSET + 11} textAnchor="middle"
                  fontFamily="var(--font-mono)" fontSize={9}
                  fill="var(--text-dim)"
                  className="fleet-map-overlay__label-text"
                  style={{ pointerEvents: "none", letterSpacing: "0.05em" }}>
              {b.city}
            </text>
          )}
        </>
      )}
    </g>
  );
};


// ---------------------------------------------------------------------------
// Site pin (Fleet v2) — a circle (UniFi location) or a diamond (placed by an
// operator), filled with the state colour; warn adds a ring, bad (Red) a
// STATIC halo (Red never pulses), unknown is hollow and dashed (never drawn
// as "ok"); a notice stays green with a thin grey dotted ring (seen, not a
// problem). BLACK is an OCTAGON with a "!" glyph — near-black inside a bright
// ring — that PULSES until acknowledged (the radar's motion toggle does not
// stop it; the OS's reduced-motion gives a static thick double ring), then
// stays solid with its owner's initials; contained = a static double ring.
// Shapes as well as colours, so the state reads without colour too.
// ---------------------------------------------------------------------------

/** An octagon of radius `r`, flat top (rotated 22.5°). */
export function octagonPoints(r: number): string {
  const pts: string[] = [];
  for (let i = 0; i < 8; i += 1) {
    const a = Math.PI / 8 + (i * Math.PI) / 4;
    pts.push(`${(r * Math.cos(a)).toFixed(2)},${(r * Math.sin(a)).toFixed(2)}`);
  }
  return pts.join(" ");
}

const BLACK_R = PIN_R * 1.35;

interface SitePinProps {
  site: PositionedSite;
  selected: boolean;
  hovered: boolean;
  /** The radar's motion setting — deliberately NOT what stops a Black's
   *  pulse (only the OS's reduced motion does); no site pin animates by it. */
  motion: RadarMotion;
  onClick?: ((s: SiteMarker) => void) | undefined;
  onHover?: ((key: string | null) => void) | undefined;
}

const SitePin: FC<SitePinProps> = ({ site, selected, hovered, onClick, onHover }) => {
  const m = site.marker;
  const reduced = useReducedMotion();
  const color = STATE_COLOR[m.state] ?? STATE_COLOR.unknown;
  const manual = handPlaced(m.source);
  const hollow = m.state === "unknown";
  const black = m.state === "black";
  const body = black ? (
    <>
      <polygon points={octagonPoints(BLACK_R)} fill="var(--fleet-threat)"
               stroke="var(--fleet-threat-ring)" strokeWidth={2}
               data-testid="site-pin-octagon" />
      <text y={BLACK_R * 0.42} textAnchor="middle" fontFamily="var(--font-mono)"
            fontSize={BLACK_R * 1.25} fontWeight={700} fill="var(--fleet-threat-ring)"
            style={{ pointerEvents: "none" }} data-testid="site-pin-glyph">!</text>
    </>
  ) : manual ? (
    <rect x={-PIN_R} y={-PIN_R} width={PIN_R * 2} height={PIN_R * 2} rx={1.5}
          transform="rotate(45)"
          fill={hollow ? "var(--bg-deep)" : color}
          stroke={hollow ? color : "var(--bg-deep)"}
          strokeWidth={hollow ? 1.6 : 1.4}
          strokeDasharray={hollow ? "2 2" : undefined} />
  ) : (
    <circle r={PIN_R}
            fill={hollow ? "var(--bg-deep)" : color}
            stroke={hollow ? color : "var(--bg-deep)"}
            strokeWidth={hollow ? 1.6 : 1.4}
            strokeDasharray={hollow ? "2 2" : undefined} />
  );
  return (
    <g transform={`translate(${site.xy.x},${site.xy.y})`}
       className="fleet-map-overlay__site"
       data-state={m.state}
       data-source={m.source ?? "unifi"}
       data-testid={`site-pin-${m.key}`}
       style={{ cursor: onClick ? "pointer" : undefined, pointerEvents: "auto" }}
       onClick={onClick ? (e) => { e.stopPropagation(); onClick(m); } : undefined}
       onMouseEnter={onHover ? () => onHover(m.key) : undefined}
       onMouseLeave={onHover ? () => onHover(null) : undefined}>
      <title>
        {`${m.name}\n`}
        {m.tenant ? `${m.tenant}\n` : ""}
        {m.label ? `${m.label}\n` : ""}
        {`${m.state}${m.reason ? ` — ${m.reason}` : ""}`}
        {black ? (m.contained ? "\ncontained" : m.acked ? "\nacknowledged" : "\nUNACKNOWLEDGED") : ""}
      </title>
      {/* Selection / hover: a dashed SQUARE in the text colour — never a
          circle in --accent (under Midas Touch the gold accent reads as the
          amber "attention" ring). */}
      {(selected || hovered) && (
        <rect x={-PIN_R * 2.4} y={-PIN_R * 2.4} width={PIN_R * 4.8} height={PIN_R * 4.8}
              fill="none" stroke="var(--text-primary)" strokeOpacity={0.95}
              strokeWidth={1.4} strokeDasharray="4 3"
              data-testid={selected ? "site-pin-selected" : "site-pin-hover"} />
      )}
      {m.state === "warn" && (
        <circle r={PIN_R * 1.7} fill="none" stroke={color} strokeOpacity={0.7}
                strokeWidth={1.2} />
      )}
      {m.state === "notice" && (
        <circle r={PIN_R * 1.6} fill="none" stroke="var(--text-dim)" strokeOpacity={0.85}
                strokeWidth={1} strokeDasharray="1.5 2" data-testid="site-pin-notice-ring" />
      )}
      {m.state === "bad" && (
        // Red never pulses: a static halo.
        <circle r={PIN_R * 1.8} fill="none" stroke={color} strokeWidth={1.6}
                strokeOpacity={0.85} data-testid="site-pin-red-halo" />
      )}
      {black && m.contained && (
        <g data-testid="site-pin-contained">
          <circle r={BLACK_R * 1.55} fill="none" stroke="var(--fleet-threat-ring)" strokeWidth={1.4} />
          <circle r={BLACK_R * 1.95} fill="none" stroke="var(--fleet-threat-ring)" strokeWidth={1.4} />
        </g>
      )}
      {black && !m.contained && !m.acked && (reduced ? (
        // The OS asked for reduced motion: a static THICK double ring.
        <g data-testid="site-pin-black-static">
          <circle r={BLACK_R * 1.55} fill="none" stroke="var(--fleet-threat-ring)" strokeWidth={3} />
          <circle r={BLACK_R * 2.05} fill="none" stroke="var(--fleet-threat-ring)" strokeWidth={3} />
        </g>
      ) : (
        // Pulses until acknowledged — whatever the radar's motion setting
        // (`motion` is deliberately not read here).
        <circle r={BLACK_R * 1.6} fill="none" stroke="var(--fleet-threat-ring)" strokeWidth={2.2}
                className="fleet-pin-black" data-testid="site-pin-black-pulse" />
      ))}
      {black && !m.contained && m.acked && (
        <circle r={BLACK_R * 1.5} fill="none" stroke="var(--fleet-threat-ring)" strokeWidth={2}
                data-testid="site-pin-black-solid" />
      )}
      {body}
      {black && m.acked && m.owner && (
        <text x={BLACK_R * 1.9} y={-BLACK_R * 0.9} fontFamily="var(--font-mono)" fontSize={9}
              fontWeight={700} fill="var(--fleet-threat-ring)"
              className="fleet-map-overlay__label-text" style={{ pointerEvents: "none" }}
              data-testid="site-pin-owner">{m.owner}</text>
      )}
      {(selected || hovered) && (
        <text y={PIN_R + LABEL_OFFSET} textAnchor="middle"
              fontFamily="var(--font-mono)" fontSize={11}
              fill="var(--text-primary)"
              className="fleet-map-overlay__label-text"
              style={{ pointerEvents: "none" }}>
          {m.name}
        </text>
      )}
    </g>
  );
};


// Internal helpers exported for unit tests.
export const __test__ = {
  signalPath, azimuth,
  spreadOverlappingBuoys, SPREAD_THRESHOLD_PX, SPREAD_RADIUS_PX,
  spreadOverlappingSites, siteRingRadius,
};

export default FleetMapOverlay;
