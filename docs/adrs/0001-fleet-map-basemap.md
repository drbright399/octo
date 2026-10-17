# ADR-0001 — Fleet map basemap: MapLibre GL JS + self-hosted PMTiles

**Status:** Accepted
**Date:** 2026-05-19
**Deciders:** Rick (operator) + Claude Design + Claude Code

---

## Context

The Fleet redesign (the 2026-05-19 design hand-off, kept outside the
repo)
introduces a real-world map view for the buoy fleet. Buoys render as
colored markers at their geographic locations; an OCTO host renders as
a radar dish at the bundle's deploy location; an SVG overlay carries
the radar sweep + heartbeat + signal traces.

The map needs a basemap (terrain + roads + place labels) for the
markers to read against. Options considered:

1. **External raster CDN** — Leaflet + CartoDB / Mapbox / Stadia tiles
2. **External vector style** — MapLibre + MapTiler / Mapbox-hosted style
3. **Self-hosted raster tiles** — TileServer-GL + MBTiles
4. **Self-hosted vector tiles** — MapLibre + PMTiles served from OCTO

The kit mock at `ui_kits/athena-console/fleet/map.jsx` uses option 1
(Leaflet + CartoDB DarkMatter raster) to make the design read; the
basemap handoff doc explicitly flags this as **not suitable for
production**.

## Decision

**Use option 4: MapLibre GL JS + self-hosted PMTiles served from OCTO.**

- Map library: `maplibre-gl` (open-source fork of Mapbox GL JS v1, no
  API-token gate)
- Tile format: PMTiles (single-file vector tiles, HTTP range-request
  served)
- Tile data: OpenStreetMap planet OR a regional extract (US-only first
  per the basemap handoff)
- Tile build: `planetiler` or `tilemaker` offline; result is a single
  `.pmtiles` file under `OCTO_DATA_ROOT/tiles/`
- Tile serving: new FastAPI endpoint `GET /api/v1/tiles/{filename}`
  honoring `Range` + returning `206 Partial Content` per PMTiles
  client expectations
- Auth: same `session_viewer_plus` gate as the rest of `/api/v1/*`
  (tiles themselves are non-sensitive but the baseline posture is
  "everything authenticated")

## Why

**Privacy (load-bearing).** Every tile request encodes
`/{z}/{x}/{y}.{ext}` in its URL — i.e., the exact geographic
coordinates a tile shows. A passive observer at any external tile CDN
(CartoDB, Mapbox, Stadia, etc.) can reconstruct **the list of
customer buoy locations** for any operator session. That's exactly
the kind of data-shape leak `docs/NON-NEGOTIABLES.md` rule 6
(tenant isolation) and rule 4 (audit-ready posture) rule out.

Self-hosting closes the leak: tile requests stay inside the bundle's
trust boundary (OCTO → Athena Console, same machine or same private
network).

**MapLibre over Leaflet.** WebGL vector rendering, silky pan/zoom
across 20+ zoom levels including street level, native `pmtiles://`
protocol support via the 4 KB `pmtiles` npm client, no external
dependencies once tiles are local. The radar overlay stays SVG +
`map.project(lngLat)` — identical positioning model to the Leaflet
mock, so the kit's overlay code ports unchanged.

**PMTiles over a tile server.** One file, no PostGIS, no
`tileserver-gl` process to operate. Range-request reads are cheap;
the FastAPI endpoint is a 100-line static-file handler. Regenerating
tiles is a periodic offline batch (monthly cadence is fine — coast
lines move slowly).

## Consequences

### Positive

- Customer buoy locations never leave the trust boundary in tile-URL
  metadata
- No third-party API key to vault, rotate, or audit
- Map view works offline once tiles are deployed
- Bundle ships portable — drop a `.pmtiles` next to the OCTO Docker
  image and the map "just works"

### Negative

- **Disk footprint.** Planet `.pmtiles` at zoom 0-14 is ~50 GB; a
  US-region extract is ~600 MB; regional MSPs can ship smaller
  extracts. Per the basemap handoff, US-only first, then regions on
  demand.
- **Build complexity.** Tile builds are an offline batch step.
  Acceptable cadence: monthly. An operator-facing fetch script
  (`scripts/fetch_dev_tiles.sh`) pulls a known-recent Protomaps build
  for dev; production builds use `planetiler` against a fresh OSM
  dump.
- **Bundle size.** `maplibre-gl` is ~1 MB minified. Bumped the
  production JS bundle from 632 KB → 1.7 MB (gz: 172 KB → 473 KB).
  Mitigation: lazy-load via `React.lazy` so the map only loads when
  the Fleet → map view is opened. (Followup; not in this slice.)
- **Supply-chain risk.** Two new npm deps (`maplibre-gl`, `pmtiles`).
  Both are widely used, open-source, actively maintained. `npm audit`
  reports 8 moderate-severity transitive vulnerabilities at install
  time — typical for the MapLibre dep tree; track upstream advisories.

## Implementation surface (today)

- `apps/octo/api/routers/tiles.py` — `GET /api/v1/tiles/{filename}`
  endpoint with range-request support, filename validation, symlink
  refusal, scope-rooted via `paths.tiles_dir()`. Auth: viewer+.
- `apps/octo/paths.py::tiles_dir()` — `OCTO_DATA_ROOT/tiles/`
- `apps/athena/web/src/components/fleet-map-view.tsx` — MapLibre
  Map mount + overlay placement + graceful degradation on tile-load
  failure
- `apps/athena/web/src/components/fleet-map-overlay.tsx` — SVG layer
  (radar + heartbeat + signal trace), unchanged from the prior commit
- `apps/athena/web/src/pages/fleet.tsx` — cards/map view toggle,
  persisted per-operator in `localStorage`
- `scripts/fetch_dev_tiles.sh` — pulls a Protomaps US-region build
  into `OCTO_DATA_ROOT/tiles/us.pmtiles` for local dev

## What's deferred

- **Production tile build pipeline.** `planetiler` + cron + a way
  to publish the tile file to bundle deploys. Out of scope today;
  operators stage tiles manually via `scripts/fetch_dev_tiles.sh`
  or their own build.
- **Multi-region tile bundling.** When the first non-US MSP onboards,
  add per-region builds + region selection.
- **Lazy-load `maplibre-gl`** to shrink the default bundle.
- **Richer MapLibre style** — the v1 style is a flat dark background
  + the PMTiles vector source. Per-feature paint specs (water, roads,
  labels) come with the first real `.pmtiles` operator deploy.
- **Buoy heartbeat lat/lng contract.** Map view filters out buoys
  with missing coords today. Heartbeat services contract extension
  (separate slice) ships `lat`/`lng`/`dns_today_blocked`/`last_action`.

## Related

- Fleet redesign + basemap design hand-offs
  (2026-05-19; kept outside the repo)
- `docs/NON-NEGOTIABLES.md` — rules 4 + 6
