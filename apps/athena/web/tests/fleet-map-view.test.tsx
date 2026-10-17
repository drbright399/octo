/**
 * Tests for components/fleet-map-view.tsx.
 *
 * MapLibre is mocked (see tests/setup.ts) so we exercise the wiring
 * around it: missing-coords banner, the basemap-unavailable hint when
 * the map errors out, and that buoys without finite lat/lng don't reach
 * the overlay.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import * as maplibregl from "maplibre-gl";

import FleetMapView from "@/components/fleet-map-view";
import type { BuoyMarker, OctoNode } from "@/components/fleet-map-overlay";


afterEach(cleanup);


const OCTO: OctoNode = {
  slug: "example-hub",
  display: "Example Hub",
  city: "Demo City",
  msp: "Demo MSP",
  lat: 39.1,
  lng: -94.6,
};

const WITH_COORDS: BuoyMarker = {
  slug: "alpha",
  hostname: "buoy-alpha",
  lat: 40.0,
  lng: -95.0,
  health: "green",
  octo: "example-hub",
};

const NO_COORDS: BuoyMarker = {
  slug: "bravo",
  hostname: "buoy-bravo",
  lat: Number.NaN,
  lng: Number.NaN,
  health: "yellow",
  octo: "example-hub",
};


describe("FleetMapView", () => {
  it("mounts without crashing with mocked MapLibre", () => {
    const { container } = render(
      <FleetMapView octos={[OCTO]} buoys={[WITH_COORDS]} />,
    );
    // Container div should exist.
    expect(container.querySelector("div")).not.toBeNull();
  });

  it("renders the 'geo data missing' banner when a buoy has no lat/lng", () => {
    render(<FleetMapView octos={[OCTO]} buoys={[NO_COORDS]} />);
    expect(screen.getByText(/geo data missing/i)).toBeTruthy();
    // Banner counts the missing buoys.
    expect(screen.getByText(/1 of 1 buoy/i)).toBeTruthy();
  });

  it("suppresses the banner when every buoy has finite coords", () => {
    render(<FleetMapView octos={[OCTO]} buoys={[WITH_COORDS]} />);
    expect(screen.queryByText(/geo data missing/i)).toBeNull();
  });

  it("points MapLibre (v6) at the bundled same-origin worker before the first map", () => {
    // v6 derives its worker URL from `import.meta.url`, which bundling
    // breaks: without setWorkerUrl the production basemap never loads.
    render(<FleetMapView octos={[OCTO]} buoys={[WITH_COORDS]} />);
    const setWorkerUrl = vi.mocked(maplibregl.setWorkerUrl);
    const MapCtor = vi.mocked(maplibregl.Map);
    expect(setWorkerUrl).toHaveBeenCalledTimes(1); // once per page lifetime
    expect(setWorkerUrl).toHaveBeenCalledWith(expect.stringContaining("maplibre-gl-worker"));
    expect(MapCtor).toHaveBeenCalled();
    expect(setWorkerUrl.mock.invocationCallOrder[0]!)
      .toBeLessThan(MapCtor.mock.invocationCallOrder[0]!);
  });

  it("passes only buoys with finite coords through to the overlay", () => {
    // We can't easily inspect overlay internals (FleetMapOverlay is its
    // own component) but we CAN assert the banner reports the missing
    // count, which is the filter's external contract.
    render(<FleetMapView octos={[OCTO]} buoys={[WITH_COORDS, NO_COORDS]} />);
    expect(screen.getByText(/1 of 2 buoys/i)).toBeTruthy();
  });
});


describe("FleetMapView basemap palette follows Appearance → Background", () => {
  const root = document.documentElement;
  afterEach(() => {
    cleanup(); // unmount first — the component observes these attributes
    root.removeAttribute("data-scheme");
    root.removeAttribute("data-theme");
  });

  /** background-color of the style the real component handed to MapLibre. */
  const mountedBackground = (): string => {
    const calls = vi.mocked(maplibregl.Map).mock.calls;
    const opts = calls[calls.length - 1]?.[0] as unknown as {
      style: { layers: Array<{ paint: Record<string, string> }> };
    };
    return opts.style.layers[0]?.paint["background-color"] ?? "";
  };

  it.each([
    ["no attribute (default scheme)", null, "#0a0414"],
    ["graphite", "graphite", "#0c0c0c"],
    ["ultra-black", "ultra-black", "#000000"],
    ["an unknown value (enum-only → default)", "#ff00ff", "#0a0414"],
  ])("dark + %s", (_label, scheme, expected) => {
    root.setAttribute("data-theme", "dark");
    if (scheme) root.setAttribute("data-scheme", scheme);
    render(<FleetMapView octos={[OCTO]} buoys={[WITH_COORDS]} />);
    expect(mountedBackground()).toBe(expected);
  });

  it("light theme ignores the stored scheme — schemes are dark-mode-only", () => {
    root.setAttribute("data-theme", "light");
    root.setAttribute("data-scheme", "ultra-black");
    render(<FleetMapView octos={[OCTO]} buoys={[WITH_COORDS]} />);
    expect(mountedBackground()).toBe("#f5f1ea");
  });
});
