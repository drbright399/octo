/**
 * Tests for components/fleet-map-overlay.tsx — the SVG layer that mounts
 * on top of the (future) MapLibre basemap.
 *
 * Covers:
 *   - signalPath / azimuth helpers (pure math)
 *   - Empty-state render (no octos, no buoys, zero size)
 *   - Single OCTO + buoy renders hub + radar + signal trace + marker
 *   - Red buoys get the ambient-urgent wrapper and skip the signal trace
 *   - project() returning null skips the affected point
 *   - Click handler fires on buoy click
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, fireEvent, cleanup } from "@testing-library/react";

import FleetMapOverlay, {
  RADAR_PERIOD,
  __test__,
  type BuoyMarker,
  type OctoNode,
  type ProjectFn,
} from "@/components/fleet-map-overlay";


afterEach(cleanup);


// ---------------------------------------------------------------------------
// Helper math
// ---------------------------------------------------------------------------

describe("signalPath", () => {
  it("starts with M and emits 61 path commands (1 M + 60 L)", () => {
    const path = __test__.signalPath({ x: 0, y: 0 }, { x: 100, y: 0 }, 0);
    expect(path.startsWith("M")).toBe(true);
    // Format is "M{x} {y} L{x} {y} L{x} {y}…" — count tokens that BEGIN
    // with an M or L command letter.
    const tokens = path.split(" ").filter((t) => /^[ML]/.test(t));
    expect(tokens).toHaveLength(61);
  });

  it("emits exactly one M (start) and 60 L (segments)", () => {
    const path = __test__.signalPath({ x: 0, y: 0 }, { x: 100, y: 0 }, 0);
    const mCount = (path.match(/(^|\s)M[\d.-]/g) ?? []).length;
    const lCount = (path.match(/(^|\s)L[\d.-]/g) ?? []).length;
    expect(mCount).toBe(1);
    expect(lCount).toBe(60);
  });

  it("varies output across wavePhase values (animated trace)", () => {
    const a = __test__.signalPath({ x: 0, y: 0 }, { x: 100, y: 0 }, 0);
    const b = __test__.signalPath({ x: 0, y: 0 }, { x: 100, y: 0 }, 0.5);
    expect(a).not.toEqual(b);
  });

  it("amplitudeMul=0.22 produces a tighter trace than amplitudeMul=1", () => {
    const wide  = __test__.signalPath({ x: 0, y: 0 }, { x: 100, y: 0 }, 0.25, 1);
    const inner = __test__.signalPath({ x: 0, y: 0 }, { x: 100, y: 0 }, 0.25, 0.22);
    // Same point count, different coordinates.
    expect(wide.split(" ").length).toEqual(inner.split(" ").length);
    expect(wide).not.toEqual(inner);
  });
});

describe("azimuth", () => {
  it("returns 0° for due-east", () => {
    expect(__test__.azimuth({ x: 0, y: 0 }, { x: 10, y: 0 })).toBeCloseTo(0, 5);
  });
  it("returns 90° for due-south (SVG y-down)", () => {
    expect(__test__.azimuth({ x: 0, y: 0 }, { x: 0, y: 10 })).toBeCloseTo(90, 5);
  });
  it("returns 180° for due-west", () => {
    expect(__test__.azimuth({ x: 0, y: 0 }, { x: -10, y: 0 })).toBeCloseTo(180, 5);
  });
  it("returns 270° for due-north (SVG y-down)", () => {
    expect(__test__.azimuth({ x: 0, y: 0 }, { x: 0, y: -10 })).toBeCloseTo(270, 5);
  });
});

describe("RADAR_PERIOD constant", () => {
  it("matches the kit spec (10s per revolution)", () => {
    expect(RADAR_PERIOD).toBe(10);
  });
});


// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const OCTO: OctoNode = {
  slug: "example-hub",
  display: "Example Hub",
  city: "Demo City",
  msp: "Demo MSP",
  lat: 39.1,
  lng: -94.6,
};

const GREEN_BUOY: BuoyMarker = {
  slug: "alpha",
  hostname: "buoy-alpha",
  city: "Site A",
  lat: 39.5,
  lng: -94.0,
  health: "green",
  octo: "example-hub",
};

const RED_BUOY: BuoyMarker = {
  slug: "bravo",
  hostname: "buoy-bravo",
  city: "Site B",
  lat: 40.0,
  lng: -93.5,
  health: "red",
  octo: "example-hub",
};

// Toy projection: lat → y descending from a base, lng → x scaled.
// Returns null for any point with lat > 41 (simulates off-screen).
const project: ProjectFn = (lat, lng) => {
  if (lat > 41) return null;
  return {
    x: (lng + 100) * 10,    // ~60 for -94 → maps roughly to canvas
    y: (45 - lat) * 10,
  };
};


// ---------------------------------------------------------------------------
// Render behavior
// ---------------------------------------------------------------------------

describe("FleetMapOverlay rendering", () => {
  it("renders nothing when containerSize is zero", () => {
    const { container } = render(
      <FleetMapOverlay
        containerSize={{ w: 0, h: 0 }}
        octos={[OCTO]}
        buoys={[GREEN_BUOY]}
        project={project}
      />,
    );
    expect(container.querySelector("svg")).toBeNull();
  });

  it("renders the hub hex + radar fan for one OCTO", () => {
    const { container } = render(
      <FleetMapOverlay
        containerSize={{ w: 800, h: 400 }}
        octos={[OCTO]}
        buoys={[]}
        project={project}
      />,
    );
    // Hub hex (polygon) + radar fan (a <g> with 24 rays).
    expect(container.querySelectorAll("polygon")).toHaveLength(1);
    const radarGroup = container.querySelector(".fleet-map-overlay__radar");
    expect(radarGroup).not.toBeNull();
    expect(radarGroup?.querySelectorAll("line")).toHaveLength(24);
  });

  it("renders the buoy marker + signal trace (3 stacked paths)", () => {
    const { container } = render(
      <FleetMapOverlay
        containerSize={{ w: 800, h: 400 }}
        octos={[OCTO]}
        buoys={[GREEN_BUOY]}
        project={project}
        motion="sweep"
      />,
    );
    const buoy = container.querySelector('[data-health="green"]');
    expect(buoy).not.toBeNull();
    const signals = container.querySelector(".fleet-map-overlay__signals");
    expect(signals).not.toBeNull();
    // Three stacked stroke layers per non-red buoy.
    expect(signals?.querySelectorAll("path")).toHaveLength(3);
  });

  it("skips the signal trace for red buoys (per design — they're not transmitting)", () => {
    const { container } = render(
      <FleetMapOverlay
        containerSize={{ w: 800, h: 400 }}
        octos={[OCTO]}
        buoys={[RED_BUOY]}
        project={project}
        motion="sweep"
      />,
    );
    // Red buoy marker is present
    expect(container.querySelector('[data-health="red"]')).not.toBeNull();
    // No path inside the signals group.
    const signals = container.querySelector(".fleet-map-overlay__signals");
    expect(signals?.querySelectorAll("path") ?? []).toHaveLength(0);
  });

  it("motion='off' suppresses both radar fan and signal traces", () => {
    const { container } = render(
      <FleetMapOverlay
        containerSize={{ w: 800, h: 400 }}
        octos={[OCTO]}
        buoys={[GREEN_BUOY]}
        project={project}
        motion="off"
      />,
    );
    expect(container.querySelector(".fleet-map-overlay__radar")).toBeNull();
    expect(container.querySelector(".fleet-map-overlay__signals")).toBeNull();
    // But the hub + buoy markers still render.
    expect(container.querySelector("polygon")).not.toBeNull();
    expect(container.querySelector('[data-health="green"]')).not.toBeNull();
  });

  it("skips points whose project() returns null", () => {
    // Place buoy at lat=42 — toy projection returns null for >41
    const offscreen: BuoyMarker = { ...GREEN_BUOY, lat: 42, slug: "offscreen" };
    const { container } = render(
      <FleetMapOverlay
        containerSize={{ w: 800, h: 400 }}
        octos={[OCTO]}
        buoys={[GREEN_BUOY, offscreen]}
        project={project}
      />,
    );
    const buoys = container.querySelectorAll('.fleet-map-overlay__buoy');
    expect(buoys).toHaveLength(1);
  });

  it("fires onBuoyClick with the original BuoyMarker on click", () => {
    const onBuoyClick = vi.fn();
    const { container } = render(
      <FleetMapOverlay
        containerSize={{ w: 800, h: 400 }}
        octos={[OCTO]}
        buoys={[GREEN_BUOY]}
        project={project}
        onBuoyClick={onBuoyClick}
      />,
    );
    const buoy = container.querySelector('[data-health="green"]');
    expect(buoy).not.toBeNull();
    fireEvent.click(buoy!);
    expect(onBuoyClick).toHaveBeenCalledTimes(1);
    expect(onBuoyClick).toHaveBeenCalledWith(GREEN_BUOY);
  });

  it("renders the slug label by default and suppresses it when showLabels=false", () => {
    const { container, rerender } = render(
      <FleetMapOverlay
        containerSize={{ w: 800, h: 400 }}
        octos={[OCTO]}
        buoys={[GREEN_BUOY]}
        project={project}
      />,
    );
    expect(container.textContent ?? "").toContain("alpha");

    rerender(
      <FleetMapOverlay
        containerSize={{ w: 800, h: 400 }}
        octos={[OCTO]}
        buoys={[GREEN_BUOY]}
        project={project}
        showLabels={false}
      />,
    );
    // Slug label is gone (the buoy is still there via data-health).
    const labelTexts = Array.from(container.querySelectorAll(".fleet-map-overlay__label-text"));
    expect(labelTexts).toHaveLength(0);
  });

  it("draws a selection ring when selectedSlug matches a buoy", () => {
    const { container, rerender } = render(
      <FleetMapOverlay
        containerSize={{ w: 800, h: 400 }}
        octos={[OCTO]}
        buoys={[GREEN_BUOY]}
        project={project}
      />,
    );
    const buoyGroup = container.querySelector('[data-health="green"]');
    // No selection ring before
    expect(buoyGroup?.querySelector("circle[fill='none']")).toBeNull();

    rerender(
      <FleetMapOverlay
        containerSize={{ w: 800, h: 400 }}
        octos={[OCTO]}
        buoys={[GREEN_BUOY]}
        project={project}
        selectedSlug="alpha"
      />,
    );
    const after = container.querySelector('[data-health="green"]');
    // Selection ring is the first <circle fill="none"> within the buoy group.
    expect(after?.querySelector("circle[fill='none']")).not.toBeNull();
  });
});


// ---------------------------------------------------------------------------
// spreadOverlappingBuoys — collision-aware screen-space cluster spread
// ---------------------------------------------------------------------------

describe("spreadOverlappingBuoys", () => {
  type B = { slug: string; xy: { x: number; y: number }; hub: null; az: number; marker: unknown };
  const b = (slug: string, x: number, y: number): B => ({
    slug, xy: { x, y }, hub: null, az: 0, marker: { slug } as unknown,
  });

  it("no-ops a single buoy", () => {
    const arr = [b("alpha", 100, 100)];
    __test__.spreadOverlappingBuoys(arr as never);
    expect(arr[0]!.xy).toEqual({ x: 100, y: 100 });
  });

  it("no-ops two distant buoys", () => {
    const arr = [b("alpha", 100, 100), b("beta", 500, 500)];
    const before = arr.map((p) => ({ ...p.xy }));
    __test__.spreadOverlappingBuoys(arr as never);
    expect(arr[0]!.xy).toEqual(before[0]);
    expect(arr[1]!.xy).toEqual(before[1]);
  });

  it("spreads two coincident buoys to opposite sides of centroid", () => {
    const arr = [b("alpha", 200, 200), b("beta", 200, 200)];
    __test__.spreadOverlappingBuoys(arr as never);
    // Two members placed at angles -π/2 (top) and π/2 (bottom).
    expect(arr[0]!.xy.x).toBeCloseTo(200, 5);
    expect(arr[0]!.xy.y).toBeCloseTo(200 - __test__.SPREAD_RADIUS_PX, 5);
    expect(arr[1]!.xy.x).toBeCloseTo(200, 5);
    expect(arr[1]!.xy.y).toBeCloseTo(200 + __test__.SPREAD_RADIUS_PX, 5);
  });

  it("spreads three coincident buoys evenly around a ring of radius SPREAD_RADIUS_PX", () => {
    const arr = [b("alpha", 300, 300), b("beta", 300, 300), b("gamma", 300, 300)];
    __test__.spreadOverlappingBuoys(arr as never);
    for (const m of arr) {
      const d = Math.hypot(m.xy.x - 300, m.xy.y - 300);
      expect(d).toBeCloseTo(__test__.SPREAD_RADIUS_PX, 5);
    }
    // Sorted-by-slug first member (alpha) sits at angle -π/2 (top).
    expect(arr[0]!.xy.x).toBeCloseTo(300, 5);
    expect(arr[0]!.xy.y).toBeCloseTo(300 - __test__.SPREAD_RADIUS_PX, 5);
  });

  it("orders cluster members by slug for stable visual identity across renders", () => {
    const a = [b("zebra", 300, 300), b("alpha", 300, 300), b("middle", 300, 300)];
    const c = [b("middle", 300, 300), b("alpha", 300, 300), b("zebra", 300, 300)];
    __test__.spreadOverlappingBuoys(a as never);
    __test__.spreadOverlappingBuoys(c as never);
    const byKey = (arr: B[]): Record<string, { x: number; y: number }> =>
      Object.fromEntries(arr.map((m) => [m.slug, m.xy]));
    expect(byKey(a)).toEqual(byKey(c));
  });

  it("does not spread members further apart than SPREAD_THRESHOLD_PX", () => {
    const sep = __test__.SPREAD_THRESHOLD_PX + 1;
    const arr = [b("alpha", 100, 100), b("beta", 100 + sep, 100)];
    __test__.spreadOverlappingBuoys(arr as never);
    expect(arr[0]!.xy).toEqual({ x: 100, y: 100 });
    expect(arr[1]!.xy).toEqual({ x: 100 + sep, y: 100 });
  });
});
