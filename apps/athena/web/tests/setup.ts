import "@testing-library/jest-dom/vitest";
import { vi } from "vitest";

// jsdom lacks ResizeObserver — components that observe their container
// element (e.g., FleetMapView) crash on mount without this polyfill.
if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = class {
    observe() { /* noop */ }
    unobserve() { /* noop */ }
    disconnect() { /* noop */ }
  } as unknown as typeof ResizeObserver;
}

// MapLibre GL JS needs WebGL, Web Workers and a real layout engine,
// none of which jsdom provides, so we don't exercise its runtime in
// unit tests; the components that wrap it are tested via the SVG
// overlay's pure projection callback. Stub the whole module so
// transitive imports through pages/fleet.tsx don't blow up.
//
// Shape mirrors maplibre-gl v6: ESM-only, named exports, NO default
// export (a stray `import maplibregl from "maplibre-gl"` fails loudly
// here instead of passing against a fake default). `Map` uses a
// `function` implementation, not an arrow: the component calls
// `new Map(...)` and Vitest 4 invokes a mock's implementation as a
// constructor (an arrow function there throws "is not a constructor").
vi.mock("maplibre-gl", () => ({
  Map: vi.fn(function MockMap() {
    return {
      on: vi.fn(),
      off: vi.fn(),
      remove: vi.fn(),
      resize: vi.fn(),
      project: vi.fn(() => ({ x: 0, y: 0 })),
      fitBounds: vi.fn(),
      getCanvas: vi.fn(() => ({ clientWidth: 800, clientHeight: 600 })),
    };
  }),
  addProtocol: vi.fn(),
  setWorkerUrl: vi.fn(),
}));

// `function` implementation for the same reason as `Map` above: the
// component calls `new Protocol()`.
vi.mock("pmtiles", () => ({
  Protocol: vi.fn(function MockProtocol() {
    return { tile: vi.fn() };
  }),
}));

// maplibre-gl ships a CSS import; vitest's transform pipeline blows up
// without a no-op handler. The empty stub keeps the import chain quiet.
vi.mock("maplibre-gl/dist/maplibre-gl.css", () => ({}));
