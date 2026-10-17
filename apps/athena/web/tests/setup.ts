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

// MapLibre GL JS touches `URL.createObjectURL(new Blob(...))` at module
// init for its web-worker bootstrap, which jsdom doesn't support. We
// don't exercise MapLibre's runtime in unit tests (it needs WebGL +
// real DOM); the components that wrap it are tested via the SVG
// overlay's pure projection callback. Stub the whole module so
// transitive imports through pages/fleet.tsx don't blow up.
vi.mock("maplibre-gl", () => ({
  default: {
    Map: vi.fn(() => ({
      on: vi.fn(),
      off: vi.fn(),
      remove: vi.fn(),
      resize: vi.fn(),
      project: vi.fn(() => ({ x: 0, y: 0 })),
      fitBounds: vi.fn(),
      getCanvas: vi.fn(() => ({ clientWidth: 800, clientHeight: 600 })),
    })),
    addProtocol: vi.fn(),
  },
  Map: vi.fn(),
  addProtocol: vi.fn(),
}));

vi.mock("pmtiles", () => ({
  Protocol: vi.fn(() => ({
    tile: vi.fn(),
  })),
}));

// maplibre-gl ships a CSS import; vitest's transform pipeline blows up
// without a no-op handler. The empty stub keeps the import chain quiet.
vi.mock("maplibre-gl/dist/maplibre-gl.css", () => ({}));
