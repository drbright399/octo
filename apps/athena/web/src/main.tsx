import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { applyStoredAppearance } from "./lib/appearance";
import "./index.css";
// MapLibre's canvas styles MUST be in the main bundle (not the lazy
// fleet-map-view chunk). Reason: when fleet-map-view is lazy-imported,
// any CSS imports inside it land in a sibling lazy CSS chunk that
// loads in parallel with the JS — MapLibre instantiates BEFORE the
// CSS arrives and sizes the canvas at 0px because .maplibregl-canvas
// rules aren't applied yet. Eager-importing here avoids that race.
import "maplibre-gl/dist/maplibre-gl.css";

// Ensure the Nier motion attribute is set on <html> regardless of how
// index.html was served (Vite cache, prod static host, etc.). Future
// Theme v2 will read the operator's persisted preference and set this
// to "standard" / "nier" / "reduced".
document.documentElement.setAttribute("data-motion", "nier");

// Hydrate the operator's appearance (theme / accent / background scheme /
// corners / font) BEFORE React mounts so the first rendered frame — boot
// splash included — is already in their palette. The pre-paint boot
// script in index.html covers theme + scheme earlier still; this is the
// guaranteed path (enum-validated, legacy bundle ids alias-mapped).
applyStoredAppearance();

const container = document.getElementById("root");
if (!container) {
  throw new Error("root element missing in index.html");
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
