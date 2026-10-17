/**
 * Appearance preferences — the curated enums, their storage keys, and the
 * read / apply helpers shared by the boot path (`main.tsx`) and
 * Settings → Appearance.
 *
 * **Enum-only by design** (a curated palette, never a free colour).
 * Every value that reaches an `<html data-*>` attribute has been matched
 * against one of the `*_IDS` lists below; anything else — a stale id, a
 * hand-edited localStorage entry, a hex colour — resolves to `null` and
 * the CSS baseline applies. There is no free-form colour path.
 *
 * CSS values live in `src/index.css`; this module only flips attributes:
 *   data-bundle   accent palette          (default `violet`   = no attribute)
 *   data-scheme   dark background scheme  (default `twilight` = no attribute)
 *   data-corners  radius set
 *   data-font     sans/mono family pair
 *
 * Pre-paint: `public/assets/appearance-boot.js` sets `data-theme` +
 * `data-scheme` (the only two that change the first painted pixel — the
 * page background) from a render-blocking same-origin script. It is a
 * plain classic script because the production CSP is `script-src 'self'`
 * (inline scripts are refused) and module scripts are deferred past first
 * paint. `applyStoredAppearance()` then runs in `main.tsx` before React
 * mounts and applies everything, so the boot script is an optimisation,
 * never the only path. `tests/appearance.test.tsx` runs the real boot
 * script against these enums to catch drift.
 *
 * Persistence: localStorage only (UI preference, not a credential).
 */

export const STORAGE = {
  theme: "athena.theme",
  bundle: "athena.appearance.bundle",
  scheme: "athena.appearance.scheme",
  corners: "athena.appearance.corners",
  font: "athena.appearance.font",
} as const;

export const BUNDLE_IDS = ["violet", "midas", "indigo", "cyan", "sky", "rose", "emerald"] as const;
export const SCHEME_IDS = ["twilight", "graphite", "ultra-black"] as const;
export const CORNER_IDS = ["terminal", "default", "friendly"] as const;
export const FONT_IDS = ["inter", "ibm-plex", "geist", "system"] as const;

export type Bundle = (typeof BUNDLE_IDS)[number];
export type Scheme = (typeof SCHEME_IDS)[number];
export type Corners = (typeof CORNER_IDS)[number];
export type Font = (typeof FONT_IDS)[number];

export const DEFAULT_BUNDLE: Bundle = "violet";
export const DEFAULT_SCHEME: Scheme = "twilight";

// LEGACY ALIAS — the gold bundle was originally keyed by a company brand
// name. Browsers that stored the old id, and deployments that stamp it on
// `<html data-bundle>`, are mapped to the current id wherever the value is
// read. This map is the ONLY place the old id may appear in the frontend;
// do not reference it anywhere else.
const LEGACY_BUNDLE_ALIASES: Readonly<Record<string, Bundle>> = {
  "micro-it": "midas",
};

/** Match `raw` against a curated enum. Unknown / empty → null. */
export function resolveEnum<T extends string>(
  raw: string | null | undefined,
  allowed: readonly T[],
): T | null {
  return raw != null && (allowed as readonly string[]).includes(raw) ? (raw as T) : null;
}

/** Resolve a bundle id, mapping legacy aliases first. Unknown → null. */
export function resolveBundle(raw: string | null | undefined): Bundle | null {
  if (raw == null) return null;
  // Own-property check so "constructor" / "__proto__" can't resolve.
  const aliased = Object.prototype.hasOwnProperty.call(LEGACY_BUNDLE_ALIASES, raw)
    ? LEGACY_BUNDLE_ALIASES[raw]
    : raw;
  return resolveEnum(aliased, BUNDLE_IDS);
}

function readRaw(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null; // storage disabled / sandboxed
  }
}

export function persist(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* quota / disabled storage — preference is session-only */
  }
}

/** Operator's stored bundle (alias-mapped) → else a deploy-time
 * `<html data-bundle>` stamp (alias-mapped) → else the default. */
export function readBundlePreference(): Bundle {
  return (
    resolveBundle(readRaw(STORAGE.bundle)) ??
    resolveBundle(document.documentElement.getAttribute("data-bundle")) ??
    DEFAULT_BUNDLE
  );
}

export function readSchemePreference(): Scheme {
  return resolveEnum(readRaw(STORAGE.scheme), SCHEME_IDS) ?? DEFAULT_SCHEME;
}

export function readStoredCorners(): Corners | null {
  return resolveEnum(readRaw(STORAGE.corners), CORNER_IDS);
}

export function readStoredFont(): Font | null {
  return resolveEnum(readRaw(STORAGE.font), FONT_IDS);
}

function setOrRemove(attr: string, value: string | null): void {
  if (value === null) document.documentElement.removeAttribute(attr);
  else document.documentElement.setAttribute(attr, value);
}

/** The default bundle means NO attribute — the bare `:root` block in
 * index.css supplies violet. Same convention for the default scheme. */
export function applyBundle(bundle: Bundle): void {
  setOrRemove("data-bundle", bundle === DEFAULT_BUNDLE ? null : bundle);
}

export function applyScheme(scheme: Scheme): void {
  setOrRemove("data-scheme", scheme === DEFAULT_SCHEME ? null : scheme);
}

export function applyCorners(corners: Corners): void {
  setOrRemove("data-corners", corners); // terminal IS a value, not removed
}

export function applyFont(font: Font): void {
  setOrRemove("data-font", font); // inter IS a value
}

/**
 * Hydrate `<html>` from stored preferences. Called once from `main.tsx`
 * BEFORE React mounts, so the first rendered frame (boot splash included)
 * already carries the operator's accent / scheme / corners / font.
 * Idempotent; never throws.
 */
export function applyStoredAppearance(): void {
  const theme = readRaw(STORAGE.theme);
  if (theme === "light" || theme === "dark") {
    document.documentElement.setAttribute("data-theme", theme);
  }

  const storedBundle = readRaw(STORAGE.bundle);
  const bundle = readBundlePreference();
  applyBundle(bundle);
  // One-way migration: a stored legacy alias is rewritten to the current
  // id so the old string ages out of operators' browsers.
  if (storedBundle !== null && storedBundle !== bundle && resolveBundle(storedBundle) === bundle) {
    persist(STORAGE.bundle, bundle);
  }

  applyScheme(readSchemePreference());

  // Corners / font: only stamp when the operator has chosen one — no
  // stored value leaves the `:root` baseline untouched.
  const corners = readStoredCorners();
  if (corners) applyCorners(corners);
  const font = readStoredFont();
  if (font) applyFont(font);
}
