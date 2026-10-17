/**
 * Settings → Appearance.
 *
 * Per-operator theme controls. Four enum-only pickers backed by the
 * `data-bundle` / `data-scheme` / `data-corners` / `data-font` attributes
 * on <html> (CSS values live in index.css; this panel only flips
 * attributes). The enums, storage keys and read/apply helpers live in
 * `@/lib/appearance` — shared with the boot path in `main.tsx`.
 *
 * **Security rationale.**
 * The picker is enum-only by design. No hex input, no custom color
 * support. The 7 named palettes cover MSP brand spread; adding a new
 * one is a code change, not a runtime upload. This avoids:
 *   - severity-cue spoofing (red/amber overlap with critical/warn)
 *   - WCAG contrast violations
 *   - CSS-context injection sinks
 *   - brand impersonation
 * The background schemes follow the same rule: a curated enum, never a
 * free-form colour.
 *
 * Persistence: localStorage only for v1. Server-side per-operator
 * persistence is a follow-up (needs `operators.appearance_*` columns +
 * PATCH endpoint). Until then preferences are per-browser.
 */
import { useEffect, useState, type FC, type KeyboardEvent } from "react";

import {
  STORAGE,
  applyBundle,
  applyCorners,
  applyFont,
  applyScheme,
  persist,
  readBundlePreference,
  readSchemePreference,
  readStoredCorners,
  readStoredFont,
  type Bundle,
  type Corners,
  type Font,
  type Scheme,
} from "@/lib/appearance";

// Visual sample for each accent swatch. These are the same hex values
// declared in src/index.css under `:root[data-bundle="..."]` — kept in
// sync by hand. If you add a palette, update both this map and the CSS
// (tests/appearance-contrast.test.ts fails on drift).
const BUNDLES: ReadonlyArray<{
  id: Bundle;
  label: string;
  accent: string;
  description: string;
}> = [
  { id: "violet",   label: "Violet",      accent: "#a78bfa", description: "Athena default — neutral / MSP-androgynous" },
  { id: "midas",    label: "Midas Touch", accent: "#FFC600", description: "Warm gold — high-visibility" },
  { id: "indigo",   label: "Indigo",      accent: "#818cf8", description: "Cool deep — corporate" },
  { id: "cyan",     label: "Cyan",        accent: "#22d3ee", description: "Bright cool — net-ops feel" },
  { id: "sky",      label: "Sky",         accent: "#38bdf8", description: "Soft cool — readable" },
  { id: "rose",     label: "Rose",        accent: "#fb7185", description: "Warm — high-energy" },
  { id: "emerald",  label: "Emerald",     accent: "#34d399", description: "Earthy — calmer" },
];

// Background schemes (dark mode). `preview` mirrors that scheme's tokens
// in src/index.css — page = --bg-deep, card = --bg-card, border =
// --border-bright, text = --text-primary, dim = --text-dim — kept in sync
// by hand like BUNDLES above (same drift test). The accent bar in the
// swatch is NOT listed here: it reads the live `var(--accent)`, so the
// preview shows the scheme with the operator's current accent.
const SCHEMES: ReadonlyArray<{
  id: Scheme;
  label: string;
  description: string;
  preview: { page: string; card: string; border: string; text: string; dim: string };
}> = [
  {
    id: "twilight",
    label: "Twilight",
    description: "Athena default — violet-tinted surfaces",
    preview: { page: "#0a0414", card: "rgba(28, 18, 52, 0.88)", border: "rgba(167, 139, 250, 0.28)", text: "#ece9f5", dim: "#6b6589" },
  },
  {
    id: "graphite",
    label: "Graphite",
    description: "Neutral dark — true greys, no tint",
    preview: { page: "#0c0c0c", card: "rgba(25, 25, 25, 0.88)", border: "rgba(255, 255, 255, 0.22)", text: "#ededed", dim: "#8e8e8e" },
  },
  {
    id: "ultra-black",
    label: "Ultra-black",
    description: "OLED — true black page, near-black panels",
    preview: { page: "#000000", card: "rgba(17, 17, 17, 0.9)", border: "rgba(255, 255, 255, 0.26)", text: "#f2f2f2", dim: "#888888" },
  },
];

const CORNERS: ReadonlyArray<{ id: Corners; label: string; hint: string }> = [
  { id: "terminal", label: "Terminal", hint: "Sharp · 0–4px radii" },
  { id: "default",  label: "Default",  hint: "Balanced · 4–14px" },
  { id: "friendly", label: "Friendly", hint: "Rounded · 6–20px" },
];

const FONTS: ReadonlyArray<{ id: Font; label: string; hint: string }> = [
  { id: "inter",    label: "Inter",        hint: "Default — neutral geometric" },
  { id: "ibm-plex", label: "IBM Plex Sans", hint: "Engineered, slightly mechanical" },
  { id: "geist",    label: "Geist",        hint: "Vercel-shaped, crisp" },
  { id: "system",   label: "System",       hint: "Native to your OS" },
];

/** Live "is the light theme active?" — the toggle lives in the topbar, so
 * watch `<html data-theme>` rather than owning the state here. */
function useIsLightTheme(): boolean {
  const read = (): boolean => document.documentElement.getAttribute("data-theme") === "light";
  const [light, setLight] = useState<boolean>(read);
  useEffect(() => {
    const observer = new MutationObserver(() => setLight(read()));
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => observer.disconnect();
  }, []);
  return light;
}

/** Arrow-key navigation for a `role="radiogroup"` of buttons (WAI-ARIA
 * radio pattern: arrows move + select, Home/End jump, selection follows
 * focus). Paired with a roving tabindex on the buttons so Tab enters and
 * leaves the group in one stop. */
function onRadioKeyDown<T extends string>(
  e: KeyboardEvent<HTMLElement>,
  ids: readonly T[],
  current: T,
  onPick: (id: T) => void,
): void {
  const last = ids.length - 1;
  const at = Math.max(0, ids.indexOf(current));
  let next: number;
  switch (e.key) {
    case "ArrowRight":
    case "ArrowDown":
      next = at === last ? 0 : at + 1;
      break;
    case "ArrowLeft":
    case "ArrowUp":
      next = at === 0 ? last : at - 1;
      break;
    case "Home":
      next = 0;
      break;
    case "End":
      next = last;
      break;
    default:
      return;
  }
  e.preventDefault();
  const id = ids[next];
  if (id === undefined) return;
  onPick(id);
  // Move focus with the selection (the radios are direct children).
  const radios = e.currentTarget.querySelectorAll<HTMLElement>('[role="radio"]');
  radios[next]?.focus();
}

const AppearanceTab: FC = () => {
  const [bundle, setBundle] = useState<Bundle>(readBundlePreference);
  const [scheme, setScheme] = useState<Scheme>(readSchemePreference);
  const [corners, setCorners] = useState<Corners>(() => readStoredCorners() ?? "terminal");
  const [font, setFont] = useState<Font>(() => readStoredFont() ?? "inter");
  const isLight = useIsLightTheme();

  // On mount + every change, reflect into <html> and persist.
  useEffect(() => {
    applyBundle(bundle);
    persist(STORAGE.bundle, bundle);
  }, [bundle]);
  useEffect(() => {
    applyScheme(scheme);
    persist(STORAGE.scheme, scheme);
  }, [scheme]);
  useEffect(() => {
    applyCorners(corners);
    persist(STORAGE.corners, corners);
  }, [corners]);
  useEffect(() => {
    applyFont(font);
    persist(STORAGE.font, font);
  }, [font]);

  return (
    <section className="flex flex-col gap-6" aria-labelledby="appearance-title">
      <header className="flex flex-col gap-1">
        <h2 id="appearance-title" className="text-sm font-semibold text-text-primary">
          Appearance
        </h2>
        <p className="text-xs leading-relaxed text-text-secondary">
          Adjust accent, background, corner style, and font. Choices apply
          instantly and persist on this browser. Server-side per-operator
          sync is coming — for now your preferences are local.
        </p>
      </header>

      <PaletteSection
        title="Accent palette"
        helpText="Curated 7-palette set. Hex pickers aren't offered — see release notes for the security rationale."
        current={bundle}
        options={BUNDLES}
        onPick={setBundle}
      />

      <SchemeSection
        title="Background"
        current={scheme}
        options={SCHEMES}
        onPick={setScheme}
        disabled={isLight}
      />

      <EnumSection
        title="Corners"
        helpText="Border radius across the whole UI."
        current={corners}
        options={CORNERS}
        onPick={setCorners}
      />

      <EnumSection
        title="Font"
        helpText="Sans-serif family. Mono is fixed."
        current={font}
        options={FONTS}
        onPick={setFont}
      />

      <div className="rounded-sm border border-border bg-bg-card px-3 py-2 text-[11px] leading-relaxed text-text-dim">
        <span className="font-mono uppercase tracking-wider text-text-secondary">·· note ··</span>{" "}
        Custom hex colors are intentionally not supported. The curated
        palettes hit WCAG contrast targets and prevent accent from
        clashing with severity cues. To add a new palette, request a
        release.
      </div>
    </section>
  );
};

/* -------------------------------------------------------------------- */

const PaletteSection: FC<{
  title: string;
  helpText: string;
  current: Bundle;
  options: typeof BUNDLES;
  onPick: (b: Bundle) => void;
}> = ({ title, helpText, current, options, onPick }) => (
  <fieldset className="flex flex-col gap-2 rounded-sm border border-border bg-bg-surface p-4">
    <legend className="px-1 font-mono text-[10px] uppercase tracking-widest text-text-dim">
      {title}
    </legend>
    <p className="text-xs text-text-secondary">{helpText}</p>
    <div
      role="radiogroup"
      aria-label={title}
      className="mt-1 grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-4"
      onKeyDown={(e) => onRadioKeyDown(e, options.map((o) => o.id), current, onPick)}
    >
      {options.map((o) => {
        const active = o.id === current;
        return (
          <button
            key={o.id}
            type="button"
            role="radio"
            aria-checked={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onPick(o.id)}
            className={[
              "group flex items-center gap-2 rounded-sm border px-2 py-1.5 text-left text-[11px] transition-colors",
              active
                ? "border-accent bg-accent-soft text-text-primary"
                : "border-border bg-bg-card text-text-secondary hover:border-border-bright",
            ].join(" ")}
            title={o.description}
          >
            <span
              aria-hidden="true"
              className="inline-block h-3.5 w-3.5 shrink-0 rounded-sm border border-black/30"
              style={{ background: o.accent }}
            />
            <span className="flex flex-col leading-tight">
              <span className="font-mono">{o.label}</span>
              <span className="text-[10px] text-text-dim">{o.description}</span>
            </span>
          </button>
        );
      })}
    </div>
  </fieldset>
);

const SchemeSection: FC<{
  title: string;
  current: Scheme;
  options: typeof SCHEMES;
  onPick: (s: Scheme) => void;
  /** Light theme active — schemes only restyle dark mode, so the group is
   *  shown disabled with the reason spelled out (no dead controls). */
  disabled: boolean;
}> = ({ title, current, options, onPick, disabled }) => (
  <fieldset
    className="flex flex-col gap-2 rounded-sm border border-border bg-bg-surface p-4"
    disabled={disabled}
  >
    <legend className="px-1 font-mono text-[10px] uppercase tracking-widest text-text-dim">
      {title}
    </legend>
    <p className="text-xs text-text-secondary">
      Surface colours behind the accent — independent of the palette above.
      Curated set; every accent stays legible on every background.
    </p>
    {disabled && (
      <p role="note" className="rounded-sm border border-border bg-bg-card px-2 py-1.5 text-[11px] text-text-secondary">
        <span className="font-mono uppercase tracking-wider text-text-dim">dark mode only ·</span>{" "}
        Background schemes restyle the dark theme. Switch to dark with the
        theme toggle in the top bar to change this — your current choice
        is kept.
      </p>
    )}
    <div
      role="radiogroup"
      aria-label={title}
      aria-disabled={disabled}
      className={["mt-1 grid grid-cols-1 gap-2 sm:grid-cols-3", disabled ? "opacity-60" : ""].join(" ")}
      onKeyDown={(e) => onRadioKeyDown(e, options.map((o) => o.id), current, onPick)}
    >
      {options.map((o) => {
        const active = o.id === current;
        return (
          <button
            key={o.id}
            type="button"
            role="radio"
            aria-checked={active}
            tabIndex={active ? 0 : -1}
            disabled={disabled}
            onClick={() => onPick(o.id)}
            className={[
              "flex items-center gap-3 rounded-sm border px-2 py-2 text-left text-[11px] transition-colors disabled:cursor-not-allowed",
              active
                ? "border-accent bg-accent-soft text-text-primary"
                : "border-border bg-bg-card text-text-secondary enabled:hover:border-border-bright",
            ].join(" ")}
            title={o.description}
          >
            {/* Mini console: page → bordered card → text ramp + live accent. */}
            <span
              aria-hidden="true"
              data-testid={`scheme-swatch-${o.id}`}
              className="flex h-10 w-14 shrink-0 items-center justify-center rounded-sm border border-border-bright"
              style={{ background: o.preview.page }}
            >
              <span
                className="flex h-7 w-10 flex-col justify-center gap-1 rounded-sm border px-1"
                style={{ background: o.preview.card, borderColor: o.preview.border }}
              >
                <span className="block h-0.5 w-6 rounded-sm" style={{ background: o.preview.text }} />
                <span className="block h-0.5 w-4 rounded-sm" style={{ background: o.preview.dim }} />
                <span className="block h-0.5 w-3 rounded-sm bg-accent" />
              </span>
            </span>
            <span className="flex flex-col leading-tight">
              <span className="font-mono">{o.label}</span>
              <span className="text-[10px] text-text-dim">{o.description}</span>
            </span>
          </button>
        );
      })}
    </div>
  </fieldset>
);

const EnumSection = <T extends string>({
  title,
  helpText,
  current,
  options,
  onPick,
}: {
  title: string;
  helpText: string;
  current: T;
  options: ReadonlyArray<{ id: T; label: string; hint: string }>;
  onPick: (v: T) => void;
}) => (
  <fieldset className="flex flex-col gap-2 rounded-sm border border-border bg-bg-surface p-4">
    <legend className="px-1 font-mono text-[10px] uppercase tracking-widest text-text-dim">
      {title}
    </legend>
    <p className="text-xs text-text-secondary">{helpText}</p>
    <div
      role="radiogroup"
      aria-label={title}
      className="mt-1 flex flex-wrap gap-2"
      onKeyDown={(e) => onRadioKeyDown(e, options.map((o) => o.id), current, onPick)}
    >
      {options.map((o) => {
        const active = o.id === current;
        return (
          <button
            key={o.id}
            type="button"
            role="radio"
            aria-checked={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onPick(o.id)}
            className={[
              "flex flex-col items-start gap-0.5 rounded-sm border px-2.5 py-1.5 text-[11px] transition-colors",
              active
                ? "border-accent bg-accent-soft text-text-primary"
                : "border-border bg-bg-card text-text-secondary hover:border-border-bright",
            ].join(" ")}
          >
            <span className="font-mono">{o.label}</span>
            <span className="text-[10px] text-text-dim">{o.hint}</span>
          </button>
        );
      })}
    </div>
  </fieldset>
);

/** Option tables, exposed for the CSS-drift test only. */
export const __test__ = { BUNDLES, SCHEMES };

export default AppearanceTab;
