/**
 * Token-level checks for the Appearance system. Parses the REAL
 * src/index.css (no copies of the values in this file) and asserts:
 *
 *   - the CSS bundle / scheme selectors are exactly the curated enums
 *     (a lingering legacy selector or a missing block fails here);
 *   - the picker's hand-synced swatch values match the CSS;
 *   - both non-default background schemes are truly neutral, keep
 *     borders + elevation distinguishable, and hold WCAG AA (4.5:1) for
 *     the text ramp and for EVERY accent bundle on EVERY surface.
 *
 * Surfaces are translucent (the network mesh canvas shows through), so
 * each one is composited over both ends of that scheme's canvas
 * gradient and the worse result is what gets asserted.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { BUNDLE_IDS, DEFAULT_BUNDLE, DEFAULT_SCHEME, SCHEME_IDS } from "@/lib/appearance";
import { __test__ as picker } from "@/pages/settings/appearance";

// (Not `new URL("…css", import.meta.url)` — Vite rewrites that into an asset URL.)
const HERE = dirname(fileURLToPath(import.meta.url));
const CSS = readFileSync(join(HERE, "..", "src", "index.css"), "utf8");

type Rgb = readonly [number, number, number];
interface Rgba { rgb: Rgb; a: number }

/** `--name: value;` pairs of the first rule whose selector list is `selector`. */
function tokensOf(selector: string): Record<string, string> {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const rule = new RegExp(`(?:^|\\n)${escaped}\\s*\\{([^}]*)\\}`).exec(CSS);
  if (!rule) throw new Error(`selector not found in index.css: ${selector}`);
  const body = rule[1] as string;
  const out: Record<string, string> = {};
  for (const m of body.replace(/\/\*[\s\S]*?\*\//g, "").matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) {
    out[m[1] as string] = (m[2] as string).trim();
  }
  return out;
}

function parseColor(raw: string): Rgba {
  const hex = /^#([0-9a-f]{6})$/i.exec(raw);
  if (hex) {
    const h = hex[1] as string;
    return { rgb: [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16)) as unknown as Rgb, a: 1 };
  }
  const fn = /^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*([\d.]+)\s*)?\)$/i.exec(raw);
  if (fn) return { rgb: [Number(fn[1]), Number(fn[2]), Number(fn[3])], a: fn[4] === undefined ? 1 : Number(fn[4]) };
  throw new Error(`unparseable colour: ${raw}`);
}

const over = (fg: Rgba, bg: Rgb): Rgb =>
  [0, 1, 2].map((i) => (fg.rgb[i] as number) * fg.a + (bg[i] as number) * (1 - fg.a)) as unknown as Rgb;

function luminance(c: Rgb): number {
  const [r, g, b] = c.map((v) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: Rgb, b: Rgb): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

const schemeSelector = (id: string): string => `:root[data-scheme="${id}"]:not([data-theme="light"])`;
const BASE = tokensOf(':root,\n:root[data-theme="dark"]');
const tok = (t: Record<string, string>, name: string): string => {
  const v = t[name];
  if (v === undefined) throw new Error(`token ${name} missing`);
  return v;
};

// accent + accent-soft per bundle, straight from the CSS.
const ACCENTS = BUNDLE_IDS.map((id) => {
  const t = id === DEFAULT_BUNDLE ? BASE : tokensOf(`:root[data-bundle="${id}"]`);
  return { id, accent: parseColor(tok(t, "--accent")), soft: parseColor(tok(t, "--accent-soft")) };
});

const SURFACES = ["--bg-input", "--bg-surface", "--bg-card", "--bg-elevated", "--bg-card-hover"] as const;
const NEUTRAL_SCHEMES = SCHEME_IDS.filter((s) => s !== DEFAULT_SCHEME);

/** Every painted backdrop of a scheme: the page itself + each surface,
 * composited over both gradient ends. */
function backdrops(t: Record<string, string>): Array<{ name: string; rgb: Rgb }> {
  const out: Array<{ name: string; rgb: Rgb }> = [];
  for (const g of ["--bg-deep", "--bg-gradient-1", "--bg-gradient-2"]) {
    const page = parseColor(tok(t, g)).rgb;
    out.push({ name: g, rgb: page });
    for (const s of SURFACES) out.push({ name: `${s} over ${g}`, rgb: over(parseColor(tok(t, s)), page) });
  }
  return out;
}

describe("index.css ↔ curated enums", () => {
  it("has a bundle selector for exactly the curated non-default bundles", () => {
    const inCss = [...CSS.matchAll(/:root\[data-bundle="([^"]+)"\]/g)].map((m) => m[1]);
    expect([...new Set(inCss)].sort()).toEqual(BUNDLE_IDS.filter((b) => b !== DEFAULT_BUNDLE).sort());
  });

  it("has a scheme selector for exactly the curated non-default schemes, all dark-only", () => {
    const inCss = [...CSS.matchAll(/:root\[data-scheme="([^"]+)"\]([^\s{,]*)/g)];
    expect([...new Set(inCss.map((m) => m[1]))].sort()).toEqual([...NEUTRAL_SCHEMES].sort());
    // Each one carries the light-mode guard — a stored scheme is inert in light.
    for (const m of inCss) expect(m[2]).toBe(':not([data-theme="light"])');
  });

  it("picker accent swatches match the CSS --accent of their bundle", () => {
    expect(picker.BUNDLES.map((b) => b.id)).toEqual([...BUNDLE_IDS]);
    for (const b of picker.BUNDLES) {
      const css = ACCENTS.find((a) => a.id === b.id);
      expect(parseColor(b.accent), b.id).toEqual(css?.accent);
    }
  });

  it("picker scheme previews match the CSS tokens of their scheme", () => {
    expect(picker.SCHEMES.map((s) => s.id)).toEqual([...SCHEME_IDS]);
    for (const s of picker.SCHEMES) {
      const t = s.id === DEFAULT_SCHEME ? BASE : tokensOf(schemeSelector(s.id));
      expect(parseColor(s.preview.page), `${s.id} page`).toEqual(parseColor(tok(t, "--bg-deep")));
      expect(parseColor(s.preview.card), `${s.id} card`).toEqual(parseColor(tok(t, "--bg-card")));
      expect(parseColor(s.preview.border), `${s.id} border`).toEqual(parseColor(tok(t, "--border-bright")));
      expect(parseColor(s.preview.text), `${s.id} text`).toEqual(parseColor(tok(t, "--text-primary")));
      expect(parseColor(s.preview.dim), `${s.id} dim`).toEqual(parseColor(tok(t, "--text-dim")));
    }
  });
});

describe.each(NEUTRAL_SCHEMES)("background scheme %s", (id) => {
  const t = tokensOf(schemeSelector(id));

  it("never overrides the curated accent or severity tokens", () => {
    const forbidden = Object.keys(t).filter((k) =>
      /^--(accent|critical|high|medium|low|info|success)/.test(k));
    expect(forbidden).toEqual([]);
  });

  it("is truly neutral — every colour it defines has r = g = b", () => {
    for (const [name, raw] of Object.entries(t)) {
      if (name === "--scrim-rgb") {
        expect(new Set(raw.split(",").map((p) => p.trim())).size, name).toBe(1);
        continue;
      }
      const [r, g, b] = parseColor(raw).rgb;
      expect(r === g && g === b, `${name}: ${raw}`).toBe(true);
    }
  });

  it("keeps the text ramp at WCAG AA or better on every surface", () => {
    for (const bd of backdrops(t)) {
      expect(contrast(parseColor(tok(t, "--text-primary")).rgb, bd.rgb), `primary on ${bd.name}`).toBeGreaterThanOrEqual(7);
      expect(contrast(parseColor(tok(t, "--text-secondary")).rgb, bd.rgb), `secondary on ${bd.name}`).toBeGreaterThanOrEqual(4.5);
      expect(contrast(parseColor(tok(t, "--text-dim")).rgb, bd.rgb), `dim on ${bd.name}`).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("keeps EVERY accent bundle at WCAG AA on every surface, incl. its own soft fill", () => {
    for (const bd of backdrops(t)) {
      for (const a of ACCENTS) {
        expect(contrast(a.accent.rgb, bd.rgb), `${a.id} on ${bd.name}`).toBeGreaterThanOrEqual(4.5);
        // Selected rows / active chips: accent text on accent-soft over the surface.
        expect(contrast(a.accent.rgb, over(a.soft, bd.rgb)), `${a.id} on soft/${bd.name}`).toBeGreaterThanOrEqual(4.5);
      }
    }
  });

  it("keeps text legible ON the accent (selected toggles, hover sweep)", () => {
    const ink = parseColor(tok(t, "--text-on-accent")).rgb;
    for (const a of ACCENTS) expect(contrast(ink, a.accent.rgb), a.id).toBeGreaterThanOrEqual(4.5);
  });

  it("keeps borders at least as visible as the default scheme's", () => {
    const edge = (tokens: Record<string, string>, border: string): number => {
      const page = parseColor(tok(tokens, "--bg-deep")).rgb;
      return Math.min(...SURFACES.map((s) => {
        const surface = over(parseColor(tok(tokens, s)), page);
        return contrast(over(parseColor(tok(tokens, border)), surface), surface);
      }));
    };
    expect(edge(t, "--border")).toBeGreaterThanOrEqual(edge(BASE, "--border"));
    expect(edge(t, "--border-bright")).toBeGreaterThanOrEqual(edge(BASE, "--border-bright"));
  });

  it("keeps the elevation ladder strictly ascending (page < input < surface < card < elevated < hover)", () => {
    const page = parseColor(tok(t, "--bg-deep")).rgb;
    const ladder = [page, ...SURFACES.map((s) => over(parseColor(tok(t, s)), page))].map(luminance);
    for (let i = 1; i < ladder.length; i++) {
      expect(ladder[i] as number, `step ${i}`).toBeGreaterThan(ladder[i - 1] as number);
    }
  });
});

describe("ultra-black", () => {
  it("paints a true #000 page, flat (no gradient lifting it off black)", () => {
    const t = tokensOf(schemeSelector("ultra-black"));
    for (const name of ["--bg-deep", "--bg-gradient-1", "--bg-gradient-2"]) {
      expect(parseColor(tok(t, name)).rgb, name).toEqual([0, 0, 0]);
    }
  });
});
