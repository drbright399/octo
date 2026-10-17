/**
 * Appearance preferences — boot hydration, legacy-id aliasing, enum
 * rejection, the Background picker, and the pre-paint boot script.
 *
 * Nothing under test is stubbed: the real `@/lib/appearance`, the real
 * <AppearanceTab>, jsdom's real localStorage + <html>, and the real
 * `public/assets/appearance-boot.js` executed as the browser would.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import {
  BUNDLE_IDS,
  DEFAULT_SCHEME,
  SCHEME_IDS,
  STORAGE,
  applyStoredAppearance,
  resolveBundle,
} from "@/lib/appearance";
import AppearanceTab from "@/pages/settings/appearance";

// The id the gold bundle shipped under before it was renamed. Browsers in
// the field still hold it, so the regression tests need the literal —
// this constant is the only place it appears in the test suite.
const LEGACY_GOLD_ID = "micro-it";

const html = document.documentElement;
const APPEARANCE_ATTRS = ["data-theme", "data-bundle", "data-scheme", "data-corners", "data-font"];

const WEB_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const BOOT_SCRIPT = readFileSync(join(WEB_ROOT, "public", "assets", "appearance-boot.js"), "utf8");
const INDEX_HTML = readFileSync(join(WEB_ROOT, "index.html"), "utf8");

/** Run the real boot script the way a classic <script> would. */
const runBootScript = (): void => {
  new Function(BOOT_SCRIPT)();
};

beforeEach(() => {
  window.localStorage.clear();
  for (const a of APPEARANCE_ATTRS) html.removeAttribute(a);
  html.setAttribute("data-theme", "dark"); // index.html's markup default
});
afterEach(cleanup);

describe("legacy gold bundle id", () => {
  it("resolves to midas, and only real ids resolve at all", () => {
    expect(resolveBundle(LEGACY_GOLD_ID)).toBe("midas");
    expect(resolveBundle("midas")).toBe("midas");
    expect(BUNDLE_IDS).not.toContain(LEGACY_GOLD_ID);
  });

  it("stored in localStorage → midas on <html>, and storage is migrated", () => {
    window.localStorage.setItem(STORAGE.bundle, LEGACY_GOLD_ID);
    applyStoredAppearance();
    expect(html.getAttribute("data-bundle")).toBe("midas");
    expect(window.localStorage.getItem(STORAGE.bundle)).toBe("midas");
  });

  it("stamped on <html data-bundle> at deploy time → rewritten to midas", () => {
    html.setAttribute("data-bundle", LEGACY_GOLD_ID);
    applyStoredAppearance();
    expect(html.getAttribute("data-bundle")).toBe("midas");
    // A deploy stamp is not an operator choice — nothing is persisted for it.
    expect(window.localStorage.getItem(STORAGE.bundle)).toBeNull();
  });

  it("the operator's stored choice beats a deploy-time stamp", () => {
    html.setAttribute("data-bundle", LEGACY_GOLD_ID);
    window.localStorage.setItem(STORAGE.bundle, "cyan");
    applyStoredAppearance();
    expect(html.getAttribute("data-bundle")).toBe("cyan");
  });

  it("opens the picker on Midas Touch and never offers the old id", () => {
    window.localStorage.setItem(STORAGE.bundle, LEGACY_GOLD_ID);
    const { container } = render(<AppearanceTab />);
    const accents = screen.getByRole("radiogroup", { name: "Accent palette" });
    expect(within(accents).getByRole("radio", { name: /Midas Touch/ })).toHaveAttribute("aria-checked", "true");
    expect(within(accents).getAllByRole("radio")).toHaveLength(BUNDLE_IDS.length);
    expect(container.innerHTML.toLowerCase()).not.toContain(LEGACY_GOLD_ID);
    expect(html.getAttribute("data-bundle")).toBe("midas");
    expect(window.localStorage.getItem(STORAGE.bundle)).toBe("midas");
  });
});

describe("enum-only: unknown stored values are rejected", () => {
  it.each([
    ["a hex colour", "#ff0000"],
    ["a CSS payload", 'x"] body { display:none } [x="'],
    ["an Object.prototype key", "constructor"],
    ["__proto__", "__proto__"],
    ["wrong case", "MIDAS"],
    ["empty string", ""],
  ])("%s never reaches <html>", (_label, junk) => {
    for (const key of [STORAGE.bundle, STORAGE.scheme, STORAGE.corners, STORAGE.font]) {
      window.localStorage.setItem(key, junk);
    }
    window.localStorage.setItem(STORAGE.theme, junk);
    applyStoredAppearance();
    expect(html.getAttribute("data-theme")).toBe("dark");
    for (const a of ["data-bundle", "data-scheme", "data-corners", "data-font"]) {
      expect(html.hasAttribute(a), a).toBe(false);
    }
  });

  it("an unknown stored scheme opens the picker on the default, and is overwritten", () => {
    window.localStorage.setItem(STORAGE.scheme, "hot-pink");
    render(<AppearanceTab />);
    const group = screen.getByRole("radiogroup", { name: "Background" });
    expect(within(group).getByRole("radio", { name: /Twilight/ })).toHaveAttribute("aria-checked", "true");
    expect(html.hasAttribute("data-scheme")).toBe(false);
    expect(window.localStorage.getItem(STORAGE.scheme)).toBe(DEFAULT_SCHEME);
  });
});

describe("applyStoredAppearance (runs in main.tsx before React mounts)", () => {
  it("hydrates every stored preference onto <html>", () => {
    window.localStorage.setItem(STORAGE.theme, "light");
    window.localStorage.setItem(STORAGE.bundle, "emerald");
    window.localStorage.setItem(STORAGE.scheme, "graphite");
    window.localStorage.setItem(STORAGE.corners, "friendly");
    window.localStorage.setItem(STORAGE.font, "geist");
    applyStoredAppearance();
    expect(html.getAttribute("data-theme")).toBe("light");
    expect(html.getAttribute("data-bundle")).toBe("emerald");
    expect(html.getAttribute("data-scheme")).toBe("graphite");
    expect(html.getAttribute("data-corners")).toBe("friendly");
    expect(html.getAttribute("data-font")).toBe("geist");
  });

  it("changes nothing for an operator with no stored preferences", () => {
    applyStoredAppearance();
    expect(html.getAttribute("data-theme")).toBe("dark");
    for (const a of ["data-bundle", "data-scheme", "data-corners", "data-font"]) {
      expect(html.hasAttribute(a), a).toBe(false);
    }
    expect(window.localStorage.length).toBe(0);
  });
});

describe("Background picker", () => {
  it("renders the three curated schemes, default selected, each with a preview swatch", () => {
    render(<AppearanceTab />);
    const group = screen.getByRole("radiogroup", { name: "Background" });
    const radios = within(group).getAllByRole("radio");
    expect(radios.map((r) => r.textContent)).toEqual([
      expect.stringContaining("Twilight"),
      expect.stringContaining("Graphite"),
      expect.stringContaining("Ultra-black"),
    ]);
    expect(radios).toHaveLength(SCHEME_IDS.length);
    expect(radios[0]).toHaveAttribute("aria-checked", "true");
    for (const id of SCHEME_IDS) expect(screen.getByTestId(`scheme-swatch-${id}`)).toBeInTheDocument();
    // Enum-only: the panel offers no free-form input of any kind.
    expect(document.querySelectorAll("input, textarea, select")).toHaveLength(0);
  });

  it("picking a scheme sets data-scheme, persists it, and survives a remount", () => {
    const first = render(<AppearanceTab />);
    fireEvent.click(screen.getByRole("radio", { name: /Ultra-black/ }));
    expect(html.getAttribute("data-scheme")).toBe("ultra-black");
    expect(window.localStorage.getItem(STORAGE.scheme)).toBe("ultra-black");

    first.unmount();
    html.removeAttribute("data-scheme"); // simulate a fresh page load…
    applyStoredAppearance();             // …hydrated by the boot path
    expect(html.getAttribute("data-scheme")).toBe("ultra-black");
    render(<AppearanceTab />);
    expect(screen.getByRole("radio", { name: /Ultra-black/ })).toHaveAttribute("aria-checked", "true");
  });

  it("picking the default scheme removes the attribute (CSS baseline applies)", () => {
    window.localStorage.setItem(STORAGE.scheme, "graphite");
    render(<AppearanceTab />);
    expect(html.getAttribute("data-scheme")).toBe("graphite");
    fireEvent.click(screen.getByRole("radio", { name: /Twilight/ }));
    expect(html.hasAttribute("data-scheme")).toBe(false);
    expect(window.localStorage.getItem(STORAGE.scheme)).toBe("twilight");
  });

  it("leaves the accent alone — the two settings are independent", () => {
    window.localStorage.setItem(STORAGE.bundle, "rose");
    render(<AppearanceTab />);
    fireEvent.click(screen.getByRole("radio", { name: /Graphite/ }));
    expect(html.getAttribute("data-bundle")).toBe("rose");
    expect(html.getAttribute("data-scheme")).toBe("graphite");
  });

  it("is keyboard operable: one tab stop, arrows move + select, Home/End jump", () => {
    render(<AppearanceTab />);
    const group = screen.getByRole("radiogroup", { name: "Background" });
    const [twilight, graphite, ultra] = within(group).getAllByRole("radio") as [HTMLElement, HTMLElement, HTMLElement];
    expect([twilight, graphite, ultra].map((r) => r.tabIndex)).toEqual([0, -1, -1]);

    twilight.focus();
    fireEvent.keyDown(twilight, { key: "ArrowRight" });
    expect(graphite).toHaveAttribute("aria-checked", "true");
    expect(graphite).toHaveFocus();
    expect(html.getAttribute("data-scheme")).toBe("graphite");
    expect([twilight, graphite, ultra].map((r) => r.tabIndex)).toEqual([-1, 0, -1]);

    fireEvent.keyDown(graphite, { key: "End" });
    expect(html.getAttribute("data-scheme")).toBe("ultra-black");
    fireEvent.keyDown(ultra, { key: "ArrowDown" }); // wraps
    expect(html.hasAttribute("data-scheme")).toBe(false);
    fireEvent.keyDown(twilight, { key: "ArrowLeft" }); // wraps back
    expect(html.getAttribute("data-scheme")).toBe("ultra-black");
    fireEvent.keyDown(ultra, { key: "Home" });
    expect(twilight).toHaveAttribute("aria-checked", "true");
  });

  it("light theme: shown as dark-mode-only — disabled with the reason, choice kept", async () => {
    window.localStorage.setItem(STORAGE.scheme, "graphite");
    html.setAttribute("data-theme", "light");
    render(<AppearanceTab />);
    const group = screen.getByRole("radiogroup", { name: "Background" });
    expect(group).toHaveAttribute("aria-disabled", "true");
    for (const r of within(group).getAllByRole("radio")) expect(r).toBeDisabled();
    expect(screen.getByRole("note")).toHaveTextContent(/dark mode only/i);
    expect(within(group).getByRole("radio", { name: /Graphite/ })).toHaveAttribute("aria-checked", "true");
    // A click on a disabled radio changes nothing.
    fireEvent.click(within(group).getByRole("radio", { name: /Ultra-black/ }));
    expect(window.localStorage.getItem(STORAGE.scheme)).toBe("graphite");
    // The accent picker is unaffected by the theme.
    expect(within(screen.getByRole("radiogroup", { name: "Accent palette" })).getAllByRole("radio")[0]).toBeEnabled();

    // Topbar toggle flips <html data-theme> → the group wakes up live.
    act(() => html.setAttribute("data-theme", "dark"));
    await waitFor(() => expect(group).toHaveAttribute("aria-disabled", "false"));
    expect(screen.queryByRole("note")).toBeNull();
    fireEvent.click(within(group).getByRole("radio", { name: /Ultra-black/ }));
    expect(html.getAttribute("data-scheme")).toBe("ultra-black");
  });
});

describe("pre-paint boot script (public/assets/appearance-boot.js)", () => {
  it("applies the stored theme + scheme before anything else runs", () => {
    window.localStorage.setItem(STORAGE.theme, "light");
    window.localStorage.setItem(STORAGE.scheme, "ultra-black");
    runBootScript();
    expect(html.getAttribute("data-theme")).toBe("light");
    expect(html.getAttribute("data-scheme")).toBe("ultra-black");
  });

  it("agrees with the TS enum for every scheme id (drift guard)", () => {
    for (const id of SCHEME_IDS) {
      html.removeAttribute("data-scheme");
      window.localStorage.setItem(STORAGE.scheme, id);
      runBootScript();
      const fromBoot = html.getAttribute("data-scheme");
      html.removeAttribute("data-scheme");
      applyStoredAppearance();
      expect(fromBoot, id).toBe(html.getAttribute("data-scheme"));
      expect(fromBoot, id).toBe(id === DEFAULT_SCHEME ? null : id);
    }
  });

  it("fails closed on unknown values", () => {
    window.localStorage.setItem(STORAGE.theme, "sepia");
    window.localStorage.setItem(STORAGE.scheme, "#000000");
    runBootScript();
    expect(html.getAttribute("data-theme")).toBe("dark");
    expect(html.hasAttribute("data-scheme")).toBe(false);
  });

  it("is wired into index.html as an external script — no inline script for the CSP to refuse", () => {
    // Parsed the way a browser parses it (any tag case, any attribute
    // quoting, `</script >`…) — not regex-matched.
    const doc = new DOMParser().parseFromString(INDEX_HTML, "text/html");
    const scripts = [...doc.querySelectorAll("script")];
    expect(scripts.length).toBeGreaterThan(0);
    for (const script of scripts) {
      expect(script.getAttribute("src"), "every <script> must have a src").toBeTruthy();
      expect((script.textContent ?? "").trim()).toBe("");
    }
    const boot = scripts.find((s) => (s.getAttribute("src") ?? "").includes("/assets/appearance-boot.js"));
    expect(boot, "boot script tag").toBeDefined();
    // Classic + synchronous: a module / async / defer script runs after first paint.
    expect((boot?.getAttribute("type") ?? "").trim().toLowerCase()).not.toBe("module");
    expect(boot?.hasAttribute("async")).toBe(false);
    expect(boot?.hasAttribute("defer")).toBe(false);
    // …and it sits in <head>, ahead of the app bundle.
    expect(boot?.parentElement).toBe(doc.head);
    const app = scripts.find((s) => (s.getAttribute("type") ?? "").trim().toLowerCase() === "module");
    expect(app, "app bundle script tag").toBeDefined();
    const order = boot && app ? boot.compareDocumentPosition(app) : 0;
    expect(order & Node.DOCUMENT_POSITION_FOLLOWING, "boot script precedes the app bundle").toBeTruthy();
  });
});
