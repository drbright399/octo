/**
 * Theme bootstrap is `public/assets/appearance-boot.js`, loaded from
 * `index.html` (runs before paint), with `applyStoredAppearance()` in
 * `lib/appearance.ts` as the pre-mount fallback. This module exposes the
 * runtime toggle + a small React hook for the toolbar.
 *
 * No tokens or auth state — just "dark" | "light". `localStorage` is the
 * right tool here (it's not a credential, it's a UI preference).
 */

import { useEffect, useState } from "react";

export type ThemeName = "dark" | "light";

const STORAGE_KEY = "athena.theme";

function readPersisted(): ThemeName {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return v === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export function useTheme(): readonly [ThemeName, () => void] {
  const [theme, setTheme] = useState<ThemeName>(() => {
    const fromDom = document.documentElement.getAttribute("data-theme");
    if (fromDom === "light" || fromDom === "dark") return fromDom;
    return readPersisted();
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      /* ignore quota / disabled storage */
    }
  }, [theme]);

  const toggle = (): void => {
    setTheme((t) => (t === "dark" ? "light" : "dark"));
  };

  return [theme, toggle] as const;
}
