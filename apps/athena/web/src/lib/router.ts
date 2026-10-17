/**
 * Path-based router using the browser History API. SPA-only; the dev
 * server (Vite) and the prod static host both need an SPA fallback that
 * serves `index.html` for any path, so the router gets to decide what
 * renders. No dependency on react-router; the surface area is small
 * enough to own in-house.
 *
 * Why path-based and not hash-based: email-flow links land at URLs like
 * `/login/reset?token=…` which must match a route literally. Hash
 * routing puts everything past the `#` and email clients strip or
 * mangle the hash. Path routing also gives us real query-string access
 * for the token consumption flows.
 *
 * Public API matches the prior hash router shape:
 *   const [route, navigate] = useRoute();
 *   matches(route, "/settings");
 *
 * Behavior:
 *   - `route` is the current pathname (e.g. "/login/reset"). Query
 *     string is NOT part of `route`; callers consume it via
 *     `window.location.search` or `useSearchParam(name)`.
 *   - `navigate(path)` pushes to history (back-button-friendly) AND
 *     fires a popstate-compatible update. Same-path navigation is a
 *     no-op to avoid history spam.
 *   - Default route on empty pathname is "/dashboard" to preserve the
 *     hash-router behavior callers depended on.
 */

import { useEffect, useState } from "react";

function readPath(): string {
  const p = window.location.pathname || "/";
  // Treat "/" as the dashboard entry point so the same logic that
  // worked under hash routing keeps working: visiting "/" shows the
  // dashboard, every other path resolves literally.
  return p === "/" ? "/dashboard" : p;
}

// Custom event the in-process navigate() fires so subscribers in the
// same tab update without round-tripping through popstate (which only
// fires on back/forward, not pushState).
const NAV_EVENT = "athena:navigate";

/**
 * Navigate from outside a component tree that holds `useRoute` (a link in a
 * card, a dashboard notice): same push + same event as the hook's navigate.
 * A path with a query string is fine — `useSearchParam` picks it up.
 */
export function navigateTo(path: string): void {
  const target = path.startsWith("/") ? path : `/${path}`;
  if (target === window.location.pathname + window.location.search) {
    return;
  }
  window.history.pushState({}, "", target);
  window.dispatchEvent(new Event(NAV_EVENT));
}

export function useRoute(): readonly [string, (path: string) => void] {
  const [route, setRoute] = useState<string>(() => readPath());

  useEffect(() => {
    const sync = (): void => setRoute(readPath());
    window.addEventListener("popstate", sync);
    window.addEventListener(NAV_EVENT, sync);
    return () => {
      window.removeEventListener("popstate", sync);
      window.removeEventListener(NAV_EVENT, sync);
    };
  }, []);

  return [route, navigateTo] as const;
}

export function matches(route: string, prefix: string): boolean {
  if (prefix === route) return true;
  return route.startsWith(prefix === "/" ? "/" : `${prefix}/`);
}

/**
 * Convenience hook for reading a single query-string parameter. Re-reads
 * on navigation so a search-params change triggered by navigate() is
 * reflected in callers.
 */
export function useSearchParam(name: string): string | null {
  const [value, setValue] = useState<string | null>(() =>
    new URLSearchParams(window.location.search).get(name),
  );
  useEffect(() => {
    const sync = (): void =>
      setValue(new URLSearchParams(window.location.search).get(name));
    window.addEventListener("popstate", sync);
    window.addEventListener(NAV_EVENT, sync);
    return () => {
      window.removeEventListener("popstate", sync);
      window.removeEventListener(NAV_EVENT, sync);
    };
  }, [name]);
  return value;
}
