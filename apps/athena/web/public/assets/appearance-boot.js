/* Pre-paint appearance bootstrap.
 *
 * Loaded from <head> as a render-blocking, same-origin CLASSIC script so
 * the persisted theme + background scheme are on <html> before the first
 * pixel is painted (no dark→light or violet→black flash).
 *
 * Why a file and not an inline <script>: the production console is served
 * with `script-src 'self'`, which refuses inline scripts. Why under
 * /assets/: that path is served ahead of the session gate, so the login
 * page gets it too.
 *
 * Only the two attributes that affect the first painted pixel (the page
 * background) are handled here. Accent / corners / font are applied by
 * applyStoredAppearance() in src/lib/appearance.ts before React mounts.
 *
 * ENUM-ONLY: values are compared against literals, never passed through.
 * Keep the scheme ids in sync with SCHEME_IDS in src/lib/appearance.ts —
 * tests/appearance.test.tsx executes this file and fails on drift.
 * Fail closed: any error leaves the markup defaults (dark / baseline). */
(function () {
  try {
    var root = document.documentElement;
    var theme = window.localStorage.getItem("athena.theme");
    if (theme === "light" || theme === "dark") {
      root.setAttribute("data-theme", theme);
    }
    var scheme = window.localStorage.getItem("athena.appearance.scheme");
    if (scheme === "graphite" || scheme === "ultra-black") {
      root.setAttribute("data-scheme", scheme);
    }
  } catch (e) {
    /* localStorage unavailable; keep defaults */
  }
})();
