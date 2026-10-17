import { useEffect, useState, type FC } from "react";
import Topbar, { type ConnectionState } from "@/components/topbar";
import Sidebar, { type SidebarNavItem } from "@/components/sidebar";
import NetworkBg from "@/components/network-bg";
import DevBanner from "@/components/dev-banner";
import AdminNotices from "@/components/admin-notices";
import ThreatStrip, { threatTitle } from "@/components/threat-strip";
import CommandPalette from "@/components/command-palette";
import ToastHost, { useToastQueue } from "@/components/toast-host";
import BootSplash, { shouldShowBoot } from "@/components/boot-splash";
import { useRoute, matches } from "@/lib/router";
import { getMe } from "@/lib/api";
import { fetchBuoyFleet } from "@/lib/buoy";
import { fetchFleetSites, problemCount } from "@/lib/fleet";
import { fetchIncidentSummary } from "@/lib/incidents";
import type { IncidentSummary } from "@/contracts/incidents";
import type { MeResponse } from "@/contracts/operator";
import DashboardPage from "@/pages/dashboard";
import FleetPage from "@/pages/fleet";
import SettingsPage from "@/pages/settings";
import SearchPage from "@/pages/search";
import TicketsPage from "@/pages/tickets";
import LoginPage from "@/pages/login";
import LoginResetPage from "@/pages/login-reset";
import LoginMagicPage from "@/pages/login-magic";
import LoginSetupPage from "@/pages/login-setup";
import { REFRESH_INTERVAL_SEC } from "@/mock/data";

const HIDE_DASH_STORAGE_KEY = "athena.hide-dash";

// Primary navigation — left sidebar (moved here from the topbar
// 2026-05-13). Markers are 1-2 mono-font chars shown in the collapsed
// rail. Keep markers visually distinct so the compact view stays
// scannable. Unicode picks lean simple/terminal-feel for Nier aesthetic.
const BASE_SIDEBAR_NAV: readonly SidebarNavItem[] = [
  { path: "/dashboard", label: "Dashboard", marker: "◐" },
  { path: "/tickets",   label: "Tickets",   marker: "▤" },
  { path: "/fleet",     label: "Fleet",     marker: "⬡" },
  { path: "/search",    label: "Search",    marker: "⌕" },
  { path: "/settings",  label: "Settings",  marker: "⚙" },
];

// Poll cadence for the Fleet attention badge. Slower than the per-page
// fleet polls (30s) — the sidebar count is glance-level info, not load-
// bearing UX.
const FLEET_BADGE_POLL_MS = 60_000;
// Tier Black: the global threat strip, the sidebar's black chip and the
// title prefix poll the incident summary every 15 s on every route.
export const THREAT_POLL_MS = 15_000;

/**
 * Top-level shell: topbar (brand + status + identity) + nav sidebar +
 * routed page + footer. Nav moved to the left sidebar 2026-05-13 so
 * the topbar branding slot is free for future per-MSP white-label.
 *
 * Routing is path-based (`@/lib/router`) — no react-router dependency
 * for a surface this small.
 */

const App: FC = () => {
  const [route, navigate] = useRoute();
  const [connection, setConnection] = useState<ConnectionState>("paused");
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [me, setMe] = useState<MeResponse | null>(null);
  const [cmdkOpen, setCmdkOpen] = useState(false);
  const [bootVisible, setBootVisible] = useState<boolean>(() => shouldShowBoot());
  const { queue: toastQueue, dismiss: dismissToast } = useToastQueue();

  // Cmd+K / Ctrl+K opens the command palette globally. Skip when an input
  // is focused so it doesn't steal keystrokes from form fields.
  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      const isMeta = e.metaKey || e.ctrlKey;
      if (isMeta && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        setCmdkOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const [dashHidden, setDashHidden] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem(HIDE_DASH_STORAGE_KEY) === "1";
    } catch {
      return false;
    }
  });

  // Persist hide-dash preference across reloads.
  useEffect(() => {
    try {
      window.localStorage.setItem(
        HIDE_DASH_STORAGE_KEY,
        dashHidden ? "1" : "0",
      );
    } catch {
      /* localStorage unavailable; preference is session-only */
    }
  }, [dashHidden]);

  // Fleet attention badge — count of sites that need attention (Fleet v2;
  // buoys that aren't `green` when the fleet endpoint is unavailable).
  // Polled at a slower cadence than per-page fleet views (60s vs 30s)
  // because the badge is glance-level info, not load-bearing. Auth
  // failures are silent — sidebar simply omits the badge until the
  // session is healthy. Counts >99 render as "99+" in the badge UI.
  const [fleetAttentionCount, setFleetAttentionCount] = useState<number>(0);
  useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      try {
        // Fleet v2: sites that need attention (problem / attention). A
        // bundle whose fleet endpoint is unavailable falls back to buoys.
        let attention: number | null = null;
        try {
          const sites = await fetchFleetSites({ quiet: true });
          if (Array.isArray(sites.sites)) attention = problemCount(sites.sites);
        } catch {
          attention = null;
        }
        if (attention === null) {
          const r = await fetchBuoyFleet();
          attention = r.buoys.filter((b) => b.health !== "green").length;
        }
        if (cancelled) return;
        setFleetAttentionCount(attention);
      } catch {
        // Silent — sidebar just won't show a badge if we can't fetch.
      }
    };
    void load();
    const id = window.setInterval(() => { void load(); }, FLEET_BADGE_POLL_MS);
    return () => { cancelled = true; window.clearInterval(id); };
  }, []);

  // Tier Black: the incident summary — every route, every 15 s. Quiet: a
  // dead session is just "no strip" (the login redirect is getMe's job).
  const [threatSummary, setThreatSummary] = useState<IncidentSummary | null>(null);
  const onLoginPage = matches(route, "/login");
  useEffect(() => {
    if (onLoginPage) return undefined;
    let cancelled = false;
    const load = (): void => {
      fetchIncidentSummary({ quiet: true })
        .then((r) => { if (!cancelled) setThreatSummary(r); })
        .catch(() => undefined);
    };
    load();
    const id = window.setInterval(load, THREAT_POLL_MS);
    return () => { cancelled = true; window.clearInterval(id); };
  }, [onLoginPage]);
  // The title prefix ("BLACK (2) · …") — seen from another tab too.
  useEffect(() => {
    document.title = threatTitle(document.title, threatSummary);
  }, [threatSummary]);
  // A browser notification when a NEW unacknowledged Black appears (only if
  // the operator already granted the permission — never a prompt from here).
  const unackedBlack = threatSummary?.view === "operator" ? threatSummary.black_unacked ?? 0 : 0;
  const [seenUnacked, setSeenUnacked] = useState(0);
  useEffect(() => {
    if (unackedBlack > seenUnacked) {
      try {
        if (typeof Notification !== "undefined" && Notification.permission === "granted") {
          new Notification("Athena: BLACK incident", {
            body: "An attack is in progress — acknowledge it in Athena.", tag: "athena-black",
          });
        }
      } catch { /* notifications unavailable */ }
    }
    setSeenUnacked(unackedBlack);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [unackedBlack]);

  // Inject the badge into the Fleet nav item. Tone choice: critical
  // when any red/stale present, else high (yellow-ish). Looking at
  // counts only here — the underlying buoy worst-state granularity
  // can be threaded through later if Design calls for it. A Black gets
  // its own chip (`alert`), never folded into the attention count.
  const blackCount = threatSummary?.black ?? 0;
  const sidebarNav: readonly SidebarNavItem[] = BASE_SIDEBAR_NAV.map(
    (item): SidebarNavItem => {
      if (item.path !== "/fleet") return item;
      let out: SidebarNavItem = item;
      if (fleetAttentionCount > 0) {
        out = { ...out, badge: { count: fleetAttentionCount, tone: "high" } };
      }
      if (blackCount > 0) {
        out = { ...out, alert: { count: blackCount, pulse: unackedBlack > 0 } };
      }
      return out;
    },
  );

  // Load identity for the topbar user-menu display. If /auth/me returns
  // 401, the SPA is unauthenticated — hard-redirect to /login rather
  // than render the dashboard with empty widgets and silent fetch
  // failures (an invalid session always redirects).
  useEffect(() => {
    // Login + reset + magic-link consumption pages run their own auth
    // ceremony — don't kick them back to /login the moment they load.
    const onLoginRoute =
      matches(route, "/login") || matches(route, "/login/");
    if (onLoginRoute) return;

    getMe()
      .then((fresh) => {
        if (!fresh) {
          window.location.href = "/login";
          return;
        }
        // Force the setup wizard when account isn't fully set up. The
        // backend setup_gate middleware enforces the same rule — this
        // redirect is the UX side.
        if (fresh.needs_setup) {
          window.location.href = "/login/setup";
          return;
        }
        setMe(fresh);
      })
      .catch(() => {
        window.location.href = "/login";
      });
  }, [route]);

  const onLogout = (): void => {
    // POST to OCTO's /api/v1/auth/logout to revoke the session, then
    // hard-redirect to /login so the SPA's in-memory state is fully
    // torn down. Failure is non-fatal — the redirect still happens.
    void fetch("/api/v1/auth/logout", {
      method: "POST",
      credentials: "include",
    }).finally(() => {
      window.location.href = "/login";
    });
  };

  // Heartbeat — fakes a polling cadence until the bridge client lands.
  useEffect(() => {
    setConnection("live");
    setLastRefresh(new Date());
    const id = window.setInterval(() => {
      setConnection("fetching");
      window.setTimeout(() => {
        setConnection("live");
        setLastRefresh(new Date());
      }, 400);
    }, REFRESH_INTERVAL_SEC * 1000);
    return () => window.clearInterval(id);
  }, []);

  // At-a-glance stats section moved to dashboard widgets 2026-05-13.
  // If you ever want them back on the sidebar, recreate a sections
  // array here and pass it as `sections={...}` to Sidebar.

  // Login routes render WITHOUT the dashboard chrome (no topbar / sidebar),
  // but DO still surface the dev banner so synthetic-data context is
  // visible even before sign-in.
  if (matches(route, "/login")) {
    const loginPage =
      route === "/login/reset" ? <LoginResetPage />
      : route === "/login/magic" ? <LoginMagicPage />
      : route === "/login/setup" ? <LoginSetupPage />
      : <LoginPage />;
    return (
      <>
        {bootVisible && <BootSplash onDone={() => setBootVisible(false)} />}
        <DevBanner />
        {loginPage}
      </>
    );
  }

  return (
    <div className="relative flex min-h-screen flex-col">
      {bootVisible && <BootSplash onDone={() => setBootVisible(false)} />}
      <NetworkBg />
      <DevBanner />
      <Topbar
        onNavigate={navigate}
        me={me}
        dashHidden={dashHidden}
        onToggleDashHidden={() => setDashHidden((v) => !v)}
        onLogout={onLogout}
      />

      <div
        className={[
          "relative z-10 flex flex-1 transition-opacity duration-300",
          dashHidden ? "pointer-events-none opacity-0" : "opacity-100",
        ].join(" ")}
        aria-hidden={dashHidden}
      >
        <Sidebar
          navItems={sidebarNav}
          currentRoute={route}
          onNavigate={navigate}
          profile={me?.username ?? null}
          footer={
            <span className="font-mono">
              tenant: <span className="text-accent">msp_root</span>
            </span>
          }
        />
        <main className="mx-auto w-full max-w-[1500px] flex-1 px-6 py-6">
          {/* v0.10: tenant changes another super admin applied ALONE —
              shown to every other admin on every page until acknowledged. */}
          {/* Tier Black: the global threat strip — every route. */}
          <ThreatStrip summary={threatSummary} onOpen={() => navigate("/fleet")} />
          <AdminNotices me={me} onNavigate={navigate} />
          <RouteSwitch
            route={route}
            username={me?.display_name ?? me?.username ?? null}
            me={me}
          />
        </main>
      </div>

      <footer
        className={[
          "relative z-10 flex items-center justify-between border-t border-border bg-bg-surface px-6 py-1.5 text-[10px] font-mono uppercase tracking-wider text-text-dim transition-opacity duration-300",
          dashHidden ? "pointer-events-none opacity-0" : "opacity-100",
        ].join(" ")}
        aria-hidden={dashHidden}
      >
        <span>athena-console v3 · framework runtime</span>
        <span className="inline-flex items-center gap-4">
          <StatusDot
            tone={connection === "error" ? "critical"
                  : connection === "paused" ? "dim"
                  : "accent"}
            label={connection === "paused" ? "paused"
                    : connection === "error" ? "offline"
                    : connection === "fetching" ? `fetching…`
                    : `live · ${REFRESH_INTERVAL_SEC}s`}
          />
          <StatusDot tone="success" label="octo · healthy" />
          {lastRefresh && (
            <span>last: {lastRefresh.toLocaleTimeString()}</span>
          )}
        </span>
      </footer>

      <CommandPalette
        open={cmdkOpen}
        onClose={() => setCmdkOpen(false)}
        onNavigate={(p) => { setCmdkOpen(false); navigate(p); }}
      />

      <ToastHost toasts={toastQueue} onDismiss={dismissToast} />
    </div>
  );
};

/** Tiny status indicator for the footer — animated dot + label.
 * Replaces the larger Topbar pills 2026-05-13. Tone maps to the
 * existing severity palette so meaning stays consistent. */
const StatusDot: FC<{
  tone: "accent" | "success" | "critical" | "dim";
  label: string;
}> = ({ tone, label }) => {
  const dotClass =
    tone === "critical" ? "bg-critical animate-pulse"
    : tone === "success" ? "bg-success"
    : tone === "dim" ? "bg-text-dim"
    : "bg-accent animate-pulse-fast";
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`h-1.5 w-1.5 rounded-full ${dotClass}`} aria-hidden="true" />
      <span>{label}</span>
    </span>
  );
};

const RouteSwitch: FC<{
  route: string;
  username: string | null;
  me: MeResponse | null;
}> = ({ route, username, me }) => {
  if (matches(route, "/dashboard")) return <DashboardPage username={username} me={me} />;
  if (matches(route, "/tickets")) return <TicketsPage />;
  if (matches(route, "/fleet")) return <FleetPage />;
  if (matches(route, "/search")) {
    const mode = route.startsWith("/search/indicators") ? "indicators" : "events";
    return (
      <SearchPage
        mode={mode}
        onNavigateMode={(m) => {
          window.history.pushState({}, "", `/search/${m}`);
          window.dispatchEvent(new Event("athena:navigate"));
        }}
      />
    );
  }
  if (matches(route, "/settings")) return <SettingsPage />;
  return <DashboardPage username={username} me={me} />;
};

export default App;
