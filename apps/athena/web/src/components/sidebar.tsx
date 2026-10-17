import { useEffect, useState, type FC, type ReactNode } from "react";

import "./fleet.css";

/**
 * Navigation sidebar — vertical rail on the left. Primary content is
 * the route nav (Dashboard / Tickets / Fleet / Search / Settings);
 * optional `sections` slot below for at-a-glance stats once we want
 * them back, currently unused (moved to Dashboard widgets).
 *
 * Collapsible (2026-05-13) — operator can shrink the rail to a thin
 * strip of nav markers via the chevron, or toggle with keyboard `[`.
 * State persists per-operator via localStorage.
 *
 * The topbar above stays light (brand + status + identity) so the
 * branding slot is free for future per-MSP white-label.
 */

export interface SidebarStat {
  readonly label: string;
  readonly value: string | number;
  readonly tone?: "default" | "critical" | "high" | "success" | "accent";
}

export interface SidebarSection {
  readonly title: string;
  readonly stats: readonly SidebarStat[];
}

export interface SidebarNavItem {
  readonly path: string;
  readonly label: string;
  /** Short marker for the collapsed-rail view (1-2 chars, mono-font). */
  readonly marker: string;
  /** Optional attention-count badge (e.g. count of buoys needing
   *  attention on the Fleet nav item). When > 0 a small chip renders
   *  to the right of the label (or stacked on the marker in the
   *  collapsed-rail view). Tone defaults to "high" — overrideable. */
  readonly badge?: { count: number; tone?: "high" | "warning" | "critical" | "accent" } | undefined;
  /** Tier Black: open Black incidents — its OWN chip (an octagon "!"),
   *  never folded into the attention count; `pulse` while any is
   *  unacknowledged. */
  readonly alert?: { count: number; pulse?: boolean } | undefined;
}

const AlertChip: FC<{ alert: { count: number; pulse?: boolean }; compact?: boolean }> = ({
  alert, compact = false,
}) => (
  <span
    data-testid="sidebar-black-chip"
    title={`${alert.count} Black incident${alert.count === 1 ? "" : "s"} open`}
    className={[
      compact
        ? "absolute left-1 top-1 min-w-[14px] rounded-full px-1 text-center text-[8px] font-bold leading-[14px]"
        : "min-w-[18px] rounded-sm px-1.5 text-center font-mono text-[10px] font-bold tracking-normal",
      "border border-[var(--fleet-threat-ring)] bg-[var(--fleet-threat)] text-[var(--fleet-threat-text)]",
      alert.pulse ? "fleet-strip-black" : "",
    ].join(" ")}
  >
    ⯃{alert.count > 99 ? "99+" : alert.count}
  </span>
);

export interface SidebarProps {
  readonly navItems: readonly SidebarNavItem[];
  readonly currentRoute: string;
  readonly onNavigate: (path: string) => void;
  readonly sections?: readonly SidebarSection[];  // optional at-a-glance below nav
  readonly footer?: ReactNode;
  readonly profile?: string | null;
}

const TONE_CLASS: Record<NonNullable<SidebarStat["tone"]>, string> = {
  default: "text-text-primary",
  critical: "text-critical",
  high: "text-high",
  success: "text-success",
  accent: "text-accent",
};

/** Tailwind classes for the per-tone background + text on a nav-item
 *  attention badge. Mirrors the toned chips elsewhere in the V3 surface. */
function badgeTone(tone: NonNullable<SidebarNavItem["badge"]>["tone"] | undefined): string {
  switch (tone) {
    case "critical": return "bg-critical/15 text-critical border border-critical/40";
    case "warning":  return "bg-warning/15 text-warning border border-warning/40";
    case "accent":   return "bg-accent/15 text-accent border border-accent/40";
    case "high":
    default:         return "bg-high/15 text-high border border-high/40";
  }
}

const STORAGE_KEY_PREFIX = "athena.sidebar-collapsed.";

function readCollapsed(profile: string | null | undefined): boolean {
  try {
    const v = window.localStorage.getItem(
      STORAGE_KEY_PREFIX + (profile || "default"),
    );
    return v === "1";
  } catch {
    return false;
  }
}

function writeCollapsed(profile: string | null | undefined, val: boolean): void {
  try {
    window.localStorage.setItem(
      STORAGE_KEY_PREFIX + (profile || "default"),
      val ? "1" : "0",
    );
  } catch {
    /* localStorage unavailable */
  }
}

/** A route prefix matches the current route if the route starts with
 * the prefix followed by '/' (or equals the prefix exactly). Mirrors
 * `router.ts::matches` so the sidebar highlights the active section
 * across all sub-routes (/search/events highlights "Search"). */
function routeMatches(route: string, prefix: string): boolean {
  if (route === prefix) return true;
  return route.startsWith(prefix === "/" ? "/" : `${prefix}/`);
}

export const Sidebar: FC<SidebarProps> = ({
  navItems, currentRoute, onNavigate, sections, footer, profile,
}) => {
  const [collapsed, setCollapsed] = useState<boolean>(() => readCollapsed(profile));

  useEffect(() => {
    setCollapsed(readCollapsed(profile));
  }, [profile]);

  const toggle = (): void => {
    setCollapsed((prev) => {
      const next = !prev;
      writeCollapsed(profile, next);
      return next;
    });
  };

  // Keyboard: `[` toggles the sidebar (skip when an input is focused).
  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (e.key !== "[") return;
      const tag = (document.activeElement?.tagName || "").toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select") return;
      if ((document.activeElement as HTMLElement | null)?.isContentEditable) return;
      e.preventDefault();
      toggle();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile]);

  if (collapsed) {
    return (
      <aside
        className="hidden w-12 shrink-0 flex-col border-r border-border bg-bg-surface md:flex"
        aria-label="Sidebar (collapsed)"
      >
        <button
          type="button"
          onClick={toggle}
          title="Expand sidebar — keyboard: [ "
          aria-expanded="false"
          className="flex h-10 w-full items-center justify-center border-b border-border text-text-dim transition-colors hover:bg-accent-soft hover:text-accent"
        >
          <span aria-hidden="true">▸</span>
        </button>
        <nav role="navigation" aria-label="Primary (compact)" className="flex flex-1 flex-col">
          {navItems.map((item) => {
            const active = routeMatches(currentRoute, item.path);
            return (
              <button
                key={item.path}
                type="button"
                onClick={() => onNavigate(item.path)}
                title={item.badge && item.badge.count > 0
                  ? `${item.label} (${item.badge.count} need attention)`
                  : item.label}
                aria-current={active ? "page" : undefined}
                className={[
                  "nav-sweep relative flex h-11 w-full items-center justify-center border-l-2 font-mono text-[11px] transition-colors",
                  active
                    ? "border-accent bg-accent-soft text-accent"
                    : "border-transparent text-text-dim",
                ].join(" ")}
              >
                <span aria-hidden="true">{item.marker}</span>
                <span className="sr-only">{item.label}</span>
                {item.alert && item.alert.count > 0 && <AlertChip alert={item.alert} compact />}
                {item.badge && item.badge.count > 0 && (
                  <span
                    aria-hidden="true"
                    className={[
                      "absolute right-1 top-1 min-w-[14px] rounded-full px-1 text-center text-[8px] font-bold leading-[14px]",
                      badgeTone(item.badge.tone),
                    ].join(" ")}
                  >
                    {item.badge.count > 99 ? "99+" : item.badge.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </aside>
    );
  }

  return (
    <aside
      className="hidden w-56 shrink-0 flex-col border-r border-border bg-bg-surface md:flex"
      aria-label="Sidebar"
    >
      <div className="flex items-center justify-between border-b border-border px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-text-dim">
        <span>navigation</span>
        <button
          type="button"
          onClick={toggle}
          title="Collapse sidebar — keyboard: [ "
          aria-expanded="true"
          className="rounded-sm px-1.5 py-0.5 text-text-dim transition-colors hover:bg-accent-soft hover:text-accent"
        >
          <span aria-hidden="true">◂</span>
        </button>
      </div>

      <nav role="navigation" aria-label="Primary" className="flex flex-col">
        {navItems.map((item) => {
          const active = routeMatches(currentRoute, item.path);
          return (
            <button
              key={item.path}
              type="button"
              onClick={() => onNavigate(item.path)}
              aria-current={active ? "page" : undefined}
              className={[
                "nav-sweep relative flex items-center gap-3 border-l-2 px-3 py-2 text-left text-xs font-mono uppercase tracking-wider transition-colors",
                active
                  ? "border-accent bg-accent-soft text-accent"
                  : "border-transparent text-text-secondary",
              ].join(" ")}
            >
              <span aria-hidden="true" className="w-4 text-center">
                {item.marker}
              </span>
              <span className="flex-1">{item.label}</span>
              {item.alert && item.alert.count > 0 && <AlertChip alert={item.alert} />}
              {item.badge && item.badge.count > 0 && (
                <span
                  aria-hidden="true"
                  className={[
                    "min-w-[18px] rounded-sm px-1.5 text-center font-mono text-[10px] font-semibold tracking-normal",
                    badgeTone(item.badge.tone),
                  ].join(" ")}
                  title={`${item.badge.count} need attention`}
                >
                  {item.badge.count > 99 ? "99+" : item.badge.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {sections && sections.length > 0 ? (
        <div className="flex-1 overflow-y-auto border-t border-border p-4">
          {sections.map((section) => (
            <SidebarSectionView key={section.title} section={section} />
          ))}
        </div>
      ) : (
        <div className="flex-1" />
      )}

      {footer ? (
        <div className="border-t border-border p-3 text-[11px] text-text-dim">
          {footer}
        </div>
      ) : null}
    </aside>
  );
};

const SidebarSectionView: FC<{ section: SidebarSection }> = ({ section }) => (
  <section className="mb-5">
    <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-text-dim">
      {section.title}
    </h3>
    <ul className="flex flex-col gap-1.5">
      {section.stats.map((stat) => (
        <li
          key={stat.label}
          className="flex items-baseline justify-between rounded-sm bg-bg-card px-2.5 py-1.5"
        >
          <span className="text-xs text-text-secondary">{stat.label}</span>
          <span
            className={[
              "font-mono text-sm font-semibold",
              TONE_CLASS[stat.tone ?? "default"],
            ].join(" ")}
          >
            {stat.value}
          </span>
        </li>
      ))}
    </ul>
  </section>
);

export default Sidebar;
