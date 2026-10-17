import { useEffect, useRef, useState, type FC } from "react";
import { useTheme, type ThemeName } from "@/lib/theme";
import { revokeMyOtherSessions } from "@/lib/api";
import { ROLE_LABEL, ROLE_TIER, type MeResponse } from "@/contracts/operator";
import AthenaMark from "@/components/athena-mark";
import TopbarLlmStatus from "@/components/topbar-llm-status";
import AgentStatusPill from "@/components/agent-status-pill";
import TopbarSyntheticToggle from "@/components/topbar-synthetic-toggle";

export type ConnectionState = "live" | "fetching" | "paused" | "error";

export interface TopbarProps {
  readonly onNavigate: (path: string) => void;
  readonly me: MeResponse | null;
  readonly dashHidden: boolean;
  readonly onToggleDashHidden: () => void;
  readonly onLogout: () => void;
}

// Primary nav moved to the left sidebar 2026-05-13 — frees up the
// topbar for branding + status pills + identity. The topbar branding
// slot (the 🦉 ATHENA wordmark) becomes the per-MSP white-label
// surface once MSP branding ships.

const Topbar: FC<TopbarProps> = ({
  onNavigate,
  me,
  dashHidden,
  onToggleDashHidden,
  onLogout,
}) => {
  const [theme, toggleTheme] = useTheme();

  return (
    <header className="sticky top-0 z-20 flex items-center gap-6 border-b border-border bg-bg-surface px-6 py-3 backdrop-blur">
      <button
        type="button"
        onClick={() => onNavigate("/dashboard")}
        title="Athena home"
        className="group flex items-center gap-2 rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <span className="text-accent transition-transform group-hover:scale-105">
          <AthenaMark size={22} />
        </span>
        <span className="text-base font-bold tracking-wider text-accent">ATHENA</span>
        <span className="text-xs text-text-dim">— Data Plane Console</span>
      </button>

      <div className="ml-auto flex items-center gap-3">
        {me && (
          <TopbarLlmStatus
            isSuperAdmin={me.role.includes("super_admin")}
            onNavigate={onNavigate}
          />
        )}
        {me && <AgentStatusPill compact onNavigate={onNavigate} />}
        {me && import.meta.env.MODE === "development" && <TopbarSyntheticToggle />}
        <UserMenu
          me={me}
          dashHidden={dashHidden}
          onToggleDashHidden={onToggleDashHidden}
          onLogout={onLogout}
          onNavigate={onNavigate}
          theme={theme}
          onToggleTheme={toggleTheme}
        />
      </div>
    </header>
  );
};

const UserMenu: FC<{
  me: MeResponse | null;
  dashHidden: boolean;
  onToggleDashHidden: () => void;
  onLogout: () => void;
  onNavigate: (path: string) => void;
  theme: ThemeName;
  onToggleTheme: () => void;
}> = ({ me, dashHidden, onToggleDashHidden, onLogout, onNavigate,
        theme, onToggleTheme }) => {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    const onDocClick = (ev: MouseEvent): void => {
      if (wrapRef.current && !wrapRef.current.contains(ev.target as Node)) {
        setOpen(false);
      }
    };
    const onEsc = (ev: KeyboardEvent): void => {
      if (ev.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onEsc);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onEsc);
    };
  }, [open]);

  // Athena prefers display_name when set; falls back to username so the
  // menu is never blank. Initial uses the same fallback.
  const display = me?.display_name ?? me?.username ?? "—";
  const initial = display.charAt(0).toUpperCase();
  const first = me?.role[0];
  const primaryRole = first
    ? me!.role.reduce(
        (best, r) =>
          (ROLE_TIER[r] ?? 0) > (ROLE_TIER[best] ?? 0) ? r : best,
        first,
      )
    : null;
  const roleLabel = primaryRole ? ROLE_LABEL[primaryRole] : null;

  const onSignOutOthers = async (): Promise<void> => {
    if (
      !window.confirm(
        "Sign out every other session for this account? Your current " +
          "session here stays signed in.",
      )
    )
      return;
    setBusy(true);
    try {
      await revokeMyOtherSessions();
    } catch (e) {
      // Surface failure via window.alert — the menu has no error pane.
      window.alert(
        e instanceof Error ? e.message : "Sign-out-everywhere failed",
      );
    } finally {
      setBusy(false);
      setOpen(false);
    }
  };

  return (
    <div ref={wrapRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        className="inline-flex items-center gap-2 rounded-sm border border-border bg-bg-card px-2 py-1 text-[11px] text-text-secondary transition-colors hover:border-border-bright hover:bg-accent-soft hover:text-accent"
      >
        <span
          aria-hidden="true"
          className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-accent-soft font-mono text-[10px] text-accent"
        >
          {initial}
        </span>
        <span className="hidden font-mono sm:inline">{display}</span>
        <span aria-hidden="true">▾</span>
      </button>

      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full z-30 mt-1 w-64 rounded-md border border-border bg-bg-elevated p-1 shadow-xl"
        >
          {/* Identity badge */}
          <div className="border-b border-border px-3 py-2 text-[11px]">
            <div className="font-mono text-sm text-text-primary">{display}</div>
            {me ? (
              <>
                <div className="text-text-dim">{me.email}</div>
                {roleLabel ? (
                  <div className="mt-1 inline-block rounded bg-accent/20 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-accent">
                    {roleLabel}
                  </div>
                ) : null}
              </>
            ) : null}
          </div>

          <MenuItem
            onClick={() => {
              setOpen(false);
              onNavigate("/settings/account");
            }}
            icon="⚙"
            label="My account"
          />

          <button
            type="button"
            role="menuitemcheckbox"
            aria-checked={dashHidden}
            onClick={onToggleDashHidden}
            className="flex w-full items-center justify-between rounded px-3 py-2 text-left text-xs text-text-secondary hover:bg-accent-soft hover:text-accent"
          >
            <span>Hide dashboard</span>
            <span
              className={[
                "inline-flex h-4 w-7 items-center rounded-full transition-colors",
                dashHidden ? "bg-accent" : "bg-bg-card",
              ].join(" ")}
              aria-hidden="true"
            >
              <span
                className={[
                  "h-3 w-3 rounded-full bg-bg-deep transition-transform",
                  dashHidden ? "translate-x-3.5" : "translate-x-0.5",
                ].join(" ")}
              />
            </span>
          </button>

          <button
            type="button"
            role="menuitemcheckbox"
            aria-checked={theme === "dark"}
            onClick={onToggleTheme}
            className="flex w-full items-center justify-between rounded px-3 py-2 text-left text-xs text-text-secondary hover:bg-accent-soft hover:text-accent"
          >
            <span className="flex items-center gap-2">
              <span aria-hidden="true">{theme === "dark" ? "☾" : "☼"}</span>
              <span>{theme === "dark" ? "Dark theme" : "Light theme"}</span>
            </span>
            <span aria-hidden="true" className="font-mono text-text-dim">
              {theme === "dark" ? "→ light" : "→ dark"}
            </span>
          </button>

          <div className="my-1 border-t border-border" />

          <button
            type="button"
            role="menuitem"
            disabled={busy}
            onClick={() => void onSignOutOthers()}
            className="flex w-full items-center gap-2 rounded px-3 py-2 text-left text-xs text-text-secondary hover:bg-accent-soft hover:text-accent disabled:opacity-50"
          >
            <span aria-hidden="true">⌫</span>
            <span>Sign out everywhere else</span>
          </button>
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              onLogout();
            }}
            className="flex w-full items-center gap-2 rounded px-3 py-2 text-left text-xs text-text-secondary hover:bg-critical/10 hover:text-critical"
          >
            <span aria-hidden="true">⎋</span>
            <span>Sign out</span>
          </button>
        </div>
      )}
    </div>
  );
};

const MenuItem: FC<{
  onClick: () => void;
  icon: string;
  label: string;
}> = ({ onClick, icon, label }) => (
  <button
    type="button"
    role="menuitem"
    onClick={onClick}
    className="flex w-full items-center gap-2 rounded px-3 py-2 text-left text-xs text-text-secondary hover:bg-accent-soft hover:text-accent"
  >
    <span aria-hidden="true">{icon}</span>
    <span>{label}</span>
  </button>
);


// ConnectionPill / HealthPill / ThemeToggle removed 2026-05-13.
// Connection + health moved to the footer status strip; theme toggle moved
// into the user-menu dropdown above.

export default Topbar;
