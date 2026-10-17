/**
 * CommandPalette — Cmd+K / Ctrl+K analyst quick-jump.
 *
 * Style per Design's spec (2026-05-13): hybrid Linear/Spotlight.
 * Centered modal, mono input at top, sectioned results grouped by
 * `·· section ··` markers, highlighted selection with accent-soft +
 * left border.
 *
 * Sections (in display order):
 *   ·· recent ··   last 5 used (only when query empty)
 *   ·· routes ··   Dashboard / Search / Tickets / Fleet / Settings
 *   ·· tenants ··  Tenant scope-switch (jumps to /search/events filtered)
 *   ·· events ··   Recent alerts (live search filter)
 *   ·· help ··     Tour / shortcuts / docs
 *
 * Per design memo: NO actions in v1 (acknowledge / isolate / create
 * ticket). Actions live in the event drawer where they're auth-gated
 * and context-bound. Plan to add when the workflow engine + AI agent
 * direct ticket close lands.
 *
 * Trigger: Cmd+K (mac) / Ctrl+K (everywhere). Esc dismisses. ↑↓ navigates.
 * ↵ activates. Recent history persists to localStorage.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type FC } from "react";

const ROUTES: ReadonlyArray<{ id: string; label: string; glyph: string; route: string }> = [
  { id: "route:dashboard",             label: "Dashboard",              glyph: "◐", route: "/dashboard" },
  { id: "route:search-events",         label: "Search events",          glyph: "⌕", route: "/search/events" },
  { id: "route:search-indicators",     label: "Search indicators",      glyph: "⌖", route: "/search/indicators" },
  { id: "route:tickets",               label: "Tickets",                glyph: "▤", route: "/tickets" },
  { id: "route:fleet",                 label: "Fleet",                  glyph: "⬡", route: "/fleet" },
  { id: "route:settings-account",      label: "Settings · Account",     glyph: "⚙", route: "/settings/account" },
  { id: "route:settings-operators",    label: "Settings · Operators",   glyph: "⚙", route: "/settings/operators" },
  { id: "route:settings-integrations", label: "Settings · Integrations", glyph: "⚙", route: "/settings/integrations" },
];

const HELP_ITEMS: ReadonlyArray<{ id: string; label: string; glyph: string; action: string }> = [
  { id: "help:onboarding", label: "Open onboarding tour",   glyph: "?", action: "tour" },
  { id: "help:shortcuts",  label: "Keyboard shortcuts",     glyph: "⌨", action: "shortcuts" },
  { id: "help:docs",       label: "Open documentation ↗",   glyph: "↗", action: "docs" },
];

const STORAGE_KEY = "athena.cmdk.recent.v1";

function loadRecent(): string[] {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as string[]).slice(0, 5) : [];
  } catch { return []; }
}
function saveRecent(ids: string[]): void {
  try { window.localStorage.setItem(STORAGE_KEY, JSON.stringify(ids.slice(0, 5))); } catch { /* */ }
}

function fuzzy(haystack: string, needle: string): boolean {
  if (!needle) return true;
  return haystack.toLowerCase().includes(needle.toLowerCase());
}

interface FlatItem {
  readonly id: string;
  readonly section: string;
  readonly label: string;
  readonly glyph: string;
  readonly subtitle?: string;
  readonly onSelect: () => void;
}

interface CommandPaletteProps {
  readonly open: boolean;
  readonly onClose: () => void;
  readonly onNavigate: (path: string) => void;
  readonly tenants?: ReadonlyArray<{ slug: string; display_name: string }>;
  readonly onHelp?: (action: string) => void;
}

const CommandPalette: FC<CommandPaletteProps> = ({
  open, onClose, onNavigate, tenants = [], onHelp,
}) => {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const [recentIds, setRecentIds] = useState<string[]>(() => loadRecent());
  const inputRef = useRef<HTMLInputElement | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);

  // Reset on open/close.
  useEffect(() => {
    if (open) {
      setQuery("");
      setSelected(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  // Build the flat list of items (filtered by query, sectioned).
  const items: FlatItem[] = useMemo(() => {
    const q = query.trim();
    const out: FlatItem[] = [];

    // ·· recent ·· — only when query is empty
    if (!q && recentIds.length > 0) {
      const findById = (id: string): FlatItem | null => {
        const r = ROUTES.find((x) => x.id === id);
        if (r) {
          return {
            id: r.id, section: "recent", label: r.label, glyph: r.glyph,
            onSelect: () => { onNavigate(r.route); commitRecent(r.id); onClose(); },
          };
        }
        return null;
      };
      for (const id of recentIds) {
        const found = findById(id);
        if (found) out.push(found);
      }
    }

    // ·· routes ··
    for (const r of ROUTES) {
      if (!fuzzy(r.label, q)) continue;
      out.push({
        id: r.id, section: "routes", label: r.label, glyph: r.glyph,
        onSelect: () => { onNavigate(r.route); commitRecent(r.id); onClose(); },
      });
    }

    // ·· tenants ··
    for (const t of tenants) {
      if (!fuzzy(t.display_name + " " + t.slug, q)) continue;
      out.push({
        id: `tenant:${t.slug}`, section: "tenants",
        label: t.display_name, glyph: "▣",
        subtitle: t.slug,
        onSelect: () => {
          onNavigate(`/search/events?tenant=${encodeURIComponent(t.slug)}`);
          onClose();
        },
      });
    }

    // ·· help ··
    for (const h of HELP_ITEMS) {
      if (!fuzzy(h.label, q)) continue;
      out.push({
        id: h.id, section: "help", label: h.label, glyph: h.glyph,
        onSelect: () => { onHelp?.(h.action); onClose(); },
      });
    }

    return out;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, recentIds, tenants, onNavigate, onClose, onHelp]);

  const commitRecent = useCallback((id: string): void => {
    setRecentIds((prev) => {
      const next = [id, ...prev.filter((x) => x !== id)].slice(0, 5);
      saveRecent(next);
      return next;
    });
  }, []);

  // Keep selection in bounds when filtering.
  useEffect(() => {
    if (selected >= items.length) setSelected(Math.max(0, items.length - 1));
  }, [items.length, selected]);

  // Global Cmd+K / Ctrl+K listener. Parent decides whether to render.
  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (!open) return;
      if (e.key === "Escape") { e.preventDefault(); onClose(); return; }
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelected((s) => Math.min(items.length - 1, s + 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelected((s) => Math.max(0, s - 1));
      } else if (e.key === "Enter") {
        e.preventDefault();
        items[selected]?.onSelect();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, items, selected, onClose]);

  if (!open) return null;

  // Group by section for rendering.
  const sections = new Map<string, FlatItem[]>();
  for (const it of items) {
    const list = sections.get(it.section) ?? [];
    list.push(it);
    sections.set(it.section, list);
  }
  const sectionOrder = ["recent", "routes", "tenants", "events", "help"];

  let flatIdx = -1;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      className="fixed inset-0 z-50 flex items-start justify-center bg-bg-deep/70 pt-[15vh] backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl overflow-hidden rounded-md border border-border-bright bg-bg-elevated shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="border-b border-border px-3 py-2">
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type a command…"
            className="w-full bg-transparent font-mono text-sm text-text-primary placeholder:text-text-dim focus:outline-none"
          />
        </div>
        <div ref={listRef} className="max-h-[60vh] overflow-y-auto py-1">
          {items.length === 0 ? (
            <div className="px-4 py-6 text-center text-xs text-text-dim">
              No matches
            </div>
          ) : sectionOrder.flatMap((sec) => {
            const list = sections.get(sec);
            if (!list || list.length === 0) return [];
            return (
              <div key={sec} className="px-2 py-1">
                <div className="px-2 py-1 font-mono text-[10px] uppercase tracking-[0.2em] text-text-dim">
                  ·· {sec} ··
                </div>
                {list.map((it) => {
                  flatIdx++;
                  const isActive = flatIdx === selected;
                  return (
                    <button
                      key={it.id}
                      type="button"
                      onClick={it.onSelect}
                      onMouseEnter={() => setSelected(items.indexOf(it))}
                      className={[
                        "flex w-full items-center gap-3 rounded-sm border-l-2 px-3 py-1.5 text-left font-mono text-xs transition-colors",
                        isActive
                          ? "border-accent bg-accent-soft text-accent"
                          : "border-transparent text-text-secondary hover:bg-bg-card",
                      ].join(" ")}
                    >
                      <span aria-hidden="true" className="w-4 text-center">{it.glyph}</span>
                      <span className="flex-1">{it.label}</span>
                      {it.subtitle && (
                        <span className="text-text-dim">{it.subtitle}</span>
                      )}
                    </button>
                  );
                })}
              </div>
            );
          })}
        </div>
        <div className="flex items-center justify-between border-t border-border bg-bg-card px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-text-dim">
          <span>↑↓ navigate · ↵ select · esc close</span>
          <span>Cmd+K · Ctrl+K</span>
        </div>
      </div>
    </div>
  );
};

export default CommandPalette;
