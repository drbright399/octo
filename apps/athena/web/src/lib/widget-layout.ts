/**
 * Widget layout state — operator-customizable arrangement of dashboard
 * widgets. Persisted to localStorage per operator (keyed by username
 * once `me` resolves; falls back to a shared default key for anonymous).
 *
 * Schema is forward-compatible: unknown widget IDs in stored layout are
 * dropped at load time, and widgets defined by the dashboard but absent
 * from stored layout are appended at the end with default state.
 */

import { useEffect, useState } from "react";

export interface WidgetLayoutEntry {
  readonly id: string;
  readonly visible: boolean;
  readonly minimized: boolean;
  // Grid placement + size (units of the 12-column grid). Optional so
  // older stored layouts (pre-2026-05-12) still parse cleanly — missing
  // values fall back to per-widget defaults the dashboard supplies.
  readonly x?: number;
  readonly y?: number;
  readonly w?: number;
  readonly h?: number;
}

export interface WidgetLayout {
  readonly entries: ReadonlyArray<WidgetLayoutEntry>;
}

/** Optional defaults the dashboard hands in alongside the canonical id list. */
export interface WidgetDefault {
  readonly id: string;
  readonly w: number;
  readonly h: number;
}

// Bumped to v2 on 2026-05-12 when the grid swapped to react-grid-layout
// (extends schema with x/y/w/h). v1 entries are ignored — operators get
// a fresh flow-layout on first load, then their drags persist into v2.
const STORAGE_KEY_PREFIX = "athena.widget-layout.v2.";

function isValidEntry(v: unknown): v is WidgetLayoutEntry {
  if (typeof v !== "object" || v === null) return false;
  const e = v as Partial<WidgetLayoutEntry>;
  if (
    typeof e.id !== "string" ||
    typeof e.visible !== "boolean" ||
    typeof e.minimized !== "boolean"
  ) {
    return false;
  }
  // Optional grid fields — if present, must be finite numbers.
  for (const k of ["x", "y", "w", "h"] as const) {
    const val = e[k];
    if (val !== undefined && (typeof val !== "number" || !Number.isFinite(val))) {
      return false;
    }
  }
  return true;
}

function storageKey(profile: string | null): string {
  return STORAGE_KEY_PREFIX + (profile || "default");
}

function readStored(profile: string | null): WidgetLayout | null {
  try {
    const raw = window.localStorage.getItem(storageKey(profile));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== "object" || parsed === null) return null;
    const obj = parsed as { entries?: unknown };
    if (!Array.isArray(obj.entries)) return null;
    const entries = obj.entries.filter(isValidEntry);
    return { entries };
  } catch {
    return null;
  }
}

function writeStored(profile: string | null, layout: WidgetLayout): void {
  try {
    window.localStorage.setItem(
      storageKey(profile),
      JSON.stringify(layout),
    );
  } catch {
    /* localStorage unavailable */
  }
}

export function reconcileLayout(
  stored: WidgetLayout | null,
  canonical: ReadonlyArray<{ id: string }>,
): WidgetLayout {
  const canonicalIds = new Set(canonical.map((c) => c.id));
  const seen = new Set<string>();
  const entries: WidgetLayoutEntry[] = [];

  if (stored) {
    for (const e of stored.entries) {
      if (!canonicalIds.has(e.id) || seen.has(e.id)) continue;
      seen.add(e.id);
      entries.push(e);
    }
  }
  for (const c of canonical) {
    if (seen.has(c.id)) continue;
    entries.push({
      id: c.id,
      visible: true,
      minimized: false,
    });
  }
  return { entries };
}

export interface UseWidgetLayoutReturn {
  readonly layout: WidgetLayout;
  readonly reorder: (fromId: string, toId: string) => void;
  readonly toggleMinimized: (id: string) => void;
  readonly hide: (id: string) => void;
  readonly restore: (id: string) => void;
  readonly resetToDefaults: () => void;
  /** Bulk-set grid placement for every visible non-minimized widget.
   * Called after a react-grid-layout drag/resize completes. */
  readonly setGridPlacement: (
    placements: ReadonlyArray<{ id: string; x: number; y: number; w: number; h: number }>,
  ) => void;
}

export function useWidgetLayout(
  canonical: ReadonlyArray<{ id: string }>,
  profile: string | null,
): UseWidgetLayoutReturn {
  const [layout, setLayout] = useState<WidgetLayout>(() =>
    reconcileLayout(readStored(profile), canonical),
  );

  useEffect(() => {
    setLayout(reconcileLayout(readStored(profile), canonical));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile, canonical.length]);

  const persist = (next: WidgetLayout): void => {
    setLayout(next);
    writeStored(profile, next);
  };

  return {
    layout,
    reorder: (fromId, toId) => {
      const fromIdx = layout.entries.findIndex((e) => e.id === fromId);
      const toIdx = layout.entries.findIndex((e) => e.id === toId);
      if (fromIdx < 0 || toIdx < 0 || fromIdx === toIdx) return;
      const next = layout.entries.slice();
      const [moved] = next.splice(fromIdx, 1);
      if (!moved) return;
      next.splice(toIdx, 0, moved);
      persist({ entries: next });
    },
    toggleMinimized: (id) => {
      const next = layout.entries.map((e) =>
        e.id === id ? { ...e, minimized: !e.minimized } : e,
      );
      persist({ entries: next });
    },
    hide: (id) => {
      const next = layout.entries.map((e) =>
        e.id === id ? { ...e, visible: false } : e,
      );
      persist({ entries: next });
    },
    restore: (id) => {
      const next = layout.entries.map((e) =>
        e.id === id ? { ...e, visible: true } : e,
      );
      persist({ entries: next });
    },
    resetToDefaults: () => {
      const fresh = reconcileLayout(null, canonical);
      persist(fresh);
    },
    setGridPlacement: (placements) => {
      const placementById = new Map(placements.map((p) => [p.id, p]));
      const next = layout.entries.map((e) => {
        const p = placementById.get(e.id);
        if (!p) return e;
        return { ...e, x: p.x, y: p.y, w: p.w, h: p.h };
      });
      persist({ entries: next });
    },
  };
}
