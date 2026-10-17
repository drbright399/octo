/**
 * /tickets — operator daily-work surface.
 *
 * Lists tickets across the operator's in-scope tenants. Click a row to
 * open the detail in either:
 *
 *   - FloatingTicketWindow (Autotask-style draggable pop-out) — default
 *   - TicketDrawer (right-side slide-out)
 *
 * Open-mode preference is operator-local, persisted to localStorage
 * (`athena.ticket_window_mode`) so it survives reloads but doesn't
 * need a server endpoint yet. When per-operator server-side prefs land
 * (Task #104 follow-up), this key migrates into the same prefs API.
 *
 * Phase 1: list + filter (status, assignee), pop-out detail with
 * status transitions. Multi-window stacking, AI sidecar, secure
 * notepad, and Autotask round-trip are Phase 2+ scope.
 */
import { type FC, useCallback, useEffect, useMemo, useState } from "react";

import {
  type AgentActivityItem,
  type TicketDetail,
  type TicketListResponse,
  type TicketStatus,
  type TicketSummary,
  type TicketBulkPatchResponse,
  agentNoteKindChip,
  bulkPatchTickets,
  fetchAgentActivity,
  listTickets,
  getTicket,
} from "@/lib/tickets";
import {
  FloatingTicketWindow,
  TicketDrawer,
} from "@/components/floating-ticket-window";
import { AgentNoteWindow } from "@/components/agent-note-window";
import NewTicketModal, { type NewTicketPrefill } from "@/components/new-ticket-modal";
import AgentStatusPill from "@/components/agent-status-pill";

type WindowMode = "floating" | "drawer";

const STORAGE_KEY = "athena.ticket_window_mode";

const STATUS_FILTERS: { value: "open" | "closed" | "all"; label: string }[] = [
  { value: "open",   label: "Open" },
  { value: "closed", label: "Closed" },
  { value: "all",    label: "All" },
];

const SEVERITY_DOT: Record<string, string> = {
  info:     "bg-text-dim",
  low:      "bg-text-secondary",
  medium:   "bg-medium",
  high:     "bg-high",
  critical: "bg-critical",
};

const STATUS_BADGE: Record<TicketStatus, string> = {
  new:               "border-accent/60       text-accent",
  in_progress:       "border-high/60         text-high",
  waiting_customer:  "border-medium/60       text-medium",
  waiting_vendor:    "border-medium/60       text-medium",
  resolved:          "border-border-bright   text-text-secondary",
  closed:            "border-border          text-text-dim",
  reopened:          "border-critical/60     text-critical",
};

// Severity ranked so "sort by severity desc" puts critical at top.
const SEVERITY_RANK: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
};

// Status ranked so "sort by status" groups the open-ones first.
const STATUS_RANK: Record<TicketStatus, number> = {
  new: 7, reopened: 6, in_progress: 5,
  waiting_customer: 4, waiting_vendor: 3,
  resolved: 2, closed: 1,
};

type SortKey = "severity" | "id" | "tenant" | "title" | "status" | "assignee" | "updated_at";
type SortDir = "asc" | "desc";
interface SortState { key: SortKey; dir: SortDir }

// For severity / updated / id, the natural first-click direction is
// DESC (top severity first, newest first, highest id first). For
// alpha fields it's ASC.
const defaultDirFor = (key: SortKey): SortDir =>
  (key === "severity" || key === "updated_at" || key === "id" || key === "status")
    ? "desc"
    : "asc";

const sortTickets = (rows: TicketSummary[], s: SortState): TicketSummary[] => {
  const mul = s.dir === "asc" ? 1 : -1;
  const cmp = (a: TicketSummary, b: TicketSummary): number => {
    switch (s.key) {
      case "severity":   return mul * ((SEVERITY_RANK[a.severity] ?? 0) - (SEVERITY_RANK[b.severity] ?? 0));
      case "id":         return mul * (a.id - b.id);
      case "tenant":     return mul * a.client_slug.localeCompare(b.client_slug);
      case "title":      return mul * a.title.localeCompare(b.title);
      case "status":     return mul * ((STATUS_RANK[a.status] ?? 0) - (STATUS_RANK[b.status] ?? 0));
      case "assignee": {
        // null assignees sorted last regardless of direction.
        const aHas = a.assignee_operator_id !== null;
        const bHas = b.assignee_operator_id !== null;
        if (!aHas && !bHas) return 0;
        if (!aHas) return 1;
        if (!bHas) return -1;
        return mul * ((a.assignee_operator_id ?? 0) - (b.assignee_operator_id ?? 0));
      }
      case "updated_at": return mul * a.updated_at.localeCompare(b.updated_at);
    }
  };
  return [...rows].sort(cmp);
};

const loadWindowMode = (): WindowMode => {
  try {
    const v = window.localStorage.getItem(STORAGE_KEY);
    return v === "drawer" ? "drawer" : "floating";
  } catch {
    return "floating";
  }
};

const saveWindowMode = (mode: WindowMode): void => {
  try { window.localStorage.setItem(STORAGE_KEY, mode); } catch { /* ignore */ }
};

const SEVERITY_FILTER_OPTIONS = ["info", "low", "medium", "high", "critical"] as const;

const TicketsPage: FC = () => {
  const [statusFilter, setStatusFilter] = useState<"open" | "closed" | "all">("open");
  const [assigneeFilter, setAssigneeFilter] = useState<"all" | "me">("all");
  const [tenantFilter, setTenantFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<Set<string>>(() => new Set());
  const [queueFilter, setQueueFilter] = useState<string>("");
  const [searchTerm, setSearchTerm] = useState<string>("");
  // Debounced echo of searchTerm — keeps the filter rail from
  // firing a request on every keystroke.
  const [searchDebounced, setSearchDebounced] = useState<string>("");
  const [windowMode, setWindowMode] = useState<WindowMode>(loadWindowMode);
  const [sort, setSort] = useState<SortState>({ key: "updated_at", dir: "desc" });

  useEffect(() => {
    const t = window.setTimeout(() => setSearchDebounced(searchTerm), 300);
    return () => window.clearTimeout(t);
  }, [searchTerm]);

  const [list, setList] = useState<TicketListResponse | null>(null);
  const [listLoading, setListLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);

  const [agentActivity, setAgentActivity] = useState<AgentActivityItem[]>([]);
  const [agentActivityError, setAgentActivityError] = useState<string | null>(null);

  const [openTicket, setOpenTicket] = useState<TicketDetail | null>(null);
  const [openLoading, setOpenLoading] = useState(false);
  const [openError, setOpenError] = useState<string | null>(null);

  const [openAgentNote, setOpenAgentNote] = useState<AgentActivityItem | null>(null);

  const [newTicketOpen, setNewTicketOpen] = useState(false);
  const [newTicketPrefill, setNewTicketPrefill] = useState<NewTicketPrefill | null>(null);
  // A prefill captured BEFORE the tickets list loads — held here until
  // `list` (and therefore `list.tenants_searched`) is available, then
  // promoted to the open-modal state. Without this gate, the modal
  // would open against an empty `tenants` array, the prefill tenant
  // would fail `tenants.includes()`, and the modal would land on the
  // empty default → submit fails with "tenant required".
  const [pendingPrefill, setPendingPrefill] = useState<NewTicketPrefill | null>(null);

  // Promote a pending prefill once tenants are loaded. If the prefill
  // tenant isn't in the operator's scope (`tenants_searched`), surface
  // a clear error rather than silently dropping it.
  useEffect(() => {
    if (!pendingPrefill || !list) return;
    const inScope = list.tenants_searched.includes(pendingPrefill.tenant ?? "");
    if (!inScope) {
      // eslint-disable-next-line no-console
      console.warn(
        "[tickets] discarded create-from-alert prefill: tenant",
        pendingPrefill.tenant,
        "is not in operator scope",
      );
      setPendingPrefill(null);
      return;
    }
    setNewTicketPrefill(pendingPrefill);
    setNewTicketOpen(true);
    setPendingPrefill(null);
  }, [pendingPrefill, list]);

  // Consume the "create from alert" hand-off stash set by alert-drawer.
  // Pattern: dashboard alert drawer puts a structured prefill into
  // localStorage, then navigates to /tickets. We read + clear it on
  // mount AND on every athena:navigate event so a cross-link from an
  // already-mounted /tickets page also works.
  useEffect(() => {
    const consumePrefill = (): void => {
      let raw: string | null = null;
      try { raw = window.localStorage.getItem("athena.tickets.create_from_alert"); }
      catch { return; }
      if (!raw) return;
      try {
        const parsed = JSON.parse(raw) as NewTicketPrefill;
        window.localStorage.removeItem("athena.tickets.create_from_alert");
        setPendingPrefill(parsed);
      } catch {
        try { window.localStorage.removeItem("athena.tickets.create_from_alert"); }
        catch { /* ignore */ }
      }
    };
    consumePrefill();
    window.addEventListener("athena:navigate", consumePrefill);
    return () => window.removeEventListener("athena:navigate", consumePrefill);
  }, []);

  // Bulk-select — Set of "slug:id" keys for ticked rows. Used to
  // power the bulk-action bar that surfaces above the table.
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkError, setBulkError] = useState<string | null>(null);
  const [bulkResult, setBulkResult] = useState<TicketBulkPatchResponse | null>(null);

  const toggleSelected = useCallback((key: string): void => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }, []);

  const clearSelected = useCallback((): void => {
    setSelected(new Set());
    setBulkResult(null);
    setBulkError(null);
  }, []);

  const runBulk = useCallback(async (
    patch: Parameters<typeof bulkPatchTickets>[1],
  ): Promise<void> => {
    if (selected.size === 0) return;
    setBulkBusy(true);
    setBulkError(null);
    setBulkResult(null);
    try {
      const refs = Array.from(selected).map((key) => {
        const [slug, idStr] = key.split(":");
        return { slug: slug ?? "", ticket_id: parseInt(idStr ?? "0", 10) };
      });
      const result = await bulkPatchTickets(refs, patch);
      setBulkResult(result);
      // If everything succeeded, clear the selection. If any failed,
      // keep selection so operator can see which row failed.
      if (result.failed === 0) setSelected(new Set());
      void refresh();
    } catch (e) {
      setBulkError(e instanceof Error ? e.message : String(e));
    } finally {
      setBulkBusy(false);
    }
    // refresh is stable enough; selected deps are read-only inside.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  const refresh = useCallback(async (): Promise<void> => {
    setListLoading(true);
    setListError(null);
    try {
      const params: Parameters<typeof listTickets>[0] = {
        status: statusFilter,
        pageSize: 100,
      };
      if (assigneeFilter === "me") params.assignee = "me";
      if (tenantFilter) params.tenant = tenantFilter;
      if (severityFilter.size > 0) {
        params.severity = Array.from(severityFilter).join(",");
      }
      if (queueFilter.trim()) params.queue = queueFilter.trim();
      if (searchDebounced.trim()) params.q = searchDebounced.trim();
      const r = await listTickets(params);
      setList(r);
    } catch (e) {
      setListError(e instanceof Error ? e.message : String(e));
    } finally {
      setListLoading(false);
    }
  }, [statusFilter, assigneeFilter, tenantFilter, severityFilter,
      queueFilter, searchDebounced]);

  useEffect(() => { void refresh(); }, [refresh]);

  // Cross-link handoff: /search drawer stashes `athena.tickets.focus`
  // = "<slug>:<id>" in localStorage before navigating here. Drain it
  // once on mount and auto-open that ticket. Stash is single-use —
  // drop the key after consuming so a regular reload doesn't keep
  // re-opening the same window.
  useEffect(() => {
    try {
      const focus = window.localStorage.getItem("athena.tickets.focus");
      if (!focus) return;
      window.localStorage.removeItem("athena.tickets.focus");
      const idx = focus.lastIndexOf(":");
      if (idx <= 0) return;
      const slug = focus.slice(0, idx);
      const id = Number(focus.slice(idx + 1));
      if (slug && Number.isFinite(id)) {
        void openTicketById(slug, id);
      }
    } catch { /* localStorage unavailable — silently skip */ }
    // intentionally empty deps — runs once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Agent activity feed — independent fetch + poll. Lives separately
  // because it spans all of the operator's tenants regardless of
  // filter state on the main table, and refreshes on its own cadence
  // (15s) so the operator can see octo working in real time without
  // refetching the whole ticket list.
  const refreshAgentActivity = useCallback(async (): Promise<void> => {
    try {
      const r = await fetchAgentActivity({ limit: 10 });
      setAgentActivity(r.items);
      setAgentActivityError(null);
    } catch (e) {
      setAgentActivityError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void refreshAgentActivity();
    const t = window.setInterval(() => { void refreshAgentActivity(); }, 15_000);
    return () => { window.clearInterval(t); };
  }, [refreshAgentActivity]);

  /**
   * Primitive: open a ticket by (slug, id). Optionally pre-fills a
   * skeleton from a list row so the window can position before the
   * fetch completes. Used by:
   *   - row clicks on the main table or strip cards (skeleton seeded)
   *   - agent-triage feed clicks (no skeleton — ticket might not be
   *     in the current filtered list)
   */
  const openTicketById = async (
    slug: string, id: number, skeleton?: TicketSummary,
  ): Promise<void> => {
    setOpenLoading(true);
    setOpenError(null);
    if (skeleton) {
      setOpenTicket({
        ...skeleton,
        description: "",
        closed_at: null,
        last_autotask_sync_at: null,
        due_at: null,
        push_to_autotask: false,
        is_billable: true,
        billing_code_id: null,
        contract_id: null,
        charges: [],
        push_state: null,
        status_history: [],
        agent_insights: [],
        agent_pattern_links: [],
      });
    } else {
      // No skeleton — show a placeholder with just the id so the
      // window mounts and shows "loading…" until the detail arrives.
      setOpenTicket({
        id,
        client_slug: slug,
        autotask_id: null,
        title: `Ticket #${id}`,
        severity: "low",
        status: "new",
        assignee_operator_id: null,
        queue: null,
        source_event_id: null,
        opened_at: "",
        updated_at: "",
        agent_note_count: 0,
        description: "",
        closed_at: null,
        last_autotask_sync_at: null,
        due_at: null,
        push_to_autotask: false,
        is_billable: true,
        billing_code_id: null,
        contract_id: null,
        charges: [],
        push_state: null,
        status_history: [],
        agent_insights: [],
        agent_pattern_links: [],
      });
    }
    try {
      const t = await getTicket(slug, id);
      setOpenTicket(t);
    } catch (e) {
      setOpenError(e instanceof Error ? e.message : String(e));
    } finally {
      setOpenLoading(false);
    }
  };

  const onRowClick = async (row: TicketSummary): Promise<void> => {
    await openTicketById(row.client_slug, row.id, row);
  };

  const onTicketUpdated = (updated: TicketDetail): void => {
    setOpenTicket(updated);
    // Refresh list in the background so the row reflects the new state
    // when the operator closes the window.
    void refresh();
  };

  const setMode = (m: WindowMode): void => {
    setWindowMode(m);
    saveWindowMode(m);
  };

  const sortedTickets = useMemo(
    () => sortTickets(list?.tickets ?? [], sort),
    [list, sort],
  );

  // Always-recent strip — independent of the active sort. Takes the
  // 5 most-recently-updated tickets that pass the current filters, so
  // the operator can glance at "what just changed" without disturbing
  // the sorted list below.
  const recentTickets = useMemo(() => {
    const rows = [...(list?.tickets ?? [])];
    rows.sort((a, b) => b.updated_at.localeCompare(a.updated_at));
    return rows.slice(0, 5);
  }, [list]);

  // Newly-arrived strip — 5 most-recently-opened tickets (by
  // opened_at). Distinct from recentTickets, which tracks
  // last-edited; this answers "what's NEW" rather than "what
  // changed". Important because incoming alerts are the supply side
  // of the auto-noise-dismissal loop.
  const newlyCreatedTickets = useMemo(() => {
    const rows = [...(list?.tickets ?? [])];
    rows.sort((a, b) => b.opened_at.localeCompare(a.opened_at));
    return rows.slice(0, 5);
  }, [list]);

  const toggleSort = (key: SortKey): void => {
    setSort((prev) =>
      prev.key === key
        ? { key, dir: prev.dir === "asc" ? "desc" : "asc" }
        : { key, dir: defaultDirFor(key) },
    );
  };

  return (
    <section className="flex h-full min-h-0 flex-col gap-4 p-6">
      <header className="flex items-baseline justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold uppercase tracking-wider text-text-primary">
            ▤ tickets
          </h1>
          <p className="text-[11px] text-text-dim">
            operator daily-work surface · {list?.tenants_searched.length ?? 0} tenant(s) in scope
          </p>
        </div>
        <div className="flex items-center gap-4">
          <button
            type="button"
            onClick={() => setNewTicketOpen(true)}
            className="rounded-sm border border-accent bg-accent px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-text-on-accent hover:bg-accent/80"
          >
            + new ticket
          </button>
          <FilterChip
            label="status"
            value={statusFilter}
            options={STATUS_FILTERS}
            onChange={(v) => setStatusFilter(v as "open" | "closed" | "all")}
          />
          <FilterChip
            label="assignee"
            value={assigneeFilter}
            options={[
              { value: "all", label: "Any" },
              { value: "me",  label: "Mine" },
            ]}
            onChange={(v) => setAssigneeFilter(v as "all" | "me")}
          />
          <FilterChip
            label="open as"
            value={windowMode}
            options={[
              { value: "floating", label: "Window" },
              { value: "drawer",   label: "Drawer" },
            ]}
            onChange={(v) => setMode(v as WindowMode)}
          />
        </div>
      </header>

      {/* Dispatch filter rail — severity multi-pick, tenant picker, queue
          exact-match, free-text search. Decoupled from the header's
          filter chips so it doesn't crowd the small ones. */}
      <div className="flex flex-wrap items-center gap-3 rounded-sm border border-border bg-bg-surface px-3 py-2 text-[11px]">
        <input
          type="search"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search title or description…"
          aria-label="Search tickets"
          className="min-w-[220px] flex-1 rounded-sm border border-border bg-bg-card px-2 py-1 text-text-primary focus:border-accent focus:outline-none"
        />
        <select
          value={tenantFilter}
          onChange={(e) => setTenantFilter(e.target.value)}
          aria-label="Tenant filter"
          className="rounded-sm border border-border bg-bg-card px-2 py-1 text-text-primary focus:border-accent focus:outline-none"
        >
          <option value="">all tenants</option>
          {(list?.tenants_searched ?? []).map((slug) => (
            <option key={slug} value={slug}>{slug}</option>
          ))}
        </select>
        <input
          type="text"
          value={queueFilter}
          onChange={(e) => setQueueFilter(e.target.value)}
          placeholder="queue"
          aria-label="Queue filter"
          className="w-28 rounded-sm border border-border bg-bg-card px-2 py-1 text-text-primary focus:border-accent focus:outline-none"
        />
        <div className="flex items-center gap-1" role="group" aria-label="Severity filter">
          <span className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
            sev
          </span>
          {SEVERITY_FILTER_OPTIONS.map((s) => {
            const active = severityFilter.has(s);
            return (
              <button
                key={s}
                type="button"
                aria-pressed={active}
                onClick={() => setSeverityFilter((prev) => {
                  const next = new Set(prev);
                  if (next.has(s)) next.delete(s); else next.add(s);
                  return next;
                })}
                className={[
                  "rounded-sm border px-2 py-0.5 font-mono text-[10px] uppercase transition-colors",
                  active
                    ? "border-accent bg-accent/15 text-accent"
                    : "border-border bg-bg-card text-text-secondary hover:border-border-bright",
                ].join(" ")}
              >
                {s}
              </button>
            );
          })}
        </div>
        {(searchTerm || tenantFilter || queueFilter || severityFilter.size > 0) && (
          <button
            type="button"
            onClick={() => {
              setSearchTerm("");
              setTenantFilter("");
              setQueueFilter("");
              setSeverityFilter(new Set());
            }}
            className="rounded-sm border border-border bg-bg-card px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-text-dim hover:text-text-primary"
          >
            clear
          </button>
        )}
      </div>

      {!listLoading && !listError && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          {newlyCreatedTickets.length > 0 && (
            <RecentTicketsStrip
              title="·· newly arrived ··"
              subtitle="5 most-recently-opened"
              tickets={newlyCreatedTickets}
              accentDot
              onPick={(t) => void onRowClick(t)}
            />
          )}
          {recentTickets.length > 0 && (
            <RecentTicketsStrip
              title="·· recently edited ··"
              subtitle="5 most-recent updates"
              tickets={recentTickets}
              onPick={(t) => void onRowClick(t)}
            />
          )}
        </div>
      )}

      {!listLoading && !listError && (
        <AgentActivityFeed
          items={agentActivity}
          error={agentActivityError}
          onPick={(it) => setOpenAgentNote(it)}
          onOpenLinkedTicket={(slug, id) => {
            const match = (list?.tickets ?? []).find(
              (t) => t.client_slug === slug && t.id === id,
            );
            void openTicketById(slug, id, match);
          }}
        />
      )}

      {selected.size > 0 && (
        <BulkActionBar
          count={selected.size}
          busy={bulkBusy}
          error={bulkError}
          result={bulkResult}
          onApply={(patch) => void runBulk(patch)}
          onClear={clearSelected}
        />
      )}

      <div className="flex-1 overflow-auto rounded-sm border border-border bg-bg-surface">
        {listLoading && <div className="p-4 text-[11px] text-text-dim">loading…</div>}
        {listError && <div className="p-4 text-[11px] text-critical">{listError}</div>}
        {!listLoading && !listError && sortedTickets.length === 0 && (
          <div className="p-4 text-[11px] text-text-dim">
            No tickets match the current filters.
          </div>
        )}
        {!listLoading && !listError && sortedTickets.length > 0 && (
          <table className="w-full border-collapse text-[11px]">
            <thead>
              <tr className="border-b border-border bg-bg-card text-left text-[10px] uppercase tracking-widest text-text-dim">
                <th className="px-3 py-2">
                  <input
                    type="checkbox"
                    aria-label="Select all visible tickets"
                    checked={sortedTickets.length > 0 && sortedTickets.every(
                      (t) => selected.has(`${t.client_slug}:${t.id}`),
                    )}
                    onChange={(e) => {
                      e.stopPropagation();
                      if (e.target.checked) {
                        setSelected(new Set(
                          sortedTickets.map((t) => `${t.client_slug}:${t.id}`),
                        ));
                      } else {
                        clearSelected();
                      }
                    }}
                    onClick={(e) => e.stopPropagation()}
                    className="h-3 w-3 accent-accent"
                  />
                </th>
                <SortableHeader col="severity"   label="sev"      sort={sort} onClick={toggleSort} />
                <th className="px-3 py-2 font-mono" title="agent has weighed in">
                  <span aria-hidden="true">⚙</span>
                </th>
                <SortableHeader col="id"         label="id"       sort={sort} onClick={toggleSort} />
                <SortableHeader col="tenant"     label="tenant"   sort={sort} onClick={toggleSort} />
                <SortableHeader col="title"      label="title"    sort={sort} onClick={toggleSort} />
                <SortableHeader col="status"     label="status"   sort={sort} onClick={toggleSort} />
                <SortableHeader col="assignee"   label="assignee" sort={sort} onClick={toggleSort} />
                <SortableHeader col="updated_at" label="updated"  sort={sort} onClick={toggleSort} />
              </tr>
            </thead>
            <tbody>
              {sortedTickets.map((t) => {
                const key = `${t.client_slug}:${t.id}`;
                const isSelected = selected.has(key);
                return (
                <tr
                  key={`${t.client_slug}-${t.id}`}
                  data-keeps-window-open
                  onClick={() => void onRowClick(t)}
                  className={[
                    "cursor-pointer border-b border-border/60 transition-colors hover:bg-bg-card-hover",
                    isSelected ? "bg-accent/5" : "",
                  ].join(" ")}
                >
                  <td className="px-3 py-2">
                    <input
                      type="checkbox"
                      aria-label={`Select ticket #${t.id}`}
                      checked={isSelected}
                      onClick={(e) => e.stopPropagation()}
                      onChange={(e) => {
                        e.stopPropagation();
                        toggleSelected(key);
                      }}
                      className="h-3 w-3 accent-accent"
                    />
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className={[
                        "inline-block h-2 w-2 rounded-full",
                        SEVERITY_DOT[t.severity] || SEVERITY_DOT.low,
                      ].join(" ")}
                      aria-label={t.severity}
                    />
                  </td>
                  <td className="px-3 py-2">
                    {t.agent_note_count > 0 ? (
                      <span
                        title={`${t.agent_note_count} agent note${t.agent_note_count > 1 ? "s" : ""}`}
                        className="inline-flex items-center gap-0.5 rounded-sm border border-accent/60 bg-accent/10 px-1 py-0.5 font-mono text-[9px] uppercase tracking-wider text-accent"
                      >
                        ⚙ {t.agent_note_count}
                      </span>
                    ) : (
                      <span className="text-text-dim" aria-hidden="true">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-text-secondary">#{t.id}</td>
                  <td className="px-3 py-2 font-mono text-text-secondary">{t.client_slug}</td>
                  <td className="px-3 py-2 text-text-primary">{t.title}</td>
                  <td className="px-3 py-2">
                    <span
                      className={[
                        "rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase",
                        STATUS_BADGE[t.status] || "border-border text-text-dim",
                      ].join(" ")}
                    >
                      {t.status.replace(/_/g, " ")}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-text-dim">
                    {t.assignee_operator_id !== null
                      ? `#${t.assignee_operator_id}`
                      : (t.queue || "—")}
                  </td>
                  <td className="px-3 py-2 font-mono text-text-dim">{t.updated_at}</td>
                </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {openTicket !== null && (
        windowMode === "floating" ? (
          <FloatingTicketWindow
            ticket={openTicket}
            loading={openLoading}
            error={openError}
            onClose={() => { setOpenTicket(null); setOpenError(null); }}
            onUpdated={onTicketUpdated}
          />
        ) : (
          <TicketDrawer
            ticket={openTicket}
            loading={openLoading}
            error={openError}
            onClose={() => { setOpenTicket(null); setOpenError(null); }}
            onUpdated={onTicketUpdated}
          />
        )
      )}

      {newTicketOpen && (
        <NewTicketModal
          tenants={list?.tenants_searched ?? []}
          prefill={newTicketPrefill ?? undefined}
          onClose={() => {
            setNewTicketOpen(false);
            setNewTicketPrefill(null);
          }}
          onCreated={(t) => {
            setNewTicketOpen(false);
            setNewTicketPrefill(null);
            // Drop the new ticket straight into the open-window /
            // drawer so the operator lands on the surface they were
            // filling out, then refresh the list in the background.
            setOpenTicket(t);
            void refresh();
          }}
        />
      )}

      {openAgentNote && (
        <AgentNoteWindow
          item={openAgentNote}
          onClose={() => setOpenAgentNote(null)}
          onOpenTicket={(slug, id) => {
            setOpenAgentNote(null);
            const match = (list?.tickets ?? []).find(
              (t) => t.client_slug === slug && t.id === id,
            );
            void openTicketById(slug, id, match);
          }}
          onOpenEvent={(slug, id) => {
            // Navigate to /search with the event ref queued. The
            // search page reads `?focus=<slug>:<id>` on mount and
            // pre-opens the payload drawer. Step-up auth happens
            // there (search is the gated surface, not tickets).
            setOpenAgentNote(null);
            window.history.pushState(
              {}, "",
              `/search/events?focus=${encodeURIComponent(slug)}:${id}`,
            );
            window.dispatchEvent(new Event("athena:navigate"));
          }}
        />
      )}
    </section>
  );
};

interface ChipOption { value: string; label: string }

const BULK_STATUS_OPTIONS: TicketStatus[] = [
  "new", "in_progress", "waiting_customer", "waiting_vendor",
  "resolved", "closed", "reopened",
];
const BULK_SEVERITY_OPTIONS: ("info" | "low" | "medium" | "high" | "critical")[] = [
  "info", "low", "medium", "high", "critical",
];

interface BulkActionBarProps {
  count: number;
  busy: boolean;
  error: string | null;
  result: TicketBulkPatchResponse | null;
  onApply: (patch: Parameters<typeof bulkPatchTickets>[1]) => void;
  onClear: () => void;
}

const BulkActionBar: FC<BulkActionBarProps> = ({
  count, busy, error, result, onApply, onClear,
}) => {
  const [reason, setReason] = useState("");
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-sm border border-accent/60 bg-accent/10 px-3 py-2 text-[11px]">
      <span className="font-mono text-[10px] uppercase tracking-widest text-accent">
        {count} selected
      </span>

      <label className="flex items-center gap-1 font-mono text-[10px] uppercase tracking-widest text-text-dim">
        <span>set status</span>
        <select
          aria-label="Bulk set status"
          disabled={busy}
          defaultValue=""
          onChange={(e) => {
            const v = e.target.value as TicketStatus | "";
            if (!v) return;
            onApply({ status: v, reason: reason || `bulk status → ${v}` });
            e.target.value = "";
          }}
          className="rounded-sm border border-border bg-bg-card px-2 py-1 text-text-primary focus:border-accent focus:outline-none"
        >
          <option value="">—</option>
          {BULK_STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>{s.replace(/_/g, " ")}</option>
          ))}
        </select>
      </label>

      <label className="flex items-center gap-1 font-mono text-[10px] uppercase tracking-widest text-text-dim">
        <span>set severity</span>
        <select
          aria-label="Bulk set severity"
          disabled={busy}
          defaultValue=""
          onChange={(e) => {
            const v = e.target.value as typeof BULK_SEVERITY_OPTIONS[number] | "";
            if (!v) return;
            onApply({ severity: v, reason: reason || `bulk severity → ${v}` });
            e.target.value = "";
          }}
          className="rounded-sm border border-border bg-bg-card px-2 py-1 text-text-primary focus:border-accent focus:outline-none"
        >
          <option value="">—</option>
          {BULK_SEVERITY_OPTIONS.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </label>

      <input
        type="text"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        disabled={busy}
        placeholder="reason (optional)"
        aria-label="Bulk reason"
        className="min-w-[160px] flex-1 rounded-sm border border-border bg-bg-card px-2 py-1 text-text-primary focus:border-accent focus:outline-none"
      />

      <button
        type="button"
        onClick={onClear}
        disabled={busy}
        className="rounded-sm border border-border bg-bg-card px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-text-dim hover:text-text-primary disabled:opacity-50"
      >
        clear
      </button>

      {busy && <span className="text-text-dim">applying…</span>}
      {error && <span className="text-critical">{error}</span>}
      {result && (
        <span className={result.failed > 0 ? "text-critical" : "text-text-secondary"}>
          {result.succeeded} ok · {result.failed} failed
        </span>
      )}
    </div>
  );
};

const FilterChip: FC<{
  label: string;
  value: string;
  options: ChipOption[];
  onChange: (v: string) => void;
}> = ({ label, value, options, onChange }) => (
  <label className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-text-dim">
    <span>{label}</span>
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="cursor-pointer rounded-sm border border-border bg-bg-surface px-2 py-1 text-[10px] text-accent transition-colors hover:border-border-bright focus:outline-none"
    >
      {options.map((o) => (
        <option key={o.value} value={o.value} className="bg-bg-surface text-text-primary">
          {o.label}
        </option>
      ))}
    </select>
  </label>
);

const SortableHeader: FC<{
  col: SortKey;
  label: string;
  sort: SortState;
  onClick: (col: SortKey) => void;
}> = ({ col, label, sort, onClick }) => {
  const active = sort.key === col;
  const arrow = active ? (sort.dir === "asc" ? "▲" : "▼") : "·";
  return (
    <th className="px-3 py-2 font-mono">
      <button
        type="button"
        onClick={() => onClick(col)}
        aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}
        className={[
          "inline-flex items-center gap-1 uppercase tracking-widest transition-colors hover:text-text-secondary",
          active ? "text-accent" : "text-text-dim",
        ].join(" ")}
      >
        <span>{label}</span>
        <span aria-hidden="true" className="text-[9px]">{arrow}</span>
      </button>
    </th>
  );
};

const RecentTicketsStrip: FC<{
  tickets: TicketSummary[];
  title: string;
  subtitle: string;
  onPick: (t: TicketSummary) => void;
  /** Highlights the leading bar with the accent color — used for the
   * "newly arrived" strip to draw the eye to incoming work. */
  accentDot?: boolean;
}> = ({ tickets, title, subtitle, onPick, accentDot }) => (
  <div className="rounded-sm border border-border bg-bg-surface">
    <div
      className={[
        "flex items-baseline justify-between border-b border-border bg-bg-card px-3 py-1.5",
        accentDot ? "border-l-2 border-l-accent" : "",
      ].join(" ")}
    >
      <span className="font-mono text-[10px] uppercase tracking-widest text-accent">
        {title}
      </span>
      <span className="font-mono text-[10px] text-text-dim">
        {subtitle}
      </span>
    </div>
    <div className="grid grid-cols-1 gap-2 p-2 md:grid-cols-2 xl:grid-cols-3">
      {tickets.map((t) => (
        <button
          key={`${t.client_slug}-${t.id}`}
          type="button"
          data-keeps-window-open
          onClick={() => onPick(t)}
          className="flex flex-col gap-1 rounded-sm border border-border bg-bg-card p-2 text-left transition-colors hover:border-accent/60"
        >
          <div className="flex items-center justify-between gap-2 font-mono text-[10px] uppercase tracking-wider">
            <span className="flex items-center gap-1.5">
              <span
                className={[
                  "inline-block h-1.5 w-1.5 rounded-full",
                  SEVERITY_DOT[t.severity] || SEVERITY_DOT.low,
                ].join(" ")}
                aria-label={t.severity}
              />
              <span className="text-text-secondary">#{t.id}</span>
            </span>
            {t.agent_note_count > 0 && (
              <span
                title={`${t.agent_note_count} agent note${t.agent_note_count > 1 ? "s" : ""}`}
                className="inline-flex items-center gap-0.5 rounded-sm border border-accent/60 bg-accent/10 px-1 text-[9px] text-accent"
              >
                ⚙ {t.agent_note_count}
              </span>
            )}
          </div>
          <div className="line-clamp-2 text-[11px] leading-snug text-text-primary">
            {t.title}
          </div>
          <div className="flex items-baseline justify-between gap-2 font-mono text-[10px] text-text-dim">
            <span className="truncate">{t.client_slug}</span>
            <span
              className={[
                "rounded-sm border px-1 py-0.5 text-[9px] uppercase",
                STATUS_BADGE[t.status] || "border-border",
              ].join(" ")}
            >
              {t.status.replace(/_/g, " ")}
            </span>
          </div>
        </button>
      ))}
    </div>
  </div>
);

/**
 * AgentActivityFeed — "what is octo working on right now" stream.
 *
 * Polls /api/v1/agent/activity every 15s (parent component handles
 * the timer). Each row shows the agent_id badge, what the agent
 * looked at (event/ticket/indicator), confidence, and a truncated
 * note. Clicking a ticket-row opens the ticket in the same
 * window/drawer mode the operator is using.
 *
 * Toward the noise-dismissal goal, this surface is the
 * trust-building layer under any future auto-close workflow: the
 * operator can see octo's reasoning at a glance and intervene early
 * if a rule is misbehaving.
 */
const AgentActivityFeed: FC<{
  items: AgentActivityItem[];
  error: string | null;
  /** Operator clicked a triage row — open the agent-note detail
   * window. Every row is clickable regardless of ref_kind; the detail
   * window provides the follow-up "open ticket" affordance when
   * applicable. */
  onPick: (item: AgentActivityItem) => void;
  /** Inline shortcut — operator clicked the small "→ ticket #N" pill
   * directly on the row, skipping the agent-note popup. */
  onOpenLinkedTicket: (slug: string, id: number) => void;
}> = ({ items, error, onPick, onOpenLinkedTicket }) => (
  <div className="rounded-sm border border-border bg-bg-surface">
    <div className="flex items-baseline justify-between border-b border-border bg-bg-card px-3 py-1.5">
      <span className="font-mono text-[10px] uppercase tracking-widest text-accent">
        ·· agent triage feed ··
      </span>
      <span className="flex items-center gap-2">
        <AgentStatusPill />
        <span className="font-mono text-[10px] text-text-dim">
          live · 15s · {items.length} recent
        </span>
      </span>
    </div>
    {error && (
      <div role="alert" className="px-3 py-2 text-[10px] text-critical">
        {error}
      </div>
    )}
    {!error && items.length === 0 && (
      <div className="px-3 py-2 text-[10px] text-text-dim">
        No recent agent activity. Once octo lands annotations they'll
        stream in here.
      </div>
    )}
    {!error && items.length > 0 && (
      <ol className="divide-y divide-border/60">
        {items.map((i, idx) => {
          // Resolve the cross-linked ticket — for ticket-kind entries
          // that's the entry's own ref; for event-kind, the derived
          // ticket if any.
          const xTicketId =
            i.ref_kind === "ticket" ? i.ref_id : i.linked_ticket_id;
          const subjectLabel =
            i.ref_kind === "ticket"
              ? `ticket #${i.ref_id}${i.linked_ticket_title ? ` · ${i.linked_ticket_title}` : ""}`
              : i.linked_ticket_id !== null
                ? `event #${i.ref_id} → ticket #${i.linked_ticket_id}${i.linked_ticket_title ? ` · ${i.linked_ticket_title}` : ""}`
                : `event #${i.ref_id}`;
          return (
            <li
              key={`${i.client_slug}-${i.ref_kind}-${i.ref_id}-${idx}`}
              data-keeps-window-open
              className="flex items-stretch"
            >
              <button
                type="button"
                onClick={() => onPick(i)}
                className="flex min-w-0 flex-1 flex-col gap-1 overflow-hidden px-3 py-2 text-left transition-colors hover:bg-bg-card-hover"
              >
                {/* Line 1 — agent + (optional ask-kind chip) + subject + when.
                    min-w-0 on the container is REQUIRED for flex-1 + truncate
                    to actually clip inside a flex parent (intrinsic content
                    size otherwise forces the container to grow). */}
                <div className="flex min-w-0 items-baseline gap-2 text-[10px]">
                  <span
                    className={[
                      "shrink-0 rounded-sm border px-1.5 py-0.5 font-mono uppercase tracking-wider",
                      i.agent_id === "octo"
                        ? "border-accent/60 text-accent"
                        : "border-high/60 text-high",
                    ].join(" ")}
                  >
                    {i.agent_id}
                  </span>
                  {/* query_kind chip — Slice 7d. "ask:<kind>" only for the
                      closed set of operator-triggered "ask octo" kinds;
                      "vendor update" for a note recorded from a vendor
                      (v0.11 R4). Autonomous notes (NULL / auto_enrich)
                      render without a chip so triage stays quiet. */}
                  {(() => {
                    const chip = agentNoteKindChip(i.query_kind);
                    if (!chip) return null;
                    return (
                      <span
                        title={chip.title}
                        data-testid="agent-note-kind-chip"
                        className={[
                          "shrink-0 rounded-sm border px-1.5 py-0.5 font-mono uppercase tracking-wider",
                          chip.tone === "ask"
                            ? "border-accent/30 bg-accent/10 text-accent"
                            : "border-border text-text-secondary",
                        ].join(" ")}
                      >
                        {chip.label}
                      </span>
                    );
                  })()}
                  <span className="min-w-0 flex-1 truncate font-mono text-text-primary">
                    {subjectLabel}
                  </span>
                  <span className="shrink-0 font-mono text-text-dim">
                    {i.client_slug}
                  </span>
                  <span className="shrink-0 font-mono text-text-dim">
                    {i.created_at.slice(11, 19)}
                  </span>
                </div>
                {/* Line 2 — note text + confidence. Slice 7m: real LLM
                    output is multi-sentence — let it wrap to 2 lines
                    with line-clamp-2 instead of truncating to 1, but
                    cap the height so the feed stays scannable. */}
                <div className="flex min-w-0 items-baseline gap-2 pl-1 text-[11px]">
                  <span
                    className="min-w-0 flex-1 overflow-hidden text-text-secondary"
                    style={{
                      display: "-webkit-box",
                      WebkitLineClamp: 2,
                      WebkitBoxOrient: "vertical",
                    }}
                    title={i.note_text}
                  >
                    {i.note_text}
                  </span>
                  <span
                    className="shrink-0 font-mono text-[10px] text-text-dim"
                    title={`confidence ${i.confidence.toFixed(2)}`}
                  >
                    {Math.round(i.confidence * 100)}% confident
                  </span>
                </div>
              </button>
              {xTicketId !== null && (
                <button
                  type="button"
                  title={`Open ticket #${xTicketId} directly`}
                  onClick={() => onOpenLinkedTicket(i.client_slug, xTicketId)}
                  className="flex shrink-0 items-center gap-1 border-l border-border bg-bg-card px-3 font-mono text-[10px] uppercase tracking-wider text-accent transition-colors hover:bg-accent/10"
                >
                  → #{xTicketId}
                </button>
              )}
            </li>
          );
        })}
      </ol>
    )}
  </div>
);

export default TicketsPage;
