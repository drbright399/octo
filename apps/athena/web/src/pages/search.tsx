/**
 * /search/events + /search/indicators — client DB search surface.
 *
 * Two separate routes share the SearchPage component, which switches
 * data source + filter rail based on which mode is active. Top-of-page
 * has a low-profile [ events | indicators ] toggle that swaps modes
 * without leaving the search shell.
 *
 * Step-up auth gates every read: on first arrival we fetch /status; if
 * not elevated, the modal opens immediately (eager). On subsequent
 * STEP_UP_REQUIRED or STEP_UP_NETWORK_CHANGED errors from the API,
 * the modal re-opens and the failing request retries after success.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type FC, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useClickOutsideClose } from "@/lib/use-click-outside-close";
import {
  ApiError,
  fetchStepUpStatus,
  searchEvents,
  searchIndicators,
  fetchEventPayload,
  listClients,
  expandLinkedRefs,
  exportSearch,
  type ClientEntry,
  type SearchEventRow,
  type SearchEventsArgs,
  type SearchEventsResponse,
  type SearchIndicatorsArgs,
  type SearchIndicatorsResponse,
  type EventPayloadResponse,
  type StepUpStatus,
  type AgentPatternLink,
} from "@/lib/api";
import { createTicket } from "@/lib/tickets";
import StepUpModal, { type StepUpReason } from "@/components/step-up-modal";
import SectionMarker from "@/components/section-marker";
import VendorLink, { type VendorDeepLink } from "@/components/vendor-link";
import HelpTip from "@/components/help-tip";
import { AgentNotesPanel } from "@/components/agent-notes-panel";
import { INDICATOR_TYPES, parseIndicatorRef } from "@/contracts/indicator";
import { navigateTo, useSearchParam } from "@/lib/router";

function buildVendorLink(payload: EventPayloadResponse): VendorDeepLink {
  const base = {
    vendor: payload.source,
    url: payload.vendor_deep_link as string,
    target_kind: "alert" as const,
  };
  return payload.vendor_display_name
    ? { ...base, label: payload.vendor_display_name }
    : base;
}

type Mode = "events" | "indicators";
type TimePresetId = "15m" | "1h" | "5h" | "24h" | "7d";

const TIME_PRESETS: Record<TimePresetId, { label: string; minutes: number }> = {
  "15m": { label: "15m", minutes: 15 },
  "1h":  { label: "1h",  minutes: 60 },
  "5h":  { label: "5h",  minutes: 300 },
  "24h": { label: "24h", minutes: 1440 },
  "7d":  { label: "7d",  minutes: 10080 },
};
const TIME_PRESET_ORDER: TimePresetId[] = ["15m", "1h", "5h", "24h", "7d"];

const SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"] as const;

interface SearchPageProps {
  readonly mode: Mode;
  readonly onNavigateMode: (mode: Mode) => void;
}

const SearchPage: FC<SearchPageProps> = ({ mode, onNavigateMode }) => {
  // ---- step-up state ----
  const [stepUp, setStepUp] = useState<StepUpStatus | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [modalReason, setModalReason] = useState<StepUpReason>("required");

  // ---- tenant picker ----
  const [clients, setClients] = useState<ClientEntry[]>([]);
  const [selectedTenants, setSelectedTenants] = useState<Set<string>>(new Set());

  // ---- filters (shared) ----
  const [timePreset, setTimePreset] = useState<TimePresetId>("24h");
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Set<string>>(new Set());
  const [eventTypesText, setEventTypesText] = useState("");
  const [indicatorTypeFilter, setIndicatorTypeFilter] = useState<Set<string>>(new Set());
  const [promotedOnly, setPromotedOnly] = useState(false);
  // Explicit ISO date range — overrides the preset when set. Either
  // bound may be empty: empty `from` means "everything up to `to`",
  // empty `to` means "from `from` forward". The auditor flow ("show me
  // every event between 2026-03-01 and 2026-03-15") lives here.
  const [customFrom, setCustomFrom] = useState<string>("");
  const [customTo, setCustomTo] = useState<string>("");

  // ---- threat-intel pulse deep link ----
  // `/search/indicators?indicator=<tenant>:<id>`: one pulse row, which the
  // dashboard shows masked. While it's set the search is exactly that row in
  // that tenant (the other filters don't apply); the step-up gate and the
  // scope check are the server's, as for every search.
  const indicatorParam = useSearchParam("indicator");
  const indicatorRef = useMemo(
    () => (mode === "indicators" ? parseIndicatorRef(indicatorParam) : null),
    [mode, indicatorParam],
  );

  // ---- results ----
  const [eventsResp, setEventsResp] = useState<SearchEventsResponse | null>(null);
  const [indicatorsResp, setIndicatorsResp] = useState<SearchIndicatorsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // ---- bulk selection ----
  // Keyed by `<client_slug>:<event_id>` so it survives across-tenant
  // selection. Audit-grade export consumes this set.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [exportBusy, setExportBusy] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [expandBusy, setExpandBusy] = useState(false);

  // Parse `<slug>:<id>` selection keys back into a list of refs.
  const selectedRefs = (): { client_slug: string; event_id: number }[] =>
    [...selected].map((k) => {
      const idx = k.lastIndexOf(":");
      return { client_slug: k.slice(0, idx), event_id: Number(k.slice(idx + 1)) };
    });

  // ---- drawer ----
  // Parse `?focus=<slug>:<event_id>` from the current URL. Used both
  // for the initial mount state AND on every `athena:navigate` event,
  // so an already-mounted /search picks up a fresh deep-link without
  // requiring a full remount.
  const readFocusFromUrl = (): { slug: string; id: number } | null => {
    try {
      const params = new URLSearchParams(window.location.search);
      const focus = params.get("focus");
      if (focus) {
        const idx = focus.lastIndexOf(":");
        if (idx > 0) {
          const slug = focus.slice(0, idx);
          const id = Number(focus.slice(idx + 1));
          if (slug && Number.isFinite(id)) return { slug, id };
        }
      }
    } catch { /* malformed query — fall through to null */ }
    return null;
  };

  const [drawerEvent, setDrawerEvent] = useState<{ slug: string; id: number } | null>(
    () => readFocusFromUrl(),
  );
  const [drawerPayload, setDrawerPayload] = useState<EventPayloadResponse | null>(null);
  const [drawerLoading, setDrawerLoading] = useState(false);
  const [drawerError, setDrawerError] = useState<string | null>(null);

  // Re-sync drawerEvent on any in-page navigation so cross-link deep
  // links (alert-drawer, ticket-window, agent-note-window) work even
  // when /search is already in the foreground.
  useEffect(() => {
    const onNav = (): void => {
      const next = readFocusFromUrl();
      if (next) setDrawerEvent(next);
    };
    window.addEventListener("athena:navigate", onNav);
    window.addEventListener("popstate", onNav);
    return () => {
      window.removeEventListener("athena:navigate", onNav);
      window.removeEventListener("popstate", onNav);
    };
  }, []);

  // ---- pagination ----
  const [offset, setOffset] = useState(0);
  const LIMIT = 100;

  // ---------------------------------------------------------------------------
  // Step-up bootstrap — fetch status on mount; if not elevated, open modal
  // ---------------------------------------------------------------------------
  useEffect(() => {
    let cancelled = false;
    fetchStepUpStatus().then((s) => {
      if (cancelled) return;
      setStepUp(s);
      if (!s.elevated) {
        setModalReason("required");
        setModalOpen(true);
      }
    }).catch(() => {
      if (cancelled) return;
      // Unauthenticated callers get a 401 here; App.tsx /auth/me redirect
      // handles routing them to /login.
    });
    return () => { cancelled = true; };
  }, []);

  // ---------------------------------------------------------------------------
  // Load client list once (used for tenant picker)
  // ---------------------------------------------------------------------------
  useEffect(() => {
    let cancelled = false;
    listClients().then((cs) => {
      if (cancelled) return;
      setClients(cs);
      // Auto-select all visible clients on first load
      setSelectedTenants(new Set(cs.map((c) => c.slug)));
    }).catch(() => undefined);
    return () => { cancelled = true; };
  }, []);

  // ---------------------------------------------------------------------------
  // Run the search whenever filters change + step-up active
  // ---------------------------------------------------------------------------
  const runSearch = useCallback(async (): Promise<void> => {
    if (!stepUp?.elevated) return;
    if (selectedTenants.size === 0 && !indicatorRef) {
      setEventsResp(null);
      setIndicatorsResp(null);
      return;
    }
    setLoading(true);
    setError(null);
    // Time bounds: explicit custom range wins when either bound is set;
    // otherwise the preset drives a "last N minutes" window. Empty
    // strings mean unbounded on that side.
    const hasCustom = customFrom !== "" || customTo !== "";
    const customFromIso = customFrom ? new Date(customFrom).toISOString() : undefined;
    const customToIso = customTo ? new Date(customTo).toISOString() : undefined;
    const now = new Date();
    const presetFromMs = now.getTime() - TIME_PRESETS[timePreset].minutes * 60_000;
    const presetFromIso = new Date(presetFromMs).toISOString();
    const time_from = hasCustom ? customFromIso : presetFromIso;
    const time_to = hasCustom ? customToIso : undefined;

    try {
      if (mode === "events") {
        const args: SearchEventsArgs = {
          tenants: [...selectedTenants],
          limit: LIMIT,
          offset,
        };
        if (time_from) args.time_from = time_from;
        if (time_to) args.time_to = time_to;
        if (query.trim()) args.query = query.trim();
        if (severityFilter.size) args.severities = [...severityFilter];
        const eventTypes = eventTypesText.split(",").map((s) => s.trim()).filter(Boolean);
        if (eventTypes.length) args.event_types = eventTypes;
        const r = await searchEvents(args);
        setEventsResp(r);
      } else if (indicatorRef) {
        setIndicatorsResp(await searchIndicators({
          tenants: [indicatorRef.tenant],
          indicator_ids: [indicatorRef.id],
          limit: LIMIT,
          offset: 0,
        }));
      } else {
        const args: SearchIndicatorsArgs = {
          tenants: [...selectedTenants],
          limit: LIMIT,
          offset,
        };
        if (query.trim()) args.query = query.trim();
        if (severityFilter.size) args.severities = [...severityFilter];
        if (indicatorTypeFilter.size) args.types = [...indicatorTypeFilter];
        if (promotedOnly) args.promoted_only = true;
        const r = await searchIndicators(args);
        setIndicatorsResp(r);
      }
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.message === "STEP_UP_REQUIRED" || e.status === 401) {
          setModalReason("required");
          setModalOpen(true);
          return;
        }
        if (e.message === "STEP_UP_NETWORK_CHANGED") {
          setModalReason("network_changed");
          setModalOpen(true);
          return;
        }
        setError(e.message);
      } else {
        setError("Search failed");
      }
    } finally {
      setLoading(false);
    }
  }, [stepUp?.elevated, selectedTenants, mode, timePreset, customFrom, customTo,
       query, severityFilter, eventTypesText, indicatorTypeFilter, promotedOnly, offset,
       indicatorRef]);

  useEffect(() => {
    void runSearch();
  }, [runSearch]);

  // Reset offset when filters change (but not when offset itself changes)
  useEffect(() => {
    setOffset(0);
  }, [mode, timePreset, customFrom, customTo, query, severityFilter, eventTypesText,
      indicatorTypeFilter, promotedOnly, selectedTenants]);

  // Clear selection when ANY filter changes — selection across changing
  // result sets gets confusing fast, and audit exports should reflect a
  // stable filter set + selection pair.
  useEffect(() => {
    setSelected(new Set());
  }, [mode, timePreset, customFrom, customTo, query, severityFilter, eventTypesText,
      indicatorTypeFilter, promotedOnly, selectedTenants]);

  // ---- bulk-selection helpers (events mode) ----
  const eventKey = (r: SearchEventRow): string => `${r.client_slug}:${r.event_id}`;
  const toggleSelected = (r: SearchEventRow): void => {
    setSelected((prev) => {
      const next = new Set(prev);
      const k = eventKey(r);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  };
  const visibleEventKeys = (eventsResp?.results ?? []).map(eventKey);
  const allPageSelected = visibleEventKeys.length > 0 &&
    visibleEventKeys.every((k) => selected.has(k));
  const somePageSelected = visibleEventKeys.some((k) => selected.has(k));
  const togglePageSelection = (): void => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (allPageSelected) {
        for (const k of visibleEventKeys) next.delete(k);
      } else {
        for (const k of visibleEventKeys) next.add(k);
      }
      return next;
    });
  };

  // ---------------------------------------------------------------------------
  // Drawer — fetch payload for selected event
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!drawerEvent) {
      setDrawerPayload(null);
      setDrawerError(null);
      return;
    }
    let cancelled = false;
    setDrawerLoading(true);
    setDrawerError(null);
    fetchEventPayload(drawerEvent.slug, drawerEvent.id)
      .then((p) => { if (!cancelled) setDrawerPayload(p); })
      .catch((e: unknown) => {
        if (cancelled) return;
        if (e instanceof ApiError && (e.message === "STEP_UP_REQUIRED" || e.message === "STEP_UP_NETWORK_CHANGED")) {
          setModalReason(e.message === "STEP_UP_NETWORK_CHANGED" ? "network_changed" : "required");
          setModalOpen(true);
        }
        setDrawerError(e instanceof ApiError ? e.message : "Payload fetch failed");
      })
      .finally(() => { if (!cancelled) setDrawerLoading(false); });
    return () => { cancelled = true; };
  }, [drawerEvent]);

  // ---------------------------------------------------------------------------
  // Step-up handlers
  // ---------------------------------------------------------------------------
  const onElevateSuccess = async (): Promise<void> => {
    setModalOpen(false);
    const fresh = await fetchStepUpStatus().catch(() => null);
    if (fresh) setStepUp(fresh);
    // Retry the in-flight search + drawer fetch if needed
    void runSearch();
    if (drawerEvent) {
      setDrawerEvent({ ...drawerEvent }); // trigger re-fetch
    }
  };

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  const expiresAt = stepUp?.expires_at;
  const expiresLabel = expiresAt ? formatExpiry(expiresAt) : "—";

  return (
    <section className="flex flex-col gap-5" aria-labelledby="search-title">
      <StepUpModal
        open={modalOpen}
        reason={modalReason}
        onClose={() => setModalOpen(false)}
        onSuccess={onElevateSuccess}
      />

      <ContextBlurb mode={mode} />

      {/* Status strip */}
      <div className="flex items-center justify-between gap-3 rounded-sm border border-border bg-bg-surface px-3 py-1.5 text-[11px] font-mono">
        <div className="flex items-center gap-2 text-text-secondary">
          <span aria-hidden="true" className="text-accent">▸</span>
          <span id="search-title" className="uppercase tracking-wider">search</span>
          <span aria-hidden="true" className="text-text-dim">·</span>
          {stepUp?.elevated ? (
            <span>step-up · expires <span className="text-accent">{expiresLabel}</span></span>
          ) : (
            <span className="text-critical">step-up required</span>
          )}
          <HelpTip>
            Step-up auth: client-data search requires a re-auth window beyond your normal session. Every query is audit-logged. Window auto-extends with activity, hard cap 4h.
          </HelpTip>
        </div>
        <div className="flex items-center gap-1">
          {(["events", "indicators"] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => onNavigateMode(m)}
              aria-pressed={mode === m}
              className={[
                "rounded-sm border px-2.5 py-0.5 text-[10px] uppercase tracking-wider transition-colors",
                mode === m
                  ? "border-accent bg-accent text-text-on-accent"
                  : "border-border bg-bg-card text-text-secondary hover:border-border-bright hover:text-accent",
              ].join(" ")}
            >
              {m}
            </button>
          ))}
        </div>
      </div>

      {/* Tenant picker */}
      <div className="flex flex-wrap items-center gap-2 rounded-sm border border-border bg-bg-surface px-3 py-2 text-[11px]">
        <span className="font-mono uppercase tracking-wider text-text-dim">tenants</span>
        <HelpTip>
          Which client tenants you can search. Visibility is determined by your operator scope — you can only see tenants you've been granted. Click a tenant to include or exclude it from the current query.
        </HelpTip>
        {clients.length === 0 && (
          <span className="text-text-dim">none in scope</span>
        )}
        {clients.map((c) => {
          const on = selectedTenants.has(c.slug);
          return (
            <button
              key={c.slug}
              type="button"
              onClick={() => {
                setSelectedTenants((prev) => {
                  const next = new Set(prev);
                  if (next.has(c.slug)) next.delete(c.slug);
                  else next.add(c.slug);
                  return next;
                });
              }}
              aria-pressed={on}
              className={[
                "rounded-sm border px-2 py-0.5 font-mono transition-colors",
                on
                  ? "border-accent bg-accent-soft text-accent"
                  : "border-border bg-bg-card text-text-dim hover:border-border-bright hover:text-text-secondary",
              ].join(" ")}
            >
              {c.display_name}
            </button>
          );
        })}
      </div>

      <div className="flex gap-4">
        {/* Filter rail */}
        <aside className="flex w-60 flex-col gap-5 rounded-sm border border-border bg-bg-surface p-4 text-[11px]">
          <div className="flex flex-col gap-1.5">
            <SectionMarker n={1} />
            <div className="flex items-center gap-1.5">
              <span className="font-mono uppercase tracking-wider text-text-dim">time range</span>
              <HelpTip>
                Quick presets OR an explicit from/to range below. Custom dates override the preset. Maximum 90-day window; older events may be archived.
              </HelpTip>
            </div>
            <div
              className={[
                "flex flex-wrap gap-1",
                customFrom !== "" || customTo !== "" ? "opacity-50" : "",
              ].join(" ")}
              title={customFrom !== "" || customTo !== "" ? "Disabled while custom range is set — clear the dates below to use presets." : undefined}
            >
              {TIME_PRESET_ORDER.map((id) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setTimePreset(id)}
                  aria-pressed={timePreset === id}
                  disabled={customFrom !== "" || customTo !== ""}
                  className={[
                    "rounded-sm border px-2 py-0.5 font-mono",
                    timePreset === id
                      ? "border-accent bg-accent text-text-on-accent"
                      : "border-border bg-bg-card text-text-secondary hover:border-border-bright",
                  ].join(" ")}
                >
                  {TIME_PRESETS[id].label}
                </button>
              ))}
            </div>
            <div className="mt-1 flex flex-col gap-1">
              <label className="flex flex-col gap-0.5">
                <span className="font-mono text-[10px] uppercase tracking-wider text-text-dim">from</span>
                <input
                  type="datetime-local"
                  value={customFrom}
                  onChange={(e) => setCustomFrom(e.target.value)}
                  className="w-full rounded-sm border border-border bg-bg-card px-2 py-1 font-mono text-text-primary focus:border-accent focus:outline-none"
                />
              </label>
              <label className="flex flex-col gap-0.5">
                <span className="font-mono text-[10px] uppercase tracking-wider text-text-dim">to</span>
                <input
                  type="datetime-local"
                  value={customTo}
                  onChange={(e) => setCustomTo(e.target.value)}
                  className="w-full rounded-sm border border-border bg-bg-card px-2 py-1 font-mono text-text-primary focus:border-accent focus:outline-none"
                />
              </label>
              {(customFrom !== "" || customTo !== "") && (
                <button
                  type="button"
                  onClick={() => { setCustomFrom(""); setCustomTo(""); }}
                  className="self-start rounded-sm border border-border bg-bg-card px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-text-dim hover:border-border-bright hover:text-text-secondary"
                >
                  × clear range
                </button>
              )}
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <SectionMarker n={2} />
            <div className="flex items-center gap-1.5">
              <span className="font-mono uppercase tracking-wider text-text-dim">query</span>
              <HelpTip>
                Free-text search against event summaries (the human-readable line each adapter emits). Substring match — no wildcards needed. Combine with other filters for precision.
              </HelpTip>
            </div>
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="free text…"
              className="w-full rounded-sm border border-border bg-bg-card px-2 py-1 text-text-primary focus:border-accent focus:outline-none"
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <SectionMarker n={3} />
            <div className="flex items-center gap-1.5">
              <span className="font-mono uppercase tracking-wider text-text-dim">severity</span>
              <HelpTip>
                P1 critical · P2 high · P3 medium · P4 low · P5 info. Leave all unchecked to include every severity; check one or more to narrow.
              </HelpTip>
            </div>
            <div className="flex flex-col gap-1">
              {SEVERITY_LEVELS.map((s) => (
                <label key={s} className="flex cursor-pointer items-center gap-2 font-mono">
                  <input
                    type="checkbox"
                    checked={severityFilter.has(s)}
                    onChange={() => {
                      setSeverityFilter((prev) => {
                        const next = new Set(prev);
                        if (next.has(s)) next.delete(s); else next.add(s);
                        return next;
                      });
                    }}
                    className="accent-accent"
                  />
                  <span className="text-text-secondary">{s}</span>
                </label>
              ))}
            </div>
          </div>

          {mode === "events" && (
            <div className="flex flex-col gap-1.5">
              <SectionMarker n={4} />
              <div className="flex items-center gap-1.5">
                <span className="font-mono uppercase tracking-wider text-text-dim">event types</span>
                <HelpTip>
                  {"Filter by adapter-emitted type. Format: 'adapter.kind' — e.g. wazuh.alert, suricata.alert, pihole.query (blocked lookups). Comma-separated for multiple. Answered DNS lookups and other network metadata are telemetry, kept apart from events and NOT searched here. \"Who looked this name up?\" has no page in the console yet: it is the API only — POST /api/v1/search/dns with a tenant and a domain or device (re-authentication; raw lookups 7 days, hourly sightings 180 days)."}
                </HelpTip>
              </div>
              <input
                type="text"
                value={eventTypesText}
                onChange={(e) => setEventTypesText(e.target.value)}
                placeholder="comma-separated (e.g. wazuh.alert)"
                className="w-full rounded-sm border border-border bg-bg-card px-2 py-1 text-text-primary focus:border-accent focus:outline-none"
              />
              <p data-testid="search-dns-scope-note" className="text-[10px] leading-snug text-text-dim">
                Answered DNS lookups (Pi-hole / Suricata) are not in this search — a
                name that was looked up but not blocked returns no hit here.
                &quot;Who looked this up?&quot; is API-only for now: POST
                /api/v1/search/dns (re-authentication).
              </p>
            </div>
          )}

          {mode === "indicators" && (
            <>
              <div className="flex flex-col gap-1.5">
                <SectionMarker n={4} />
                <div className="font-mono uppercase tracking-wider text-text-dim">indicator type</div>
                <div className="flex flex-wrap gap-1">
                  {INDICATOR_TYPES.map((t) => (
                    <button
                      key={t}
                      type="button"
                      onClick={() => {
                        setIndicatorTypeFilter((prev) => {
                          const next = new Set(prev);
                          if (next.has(t)) next.delete(t); else next.add(t);
                          return next;
                        });
                      }}
                      aria-pressed={indicatorTypeFilter.has(t)}
                      className={[
                        "rounded-sm border px-1.5 py-0.5 font-mono text-[10px]",
                        indicatorTypeFilter.has(t)
                          ? "border-accent bg-accent text-text-on-accent"
                          : "border-border bg-bg-card text-text-secondary hover:border-border-bright",
                      ].join(" ")}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>
              <label className="flex cursor-pointer items-center gap-2 font-mono">
                <input
                  type="checkbox"
                  checked={promotedOnly}
                  onChange={(e) => setPromotedOnly(e.target.checked)}
                  className="accent-accent"
                />
                <span className="text-text-secondary">promoted only</span>
              </label>
            </>
          )}
        </aside>

        {/* Results */}
        <div className="flex-1 overflow-hidden rounded-sm border border-border bg-bg-surface">
          {error && (
            <div role="alert" className="border-b border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical">
              {error}
            </div>
          )}
          {indicatorRef && (
            <div
              role="status"
              className="flex flex-wrap items-center justify-between gap-2 border-b border-accent/40 bg-accent/5 px-3 py-2 text-[11px] text-text-secondary"
            >
              <span>
                One indicator from the threat-intel pulse · tenant{" "}
                <span className="font-mono text-text-primary">{indicatorRef.tenant}</span>
                {" "}· the filters don&apos;t apply
              </span>
              <button
                type="button"
                onClick={() => navigateTo("/search/indicators")}
                className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-text-secondary hover:border-border-bright hover:text-accent"
              >
                show all indicators
              </button>
            </div>
          )}
          {mode === "events" && selected.size > 0 && (
            <SelectionToolbar
              count={selected.size}
              busy={expandBusy || exportBusy}
              onClear={() => setSelected(new Set())}
              onIncludeLinkedRefs={async () => {
                if (expandBusy) return;
                setExpandBusy(true);
                try {
                  const refs = selectedRefs();
                  const expanded = await expandLinkedRefs(refs);
                  // Merge every linked `event` ref's `to_id` into the
                  // selection set. Only `event` kinds are mergeable
                  // today — tickets/indicators get their own selectable
                  // surfaces when those pages land.
                  setSelected((prev) => {
                    const next = new Set(prev);
                    for (const ref of expanded) {
                      for (const lk of ref.linked_refs) {
                        if (lk.to_kind === "event") {
                          next.add(`${ref.client_slug}:${lk.to_id}`);
                        }
                      }
                    }
                    return next;
                  });
                } catch (e) {
                  window.alert(`Include linked refs failed: ${e instanceof Error ? e.message : String(e)}`);
                } finally {
                  setExpandBusy(false);
                }
              }}
              onExport={() => setExportModalOpen(true)}
            />
          )}
          {exportModalOpen && (
            <ExportModal
              count={selected.size}
              busy={exportBusy}
              error={exportError}
              onClose={() => { setExportModalOpen(false); setExportError(null); }}
              onConfirm={async (format, opts) => {
                setExportBusy(true);
                setExportError(null);
                try {
                  const result = await exportSearch({
                    tenants: [...selectedTenants],
                    event_ids: selectedRefs(),
                    format,
                    include_agent_notes: opts.includeAgentNotes,
                    include_indicators: opts.includeIndicators,
                  });
                  // Trigger browser download via a transient anchor.
                  const url = window.URL.createObjectURL(result.blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = result.filename;
                  document.body.appendChild(a);
                  a.click();
                  document.body.removeChild(a);
                  window.URL.revokeObjectURL(url);
                  setExportModalOpen(false);
                } catch (e) {
                  setExportError(e instanceof Error ? e.message : String(e));
                } finally {
                  setExportBusy(false);
                }
              }}
            />
          )}
          {mode === "events" ? (
            <EventsTable
              resp={eventsResp}
              loading={loading}
              onRowClick={(r) => setDrawerEvent({ slug: r.client_slug, id: r.event_id })}
              selected={selected}
              eventKey={eventKey}
              onToggleRow={toggleSelected}
              onTogglePage={togglePageSelection}
              allPageSelected={allPageSelected}
              somePageSelected={somePageSelected}
            />
          ) : (
            <IndicatorsTable resp={indicatorsResp} loading={loading} />
          )}

          {/* Pagination */}
          <Pagination
            offset={offset}
            limit={LIMIT}
            total={mode === "events"
                    ? eventsResp?.total_estimate ?? 0
                    : indicatorsResp?.total_estimate ?? 0}
            onPrev={() => setOffset(Math.max(0, offset - LIMIT))}
            onNext={() => setOffset(offset + LIMIT)}
          />
        </div>
      </div>

      {/* Drawer */}
      {drawerEvent && (
        <Drawer
          loading={drawerLoading}
          error={drawerError}
          payload={drawerPayload}
          onClose={() => setDrawerEvent(null)}
        />
      )}
    </section>
  );
};

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** Bulk-action toolbar — appears above the table when selection > 0.
 * Mirrors the audit-grade workflow: pick rows, optionally expand to
 * include linked refs (agent_pattern_links), then export to a branded
 * CSV / PDF report (download or email). Both expand + export are
 * server-side and audit-logged. */
const SelectionToolbar: FC<{
  count: number;
  busy: boolean;
  onClear: () => void;
  onIncludeLinkedRefs: () => void;
  onExport: () => void;
}> = ({ count, busy, onClear, onIncludeLinkedRefs, onExport }) => (
  <div
    className="sticky top-0 z-10 flex items-center justify-between gap-3 rounded-sm border border-accent/40 bg-accent-soft px-3 py-1.5 text-[11px]"
    role="toolbar"
    aria-label="Selection actions"
  >
    <div className="flex items-center gap-3">
      <span className="font-mono uppercase tracking-wider text-accent">
        ·· {count} selected ··
      </span>
      <button
        type="button"
        onClick={onClear}
        disabled={busy}
        className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-text-secondary hover:border-border-bright hover:text-text-primary disabled:opacity-50"
      >
        × clear
      </button>
    </div>
    <div className="flex items-center gap-2">
      <button
        type="button"
        onClick={onIncludeLinkedRefs}
        disabled={busy}
        title="Add events linked via agent_pattern_links to the selection"
        className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-text-secondary hover:border-border-bright hover:text-text-primary disabled:opacity-50"
      >
        {busy ? "·· expanding ··" : "+ include linked refs"}
      </button>
      <button
        type="button"
        onClick={onExport}
        disabled={busy}
        className="rounded-sm border border-accent bg-accent px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-text-on-accent hover:opacity-90 disabled:opacity-50"
      >
        ↓ export
      </button>
    </div>
  </div>
);

/** Export-format chooser. Two options today (CSV + PDF), download
 * delivery only. Email lands when SMTP wires up. Two opt-in include
 * toggles let auditors pull richer context (agent reasoning + related
 * IOCs) into the same audit-logged report. */
interface ExportOptions {
  includeAgentNotes: boolean;
  includeIndicators: boolean;
}

const ExportModal: FC<{
  count: number;
  busy: boolean;
  error: string | null;
  onClose: () => void;
  onConfirm: (format: "csv" | "pdf", opts: ExportOptions) => void;
}> = ({ count, busy, error, onClose, onConfirm }) => {
  const [includeAgentNotes, setIncludeAgentNotes] = useState(false);
  const [includeIndicators, setIncludeIndicators] = useState(false);
  const opts: ExportOptions = { includeAgentNotes, includeIndicators };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Export selected events"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-md rounded-sm border border-border bg-bg-elevated p-5 text-[12px] shadow-2xl"
      >
        <header className="mb-3 flex items-center justify-between">
          <h2 className="font-mono text-[11px] uppercase tracking-widest text-accent">
            ·· export {count} event{count === 1 ? "" : "s"} ··
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[10px] text-text-secondary hover:text-text-primary"
          >
            ✕
          </button>
        </header>

        <p className="mb-4 text-text-secondary">
          Pick a format. Every export is audit-logged with the filter hash,
          row count, your operator id, and which optional includes you
          ticked — auditors can reproduce the exact contents later.
        </p>

        <fieldset className="mb-4 flex flex-col gap-2 rounded-sm border border-border bg-bg-card p-3">
          <legend className="px-1 font-mono text-[10px] uppercase tracking-wider text-text-dim">
            include
          </legend>
          <label className="flex items-start gap-2 text-text-secondary">
            <input
              type="checkbox"
              checked={includeAgentNotes}
              onChange={(e) => setIncludeAgentNotes(e.target.checked)}
              className="mt-0.5 accent-accent"
            />
            <span className="flex-1">
              <span className="text-text-primary">AI agent notes</span>
              <span className="block text-[10px] text-text-dim">
                Shallow / Deep / Athena notes attached to each event, with
                confidence scores. CSV adds an <code className="text-accent">agent_notes_json</code>{" "}
                column; PDF gets its own section.
              </span>
            </span>
          </label>
          <label className="flex items-start gap-2 text-text-secondary">
            <input
              type="checkbox"
              checked={includeIndicators}
              onChange={(e) => setIncludeIndicators(e.target.checked)}
              className="mt-0.5 accent-accent"
            />
            <span className="flex-1">
              <span className="text-text-primary">Related indicators</span>
              <span className="block text-[10px] text-text-dim">
                IOCs related to the exported events via value overlap +
                agent pattern links. Per-tenant only; cross-tenant pool
                matches will land with M10.
              </span>
            </span>
          </label>
        </fieldset>

        <div className="mb-4 grid gap-2 sm:grid-cols-2">
          <button
            type="button"
            onClick={() => onConfirm("csv", opts)}
            disabled={busy}
            className="flex flex-col items-start gap-1 rounded-sm border border-border bg-bg-card p-3 text-left hover:border-accent hover:bg-accent-soft disabled:opacity-50"
          >
            <span className="font-mono text-[11px] uppercase tracking-wider text-accent">CSV</span>
            <span className="text-text-secondary">Raw data, RFC-4180. Up to 50,000 rows.</span>
          </button>
          <button
            type="button"
            onClick={() => onConfirm("pdf", opts)}
            disabled={busy}
            className="flex flex-col items-start gap-1 rounded-sm border border-border bg-bg-card p-3 text-left hover:border-accent hover:bg-accent-soft disabled:opacity-50"
          >
            <span className="font-mono text-[11px] uppercase tracking-wider text-accent">PDF</span>
            <span className="text-text-secondary">Branded report. Up to 2,000 rows. Handoff-ready.</span>
          </button>
        </div>

        <details className="mb-3 rounded-sm border border-border bg-bg-card p-2 text-[11px]">
          <summary className="cursor-pointer font-mono text-[10px] uppercase tracking-wider text-text-dim">
            email delivery
          </summary>
          <p className="mt-2 text-text-secondary">
            Coming with the SMTP integration. Will route through the same
            audit shape with recipient + delivery=email captured. For now:
            download, then attach.
          </p>
        </details>

        {busy && (
          <div className="mb-2 text-center font-mono text-[10px] uppercase tracking-wider text-text-dim">
            ·· generating · audit chain writing ··
          </div>
        )}
        {error && (
          <div role="alert" className="mb-2 rounded-sm border border-critical/40 bg-critical/10 px-2 py-1 font-mono text-[10px] text-critical">
            {error}
          </div>
        )}
      </div>
    </div>
  );
};

const EventsTable: FC<{
  resp: SearchEventsResponse | null;
  loading: boolean;
  onRowClick: (r: SearchEventRow) => void;
  selected: Set<string>;
  eventKey: (r: SearchEventRow) => string;
  onToggleRow: (r: SearchEventRow) => void;
  onTogglePage: () => void;
  allPageSelected: boolean;
  somePageSelected: boolean;
}> = ({ resp, loading, onRowClick, selected, eventKey, onToggleRow,
         onTogglePage, allPageSelected, somePageSelected }) => {
  if (loading && !resp) {
    return <div className="p-6 text-center text-xs text-text-dim">loading…</div>;
  }
  if (!resp || resp.results.length === 0) {
    return (
      <div className="p-8 text-center text-xs text-text-dim">
        no events match the current filters
      </div>
    );
  }
  return (
    <table className="w-full border-collapse text-[11px] font-mono">
      <thead>
        <tr className="border-b border-border bg-bg-card text-left text-text-dim">
          <Th>
            <input
              type="checkbox"
              aria-label={allPageSelected ? "Deselect this page" : "Select this page"}
              checked={allPageSelected}
              ref={(el) => {
                if (el) el.indeterminate = somePageSelected && !allPageSelected;
              }}
              onChange={onTogglePage}
              onClick={(e) => e.stopPropagation()}
              className="accent-accent"
            />
          </Th>
          <Th>&nbsp;</Th>
          <Th>timestamp</Th>
          <Th>type</Th>
          <Th>tenant</Th>
          <Th>vendor</Th>
          <Th>host</Th>
          <Th>summary</Th>
        </tr>
      </thead>
      <tbody>
        {resp.results.map((r) => {
          const k = eventKey(r);
          const isSelected = selected.has(k);
          return (
          <tr
            key={k}
            onClick={() => onRowClick(r)}
            data-sev={r.severity}
            aria-selected={isSelected}
            className={[
              "row-stripe cursor-pointer border-b border-border/40 transition-colors",
              // Subtle bg-shift on hover — full accent-fill sweep was the
              // wrong pattern for data rows: cells carry their own
              // backgrounds (vendor badge, agent-note chip) that clash
              // with the sweep, making nested chip text wash out. Plain
              // bg-card-hover reads cleanly in both light + dark.
              isSelected ? "bg-accent-soft" : "hover:bg-bg-card-hover",
            ].join(" ")}
          >
            <Td className="w-8 pl-2 pr-0">
              <input
                type="checkbox"
                aria-label={isSelected ? "Deselect row" : "Select row"}
                checked={isSelected}
                onChange={() => onToggleRow(r)}
                onClick={(e) => e.stopPropagation()}
                className="accent-accent"
              />
            </Td>
            <Td className="w-10 pl-2 pr-0 font-semibold tracking-wider"
                title={r.severity}
                style={{ color: "var(--stripe-color)" }}>
              {severityToPnum(r.severity)}
            </Td>
            <Td className="pl-6">{formatTs(r.received_at)}</Td>
            <Td>{r.event_type}</Td>
            <Td>{r.client_slug}</Td>
            <Td><VendorBadge slug={r.source} /></Td>
            <Td>{r.source_host || "—"}</Td>
            <Td className="max-w-[460px]">
              <span className="flex items-center gap-2">
                <span className="truncate" title={r.summary}>
                  {r.summary || "—"}
                </span>
                {r.agent_note_count > 0 && <AgentNoteChip count={r.agent_note_count} />}
              </span>
            </Td>
          </tr>
          );
        })}
      </tbody>
    </table>
  );
};

const IndicatorsTable: FC<{
  resp: SearchIndicatorsResponse | null;
  loading: boolean;
}> = ({ resp, loading }) => {
  if (loading && !resp) {
    return <div className="p-6 text-center text-xs text-text-dim">loading…</div>;
  }
  if (!resp || resp.results.length === 0) {
    return (
      <div className="p-8 text-center text-xs text-text-dim">
        no indicators match the current filters
      </div>
    );
  }
  return (
    <table className="w-full border-collapse text-[11px] font-mono">
      <thead>
        <tr className="border-b border-border bg-bg-card text-left text-text-dim">
          <Th>&nbsp;</Th>
          <Th>last seen</Th>
          <Th>type</Th>
          <Th>value</Th>
          <Th>tenant</Th>
          <Th>conf</Th>
          <Th>hits</Th>
          <Th>source</Th>
        </tr>
      </thead>
      <tbody>
        {resp.results.map((r) => (
          <tr
            key={`${r.client_slug}:${r.indicator_id}`}
            data-sev={r.severity}
            className="row-stripe border-b border-border/40 transition-colors hover:bg-bg-card-hover"
          >
            <Td className="w-10 pl-2 pr-0 font-semibold tracking-wider"
                title={r.severity}
                style={{ color: "var(--stripe-color)" }}>
              {severityToPnum(r.severity)}
            </Td>
            <Td className="pl-6">{formatTs(r.last_seen)}</Td>
            <Td>{r.type}</Td>
            <Td className="max-w-[280px] truncate" title={r.value}>{r.value}</Td>
            <Td>{r.client_slug}</Td>
            <Td>{(r.confidence * 100).toFixed(0)}%</Td>
            <Td>{r.hits}</Td>
            <Td>{r.source}</Td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};

const Pagination: FC<{
  offset: number; limit: number; total: number;
  onPrev: () => void; onNext: () => void;
}> = ({ offset, limit, total, onPrev, onNext }) => {
  if (total === 0) return null;
  const page = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  return (
    <div className="flex items-center justify-between border-t border-border bg-bg-card px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-text-dim">
      <span>
        page {page} of {totalPages} · {total.toLocaleString()} estimated
      </span>
      <div className="flex items-center gap-2">
        <button
          type="button" onClick={onPrev} disabled={offset === 0}
          className="rounded-sm border border-border bg-bg-surface px-2 py-0.5 transition-colors hover:border-border-bright disabled:opacity-30"
        >◂ prev</button>
        <button
          type="button" onClick={onNext} disabled={page >= totalPages}
          className="rounded-sm border border-border bg-bg-surface px-2 py-0.5 transition-colors hover:border-border-bright disabled:opacity-30"
        >next ▸</button>
      </div>
    </div>
  );
};

/**
 * Event payload drawer. Rendered through a portal to document.body so
 * the `fixed ... z-40` actually wins over the sticky topbar. Without the
 * portal, the search page's parent (App.tsx's `relative z-10`) creates
 * a stacking context that traps the drawer at effective z=10-internal,
 * letting the topbar's z-20 cover the drawer's close button. The portal
 * escapes that context entirely.
 */
const Drawer: FC<{
  loading: boolean; error: string | null;
  payload: EventPayloadResponse | null; onClose: () => void;
}> = ({ loading, error, payload, onClose }) => {
  const drawerRef = useRef<HTMLDivElement | null>(null);
  // /search drawer is read-only today — every cell renders from the
  // fetched payload, nothing accumulates as a pending edit. The dirty
  // hook stays in place so when agent-note editing lands here, the
  // confirm step is one ref-flip away.
  const isDirty = useCallback(() => false, []);
  useClickOutsideClose(drawerRef, isDirty, onClose);
  return createPortal(
    <div
      ref={drawerRef}
      role="dialog" aria-modal="false" aria-label="Event payload"
      className="fixed right-0 top-0 z-40 flex h-full w-[520px] flex-col border-l border-border-bright bg-bg-elevated shadow-2xl"
    >
      <header className="flex items-center justify-between border-b border-border px-4 py-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-accent">
            [ event payload ]
          </div>
          <div className="text-sm font-semibold text-text-primary">
            {payload ? `${payload.client_slug} · #${payload.event_id}` : "loading…"}
          </div>
        </div>
        <button
          type="button" onClick={onClose}
          className="rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[11px] text-text-secondary transition-colors hover:border-border-bright hover:text-text-primary"
        >✕ close</button>
      </header>
      <div className="flex-1 overflow-auto p-4 text-[11px] font-mono text-text-secondary">
        {loading && <div className="text-text-dim">loading…</div>}
        {error && <div className="text-critical">{error}</div>}
        {payload && (
          <div className="flex flex-col gap-3">
            <Meta label="received">{formatTs(payload.received_at)}</Meta>
            <Meta label="event_type">{payload.event_type}</Meta>
            <Meta label="severity"><SeverityChip severity={payload.severity} /></Meta>
            <Meta label="source">
              <span className="inline-flex items-center gap-2">
                <VendorBadge slug={payload.source} label={payload.vendor_display_name} />
                {payload.vendor_deep_link && (
                  <VendorLink
                    vendors={buildVendorLink(payload)}
                    size="lg"
                  />
                )}
              </span>
            </Meta>
            <Meta label="source_host">{payload.source_host || "—"}</Meta>
            <Meta label="summary">{payload.summary || "—"}</Meta>
            <Meta label="sha256">{payload.payload_sha256.slice(0, 16)}…</Meta>

            {payload.derived_ticket_id !== null && (
              <div className="rounded-sm border border-accent/40 bg-accent/5 p-2">
                <div className="mb-1 text-[10px] uppercase tracking-widest text-accent">
                  associated ticket
                </div>
                <button
                  type="button"
                  onClick={() => {
                    window.history.pushState({}, "", "/tickets");
                    window.dispatchEvent(new CustomEvent("athena:navigate"));
                    // Stash the deep-link target so /tickets can auto-open
                    // the ticket on mount. localStorage is the simplest
                    // hand-off vehicle that survives the route change.
                    try {
                      window.localStorage.setItem(
                        "athena.tickets.focus",
                        `${payload.client_slug}:${payload.derived_ticket_id}`,
                      );
                    } catch { /* ignore */ }
                  }}
                  className="flex w-full items-baseline justify-between gap-3 rounded-sm border border-accent bg-accent/10 px-3 py-1.5 text-left transition-colors hover:bg-accent/20"
                >
                  <span className="font-mono text-[11px] text-text-primary">
                    #{payload.derived_ticket_id}
                    {payload.derived_ticket_title && (
                      <span className="ml-1 text-text-secondary">
                        · {payload.derived_ticket_title}
                      </span>
                    )}
                  </span>
                  <span className="font-mono text-[9px] uppercase tracking-widest text-accent">
                    open in tickets →
                  </span>
                </button>
              </div>
            )}

            {payload.derived_ticket_id === null && (
              <CreateTicketFromAlert
                payload={payload}
              />
            )}

            {/* Agent notes + Ask Octo enrichment.
                Replaces the old inline AgentLayerSection — the panel
                renders existing notes AND surfaces the canned-query
                button bar so the operator can ask octo for more
                context on older events with new threat-intel
                added since the original notes landed. Same access
                gates as the alert drawer + tickets sidebar. */}
            <AgentNotesPanel
              notes={payload.agent_notes}
              clientSlug={payload.client_slug}
              refKind="event"
              refId={payload.event_id}
              heuristicNote={payload.summary || payload.event_type}
            />
            {payload.agent_pattern_links.length > 0 && (
              <RecognizedPatternsSection
                links={payload.agent_pattern_links}
              />
            )}

            <div>
              <div className="mb-1 text-[10px] uppercase tracking-widest text-text-dim">payload</div>
              <pre className="overflow-auto rounded-sm border border-border bg-bg-card p-2 text-[10px] leading-relaxed text-text-primary">
{JSON.stringify(payload.payload, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>,
    document.body,
  );
};

// ---------------------------------------------------------------------------
// Tiny helpers
// ---------------------------------------------------------------------------

const Th: FC<{ children?: ReactNode }> = ({ children }) => (
  <th className="px-3 py-1.5 text-[10px] uppercase tracking-wider">{children}</th>
);
const Td: FC<{
  children: ReactNode;
  className?: string;
  title?: string;
  style?: React.CSSProperties;
}> = ({ children, className, title, style }) => (
  <td className={["px-3 py-1.5 text-text-primary", className].join(" ")}
       title={title} style={style}>
    {children}
  </td>
);
const Meta: FC<{ label: string; children: ReactNode }> = ({ label, children }) => (
  <div className="flex items-baseline gap-3">
    <span className="w-24 shrink-0 text-[10px] uppercase tracking-widest text-text-dim">{label}</span>
    <span>{children}</span>
  </div>
);
function severityToPnum(severity: string): string {
  switch (severity) {
    case "critical": return "P1";
    case "high":     return "P2";
    case "medium":   return "P3";
    case "low":      return "P4";
    case "info":     return "P5";
    default:         return "—";
  }
}

/**
 * Small contextual blurb at the top of the search page. Tells a new
 * operator what they're looking at without taking much room.
 * Dismissible — preference persists per-session in localStorage
 * (separate keys for events vs indicators so the explanation re-appears
 * when switching modes for the first time).
 */
const BLURB_KEY_PREFIX = "athena.search.blurb-dismissed.v1.";
const ContextBlurb: FC<{ mode: Mode }> = ({ mode }) => {
  const key = BLURB_KEY_PREFIX + mode;
  const [dismissed, setDismissed] = useState<boolean>(() => {
    try { return window.localStorage.getItem(key) === "1"; }
    catch { return false; }
  });
  useEffect(() => {
    try { setDismissed(window.localStorage.getItem(key) === "1"); }
    catch { setDismissed(false); }
  }, [key]);
  if (dismissed) return null;
  const onDismiss = (): void => {
    try { window.localStorage.setItem(key, "1"); } catch { /* */ }
    setDismissed(true);
  };
  return (
    <div className="flex items-start gap-3 rounded-sm border border-accent/30 bg-accent-soft px-3 py-2 text-[11px] leading-relaxed text-text-secondary">
      <span aria-hidden="true" className="mt-0.5 font-mono text-[10px] uppercase tracking-widest text-accent">
        ·· about ··
      </span>
      <div className="flex-1">
        {mode === "events" ? (
          <p>
            <strong className="text-text-primary">Event search</strong> reads each tenant's <code className="font-mono text-accent">events.db</code> across the
            tenants you have visibility for. Every query and every payload-fetch is audit-logged
            against your operator id. Results show metadata only — click a row to open the full
            payload drawer (separately audited). Re-auth window enforced; hover the <span className="font-mono">(?)</span> markers
            for per-control details.
          </p>
        ) : (
          <p>
            <strong className="text-text-primary">Indicator search</strong> queries threat-intel IOCs (IPs, domains, hashes, URLs) extracted
            from event ingestion across your in-scope tenants. <em>Promoted</em> indicators have been
            manually flagged as high-confidence; the rest are auto-extracted. Same step-up + audit
            rules as event search.
          </p>
        )}
      </div>
      <button
        type="button"
        onClick={onDismiss}
        title="Hide this blurb (this session)"
        aria-label="Dismiss"
        className="shrink-0 rounded-sm border border-transparent px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-text-dim transition-colors hover:border-border-bright hover:text-text-primary"
      >
        × hide
      </button>
    </div>
  );
};

/** Small text-only badge identifying which vendor a row came from.
 * Distinct from VendorLink — VendorLink is a clickable affordance; this
 * is provenance shown even when the deep-link URL is unavailable (no
 * adapter registered, env URL not configured, payload lacks the right
 * id). Falls back to the raw source slug when no display name is given. */
const VENDOR_LABEL_FALLBACK: Record<string, string> = {
  datto: "Datto",
  wazuh: "Wazuh",
  unifi: "UniFi",
  rocketcyber: "RocketCyber",
};
const VendorBadge: FC<{ slug: string; label?: string | null }> = ({ slug, label }) => {
  const text = label || VENDOR_LABEL_FALLBACK[slug] || slug;
  return (
    <span className="inline-flex items-center rounded-sm border border-border bg-bg-card px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-text-secondary">
      {text}
    </span>
  );
};

/** `+N` chip on event rows when one or more agents have annotated.
 * Tiny, accent-colored, doesn't shift row height. Click bubbles up to
 * the row's onRowClick so opening the chip == opening the drawer. */
const AgentNoteChip: FC<{ count: number }> = ({ count }) => (
  <span
    className="shrink-0 rounded-sm border border-accent/40 bg-accent-soft px-1 py-[1px] font-mono text-[9px] uppercase tracking-wider text-accent"
    title={`${count} agent note${count === 1 ? "" : "s"} — click row to open`}
    aria-label={`${count} agent note${count === 1 ? "" : "s"}`}
  >
    +{count}
  </span>
);

/** Relation icons map to the 5 agent_pattern_links relation types.
 * Single-glyph identity keeps the drawer's pattern list scannable. */
const RELATION_ICON: Record<string, string> = {
  same_ioc:  "◇",
  same_host: "▢",
  same_ttp:  "△",
  temporal:  "⌖",
  semantic:  "◯",
};

const RELATION_LABEL: Record<string, string> = {
  same_ioc:  "same IOC",
  same_host: "same host",
  same_ttp:  "same TTP",
  temporal:  "temporal",
  semantic:  "semantic",
};

/** Recognized-pattern edges (agent_pattern_links). Rendered ALONGSIDE
 * the shared AgentNotesPanel — notes + "ask octo" live in the panel;
 * edge relationships are a separate visual concept (graph edges, not
 * notes). Both surface in the /search payload drawer + /tickets
 * floating window so the operator sees one consistent agent layer. */
const RecognizedPatternsSection: FC<{
  links: AgentPatternLink[];
}> = ({ links }) => (
  <div className="flex flex-col gap-1 rounded-sm border border-accent/30 bg-accent-soft p-3 text-[11px]">
    <div className="font-mono text-[10px] uppercase tracking-widest text-accent">
      ·· recognized patterns ({links.length}) ··
    </div>
    <ul role="list" className="flex flex-col gap-1">
      {links.map((lk) => (
        <li
          key={lk.id}
          className="flex items-baseline gap-2 rounded-sm border border-border bg-bg-card px-2 py-1"
        >
          <span aria-hidden="true" className="text-accent" title={RELATION_LABEL[lk.relation] ?? lk.relation}>
            {RELATION_ICON[lk.relation] ?? "·"}
          </span>
          <span className="font-mono text-[10px] uppercase tracking-wider text-text-secondary">
            {RELATION_LABEL[lk.relation] ?? lk.relation}
          </span>
          <span className="font-mono text-[10px] text-text-dim">
            str {Math.round(lk.strength * 100)}%
          </span>
          <span className="font-mono text-[10px] text-accent">
            → {lk.to_kind} #{lk.to_id}
          </span>
          <span className="ml-auto truncate text-text-secondary" title={lk.rationale}>
            {lk.rationale}
          </span>
        </li>
      ))}
    </ul>
  </div>
);

const SeverityChip: FC<{ severity: string }> = ({ severity }) => {
  const tone =
    severity === "critical" ? "bg-critical/20 text-critical"
    : severity === "high" ? "bg-high/20 text-high"
    : severity === "medium" ? "bg-medium/20 text-medium"
    : severity === "low" ? "bg-accent-soft text-accent"
    : "bg-bg-card text-text-dim";
  return (
    <span className={`rounded-sm px-1.5 py-0.5 text-[10px] font-mono uppercase ${tone}`}>
      {severity}
    </span>
  );
};

function formatTs(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString([], { hour12: false });
  } catch { return iso; }
}

function formatExpiry(iso: string): string {
  try {
    const d = new Date(iso);
    const now = new Date();
    const diff = (d.getTime() - now.getTime()) / 1000;
    if (diff < 0) return "expired";
    const mins = Math.floor(diff / 60);
    const secs = Math.floor(diff % 60);
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  } catch { return iso; }
}

/**
 * CreateTicketFromAlert — small inline form rendered in the /search
 * event drawer when the event has no derived ticket. Submits to
 * POST /tickets/{slug} with source_event_id wired so the bidirectional
 * cross-link picks up on next fetch.
 *
 * Future workflow (the noise-dismissal goal):
 * elevated / agent-confident alerts will spawn tickets automatically
 * via a rule engine. This manual form is the operator-driven path
 * + the reference shape the auto-spawn rule applies.
 */
const CreateTicketFromAlert: FC<{ payload: EventPayloadResponse }> = ({ payload }) => {
  const [expanded, setExpanded] = useState(false);
  const [title, setTitle] = useState(
    () => `[${payload.severity.toUpperCase()}] ${payload.summary || payload.event_type}`.slice(0, 200),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createdTicketId, setCreatedTicketId] = useState<number | null>(null);

  const onCreate = async (): Promise<void> => {
    if (busy || !title.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const t = await createTicket(payload.client_slug, {
        title: title.trim(),
        description: `Opened from alert: event #${payload.event_id} (${payload.event_type}) received ${payload.received_at}.`,
        severity: payload.severity as "info" | "low" | "medium" | "high" | "critical",
        source_event_id: payload.event_id,
      });
      setCreatedTicketId(t.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (createdTicketId !== null) {
    return (
      <div className="rounded-sm border border-accent bg-accent/10 p-2">
        <div className="mb-1 text-[10px] uppercase tracking-widest text-accent">
          ticket opened
        </div>
        <button
          type="button"
          onClick={() => {
            try {
              window.localStorage.setItem(
                "athena.tickets.focus",
                `${payload.client_slug}:${createdTicketId}`,
              );
            } catch { /* ignore */ }
            window.history.pushState({}, "", "/tickets");
            window.dispatchEvent(new CustomEvent("athena:navigate"));
          }}
          className="flex w-full items-baseline justify-between gap-3 text-left"
        >
          <span className="font-mono text-[11px] text-text-primary">
            #{createdTicketId} · {title}
          </span>
          <span className="font-mono text-[9px] uppercase tracking-widest text-accent">
            open in tickets →
          </span>
        </button>
      </div>
    );
  }

  return (
    <div className="rounded-sm border border-border bg-bg-card p-2">
      <div className="mb-1 flex items-baseline justify-between">
        <span className="text-[10px] uppercase tracking-widest text-text-dim">
          no ticket yet
        </span>
        {!expanded && (
          <button
            type="button"
            onClick={() => setExpanded(true)}
            className="rounded-sm border border-accent/60 bg-bg-surface px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-accent transition-colors hover:border-accent"
          >
            + create ticket from this alert
          </button>
        )}
      </div>
      {expanded && (
        <div className="flex flex-col gap-2">
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value.slice(0, 500))}
            placeholder="Ticket title"
            className="rounded-sm border border-border bg-bg-surface px-2 py-1 text-[11px] text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
          />
          {error && (
            <div role="alert" className="rounded-sm border border-critical/40 bg-critical/10 px-2 py-1 text-[10px] text-critical">
              {error}
            </div>
          )}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => { setExpanded(false); setError(null); }}
              disabled={busy}
              className="rounded-sm border border-border bg-bg-surface px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-text-secondary hover:border-border-bright"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => void onCreate()}
              disabled={busy || !title.trim()}
              className="rounded-sm border border-accent bg-accent px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-text-on-accent transition-colors hover:bg-accent/80 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy ? "creating…" : "Create ticket"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default SearchPage;
