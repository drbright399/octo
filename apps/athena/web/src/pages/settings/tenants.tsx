/**
 * Settings → Tenants — the tenant manager (admin+ only).
 *
 * Integrations now create tenants from their own traffic (auto-create) and
 * hold what they cannot attribute in quarantine — a site with the same name
 * as a client is held with a one-click suggestion, never linked. This page
 * is where a human closes the loop: tag what each tenant IS (kind +
 * compliance), confirm it, fix names, offboard, merge, and route the
 * quarantine. Two views under one tab: the tenant table (+ the two-person
 * request queue) and the quarantine review.
 *
 * Finding a row: a name/slug search, a review-state select (All / Needs
 * review / Confirmed — carried in the URL as `?filter=`, so the dashboard
 * notice's deep link lands on it and any navigation to plain
 * /settings/tenants clears it), kind / compliance / origin filters, and an
 * "N hidden by filters — Clear filters" line. A row the operator just
 * changed (confirm, edit, bulk) stays on screen even when it no longer
 * matches the filters, until the filters change — a confirmed tenant never
 * vanishes from under the click that confirmed it.
 *
 * Review at scale: select rows → Bulk edit… (kind / compliance / AI policy /
 * confirm) → a server-computed per-row diff → apply all-or-nothing. Rows
 * whose names look like the same business carry a "possible duplicate"
 * hint whose Merge… opens the ordinary merge dialog — a hint never merges.
 *
 * Role gates, mirrored from the server (`session_admin_plus` /
 * `session_super_admin` in admin_tenants.py):
 *   - analyst / viewer: the tab is hidden AND this component renders
 *     nothing but a refusal — a viewer is a client user and must never
 *     see other tenants' names, integrations or quarantined traffic;
 *   - admin: everything except deciding requests; offboard and merge are
 *     requests; post-reviews a single-person change someone else applied;
 *   - super_admin: approves/rejects requests (never its own — the
 *     two-person rule); offboards and merges by request too, or ALONE as
 *     the attested exception (v0.10: attestation, slug typed back, step-up;
 *     a merge only when the eligibility guards allow); may set AI policy
 *     'cloud' and signs (or revokes) the compliance sign-off cloud needs.
 *
 * The requests panel shows the two-person queue AND the single-person
 * changes (badged "applied alone", with the attestation as typed): any
 * admin+ other than the one who applied it records the optional
 * post-review there (OK / concern, with a note).
 *
 * The AI column shows what RUNS: 'cloud' asked for without a live sign-off
 * reads "cloud → local" with the reason — the console never implies cloud
 * is on when it is not. Its "sign-offs…" opens the sign-off dialog (the
 * history for an admin; the "Sign off for cloud AI" form for a super admin).
 */
import { type FC, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  BULK_UPDATE_MAX,
  COMPLIANCE_LABEL,
  DUPLICATE_RULE_HELP,
  KIND_LABEL,
  ORIGIN_LABEL,
  SIGNOFF_STATE_LABEL,
  STATUS_LABEL,
  aiPolicyView,
  canBeMergeTarget,
  canConfirm,
  canMergeFrom,
  canOffboard,
  canSignOff,
  POST_REVIEW_LABEL,
  labelFor,
  matchesSearch,
  needsReview,
  reviewFilterPath,
  type ChangeRequest,
  type PostReviewVerdict,
  type ReviewFilter,
  type Tenant,
  type TenantListResponse,
} from "@/contracts/tenant";
import { canManageRole, type MeResponse } from "@/contracts/operator";
import {
  decideChangeRequest,
  listChangeRequests,
  listTenants,
  patchTenant,
  postReviewChangeRequest,
} from "@/lib/api";
import { formatRelative } from "@/lib/time";
import { MergeDialog, OffboardDialog, TenantFormDialog, inputCls } from "@/components/tenant-dialogs";
import { BulkEditDialog } from "@/components/tenant-bulk-dialog";
import { ComplianceSignoffDialog } from "@/components/tenant-compliance-dialog";
import TenantLocationDialog from "@/components/tenant-location-dialog";
import { QuarantineReviewPanel } from "@/components/quarantine-review-panel";
import { EntityLinksPanel } from "@/components/entity-links-panel";
import { KnownBenignPanel } from "@/components/known-benign-panel";

export type TenantsView = "tenants" | "quarantine" | "links";

interface TenantsTabProps {
  readonly me: MeResponse | null;
  readonly view: TenantsView;
  readonly onNavigate: (path: string) => void;
  /** The review-state filter as the URL states it (`?filter=needs-review`
   *  from an integration card or the dashboard notice). Followed on every
   *  navigation, not just the first render. */
  readonly reviewFilter?: ReviewFilter | undefined;
  /** `?instance=<id>` — pre-filter the quarantine view. */
  readonly initialInstanceId?: number | undefined;
  /** `?client=<slug>` — the client the entity links view opens on (an
   *  `entity_review` notice's "Review it"). */
  readonly initialClient?: string | undefined;
}

const NO_SLUGS: ReadonlySet<string> = new Set();

/** A duplicate hint's merge, in the direction the server accepts: the row's
 *  own tenant into the other when it can, else the other into this one. */
function mergeFor(t: Tenant, other: Tenant | undefined): { subject: Tenant; target: string } | null {
  if (!other || t.pending_request || other.pending_request) return null;
  if (canMergeFrom(t) && canBeMergeTarget(other)) return { subject: t, target: other.slug };
  if (canBeMergeTarget(t) && canMergeFrom(other)) return { subject: other, target: t.slug };
  return null;
}

type SortKey = "name" | "kind" | "origin" | "events" | "last_event" | "review";

const REQUEST_POLL_MS = 30_000;

const badge = (tone: "accent" | "high" | "dim" | "critical" | "success"): string =>
  [
    "inline-flex items-center rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider",
    tone === "accent"
      ? "border-accent/50 bg-accent/10 text-accent"
      : tone === "high"
        ? "border-high/60 bg-high/10 text-high"
        : tone === "critical"
          ? "border-critical/60 bg-critical/10 text-critical"
          : tone === "success"
            ? "border-success/60 bg-success/10 text-success"
            : "border-border text-text-dim",
  ].join(" ");

const rowBtn =
  "rounded-sm border border-border bg-bg-input px-2 py-1 text-[11px] text-text-secondary hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-40";

const TenantsTab: FC<TenantsTabProps> = ({
  me, view, onNavigate, reviewFilter, initialInstanceId, initialClient,
}) => {
  const isAdminPlus = me ? canManageRole(me.role, "admin") : false;
  const isSuperAdmin = me ? canManageRole(me.role, "super_admin") : false;

  const [data, setData] = useState<TenantListResponse | null>(null);
  const [requests, setRequests] = useState<readonly ChangeRequest[]>([]);
  // Single-person changes (approval_mode single_attested), newest first.
  const [attested, setAttested] = useState<readonly ChangeRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Filters + sort. The review filter FOLLOWS the URL: SettingsPage stays
  // mounted across tab clicks, so a value seeded once from the deep link
  // used to outlive the navigation that should have cleared it.
  const urlReview: ReviewFilter = reviewFilter ?? "all";
  const [review, setReview] = useState<ReviewFilter>(urlReview);
  const [search, setSearch] = useState("");
  const [kindFilter, setKindFilter] = useState("all");
  const [complianceFilter, setComplianceFilter] = useState("all");
  const [originFilter, setOriginFilter] = useState("all");
  const [includeArchived, setIncludeArchived] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("review");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  // Rows changed from this screen (confirmed / edited / bulk-applied): kept
  // visible though they may no longer match the filters, until the filters
  // change.
  const [kept, setKept] = useState<ReadonlySet<string>>(NO_SLUGS);
  const [selected, setSelected] = useState<ReadonlySet<string>>(NO_SLUGS);

  useEffect(() => {
    setReview(urlReview);
    setKept(NO_SLUGS);
  }, [urlReview]);

  // Dialogs.
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<{ tenant: Tenant; confirm: boolean } | null>(null);
  const [offboarding, setOffboarding] = useState<Tenant | null>(null);
  const [merging, setMerging] = useState<{ tenant: Tenant; target?: string } | null>(null);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [signing, setSigning] = useState<Tenant | null>(null);
  const [locating, setLocating] = useState<Tenant | null>(null);
  const [busySlug, setBusySlug] = useState<string | null>(null);

  const keep = (slugs: readonly string[]): void =>
    setKept((prev) => new Set([...prev, ...slugs]));
  /** Any filter change: what was kept on screen is released. */
  const refilter =
    <T,>(setter: (v: T) => void) =>
    (v: T): void => {
      setter(v);
      setKept(NO_SLUGS);
    };
  const changeReview = (next: ReviewFilter): void => {
    setReview(next);
    setKept(NO_SLUGS);
    // The URL is the review filter's home: the deep link, Back, and any
    // plain /settings/tenants navigation all agree with what is shown.
    // (Navigating to the path already shown is a no-op.)
    onNavigate(reviewFilterPath(next));
  };
  const clearFilters = (): void => {
    changeReview("all");
    setSearch("");
    setKindFilter("all");
    setComplianceFilter("all");
    setOriginFilter("all");
  };

  // `background`: the 30 s poll. It refreshes the data but never clears an
  // error the operator has not read (a failed Confirm must stay on screen
  // until the next thing THEY do); a failed poll does report itself.
  const reload = useCallback(
    async (background = false): Promise<void> => {
      if (!isAdminPlus) return;
      if (!background) setError(null);
      try {
        const [list, reqs, alone] = await Promise.all([
          listTenants(),
          listChangeRequests("pending"),
          listChangeRequests("all", "single_attested"),
        ]);
        setData(list);
        setRequests(reqs);
        setAttested(alone);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load tenants");
      } finally {
        setLoading(false);
      }
    },
    [isAdminPlus],
  );

  useEffect(() => {
    void reload();
  }, [reload]);

  // The request queue is the two-person handshake: keep it fresh while the
  // page is open so the second person sees it without a manual refresh.
  useEffect(() => {
    if (!isAdminPlus) return undefined;
    const id = window.setInterval(() => {
      if (document.visibilityState !== "hidden") void reload(true);
    }, REQUEST_POLL_MS);
    return () => window.clearInterval(id);
  }, [isAdminPlus, reload]);

  // Follows every reload (`data` is a fresh response object per load).
  const tenants = useMemo(() => data?.tenants ?? [], [data]);
  const vocab = useMemo(
    () => ({
      kinds: data?.kinds ?? [],
      compliance_tags: data?.compliance_tags ?? [],
      ai_policies: data?.ai_policies ?? [],
    }),
    [data],
  );

  const bySlug = useMemo(() => new Map(tenants.map((t) => [t.slug, t])), [tenants]);

  const { visible, hidden, keptOnly } = useMemo(() => {
    const matches = (t: Tenant): boolean =>
      (review === "all" || (review === "needs-review" ? needsReview(t) : t.review_state === "confirmed")) &&
      (kindFilter === "all" || t.kind === kindFilter) &&
      (complianceFilter === "all" || t.compliance_flags.includes(complianceFilter)) &&
      (originFilter === "all" || t.origin === originFilter) &&
      matchesSearch(t, search);
    // Archived rows sit behind their own toggle — they are history, not
    // something a filter hides.
    const base = tenants.filter((t) => includeArchived || t.status !== "archived");
    const only = new Set<string>();
    const filtered = base.filter((t) => {
      if (matches(t)) return true;
      if (kept.has(t.slug)) {
        only.add(t.slug);
        return true;
      }
      return false;
    });
    const dir = sortDir === "asc" ? 1 : -1;
    const cmp = (a: Tenant, b: Tenant): number => {
      switch (sortKey) {
        case "name":
          return a.display_name.localeCompare(b.display_name);
        case "kind":
          return a.kind.localeCompare(b.kind);
        case "origin":
          return a.origin.localeCompare(b.origin);
        case "events":
          return a.event_count - b.event_count;
        case "last_event":
          return (a.last_event_at ?? "").localeCompare(b.last_event_at ?? "");
        case "review":
        default: {
          // Needs-review first, then active before the rest, then by name.
          const pa = needsReview(a) ? 0 : 1;
          const pb = needsReview(b) ? 0 : 1;
          if (pa !== pb) return pa - pb;
          const sa = a.status === "active" ? 0 : 1;
          const sb = b.status === "active" ? 0 : 1;
          if (sa !== sb) return sa - sb;
          return a.display_name.localeCompare(b.display_name);
        }
      }
    };
    return {
      visible: [...filtered].sort((a, b) => dir * cmp(a, b)),
      hidden: base.length - filtered.length,
      keptOnly: only as ReadonlySet<string>,
    };
  }, [tenants, includeArchived, review, search, kindFilter, complianceFilter, originFilter, kept, sortKey, sortDir]);

  // Bulk acts on what the operator can SEE selected — a row hidden by a
  // filter is never edited behind their back.
  const selectable = useMemo(() => visible.filter((t) => t.status !== "archived"), [visible]);
  const selectedRows = useMemo(() => selectable.filter((t) => selected.has(t.slug)), [selectable, selected]);
  const allShownSelected = selectable.length > 0 && selectedRows.length === selectable.length;
  const toggleSelected = (slug: string): void =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(slug)) next.delete(slug);
      else next.add(slug);
      return next;
    });
  const toggleAllShown = (): void =>
    setSelected(allShownSelected ? NO_SLUGS : new Set(selectable.map((t) => t.slug)));

  const onSort = (key: SortKey): void => {
    if (key === sortKey) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const confirmNow = async (t: Tenant): Promise<void> => {
    // A kind is set: confirm in one click. Unclassified: the Edit dialog
    // opens in confirm mode — 'unclassified' is never confirmed.
    if (t.kind === "unclassified") {
      setEditing({ tenant: t, confirm: true });
      return;
    }
    setBusySlug(t.slug);
    setError(null);
    try {
      await patchTenant(t.slug, { review_state: "confirmed" });
      setNotice(`Tenant ${t.slug} confirmed as ${labelFor(KIND_LABEL, t.kind)}.`);
      keep([t.slug]);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Confirm failed");
    } finally {
      setBusySlug(null);
    }
  };

  const decide = async (r: ChangeRequest, decision: "approve" | "reject" | "cancel", note: string): Promise<void> => {
    setError(null);
    try {
      const out = await decideChangeRequest(r.id, decision, note);
      setNotice(
        decision === "approve"
          ? `Request #${out.id} approved and applied: ${out.kind} of ${out.subject_slug}${out.target_slug ? ` into ${out.target_slug}` : ""}.`
          : decision === "reject"
            ? `Request #${out.id} rejected.`
            : `Request #${out.id} cancelled.`,
      );
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : `Could not ${decision} the request`);
    }
  };

  const postReview = async (r: ChangeRequest, verdict: PostReviewVerdict, note: string): Promise<void> => {
    setError(null);
    try {
      const out = await postReviewChangeRequest(r.id, verdict, note);
      setNotice(`Post-review of change #${out.id} recorded: ${labelFor(POST_REVIEW_LABEL, out.post_review_state ?? "")}.`);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not record the post-review");
    }
  };

  if (!me) {
    return (
      <section className="rounded-lg border border-border bg-bg-surface p-6 text-text-dim">
        Loading identity…
      </section>
    );
  }
  if (!isAdminPlus) {
    // Defence in depth: the nav hides the tab; the server answers 403; and
    // this page fetches nothing for a non-admin.
    return (
      <section role="alert" data-testid="tenants-forbidden" className="rounded-lg border border-border bg-bg-surface p-6 text-sm text-text-secondary">
        Tenant management is for admins.
      </section>
    );
  }

  const pendingCount = data?.pending_review ?? 0;
  const heldCount = data?.quarantined ?? 0;

  return (
    <section className="rounded-lg border border-border bg-bg-surface p-6">
      <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="mb-1 text-lg font-semibold text-text-primary">Tenants</h1>
          <p className="text-sm text-text-dim">
            Every vendor site gets a bucket. Say what each tenant is (client, internal, dev, vendor,
            other), which compliance regimes apply, and route whatever the integrations could not
            attribute. Every change here is audit-logged.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <div className="flex rounded-sm border border-border" role="tablist" aria-label="tenant views">
            <ViewTab
              active={view === "tenants"}
              onClick={() => onNavigate("/settings/tenants")}
              label="Tenants"
              count={pendingCount}
              countLabel="need review"
              testId="view-tenants"
            />
            <ViewTab
              active={view === "quarantine"}
              onClick={() => onNavigate("/settings/tenants/quarantine")}
              label="Quarantine"
              count={heldCount}
              countLabel="held"
              testId="view-quarantine"
            />
            <ViewTab
              active={view === "links"}
              onClick={() => onNavigate("/settings/tenants/links")}
              label="Entity links"
              count={0}
              countLabel=""
              testId="view-links"
            />
          </div>
          {view === "tenants" ? (
            <button
              type="button"
              onClick={() => setAdding(true)}
              data-testid="add-tenant"
              className="rounded-sm border border-accent-cta bg-accent-cta px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong"
            >
              + Add tenant
            </button>
          ) : null}
        </div>
      </header>

      {error ? (
        <div role="alert" className="mb-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical">
          {error}
        </div>
      ) : null}
      {notice ? (
        <p role="status" data-testid="tenants-notice" className="mb-3 rounded border border-border bg-bg-card px-3 py-2 text-xs text-text-secondary">
          {notice}
        </p>
      ) : null}

      {view === "links" ? (
        <EntityLinksView
          tenants={tenants.filter((t) => t.status === "active").map((t) => ({ slug: t.slug, name: t.display_name }))}
          initialSlug={initialClient}
        />
      ) : view === "quarantine" ? (
        <QuarantineReviewPanel initialInstanceId={initialInstanceId} onChanged={() => void reload()} />
      ) : loading ? (
        <p className="text-sm text-text-dim">Loading tenants…</p>
      ) : (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-2 text-[11px] text-text-secondary">
            <input
              type="search"
              aria-label="search tenants"
              className={`${inputCls} min-w-[200px]`}
              placeholder="search name or slug"
              value={search}
              maxLength={200}
              onChange={(e) => refilter(setSearch)(e.target.value)}
            />
            <select
              aria-label="filter by review state"
              className={inputCls}
              value={review}
              onChange={(e) => changeReview(e.target.value as ReviewFilter)}
              title="Needs review = active tenants still awaiting a kind (the dashboard notice's count). Disabled / offboarded tenants never count."
            >
              <option value="all">any review state</option>
              <option value="needs-review">needs review{pendingCount ? ` (${pendingCount})` : ""}</option>
              <option value="confirmed">confirmed</option>
            </select>
            <select aria-label="filter by kind" className={inputCls} value={kindFilter} onChange={(e) => refilter(setKindFilter)(e.target.value)}>
              <option value="all">any kind</option>
              {vocab.kinds.map((k) => (
                <option key={k} value={k}>
                  {labelFor(KIND_LABEL, k)}
                </option>
              ))}
            </select>
            <select
              aria-label="filter by compliance"
              className={inputCls}
              value={complianceFilter}
              onChange={(e) => refilter(setComplianceFilter)(e.target.value)}
            >
              <option value="all">any compliance</option>
              {vocab.compliance_tags.map((c) => (
                <option key={c} value={c}>
                  {labelFor(COMPLIANCE_LABEL, c)}
                </option>
              ))}
            </select>
            <select aria-label="filter by origin" className={inputCls} value={originFilter} onChange={(e) => refilter(setOriginFilter)(e.target.value)}>
              <option value="all">any origin</option>
              {["bootstrap", "manual", "auto"].map((o) => (
                <option key={o} value={o}>
                  {labelFor(ORIGIN_LABEL, o)}
                </option>
              ))}
            </select>
            <label className="inline-flex items-center gap-1">
              <input
                type="checkbox"
                checked={includeArchived}
                onChange={(e) => setIncludeArchived(e.target.checked)}
                aria-label="include archived"
              />
              include archived
            </label>
            <span className="ml-auto text-text-dim" data-testid="tenants-count">
              {visible.length} of {tenants.length}
            </span>
          </div>

          {hidden > 0 ? (
            <p className="mb-2 text-[11px] text-text-secondary" data-testid="hidden-by-filters">
              {hidden} hidden by filters —{" "}
              <button type="button" className="text-accent underline decoration-dotted underline-offset-2" onClick={clearFilters} data-testid="clear-filters">
                Clear filters
              </button>
            </p>
          ) : null}
          {keptOnly.size > 0 ? (
            <p role="status" className="mb-2 rounded border border-border bg-bg-card px-3 py-2 text-[11px] text-text-secondary" data-testid="kept-visible-note">
              {keptOnly.size} row(s) you just changed no longer match these filters — kept on screen until
              the filters change.{" "}
              <button type="button" className="text-accent underline decoration-dotted underline-offset-2" onClick={clearFilters} data-testid="show-all-tenants">
                Show all tenants
              </button>
            </p>
          ) : null}
          {selectedRows.length > 0 ? (
            <div className="mb-2 flex flex-wrap items-center gap-2 rounded border border-accent/40 bg-accent/5 px-3 py-2 text-xs" data-testid="bulk-bar">
              <span className="text-text-primary">{selectedRows.length} selected</span>
              <button
                type="button"
                className={`${rowBtn} border-accent text-accent`}
                disabled={selectedRows.length > BULK_UPDATE_MAX}
                title={selectedRows.length > BULK_UPDATE_MAX ? `At most ${BULK_UPDATE_MAX} tenants at once.` : ""}
                onClick={() => setBulkOpen(true)}
                data-testid="bulk-edit"
              >
                Bulk edit…
              </button>
              <button type="button" className={rowBtn} onClick={() => setSelected(NO_SLUGS)} data-testid="clear-selection">
                Clear selection
              </button>
              {selectedRows.length > BULK_UPDATE_MAX ? (
                <span className="text-[11px] text-high">At most {BULK_UPDATE_MAX} tenants at once — narrow the selection.</span>
              ) : null}
            </div>
          ) : null}

          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-left text-xs" data-testid="tenants-table">
              <thead className="border-b border-border text-text-dim">
                <tr>
                  <th className="w-6 px-3 py-2 font-normal">
                    <input
                      type="checkbox"
                      aria-label="select all shown"
                      checked={allShownSelected}
                      disabled={selectable.length === 0}
                      onChange={toggleAllShown}
                      data-testid="select-all"
                    />
                  </th>
                  <SortTh label="Tenant" k="name" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortTh label="Kind" k="kind" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <th className="px-3 py-2 font-normal">Compliance</th>
                  <SortTh label="Origin" k="origin" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortTh label="Review" k="review" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <SortTh label="Events" k="events" sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
                  <th className="px-3 py-2 font-normal">Sources</th>
                  <th className="px-3 py-2 font-normal">AI</th>
                  <th className="px-3 py-2 text-right font-normal">Actions</th>
                </tr>
              </thead>
              <tbody>
                {visible.length === 0 ? (
                  <tr>
                    <td colSpan={10} className="px-3 py-6 text-center text-text-dim" data-testid="tenants-empty">
                      {tenants.length === 0 ? "No tenants yet." : "No tenants match these filters."}
                    </td>
                  </tr>
                ) : (
                  visible.map((t) => {
                    const pending = needsReview(t);
                    const locked = t.pending_request !== null;
                    return (
                      <tr
                        key={t.slug}
                        data-testid={`tenant-row-${t.slug}`}
                        className={`border-b border-border/40 align-top last:border-b-0 ${pending ? "bg-high/5" : ""}`}
                      >
                        <td className="px-3 py-2">
                          <input
                            type="checkbox"
                            aria-label={`select ${t.slug}`}
                            checked={selected.has(t.slug)}
                            disabled={t.status === "archived"}
                            onChange={() => toggleSelected(t.slug)}
                            data-testid={`select-${t.slug}`}
                          />
                        </td>
                        <td className="px-3 py-2">
                          <div className="font-semibold text-text-primary">{t.display_name}</div>
                          <div className="font-mono text-[10px] text-text-dim">{t.slug}</div>
                          {t.status !== "active" ? (
                            <span className={`mt-1 ${badge(t.status === "archived" ? "dim" : "critical")}`}>
                              {labelFor(STATUS_LABEL, t.status)}
                            </span>
                          ) : null}
                          {t.notes ? <div className="mt-1 text-[10px] text-text-dim">{t.notes}</div> : null}
                          {t.placeholder_name ? (
                            <div className="mt-1">
                              <span
                                className={badge("high")}
                                data-testid={`placeholder-name-${t.slug}`}
                                title="Auto-created with no name from the vendor, so it is named after the vendor. Client users must never see vendor names: the server refuses to invite a viewer to this tenant until you rename it (Edit)."
                              >
                                placeholder name — rename before inviting client users
                              </span>
                            </div>
                          ) : null}
                          {t.placeholder_slug ? (
                            <div className="mt-1">
                              <span
                                className={badge("high")}
                                data-testid={`placeholder-slug-${t.slug}`}
                                title="The slug was made from the vendor-named placeholder and a slug can't be renamed. Client users see their tenant's slug, so the server refuses to invite a viewer here: create the tenant under a proper slug and merge this one into it."
                              >
                                placeholder slug — merge into a properly named tenant before inviting client users
                              </span>
                            </div>
                          ) : null}
                          {(t.duplicate_hints ?? []).map((h) => {
                            const merge = mergeFor(t, bySlug.get(h.slug));
                            return (
                              <div
                                key={h.slug}
                                className="mt-1 flex flex-wrap items-center gap-1"
                                data-testid={`duplicate-hint-${t.slug}-${h.slug}`}
                              >
                                <span className={badge("high")} title={DUPLICATE_RULE_HELP[h.rule] ?? ""}>
                                  possible duplicate of {h.display_name}
                                  {h.status !== "active" ? ` (${labelFor(STATUS_LABEL, h.status)})` : ""}
                                </span>
                                {merge ? (
                                  <button
                                    type="button"
                                    className={rowBtn}
                                    onClick={() => setMerging({ tenant: merge.subject, target: merge.target })}
                                    title={`Merge ${merge.subject.slug} into ${merge.target}: the merge dialog opens; nothing happens until you confirm there.`}
                                    data-testid={`duplicate-merge-${t.slug}-${h.slug}`}
                                  >
                                    {merge.subject.slug === t.slug ? "Merge this into it…" : "Merge it into this…"}
                                  </button>
                                ) : null}
                              </div>
                            );
                          })}
                        </td>
                        <td className="px-3 py-2">
                          <span className={badge(t.kind === "unclassified" ? "high" : "accent")} data-testid="kind-badge">
                            {labelFor(KIND_LABEL, t.kind)}
                          </span>
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex flex-wrap gap-1">
                            {t.compliance_flags.length === 0 ? (
                              <span className="text-[10px] text-text-dim">—</span>
                            ) : (
                              t.compliance_flags.map((c) => (
                                <span key={c} className={badge(c === "none" ? "dim" : "accent")} data-testid="compliance-badge">
                                  {labelFor(COMPLIANCE_LABEL, c)}
                                </span>
                              ))
                            )}
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          <span className="font-mono text-[10px] text-text-secondary">{labelFor(ORIGIN_LABEL, t.origin)}</span>
                          {t.created_by_instance ? (
                            <div className="text-[10px] text-text-dim">by {t.created_by_instance.label}</div>
                          ) : null}
                        </td>
                        <td className="px-3 py-2">
                          {pending ? (
                            <span className={badge("high")} data-testid="needs-review-chip">
                              Needs review
                            </span>
                          ) : t.review_state === "confirmed" ? (
                            <span className={badge("success")}>confirmed</span>
                          ) : (
                            <span
                              className={badge("dim")}
                              data-testid="pending-inactive-chip"
                              title="Not counted as needing review: a tenant that is not active receives no traffic. Confirm it to clear it."
                            >
                              pending · {labelFor(STATUS_LABEL, t.status)}
                            </span>
                          )}
                          {keptOnly.has(t.slug) ? (
                            <div className="mt-1 text-[10px] text-text-dim" data-testid="kept-visible-chip">
                              kept on screen
                            </div>
                          ) : null}
                        </td>
                        <td className="px-3 py-2">
                          <div className="font-mono text-text-primary">{t.event_count}</div>
                          <div className="text-[10px] text-text-dim">
                            {t.last_event_at ? `last ${formatRelative(t.last_event_at)}` : "none yet"}
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          {t.mapped_sources.length === 0 ? (
                            <span className="text-[10px] text-text-dim">no mapped site</span>
                          ) : (
                            <ul className="flex flex-col gap-0.5">
                              {t.mapped_sources.map((s) => (
                                <li key={`${s.instance_id}:${s.vendor_tenant_id}`} className="text-[11px] text-text-secondary">
                                  <span className="font-mono text-[10px] text-text-dim">{s.vendor}</span>{" "}
                                  {s.label ?? s.vendor_tenant_id}
                                  <span className="text-[10px] text-text-dim"> · {s.match_source}</span>
                                </li>
                              ))}
                            </ul>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          <AiPolicyCell t={t} isSuperAdmin={isSuperAdmin} onOpen={() => setSigning(t)} />
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex flex-wrap justify-end gap-1">
                            {locked && t.pending_request ? (
                              <span className={badge("high")} data-testid="pending-request-badge" title={t.pending_request.reason}>
                                {t.pending_request.kind} request #{t.pending_request.id}
                              </span>
                            ) : null}
                            {canConfirm(t) ? (
                              <button
                                type="button"
                                className={`${rowBtn} border-accent text-accent`}
                                disabled={busySlug === t.slug}
                                onClick={() => void confirmNow(t)}
                                title={
                                  t.kind === "unclassified"
                                    ? "Pick a kind first — “unclassified” cannot be confirmed."
                                    : `Confirm as ${labelFor(KIND_LABEL, t.kind)}`
                                }
                                data-testid={`confirm-${t.slug}`}
                              >
                                {busySlug === t.slug ? "Confirming…" : "Confirm"}
                              </button>
                            ) : null}
                            {t.status !== "archived" ? (
                              <button
                                type="button"
                                className={rowBtn}
                                onClick={() => setEditing({ tenant: t, confirm: false })}
                                data-testid={`edit-${t.slug}`}
                              >
                                Edit
                              </button>
                            ) : null}
                            {isAdminPlus && t.status === "active" ? (
                              <button
                                type="button"
                                className={rowBtn}
                                onClick={() => setLocating(t)}
                                title="Fleet map location: for a client without a UniFi console location (admin+, audited)"
                                data-testid={`location-${t.slug}`}
                              >
                                Location…
                              </button>
                            ) : null}
                            {canOffboard(t) ? (
                              <button
                                type="button"
                                className={`${rowBtn} text-critical`}
                                disabled={locked}
                                title={locked ? "A change request is pending for this tenant." : ""}
                                onClick={() => setOffboarding(t)}
                                data-testid={`offboard-${t.slug}`}
                              >
                                {isSuperAdmin ? "Offboard" : "Request offboard"}
                              </button>
                            ) : null}
                            {canMergeFrom(t) ? (
                              <button
                                type="button"
                                className={rowBtn}
                                disabled={locked}
                                title={locked ? "A change request is pending for this tenant." : ""}
                                onClick={() => setMerging({ tenant: t })}
                                data-testid={`merge-${t.slug}`}
                              >
                                Merge into…
                              </button>
                            ) : null}
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          <RequestsPanel requests={requests} me={me} isSuperAdmin={isSuperAdmin} onDecide={decide} />
          <AttestedChangesPanel changes={attested} me={me} onPostReview={postReview} />
        </>
      )}

      {adding ? (
        <TenantFormDialog
          tenant={null}
          vocab={vocab}
          isSuperAdmin={isSuperAdmin}
          onClose={() => setAdding(false)}
          onSaved={(_t, note) => {
            setAdding(false);
            setNotice(note);
            void reload();
          }}
        />
      ) : null}
      {editing ? (
        <TenantFormDialog
          tenant={editing.tenant}
          vocab={vocab}
          isSuperAdmin={isSuperAdmin}
          confirmOnSave={editing.confirm}
          onClose={() => setEditing(null)}
          onSaved={(t, note) => {
            setEditing(null);
            setNotice(note);
            keep([t.slug]);
            void reload();
          }}
        />
      ) : null}
      {bulkOpen ? (
        <BulkEditDialog
          tenants={selectedRows}
          vocab={vocab}
          isSuperAdmin={isSuperAdmin}
          onClose={() => setBulkOpen(false)}
          onApplied={(r, note) => {
            setBulkOpen(false);
            setNotice(note);
            keep(r.rows.filter((row) => row.changes.length > 0).map((row) => row.slug));
            setSelected(NO_SLUGS);
            void reload();
          }}
        />
      ) : null}
      {signing ? (
        <ComplianceSignoffDialog
          tenant={signing}
          isSuperAdmin={isSuperAdmin}
          onClose={() => setSigning(null)}
          onDone={(note) => {
            setSigning(null);
            setNotice(note);
            keep([signing.slug]);
            void reload();
          }}
        />
      ) : null}
      {locating ? (
        <TenantLocationDialog
          tenant={locating}
          onClose={() => setLocating(null)}
          onDone={(note) => {
            setLocating(null);
            setNotice(note);
            keep([locating.slug]);
          }}
        />
      ) : null}
      {offboarding ? (
        <OffboardDialog
          tenant={offboarding}
          isSuperAdmin={isSuperAdmin}
          onClose={() => setOffboarding(null)}
          onDone={(_r, note) => {
            setOffboarding(null);
            setNotice(note);
            void reload();
          }}
        />
      ) : null}
      {merging ? (
        <MergeDialog
          tenant={merging.tenant}
          candidates={tenants}
          isSuperAdmin={isSuperAdmin}
          initialTarget={merging.target}
          onClose={() => setMerging(null)}
          onDone={(_r, note) => {
            setMerging(null);
            setNotice(note);
            void reload();
          }}
        />
      ) : null}
    </section>
  );
};

/** Requested vs what RUNS, with the reason — and the way to the sign-off
 *  dialog. "cloud → local" is never shortened to "cloud". */
const AiPolicyCell: FC<{
  readonly t: Tenant;
  readonly isSuperAdmin: boolean;
  readonly onOpen: () => void;
}> = ({ t, isSuperAdmin, onOpen }) => {
  const view = aiPolicyView(t);
  const state = t.signoff?.state;
  const signable = isSuperAdmin && canSignOff(t) && t.ai_policy === "cloud";
  const showLink = t.status !== "archived" && (t.ai_policy === "cloud" || (t.signoff?.signoff_id ?? null) !== null);
  return (
    <div className="flex flex-col items-start gap-1">
      <span className={badge(view.tone)} title={view.title} data-testid={`ai-policy-${t.slug}`}>
        {view.label}
      </span>
      {view.degraded ? (
        <span className="text-[10px] text-high" data-testid={`ai-policy-why-${t.slug}`} title={view.title}>
          {state ? labelFor(SIGNOFF_STATE_LABEL, state) : "runs as local"}
        </span>
      ) : state === "live" && t.signoff?.expires_at ? (
        <span className="text-[10px] text-text-dim">signed until {t.signoff.expires_at.slice(0, 10)}</span>
      ) : null}
      {signable ? (
        <button
          type="button"
          className={`${rowBtn} border-accent text-accent`}
          onClick={onOpen}
          title="Record the compliance sign-off cloud AI needs (step-up re-authentication)."
          data-testid={`sign-off-${t.slug}`}
        >
          Sign off…
        </button>
      ) : showLink ? (
        <button
          type="button"
          className="text-[10px] text-accent underline decoration-dotted underline-offset-2"
          onClick={onOpen}
          data-testid={`signoffs-${t.slug}`}
        >
          sign-offs…
        </button>
      ) : null}
    </div>
  );
};

const ViewTab: FC<{
  readonly active: boolean;
  readonly onClick: () => void;
  readonly label: string;
  readonly count: number;
  readonly countLabel: string;
  readonly testId: string;
}> = ({ active, onClick, label, count, countLabel, testId }) => (
  <button
    type="button"
    role="tab"
    aria-selected={active}
    onClick={onClick}
    data-testid={testId}
    className={[
      "px-3 py-1.5 text-xs",
      active ? "bg-accent/15 text-accent" : "text-text-secondary hover:text-text-primary",
    ].join(" ")}
  >
    {label}
    {count > 0 ? (
      <span className="ml-1 rounded-full bg-high/20 px-1.5 font-mono text-[10px] text-high" title={`${count} ${countLabel}`}>
        {count}
      </span>
    ) : null}
  </button>
);

const SortTh: FC<{
  readonly label: string;
  readonly k: SortKey;
  readonly sortKey: SortKey;
  readonly sortDir: "asc" | "desc";
  readonly onSort: (k: SortKey) => void;
}> = ({ label, k, sortKey, sortDir, onSort }) => (
  <th className="px-3 py-2 font-normal">
    <button
      type="button"
      onClick={() => onSort(k)}
      className={`inline-flex items-center gap-1 hover:text-text-primary ${sortKey === k ? "text-text-primary" : ""}`}
      aria-sort={sortKey === k ? (sortDir === "asc" ? "ascending" : "descending") : "none"}
    >
      {label}
      {sortKey === k ? <span aria-hidden="true">{sortDir === "asc" ? "▲" : "▼"}</span> : null}
    </button>
  </th>
);

// ---------------------------------------------------------------------------
// Requests — the two-person queue
// ---------------------------------------------------------------------------

const RequestsPanel: FC<{
  readonly requests: readonly ChangeRequest[];
  readonly me: MeResponse;
  readonly isSuperAdmin: boolean;
  readonly onDecide: (r: ChangeRequest, decision: "approve" | "reject" | "cancel", note: string) => Promise<void>;
}> = ({ requests, me, isSuperAdmin, onDecide }) => {
  const [notes, setNotes] = useState<Record<number, string>>({});
  const [busy, setBusy] = useState<number | null>(null);

  const act = async (r: ChangeRequest, decision: "approve" | "reject" | "cancel"): Promise<void> => {
    setBusy(r.id);
    try {
      await onDecide(r, decision, notes[r.id] ?? "");
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="mt-5" data-testid="requests-panel">
      <h2 className="mb-1 text-sm font-semibold text-text-primary">
        Change requests{requests.length ? ` (${requests.length} pending)` : ""}
      </h2>
      <p className="mb-2 text-[11px] leading-relaxed text-text-dim">
        Two-person approval is the default: offboards and merges wait here for a super admin — never
        the one who asked — to approve. Approving applies the change.
      </p>
      {requests.length === 0 ? (
        <p className="rounded border border-border bg-bg-card px-3 py-3 text-xs text-text-dim" data-testid="requests-empty">
          No pending requests.
        </p>
      ) : (
        <ul role="list" className="flex flex-col gap-2">
          {requests.map((r) => {
            const mine = r.requested_by === me.operator_id;
            const decideBlocked = !isSuperAdmin
              ? "Only a super admin can decide a request."
              : mine
                ? "You requested this — a different super admin must decide it (two-person rule)."
                : "";
            return (
              <li key={r.id} data-testid={`request-${r.id}`} className="flex flex-col gap-2 rounded-lg border border-border bg-bg-card p-3 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={badge("high")}>{r.kind}</span>
                  <span className="font-mono text-text-primary">
                    {r.subject_slug}
                    {r.target_slug ? ` → ${r.target_slug}` : ""}
                  </span>
                  <span className="text-text-dim">
                    #{r.id} · requested {formatRelative(r.requested_at)} by {mine ? "you" : `operator #${r.requested_by}`}
                  </span>
                </div>
                <p className="text-text-secondary">{r.reason}</p>
                <div className="flex flex-wrap items-center gap-2">
                  <input
                    aria-label={`decision note for request ${r.id}`}
                    className={`${inputCls} min-w-[220px] flex-1`}
                    placeholder="note (optional, audit-logged)"
                    value={notes[r.id] ?? ""}
                    maxLength={500}
                    onChange={(e) => setNotes((n) => ({ ...n, [r.id]: e.target.value }))}
                  />
                  {isSuperAdmin ? (
                    <>
                      <button
                        type="button"
                        className="rounded-sm border border-accent-cta bg-accent-cta px-3 py-1 text-[11px] font-semibold text-white disabled:cursor-not-allowed disabled:opacity-40"
                        disabled={busy === r.id || decideBlocked !== ""}
                        title={decideBlocked}
                        onClick={() => void act(r, "approve")}
                        data-testid={`approve-${r.id}`}
                      >
                        Approve & apply
                      </button>
                      <button
                        type="button"
                        className={`${rowBtn} text-critical`}
                        disabled={busy === r.id || decideBlocked !== ""}
                        title={decideBlocked}
                        onClick={() => void act(r, "reject")}
                        data-testid={`reject-${r.id}`}
                      >
                        Reject
                      </button>
                    </>
                  ) : null}
                  {mine ? (
                    <button
                      type="button"
                      className={rowBtn}
                      disabled={busy === r.id}
                      onClick={() => void act(r, "cancel")}
                      data-testid={`cancel-${r.id}`}
                    >
                      Cancel request
                    </button>
                  ) : null}
                  {decideBlocked ? (
                    <span className="text-[10px] text-text-dim" data-testid={`decide-blocked-${r.id}`}>
                      {decideBlocked}
                    </span>
                  ) : null}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
};

// ---------------------------------------------------------------------------
// Single-person changes — the attested exception, and its post-review
// ---------------------------------------------------------------------------

const POST_REVIEW_MIN = 3;

function reviewTone(state: string): "high" | "success" | "critical" | "dim" {
  if (state === "pending") return "high";
  if (state === "reviewed_ok") return "success";
  if (state === "reviewed_concern") return "critical";
  return "dim";
}

const AttestedChangesPanel: FC<{
  readonly changes: readonly ChangeRequest[];
  readonly me: MeResponse;
  readonly onPostReview: (r: ChangeRequest, verdict: PostReviewVerdict, note: string) => Promise<void>;
}> = ({ changes, me, onPostReview }) => {
  const [verdicts, setVerdicts] = useState<Record<number, PostReviewVerdict>>({});
  const [notes, setNotes] = useState<Record<number, string>>({});
  const [busy, setBusy] = useState<number | null>(null);
  const awaiting = changes.filter((c) => c.post_review_state === "pending").length;

  const submit = async (c: ChangeRequest): Promise<void> => {
    setBusy(c.id);
    try {
      await onPostReview(c, verdicts[c.id] ?? "ok", notes[c.id] ?? "");
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="mt-5" data-testid="attested-panel">
      <h2 className="mb-1 text-sm font-semibold text-text-primary">
        Single-person changes{awaiting ? ` (${awaiting} awaiting a post-review)` : ""}
      </h2>
      <p className="mb-2 text-[11px] leading-relaxed text-text-dim">
        Offboards and merges a super admin applied alone, on a typed attestation — the exception to
        two-person approval. Any admin other than the one who applied it can review it afterwards.
      </p>
      {changes.length === 0 ? (
        <p className="rounded border border-border bg-bg-card px-3 py-3 text-xs text-text-dim" data-testid="attested-empty">
          No single-person changes.
        </p>
      ) : (
        <ul role="list" className="flex flex-col gap-2">
          {changes.map((c) => {
            const mine = c.requested_by === me.operator_id;
            const state = c.post_review_state ?? "not_requested";
            const note = notes[c.id] ?? "";
            return (
              <li key={c.id} data-testid={`attested-${c.id}`} className="flex flex-col gap-2 rounded-lg border border-critical/40 bg-bg-card p-3 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={badge("critical")} data-testid={`attested-badge-${c.id}`}>
                    applied alone
                  </span>
                  <span className={badge("high")}>{c.kind}</span>
                  <span className="font-mono text-text-primary">
                    {c.subject_slug}
                    {c.target_slug ? ` → ${c.target_slug}` : ""}
                  </span>
                  <span className="text-text-dim">
                    #{c.id} · {formatRelative(c.decided_at ?? c.requested_at)} by {mine ? "you" : `operator #${c.requested_by}`}
                  </span>
                  <span className={badge(reviewTone(state))} data-testid={`post-review-state-${c.id}`}>
                    {labelFor(POST_REVIEW_LABEL, state)}
                  </span>
                </div>
                <p className="text-text-secondary">{c.reason}</p>
                <details className="text-[11px] text-text-secondary" open={state === "pending" && !mine}>
                  <summary className="cursor-pointer text-text-dim">attestation as typed · slug typed: {c.subject_confirmation ?? "—"}</summary>
                  <p className="mt-1 whitespace-pre-wrap" data-testid={`attestation-${c.id}`}>
                    {c.attestation}
                  </p>
                </details>
                {state === "reviewed_ok" || state === "reviewed_concern" ? (
                  <p className="text-[11px] text-text-secondary" data-testid={`post-review-${c.id}`}>
                    Reviewed by {c.post_reviewed_by === me.operator_id ? "you" : `operator #${c.post_reviewed_by ?? "?"}`}
                    {c.post_reviewed_at ? ` ${formatRelative(c.post_reviewed_at)}` : ""}: {c.post_review_note}
                  </p>
                ) : state === "pending" && mine ? (
                  <p className="text-[10px] text-text-dim" data-testid={`post-review-blocked-${c.id}`}>
                    You applied this alone — an admin other than you reviews it.
                  </p>
                ) : state === "pending" ? (
                  <div className="flex flex-wrap items-center gap-2">
                    <select
                      aria-label={`post-review verdict for change ${c.id}`}
                      className={inputCls}
                      value={verdicts[c.id] ?? "ok"}
                      onChange={(e) => setVerdicts((v) => ({ ...v, [c.id]: e.target.value as PostReviewVerdict }))}
                    >
                      <option value="ok">OK — nothing to add</option>
                      <option value="concern">Concern — raise it</option>
                    </select>
                    <input
                      aria-label={`post-review note for change ${c.id}`}
                      className={`${inputCls} min-w-[220px] flex-1`}
                      placeholder="note (required, audit-logged)"
                      value={note}
                      maxLength={500}
                      onChange={(e) => setNotes((n) => ({ ...n, [c.id]: e.target.value }))}
                    />
                    <button
                      type="button"
                      className="rounded-sm border border-accent-cta bg-accent-cta px-3 py-1 text-[11px] font-semibold text-white disabled:cursor-not-allowed disabled:opacity-40"
                      disabled={busy === c.id || note.trim().length < POST_REVIEW_MIN}
                      onClick={() => void submit(c)}
                      data-testid={`post-review-submit-${c.id}`}
                    >
                      Record post-review
                    </button>
                  </div>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
};

export default TenantsTab;


/**
 * Entity links (entity resolution, migration 040): one client at a time —
 * its rollout switch and its "Links to review" — plus the bundle-wide
 * known-benign list. Admin+ (this whole page is).
 */
const EntityLinksView: FC<{
  tenants: { slug: string; name: string }[];
  initialSlug?: string | undefined;
}> = ({ tenants, initialSlug }) => {
  const known = (s: string | undefined): s is string => !!s && tenants.some((t) => t.slug === s);
  const [slug, setSlug] = useState<string>(known(initialSlug) ? initialSlug : tenants[0]?.slug ?? "");
  // The deep link's client is applied ONCE per link (the tenant list loads
  // later); the operator's own pick in the selector is never overridden.
  const applied = useRef<string | undefined>(known(initialSlug) ? initialSlug : undefined);
  useEffect(() => {
    if (initialSlug && initialSlug !== applied.current && tenants.some((t) => t.slug === initialSlug)) {
      applied.current = initialSlug;
      setSlug(initialSlug);
    } else if (!slug && tenants[0]) {
      setSlug(tenants[0].slug);
    }
  }, [tenants, initialSlug, slug]);
  return (
    <div className="space-y-4" data-testid="entity-links-view">
      <label className="flex items-center gap-2 text-[11px] text-text-secondary">
        Client
        <select
          aria-label="client"
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          className={inputCls}
        >
          {tenants.map((t) => (
            <option key={t.slug} value={t.slug}>{t.name} ({t.slug})</option>
          ))}
        </select>
      </label>
      {slug ? <EntityLinksPanel key={slug} slug={slug} canAdmin /> : null}
      <KnownBenignPanel canEdit />
    </div>
  );
};
