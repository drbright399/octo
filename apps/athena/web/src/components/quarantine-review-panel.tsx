/**
 * QuarantineReviewPanel — the human side of the quarantine bucket.
 *
 * Held events are grouped by integration + vendor site + hold reason, each
 * group with its count and newest time. A group routes or discards as one
 * (the server's bulk routes, bounded per call); a single event can be
 * routed or discarded on its own. Routing to a tenant also MAPS the vendor
 * site so its future traffic goes straight there; routing never resurrects
 * an offboarded tenant (the reason text says so before the click).
 *
 * Threat model: the payload is UNTRUSTED vendor text. It is rendered as
 * text inside <pre> (React escapes it; there is no dangerouslySetInnerHTML
 * anywhere in this file), bounded on screen, copied verbatim on request.
 * Headlines and site labels are text too. Nothing here is interpreted.
 */
import { type FC, useCallback, useEffect, useMemo, useState } from "react";
import {
  KIND_LABEL,
  REASON_MAX,
  REASON_MIN,
  explainQuarantineReason,
  labelFor,
  type QuarantineDetail,
  type QuarantineRow,
  type RouteResponse,
  type RouteTarget,
  type Tenant,
} from "@/contracts/tenant";
import {
  bulkDiscardQuarantined,
  bulkRouteQuarantined,
  discardQuarantined,
  getQuarantined,
  listIntegrations,
  listQuarantine,
  listTenants,
  routeQuarantined,
} from "@/lib/api";
import { formatRelative } from "@/lib/time";
import { useClipboardCopy } from "@/lib/use-clipboard-copy";
import {
  ComplianceTagPicker,
  ErrorLine,
  KindSelect,
  ModalFrame,
  inputCls,
} from "@/components/tenant-dialogs";

/** Pages fetched to build the groups (server page cap is 200). Beyond this
 *  the panel says the view is partial rather than pretending. */
const PAGE = 200;
const MAX_PAGES = 5;
/** What the payload viewer shows before it says "…and N more characters". */
const PAYLOAD_VIEW_CHARS = 64 * 1024;

export interface QuarantineGroup {
  readonly key: string;
  readonly instance_id: number;
  readonly vendor: string;
  readonly vendor_tenant_id: string | null;
  readonly vendor_tenant_label: string | null;
  readonly reason: string;
  readonly rows: readonly QuarantineRow[];
  readonly newest_at: string;
  /** The server's same-name suggestion for the site, when it has one. */
  readonly suggested_slug: string | null;
  readonly suggested_name: string | null;
}

/** Pure: newest group first, rows newest first within a group. */
export function groupHeld(rows: readonly QuarantineRow[]): QuarantineGroup[] {
  const map = new Map<string, QuarantineRow[]>();
  for (const r of rows) {
    const key = `${r.instance_id}|${r.vendor_tenant_id ?? ""}|${r.reason}`;
    const bucket = map.get(key);
    if (bucket) bucket.push(r);
    else map.set(key, [r]);
  }
  const groups: QuarantineGroup[] = [];
  for (const [key, bucket] of map) {
    bucket.sort((a, b) => (a.received_at < b.received_at ? 1 : a.received_at > b.received_at ? -1 : b.id - a.id));
    const first = bucket[0];
    if (!first) continue;
    groups.push({
      key,
      instance_id: first.instance_id,
      vendor: first.vendor,
      vendor_tenant_id: first.vendor_tenant_id,
      vendor_tenant_label: bucket.find((r) => r.vendor_tenant_label)?.vendor_tenant_label ?? null,
      reason: first.reason,
      rows: bucket,
      newest_at: first.received_at,
      suggested_slug: bucket.find((r) => r.suggested_slug)?.suggested_slug ?? null,
      suggested_name: bucket.find((r) => r.suggested_slug)?.suggested_name ?? null,
    });
  }
  groups.sort((a, b) => (a.newest_at < b.newest_at ? 1 : a.newest_at > b.newest_at ? -1 : 0));
  return groups;
}

interface Props {
  /** Pre-filter to one integration instance (from the card's link). */
  readonly initialInstanceId?: number | undefined;
  /** Something was routed/discarded — parents refresh their counts. */
  readonly onChanged?: (() => void) | undefined;
}

type Scope =
  | { readonly kind: "group"; readonly group: QuarantineGroup }
  | { readonly kind: "row"; readonly row: QuarantineRow };

const btn =
  "rounded-sm border border-border bg-bg-input px-2 py-1 text-[11px] text-text-secondary hover:text-text-primary disabled:opacity-50";

export const QuarantineReviewPanel: FC<Props> = ({ initialInstanceId, onChanged }) => {
  const [rows, setRows] = useState<readonly QuarantineRow[]>([]);
  const [total, setTotal] = useState(0);
  const [partial, setPartial] = useState(false);
  const [reasons, setReasons] = useState<readonly string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [instanceFilter, setInstanceFilter] = useState<number | "all">(initialInstanceId ?? "all");
  const [reasonFilter, setReasonFilter] = useState<string>("all");
  const [vendorNames, setVendorNames] = useState<Readonly<Record<string, string>>>({});
  const [tenants, setTenants] = useState<readonly Tenant[]>([]);
  const [vocab, setVocab] = useState<{ kinds: readonly string[]; compliance_tags: readonly string[] }>({
    kinds: [],
    compliance_tags: [],
  });
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [routing, setRouting] = useState<Scope | null>(null);
  const [discarding, setDiscarding] = useState<Scope | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [mapping, setMapping] = useState<string | null>(null);

  const load = useCallback(async (): Promise<void> => {
    setError(null);
    try {
      const all: QuarantineRow[] = [];
      let offset = 0;
      let totalSeen = 0;
      let pages = 0;
      let reasonList: readonly string[] = [];
      // Everything held, page by page, so the groups are complete.
      for (;;) {
        const page = await listQuarantine({ state: "held", limit: PAGE, offset });
        all.push(...page.rows);
        totalSeen = page.total;
        reasonList = page.reasons;
        pages += 1;
        offset += page.rows.length;
        if (page.rows.length === 0 || offset >= page.total || pages >= MAX_PAGES) break;
      }
      setRows(all);
      setTotal(totalSeen);
      setPartial(all.length < totalSeen);
      setReasons(reasonList);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load quarantine");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    // Best effort: names for the group headers and tenants for the pickers.
    listIntegrations()
      .then((r) => {
        const names: Record<string, string> = {};
        for (const d of r.definitions) names[d.slug] = d.name;
        setVendorNames(names);
      })
      .catch(() => undefined);
    listTenants()
      .then((r) => {
        setTenants(r.tenants);
        setVocab({ kinds: r.kinds, compliance_tags: r.compliance_tags });
      })
      .catch(() => undefined);
  }, [load]);

  const groups = useMemo(() => groupHeld(rows), [rows]);
  const instances = useMemo(() => {
    const seen = new Map<number, string>();
    for (const g of groups) seen.set(g.instance_id, vendorNames[g.vendor] ?? g.vendor);
    return [...seen.entries()].sort((a, b) => a[0] - b[0]);
  }, [groups, vendorNames]);
  const visible = groups.filter(
    (g) =>
      (instanceFilter === "all" || g.instance_id === instanceFilter) &&
      (reasonFilter === "all" || g.reason === reasonFilter),
  );

  const toggle = (key: string): void =>
    setExpanded((s) => {
      const next = new Set(s);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const afterChange = (message: string): void => {
    setRouting(null);
    setDiscarding(null);
    setNotice(message);
    void load();
    listTenants().then((r) => setTenants(r.tenants)).catch(() => undefined);
    onChanged?.();
  };

  /** The one-click "map to <client>" of a name-match group: the operator's
   *  decision — the site is mapped there (match_source 'manual') and its
   *  held events routed. */
  const mapToSuggested = async (g: QuarantineGroup): Promise<void> => {
    if (!g.suggested_slug || g.vendor_tenant_id === null) return;
    setMapping(g.key);
    setError(null);
    try {
      const r = await bulkRouteQuarantined({
        instance_id: g.instance_id,
        vendor_tenant_id: g.vendor_tenant_id,
        quarantine_reason: g.reason,
        target: { slug: g.suggested_slug },
      });
      afterChange(
        `Mapped ${g.vendor_tenant_label ?? g.vendor_tenant_id} to ${g.suggested_name ?? r.slug} and routed ` +
          `${r.routed} event${r.routed === 1 ? "" : "s"}` +
          (r.duplicates ? ` (${r.duplicates} already there)` : "") +
          (r.skipped ? `; ${r.skipped} could not be replayed and stay held — discard them.` : "."),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Mapping failed");
    } finally {
      setMapping(null);
    }
  };

  if (loading) {
    return <p className="text-sm text-text-dim">Loading quarantine…</p>;
  }

  return (
    <div className="flex flex-col gap-3" data-testid="quarantine-review">
      <p className="text-xs leading-relaxed text-text-secondary">
        Events the integrations could not attribute to a tenant are held here — whole, nothing is
        dropped, nothing is created by itself. Route a group to the right tenant (the vendor site is
        mapped so its future traffic goes straight there) or discard it with a reason. Payloads are
        untrusted vendor text and are only ever shown as text.
      </p>
      {error ? (
        <div role="alert" className="rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical">
          {error}
        </div>
      ) : null}
      {notice ? (
        <p role="status" data-testid="quarantine-notice" className="rounded border border-border bg-bg-card px-3 py-2 text-xs text-text-secondary">
          {notice}
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-2 text-[11px] text-text-dim">
        <span data-testid="quarantine-held-total">
          {total} held event{total === 1 ? "" : "s"} in {groups.length} group{groups.length === 1 ? "" : "s"}
        </span>
        {partial ? (
          <span role="alert" className="text-high">
            Showing the newest {rows.length} only — route or discard some to see the rest.
          </span>
        ) : null}
        <select
          aria-label="filter by integration"
          className={inputCls}
          value={instanceFilter === "all" ? "all" : String(instanceFilter)}
          onChange={(e) => setInstanceFilter(e.target.value === "all" ? "all" : Number(e.target.value))}
        >
          <option value="all">all integrations</option>
          {instances.map(([id, name]) => (
            <option key={id} value={String(id)}>
              {name} #{id}
            </option>
          ))}
        </select>
        <select
          aria-label="filter by reason"
          className={inputCls}
          value={reasonFilter}
          onChange={(e) => setReasonFilter(e.target.value)}
        >
          <option value="all">all reasons</option>
          {reasons.map((r) => (
            <option key={r} value={r}>
              {explainQuarantineReason(r).title}
            </option>
          ))}
        </select>
        <button type="button" onClick={() => void load()} className={btn}>
          Refresh
        </button>
      </div>

      {visible.length === 0 ? (
        <p className="rounded border border-border bg-bg-card px-3 py-4 text-center text-xs text-text-dim" data-testid="quarantine-empty">
          {groups.length === 0 ? "Nothing is held in quarantine." : "No held events match these filters."}
        </p>
      ) : (
        <ul role="list" className="flex flex-col gap-2">
          {visible.map((g) => {
            const why = explainQuarantineReason(g.reason);
            const open = expanded.has(g.key);
            const canBulk = g.vendor_tenant_id !== null;
            // A truncated payload cannot be replayed: a bulk route skips it
            // (and counts it) and routes the rest, so say so before the click.
            const truncated = g.rows.filter((r) => r.payload_truncated).length;
            return (
              <li key={g.key} data-testid="quarantine-group" className="rounded-lg border border-border bg-bg-card p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <button
                    type="button"
                    onClick={() => toggle(g.key)}
                    aria-expanded={open}
                    className="flex min-w-0 flex-1 flex-col items-start gap-0.5 text-left"
                  >
                    <span className="text-sm font-semibold text-text-primary">
                      {vendorNames[g.vendor] ?? g.vendor}
                      <span className="text-text-dim"> · </span>
                      {g.vendor_tenant_label ?? (g.vendor_tenant_id ? "(site name unknown)" : "(no site id)")}
                    </span>
                    <span className="font-mono text-[10px] text-text-dim">
                      {g.vendor_tenant_id ? `site ${g.vendor_tenant_id}` : "no site id"} · instance #{g.instance_id}
                    </span>
                    <span className="text-[11px] text-high" data-testid="quarantine-group-reason">
                      {why.title} — {g.rows.length} event{g.rows.length === 1 ? "" : "s"}, newest{" "}
                      {formatRelative(g.newest_at)}
                    </span>
                    <span className="text-[11px] leading-relaxed text-text-secondary">{why.body}</span>
                    {truncated > 0 ? (
                      <span className="text-[11px] text-high" data-testid="group-truncated-hint">
                        {truncated} of these payloads {truncated === 1 ? "was" : "were"} truncated on arrival and cannot
                        be routed — “Route all” skips {truncated === 1 ? "it" : "them"} and routes the rest; discard{" "}
                        {truncated === 1 ? "it" : "them"} afterwards.
                      </span>
                    ) : null}
                  </button>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    {canBulk ? (
                      <>
                        {g.suggested_slug ? (
                          <button
                            type="button"
                            className="rounded-sm border border-accent bg-accent px-2 py-1 text-[11px] font-semibold text-text-on-accent disabled:opacity-50"
                            disabled={mapping !== null}
                            onClick={() => void mapToSuggested(g)}
                            data-testid="group-map-suggested"
                            title="Same name only — confirm it is this client before you click"
                          >
                            {mapping === g.key ? "Mapping…" : `Map to ${g.suggested_name ?? g.suggested_slug}`}
                          </button>
                        ) : null}
                        <button
                          type="button"
                          className="rounded-sm border border-accent bg-accent/10 px-2 py-1 text-[11px] text-accent hover:bg-accent/20"
                          onClick={() => setRouting({ kind: "group", group: g })}
                          data-testid="group-route-all"
                        >
                          Route all to…
                        </button>
                        <button
                          type="button"
                          className="rounded-sm border border-critical/50 bg-bg-input px-2 py-1 text-[11px] text-critical hover:bg-critical/10"
                          onClick={() => setDiscarding({ kind: "group", group: g })}
                          data-testid="group-discard-all"
                        >
                          Discard all
                        </button>
                      </>
                    ) : (
                      <span className="max-w-[180px] text-right text-[10px] text-text-dim">
                        No site id — route or discard each event on its own.
                      </span>
                    )}
                    <button type="button" className={btn} onClick={() => toggle(g.key)}>
                      {open ? "Hide events" : `Show ${g.rows.length} event${g.rows.length === 1 ? "" : "s"}`}
                    </button>
                  </div>
                </div>
                {open ? (
                  <ul role="list" className="mt-3 flex flex-col gap-1 border-t border-border/60 pt-2">
                    {g.rows.map((r) => (
                      <HeldEventRow
                        key={r.id}
                        row={r}
                        onRoute={() => setRouting({ kind: "row", row: r })}
                        onDiscard={() => setDiscarding({ kind: "row", row: r })}
                      />
                    ))}
                  </ul>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}

      {routing ? (
        <RouteDialog
          scope={routing}
          tenants={tenants}
          vocab={vocab}
          onClose={() => setRouting(null)}
          onDone={afterChange}
        />
      ) : null}
      {discarding ? (
        <DiscardDialog scope={discarding} onClose={() => setDiscarding(null)} onDone={afterChange} />
      ) : null}
    </div>
  );
};

// ---------------------------------------------------------------------------
// One held event + its payload viewer
// ---------------------------------------------------------------------------

const HeldEventRow: FC<{
  readonly row: QuarantineRow;
  readonly onRoute: () => void;
  readonly onDiscard: () => void;
}> = ({ row, onRoute, onDiscard }) => {
  const [detail, setDetail] = useState<QuarantineDetail | null>(null);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { state: copyState, copy } = useClipboardCopy();

  const view = async (): Promise<void> => {
    if (open) {
      setOpen(false);
      return;
    }
    setOpen(true);
    if (detail) return;
    setLoading(true);
    setError(null);
    try {
      setDetail(await getQuarantined(row.id));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load the payload");
    } finally {
      setLoading(false);
    }
  };

  const shown = detail ? detail.payload.slice(0, PAYLOAD_VIEW_CHARS) : "";
  const cut = detail ? detail.payload.length - shown.length : 0;

  return (
    <li data-testid="held-event" className="flex flex-col gap-1 rounded-sm px-1 py-1 hover:bg-bg-card-hover">
      <div className="flex flex-wrap items-center gap-2">
        <span className="min-w-0 flex-1 truncate text-xs text-text-primary" title={row.event_summary ?? ""}>
          {row.event_summary ?? "(no headline)"}
        </span>
        <span className="font-mono text-[10px] text-text-dim">
          <time dateTime={row.received_at}>{formatRelative(row.received_at)}</time> · {row.source}
          {row.payload_truncated ? " · payload truncated (cannot be routed)" : ""}
        </span>
        <button type="button" className={btn} onClick={() => void view()} data-testid="held-event-payload">
          {open ? "Hide payload" : "View payload"}
        </button>
        <button type="button" className={btn} onClick={onRoute} disabled={row.payload_truncated} data-testid="held-event-route">
          Route…
        </button>
        <button type="button" className={`${btn} text-critical`} onClick={onDiscard} data-testid="held-event-discard">
          Discard…
        </button>
      </div>
      {open ? (
        <div className="rounded border border-border bg-bg-deep p-2">
          {loading ? (
            <p className="text-[11px] text-text-dim">Loading payload…</p>
          ) : error ? (
            <p role="alert" className="text-[11px] text-critical">
              {error}
            </p>
          ) : detail ? (
            <>
              <div className="mb-1 flex items-center gap-2 font-mono text-[10px] text-text-dim">
                <span>sha256 {detail.payload_sha256.slice(0, 16)}…</span>
                <span>{detail.payload.length} chars</span>
                <button
                  type="button"
                  className={`ml-auto ${btn}`}
                  onClick={() => void copy(detail.payload)}
                  data-testid="payload-copy"
                >
                  {copyState === "copied" ? "Copied" : copyState === "failed" ? "Copy failed — select the text" : "Copy"}
                </button>
              </div>
              {/* TEXT ONLY: React escapes the string; no markup is ever interpreted. */}
              <pre
                data-testid="payload-text"
                className="max-h-[320px] overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] leading-snug text-text-secondary"
              >
                {shown}
              </pre>
              {cut > 0 ? (
                <p className="mt-1 text-[10px] text-text-dim">…and {cut} more characters — use Copy for the whole payload.</p>
              ) : null}
            </>
          ) : null}
        </div>
      ) : null}
    </li>
  );
};

// ---------------------------------------------------------------------------
// Route dialog — existing tenant OR create new inline
// ---------------------------------------------------------------------------

function scopeCount(scope: Scope): number {
  return scope.kind === "group" ? scope.group.rows.length : 1;
}

function scopeTitle(scope: Scope): string {
  if (scope.kind === "row") return scope.row.event_summary ?? `event #${scope.row.id}`;
  const g = scope.group;
  return `${g.rows.length} event${g.rows.length === 1 ? "" : "s"} from ${g.vendor_tenant_label ?? g.vendor_tenant_id ?? "(no site id)"}`;
}

const RouteDialog: FC<{
  readonly scope: Scope;
  readonly tenants: readonly Tenant[];
  readonly vocab: { readonly kinds: readonly string[]; readonly compliance_tags: readonly string[] };
  readonly onClose: () => void;
  readonly onDone: (message: string) => void;
}> = ({ scope, tenants, vocab, onClose, onDone }) => {
  const [mode, setMode] = useState<"existing" | "new">("existing");
  // A same-name suggestion pre-selects its client; the operator still decides.
  const [slug, setSlug] = useState(
    () => (scope.kind === "group" ? scope.group.suggested_slug : scope.row.suggested_slug) ?? "",
  );
  // The vendor's own site name is the natural name for a new tenant.
  const [newName, setNewName] = useState(
    () => (scope.kind === "group" ? scope.group.vendor_tenant_label : scope.row.vendor_tenant_label) ?? "",
  );
  const [newKind, setNewKind] = useState("client");
  const [newFlags, setNewFlags] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reason = scope.kind === "group" ? scope.group.reason : scope.row.reason;
  const why = explainQuarantineReason(reason);
  const active = useMemo(
    () => tenants.filter((t) => t.status === "active").sort((a, b) => a.display_name.localeCompare(b.display_name)),
    [tenants],
  );

  const canSubmit =
    !busy && (mode === "existing" ? slug !== "" : newName.trim().length > 0 && newKind !== "unclassified");

  const onSubmit = async (): Promise<void> => {
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    const target: RouteTarget =
      mode === "existing"
        ? { slug }
        : { new: { display_name: newName.trim(), kind: newKind, compliance_flags: newFlags } };
    try {
      let r: RouteResponse;
      if (scope.kind === "group") {
        const g = scope.group;
        if (g.vendor_tenant_id === null) throw new Error("This group has no site id — route each event on its own.");
        r = await bulkRouteQuarantined({
          instance_id: g.instance_id,
          vendor_tenant_id: g.vendor_tenant_id,
          quarantine_reason: g.reason,
          target,
        });
      } else {
        r = await routeQuarantined(scope.row.id, target);
      }
      onDone(
        `Routed ${r.routed} event${r.routed === 1 ? "" : "s"} to ${r.slug}` +
          (r.duplicates ? ` (${r.duplicates} already there)` : "") +
          (r.created_tenant ? ` — tenant created` : "") +
          (r.mapping_written ? "; the vendor site is now mapped there." : ".") +
          (r.skipped
            ? ` ${r.skipped} could not be replayed (payload truncated on arrival) and stay held — discard them.`
            : ""),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Route failed");
      setBusy(false);
    }
  };

  return (
    <ModalFrame label="Route held events" testId="route-dialog" busy={busy} onClose={onClose}>
      <h2 className="text-base font-semibold text-text-primary">Route {scopeTitle(scope)}</h2>
      <p className="mt-1 text-[11px] text-high">{why.title}</p>
      <p className="mt-1 text-xs leading-relaxed text-text-secondary">{why.body}</p>
      <p className="mt-2 text-xs leading-relaxed text-text-secondary">
        The event{scopeCount(scope) === 1 ? " is" : "s are"} ingested into the tenant through the
        integration's normal path, and the vendor site is mapped to it so future traffic routes
        there without review.
      </p>
      <div className="mt-3 flex gap-3 text-xs text-text-primary" role="radiogroup" aria-label="route target">
        <label className="inline-flex items-center gap-1">
          <input type="radio" name="route-mode" checked={mode === "existing"} onChange={() => setMode("existing")} />
          existing tenant
        </label>
        <label className="inline-flex items-center gap-1">
          <input type="radio" name="route-mode" checked={mode === "new"} onChange={() => setMode("new")} />
          create new tenant
        </label>
      </div>
      {mode === "existing" ? (
        <label className="mt-3 flex flex-col gap-1 text-xs text-text-primary">
          <span>Tenant</span>
          <select aria-label="target tenant" className={inputCls} value={slug} onChange={(e) => setSlug(e.target.value)}>
            <option value="">— select tenant —</option>
            {active.map((t) => (
              <option key={t.slug} value={t.slug}>
                {t.display_name} ({t.slug}){t.review_state === "pending" ? " — needs review" : ""}
              </option>
            ))}
          </select>
        </label>
      ) : (
        <div className="mt-3 flex flex-col gap-3">
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-text-dim">
            display name
            <input
              aria-label="new tenant display name"
              className={inputCls}
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Acme Corp"
            />
          </label>
          <KindSelect value={newKind} kinds={vocab.kinds} onChange={setNewKind} allowUnclassified={false} />
          <ComplianceTagPicker value={newFlags} tags={vocab.compliance_tags} onChange={setNewFlags} />
          <p className="text-[11px] text-text-dim">
            Created as {labelFor(KIND_LABEL, newKind)}, confirmed, AI policy “none”. The slug is derived
            from the name.
          </p>
        </div>
      )}
      <ErrorLine message={error} />
      <div className="mt-4 flex items-center justify-end gap-2">
        <button type="button" disabled={busy} onClick={onClose} className={btn}>
          Cancel
        </button>
        <button
          type="button"
          disabled={!canSubmit}
          onClick={() => void onSubmit()}
          className="rounded-sm border border-accent-cta bg-accent-cta px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
          data-testid="route-submit"
        >
          {busy ? "Routing…" : mode === "new" ? "Create tenant & route" : "Route"}
        </button>
      </div>
    </ModalFrame>
  );
};

// ---------------------------------------------------------------------------
// Discard dialog — reason required
// ---------------------------------------------------------------------------

const DiscardDialog: FC<{
  readonly scope: Scope;
  readonly onClose: () => void;
  readonly onDone: (message: string) => void;
}> = ({ scope, onClose, onDone }) => {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reasonOk = reason.trim().length >= REASON_MIN;
  const n = scopeCount(scope);

  const onSubmit = async (): Promise<void> => {
    if (!reasonOk || busy) return;
    setBusy(true);
    setError(null);
    try {
      if (scope.kind === "group") {
        const g = scope.group;
        if (g.vendor_tenant_id === null) throw new Error("This group has no site id — discard each event on its own.");
        const r = await bulkDiscardQuarantined({
          instance_id: g.instance_id,
          vendor_tenant_id: g.vendor_tenant_id,
          quarantine_reason: g.reason,
          reason: reason.trim(),
        });
        onDone(`Discarded ${r.discarded} event${r.discarded === 1 ? "" : "s"}.`);
      } else {
        await discardQuarantined(scope.row.id, reason.trim());
        onDone("Discarded 1 event.");
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Discard failed");
      setBusy(false);
    }
  };

  return (
    <ModalFrame label="Discard held events" testId="discard-dialog" busy={busy} onClose={onClose}>
      <h2 className="text-base font-semibold text-text-primary">
        Discard {n} event{n === 1 ? "" : "s"}?
      </h2>
      <p className="mt-2 text-xs leading-relaxed text-text-secondary">
        {scopeTitle(scope)}. Discarding is final for these events and writes no mapping: the same
        site's next event will be held again unless you route it. The decision and your reason go
        to the audit log.
      </p>
      <label className="mt-3 flex flex-col gap-1 text-xs text-text-primary">
        <span>
          Reason <span className="text-critical">*</span>
        </span>
        <textarea
          aria-label="discard reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          maxLength={REASON_MAX}
          rows={3}
          placeholder="e.g. vendor test alerts from a demo site"
          className={`${inputCls} font-mono`}
        />
      </label>
      <ErrorLine message={error} />
      <div className="mt-4 flex items-center justify-end gap-2">
        <button type="button" disabled={busy} onClick={onClose} className={btn}>
          Cancel
        </button>
        <button
          type="button"
          disabled={busy || !reasonOk}
          onClick={() => void onSubmit()}
          className="rounded-sm border border-critical bg-critical px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
          data-testid="discard-submit"
        >
          {busy ? "Discarding…" : `Discard ${n === 1 ? "event" : `${n} events`}`}
        </button>
      </div>
    </ModalFrame>
  );
};
