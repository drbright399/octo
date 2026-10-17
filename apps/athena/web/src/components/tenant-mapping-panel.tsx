/**
 * TenantMappingPanel — the wizard step that establishes cross-source client
 * identity for a configured integration: map each of the source's vendor tenant
 * ids (Datto siteUid, Wazuh agent group, RocketCyber customerId…) to an OCTO
 * client. Events then route to that client's events.db, so "Client A in Datto"
 * and "Client A in Wazuh" land under the same OCTO client.
 *
 * Routing is an EXACT match on the vendor tenant id, so the id is PICKED, not
 * typed, wherever the adapter can list its tenants ("<name> — <uid>"; choosing
 * one fills id + label). This panel used to be free text with a made-up
 * placeholder, and an operator reasonably typed site NAMES — mappings that
 * could never match. Rules it now keeps:
 *   - discovery failed → the reason is SHOWN (the server's actionable message);
 *     manual entry stays possible but is never a silent fallback;
 *   - a row whose id is not a discovered tenant is flagged; if it equals a
 *     tenant's NAME the matching id is offered — a suggestion the operator
 *     clicks, then saves. Nothing is rewritten for them.
 *   - a mapping whose client is no longer active (offboarded / archived /
 *     disabled) is FROZEN: it is kept on purpose so the site's traffic is held
 *     in quarantine instead of auto-creating a look-alike tenant. Its client
 *     is not in the active picker list, so the row used to render with a
 *     BLANK client — and an operator who "cleaned up" the blank row and saved
 *     deleted the mapping. Such a row is now read-only, labelled with the
 *     departed tenant's name and status, has no remove control, is sent back
 *     verbatim on save (and the server keeps it even if a client omits it).
 *
 *   - a mapping made from a NAME by an earlier version (the server's
 *     `needs_review` — the same-name fix, 2026-10-01; never the mapping an
 *     integration wrote for a tenant it auto-created itself, whatever its
 *     match_source says) is marked "unconfirmed" with a Confirm button.
 *     Saved unchanged, any row goes back with its stored source (an
 *     unconfirmed one stays unconfirmed — the server refuses a NEW
 *     non-manual row); confirmed or edited, it is the operator's decision
 *     ('manual').
 *
 *   - the ✕ on a SAVED mapping asks first (it stops that tenant's events
 *     routing to the client — and says what happens to them instead, which
 *     depends on the integration) and then SAVES AT ONCE: the PUT replaces
 *     the whole set, so it is the server's mappings RE-READ at that moment
 *     (one written elsewhere since the panel opened — another tab,
 *     Quarantine's "map to", an integration's auto-created tenant — is kept)
 *     minus that row, frozen rows verbatim, as Save sends them; never the
 *     operator's other unsaved edits, which stay staged. If that mapping
 *     itself changed meanwhile nothing is saved. After the ✕ — saved or
 *     failed — the untouched rows follow what the server holds. A new row
 *     that was never saved is removed without asking, as before.
 *
 * Includes inline "create client" — the operator can provision a new OCTO client
 * on the spot (POST /admin/clients) without leaving the flow.
 */
import { type FC, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import {
  isFrozenMapping,
  type TenantMappingEntry,
  type TenantMappingShape,
  type VendorTenant,
} from "@/contracts/integration";
import {
  type ClientEntry,
  createClient,
  getTenantMappings,
  listClients,
  listVendorTenants,
  setTenantMappings,
} from "@/lib/api";
import { formatRelative } from "@/lib/time";

interface Row {
  vendor_tenant_id: string;
  octo_client_slug: string;
  vendor_tenant_label: string;
  /** The operator chose to type the id although a picker is available. */
  manual: boolean;
  /** The stored mapping this row was loaded from (null: a new row). */
  stored?: {
    readonly id: string;
    readonly slug: string;
    readonly source: string;
    /** The server says this mapping is still to re-review (a name match). */
    readonly review: boolean;
  } | null;
  /** The operator confirmed a stored name-matched (non-manual) row. */
  confirmed?: boolean;
}

/** A stored row the operator has neither changed nor confirmed. */
function unchangedRow(row: Row): boolean {
  const st = row.stored;
  return !!st && !row.confirmed && row.vendor_tenant_id.trim() === st.id &&
    row.octo_client_slug === st.slug;
}

/** A stored mapping the SERVER marks for re-review (a name match), neither
 *  changed nor confirmed by the operator. */
function unconfirmedRow(row: Row): boolean {
  return unchangedRow(row) && !!row.stored?.review;
}

/** A stored mapping as an editable row. */
function rowFrom(m: TenantMappingEntry): Row {
  return {
    vendor_tenant_id: m.vendor_tenant_id,
    octo_client_slug: m.octo_client_slug,
    vendor_tenant_label: m.vendor_tenant_label ?? "",
    manual: false,
    stored: {
      id: m.vendor_tenant_id,
      slug: m.octo_client_slug,
      source: m.match_source ?? "manual",
      // The server decides (an older server: any non-manual row).
      review: m.needs_review ?? (m.match_source ?? "manual") !== "manual",
    },
    confirmed: false,
  };
}

/** What Save sends for a row. */
function entryOf(r: Row): TenantMappingEntry {
  return {
    vendor_tenant_id: r.vendor_tenant_id.trim(),
    octo_client_slug: r.octo_client_slug,
    vendor_tenant_label: r.vendor_tenant_label.trim() || null,
    // Unchanged: sent back as stored (an unconfirmed row stays so; an
    // auto-created tenant's own mapping keeps its source).
    match_source: unchangedRow(r) && r.stored ? r.stored.source : "manual",
  };
}

/** Anything Save would change: a new row with something in it, a stored row
 *  edited or confirmed, or a stored mapping whose row was removed. */
function pendingEdits(rows: readonly Row[], server: readonly TenantMappingEntry[]): boolean {
  const onScreen = new Set<string>();
  for (const r of rows) {
    const m = r.stored ? server.find((x) => x.vendor_tenant_id === r.stored?.id) : undefined;
    if (!m) {
      if (r.vendor_tenant_id.trim() || r.octo_client_slug || r.vendor_tenant_label.trim()) return true;
      continue;
    }
    onScreen.add(m.vendor_tenant_id);
    if (
      r.confirmed ||
      r.vendor_tenant_id !== m.vendor_tenant_id ||
      r.octo_client_slug !== m.octo_client_slug ||
      r.vendor_tenant_label !== (m.vendor_tenant_label ?? "")
    ) {
      return true;
    }
  }
  return server.some((m) => !onScreen.has(m.vendor_tenant_id));
}

/** The rows once the server answers `next` (it held `before`): a row the
 *  operator has not touched follows the server — a mapping changed, added or
 *  removed elsewhere — and an edited or new row stays staged. `drop`: the
 *  mapping just removed (its row goes, edited or not). */
function followServer(
  rows: readonly Row[],
  before: readonly TenantMappingEntry[],
  next: readonly TenantMappingEntry[],
  drop?: string,
): Row[] {
  const now = new Map(next.map((m) => [m.vendor_tenant_id, m]));
  const seen = new Set<string>();
  const out: Row[] = [];
  for (const r of rows) {
    const id = r.stored?.id;
    if (id !== undefined && id === drop) continue;
    const was = id !== undefined ? before.find((m) => m.vendor_tenant_id === id) : undefined;
    if (!was) {
      out.push(r);                                       // a new row: staged
      continue;
    }
    seen.add(was.vendor_tenant_id);
    const stored = now.get(was.vendor_tenant_id);
    if (pendingEdits([r], [was])) out.push(r);           // edited: staged
    else if (stored) out.push(rowFrom(stored));
    // untouched and no longer stored: gone here too
  }
  for (const m of next) {
    if (!seen.has(m.vendor_tenant_id) && m.vendor_tenant_id !== drop) out.push(rowFrom(m));
  }
  return out;
}

/** Integrations whose unmapped traffic is never dropped: the platform's
 *  tenant resolution (instances.tenant_autocreate, on the poll and the
 *  webhook path) holds it in Quarantine — a site named like a client — or
 *  auto-creates a pending client for it. Any other drops or skips it. */
const RESOLVES_UNMAPPED: ReadonlySet<string> = new Set(["datto", "rocketcyber", "resend"]);

type Discovery =
  | { readonly state: "loading" }
  | { readonly state: "unsupported" }
  | { readonly state: "failed"; readonly message: string }
  | {
      readonly state: "ready";
      readonly tenants: readonly VendorTenant[];
      readonly truncated: boolean;
      readonly fetchedAt: string | null;
      /** A Reload is in flight — the current list stays usable meanwhile. */
      readonly reloading?: boolean;
    };

interface Props {
  readonly vendorSlug: string;
  readonly instanceId: number;
  /** Display name for the map-before-attach hint ("Datto RMM"). */
  readonly vendorName?: string | undefined;
  /** The adapter's tenant_mapping_shape from the catalog, when the caller has
   *  it — so the wording is right even if discovery fails. The discovery
   *  response carries the same shape and wins once it arrives. */
  readonly shape?: TenantMappingShape | null | undefined;
  /** Label of the leave-without-saving button. The wizard's default is "Skip
   *  for now"; on an existing instance there is nothing to skip. */
  readonly dismissLabel?: string | undefined;
  readonly onDone: () => void;
}

const EMPTY_ROW: Row = {
  vendor_tenant_id: "",
  octo_client_slug: "",
  vendor_tenant_label: "",
  manual: false,
};
const MANUAL_OPTION = "__manual__";

const norm = (s: string): string => s.trim().toLowerCase();

export const TenantMappingPanel: FC<Props> = ({
  vendorSlug,
  instanceId,
  vendorName,
  shape: shapeProp,
  dismissLabel = "Skip for now",
  onDone,
}) => {
  const [clients, setClients] = useState<readonly ClientEntry[]>([]);
  const [rows, setRows] = useState<Row[]>([EMPTY_ROW]);
  /** The editable mappings as the server last answered them — what a ✕ on
   *  a saved row saves from (never the unsaved edits on screen). */
  const [server, setServer] = useState<readonly TenantMappingEntry[]>([]);
  /** Mappings of departed tenants — shown read-only, saved back verbatim. */
  const [frozen, setFrozen] = useState<readonly TenantMappingEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showNewClient, setShowNewClient] = useState(false);
  const [newSlug, setNewSlug] = useState("");
  const [newName, setNewName] = useState("");
  const [discovery, setDiscovery] = useState<Discovery>({ state: "loading" });
  const [discoveredShape, setDiscoveredShape] = useState<TenantMappingShape | null>(null);
  const [dirty, setDirty] = useState(false);
  /** The ✕ pressed on a saved row: its stored id. */
  const [removal, setRemoval] = useState<{ readonly id: string } | null>(null);
  const [removing, setRemoving] = useState(false);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const addRef = useRef<HTMLButtonElement | null>(null);
  /** Each saved row's ✕ by its stored id — where focus goes back to. Rows are
   *  keyed by position, so the element that opened the dialog may now be
   *  another row's. */
  const removeRefs = useRef(new Map<string, HTMLButtonElement>());

  useEffect(() => {
    let cancelled = false;
    Promise.all([listClients(), getTenantMappings(vendorSlug, instanceId)])
      .then(([cs, ms]: [readonly ClientEntry[], readonly TenantMappingEntry[]]) => {
        if (cancelled) return;
        setClients(cs);
        const held = ms.filter(isFrozenMapping);
        const editable = ms.filter((m) => !isFrozenMapping(m));
        setFrozen(held);
        setServer(editable);
        setRows(editable.length ? editable.map(rowFrom) : [EMPTY_ROW]);
      })
      .catch((e: Error) => !cancelled && setError(e.message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [vendorSlug, instanceId]);

  // Discovery runs beside the load above, never in front of it: a vendor that
  // is down must not take the saved mappings off the screen with it.
  const discover = useCallback(
    async (refresh: boolean, isCancelled: () => boolean = () => false): Promise<void> => {
      setDiscovery((d) => (d.state === "ready" ? { ...d, reloading: true } : { state: "loading" }));
      try {
        const d = await listVendorTenants(instanceId, { refresh });
        if (isCancelled()) return;
        if (d.tenant_mapping_shape) setDiscoveredShape(d.tenant_mapping_shape);
        setDiscovery(
          d.supported
            ? {
                state: "ready",
                tenants: d.tenants,
                truncated: d.truncated,
                fetchedAt: d.fetched_at,
              }
            : { state: "unsupported" },
        );
      } catch (e) {
        if (isCancelled()) return;
        setDiscovery({
          state: "failed",
          message:
            e instanceof Error && e.message
              ? e.message
              : "The request failed and the server gave no reason.",
        });
      }
    },
    [instanceId],
  );

  useEffect(() => {
    let cancelled = false;
    void discover(false, () => cancelled);
    return () => {
      cancelled = true;
    };
  }, [discover]);

  const shape = discoveredShape ?? shapeProp ?? null;
  const vendor = vendorName ?? "the vendor";
  const noun = shape?.tenant_noun || "tenant";
  const idField = shape?.vendor_tenant_id_field ?? null;
  const idPlaceholder = idField ? `${noun} ${idField}` : `${noun} id`;
  const idHelp =
    shape?.id_help ??
    `Enter each ${noun}'s ${idField ? `'${idField}'` : "identifier"} exactly as ${vendor} ` +
      "sends it on an event. Routing is an exact match — a display name never matches.";

  const tenants = discovery.state === "ready" ? discovery.tenants : null;
  const byId = useMemo(() => new Map((tenants ?? []).map((t) => [t.id, t])), [tenants]);
  // "Not in the list" only means something when the list is complete.
  const canVerify = discovery.state === "ready" && !discovery.truncated;

  const update = (i: number, patch: Partial<Row>): void => {
    setDirty(true);
    setNotice(null);
    setRows((r) => r.map((row, idx) => (idx === i ? { ...row, ...patch } : row)));
  };
  const addRow = (): void => setRows((r) => [...r, { ...EMPTY_ROW }]);
  const removeRow = (i: number): void => {
    const id = rows[i]?.stored?.id;
    if (id !== undefined && server.some((m) => m.vendor_tenant_id === id)) {
      // A saved mapping: ask, then save just that removal.
      setRemoveError(null);
      setRemoval({ id });
      return;
    }
    setDirty(true);
    setNotice(null);
    setRows((r) => r.filter((_, idx) => idx !== i));
  };
  const pick = (i: number, t: VendorTenant): void =>
    update(i, { vendor_tenant_id: t.id, vendor_tenant_label: t.label, manual: false });

  const isUnmatched = (row: Row): boolean =>
    canVerify && row.vendor_tenant_id.trim() !== "" && !byId.has(row.vendor_tenant_id.trim());
  const unmatchedCount = rows.filter(isUnmatched).length;

  const onCreateClient = async (): Promise<void> => {
    setError(null);
    try {
      const c = await createClient(newSlug.trim(), newName.trim());
      setClients((cs) => [...cs, c]);
      setNewSlug("");
      setNewName("");
      setShowNewClient(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Create client failed");
    }
  };

  const onSave = async (): Promise<void> => {
    setError(null);
    // A half-filled row is NOT skipped: Save used to drop it without a word
    // and close the panel, leaving that tenant unmapped (its alerts dropped).
    // Only a fully blank row is ignored.
    const half = rows
      .map((r, i) => ({ r, n: i + 1 }))
      .filter(({ r }) => (r.vendor_tenant_id.trim() !== "") !== (r.octo_client_slug !== ""));
    if (half.length > 0) {
      const which = half
        .map(({ r, n }) =>
          r.vendor_tenant_id.trim()
            ? `row ${n} (${r.vendor_tenant_label.trim() || r.vendor_tenant_id.trim()}) has no client`
            : `row ${n} has a client but no ${noun}`,
        )
        .join("; ");
      setError(
        `Nothing was saved: ${which}. Finish ${half.length === 1 ? "it" : "them"} or remove ${
          half.length === 1 ? "the row" : "those rows"
        } — events from an unmapped ${noun} are dropped.`,
      );
      return;
    }
    const edited: TenantMappingEntry[] = rows
      .filter((r) => r.vendor_tenant_id.trim() && r.octo_client_slug)
      .map(entryOf);
    // Frozen rows go back EXACTLY as they came (the server keeps them even
    // if omitted, and refuses a re-point: that is a quarantine decision).
    const payload: TenantMappingEntry[] = [...edited, ...frozen];
    const ids = payload.map((p) => p.vendor_tenant_id);
    const dup = ids.find((id, i) => ids.indexOf(id) !== i);
    if (dup !== undefined) {
      const frozenHit = frozen.find((f) => f.vendor_tenant_id === dup);
      setError(
        frozenHit
          ? `"${dup}" is frozen to ${frozenHit.client_display_name ?? frozenHit.octo_client_slug} (${frozenHit.client_status ?? "not active"}) and cannot be mapped again here — to point it at another client, route its held events under Quarantine.`
          : `"${dup}" is mapped more than once — one ${noun} maps to exactly one client.`,
      );
      return;
    }
    setSaving(true);
    try {
      await setTenantMappings(vendorSlug, instanceId, payload);
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const removed = removal ? (server.find((m) => m.vendor_tenant_id === removal.id) ?? null) : null;
  const removedClient = removed
    ? (removed.client_display_name ??
      clients.find((c) => c.slug === removed.octo_client_slug)?.display_name ??
      removed.octo_client_slug)
    : "";
  /** Unsaved edits on OTHER rows — the ✕ never saves them. */
  const othersPending = (id: string): boolean =>
    pendingEdits(
      rows.filter((r) => r.stored?.id !== id),
      server.filter((m) => m.vendor_tenant_id !== id),
    );

  /** Take the server's mappings: the base of the next ✕, the frozen rows,
   *  and the rows (`followServer`). Runs from the open dialog, which is
   *  modal: `rows` and `server` cannot have changed since it opened. */
  const adoptServer = (answer: readonly TenantMappingEntry[], drop?: string): boolean => {
    const editable = answer.filter((m) => !isFrozenMapping(m));
    const next = followServer(rows, server, editable, drop);
    const pending = pendingEdits(next, editable);
    setServer(editable);
    setFrozen(answer.filter(isFrozenMapping));
    setRows(next);
    setDirty(pending);
    return pending;
  };

  const onRemoveSaved = async (): Promise<void> => {
    if (!removed) return;
    const id = removed.vendor_tenant_id;
    const slug = removed.octo_client_slug;
    const what = removed.vendor_tenant_label || id;
    const isStill = (ms: readonly TenantMappingEntry[]): TenantMappingEntry | undefined =>
      ms.find((m) => m.vendor_tenant_id === id && !isFrozenMapping(m) && m.octo_client_slug === slug);
    setRemoving(true);
    setRemoveError(null);
    try {
      // The server's mappings NOW, not when the panel opened: the PUT
      // replaces the whole set, and a mapping written since must not be
      // undone by removing another.
      const fresh = await getTenantMappings(vendorSlug, instanceId);
      if (!isStill(fresh)) {
        // This very mapping changed meanwhile: what was confirmed is not
        // what would be saved. Show what the server holds; save nothing.
        const was = fresh.find((m) => m.vendor_tenant_id === id);
        adoptServer(fresh);
        setRemoval(null);
        setNotice(null);
        setError(
          `Nothing was saved: the mapping of ${what} changed since this list was read — ${
            was ? `it now points to ${was.client_display_name ?? was.octo_client_slug}` : "it is no longer stored"
          }. Check it and try again.`,
        );
        return;
      }
      // That state minus this one row — each sent as Save sends an
      // untouched row — plus the frozen rows verbatim.
      const answer = await setTenantMappings(vendorSlug, instanceId, [
        ...fresh.filter((m) => !isFrozenMapping(m) && m.vendor_tenant_id !== id).map((m) => entryOf(rowFrom(m))),
        ...fresh.filter(isFrozenMapping),
      ]);
      const others = adoptServer(answer, id);              // other edits stay staged
      setError(null);
      setNotice(
        others ? "Mapping removed and saved. Your other unsaved changes are still pending." : "Mapping removed and saved.",
      );
      setRemoval(null);
    } catch (e) {
      const reason = e instanceof Error ? e.message : "The mapping could not be removed.";
      // A failure can come after the server stored the change: re-read, so
      // the screen — and the base of the next save — is what it holds.
      // Unreadable: the screen stays as it was.
      const now = await getTenantMappings(vendorSlug, instanceId).catch(() => null);
      if (now) {
        adoptServer(now);
        if (!isStill(now)) {
          setRemoval(null);
          setNotice(null);
          setError(`${reason} — yet the mapping of ${what} to ${removedClient} is no longer stored. The list shows what is stored now.`);
          return;
        }
      }
      // Nothing changed: the dialog stays, with the server's reason.
      setRemoveError(reason);
    } finally {
      setRemoving(false);
    }
  };

  const inputCls =
    "w-full min-w-0 truncate rounded border border-border bg-bg-input px-2 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none";
  const linkCls =
    "self-start font-mono text-[10px] text-text-dim underline decoration-dotted hover:text-accent";

  if (loading) {
    return <div className="flex flex-1 items-center justify-center p-6 text-text-dim">Loading…</div>;
  }

  return (
    <div className="flex flex-1 flex-col overflow-y-auto p-5">
      <div className="mb-2 flex items-center gap-2 font-mono text-[11px] uppercase tracking-wider text-text-dim">
        <span className="text-accent">·· 03 ··</span>
        <span>map tenants to clients</span>
      </div>
      <p className="mb-2 text-xs leading-relaxed text-text-secondary">
        Map each of this source's tenant identifiers to a client so its
        events land under the right client. Map the <em className="text-accent">same</em> client
        across every source to unify it (e.g. Datto site and Wazuh group both → Acme).
      </p>
      <p data-testid="tenant-id-help" className="mb-3 text-xs leading-relaxed text-text-secondary">
        {idHelp}
      </p>

      {discovery.state === "loading" ? (
        <p role="status" data-testid="discovery-loading" className="mb-3 text-[11px] text-text-dim">
          Loading the {noun} list from {vendor}…
        </p>
      ) : discovery.state === "failed" ? (
        <div
          role="alert"
          data-testid="discovery-failed"
          className="mb-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs leading-relaxed"
        >
          <p className="mb-1 font-semibold text-critical">
            Could not load the {noun} list from {vendor}
          </p>
          <p className="text-text-primary">{discovery.message}</p>
          <p className="mt-1.5 text-text-secondary">
            You can still type ids below, but they cannot be checked against {vendor} until
            this is fixed — a wrong id means its events are dropped.
          </p>
          <button
            type="button"
            onClick={() => void discover(true)}
            className="mt-2 rounded-sm border border-border px-2 py-1 font-mono text-[11px] text-text-secondary hover:text-text-primary"
          >
            Retry
          </button>
        </div>
      ) : discovery.state === "unsupported" ? (
        <p role="note" data-testid="discovery-unsupported" className="mb-3 text-[11px] text-text-dim">
          {vendor} cannot list its {noun}s here, so there is nothing to pick from — type
          each id exactly as it appears on {vendor}'s events.
        </p>
      ) : (
        <div className="mb-3 flex flex-wrap items-center gap-2 text-[11px] text-text-dim">
          <span data-testid="discovery-ready">
            {discovery.tenants.length} {vendor} {noun}
            {discovery.tenants.length === 1 ? "" : "s"} loaded
            {discovery.fetchedAt ? ` · ${formatRelative(discovery.fetchedAt)}` : ""}
          </span>
          <button
            type="button"
            disabled={discovery.reloading === true}
            onClick={() => void discover(true)}
            className="rounded-sm border border-border px-2 py-0.5 font-mono text-[10px] text-text-secondary hover:text-text-primary disabled:opacity-40"
          >
            {discovery.reloading ? "Reloading…" : "Reload"}
          </button>
          {discovery.truncated ? (
            <span role="alert" data-testid="discovery-truncated" className="basis-full text-high">
              The list was capped and is incomplete. A {noun} missing from the picker can be
              entered manually; ids cannot be verified against a partial list.
            </span>
          ) : null}
        </div>
      )}

      <div className="flex flex-col gap-2">
        <div className="grid grid-cols-[minmax(0,1fr),minmax(0,1fr),minmax(0,1fr),auto] gap-2 font-mono text-[10px] uppercase tracking-wider text-text-dim">
          <span>
            {vendor} {noun}
          </span>
          <span>client</span>
          <span>label (optional)</span>
          <span />
        </div>
        {frozen.map((f) => {
          const status = f.client_status ?? "not active";
          const who = f.client_display_name ?? f.octo_client_slug;
          return (
            <div
              key={`frozen-${f.vendor_tenant_id}`}
              data-testid={`mapping-frozen-${f.vendor_tenant_id}`}
              role="note"
              aria-label={`${vendor} ${noun} ${f.vendor_tenant_id}, frozen to ${who}`}
              className="grid grid-cols-[minmax(0,1fr),minmax(0,1fr),minmax(0,1fr),auto] items-start gap-2 rounded border border-dashed border-border bg-bg-card/40 px-2 py-1.5"
            >
              <span className="min-w-0 truncate font-mono text-xs text-text-secondary" title={f.vendor_tenant_id}>
                {f.vendor_tenant_label ? `${f.vendor_tenant_label} — ` : ""}
                {f.vendor_tenant_id}
              </span>
              <span className="col-span-2 min-w-0 text-xs leading-relaxed text-text-secondary">
                <span className="text-text-primary">{who}</span>
                <span className="font-mono text-[11px] text-text-dim"> ({f.octo_client_slug})</span>
                <span className="text-high"> — {status}</span>
                <span className="text-text-dim">
                  {" "}
                  (frozen: traffic from this {noun} is held in quarantine — to point it at another
                  client, route its held events under Quarantine)
                </span>
              </span>
              <span className="px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-text-dim" aria-hidden="true">
                read-only
              </span>
            </div>
          );
        })}
        {rows.map((row, i) => {
          const id = row.vendor_tenant_id.trim();
          const known = byId.has(id);
          const showPicker = tenants !== null && !row.manual && (id === "" || known);
          const usedElsewhere = new Set([
            ...rows.filter((_, idx) => idx !== i).map((r) => r.vendor_tenant_id.trim()),
            ...frozen.map((f) => f.vendor_tenant_id),
          ]);
          const unmatched = isUnmatched(row);
          // The operator typed a NAME where the id belongs: offer the id(s)
          // that carry that name. Offered, never applied for them.
          const suggestions = unmatched
            ? (tenants ?? []).filter((t) => norm(t.label) === norm(id))
            : [];
          return (
            <div key={i} data-testid={`mapping-row-${i}`} className="flex flex-col gap-1">
              <div className="grid grid-cols-[minmax(0,1fr),minmax(0,1fr),minmax(0,1fr),auto] items-start gap-2">
                <div className="flex min-w-0 flex-col gap-1">
                  {showPicker ? (
                    <select
                      aria-label={`${vendor} ${noun}, row ${i + 1}`}
                      className={inputCls}
                      value={known ? id : ""}
                      onChange={(e) => {
                        const v = e.target.value;
                        if (v === MANUAL_OPTION) {
                          update(i, { manual: true });
                          return;
                        }
                        const t = byId.get(v);
                        if (t) pick(i, t);
                        else update(i, { vendor_tenant_id: "", vendor_tenant_label: "" });
                      }}
                    >
                      <option value="">— select {noun} —</option>
                      {(tenants ?? []).map((t) => (
                        <option key={t.id} value={t.id} disabled={usedElsewhere.has(t.id)}>
                          {t.label} — {t.id}
                        </option>
                      ))}
                      <option value={MANUAL_OPTION}>Not listed — enter the id manually…</option>
                    </select>
                  ) : (
                    <>
                      <input
                        aria-label={`${vendor} ${idPlaceholder}, row ${i + 1}`}
                        className={`${inputCls} ${unmatched ? "border-high" : ""}`}
                        value={row.vendor_tenant_id}
                        placeholder={idPlaceholder}
                        onChange={(e) => update(i, { vendor_tenant_id: e.target.value })}
                      />
                      {tenants !== null ? (
                        <button
                          type="button"
                          className={linkCls}
                          onClick={() =>
                            update(
                              i,
                              known
                                ? { manual: false }
                                : { manual: false, vendor_tenant_id: "", vendor_tenant_label: "" },
                            )
                          }
                        >
                          {known || id === "" ? "pick from the list" : "clear and pick from the list"}
                        </button>
                      ) : null}
                    </>
                  )}
                </div>
                <select
                  aria-label={`client, row ${i + 1}`}
                  className={inputCls}
                  value={row.octo_client_slug}
                  onChange={(e) => update(i, { octo_client_slug: e.target.value })}
                >
                  <option value="">— select client —</option>
                  {clients.map((c) => (
                    <option key={c.slug} value={c.slug}>
                      {c.display_name} ({c.slug})
                    </option>
                  ))}
                </select>
                <input
                  aria-label={`label, row ${i + 1}`}
                  className={inputCls}
                  value={row.vendor_tenant_label}
                  placeholder="display name"
                  onChange={(e) => update(i, { vendor_tenant_label: e.target.value })}
                />
                <button
                  ref={(el) => {
                    const sid = row.stored?.id;
                    if (sid === undefined) return;
                    if (el) removeRefs.current.set(sid, el);
                    else removeRefs.current.delete(sid);
                  }}
                  type="button"
                  aria-label="Remove row"
                  title={row.stored ? "Remove this saved mapping — asks first, then saves" : undefined}
                  disabled={saving}
                  onClick={() => removeRow(i)}
                  className="rounded-sm px-2 py-1 text-text-dim hover:text-critical disabled:opacity-40"
                >
                  ✕
                </button>
              </div>
              {unconfirmedRow(row) ? (
                <div
                  role="note"
                  data-testid={`mapping-unconfirmed-${i}`}
                  className="flex flex-wrap items-center gap-2 rounded border border-warning/60 bg-warning/10 px-2 py-1.5 text-[11px] leading-relaxed text-text-secondary"
                >
                  <span>
                    <span className="font-semibold text-warning">Unconfirmed</span> — mapped from a name
                    match by an earlier version, not by a person. Two businesses can share a name: check
                    it is this client, then confirm (or re-map it).
                  </span>
                  <button
                    type="button"
                    data-testid={`mapping-confirm-${i}`}
                    onClick={() => update(i, { confirmed: true })}
                    className="rounded-sm border border-accent px-2 py-0.5 font-mono text-[10px] text-accent hover:bg-accent/10"
                  >
                    Confirm
                  </button>
                </div>
              ) : null}
              {unmatched ? (
                <div
                  role="alert"
                  data-testid={`mapping-unmatched-${i}`}
                  className="rounded border border-high bg-high/10 px-2 py-1.5 text-[11px] leading-relaxed text-high"
                >
                  <span>
                    “{id}” does not match any {vendor} {noun} — alerts will never route here.
                  </span>
                  {suggestions.length ? (
                    <span className="mt-1 flex flex-wrap items-center gap-2 text-text-secondary">
                      <span>
                        It is the NAME of {suggestions.length === 1 ? `a ${noun}` : `${suggestions.length} ${noun}s`}
                        . Its id:
                      </span>
                      {suggestions.map((t) => (
                        <button
                          key={t.id}
                          type="button"
                          data-testid={`mapping-suggestion-${i}`}
                          onClick={() => pick(i, t)}
                          className="rounded-sm border border-accent px-2 py-0.5 font-mono text-[11px] text-accent hover:bg-accent/10"
                        >
                          use {t.id}
                        </button>
                      ))}
                      <span className="text-text-dim">(nothing changes until you save)</span>
                    </span>
                  ) : null}
                </div>
              ) : null}
            </div>
          );
        })}
      </div>

      <div className="mt-3 flex items-center gap-3">
        <button
          ref={addRef}
          type="button"
          onClick={addRow}
          className="nav-sweep rounded-sm border border-border px-3 py-1 font-mono text-[11px] text-text-secondary"
        >
          + add mapping
        </button>
        <button
          type="button"
          onClick={() => setShowNewClient((v) => !v)}
          className="nav-sweep rounded-sm border border-border px-3 py-1 font-mono text-[11px] text-text-secondary"
        >
          + new client
        </button>
      </div>

      {showNewClient ? (
        <div className="mt-3 flex flex-wrap items-end gap-2 rounded-sm border border-accent/30 bg-accent-soft/40 p-3">
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-text-dim">
            slug
            <input
              className={inputCls}
              value={newSlug}
              placeholder="acme-corp"
              onChange={(e) => setNewSlug(e.target.value)}
            />
          </label>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-text-dim">
            display name
            <input
              className={inputCls}
              value={newName}
              placeholder="Acme Corp"
              onChange={(e) => setNewName(e.target.value)}
            />
          </label>
          <button
            type="button"
            disabled={!newSlug.trim() || !newName.trim()}
            onClick={() => void onCreateClient()}
            className="rounded-sm border border-accent bg-accent px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider text-text-on-accent disabled:opacity-40"
          >
            create
          </button>
        </div>
      ) : null}

      {error ? (
        <div role="alert" className="mt-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical">
          {error}
        </div>
      ) : null}
      {notice ? (
        <p role="status" data-testid="mapping-removed" className="mt-3 text-[11px] text-success">
          {notice}
        </p>
      ) : null}

      {unmatchedCount || dirty ? (
        <p data-testid="mapping-save-state" className="mt-3 text-right text-[11px] text-text-dim">
          {unmatchedCount ? (
            <span className="text-high">
              {unmatchedCount} mapping{unmatchedCount === 1 ? "" : "s"} match
              {unmatchedCount === 1 ? "es" : ""} no {vendor} {noun}.{" "}
            </span>
          ) : null}
          {dirty ? "Unsaved changes — nothing is stored until you press Save mappings." : null}
        </p>
      ) : null}

      <div className="mt-auto flex items-center justify-end gap-2 pt-5">
        <p
          data-testid="map-before-attach-hint"
          className="mr-auto max-w-[60%] text-[11px] leading-relaxed text-text-dim"
        >
          If you enabled real-time webhooks, map sites before attaching the webhook
          in {vendorName ?? "the vendor"} — alerts from unmapped sites create pending
          tenants or are held for review.
        </p>
        <button
          type="button"
          onClick={onDone}
          className="rounded-sm border border-border px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider text-text-secondary"
        >
          {dismissLabel}
        </button>
        <button
          type="button"
          disabled={saving || removing}
          onClick={() => void onSave()}
          className="rounded-sm border border-accent bg-accent px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider text-text-on-accent disabled:opacity-40"
        >
          {saving ? "Saving…" : "Save mappings"}
        </button>
      </div>

      {removal && removed ? (
        <ConfirmDialog
          title="Remove this mapping?"
          testId="mapping-remove-dialog"
          busy={removing ? "remove" : null}
          error={removeError}
          onCancel={() => {
            setRemoval(null);
            setRemoveError(null);
          }}
          // Back to the ✕ — once removed, its row is gone: then "+ add mapping".
          returnFocus={() => removeRefs.current.get(removal.id) ?? addRef.current}
          actions={[
            {
              id: "remove",
              label: "Remove mapping",
              busyLabel: "Removing…",
              primary: true,
              onSelect: () => void onRemoveSaved(),
            },
          ]}
        >
          <p>
            Remove the mapping of {vendor} {noun}{" "}
            <strong className="text-text-primary">
              {removed.vendor_tenant_label ? `${removed.vendor_tenant_label} — ` : ""}
              {removed.vendor_tenant_id}
            </strong>{" "}
            to <strong className="text-text-primary">{removedClient}</strong>? Events from{" "}
            {removed.vendor_tenant_label || removed.vendor_tenant_id} will no longer route to{" "}
            {removedClient} —{" "}
            {RESOLVES_UNMAPPED.has(vendorSlug)
              ? `events from an unmapped ${noun} are not dropped: they create a new pending client for review, or are held in Quarantine.`
              : `events from an unmapped ${noun} are dropped.`}{" "}
            Its past events stay with {removedClient}.
          </p>
          <p>
            This is saved as soon as you choose.
            {othersPending(removed.vendor_tenant_id)
              ? " Your other unsaved changes are not saved with it — they stay pending until you press Save mappings."
              : ""}
          </p>
        </ConfirmDialog>
      ) : null}
    </div>
  );
};
