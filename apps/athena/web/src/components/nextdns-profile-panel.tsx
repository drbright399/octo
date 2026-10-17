/**
 * NextDnsProfilePanel — the NextDNS mapping step (wizard) and the card's
 * "Tenant mapping" drawer.
 *
 * A NextDNS account lists every profile it can see: client sites, but also
 * personal and test profiles. NOTHING is polled until a profile is mapped to
 * a client, and an unmapped profile is never polled. Each profile row offers:
 *   - a client (several profiles may map to one client — one per site);
 *   - "Ignore": the profile stops being listed as needing attention (still
 *     never polled — ignoring is about attention, not data);
 *   - the server's name-match SUGGESTION, which the operator CONFIRMS ROW BY
 *     ROW (the same-name rule, 2026-10-01: two businesses can share a
 *     name). "Review N suggestions" only pre-fills the rows as PENDING — each
 *     still needs its own Confirm, and a pending row is never saved. A
 *     confirmed suggestion is the operator's decision (saved 'manual'); a
 *     name-matched mapping stored by an earlier version stays marked
 *     "unconfirmed" until someone confirms it.
 * The list comes from the last discovery (the server never asks NextDNS to
 * build this panel); "Reload list" is ONE NextDNS call and also re-reads the
 * client list (a client created meanwhile in Settings → Tenants appears) —
 * it never discards unsaved choices. Save sends the mappings and the ignore
 * list together (one audited PUT). Closing with unsaved choices asks first.
 * A name that reads like a personal / test profile is suggested on its row
 * only, never by "Review N suggestions".
 */
import { type FC, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { NextDnsProfile, NextDnsProfiles } from "@/contracts/integration";
import {
  type ClientEntry,
  getNextDnsProfiles,
  listClients,
  listVendorTenants,
  saveNextDnsProfiles,
} from "@/lib/api";
import { formatRelative } from "@/lib/time";

/** A row's choice: a client slug, IGNORE, or UNMAPPED. */
const IGNORE = "__ignore__";
const UNMAPPED = "";

/**
 * How a row's client was chosen:
 *   confirmed    the operator's decision (picked, or a suggestion confirmed on
 *                its row) — saved as match_source 'manual';
 *   pending      pre-filled by "Review N suggestions" — NOT saved until the
 *                row is confirmed;
 *   unconfirmed  a stored mapping made from a name by an earlier version —
 *                sent back unchanged until someone confirms it.
 */
type ChoiceState = "confirmed" | "pending" | "unconfirmed";

interface Choice {
  readonly value: string;
  readonly state: ChoiceState;
}

function initialChoice(p: NextDnsProfile): Choice {
  if (p.tenant_slug) {
    const named = p.match_source !== null && p.match_source !== "manual";
    return { value: p.tenant_slug, state: named ? "unconfirmed" : "confirmed" };
  }
  if (p.ignored) return { value: IGNORE, state: "confirmed" };
  return { value: UNMAPPED, state: "confirmed" };
}

function sameChoice(a: Choice, b: Choice): boolean {
  return a.value === b.value && a.state === b.state;
}

const STATE_TEXT: Record<NonNullable<NextDnsProfile["state"]>, { label: string; tone: string }> = {
  active: { label: "active", tone: "text-success" },
  pending: { label: "pending rollout", tone: "text-text-dim" },
  lapsed: { label: "stopped reporting", tone: "text-high" },
  new: { label: "checking…", tone: "text-text-dim" },
};

const DISCARD_PROMPT = "You have unsaved profile choices. Discard them and close?";

interface Props {
  readonly instanceId: number;
  readonly dismissLabel?: string;
  readonly onDone: () => void;
  /** Told whenever the unsaved state changes (the drawer guards its ✕). */
  readonly onDirtyChange?: (dirty: boolean) => void;
}

export const NextDnsProfilePanel: FC<Props> = ({
  instanceId,
  dismissLabel = "Skip for now",
  onDone,
  onDirtyChange,
}) => {
  const [data, setData] = useState<NextDnsProfiles | null>(null);
  const [clients, setClients] = useState<readonly ClientEntry[]>([]);
  const [choices, setChoices] = useState<Record<string, Choice>>({});
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloading, setReloading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  // The list the current choices were made against (to tell an operator's
  // unsaved edit from a row that simply showed what was stored).
  const shownRef = useRef<ReadonlyMap<string, NextDnsProfile>>(new Map());

  /** Take the server's list. The operator's unsaved edits are KEPT (a
   *  Reload never discards work); every other row shows what is stored now.
   *  `reset` — after a save — starts from what is stored. */
  const adopt = useCallback((body: NextDnsProfiles, opts: { readonly reset?: boolean } = {}) => {
    const shown = shownRef.current;
    shownRef.current = new Map(body.profiles.map((p) => [p.profile_id, p]));
    setData(body);
    setChoices((prev) =>
      Object.fromEntries(
        body.profiles.map((p) => {
          const kept = prev[p.profile_id];
          const before = shown.get(p.profile_id);
          const edited =
            !opts.reset && kept !== undefined && before !== undefined &&
            !sameChoice(kept, initialChoice(before));
          return [p.profile_id, edited ? kept : initialChoice(p)];
        }),
      ),
    );
  }, []);

  const reloadList = useCallback(async (): Promise<void> => {
    setReloading(true);
    setError(null);
    try {
      await listVendorTenants(instanceId, { refresh: true });
      const [body, cl] = await Promise.all([getNextDnsProfiles(instanceId), listClients()]);
      setClients(cl.filter((c) => c.status === "active"));
      adopt(body);
    } catch (e) {
      setError(e instanceof Error ? e.message : "The profile list could not be loaded.");
    } finally {
      setReloading(false);
    }
  }, [adopt, instanceId]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [body, cl] = await Promise.all([getNextDnsProfiles(instanceId), listClients()]);
        if (cancelled) return;
        setClients(cl.filter((c) => c.status === "active"));
        if (!body.discovered) {
          // First open since the service started: list the profiles (ONE call).
          await listVendorTenants(instanceId);
          if (cancelled) return;
          adopt(await getNextDnsProfiles(instanceId));
        } else {
          adopt(body);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "The NextDNS profiles could not be loaded.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [adopt, instanceId]);

  const profiles = data?.profiles ?? [];
  const dirty = useMemo(
    () => profiles.some((p) => {
      const now = choices[p.profile_id];
      return now !== undefined && !sameChoice(now, initialChoice(p));
    }),
    [choices, profiles],
  );
  useEffect(() => {
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);
  // "Review N suggestions" never takes a personal / test-looking profile.
  const pendingSuggestions = profiles.filter(
    (p) =>
      p.suggestion &&
      p.suggestion.bulk !== false &&
      (choices[p.profile_id]?.value ?? UNMAPPED) === UNMAPPED,
  );
  const tally = useMemo(() => {
    let mapped = 0;
    let ignored = 0;
    let unmapped = 0;
    let pending = 0;
    let unconfirmed = 0;
    for (const p of profiles) {
      const c = choices[p.profile_id] ?? initialChoice(p);
      if (c.value === IGNORE) ignored += 1;
      else if (c.value === UNMAPPED) unmapped += p.listed ? 1 : 0;
      else if (c.state === "pending") {
        pending += 1;
        unmapped += p.listed ? 1 : 0;
      } else {
        mapped += 1;
        if (c.state === "unconfirmed") unconfirmed += 1;
      }
    }
    return { mapped, ignored, unmapped, pending, unconfirmed };
  }, [choices, profiles]);

  const choose = (pid: string, value: string, state: ChoiceState = "confirmed"): void => {
    setNotice(null);
    setSaved(false);
    setChoices((prev) => ({ ...prev, [pid]: { value, state } }));
  };

  const dismiss = (): void => {
    if (dirty && !window.confirm(DISCARD_PROMPT)) return;
    onDone();
  };

  /** Pre-fill every bulk-eligible suggestion as PENDING: each row still
   *  needs its own Confirm, and a pending row is never saved. */
  const reviewAll = (): void => {
    setNotice(null);
    setChoices((prev) => {
      const next = { ...prev };
      for (const p of pendingSuggestions) {
        if (p.suggestion) next[p.profile_id] = { value: p.suggestion.tenant_slug, state: "pending" };
      }
      return next;
    });
  };

  const onSave = async (): Promise<void> => {
    setSaving(true);
    setError(null);
    try {
      // A PENDING suggestion is never saved: only confirmed rows, and stored
      // name matches sent back exactly as they are (still unconfirmed).
      const notConfirmed = tally.pending;
      const mappings = profiles
        .filter((p) => {
          const c = choices[p.profile_id] ?? initialChoice(p);
          return c.value !== UNMAPPED && c.value !== IGNORE && c.state !== "pending";
        })
        .map((p) => {
          const c = choices[p.profile_id] ?? initialChoice(p);
          return {
            profile_id: p.profile_id,
            tenant_slug: c.value,
            match_source:
              c.state === "unconfirmed" && p.match_source === "auto-name"
                ? ("auto-name" as const)
                : ("manual" as const),
          };
        });
      const ignored = profiles
        .filter((p) => choices[p.profile_id]?.value === IGNORE)
        .map((p) => p.profile_id);
      adopt(await saveNextDnsProfiles(instanceId, { mappings, ignored }), { reset: true });
      setSaved(true);
      const skipped = notConfirmed
        ? ` ${notConfirmed} suggestion${notConfirmed === 1 ? " was" : "s were"} not confirmed and stay${notConfirmed === 1 ? "s" : ""} unmapped.`
        : "";
      setNotice(
        (mappings.length
          ? `Saved. ${mappings.length} profile${mappings.length === 1 ? "" : "s"} mapped — Athena starts checking them now: about 2 s per NextDNS call, then the last 24 hours of security blocks are back-filled, so the first pass takes a few minutes.`
          : "Saved. No profile is mapped yet, so nothing is polled.") + skipped,
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "The mapping could not be saved.");
    } finally {
      setSaving(false);
    }
  };

  const selectCls =
    "w-full rounded-sm border border-border bg-bg-input px-2 py-1 font-mono text-[11px] text-text-primary";

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-y-auto px-5 py-4" data-testid="nextdns-profile-panel">
      <p className="mb-3 text-xs leading-relaxed text-text-secondary">
        Map each NextDNS profile (one per site) to its client. Several profiles may map to one
        client. <strong>Nothing is polled until a profile is mapped</strong>, and an unmapped
        profile is never polled. Mark personal or test profiles <em>Ignore</em> so they stop
        being listed as needing attention. Athena never creates a client from a profile: if a
        profile&apos;s client is not in the list, create it in Settings → Tenants first, then
        press <em>Reload list</em> (your choices here are kept).
      </p>

      <div className="mb-3 flex flex-wrap items-center gap-2 font-mono text-[11px]">
        <span data-testid="nextdns-tally" className="text-text-secondary">
          {tally.mapped} mapped · {tally.ignored} ignored · {tally.unmapped} need a decision
          {tally.pending ? ` · ${tally.pending} awaiting your confirmation` : ""}
          {tally.unconfirmed ? ` · ${tally.unconfirmed} unconfirmed name match${tally.unconfirmed === 1 ? "" : "es"}` : ""}
        </span>
        {data?.fetched_at ? (
          <span className="text-text-dim">list read {formatRelative(data.fetched_at)}</span>
        ) : null}
        <button
          type="button"
          disabled={reloading}
          onClick={() => void reloadList()}
          data-testid="nextdns-reload"
          className="rounded-sm border border-border px-2 py-0.5 text-text-secondary hover:text-text-primary disabled:opacity-50"
        >
          {reloading ? "Reading…" : "Reload list"}
        </button>
        {pendingSuggestions.length ? (
          <button
            type="button"
            onClick={reviewAll}
            data-testid="nextdns-accept-all"
            title="Fills in each suggestion for you to confirm row by row — a name alone is never saved"
            className="rounded-sm border border-accent px-2 py-0.5 text-accent hover:bg-accent/10"
          >
            Review {pendingSuggestions.length} suggestion{pendingSuggestions.length === 1 ? "" : "s"}
          </button>
        ) : null}
      </div>

      {loading ? (
        <p className="py-6 text-center text-sm italic text-text-dim">Loading profiles…</p>
      ) : (
        <ul className="flex flex-col gap-1.5" aria-label="NextDNS profiles">
          {profiles.map((p) => {
            const c = choices[p.profile_id] ?? initialChoice(p);
            const frozen = p.tenant_slug !== null && p.tenant_status !== null && p.tenant_status !== "active";
            const st = p.state ? STATE_TEXT[p.state] : null;
            return (
              <li
                key={p.profile_id}
                data-testid={`nextdns-profile-${p.profile_id}`}
                className="grid grid-cols-[minmax(0,1fr)_minmax(0,14rem)] items-center gap-2 rounded-sm bg-bg-input px-2 py-1.5 text-xs"
              >
                <div className="min-w-0">
                  <span className="font-semibold text-text-primary">{p.name}</span>{" "}
                  <span className="font-mono text-[10px] text-text-dim">{p.profile_id}</span>
                  {!p.listed ? (
                    <span className="ml-1 text-[10px] text-high">not in NextDNS&apos;s list any more</span>
                  ) : null}
                  {st ? (
                    <span className={`ml-2 font-mono text-[10px] uppercase ${st.tone}`}>
                      {st.label}
                      {p.queries_24h !== null ? ` · ${p.queries_24h.toLocaleString()} queries / 24 h` : ""}
                    </span>
                  ) : null}
                  {p.missing ? (
                    <span
                      className="ml-2 font-mono text-[10px] uppercase text-high"
                      data-testid={`nextdns-missing-${p.profile_id}`}
                    >
                      not visible to the API key
                    </span>
                  ) : null}
                  {p.problem ? (
                    <span
                      className="mt-0.5 block text-[10px] text-warning"
                      data-testid={`nextdns-problem-${p.profile_id}`}
                    >
                      {p.problem}
                    </span>
                  ) : null}
                  {c.state === "pending" ? (
                    <span className="ml-2 inline-flex items-center gap-1" data-testid={`nextdns-pending-${p.profile_id}`}>
                      <span className="font-mono text-[10px] uppercase text-warning">
                        suggested by name — not saved until confirmed
                      </span>
                      <button
                        type="button"
                        data-testid={`nextdns-confirm-${p.profile_id}`}
                        onClick={() => choose(p.profile_id, c.value, "confirmed")}
                        className="rounded-sm border border-accent px-1.5 font-mono text-[10px] text-accent hover:bg-accent/10"
                      >
                        Confirm
                      </button>
                      <button
                        type="button"
                        aria-label={`Drop the suggestion for ${p.name}`}
                        data-testid={`nextdns-drop-${p.profile_id}`}
                        onClick={() => choose(p.profile_id, UNMAPPED)}
                        className="rounded-sm border border-border px-1.5 font-mono text-[10px] text-text-secondary"
                      >
                        ✕
                      </button>
                    </span>
                  ) : null}
                  {c.state === "unconfirmed" && c.value !== UNMAPPED && c.value !== IGNORE ? (
                    <span className="ml-2 inline-flex items-center gap-1" data-testid={`nextdns-unconfirmed-${p.profile_id}`}>
                      <span
                        className="font-mono text-[10px] uppercase text-warning"
                        title="Mapped from a name match by an earlier version — two businesses can share a name"
                      >
                        unconfirmed name match
                      </span>
                      <button
                        type="button"
                        data-testid={`nextdns-confirm-${p.profile_id}`}
                        onClick={() => choose(p.profile_id, c.value, "confirmed")}
                        className="rounded-sm border border-accent px-1.5 font-mono text-[10px] text-accent hover:bg-accent/10"
                      >
                        Confirm
                      </button>
                    </span>
                  ) : null}
                  {p.suggestion && c.value === UNMAPPED ? (
                    <button
                      type="button"
                      data-testid={`nextdns-suggest-${p.profile_id}`}
                      onClick={() => choose(p.profile_id, p.suggestion!.tenant_slug, "confirmed")}
                      className="ml-2 rounded-sm border border-accent px-1.5 font-mono text-[10px] text-accent hover:bg-accent/10"
                      title={
                        (p.suggestion.rule === "same-name" ? "Same name" : "The client's name leads the profile's") +
                        (p.suggestion.bulk === false ? " — looks like a personal / test profile: check before using" : "")
                      }
                    >
                      use {p.suggestion.tenant_name}
                    </button>
                  ) : null}
                </div>
                {frozen ? (
                  <span className="text-[11px] text-text-dim" title="Kept on purpose: the tenant left">
                    {p.tenant_name ?? p.tenant_slug} ({p.tenant_status})
                  </span>
                ) : (
                  <select
                    aria-label={`Client for ${p.name}`}
                    data-testid={`nextdns-choice-${p.profile_id}`}
                    className={selectCls}
                    value={c.value}
                    onChange={(e) => choose(p.profile_id, e.target.value)}
                  >
                    <option value={UNMAPPED}>— not mapped (never polled) —</option>
                    <option value={IGNORE}>Ignore (personal / test)</option>
                    {clients.map((cl) => (
                      <option key={cl.slug} value={cl.slug}>
                        {cl.display_name}
                      </option>
                    ))}
                  </select>
                )}
              </li>
            );
          })}
          {!profiles.length && !error ? (
            <li className="py-4 text-center text-sm italic text-text-dim">
              No profiles listed yet — press Reload list.
            </li>
          ) : null}
        </ul>
      )}

      {error ? (
        <div role="alert" className="mt-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical">
          {error}
        </div>
      ) : null}
      {notice ? (
        <p role="status" data-testid="nextdns-saved" className="mt-3 text-[11px] text-success">
          {notice}
        </p>
      ) : null}
      {dirty ? (
        <p className="mt-3 text-right text-[11px] text-text-dim">
          Unsaved changes — nothing is stored until you press Save.
        </p>
      ) : null}

      <div className="mt-auto flex items-center justify-end gap-2 pt-5">
        <button
          type="button"
          onClick={dismiss}
          data-testid="nextdns-dismiss"
          className="rounded-sm border border-border px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider text-text-secondary"
        >
          {saved && !dirty ? "Close" : dismissLabel}
        </button>
        <button
          type="button"
          disabled={saving || loading}
          onClick={() => void onSave()}
          data-testid="nextdns-save"
          className="rounded-sm border border-accent bg-accent px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider text-text-on-accent disabled:opacity-40"
        >
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </div>
  );
};

export default NextDnsProfilePanel;
