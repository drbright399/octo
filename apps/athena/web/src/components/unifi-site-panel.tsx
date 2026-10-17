/**
 * UniFiSitePanel — the UniFi mapping step (wizard) and the card's "Tenant
 * mapping" drawer.
 *
 * One cloud key sees every console of the account — client sites, but also
 * personal and non-client consoles. NOTHING is read from a site until it is
 * mapped to a client. Every site is keyed by its console AND its site id
 * (site ids collide across consoles), and shown with its console, its
 * LOCATION and its internet connection, because a name alone proves nothing:
 * two businesses can share one (the same-name rule, 2026-10-01). So:
 *   - there is NO bulk accept: the operator picks the client site by site;
 *   - a same-name suggestion is offered on its row only ("use <client>") and
 *     still needs a Save;
 *   - "Ignore" keeps a personal / non-client site out of "needs a decision".
 * The list comes from the poller's last fleet poll (the server never asks
 * UniFi to build this panel); "Reload list" is two UniFi calls. Save sends
 * the mappings and the ignore list together (one audited PUT); closing with
 * unsaved choices asks first.
 *
 * A mapped site has a ✕ (2026-10-08: after a client's network moved to new
 * hardware the OLD site's mapping had to go, and changing the dropdown and
 * saving was not discoverable). It asks first — unlink only, or unlink and
 * ignore — and then SAVES AT ONCE: the PUT replaces the whole set, so it is
 * the server's state RE-READ at that moment (a mapping written elsewhere
 * since this list was read is kept) plus that one change, never the
 * operator's other unsaved choices, which stay staged. If that site itself
 * changed meanwhile nothing is saved: the operator confirmed something else.
 * A failed PUT is followed by a re-read too — the server stores the mappings
 * and the ignore list one after the other, so a failure can come after the
 * first. A Reload and a save never overlap (an older list must not put back
 * what a save just changed). A frozen mapping (the client left) has no ✕, as
 * in the generic mapping panel: the server keeps it whatever a save sends.
 */
import { type FC, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { UniFiSite, UniFiSites, UniFiSitesSave } from "@/contracts/integration";
import { ConfirmDialog } from "@/components/confirm-dialog";
import {
  type ClientEntry,
  getUniFiSites,
  listClients,
  listVendorTenants,
  saveUniFiSites,
} from "@/lib/api";
import { formatRelative } from "@/lib/time";

const IGNORE = "__ignore__";
const UNMAPPED = "";
const DISCARD_PROMPT = "You have unsaved site choices. Discard them and close?";

function initialChoice(s: UniFiSite): string {
  if (s.tenant_slug) return s.tenant_slug;
  if (s.ignored) return IGNORE;
  return UNMAPPED;
}

/** The one PUT body: every site's choice (a client slug, IGNORE or UNMAPPED). */
function saveBody(sites: readonly UniFiSite[], choiceOf: (s: UniFiSite) => string): UniFiSitesSave {
  const mappings = sites
    .filter((s) => {
      const v = choiceOf(s);
      return v !== UNMAPPED && v !== IGNORE;
    })
    .map((s) => ({ scope: s.scope, tenant_slug: choiceOf(s) }));
  const ignored = sites.filter((s) => choiceOf(s) === IGNORE).map((s) => s.scope);
  return { mappings, ignored };
}

/** Why "Unlink and ignore" is the recommended choice for this site, or null:
 *  UniFi no longer lists it, its console is offline (the gateway counts it
 *  last sent go stale with it — a retired console), or its gateway is. */
function retiringReason(s: UniFiSite): string | null {
  if (!s.listed) return "It is no longer in UniFi's list";
  if (s.host_connected === false) return "Its console is offline";
  if (s.gateway_online === false) return "Its gateway is offline";
  return null;
}

/** A site as the server holds it, in words ("mapped to Acme Corp"). */
function stateOf(s: UniFiSite | undefined): string {
  if (!s) return "no longer listed";
  if (s.tenant_slug) return `mapped to ${s.tenant_name ?? s.tenant_slug}`;
  return s.ignored ? "ignored" : "not mapped";
}

type UnlinkTo = "unmap" | "ignore";

interface Props {
  readonly instanceId: number;
  readonly dismissLabel?: string;
  readonly onDone: () => void;
  readonly onDirtyChange?: (dirty: boolean) => void;
}

export const UniFiSitePanel: FC<Props> = ({
  instanceId,
  dismissLabel = "Skip for now",
  onDone,
  onDirtyChange,
}) => {
  const [data, setData] = useState<UniFiSites | null>(null);
  const [clients, setClients] = useState<readonly ClientEntry[]>([]);
  const [choices, setChoices] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloading, setReloading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  /** The ✕ that was pressed: which site, the mapping it showed (what the
   *  operator confirms), and where focus goes back to. */
  const [unlink, setUnlink] = useState<{
    readonly scope: string;
    readonly slug: string;
    readonly client: string;
    readonly opener: HTMLElement;
  } | null>(null);
  const [unlinking, setUnlinking] = useState<UnlinkTo | null>(null);
  const [unlinkError, setUnlinkError] = useState<string | null>(null);
  const shownRef = useRef<ReadonlyMap<string, UniFiSite>>(new Map());
  const selectRefs = useRef(new Map<string, HTMLSelectElement>());
  const rootRef = useRef<HTMLDivElement | null>(null);
  const noticeRef = useRef<HTMLParagraphElement | null>(null);
  const errorRef = useRef<HTMLDivElement | null>(null);

  /** Take the server's list; unsaved edits are KEPT unless `reset`. */
  const adopt = useCallback((body: UniFiSites, opts: { readonly reset?: boolean } = {}) => {
    const shown = shownRef.current;
    shownRef.current = new Map(body.sites.map((s) => [s.scope, s]));
    setData(body);
    setChoices((prev) =>
      Object.fromEntries(
        body.sites.map((s) => {
          const kept = prev[s.scope];
          const before = shown.get(s.scope);
          const edited = !opts.reset && kept !== undefined && before !== undefined && kept !== initialChoice(before);
          return [s.scope, edited ? kept : initialChoice(s)];
        }),
      ),
    );
  }, []);

  const reloadList = useCallback(async (): Promise<void> => {
    setReloading(true);
    setError(null);
    try {
      await listVendorTenants(instanceId, { refresh: true });
      const [body, cl] = await Promise.all([getUniFiSites(instanceId), listClients()]);
      setClients(cl.filter((c) => c.status === "active"));
      adopt(body);
    } catch (e) {
      setError(e instanceof Error ? e.message : "The site list could not be loaded.");
    } finally {
      setReloading(false);
    }
  }, [adopt, instanceId]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [body, cl] = await Promise.all([getUniFiSites(instanceId), listClients()]);
        if (cancelled) return;
        setClients(cl.filter((c) => c.status === "active"));
        if (!body.discovered) {
          await listVendorTenants(instanceId);           // two UniFi calls, once
          if (cancelled) return;
          adopt(await getUniFiSites(instanceId));
        } else {
          adopt(body);
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "The UniFi sites could not be loaded.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [adopt, instanceId]);

  const sites = data?.sites ?? [];
  const dirty = useMemo(
    () => sites.some((s) => choices[s.scope] !== undefined && choices[s.scope] !== initialChoice(s)),
    [choices, sites],
  );
  useEffect(() => {
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);

  const tally = useMemo(() => {
    let mapped = 0;
    let ignored = 0;
    let unmapped = 0;
    for (const s of sites) {
      const v = choices[s.scope] ?? UNMAPPED;
      if (v === IGNORE) ignored += 1;
      else if (v === UNMAPPED) unmapped += s.listed ? 1 : 0;
      else mapped += 1;
    }
    return { mapped, ignored, unmapped };
  }, [choices, sites]);

  const choose = (scope: string, value: string): void => {
    setNotice(null);
    setSaved(false);
    setChoices((prev) => ({ ...prev, [scope]: value }));
  };

  const dismiss = (): void => {
    if (dirty && !window.confirm(DISCARD_PROMPT)) return;
    onDone();
  };

  const onSave = async (): Promise<void> => {
    setSaving(true);
    setError(null);
    try {
      const { mappings, ignored } = saveBody(sites, (s) => choices[s.scope] ?? UNMAPPED);
      adopt(await saveUniFiSites(instanceId, { mappings, ignored }), { reset: true });
      setSaved(true);
      setNotice(
        mappings.length
          ? `Saved. ${mappings.length} site${mappings.length === 1 ? "" : "s"} mapped — Athena reads each one's last 24 hours of security events now, then every 5 minutes.`
          : "Saved. No site is mapped yet, so nothing is read from any site.",
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "The mapping could not be saved.");
    } finally {
      setSaving(false);
    }
  };

  const target = unlink ? (sites.find((s) => s.scope === unlink.scope) ?? null) : null;
  /** Staged choices on OTHER rows — the ✕ never saves them. */
  const othersStaged = (scope: string): boolean =>
    sites.some((s) => s.scope !== scope && choices[s.scope] !== undefined && choices[s.scope] !== initialChoice(s));

  const onUnlink = async (to: UnlinkTo): Promise<void> => {
    if (!unlink || !target) return;
    const { scope, slug, client } = unlink;
    const name = target.name;
    const others = othersStaged(scope);
    setUnlinking(to);
    setUnlinkError(null);
    try {
      // The server's state NOW, not when this list was read: the PUT
      // replaces the whole set, and a mapping written since (another tab,
      // Quarantine's "map to") must not be undone by unlinking another site.
      const fresh = await getUniFiSites(instanceId);
      const was = fresh.sites.find((s) => s.scope === scope);
      if (was?.tenant_slug !== slug) {
        // This very site changed meanwhile: what was confirmed is not what
        // would be saved. Show what the server holds; save nothing.
        adopt(fresh);
        setUnlink(null);
        setNotice(null);
        setError(`Nothing was saved: ${name} changed since this list was read — it is now ${stateOf(was)}. Check it and choose again.`);
        return;
      }
      // That state plus this one change: every other site goes out as the
      // server holds it, whatever its dropdown shows right now.
      const answer = await saveUniFiSites(
        instanceId,
        saveBody(fresh.sites, (s) => (s.scope !== scope ? initialChoice(s) : to === "ignore" ? IGNORE : UNMAPPED)),
      );
      adopt(answer);                                     // other staged choices are kept
      const now = answer.sites.find((s) => s.scope === scope);
      if (now) setChoices((prev) => ({ ...prev, [scope]: initialChoice(now) }));   // the ✕ wins on its own row
      setError(null);
      setSaved(true);
      setNotice(others ? "Unlinked and saved. Your other unsaved changes are still pending." : "Unlinked and saved.");
      setUnlink(null);
    } catch (e) {
      const reason = e instanceof Error ? e.message : "The site could not be unlinked.";
      // The server stores the mappings, then the ignore list: a failure can
      // come after the first. Re-read, so the screen — and the base of the
      // next save — is what it holds. Unreadable: the screen stays as it was.
      const now = await getUniFiSites(instanceId).catch(() => null);
      if (now) {
        adopt(now);
        const site = now.sites.find((s) => s.scope === scope);
        if (site?.tenant_slug !== slug) {
          setUnlink(null);
          setNotice(null);
          setError(`${reason} — yet ${name} is no longer linked to ${client}: it is ${stateOf(site)}. The list shows what is stored now.`);
          return;
        }
      }
      // Nothing changed: the dialog stays, with the server's reason.
      setUnlinkError(reason);
    } finally {
      setUnlinking(null);
    }
  };

  const selectCls =
    "w-full rounded-sm border border-border bg-bg-input px-2 py-1 font-mono text-[11px] text-text-primary";

  return (
    <div
      ref={rootRef}
      tabIndex={-1}
      className="flex min-h-0 flex-1 flex-col overflow-y-auto px-5 py-4 focus:outline-none"
      data-testid="unifi-site-panel"
    >
      <p className="mb-3 text-xs leading-relaxed text-text-secondary">
        Map each UniFi site to its client, <strong>one site at a time</strong> — several sites may
        belong to one client. <strong>Nothing is read from a site until it is mapped.</strong> Two
        businesses can share a name, so a matching name is only a hint: check the console and the
        location. Mark personal and non-client consoles <em>Ignore</em>. Athena never creates a
        client from a UniFi site: if a site&apos;s client is missing, create it in Settings →
        Tenants first, then press <em>Reload list</em> (your choices here are kept). To unlink a
        mapped site, press its <strong>✕</strong> — it asks first, then saves that one change.
      </p>

      <div className="mb-3 flex flex-wrap items-center gap-2 font-mono text-[11px]">
        <span data-testid="unifi-tally" className="text-text-secondary">
          {tally.mapped} mapped · {tally.ignored} ignored · {tally.unmapped} need a decision
        </span>
        {data?.fetched_at ? <span className="text-text-dim">list read {formatRelative(data.fetched_at)}</span> : null}
        <button
          type="button"
          disabled={reloading || saving || unlinking !== null}
          onClick={() => void reloadList()}
          data-testid="unifi-reload"
          className="rounded-sm border border-border px-2 py-0.5 text-text-secondary hover:text-text-primary disabled:opacity-50"
        >
          {reloading ? "Reading…" : "Reload list"}
        </button>
      </div>

      {loading ? (
        <p className="py-6 text-center text-sm italic text-text-dim">Loading sites…</p>
      ) : (
        <ul className="flex flex-col gap-1.5" aria-label="UniFi sites">
          {sites.map((s) => {
            const v = choices[s.scope] ?? initialChoice(s);
            const frozen = s.tenant_slug !== null && s.tenant_status !== null && s.tenant_status !== "active";
            // A saved mapping: what the SERVER holds, whatever the dropdown shows.
            const linked = s.tenant_slug !== null && !frozen;
            const client = s.tenant_name ?? s.tenant_slug ?? "";
            const wan = s.wans
              .filter((w) => w.external_ip)
              .map((w) => `${w.wan} ${w.external_ip}${w.isp ? ` (${w.isp})` : ""}${w.shared_external ? " — shared with another network" : ""}`)
              .join(" · ");
            return (
              <li
                key={s.scope}
                data-testid={`unifi-site-${s.scope}`}
                className="grid grid-cols-[minmax(0,1fr)_minmax(0,14rem)_1.75rem] items-center gap-2 rounded-sm bg-bg-input px-2 py-1.5 text-xs"
              >
                <div className="min-w-0">
                  <span className="font-semibold text-text-primary">{s.name}</span>{" "}
                  <span className="text-[11px] text-text-secondary">on {s.console_name || "a console"}</span>
                  {!s.listed ? (
                    <span className="ml-1 text-[10px] text-high">not in UniFi&apos;s list any more</span>
                  ) : null}
                  {s.gateway_online === false ? (
                    <span className="ml-2 font-mono text-[10px] uppercase text-high">gateway offline</span>
                  ) : null}
                  <span className="block text-[10px] text-text-dim" data-testid={`unifi-location-${s.scope}`}>
                    {s.location_text ?? "no location"}
                    {s.timezone ? ` · ${s.timezone}` : ""}
                    {wan ? ` · ${wan}` : ""}
                  </span>
                  {s.problem ? (
                    <span className="mt-0.5 block text-[10px] text-warning" data-testid={`unifi-problem-${s.scope}`}>
                      {s.problem}
                    </span>
                  ) : null}
                  {s.suggestion && v === UNMAPPED ? (
                    <button
                      type="button"
                      data-testid={`unifi-suggest-${s.scope}`}
                      onClick={() => choose(s.scope, s.suggestion!.tenant_slug)}
                      title="Same name only — check the console and the location before you save"
                      className="mt-0.5 rounded-sm border border-accent px-1.5 font-mono text-[10px] text-accent hover:bg-accent/10"
                    >
                      use {s.suggestion.tenant_name}?
                    </button>
                  ) : null}
                </div>
                {frozen ? (
                  <span className="text-[11px] text-text-dim" title="Kept on purpose: the tenant left">
                    {s.tenant_name ?? s.tenant_slug} ({s.tenant_status})
                  </span>
                ) : (
                  <select
                    ref={(el) => {
                      if (el) selectRefs.current.set(s.scope, el);
                      else selectRefs.current.delete(s.scope);
                    }}
                    aria-label={`Client for ${s.name} on ${s.console_name}`}
                    data-testid={`unifi-choice-${s.scope}`}
                    className={selectCls}
                    value={v}
                    onChange={(e) => choose(s.scope, e.target.value)}
                  >
                    <option value={UNMAPPED}>— not mapped (never read) —</option>
                    <option value={IGNORE}>Ignore (personal / not a client)</option>
                    {clients.map((cl) => (
                      <option key={cl.slug} value={cl.slug}>
                        {cl.display_name}
                      </option>
                    ))}
                  </select>
                )}
                {linked ? (
                  <button
                    type="button"
                    // Never beside a Reload: an older list must not put back what it saves.
                    disabled={saving || reloading}
                    // With its console: a restored client has two sites of one name.
                    aria-label={`Unlink ${s.name} (on ${s.console_name || "a console"}) from ${client}`}
                    title={`Unlink from ${client} — asks first, then saves`}
                    data-testid={`unifi-unlink-${s.scope}`}
                    onClick={(e) => {
                      setUnlinkError(null);
                      setUnlink({ scope: s.scope, slug: s.tenant_slug ?? "", client, opener: e.currentTarget });
                    }}
                    className="rounded-sm border border-border px-1 py-0.5 text-text-secondary hover:border-critical hover:text-critical disabled:opacity-40"
                  >
                    ✕
                  </button>
                ) : (
                  <span aria-hidden="true" />
                )}
              </li>
            );
          })}
          {!sites.length && !error ? (
            <li className="py-4 text-center text-sm italic text-text-dim">No sites listed yet — press Reload list.</li>
          ) : null}
        </ul>
      )}

      {data?.legacy.length ? (
        <p role="note" className="mt-3 text-[11px] text-text-dim" data-testid="unifi-legacy">
          {data.legacy.length} mapping{data.legacy.length === 1 ? "" : "s"} of the retired local-controller
          integration ({data.legacy.map((m) => m.tenant_name ?? m.tenant_slug).join(", ")}) {data.legacy.length === 1 ? "is" : "are"} kept but
          never read: a bare site id is the same on every console. Map the sites above instead.
        </p>
      ) : null}

      {error ? (
        <div
          ref={errorRef}
          role="alert"
          tabIndex={-1}
          className="mt-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical"
        >
          {error}
        </div>
      ) : null}
      {notice ? (
        <p ref={noticeRef} role="status" tabIndex={-1} data-testid="unifi-saved" className="mt-3 text-[11px] text-success">
          {notice}
        </p>
      ) : null}
      {dirty ? (
        <p className="mt-3 text-right text-[11px] text-text-dim">Unsaved changes — nothing is stored until you press Save.</p>
      ) : null}

      <div className="mt-auto flex items-center justify-end gap-2 pt-5">
        <button
          type="button"
          onClick={dismiss}
          data-testid="unifi-dismiss"
          className="rounded-sm border border-border px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider text-text-secondary"
        >
          {saved && !dirty ? "Close" : dismissLabel}
        </button>
        <button
          type="button"
          disabled={saving || loading || reloading || unlinking !== null}
          onClick={() => void onSave()}
          data-testid="unifi-save"
          className="rounded-sm border border-accent bg-accent px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider text-text-on-accent disabled:opacity-40"
        >
          {saving ? "Saving…" : "Save"}
        </button>
      </div>

      {unlink && target ? (
        <ConfirmDialog
          title="Unlink this site?"
          testId="unifi-unlink-dialog"
          busy={unlinking}
          error={unlinkError}
          onCancel={() => {
            setUnlink(null);
            setUnlinkError(null);
          }}
          // Back to the ✕ — once unlinked it is gone: then the row's dropdown;
          // a site UniFi no longer lists leaves the panel: then what happened.
          returnFocus={() =>
            unlink.opener.isConnected
              ? unlink.opener
              : (selectRefs.current.get(unlink.scope) ?? noticeRef.current ?? errorRef.current ?? rootRef.current)
          }
          actions={[
            {
              id: "unmap",
              label: "Unlink only",
              busyLabel: "Unlinking…",
              primary: retiringReason(target) === null,
              onSelect: () => void onUnlink("unmap"),
            },
            {
              id: "ignore",
              label: "Unlink and ignore",
              busyLabel: "Unlinking…",
              primary: retiringReason(target) !== null,
              onSelect: () => void onUnlink("ignore"),
            },
          ]}
        >
          <p>
            Unlink <strong className="text-text-primary">{target.name}</strong> (on{" "}
            {target.console_name || "a console"}) from <strong className="text-text-primary">{unlink.client}</strong>?
            Athena stops reading this site — no new alerts, status or WAN from it. Its past events stay with{" "}
            {unlink.client}.
          </p>
          <p>
            {!target.listed
              ? // The server lists an unmapped site only while UniFi does.
                `${retiringReason(target)} — Unlink and ignore is recommended: it stays ignored if UniFi lists it again. Unlink only takes it off this list until UniFi lists it again; then it needs a decision.`
              : retiringReason(target)
                ? `${retiringReason(target)} — Unlink and ignore is recommended: it also keeps the site out of “need a decision”. Unlink only leaves it not mapped, to decide later.`
                : "Unlink and ignore also keeps it out of “need a decision” — the choice when the console is retired or the gateway is gone for good. Unlink only leaves it not mapped, to decide later."}
          </p>
          <p>
            This is saved as soon as you choose.
            {othersStaged(target.scope)
              ? " Your other unsaved changes are not saved with it — they stay pending until you press Save."
              : ""}
          </p>
        </ConfirmDialog>
      ) : null}
    </div>
  );
};

export default UniFiSitePanel;
