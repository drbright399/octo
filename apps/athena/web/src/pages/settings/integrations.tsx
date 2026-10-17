import { type FC, useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  configureIntegration,
  disableIntegration,
  fetchAdapterCatalog,
  listIntegrations,
  testIntegration,
} from "@/lib/api";
import type {
  CatalogAdapter,
  IntegrationDefinition,
  IntegrationInstance,
  IntegrationStatus,
  ProfileSummary,
  SiteSummary,
} from "@/contracts/integration";
import { canManageRole, type MeResponse } from "@/contracts/operator";
import { CatalogPopout } from "@/components/catalog-popout";
import { CredentialFieldInput } from "@/components/credential-field-input";
import { OnboardingGuide } from "@/components/onboarding-guide";
import { NextDnsProfilePanel } from "@/components/nextdns-profile-panel";
import { TenantMappingPanel } from "@/components/tenant-mapping-panel";
import { UniFiSitePanel } from "@/components/unifi-site-panel";
import { VendorLinksPanel } from "@/components/vendor-links-panel";
import { WebhookReachability } from "@/components/webhook-reachability";
import { allRequiredFilled, recoveryPath, visibleFields } from "@/lib/integration-fields";
import {
  AFTER_SAVE_REFRESH_MS,
  STATUS_REFRESH_MS,
  problemHeadline,
  withoutLifecycleSentences,
} from "@/lib/integration-status";
import { formatRelative } from "@/lib/time";
import { navigateTo } from "@/lib/router";

const STATUS_DOT: Record<IntegrationStatus, string> = {
  connected: "bg-success animate-pulse",
  disconnected: "bg-text-dim",
  disabled: "bg-text-dim",
  error: "bg-critical animate-pulse",
};
const STATUS_TEXT: Record<IntegrationStatus, string> = {
  connected: "text-success",
  disconnected: "text-text-dim",
  disabled: "text-text-dim",
  error: "text-critical",
};

/** "15:04" in the viewer's local time (the wait is at most an hour or so). */
const clockTime = (iso: string): string => {
  const t = new Date(iso);
  return Number.isNaN(t.getTime())
    ? iso
    : t.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
};

interface IntegrationsTabProps {
  /** The signed-in operator. Admin-only controls (Disable integration) render
   *  only for admin+ — UX hygiene; the server enforces the same gate. */
  readonly me?: MeResponse | null;
}

const IntegrationsTab: FC<IntegrationsTabProps> = ({ me = null }) => {
  const [definitions, setDefinitions] = useState<readonly IntegrationDefinition[]>([]);
  const [instances, setInstances] = useState<Record<string, IntegrationInstance>>({});
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<IntegrationDefinition | null>(null);
  const [catalogOpen, setCatalogOpen] = useState(false);
  const [disabling, setDisabling] = useState<IntegrationDefinition | null>(null);
  const [guideFor, setGuideFor] = useState<IntegrationDefinition | null>(null);
  const [mappingFor, setMappingFor] = useState<IntegrationDefinition | null>(null);
  const [linksFor, setLinksFor] = useState<IntegrationDefinition | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Same rule as the Operators-tab gate in pages/settings.tsx.
  const isAdminPlus = me ? canManageRole(me.role, "admin") : false;

  const reload = useCallback(async (): Promise<void> => {
    const r = await listIntegrations();
    setDefinitions(r.definitions);
    setInstances({ ...r.instances });
  }, []);
  const [refreshing, setRefreshing] = useState(false);
  const afterSaveTimer = useRef<number | null>(null);

  // Best effort: a failed background refresh keeps what is on screen.
  const refreshQuietly = useCallback((): void => {
    void reload().catch(() => undefined);
  }, [reload]);

  useEffect(() => {
    const whenVisible = (): void => {
      if (document.visibilityState !== "hidden") refreshQuietly();
    };
    const timer = window.setInterval(whenVisible, STATUS_REFRESH_MS);
    window.addEventListener("focus", whenVisible);
    document.addEventListener("visibilitychange", whenVisible);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("focus", whenVisible);
      document.removeEventListener("visibilitychange", whenVisible);
      if (afterSaveTimer.current !== null) window.clearTimeout(afterSaveTimer.current);
    };
  }, [refreshQuietly]);

  const onRefreshNow = async (): Promise<void> => {
    setRefreshing(true);
    try {
      await reload();
    } catch {
      // keep what is on screen
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    listIntegrations()
      .then((r) => {
        if (cancelled) return;
        setDefinitions(r.definitions);
        setInstances({ ...r.instances });
      })
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, []);

  const onSaved = (updated: IntegrationInstance): void => {
    setInstances((prev) => ({ ...prev, [updated.slug]: updated }));
    // A vendor connected for the first time has no card definition yet —
    // refresh so its card (Setup guide / Disable) appears without a reload.
    refreshQuietly();
    // …and again once the first poll has reported: the create response says
    // "started", which is a claim, not yet an observation.
    if (afterSaveTimer.current !== null) window.clearTimeout(afterSaveTimer.current);
    afterSaveTimer.current = window.setTimeout(refreshQuietly, AFTER_SAVE_REFRESH_MS);
  };

  if (loading) {
    return (
      <section className="rounded-lg border border-border bg-bg-surface p-6 text-center text-text-dim">
        Loading integrations…
      </section>
    );
  }

  return (
    <section className="rounded-lg border border-border bg-bg-surface p-6">
      <header className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h1 className="mb-1 text-lg font-semibold text-text-primary">Integrations</h1>
          <p className="text-sm text-text-dim">
            Connect MSP source-adapters. Credentials are submitted over HTTPS
            and pubkey-encrypted at rest inside this OCTO bundle's credential
            store before persistence. The browser does not store them.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setCatalogOpen(true)}
          data-testid="open-catalog-popout"
          className="shrink-0 rounded-sm border border-accent-cta bg-accent-cta px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong"
        >
          + Add integration
        </button>
      </header>

      {notice ? (
        <p
          role="status"
          data-testid="integrations-notice"
          className="mb-4 rounded border border-border bg-bg-card px-3 py-2 text-xs leading-relaxed text-text-secondary"
        >
          {notice}
        </p>
      ) : null}

      <ul
        role="list"
        className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3"
      >
        {definitions.map((def) => {
          const instance = instances[def.slug];
          const status = instance?.status ?? "disconnected";
          return (
            <li
              key={def.slug}
              data-testid={`integration-card-${def.slug}`}
              className={`flex flex-col rounded-lg border bg-bg-card p-4 ${
                status === "error" ? "border-critical" : "border-border"
              }`}
            >
              <div className="mb-2 flex items-start justify-between gap-2">
                <div>
                  <h2 className="text-sm font-semibold text-text-primary">{def.name}</h2>
                  <p className="font-mono text-[10px] uppercase tracking-wider text-text-dim">
                    {def.category}
                  </p>
                </div>
                <span className="inline-flex items-center gap-1 font-mono text-[10px] uppercase">
                  <span className={`h-1.5 w-1.5 rounded-full ${STATUS_DOT[status]}`} />
                  <span className={STATUS_TEXT[status]}>{status}</span>
                </span>
              </div>
              <p className="mb-3 flex-1 text-xs text-text-secondary">{def.description}</p>
              {/* Not healthy: say so unmistakably, with what to do about it.
                  The backend sets `error` whenever the most recent contact
                  with the vendor failed — never a quiet grey line. */}
              {instance && status === "error" ? (
                <div
                  role="alert"
                  data-testid={`integration-problem-${def.slug}`}
                  className="mb-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs leading-relaxed"
                >
                  <p className="mb-1 font-semibold text-critical">
                    {problemHeadline(instance, def.name)}
                  </p>
                  <p className="text-text-primary">
                    {instance.status_detail ??
                      "The last contact with the vendor failed and no detail was recorded. Check the server log."}
                  </p>
                  {/* Only what was OBSERVED: `receives_webhooks` means a usable
                      secret is stored (the path CAN deliver); whether anything
                      actually arrives is the receipt line below, never assumed. */}
                  {instance.contact_failure_kind && instance.receives_webhooks ? (
                    <p
                      data-testid={`integration-webhooks-unaffected-${def.slug}`}
                      className="mt-1.5 text-text-secondary"
                    >
                      {instance.webhook_receipt?.last_accepted_at
                        ? `This is about polling only: inbound webhooks are a separate path, and the last one was received ${formatRelative(instance.webhook_receipt.last_accepted_at)}.`
                        : "This is about polling only. Inbound webhooks are a separate path and a polling failure does not stop them — but none has been received yet (see below)."}
                    </p>
                  ) : null}
                  <p
                    data-testid={`integration-last-contact-${def.slug}`}
                    className="mt-1.5 font-mono text-[10px] text-text-secondary"
                  >
                    {instance.last_contact_ok_at ? (
                      <>
                        Last successful contact:{" "}
                        <time dateTime={instance.last_contact_ok_at}>
                          {formatRelative(instance.last_contact_ok_at)} (
                          {instance.last_contact_ok_at})
                        </time>
                      </>
                    ) : (
                      "No successful contact since the service last started."
                    )}
                  </p>
                  <p className="mt-1.5 flex flex-wrap items-center gap-2 text-[11px] text-text-secondary">
                    <button
                      type="button"
                      disabled={refreshing}
                      onClick={() => void onRefreshNow()}
                      data-testid={`integration-refresh-${def.slug}`}
                      className="rounded-sm border border-border bg-bg-input px-2 py-0.5 text-[11px] text-text-secondary hover:text-text-primary disabled:opacity-50"
                    >
                      {refreshing ? "Checking…" : "Refresh status"}
                    </button>
                    <span>
                      This card updates by itself every {STATUS_REFRESH_MS / 1000}s.
                      {instance.contact_failure_kind
                        ? " Once the vendor side is fixed, a successful Reload of the list under Tenant mapping makes Athena poll again at once."
                        : ""}
                    </span>
                  </p>
                </div>
              ) : instance?.status_detail ? (
                <p className="mb-3 font-mono text-[11px] text-text-dim">
                  {instance.status_detail}
                </p>
              ) : null}
              {instance
                ? withoutLifecycleSentences(instance, instance.warnings ?? []).map((w) => (
                    <p key={w} role="alert" className="mb-3 text-[11px] text-warning">
                      {w}
                    </p>
                  ))
                : null}
              {/* Tenant lifecycle: what this integration's traffic left for a
                  human, with the way there. Counts come from the backend;
                  nothing here is inferred. */}
              {instance?.id != null &&
              (instance.auto_created_pending || instance.quarantined || instance.autocreate_limited) ? (
                <TenantLifecycleLines slug={def.slug} instance={instance} />
              ) : null}
              {/* A new integration that waits for the customer mapping before
                  its first import (RocketCyber): say so, and until when — an
                  empty feed here is expected, not a fault. */}
              {instance?.first_import_waiting_until ? (
                <p
                  role="status"
                  data-testid={`integration-first-import-${def.slug}`}
                  className="mb-3 text-[11px] text-text-secondary"
                >
                  Waiting for your customer mapping — imports start as soon as you save it, or
                  automatically at{" "}
                  <time dateTime={instance.first_import_waiting_until}>
                    {clockTime(instance.first_import_waiting_until)}
                  </time>
                  .
                </p>
              ) : null}
              {/* A first import that waits for the mapping with NO deadline
                  (NextDNS: nothing is ever imported from an unmapped
                  profile, so it never "starts on its own"). */}
              {instance?.waiting_for_tenant_mapping && !instance.first_import_waiting_until ? (
                <p
                  role="status"
                  data-testid={`integration-first-import-${def.slug}`}
                  className="mb-3 text-[11px] text-text-secondary"
                >
                  Waiting for your {instance.profiles ? "profile" : instance.sites ? "site" : "tenant"} mapping — imports
                  start as soon as you save it.
                  {instance.profiles ? " Unmapped profiles are never polled." : ""}
                  {instance.sites ? " Nothing is read from an unmapped site." : ""}
                </p>
              ) : null}
              {instance?.sites ? (
                <SiteSummaryLines
                  slug={def.slug}
                  summary={instance.sites}
                  canMap={isAdminPlus && instance.id != null}
                  onMap={() => setMappingFor(def)}
                />
              ) : null}
              {instance?.profiles ? (
                <ProfileSummaryLines
                  slug={def.slug}
                  summary={instance.profiles}
                  canMap={isAdminPlus && instance.id != null}
                  onMap={() => setMappingFor(def)}
                />
              ) : null}
              {/* Notes are a deliberate choice (e.g. poll-only), not a fault:
                  no alert role, no warning colour. */}
              {instance?.notes?.map((n) => (
                <p
                  key={n}
                  role="note"
                  data-testid={`integration-note-${def.slug}`}
                  className="mb-3 text-[11px] text-text-dim"
                >
                  {n}
                </p>
              ))}
              {/* Did the vendor's webhook ever REACH Athena? A 403 in the
                  vendor's own test comes from the edge, never from Athena. */}
              {instance?.webhook_receipt ? (
                <WebhookReachability slug={def.slug} receipt={instance.webhook_receipt} />
              ) : null}
              <div className="flex flex-wrap gap-2">
                {/* Credentials are create-only: once connected there is nothing
                    to configure here — the old drawer opened an empty form whose
                    Save posted blank credentials. Replace = Disable, then + Add. */}
                {!instance ? (
                  <button
                    type="button"
                    onClick={() => setEditing(def)}
                    className="rounded-sm border border-border-bright bg-accent-soft px-3 py-1.5 text-xs text-accent hover:bg-accent/20"
                  >
                    Configure
                  </button>
                ) : null}
                {instance ? (
                  <button
                    type="button"
                    onClick={() => setGuideFor(def)}
                    data-testid={`setup-guide-${def.slug}`}
                    className="rounded-sm border border-border bg-bg-input px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary"
                  >
                    Setup guide
                  </button>
                ) : null}
                {/* The mapping step of the wizard, reachable again: without
                    this a wrong mapping could only be fixed by Disable + re-add. */}
                {isAdminPlus && instance?.id != null ? (
                  <button
                    type="button"
                    onClick={() => setMappingFor(def)}
                    data-testid={`tenant-mapping-${def.slug}`}
                    className="rounded-sm border border-border bg-bg-input px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary"
                  >
                    Tenant mapping
                  </button>
                ) : null}
                {/* "Open in <vendor>" link settings — only for adapters that
                    can build such links. Non-secret; admin+. */}
                {isAdminPlus && instance?.id != null && instance.supports_vendor_links ? (
                  <button
                    type="button"
                    onClick={() => setLinksFor(def)}
                    data-testid={`vendor-links-${def.slug}`}
                    className="rounded-sm border border-border bg-bg-input px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary"
                  >
                    Portal links
                  </button>
                ) : null}
                {isAdminPlus && instance?.id != null ? (
                  <button
                    type="button"
                    onClick={() => setDisabling(def)}
                    data-testid={`disable-integration-${def.slug}`}
                    className="rounded-sm border border-critical/50 bg-bg-input px-3 py-1.5 text-xs text-critical hover:bg-critical/10"
                  >
                    Disable
                  </button>
                ) : null}
                {def.docs_url ? (
                  <a
                    href={def.docs_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="rounded-sm border border-border bg-bg-input px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary"
                  >
                    docs ↗
                  </a>
                ) : null}
              </div>
            </li>
          );
        })}
      </ul>

      {editing ? (
        <ConfigureDrawer
          def={editing}
          onClose={() => setEditing(null)}
          onSaved={onSaved}
        />
      ) : null}

      {disabling && instances[disabling.slug]?.id != null ? (
        <DisableIntegrationDialog
          def={disabling}
          instanceId={instances[disabling.slug]?.id ?? 0}
          onClose={() => setDisabling(null)}
          onDisabled={(message) => {
            setDisabling(null);
            setNotice(message);
            // The list carries active instances only — refresh so the card
            // goes and "+ Add integration" is the obvious next step.
            void reload().catch(() => undefined);
          }}
        />
      ) : null}

      {guideFor ? (
        <SetupGuideDrawer def={guideFor} onClose={() => setGuideFor(null)} />
      ) : null}

      {mappingFor && instances[mappingFor.slug]?.id != null ? (
        <TenantMappingDrawer
          def={mappingFor}
          instanceId={instances[mappingFor.slug]?.id ?? 0}
          onClose={() => {
            setMappingFor(null);
            // The card's "mappings match no site" warning follows what was
            // just saved (or just discovered) — refresh it.
            void reload().catch(() => undefined);
          }}
        />
      ) : null}

      {linksFor && instances[linksFor.slug]?.id != null ? (
        <VendorLinksDrawer
          def={linksFor}
          instanceId={instances[linksFor.slug]?.id ?? 0}
          onClose={() => setLinksFor(null)}
        />
      ) : null}

      <CatalogPopout
        open={catalogOpen}
        onClose={() => {
          setCatalogOpen(false);
          // The wizard's mapping step may just have been used (and its site
          // discovery nudges the poller): show what is true now.
          refreshQuietly();
        }}
        onConfigured={onSaved}
      />
    </section>
  );
};

// ---------------------------------------------------------------------------
// Per-profile counts (NextDNS) — what is mapped, what needs a decision, how
// the sites' DNS filtering is doing, and whether NextDNS is throttling us.
// ---------------------------------------------------------------------------

const ProfileSummaryLines: FC<{
  readonly slug: string;
  readonly summary: ProfileSummary;
  readonly canMap: boolean;
  readonly onMap: () => void;
}> = ({ slug, summary, canMap, onMap }) => {
  const unmapped = summary.unmapped ?? 0;
  return (
    <div className="mb-3 flex flex-col gap-1 text-[11px]" data-testid={`integration-profiles-${slug}`}>
      <p data-testid={`integration-profile-counts-${slug}`} className="text-text-secondary">
        {summary.mapped} profile{summary.mapped === 1 ? "" : "s"} mapped · {summary.ignored} ignored
        {summary.unmapped === null ? "" : ` · ${summary.unmapped} unmapped`}
      </p>
      {unmapped > 0 ? (
        <p role="alert" className="text-warning" data-testid={`integration-profiles-unmapped-${slug}`}>
          {canMap ? (
            <button type="button" className={linkBtn} onClick={onMap}>
              {unmapped} profile{unmapped === 1 ? "" : "s"} need{unmapped === 1 ? "s" : ""} a decision
            </button>
          ) : (
            `${unmapped} profile${unmapped === 1 ? "" : "s"} need${unmapped === 1 ? "s" : ""} a decision`
          )}
          {" — map each to its client, or ignore it (unmapped profiles are never polled)."}
        </p>
      ) : null}
      {summary.mapped > 0 ? (
        <p data-testid={`integration-protection-${slug}`} className="text-text-secondary">
          Protection: {summary.active} active · {summary.pending} pending rollout
          {summary.checking ? ` · ${summary.checking} being checked` : ""}
          {summary.lapsed ? (
            <span className="text-high"> · {summary.lapsed} stopped reporting</span>
          ) : null}
          {summary.missing ? (
            <span className="text-high"> · {summary.missing} not visible to the key</span>
          ) : null}
        </p>
      ) : null}
      {summary.checking && summary.checking === summary.mapped ? (
        <p role="status" className="text-text-dim" data-testid={`integration-first-pass-${slug}`}>
          First pass under way: each newly mapped profile is checked (about 2 s per NextDNS
          call), then its last 24 hours of security blocks are back-filled — this takes a few
          minutes.
        </p>
      ) : null}
      {summary.problems ? (
        <p role="status" className="text-warning" data-testid={`integration-profile-problems-${slug}`}>
          {summary.problems} profile{summary.problems === 1 ? "" : "s"} need{summary.problems === 1 ? "s" : ""} a
          look (see Tenant mapping) — the other profiles are polled as usual.
        </p>
      ) : null}
      {summary.rollup_lag_hours && summary.rollup_lag_hours >= 2 ? (
        <p role="status" className="text-warning" data-testid={`integration-rollup-lag-${slug}`}>
          Hourly roll-ups are {summary.rollup_lag_hours} h behind: the mapped profiles need more
          NextDNS calls than the rate limit allows, so checks come less often.
        </p>
      ) : null}
      {summary.fleet_outage_sites ? (
        <p role="alert" className="text-high" data-testid={`integration-fleet-outage-${slug}`}>
          {summary.fleet_outage_sites} of {summary.fleet_outage_watched ?? summary.mapped} sites
          stopped reporting at the same time — one fleet-wide incident: check NextDNS status and
          the UniFi DNS template.
          {summary.fleet_outage_tenant
            ? ` The alert is in ${summary.fleet_outage_tenant}.`
            : " No tenant of kind “internal” exists to hold its alert — set one in Settings → Tenants."}
        </p>
      ) : null}
      {summary.analytics_gaps ? (
        <p role="status" className="text-text-dim" data-testid={`integration-analytics-gap-${slug}`}>
          NextDNS analytics returned no data for most sites in {summary.analytics_gaps} recent
          hour{summary.analytics_gaps === 1 ? "" : "s"} — read as a NextDNS-side gap (at most 2
          hours in a row), not site outages.
        </p>
      ) : null}
      {summary.throttled ? (
        <p role="status" className="text-warning" data-testid={`integration-throttled-${slug}`}>
          Throttled by NextDNS (rate limit) — calls wait
          {summary.throttled_for_sec ? ` ${summary.throttled_for_sec} s` : ""} and back off on
          their own. Not a failure: the next checks cover the gap, nothing is lost.
        </p>
      ) : null}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Per-site counts (UniFi) — what is mapped, what needs a decision, consoles
// and gateways offline, and whether UniFi is throttling us.
// ---------------------------------------------------------------------------

const SiteSummaryLines: FC<{
  readonly slug: string;
  readonly summary: SiteSummary;
  readonly canMap: boolean;
  readonly onMap: () => void;
}> = ({ slug, summary, canMap, onMap }) => {
  const unmapped = summary.unmapped ?? 0;
  return (
    <div className="mb-3 flex flex-col gap-1 text-[11px]" data-testid={`integration-sites-${slug}`}>
      <p data-testid={`integration-site-counts-${slug}`} className="text-text-secondary">
        {summary.mapped} site{summary.mapped === 1 ? "" : "s"} mapped · {summary.ignored} ignored
        {summary.unmapped === null ? "" : ` · ${summary.unmapped} unmapped`}
        {summary.consoles ? ` · ${summary.consoles} console${summary.consoles === 1 ? "" : "s"}` : ""}
      </p>
      {unmapped > 0 ? (
        <p role="alert" className="text-warning" data-testid={`integration-sites-unmapped-${slug}`}>
          {canMap ? (
            <button type="button" className={linkBtn} onClick={onMap}>
              {unmapped} site{unmapped === 1 ? "" : "s"} need{unmapped === 1 ? "s" : ""} a decision
            </button>
          ) : (
            `${unmapped} site${unmapped === 1 ? "" : "s"} need${unmapped === 1 ? "s" : ""} a decision`
          )}
          {" — map each to its client one at a time, or ignore it (nothing is read from an unmapped site)."}
        </p>
      ) : null}
      {summary.consoles_offline || summary.gateways_offline ? (
        <p role="status" className="text-high" data-testid={`integration-sites-offline-${slug}`}>
          {summary.consoles_offline ? `${summary.consoles_offline} console${summary.consoles_offline === 1 ? "" : "s"} offline` : ""}
          {summary.consoles_offline && summary.gateways_offline ? " · " : ""}
          {summary.gateways_offline
            ? `${summary.gateways_offline} mapped site${summary.gateways_offline === 1 ? "" : "s"} with the gateway offline`
            : ""}
        </p>
      ) : null}
      {summary.problems ? (
        <p role="status" className="text-warning" data-testid={`integration-site-problems-${slug}`}>
          {summary.problems} site{summary.problems === 1 ? "" : "s"} need{summary.problems === 1 ? "s" : ""} a look
          (see Tenant mapping) — the other sites are read as usual.
        </p>
      ) : null}
      {summary.legacy_mappings ? (
        <p role="note" className="text-text-dim" data-testid={`integration-site-legacy-${slug}`}>
          {summary.legacy_mappings} mapping{summary.legacy_mappings === 1 ? "" : "s"} of the retired
          local-controller integration {summary.legacy_mappings === 1 ? "is" : "are"} kept but never read —
          map the sites in Tenant mapping.
        </p>
      ) : null}
      {summary.throttled ? (
        <p role="status" className="text-warning" data-testid={`integration-sites-throttled-${slug}`}>
          Throttled by UniFi (rate limit) — calls wait
          {summary.throttled_for_sec ? ` ${summary.throttled_for_sec} s` : ""} and back off on their
          own. Not a failure: the system log is read from where it stopped, nothing is lost.
        </p>
      ) : null}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Tenant lifecycle lines — what this instance's traffic left for a human
// ---------------------------------------------------------------------------

const linkBtn =
  "underline decoration-dotted underline-offset-2 hover:text-accent";

const TenantLifecycleLines: FC<{
  readonly slug: string;
  readonly instance: IntegrationInstance;
}> = ({ slug, instance }) => {
  const pending = instance.auto_created_pending ?? 0;
  const held = instance.quarantined ?? 0;
  return (
    <div className="mb-3 flex flex-col gap-1 text-[11px]" data-testid={`integration-lifecycle-${slug}`}>
      {pending > 0 ? (
        <p role="alert" className="text-warning">
          <button
            type="button"
            className={linkBtn}
            onClick={() => navigateTo("/settings/tenants?filter=needs-review")}
            data-testid={`integration-autocreated-${slug}`}
          >
            {pending} tenant{pending === 1 ? "" : "s"} auto-created, awaiting review
          </button>
          {" — say what each one is under Settings → Tenants."}
        </p>
      ) : null}
      {held > 0 ? (
        <p role="alert" className="text-warning">
          <button
            type="button"
            className={linkBtn}
            onClick={() => navigateTo(`/settings/tenants/quarantine?instance=${instance.id ?? ""}`)}
            data-testid={`integration-quarantined-${slug}`}
          >
            {held} event{held === 1 ? "" : "s"} in quarantine
          </button>
          {" — could not be attributed to a tenant; held until you route or discard them."}
        </p>
      ) : null}
      {instance.autocreate_limited ? (
        <p role="alert" className="text-high" data-testid={`integration-autocreate-limited-${slug}`}>
          Auto-create is paused for this integration: the bound on new tenants per hour / awaiting
          review is reached. New sites are held in quarantine until pending tenants are reviewed.
        </p>
      ) : null}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Disable integration — confirm + required reason (admin+)
// ---------------------------------------------------------------------------

const REASON_MIN = 3; // mirrors the backend's DisableInstanceRequest
const REASON_MAX = 500;

interface DisableDialogProps {
  readonly def: IntegrationDefinition;
  readonly instanceId: number;
  readonly onClose: () => void;
  readonly onDisabled: (serverMessage: string) => void;
}

const DisableIntegrationDialog: FC<DisableDialogProps> = ({
  def,
  instanceId,
  onClose,
  onDisabled,
}) => {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reasonOk = reason.trim().length >= REASON_MIN;

  const onConfirm = async (): Promise<void> => {
    if (!reasonOk) return;
    setBusy(true);
    setError(null);
    try {
      const r = await disableIntegration(instanceId, reason.trim());
      onDisabled(r.message);
    } catch (e) {
      // The server's own message — it says what went wrong.
      setError(e instanceof Error ? e.message : "Disable failed");
      setBusy(false);
    }
  };

  return createPortal(
    <>
      <div
        onClick={busy ? undefined : onClose}
        aria-hidden="true"
        className="fixed inset-0 z-40 bg-black/50"
      />
      <div
        role="alertdialog"
        aria-modal="true"
        aria-label={`Disable ${def.name}`}
        data-testid="disable-integration-dialog"
        className="fixed left-1/2 top-1/2 z-50 w-[min(520px,92vw)] -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border-bright bg-bg-elevated p-5 shadow-xl"
      >
        <h2 className="text-base font-semibold text-text-primary">Disable {def.name}?</h2>
        <p className="mt-2 text-xs leading-relaxed text-text-secondary">
          This stops its poller and rejects its inbound webhooks immediately. Stored
          credentials cannot be edited or read back, so disabling is how an
          integration is replaced: afterwards use{" "}
          <span className="text-text-primary">+ Add integration</span> to create it
          again (a new webhook token is generated and shown once). Tenant mappings
          belong to this instance and are <strong>not</strong> carried over — map
          sites again before attaching the webhook in the vendor.
        </p>
        <label className="mt-3 flex flex-col gap-1 text-xs text-text-primary">
          <span>
            Reason <span className="text-critical">*</span>{" "}
            <span className="text-text-dim">
              — recorded in the audit log. Never paste a credential here.
            </span>
          </span>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={REASON_MAX}
            rows={3}
            placeholder="e.g. webhook token lost — creating it again"
            className="rounded border border-border bg-bg-input px-2 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-dim focus:border-accent focus:outline-none"
          />
        </label>
        {error ? (
          <div
            role="alert"
            className="mt-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical"
          >
            {error}
          </div>
        ) : null}
        <div className="mt-4 flex items-center justify-end gap-2">
          <button
            type="button"
            disabled={busy}
            onClick={onClose}
            className="rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={busy || !reasonOk}
            onClick={() => void onConfirm()}
            className="rounded-sm border border-critical bg-critical px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
          >
            {busy ? "Disabling…" : "Disable integration"}
          </button>
        </div>
      </div>
    </>,
    document.body,
  );
};

// ---------------------------------------------------------------------------
// Setup guide — read-only, reachable from an existing instance card
// ---------------------------------------------------------------------------

interface SetupGuideDrawerProps {
  readonly def: IntegrationDefinition;
  readonly onClose: () => void;
}

/**
 * The adapter's guided-setup content (webhook URL, header NAME, payload
 * templates) for an integration that already exists. Catalog metadata only:
 * no secret is fetched or shown — the webhook token was shown once at create
 * time and no route can return it.
 */
const SetupGuideDrawer: FC<SetupGuideDrawerProps> = ({ def, onClose }) => {
  const [adapter, setAdapter] = useState<CatalogAdapter | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchAdapterCatalog()
      .then((c) => {
        if (cancelled) return;
        setAdapter(c.adapters.find((a) => a.vendor_slug === def.slug) ?? null);
      })
      .catch((e: Error) => !cancelled && setError(e.message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [def.slug]);

  // The NextDNS panel reports unsaved choices: the backdrop and ✕ ask first.
  const dirtyRef = useRef(false);
  const guardedClose = (): void => {
    if (dirtyRef.current && !window.confirm("You have unsaved profile choices. Discard them and close?")) {
      return;
    }
    onClose();
  };

  return createPortal(
    <>
      <div onClick={guardedClose} aria-hidden="true" className="fixed inset-0 z-40 bg-black/50" />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={`${def.name} setup guide`}
        data-testid="setup-guide-drawer"
        className="fixed right-0 top-0 z-50 flex h-full w-[min(640px,100vw)] flex-col border-l border-border-bright bg-bg-elevated shadow-xl"
      >
        <header className="flex items-center justify-between border-b border-border bg-bg-surface px-5 py-4">
          <div>
            <span className="font-mono text-[10px] uppercase tracking-wider text-accent">
              Setup guide — read-only
            </span>
            <h2 className="mt-0.5 text-base font-semibold text-text-primary">{def.name}</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-sm p-1 text-text-secondary hover:bg-accent-soft hover:text-accent"
          >
            ✕
          </button>
        </header>
        <div className="flex flex-1 flex-col overflow-y-auto p-5">
          {loading ? (
            <p className="text-sm text-text-dim">Loading setup guide…</p>
          ) : error ? (
            <p role="alert" className="text-sm text-critical">
              {error}
            </p>
          ) : adapter?.onboarding ? (
            <>
              <OnboardingGuide
                onboarding={adapter.onboarding}
                deliveryMode={adapter.delivery_mode}
              />
              <p className="rounded border border-border bg-bg-surface px-3 py-2 text-xs leading-relaxed text-text-secondary">
                This integration is already saved — nothing here changes it, and this
                guide says nothing about whether it is working (its card does). The
                webhook token itself is not shown: it was displayed once when the
                integration was created and cannot be retrieved. If it is lost:{" "}
                {recoveryPath(def.name)}.
              </p>
            </>
          ) : (
            <p className="text-sm text-text-dim">This integration has no setup guide.</p>
          )}
        </div>
      </aside>
    </>,
    document.body,
  );
};

// ---------------------------------------------------------------------------
// Tenant mapping — the wizard's mapping step, for an existing instance
// ---------------------------------------------------------------------------

interface TenantMappingDrawerProps {
  readonly def: IntegrationDefinition;
  readonly instanceId: number;
  readonly onClose: () => void;
}

const TenantMappingDrawer: FC<TenantMappingDrawerProps> = ({ def, instanceId, onClose }) => {
  // Wording only (what a tenant is called, which value its id is). Best
  // effort: the panel has sensible generic wording without it, and the
  // discovery response carries the same shape.
  const [adapter, setAdapter] = useState<CatalogAdapter | null>(null);
  useEffect(() => {
    let cancelled = false;
    fetchAdapterCatalog()
      .then((c) => {
        if (!cancelled) setAdapter(c.adapters.find((a) => a.vendor_slug === def.slug) ?? null);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [def.slug]);

  // The NextDNS / UniFi panels report unsaved choices: the backdrop and ✕ ask first.
  const dirtyRef = useRef(false);
  const noun = def.slug === "unifi" ? "site" : "profile";
  const guardedClose = (): void => {
    if (dirtyRef.current && !window.confirm(`You have unsaved ${noun} choices. Discard them and close?`)) {
      return;
    }
    onClose();
  };

  return createPortal(
    <>
      <div onClick={guardedClose} aria-hidden="true" className="fixed inset-0 z-40 bg-black/50" />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={`${def.name} tenant mapping`}
        data-testid="tenant-mapping-drawer"
        className="fixed right-0 top-0 z-50 flex h-full w-[min(760px,100vw)] flex-col border-l border-border-bright bg-bg-elevated shadow-xl"
      >
        <header className="flex items-center justify-between border-b border-border bg-bg-surface px-5 py-4">
          <div>
            <span className="font-mono text-[10px] uppercase tracking-wider text-accent">
              Tenant mapping
            </span>
            <h2 className="mt-0.5 text-base font-semibold text-text-primary">{def.name}</h2>
          </div>
          <button
            type="button"
            onClick={guardedClose}
            aria-label="Close"
            className="rounded-sm p-1 text-text-secondary hover:bg-accent-soft hover:text-accent"
          >
            ✕
          </button>
        </header>
        {def.slug === "nextdns" ? (
          <NextDnsProfilePanel
            instanceId={instanceId}
            dismissLabel="Close"
            onDone={onClose}
            onDirtyChange={(d) => {
              dirtyRef.current = d;
            }}
          />
        ) : def.slug === "unifi" ? (
          <UniFiSitePanel
            instanceId={instanceId}
            dismissLabel="Close"
            onDone={onClose}
            onDirtyChange={(d) => {
              dirtyRef.current = d;
            }}
          />
        ) : (
          <TenantMappingPanel
            vendorSlug={def.slug}
            instanceId={instanceId}
            vendorName={def.name}
            shape={adapter?.tenant_mapping_shape}
            dismissLabel="Close without saving"
            onDone={onClose}
          />
        )}
      </aside>
    </>,
    document.body,
  );
};

const VendorLinksDrawer: FC<TenantMappingDrawerProps> = ({ def, instanceId, onClose }) =>
  createPortal(
    <>
      <div onClick={onClose} aria-hidden="true" className="fixed inset-0 z-40 bg-black/50" />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={`${def.name} portal links`}
        data-testid="vendor-links-drawer"
        className="fixed right-0 top-0 z-50 flex h-full w-[min(560px,100vw)] flex-col border-l border-border-bright bg-bg-elevated shadow-xl"
      >
        <header className="flex items-center justify-between border-b border-border bg-bg-surface px-5 py-4">
          <div>
            <span className="font-mono text-[10px] uppercase tracking-wider text-accent">
              Portal links
            </span>
            <h2 className="mt-0.5 text-base font-semibold text-text-primary">{def.name}</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-sm p-1 text-text-secondary hover:bg-accent-soft hover:text-accent"
          >
            ✕
          </button>
        </header>
        <VendorLinksPanel
          vendorSlug={def.slug}
          instanceId={instanceId}
          vendorName={def.name}
          onDone={onClose}
        />
      </aside>
    </>,
    document.body,
  );

interface ConfigureDrawerProps {
  readonly def: IntegrationDefinition;
  readonly onClose: () => void;
  readonly onSaved: (i: IntegrationInstance) => void;
}

const ConfigureDrawer: FC<ConfigureDrawerProps> = ({ def, onClose, onSaved }) => {
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(def.fields.map((f) => [f.name, ""])),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; detail: string } | null>(null);

  const setField = (name: string, value: string): void =>
    setValues((prev) => ({ ...prev, [name]: value }));

  const allFilled = allRequiredFilled(def.fields, values);

  const onSave = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const updated = await configureIntegration(def.slug, values);
      onSaved(updated);
      // Wipe values from memory after save — the server has them now.
      setValues(Object.fromEntries(def.fields.map((f) => [f.name, ""])));
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setBusy(false);
    }
  };

  const onTest = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    setTestResult(null);
    try {
      const r = await testIntegration(def.slug);
      setTestResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Test failed");
    } finally {
      setBusy(false);
    }
  };

  // Portal to document.body. Without this the drawer renders inside
  // the App root's `relative z-10` stacking context, where its z-50
  // only wins against siblings in that context — the status-strip
  // footer (also z-10 at App-root level) then paints over the
  // drawer's bottom action buttons because DOM order tiebreaks.
  // Portal'ing escapes the parent context so z-50 wins against
  // every App-root sibling. Same trick we use for the floating
  // ticket window + /search drawer.
  return createPortal(
    <>
      <div
        onClick={onClose}
        aria-hidden="true"
        className="fixed inset-0 z-40 bg-black/50"
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={`Configure ${def.name}`}
        className="fixed right-0 top-0 z-50 flex h-full w-[min(560px,100vw)] flex-col border-l border-border-bright bg-bg-elevated shadow-xl"
      >
        <header className="flex items-center justify-between border-b border-border bg-bg-surface px-5 py-4">
          <div>
            <span className="font-mono text-[10px] uppercase tracking-wider text-accent">
              Configure integration
            </span>
            <h2 className="mt-0.5 text-base font-semibold text-text-primary">
              {def.name}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-sm p-1 text-text-secondary hover:bg-accent-soft hover:text-accent"
          >
            ✕
          </button>
        </header>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void onSave();
          }}
          className="flex flex-1 flex-col overflow-y-auto p-5"
        >
          <p className="mb-4 rounded border border-accent/30 bg-accent-soft px-3 py-2 text-xs text-text-secondary">
            Values are submitted once over HTTPS and encrypted server-side.
            Nothing here is persisted by the browser.
          </p>

          {visibleFields(def.fields, values).map((field) => (
            <CredentialFieldInput
              key={field.name}
              field={field}
              value={values[field.name] ?? ""}
              onChange={(v) => setField(field.name, v)}
            />
          ))}

          {error ? (
            <div role="alert" className="mt-3 rounded border border-critical bg-critical/10 px-3 py-2 text-xs text-critical">
              {error}
            </div>
          ) : null}
          {testResult ? (
            <div
              role="status"
              className={[
                "mt-3 rounded border px-3 py-2 text-xs",
                testResult.ok
                  ? "border-success/50 bg-success/10 text-success"
                  : "border-critical bg-critical/10 text-critical",
              ].join(" ")}
            >
              {testResult.ok ? "✓ " : "✗ "}
              {testResult.detail}
            </div>
          ) : null}
        </form>

        <footer className="flex items-center justify-end gap-2 border-t border-border bg-bg-surface px-5 py-3">
          <button
            type="button"
            disabled={busy || !allFilled}
            onClick={() => void onTest()}
            className="rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary hover:border-border-bright hover:text-text-primary disabled:opacity-50"
          >
            Test connection
          </button>
          <button
            type="button"
            onClick={onClose}
            className="rounded-sm border border-border bg-bg-card px-3 py-1.5 text-xs text-text-secondary hover:text-text-primary"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={busy || !allFilled}
            onClick={() => void onSave()}
            className="rounded-sm border border-accent-cta bg-accent-cta px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-strong disabled:opacity-50"
          >
            {busy ? "Saving…" : "Save & encrypt"}
          </button>
        </footer>
      </aside>
    </>,
    document.body,
  );
};

export default IntegrationsTab;
