/**
 * Adapter integration contract — what the front-end needs to render
 * configure forms and what it sends back to the backend.
 *
 * Real adapter declarations come from the backend's adapter registry; the
 * front-end fetches them once the bridge wiring lands. For now, mock
 * declarations live in `src/mock/integrations.ts` for UI development.
 *
 * Security: NEVER include actual credential values in any object that is
 * stored client-side or logged. The form submits values once over HTTPS;
 * the backend pubkey-encrypts them at rest inside this bundle's
 * credential store before persisting. The browser never STORES them.
 */

// Mirrors the backend CredentialKind. `text`/`password` (renamed from the old
// `string`/`secret`); `webhook-url-out` is a display-only copy field.
export type CredentialFieldKind =
  | "text"
  | "password"
  | "enum"
  | "url"
  | "webhook-url-out";

export interface CredentialField {
  readonly name: string;
  readonly label: string;
  readonly kind: CredentialFieldKind;
  readonly description?: string;
  readonly required: boolean;
  readonly placeholder?: string;
  /** Allowed values when kind === "enum" (backend field: `choices`). */
  readonly choices?: readonly string[] | null;
  readonly pattern?: string;
  /** Conditional visibility: sibling field name → values for which this shows. */
  readonly show_when?: Readonly<Record<string, readonly string[]>> | null;
  /** Conditional requiredness: sibling field name → values for which required. */
  readonly required_when?: Readonly<Record<string, readonly string[]>> | null;
  /**
   * Webhook-secret fields only — WHO mints the secret. "platform": leave it
   * blank and the platform generates it on save (shown once); "vendor": issued
   * on the vendor side (e.g. Resend's whsec_…) and pasted in, never generated.
   */
  readonly secret_origin?: "platform" | "vendor" | null;
  /** Header a platform-defined token is presented in (e.g. X-Webhook-Token). */
  readonly webhook_header?: string | null;
}

/**
 * A webhook token the platform generated during create. Returned by the
 * backend exactly ONCE, in the create response — no route can produce it
 * again. Hold it in component state only: never localStorage/sessionStorage,
 * never a URL, never a log line.
 */
export interface GeneratedWebhookSecret {
  readonly credential_field: string;
  /** The wizard label of that field ("Webhook Token") — what operators see. */
  readonly credential_label?: string;
  readonly header_name: string;
  readonly header_value: string;
  readonly webhook_url: string | null;
  /** Why there is no webhook_url (no public ingest hostname configured). */
  readonly webhook_url_problem: string | null;
}

export interface OnboardingStep {
  readonly title: string;
  readonly body: string;
  /** Read-only value rendered with a copy button (e.g. the webhook URL). */
  readonly copy_value?: string | null;
  /** Monospaced block rendered with a copy button (e.g. a payload template). */
  readonly code_sample?: string | null;
}

export interface Onboarding {
  readonly summary: string;
  readonly webhook_url: string | null;
  /**
   * Set (with webhook_url null) when a webhook-receiving vendor has no URL
   * because no public ingest hostname is configured. Shown instead of a URL —
   * the console's own address is never a substitute.
   */
  readonly webhook_url_problem?: string | null;
  readonly steps: readonly OnboardingStep[];
}

/**
 * `error` covers BOTH "could not start" and "running, but its most recent
 * contact with the vendor failed" (backend status `error` — the poller reports
 * every poll outcome). The card must never read healthy while that is true;
 * `status_detail` says what to do about it.
 */
export type IntegrationStatus = "connected" | "disconnected" | "disabled" | "error";

export interface IntegrationDefinition {
  readonly slug: string;
  readonly name: string;
  readonly category: string;
  readonly description: string;
  readonly docs_url?: string;
  readonly fields: readonly CredentialField[];
}

/**
 * How an adapter's tenants are identified — mirrors the backend
 * `tenant_mapping_shape`. Drives the mapping panel's wording, so the field
 * says "Datto RMM site uid", not a made-up example id.
 */
export interface TenantMappingShape {
  readonly fetch_method: string;
  readonly fetch_endpoint?: string | null;
  readonly vendor_tenant_id_field: string;
  readonly vendor_tenant_label_field: string;
  /** What the vendor calls one tenant, singular ("site"). */
  readonly tenant_noun?: string;
  /** Which vendor value the id is, and what it must not be confused with. */
  readonly id_help?: string | null;
}

/** One tenant as the VENDOR knows it; `id` is the exact routing key. */
export interface VendorTenant {
  readonly id: string;
  readonly label: string;
}

/**
 * `POST /admin/adapters/instances/{id}/vendor-tenants`. `supported: false` =
 * this adapter cannot list its tenants (manual entry only). A vendor FAILURE
 * is never an empty list — the request rejects with the actionable reason.
 */
export interface VendorTenantDiscovery {
  readonly supported: boolean;
  readonly tenants: readonly VendorTenant[];
  /** The list was capped: a missing id is NOT proven wrong. */
  readonly truncated: boolean;
  readonly fetched_at: string | null;
  readonly tenant_mapping_shape: TenantMappingShape | null;
}

export interface TenantMappingEntry {
  readonly vendor_tenant_id: string;
  readonly octo_client_slug: string;
  readonly vendor_tenant_label?: string | null;
  readonly match_source?: string;
  /** Set on GET: the mapped client's lifecycle status — active | disabled |
   *  offboarded | archived. Anything but 'active' is a FROZEN row: the
   *  tenant left and its mapping is kept on purpose so the site's traffic
   *  is held in quarantine ('offboarded-tenant') instead of auto-creating a
   *  look-alike tenant. The panel shows it read-only and the server keeps
   *  it whatever a PUT sends. */
  readonly client_status?: string;
  /** Set on GET: the mapped client's display name (a departed tenant is
   *  not in the active client list the picker offers). */
  readonly client_display_name?: string;
  /** Set on GET: a mapping still to re-review (made from a NAME by an earlier
   *  version) — computed by the server; never the mapping an integration
   *  wrote for a tenant it auto-created itself. */
  readonly needs_review?: boolean;
}

export const isFrozenMapping = (m: TenantMappingEntry): boolean =>
  m.client_status !== undefined && m.client_status !== "active";

/**
 * Inbound-webhook reachability for one instance — adapter-agnostic. Answers
 * "has the vendor's request ever REACHED Athena?", which the vendor's own test
 * result cannot: a 403 / block page there is produced by whatever fronts the
 * ingest hostname, never by Athena (its webhook URL never answers 403).
 * Timestamps survive a restart (persisted); counts are in-memory and restart
 * with the service. Sentences are platform-authored — render them as-is.
 */
export interface WebhookReceipt {
  /** Vendor has a webhook route and the operator did not choose poll-only. */
  readonly enabled: boolean;
  /** …and a usable secret is stored: a correct request WOULD be accepted. */
  readonly usable: boolean;
  readonly last_accepted_at: string | null;
  readonly last_rejected_at: string | null;
  /** bad_token / replay_window / malformed / unmapped / rate_limited /
   *  not_configured / store_failed / unresolvable. */
  readonly last_reject_reason: string | null;
  /** Any request, accepted or rejected, has ever reached this instance. */
  readonly ever_reached: boolean;
  readonly accepted_since_start: number;
  readonly rejected_since_start: number;
  readonly rejected_recent: number;
  /** One line per reason class seen in the rolling window, count included. */
  readonly recent_rejections: readonly string[];
  /** Why the LAST rejected request was refused (kept across restarts). */
  readonly last_reject_detail: string | null;
  /** The calm edge checklist; non-empty only while nothing has ever arrived. */
  readonly guidance: readonly string[];
}

export interface IntegrationInstance {
  readonly slug: string;
  /** Persisted instance id — needed to address its tenant mappings. */
  readonly id?: number;
  readonly status: IntegrationStatus;
  readonly status_detail?: string;
  readonly configured_at?: string;
  readonly last_test_at?: string;
  /** Last completed vendor round-trip by the poller. In-memory on the server:
   *  absent until the first success after a restart, and for adapters whose
   *  pollers do not report contact yet. */
  readonly last_contact_ok_at?: string;
  /** WHY status is `error`, when the POLLER observed it: forbidden / auth /
   *  transport / internal. Absent for a start failure. The card words its
   *  headline by this — it never claims more than was observed. */
  readonly contact_failure_kind?: string;
  /** This instance also takes inbound webhooks AND can accept them (a usable
   *  secret is stored). They are accepted whatever the poller reports, so
   *  "polling is failing" must not read as "no data" — but this is never true
   *  for an instance that would reject every one of them. */
  readonly receives_webhooks?: boolean;
  /** What has actually arrived on that path. Absent when webhooks are off. */
  readonly webhook_receipt?: WebhookReceipt;
  /** Config problems that don't flip status (e.g. webhook secret not set →
   *  inbound webhooks are rejected). */
  readonly warnings?: readonly string[];
  /** Neutral, informational lines — a deliberate choice, not a fault (e.g.
   *  poll-only by choice). Rendered WITHOUT alert styling. */
  readonly notes?: readonly string[];
  /** The adapter can build "Open in <vendor>" links — the card offers the
   *  portal-link settings. */
  readonly supports_vendor_links?: boolean;
  /** Tenant lifecycle: tenants this instance created from its own traffic
   *  that still await a human's tag (Settings → Tenants). Absent = 0. */
  readonly auto_created_pending?: number;
  /** Events from this instance held in quarantine (could not be attributed
   *  to a tenant). Nothing is dropped; a human routes or discards them. */
  readonly quarantined?: number;
  /** The per-instance auto-create bound is reached: further new sites are
   *  held in quarantine until pending tenants are reviewed. */
  readonly autocreate_limited?: boolean;
  /** A new instance whose first import WAITS for the operator's customer
   *  mapping (RocketCyber): when it starts on its own (UTC ISO). It starts
   *  at once when a mapping is saved. Absent = not waiting. */
  readonly first_import_waiting_until?: string;
  /** The first import waits for the tenant mapping with NO deadline (NextDNS:
   *  nothing is imported until a profile is mapped — it never starts on its
   *  own). Absent = not waiting. */
  readonly waiting_for_tenant_mapping?: boolean;
  /** Per-profile integrations (NextDNS): profile counts, protection states,
   *  the vendor's rate limiting. Absent for other adapters. */
  readonly profiles?: ProfileSummary;
  /** Per-site integrations (UniFi): the fleet's sites, consoles / gateways
   *  offline, the vendor's rate limiting. Absent / null for other adapters. */
  readonly sites?: SiteSummary | null;
  /** Live feed health (from the feed's real-time state, not config status). */
  readonly live?: "up" | "degraded" | "down" | null;
  /** Resolved vendor dashboard URL for a quicklink (e.g. the Wazuh server). */
  readonly deep_link?: string | null;
  readonly deep_link_label?: string | null;
}

/**
 * Shape of one adapter row in the catalog popout. Mirrors the backend
 * `/api/v1/admin/adapters/catalog` `adapters[]` entries — the catalog
 * is metadata-only; no credential values are ever in this payload.
 */
export interface CatalogAdapter {
  readonly vendor_slug: string;
  readonly vendor_display_name: string;
  readonly vendor_logo_path: string;
  readonly vendor_category: string;
  readonly auth_model: string;
  readonly delivery_mode: string;
  readonly availability: string;
  readonly compliance_categories: readonly string[];
  readonly credential_shape: readonly CredentialField[];
  readonly tenant_mapping_shape?: TenantMappingShape | null;
  /** Guided-setup payload (steps + webhook URL + payload templates) or null. */
  readonly onboarding?: Onboarding | null;
  /** Inbound webhook URL for push/hybrid adapters (composed by the backend). */
  readonly webhook_url?: string | null;
}

/**
 * One category section in the catalog popout. The backend provides the
 * `display_label` so the UI doesn't have to title-case slugs.
 */
export interface CatalogCategoryGroup {
  readonly category: string;
  readonly display_label: string;
  readonly adapters: readonly CatalogAdapter[];
}

export interface CatalogResponse {
  readonly adapters: readonly CatalogAdapter[];
  readonly categories: readonly CatalogCategoryGroup[];
}

/**
 * The integration card's per-profile counts (NextDNS). `known` / `unmapped`
 * are null until the profile list has been read since the service started.
 */
export interface ProfileSummary {
  readonly known: number | null;
  readonly mapped: number;
  readonly ignored: number;
  readonly unmapped: number | null;
  readonly active: number;
  readonly pending: number;
  readonly lapsed: number;
  /** Mapped moments ago, first 24-hour read not done yet. */
  readonly checking: number;
  /** Mapped profiles NextDNS no longer shows to the key (HTTP 404). */
  readonly missing?: number;
  /** Profiles whose own polling has a problem (the others go on). */
  readonly problems?: number;
  /** Hours the hourly roll-ups are behind (the polling does not fit). */
  readonly rollup_lag_hours?: number;
  /** Recent hours read as a NextDNS-side analytics gap (at most 2 in a row;
   *  no lapse alerts for them). */
  readonly analytics_gaps?: number;
  /** A fleet-wide outage in progress: sites dark at once, of how many
   *  watched, and the (internal) tenant its ONE alert went to — null when
   *  there is no internal tenant to raise it in. */
  readonly fleet_outage_sites?: number;
  readonly fleet_outage_watched?: number;
  readonly fleet_outage_tenant?: string | null;
  /** NextDNS is rate limiting right now — calls wait; not a failure. */
  readonly throttled: boolean;
  readonly throttled_for_sec: number;
}

/** One NextDNS profile in the mapping panel
 *  (`GET /integrations/nextdns/{id}/profiles`). */
export interface NextDnsProfile {
  readonly profile_id: string;
  readonly name: string;
  /** Still in NextDNS's profile list. */
  readonly listed: boolean;
  readonly tenant_slug: string | null;
  readonly tenant_name: string | null;
  readonly tenant_status: string | null;
  readonly match_source: string | null;
  readonly ignored: boolean;
  readonly suggestion: {
    readonly tenant_slug: string;
    readonly tenant_name: string;
    readonly rule: "same-name" | "name-prefix";
    /** False: the name reads like a personal / test profile — offered on
     *  its row only, never by "Use N suggestions". Absent = true. */
    readonly bulk?: boolean;
  } | null;
  /** Protection as the poller last saw it (null = not polled). */
  readonly state: "new" | "pending" | "active" | "lapsed" | null;
  readonly state_since: string | null;
  readonly queries_24h: number | null;
  /** NextDNS no longer shows this mapped profile to the key (HTTP 404). */
  readonly missing?: boolean;
  /** The poller's current problem with this profile (operator text). */
  readonly problem?: string | null;
}

export interface NextDnsProfiles {
  readonly instance_id: number;
  /** False: no profile list since the service started — Reload lists them
   *  (ONE NextDNS call). */
  readonly discovered: boolean;
  readonly fetched_at: string | null;
  readonly profiles: readonly NextDnsProfile[];
  readonly counts: {
    readonly known: number | null;
    readonly mapped: number;
    readonly ignored: number;
    readonly unmapped: number | null;
    readonly active: number;
    readonly pending: number;
    readonly lapsed: number;
    readonly missing?: number;
  };
}

export interface NextDnsProfilesSave {
  readonly mappings: ReadonlyArray<{
    readonly profile_id: string;
    readonly tenant_slug: string;
    readonly match_source: "manual" | "auto-name";
  }>;
  readonly ignored: readonly string[];
}

/**
 * The integration card's per-site counts (UniFi). `known` / `unmapped` are
 * null until the fleet has been read since the service started.
 */
export interface SiteSummary {
  readonly known: number | null;
  readonly known_at?: string | null;
  readonly consoles: number;
  readonly consoles_offline: number;
  readonly mapped: number;
  readonly ignored: number;
  readonly unmapped: number | null;
  readonly gateways_offline: number;
  /** Mapped sites whose own polling has a problem (the others go on). */
  readonly problems: number;
  /** Mappings of the RETIRED local-controller adapter (a bare site id): never polled. */
  readonly legacy_mappings: number;
  readonly throttled: boolean;
  readonly throttled_for_sec: number;
  readonly calls_per_hour_planned?: number | null;
}

export interface UniFiWan {
  readonly wan: string;
  readonly external_ip: string | null;
  readonly isp: string | null;
  readonly asn: number | null;
  /** The same public address is another console's WAN (one bit, nothing more). */
  readonly shared_external: boolean;
}

/** One UniFi site in the mapping panel (`GET /integrations/unifi/{id}/sites`).
 *  Keyed "<hostId>/<siteId>": site ids collide across consoles. */
export interface UniFiSite {
  readonly scope: string;
  readonly host_id: string;
  readonly site_id: string;
  readonly name: string;
  readonly console_name: string;
  readonly location_text: string | null;
  readonly timezone: string | null;
  readonly wans: readonly UniFiWan[];
  readonly gateway_online: boolean | null;
  readonly host_connected: boolean | null;
  readonly listed: boolean;
  readonly tenant_slug: string | null;
  readonly tenant_name: string | null;
  readonly tenant_status: string | null;
  readonly match_source: string | null;
  readonly ignored: boolean;
  /** The ONE client with the same name — offered on its row only, never in bulk. */
  readonly suggestion: { readonly tenant_slug: string; readonly tenant_name: string; readonly rule: string } | null;
  readonly problem: string | null;
  readonly last_syslog_at: string | null;
  readonly clients: number | null;
}

export interface UniFiSites {
  readonly instance_id: number;
  readonly discovered: boolean;
  readonly fetched_at: string | null;
  readonly sites: readonly UniFiSite[];
  /** Mappings of the retired local-controller adapter: kept, never polled. */
  readonly legacy: ReadonlyArray<{
    readonly vendor_tenant_id: string;
    readonly tenant_slug: string;
    readonly tenant_name: string | null;
  }>;
  readonly counts: {
    readonly known: number | null;
    readonly mapped: number;
    readonly ignored: number;
    readonly unmapped: number | null;
    readonly gateways_offline: number;
    readonly problems: number;
  };
}

/** No match source: every mapping saved here is the operator's decision. */
export interface UniFiSitesSave {
  readonly mappings: ReadonlyArray<{ readonly scope: string; readonly tenant_slug: string }>;
  readonly ignored: readonly string[];
}
