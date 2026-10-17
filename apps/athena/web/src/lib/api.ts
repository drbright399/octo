/**
 * Bridge API client (front-end side).
 *
 * Today: stub against a `MOCK_API` target so the Settings/Integrations
 * UI can be tested without the backend wired. Real implementation will
 * point at `/api/v1/*` and use the same shapes.
 *
 * Auth: the backend sets an httpOnly session cookie at login; this
 * client never touches the cookie or any token. `credentials: "include"`
 * lets the browser attach the cookie automatically.
 *
 * Security:
 *   - Credential field VALUES are sent in the POST body once and never
 *     read back. Server returns metadata only (configured_at, status).
 *   - No localStorage / sessionStorage for credential material.
 *   - Errors surfaced as typed `ApiError`; the UI shows friendly text,
 *     never the raw response (which could leak server-side detail).
 */

import type {
  CredentialFieldKind,
  CatalogAdapter,
  CatalogCategoryGroup,
  CatalogResponse,
  GeneratedWebhookSecret,
  IntegrationDefinition,
  IntegrationInstance,
  WebhookReceipt,
} from "@/contracts/integration";
import {
  MOCK_INTEGRATIONS,
  MOCK_INTEGRATION_STATE,
} from "@/mock/integrations";
import type {
  CreateOperatorPayload,
  CreateOperatorResponse,
  MeResponse,
  OperatorListEntry,
  RoleName,
} from "@/contracts/operator";
import type {
  ApprovalMode,
  AttestedAction,
  BulkDiscardResponse,
  BulkUpdateItem,
  BulkUpdateResponse,
  ChangeRequest,
  ChangeRequestState,
  CreateTenantPayload,
  MergePreview,
  MergeResponse,
  OffboardResponse,
  PostReviewVerdict,
  PatchTenantPayload,
  QuarantineDetail,
  QuarantineListResponse,
  ReviewSummary,
  RouteResponse,
  RouteTarget,
  SignoffHistoryResponse,
  SignoffPayload,
  SignoffResult,
  Tenant,
  TenantListResponse,
} from "@/contracts/tenant";
import type { TiPulseResponse } from "@/contracts/indicator";
import type { DnsSummaryResponse } from "@/contracts/dns-summary";
import type { NoticeListResponse, OperatorNotice } from "@/contracts/notice";

export class ApiError extends Error {
  // `code` is the machine-readable error code from the API body ({code,
  // message,...}) — use it (not the human `message`) for control flow like
  // STEP_UP_REQUIRED detection. Optional + last so existing
  // `new ApiError(msg, status)` call sites are unaffected.
  constructor(message: string, readonly status: number, readonly code?: string) {
    super(message);
    this.name = "ApiError";
  }
}

const USE_MOCK = false;

async function delay(ms: number): Promise<void> {
  await new Promise((r) => setTimeout(r, ms));
}

export async function listIntegrations(): Promise<{
  definitions: readonly IntegrationDefinition[];
  instances: Readonly<Record<string, IntegrationInstance>>;
}> {
  if (USE_MOCK) {
    await delay(120);
    return { definitions: MOCK_INTEGRATIONS, instances: { ...MOCK_INTEGRATION_STATE } };
  }
  const res = await fetch("/api/v1/integrations", { credentials: "include" });
  if (!res.ok) throw new ApiError("Failed to load integrations", res.status);
  const body = (await res.json()) as {
    definitions: ReadonlyArray<{
      slug: string;
      name: string;
      category: string;
      description: string;
    }>;
    instances: Record<
      string,
      {
        slug: string;
        id?: number;
        status: string;
        status_detail: string | null;
        configured_at: string;
        last_test_at: string | null;
        last_contact_ok_at?: string | null;
        contact_failure_kind?: string | null;
        receives_webhooks?: boolean;
        webhook_receipt?: RawWebhookReceipt | null;
        warnings?: string[];
        notes?: string[];
        supports_vendor_links?: boolean;
        auto_created_pending?: number;
        quarantined?: number;
        autocreate_limited?: boolean;
        first_import_waiting_until?: string | null;
        waiting_for_tenant_mapping?: boolean;
        profiles?: import("@/contracts/integration").ProfileSummary | null;
        sites?: import("@/contracts/integration").SiteSummary | null;
      }
    >;
  };
  const definitions: IntegrationDefinition[] = body.definitions.map((d) => ({
    slug: d.slug,
    name: d.name,
    category: d.category,
    description: d.description,
    fields: [],
  }));
  const instances: Record<string, IntegrationInstance> = {};
  for (const [slug, inst] of Object.entries(body.instances)) {
    instances[slug] = {
      slug,
      // Needed to address the instance (Disable integration).
      ...(typeof inst.id === "number" ? { id: inst.id } : {}),
      status: normalizeStatus(inst.status),
      configured_at: inst.configured_at,
      ...(inst.status_detail ? { status_detail: inst.status_detail } : {}),
      ...(inst.last_test_at ? { last_test_at: inst.last_test_at } : {}),
      ...(inst.last_contact_ok_at ? { last_contact_ok_at: inst.last_contact_ok_at } : {}),
      ...(inst.contact_failure_kind ? { contact_failure_kind: inst.contact_failure_kind } : {}),
      ...(inst.receives_webhooks ? { receives_webhooks: true } : {}),
      ...webhookReceiptField(inst.webhook_receipt),
      ...(inst.warnings?.length ? { warnings: inst.warnings } : {}),
      ...(inst.notes?.length ? { notes: inst.notes } : {}),
      ...(inst.supports_vendor_links ? { supports_vendor_links: true } : {}),
      // Lifecycle counters: carried only when positive so older backends
      // (and quiet instances) render exactly as before.
      ...(typeof inst.auto_created_pending === "number" && inst.auto_created_pending > 0
        ? { auto_created_pending: inst.auto_created_pending }
        : {}),
      ...(typeof inst.quarantined === "number" && inst.quarantined > 0
        ? { quarantined: inst.quarantined }
        : {}),
      ...(inst.autocreate_limited ? { autocreate_limited: true } : {}),
      ...(inst.first_import_waiting_until
        ? { first_import_waiting_until: inst.first_import_waiting_until }
        : {}),
      ...(inst.waiting_for_tenant_mapping ? { waiting_for_tenant_mapping: true } : {}),
      ...(inst.profiles ? { profiles: inst.profiles } : {}),
      ...(inst.sites ? { sites: inst.sites } : {}),
    };
  }
  return { definitions, instances };
}

export interface DisableIntegrationResult {
  readonly instanceId: number;
  readonly alreadyDisabled: boolean;
  /** Tenant mappings belong to the instance — a replacement starts with none. */
  readonly tenantMappingsNotCarriedOver: number;
  /** The backend's plain-language outcome, shown to the operator as-is. */
  readonly message: string;
}

/**
 * Disable an integration instance (admin+). Credentials are create-only, so
 * this is step one of every "replace" — a lost webhook token, a rotated API
 * key, turning webhooks on later: Disable, then Add integration again.
 * `reason` is required and lands in the audit chain; never put a secret in it.
 * On failure the server's own message is thrown so the UI can show it.
 */
export async function disableIntegration(
  instanceId: number,
  reason: string,
): Promise<DisableIntegrationResult> {
  const res = await fetch(
    `/api/v1/admin/adapters/instances/${encodeURIComponent(String(instanceId))}/disable`,
    {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const b = body as { message?: string; code?: string };
    throw new ApiError(b.message || "Disable failed", res.status, b.code);
  }
  const body = (await res.json()) as {
    instance_id: number;
    already_disabled?: boolean;
    tenant_mappings_not_carried_over?: number;
    message?: string;
  };
  return {
    instanceId: body.instance_id,
    alreadyDisabled: body.already_disabled === true,
    tenantMappingsNotCarriedOver: body.tenant_mappings_not_carried_over ?? 0,
    message: body.message ?? "Integration disabled.",
  };
}

export interface CreateIntegrationOptions {
  /**
   * The operator's answer to "real-time webhooks?". true + a blank
   * platform-defined token → the backend generates one and returns it once.
   * false → poll-only. Omit for vendors with no platform-defined token
   * (legacy semantics: a blank secret means no inbound webhook).
   */
  readonly enableWebhook?: boolean;
}

export interface CreateIntegrationResult {
  readonly instance: IntegrationInstance;
  /** Present ONLY when the platform generated the token. Shown once. */
  readonly generatedWebhookSecret: GeneratedWebhookSecret | null;
}

/** Create without the webhook choice — instance metadata only. Callers that
 *  can show a generated secret use `createIntegration` instead. */
export async function configureIntegration(
  slug: string,
  values: Readonly<Record<string, string>>,
): Promise<IntegrationInstance> {
  return (await createIntegration(slug, values)).instance;
}

export async function createIntegration(
  slug: string,
  values: Readonly<Record<string, string>>,
  options: CreateIntegrationOptions = {},
): Promise<CreateIntegrationResult> {
  if (USE_MOCK) {
    await delay(450);
    void values;
    return {
      instance: {
        slug,
        status: "connected",
        status_detail: "saved (mock)",
        configured_at: new Date().toISOString(),
      },
      generatedWebhookSecret: null,
    };
  }
  const res = await fetch(
    `/api/v1/admin/adapters/${encodeURIComponent(slug)}/instances`,
    {
      method: "POST",
      credentials: "include",
      // The response may carry a one-time secret — keep it out of any cache.
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credentials: values,
        ...(options.enableWebhook === undefined
          ? {}
          : { enable_webhook: options.enableWebhook }),
      }),
    },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Save failed",
      res.status,
    );
  }
  // Backend returns `{instance, smoke_test_message, generated_webhook_secret}`;
  // the front-end's IntegrationInstance shape only needs the metadata fields.
  const body = (await res.json()) as {
    instance: {
      id: number;
      vendor_slug: string;
      status: string;
      status_detail: string | null;
      configured_at: string;
      last_test_at: string | null;
      last_contact_ok_at?: string | null;
      contact_failure_kind?: string | null;
      receives_webhooks?: boolean;
      webhook_receipt?: RawWebhookReceipt | null;
      warnings?: string[];
      notes?: string[];
    };
    generated_webhook_secret?: GeneratedWebhookSecret | null;
  };
  const i = body.instance;
  const g = body.generated_webhook_secret ?? null;
  return {
    instance: {
      slug: i.vendor_slug,
      id: i.id,
      status: normalizeStatus(i.status),
      configured_at: i.configured_at,
      ...(i.status_detail ? { status_detail: i.status_detail } : {}),
      ...(i.last_test_at ? { last_test_at: i.last_test_at } : {}),
      ...(i.last_contact_ok_at ? { last_contact_ok_at: i.last_contact_ok_at } : {}),
      ...(i.contact_failure_kind ? { contact_failure_kind: i.contact_failure_kind } : {}),
      ...(i.receives_webhooks ? { receives_webhooks: true } : {}),
      ...webhookReceiptField(i.webhook_receipt),
      ...(i.warnings?.length ? { warnings: i.warnings } : {}),
      ...(i.notes?.length ? { notes: i.notes } : {}),
    },
    generatedWebhookSecret: g
      ? {
          credential_field: g.credential_field,
          ...(g.credential_label ? { credential_label: g.credential_label } : {}),
          header_name: g.header_name,
          header_value: g.header_value,
          webhook_url: g.webhook_url ?? null,
          webhook_url_problem: g.webhook_url_problem ?? null,
        }
      : null,
  };
}

// --- Client provisioning (create; listClients lives further below) ---

export async function createClient(
  slug: string,
  display_name: string,
): Promise<ClientEntry> {
  const res = await fetch("/api/v1/admin/clients", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ slug, display_name }),
  });
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new ApiError((b as { message?: string }).message || "Create client failed", res.status);
  }
  return (await res.json()) as ClientEntry;
}

// --- Per-instance tenant mappings (vendor tenant id → OCTO client slug) ---

export async function getTenantMappings(
  vendorSlug: string,
  instanceId: number,
): Promise<readonly import("@/contracts/integration").TenantMappingEntry[]> {
  const res = await fetch(
    `/api/v1/integrations/${encodeURIComponent(vendorSlug)}/${instanceId}/mappings/tenants`,
    { credentials: "include" },
  );
  if (!res.ok) throw new ApiError("Failed to load mappings", res.status);
  const body = (await res.json()) as {
    mappings: Array<import("@/contracts/integration").TenantMappingEntry>;
  };
  return body.mappings;
}

export async function setTenantMappings(
  vendorSlug: string,
  instanceId: number,
  mappings: readonly import("@/contracts/integration").TenantMappingEntry[],
): Promise<readonly import("@/contracts/integration").TenantMappingEntry[]> {
  const res = await fetch(
    `/api/v1/integrations/${encodeURIComponent(vendorSlug)}/${instanceId}/mappings/tenants`,
    {
      method: "PUT",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mappings }),
    },
  );
  if (!res.ok) {
    // The server says WHICH mapping it refused and why — show that.
    const b = await res.json().catch(() => ({}));
    throw new ApiError(
      (b as { message?: string }).message || "Failed to save mappings",
      res.status,
      (b as { code?: string }).code,
    );
  }
  const body = (await res.json()) as {
    mappings: Array<import("@/contracts/integration").TenantMappingEntry>;
  };
  return body.mappings;
}

/**
 * "Open in <vendor>" link settings for a saved instance (admin+). Non-secret:
 * the vendor portal's base URL (normally derived server-side from the API
 * URL) and the alert path template. Device pages have no template — they are
 * looked up at the vendor on click. The server validates every field and
 * answers 422 with an operator-readable reason.
 */
export interface VendorLinkSettings {
  vendor_slug: string;
  instance_id: number;
  portal_name: string;
  allowed_domain: string;
  placeholders: string[];
  overrides: Partial<Record<VendorLinkSettingField, string>>;
  portal_base_url: string | null;
  alert_path_template: string;
  derived_portal_base_url: string | null;
  default_alert_path_template: string;
  paths_verified: boolean;
  sample_alert_url: string | null;
  /** Device pages are looked up at the vendor on click (no template). */
  device_links_resolved: boolean;
  links_enabled: boolean;
  problem: string | null;
}

export type VendorLinkSettingField = "portal_base_url" | "alert_path_template";

export async function fetchVendorLinkSettings(
  vendorSlug: string,
  instanceId: number,
): Promise<VendorLinkSettings> {
  const res = await fetch(
    `/api/v1/integrations/${encodeURIComponent(vendorSlug)}/${instanceId}/vendor-links`,
    { credentials: "include" },
  );
  if (!res.ok) throw new ApiError("Failed to load portal link settings", res.status);
  return (await res.json()) as VendorLinkSettings;
}

/** Blank / omitted field = use the default. */
export async function saveVendorLinkSettings(
  vendorSlug: string,
  instanceId: number,
  settings: Partial<Record<VendorLinkSettingField, string>>,
): Promise<VendorLinkSettings> {
  const res = await fetch(
    `/api/v1/integrations/${encodeURIComponent(vendorSlug)}/${instanceId}/vendor-links`,
    {
      method: "PUT",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(settings),
    },
  );
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new ApiError(
      (b as { message?: string }).message || "Failed to save portal link settings",
      res.status,
      (b as { code?: string }).code,
    );
  }
  return (await res.json()) as VendorLinkSettings;
}

/**
 * What the VENDOR calls its tenants for a saved instance (Datto sites, …), for
 * the mapping picker. On demand only; the server caches briefly, `refresh`
 * (the Reload button) asks the vendor again — except within a few seconds of
 * a FAILURE, which the server replays without hammering the vendor. Rejects with the server's
 * operator-actionable message when the vendor refuses or cannot be reached —
 * callers must SHOW it, never fall back to silence.
 */
/** NextDNS mapping panel: every profile with its mapping, ignore mark,
 *  suggestion and protection state. Local state only — never a NextDNS call
 *  (the list comes from the last discovery; `listVendorTenants` refreshes it). */
export async function getNextDnsProfiles(
  instanceId: number,
): Promise<import("@/contracts/integration").NextDnsProfiles> {
  const res = await fetch(`/api/v1/integrations/nextdns/${instanceId}/profiles`, {
    credentials: "include",
    cache: "no-store",
  });
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new ApiError(
      (b as { message?: string }).message || "Failed to load the NextDNS profiles",
      res.status,
      (b as { code?: string }).code,
    );
  }
  return (await res.json()) as import("@/contracts/integration").NextDnsProfiles;
}

/** Save the NextDNS profile mappings AND the ignore list (one audited PUT). */
export async function saveNextDnsProfiles(
  instanceId: number,
  body: import("@/contracts/integration").NextDnsProfilesSave,
): Promise<import("@/contracts/integration").NextDnsProfiles> {
  const res = await fetch(`/api/v1/integrations/nextdns/${instanceId}/profiles`, {
    method: "PUT",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    // The server says which profile it refused and why — show that.
    const b = await res.json().catch(() => ({}));
    throw new ApiError(
      (b as { message?: string }).message || "Failed to save the profile mapping",
      res.status,
      (b as { code?: string }).code,
    );
  }
  return (await res.json()) as import("@/contracts/integration").NextDnsProfiles;
}

/** UniFi mapping panel: every site of every console with its location,
 *  WAN, mapping, ignore mark and a same-name suggestion. Local state only —
 *  never a UniFi call (`listVendorTenants` refreshes the list: two calls). */
export async function getUniFiSites(
  instanceId: number,
): Promise<import("@/contracts/integration").UniFiSites> {
  const res = await fetch(`/api/v1/integrations/unifi/${instanceId}/sites`, {
    credentials: "include",
    cache: "no-store",
  });
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new ApiError(
      (b as { message?: string }).message || "Failed to load the UniFi sites",
      res.status,
      (b as { code?: string }).code,
    );
  }
  return (await res.json()) as import("@/contracts/integration").UniFiSites;
}

/** Save the UniFi site mappings AND the ignore list (one audited PUT). */
export async function saveUniFiSites(
  instanceId: number,
  body: import("@/contracts/integration").UniFiSitesSave,
): Promise<import("@/contracts/integration").UniFiSites> {
  const res = await fetch(`/api/v1/integrations/unifi/${instanceId}/sites`, {
    method: "PUT",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new ApiError(
      (b as { message?: string }).message || "Failed to save the site mapping",
      res.status,
      (b as { code?: string }).code,
    );
  }
  return (await res.json()) as import("@/contracts/integration").UniFiSites;
}

export async function listVendorTenants(
  instanceId: number,
  opts: { readonly refresh?: boolean } = {},
): Promise<import("@/contracts/integration").VendorTenantDiscovery> {
  const res = await fetch(
    `/api/v1/admin/adapters/instances/${instanceId}/vendor-tenants${
      opts.refresh ? "?refresh=true" : ""
    }`,
    // POST: a cache miss decrypts credentials and contacts the vendor. The
    // session cookie is SameSite=Lax, which is never sent on a cross-site
    // POST (it IS on a cross-site top-level GET navigation).
    { method: "POST", credentials: "include", cache: "no-store" },
  );
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new ApiError(
      (b as { message?: string }).message ||
        `The vendor's tenant list could not be loaded (HTTP ${res.status}).`,
      res.status,
      (b as { code?: string }).code,
    );
  }
  const body = (await res.json()) as Partial<
    import("@/contracts/integration").VendorTenantDiscovery
  >;
  return {
    supported: body.supported === true,
    tenants: Array.isArray(body.tenants)
      ? body.tenants.filter(
          (t) => typeof t?.id === "string" && t.id !== "" && typeof t.label === "string",
        )
      : [],
    truncated: body.truncated === true,
    fetched_at: body.fetched_at ?? null,
    tenant_mapping_shape: body.tenant_mapping_shape ?? null,
  };
}

/** The backend's `webhook_receipt`, as sent. Older backends omit it. */
type RawWebhookReceipt = Partial<WebhookReceipt>;

/** Carried only for an instance whose webhooks are switched on: a poll-only
 *  or webhook-less integration has nothing to say here, so its card says
 *  nothing. Missing fields take the "nothing observed" value, never a guess. */
function webhookReceiptField(
  raw: RawWebhookReceipt | null | undefined,
): { webhook_receipt?: WebhookReceipt } {
  if (!raw?.enabled) return {};
  return {
    webhook_receipt: {
      enabled: true,
      usable: raw.usable === true,
      last_accepted_at: raw.last_accepted_at ?? null,
      last_rejected_at: raw.last_rejected_at ?? null,
      last_reject_reason: raw.last_reject_reason ?? null,
      ever_reached: raw.ever_reached === true,
      accepted_since_start: raw.accepted_since_start ?? 0,
      rejected_since_start: raw.rejected_since_start ?? 0,
      rejected_recent: raw.rejected_recent ?? 0,
      recent_rejections: raw.recent_rejections ?? [],
      last_reject_detail: raw.last_reject_detail ?? null,
      guidance: raw.guidance ?? [],
    },
  };
}

function normalizeStatus(s: string): IntegrationInstance["status"] {
  // Backend uses `starting / running / disabled / error`. Map to the
  // front-end's `connected / disconnected / disabled / error` vocabulary.
  // `error` includes a RUNNING instance whose last vendor contact failed.
  if (s === "running") return "connected";
  if (s === "disabled") return "disabled";
  if (s === "error") return "error";
  return "disconnected";
}

/**
 * Fetch the discovered adapter catalog. Returns one entry per registered
 * adapter class + a sibling `categories` array bucketed by `vendor_category`.
 *
 * Backend route: GET /api/v1/admin/adapters/catalog (admin-tier gated).
 * Mock derives categories from the MOCK_INTEGRATIONS list so the UI can
 * develop before the backend is reachable.
 */
export async function fetchAdapterCatalog(): Promise<CatalogResponse> {
  if (USE_MOCK) {
    await delay(120);
    return buildMockCatalog();
  }
  const res = await fetch("/api/v1/admin/adapters/catalog", {
    credentials: "include",
  });
  if (!res.ok) throw new ApiError("Failed to load catalog", res.status);
  const raw = (await res.json()) as {
    adapters: Array<{
      vendor_slug: string;
      vendor_display_name: string;
      vendor_logo_path: string;
      vendor_category: string;
      auth_model: string;
      delivery_mode: string;
      availability: string;
      compliance_categories: string[];
      credential_shape: Array<{
        name: string;
        label: string;
        kind: string;
        description?: string | null;
        required?: boolean;
        choices?: string[] | null;
        placeholder?: string | null;
        pattern?: string | null;
        show_when?: Record<string, string[]> | null;
        required_when?: Record<string, string[]> | null;
        secret_origin?: string | null;
        webhook_header?: string | null;
      }>;
      tenant_mapping_shape?:
        | import("@/contracts/integration").TenantMappingShape
        | null;
      onboarding?: {
        summary: string;
        webhook_url: string | null;
        webhook_url_problem?: string | null;
        steps: Array<{
          title: string;
          body: string;
          copy_value?: string | null;
          code_sample?: string | null;
        }>;
      } | null;
      webhook_url?: string | null;
    }>;
    categories: Array<{
      category: string;
      display_label: string;
      adapters: Array<{ vendor_slug: string }>;
    }>;
  };

  const mapAdapter = (a: (typeof raw.adapters)[number]) => ({
    vendor_slug: a.vendor_slug,
    vendor_display_name: a.vendor_display_name,
    vendor_logo_path: a.vendor_logo_path,
    vendor_category: a.vendor_category,
    auth_model: a.auth_model,
    delivery_mode: a.delivery_mode,
    availability: a.availability,
    compliance_categories: a.compliance_categories,
    credential_shape: a.credential_shape.map((f) => ({
      name: f.name,
      label: f.label,
      kind: mapCredentialKind(f.kind),
      required: f.required ?? true,
      ...(f.description ? { description: f.description } : {}),
      ...(f.placeholder ? { placeholder: f.placeholder } : {}),
      ...(f.pattern ? { pattern: f.pattern } : {}),
      ...(f.choices ? { choices: f.choices } : {}),
      ...(f.show_when ? { show_when: f.show_when } : {}),
      ...(f.required_when ? { required_when: f.required_when } : {}),
      ...(f.secret_origin === "platform"
        ? { secret_origin: "platform" as const }
        : f.secret_origin === "vendor"
          ? { secret_origin: "vendor" as const }
          : {}),
      ...(f.webhook_header ? { webhook_header: f.webhook_header } : {}),
    })),
    ...(a.tenant_mapping_shape ? { tenant_mapping_shape: a.tenant_mapping_shape } : {}),
    ...(a.onboarding ? { onboarding: a.onboarding } : {}),
    ...(a.webhook_url ? { webhook_url: a.webhook_url } : {}),
  });

  const adapters = raw.adapters.map(mapAdapter);
  // The /catalog response's `categories[].adapters[]` carries the same
  // adapter rows already in `adapters[]`. Re-look-up by slug so the
  // mapped shape stays consistent between the two arrays.
  const bySlug = new Map(adapters.map((a) => [a.vendor_slug, a]));
  const categories = raw.categories.map((g) => ({
    category: g.category,
    display_label: g.display_label,
    adapters: g.adapters
      .map((a) => bySlug.get(a.vendor_slug))
      .filter((a): a is (typeof adapters)[number] => a !== undefined),
  }));
  return { adapters, categories };
}

function mapCredentialKind(backendKind: string): CredentialFieldKind {
  switch (backendKind) {
    case "password":
    case "secret": // legacy alias
      return "password";
    case "enum":
      return "enum";
    case "url":
      return "url";
    case "webhook-url-out":
      return "webhook-url-out";
    case "text":
    case "string": // legacy alias
    case "oauth-flow":
    case "cert-upload":
    default:
      return "text";
  }
}

function buildMockCatalog(): CatalogResponse {
  // Derive a CatalogAdapter from each mock IntegrationDefinition, using
  // the definition's category as vendor_category so the popout has data
  // to bucket. Order is stable by display name for predictable rendering.
  const adapters: CatalogAdapter[] = [...MOCK_INTEGRATIONS]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((def) => ({
      vendor_slug: def.slug,
      vendor_display_name: def.name,
      vendor_logo_path: "",
      vendor_category: def.category.toLowerCase().replace(/\s*\/\s*/g, "-").replace(/\s+/g, "-"),
      auth_model: "api-key",
      delivery_mode: "poll",
      availability: "available",
      compliance_categories: [],
      credential_shape: def.fields,
    }));

  const buckets = new Map<string, CatalogAdapter[]>();
  for (const a of adapters) {
    const list = buckets.get(a.vendor_category) ?? [];
    list.push(a);
    buckets.set(a.vendor_category, list);
  }
  const categories: CatalogCategoryGroup[] = [...buckets.entries()]
    .map(([slug, items]) => ({
      category: slug,
      display_label: catalogCategoryLabel(slug),
      adapters: items,
    }))
    .sort((a, b) => a.display_label.localeCompare(b.display_label));

  return { adapters, categories };
}

function catalogCategoryLabel(slug: string): string {
  switch (slug) {
    case "siem":
      return "SIEM";
    case "rmm":
      return "RMM";
    case "soc":
      return "Managed SOC";
    case "mdr":
      return "MDR";
    case "network":
      return "Network";
    case "edr":
      return "EDR";
    case "edr-siem":
      return "EDR / SIEM";
    case "ticketing":
      return "Ticketing";
    case "asset-mgmt":
      return "Asset Management";
    case "other":
      return "Other";
    default:
      return slug
        .split("-")
        .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
        .join(" ");
  }
}

export async function testIntegration(
  slug: string,
  credentials?: Readonly<Record<string, string>>,
): Promise<{ ok: boolean; detail: string }> {
  if (USE_MOCK) {
    await delay(800);
    if (slug === "rocketcyber") {
      return { ok: false, detail: "401 unauthorized — check API key" };
    }
    return { ok: true, detail: "round-trip OK · 142ms" };
  }
  // The smoke-test endpoint validates candidate credentials WITHOUT
  // persisting them. The reconfigure-existing-instance path (no creds at
  // hand) is a future endpoint (`POST /admin/adapters/instances/{id}/test`)
  // that decrypts the persisted creds — for now we require creds.
  const res = await fetch(
    `/api/v1/admin/adapters/${encodeURIComponent(slug)}/smoke-test`,
    {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credentials: credentials ?? {} }),
    },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Test failed",
      res.status,
    );
  }
  const body = (await res.json()) as { ok: boolean; message: string };
  return { ok: body.ok, detail: body.message };
}

// ---------------------------------------------------------------------------
// Auth + me
//
// `me` is the canonical "who am I" endpoint. Returns the caller's identity
// + roles. UI uses the returned roles list to gate visibility (server gates
// auth too — never trust the client).
// ---------------------------------------------------------------------------

export async function getMe(): Promise<MeResponse | null> {
  const res = await fetch("/api/v1/auth/me", { credentials: "include" });
  if (res.status === 401 || res.status === 403) return null;
  if (!res.ok) throw new ApiError("Failed to load identity", res.status);
  return res.json() as Promise<MeResponse>;
}

// ---------------------------------------------------------------------------
// Self-service account management — endpoints that read/mutate the
// signed-in operator's own auth state. Distinct from the admin-side
// operator-management endpoints below (those act on OTHER operators).
// ---------------------------------------------------------------------------

export interface SessionEntry {
  id: string;
  issued_at: string;
  last_active_at: string;
  expires_at: string;
  auth_method: string;
  ip_address: string | null;
  user_agent: string | null;
  is_current: boolean;
}

export async function listMySessions(): Promise<SessionEntry[]> {
  const res = await fetch("/api/v1/auth/sessions", {
    credentials: "include",
  });
  if (!res.ok) throw new ApiError("Failed to load sessions", res.status);
  const body = (await res.json()) as { sessions: SessionEntry[] };
  return body.sessions;
}

export async function revokeMySession(sessionIdPrefix: string): Promise<void> {
  const res = await fetch(
    `/api/v1/auth/sessions/${encodeURIComponent(sessionIdPrefix)}`,
    { method: "DELETE", credentials: "include" },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Revoke failed",
      res.status,
    );
  }
}

export async function revokeMyOtherSessions(): Promise<number> {
  const res = await fetch("/api/v1/auth/sessions/revoke-others", {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Sign-out-everywhere failed",
      res.status,
    );
  }
  const body = (await res.json()) as { revoked_count: number };
  return body.revoked_count;
}

export async function changeMyPassword(
  currentPassword: string | null,
  newPassword: string,
): Promise<void> {
  const payload: { new_password: string; current_password?: string } = {
    new_password: newPassword,
  };
  if (currentPassword !== null) payload.current_password = currentPassword;
  const res = await fetch("/api/v1/auth/password/change", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Change password failed",
      res.status,
    );
  }
}

export interface TotpEnrollBeginResponse {
  pending_token: string;
  secret_b32: string;
  otpauth_uri: string;
}

export async function totpEnrollBegin(): Promise<TotpEnrollBeginResponse> {
  const res = await fetch("/api/v1/auth/totp/enroll/begin", {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "TOTP enrollment failed",
      res.status,
    );
  }
  return (await res.json()) as TotpEnrollBeginResponse;
}

export async function totpEnrollComplete(
  pendingToken: string,
  totpCode: string,
): Promise<string[]> {
  const res = await fetch("/api/v1/auth/totp/enroll/complete", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pending_token: pendingToken, totp_code: totpCode }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "TOTP verification failed",
      res.status,
    );
  }
  const body = (await res.json()) as { backup_codes: string[] };
  return body.backup_codes;
}

export async function logoutCurrentSession(): Promise<void> {
  await fetch("/api/v1/auth/logout", {
    method: "POST",
    credentials: "include",
  });
}

export interface ProfileUpdateResult {
  operator_id: number;
  display_name: string | null;
  email: string;
}

/**
 * Update display_name and/or email on the caller's own operator row.
 * `currentPassword` is REQUIRED when changing email (server enforces);
 * leave null when only updating display_name.
 */
export async function updateMyProfile(args: {
  displayName?: string | null;
  email?: string;
  currentPassword?: string;
}): Promise<ProfileUpdateResult> {
  const payload: {
    display_name?: string | null;
    email?: string;
    current_password?: string;
  } = {};
  if (args.displayName !== undefined) payload.display_name = args.displayName;
  if (args.email !== undefined) payload.email = args.email;
  if (args.currentPassword !== undefined)
    payload.current_password = args.currentPassword;
  const res = await fetch("/api/v1/auth/me/profile", {
    method: "PATCH",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Profile update failed",
      res.status,
    );
  }
  return (await res.json()) as ProfileUpdateResult;
}

/**
 * Rotate the operator's backup-code set without touching their TOTP
 * secret. Requires current_password proof. Returns the fresh codes —
 * shown ONCE.
 */
export async function regenerateBackupCodes(
  currentPassword: string,
): Promise<string[]> {
  const res = await fetch("/api/v1/auth/backup-codes/regenerate", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ current_password: currentPassword }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Backup-code regen failed",
      res.status,
    );
  }
  const body = (await res.json()) as { backup_codes: string[] };
  return body.backup_codes;
}

// ---------------------------------------------------------------------------
// Operator management (admin tier)
//
// All endpoints below require the caller to hold at least the `admin` role.
// Tier rules also enforced on each endpoint:
//   - admin can manage operators with role ≤ admin
//   - super_admin can manage anything
// ---------------------------------------------------------------------------

export async function listOperators(): Promise<OperatorListEntry[]> {
  const res = await fetch("/api/v1/admin/operators", {
    credentials: "include",
  });
  if (!res.ok) throw new ApiError("Failed to load operators", res.status);
  const body = (await res.json()) as { operators: OperatorListEntry[] };
  return body.operators;
}

export async function createOperator(
  payload: CreateOperatorPayload,
): Promise<CreateOperatorResponse> {
  const res = await fetch("/api/v1/admin/operators", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Create failed",
      res.status,
    );
  }
  return res.json() as Promise<CreateOperatorResponse>;
}

export async function disableOperator(
  operatorId: number,
  reason?: string,
): Promise<void> {
  const res = await fetch(
    `/api/v1/admin/operators/${operatorId}/disable`,
    {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: reason ?? "" }),
    },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Disable failed",
      res.status,
    );
  }
}

// Remove an operator. The server DELETES a never-used account and RETIRES one
// with history (access revoked, username + email freed, hidden from the list,
// row kept so the audit trail still resolves). Returns which one happened.
export async function removeOperator(
  operatorId: number,
  reason: string,
): Promise<"deleted" | "retired" | "already-removed"> {
  const res = await fetch(`/api/v1/admin/operators/${operatorId}/remove`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiError(
      (body as { message?: string }).message || "Remove failed",
      res.status,
    );
  }
  return (body as { state: "deleted" | "retired" | "already-removed" }).state;
}

// Change an operator's email. Needed because a DISABLED account keeps its
// (unique) email and cannot sign in to change it itself.
export async function updateOperatorEmail(
  operatorId: number,
  email: string,
): Promise<void> {
  const res = await fetch(`/api/v1/admin/operators/${operatorId}/email`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Email change failed",
      res.status,
    );
  }
}

export async function enableOperator(operatorId: number): Promise<void> {
  const res = await fetch(
    `/api/v1/admin/operators/${operatorId}/enable`,
    { method: "POST", credentials: "include" },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Enable failed",
      res.status,
    );
  }
}

export async function grantRole(
  operatorId: number,
  role: RoleName,
  scopeSlugs: string[] = ["*"],
): Promise<void> {
  const res = await fetch(
    `/api/v1/admin/operators/${operatorId}/role/grant`,
    {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role, scope_slugs: scopeSlugs }),
    },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Grant failed",
      res.status,
    );
  }
}

// ---------------------------------------------------------------------------
// Clients (tenants the bundle manages)
// ---------------------------------------------------------------------------

export interface ClientEntry {
  slug: string;
  display_name: string;
  status: string;
  /** Still the vendor-named auto-create placeholder (name, or the slug made
   *  from it): the server refuses to scope a viewer to it. Absent = false. */
  placeholder_name?: boolean;
  placeholder_slug?: boolean;
}

export async function listClients(): Promise<ClientEntry[]> {
  const res = await fetch("/api/v1/admin/clients", {
    credentials: "include",
  });
  if (!res.ok) throw new ApiError("Failed to load clients", res.status);
  const body = (await res.json()) as { clients: ClientEntry[] };
  return body.clients;
}

export async function revokeRole(
  operatorId: number,
  role: RoleName,
): Promise<void> {
  const res = await fetch(
    `/api/v1/admin/operators/${operatorId}/role/revoke`,
    {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role }),
    },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Revoke failed",
      res.status,
    );
  }
}

/**
 * Admin-driven password reset. Generates a one-time magic-link URL the
 * caller hands off to the target operator out-of-band. Side-effects on
 * the target server-side: password cleared, must_change_password set,
 * all active sessions revoked. 10-minute TTL on the link.
 */
export interface ResetPasswordResult {
  operator_id: number;
  username: string;
  temporary_password_set?: boolean;
  magic_link_url?: string;
  magic_link_expires_at?: string;
}

// ---------------------------------------------------------------------------
// Dashboard data — real OCTO event aggregates surfaced to V3 widgets.
// First wire-up of the bedrock data path to a UI surface (Task #15).
// ---------------------------------------------------------------------------

export interface ThroughputPoint {
  t: string; // ISO-8601 UTC, bucket start
  v: number; // event count
}

export interface ThroughputResponse {
  points: ThroughputPoint[];
  window_minutes: number;
  window_hours: number; // back-compat — 0 when sub-hour
  bucket_minutes: number;
  scope_slugs: string[];
}

// ---------------------------------------------------------------------------
// Client DB search — step-up auth + events + indicators + payload fetch.
// All endpoints under /api/v1/search/* gated by step-up clearance with
// sliding TTL + IP-binding (see the internal vendor deep-link pattern note,
// the Athena/OCTO audit v1 of 2026-04-30, design doc 2026-05-12).
// ---------------------------------------------------------------------------

export interface StepUpStatus {
  elevated: boolean;
  granted_at: string | null;
  expires_at: string | null;
  absolute_expires_at: string | null;
  ttl_minutes: number;
  absolute_cap_hours: number;
}

export async function fetchStepUpStatus(): Promise<StepUpStatus> {
  const res = await fetch("/api/v1/search/status", { credentials: "include" });
  if (!res.ok) throw new ApiError("Failed to load step-up status", res.status);
  return (await res.json()) as StepUpStatus;
}

export async function elevateStepUp(
  currentPassword: string, totpCode: string,
): Promise<StepUpStatus> {
  const res = await fetch("/api/v1/search/elevate", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ current_password: currentPassword, totp_code: totpCode }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Re-authentication failed",
      res.status,
    );
  }
  return (await res.json()) as StepUpStatus;
}

export interface SearchEventRow {
  client_slug: string;
  event_id: number;
  received_at: string;
  event_type: string;
  severity: string;
  source: string;
  source_host: string | null;
  summary: string;
  agent_note_count: number;
}

export interface AgentNote {
  id: number;
  agent_id: string;       // 'octo' | 'athena' — per the 2026-05-14 agent-naming decision
  note_text: string;
  confidence: number;
  created_at: string;
  updated_at: string | null;
}

export interface AgentPatternLink {
  id: number;
  to_kind: string;        // 'event' | 'ticket' | 'indicator'
  to_id: number;
  relation: string;       // 'same_ioc' | 'same_host' | 'same_ttp' | 'temporal' | 'semantic'
  strength: number;
  rationale: string;
  created_by_agent: string;
  created_at: string;
}

export interface SearchEventsResponse {
  results: SearchEventRow[];
  total_estimate: number;
  truncated: boolean;
  page_size: number;
  offset: number;
  tenants_searched: string[];
  step_up_expires_at: string | null;
}

export interface SearchEventsArgs {
  tenants?: string[];
  query?: string;
  event_types?: string[];
  severities?: string[];
  time_from?: string;
  time_to?: string;
  source_host?: string;
  limit?: number;
  offset?: number;
}

export async function searchEvents(args: SearchEventsArgs): Promise<SearchEventsResponse> {
  const res = await fetch("/api/v1/search/events", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(args),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { code?: string; message?: string }).code
        || (body as { message?: string }).message
        || "Search failed",
      res.status,
    );
  }
  return (await res.json()) as SearchEventsResponse;
}

export interface EventPayloadResponse {
  client_slug: string;
  event_id: number;
  received_at: string;
  source: string;
  source_host: string | null;
  event_type: string;
  severity: string;
  summary: string;
  payload: Record<string, unknown>;
  payload_sha256: string;
  relay_status: string;
  relay_attempts: number;
  relayed_at: string | null;
  step_up_expires_at: string | null;
  vendor_deep_link: string | null;
  vendor_display_name: string | null;
  agent_notes: AgentNote[];
  agent_pattern_links: AgentPatternLink[];
  derived_ticket_id: number | null;
  derived_ticket_title: string | null;
}

export async function fetchEventPayload(
  clientSlug: string, eventId: number,
): Promise<EventPayloadResponse> {
  const res = await fetch(
    `/api/v1/search/event/${encodeURIComponent(clientSlug)}/${eventId}`,
    { credentials: "include" },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { code?: string; message?: string }).code
        || (body as { message?: string }).message
        || "Payload fetch failed",
      res.status,
    );
  }
  return (await res.json()) as EventPayloadResponse;
}

// ---------------------------------------------------------------------------
// Search export (Task #116 — audit-grade CSV + branded PDF)
// ---------------------------------------------------------------------------

export interface ExpandedLinkedRef {
  to_kind: string;
  to_id: number;
  relation: string;
  strength: number;
}

export interface ExpandedRef {
  client_slug: string;
  event_id: number;
  linked_refs: ExpandedLinkedRef[];
}

/** Toolbar "+ include linked refs". One audit entry per call. */
export async function expandLinkedRefs(
  refs: { client_slug: string; event_id: number }[],
): Promise<ExpandedRef[]> {
  const res = await fetch("/api/v1/search/links/expand", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refs }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { code?: string; message?: string }).code
        || (body as { message?: string }).message
        || "Expand failed",
      res.status,
    );
  }
  const data = (await res.json()) as { refs: ExpandedRef[] };
  return data.refs;
}

export interface ExportArgs extends SearchEventsArgs {
  event_ids?: { client_slug: string; event_id: number }[];
  format: "csv" | "pdf";
  include_agent_notes?: boolean;
  include_indicators?: boolean;
}

/** Trigger audit-grade export. Returns blob + filename + audit headers
 * so callers can render an `<a download>` or open in a new tab. */
export async function exportSearch(args: ExportArgs): Promise<{
  blob: Blob;
  filename: string;
  auditRequestId: string;
  filterHash: string;
}> {
  const res = await fetch("/api/v1/search/export", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(args),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { code?: string; message?: string }).code
        || (body as { message?: string }).message
        || "Export failed",
      res.status,
    );
  }
  const blob = await res.blob();
  // Pull filename from Content-Disposition, fall back to a sensible default.
  const cd = res.headers.get("content-disposition") || "";
  const match = cd.match(/filename="?([^";]+)"?/i);
  const filename = match?.[1] ?? `athena-export.${args.format}`;
  return {
    blob,
    filename,
    auditRequestId: res.headers.get("x-athena-audit-request-id") ?? "",
    filterHash: res.headers.get("x-athena-filter-hash") ?? "",
  };
}

// ---------------------------------------------------------------------------
// Data Management (Task #117 — super_admin storage stats + retention view)
// ---------------------------------------------------------------------------

export interface ClientDbStat {
  name: string;
  size_bytes: number;
  row_count_estimate: number | null;
  /** false = a fast estimate (the file is over the exact-count gate): shown
   *  as "≈". Absent (older backends) = exact. */
  row_count_exact?: boolean;
  last_modified: string | null;
}

export interface TenantStat {
  slug: string;
  display_name: string | null;
  status: string;
  dbs: ClientDbStat[];
  total_size_bytes: number;
}

export interface GlobalDbStat {
  name: string;
  size_bytes: number;
  row_count_estimate: number | null;
  row_count_exact?: boolean;
  last_modified: string | null;
}

/** A row count for the System page: exact, "≈ n" for a fast estimate, "—"
 *  when unknown. */
export function formatRowCount(
  stat: { row_count_estimate: number | null; row_count_exact?: boolean } | undefined,
): string {
  const n = stat?.row_count_estimate;
  if (n === null || n === undefined) return "—";
  return stat?.row_count_exact === false ? `≈ ${n.toLocaleString()}` : n.toLocaleString();
}

export interface DiskStat {
  total_bytes: number;
  used_bytes: number;
  free_bytes: number;
  data_root_bytes: number;
  used_pct: number;
  mount_point: string | null;
  mount_device: string | null;
  quota_bytes: number | null;
  used_pct_against_quota: number | null;
}

export interface StorageStatsResponse {
  tenants: TenantStat[];
  globals: GlobalDbStat[];
  disk: DiskStat;
  snapshot_at: string;
}

export interface RetentionPolicy {
  data_class: string;
  days: number | null;
  editable: boolean;
  description: string;
  overridden: boolean;
  allowed_days: number[];
  legal_baseline_days: number | null;
  regulator_basis: string;
  /** What the retention job applies: `days` floored at the baseline
   *  (null = permanent). Absent from a pre-036 backend. */
  effective_days?: number | null;
  /** `days` is below the baseline; the job uses the baseline. */
  floored?: boolean;
  /** False = the job has nothing to prune for this class. */
  enforced?: boolean;
  /** Rows the latest enforcing run deleted (null = no run on record). */
  last_run_deleted?: number | null;
  /** Expired rows the latest run HELD: an incident record cites them
   *  ('events' only; null = no run on record). */
  last_run_referenced?: number | null;
  /** Expired rows the latest run KEPT because they lie inside an evidence
   *  window (a confirmed threat's first detection → its all-clear, until an
   *  admin releases it; null = no run on record). */
  last_run_evidence?: number | null;
}

/** Is buoy telemetry landing in the telemetry store (migration 036)? */
export interface RetentionTelemetryStore {
  /** Writes stored in events.db instead in the last `window_hours`
   *  (recent faults only — the warning clears a day after the fault). */
  recent_fallbacks: number;
  window_hours: number;
  /** When the newest of them happened (null: none in the window). */
  last_fallback_at: string | null;
  tenants: Record<string, number>;
  /** Rows the latest enforcing run's sweep moved out of events.db. */
  last_sweep_moved: number | null;
  last_sweep_errors: string[];
}

/** The newest ENFORCING run of the nightly retention job (migration 036). */
export interface RetentionRun {
  run_id: string;
  started_at: string;
  finished_at: string | null;
  trigger: "scheduler" | "script" | "api" | "backfill" | string;
  status: "running" | "ok" | "partial" | "failed" | string;
  archive_enabled: boolean;
  tenants: number;
  deleted_total: number;
  error: string | null;
}

export interface RetentionScheduler {
  enabled: boolean;
  hour_utc: number | null;
  next_run_at: string | null;
  /** Why this process's last scheduled run failed (e.g. the clock check
   *  refused it — nothing was done); null/absent when it did not. */
  last_failure?: string | null;
}

export interface RetentionArchive {
  enabled: boolean;
  root: string | null;
  usable: boolean | null;
  reason: string | null;
  /** The root is open to other users (it holds unmasked DNS history). */
  warning?: string | null;
  /** New archive files are encrypted (required AND usable). */
  encrypted?: boolean;
  encryption?: RetentionArchiveEncryption | null;
  /** "archive NOT encrypted — …" when new files are plaintext. */
  encryption_note?: string | null;
  /** Data files in the archive (cached up to 10 min). */
  files?: RetentionArchiveFiles | null;
}

/** A PUBLIC key the archive encrypts to — short form + fingerprint only. */
export interface RetentionArchiveRecipient {
  short: string;
  fingerprint: string;
}

/** Cold-archive encryption (age, X25519): the operator holds the private
 *  key off the machine; Athena only ever sees public keys. */
export interface RetentionArchiveEncryption {
  mode: "required" | "off" | string;
  /** archive = unset, and the archive already holds encrypted files
   *  (required — fail closed). */
  source: "env" | "default" | "archive" | string;
  custody: "operator" | string;
  scheme: string;
  encrypted: boolean;
  recipients_path: string | null;
  recipients: RetentionArchiveRecipient[];
  /** Why a REQUIRED encryption is unusable (nothing is pruned then). */
  error: string | null;
  recipients_error?: string | null;
  note: string | null;
}

export interface RetentionArchiveFiles {
  plaintext: number;
  encrypted: number;
  /** Of `plaintext`: temp files interrupted writes left of plaintext day
   *  files (plaintext rows inside; encrypt_archive.py --delete-plaintext
   *  removes them). */
  plaintext_temp?: number;
  complete: boolean;
}

export interface RetentionResponse {
  policies: RetentionPolicy[];
  note: string;
  last_run?: RetentionRun | null;
  scheduler?: RetentionScheduler;
  archive?: RetentionArchive;
  telemetry_store?: RetentionTelemetryStore;
}

export interface RetentionPatchResponse {
  data_class: string;
  retention_days: number | null;
  previous_days: number | null;
  updated_at: string;
}

export async function patchRetention(
  dataClass: string,
  retentionDays: number,
): Promise<RetentionPatchResponse> {
  const res = await fetch(
    `/api/v1/admin/data/retention/${encodeURIComponent(dataClass)}`,
    {
      method: "PATCH",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ retention_days: retentionDays }),
    },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const { code, message } = body as { code?: string; message?: string };
    throw new ApiError(
      message || code || "Retention update failed",
      res.status,
      code,  // STEP_UP_REQUIRED / STEP_UP_NETWORK_CHANGED → re-auth dialog
    );
  }
  return (await res.json()) as RetentionPatchResponse;
}

export async function fetchStorageStats(): Promise<StorageStatsResponse> {
  const res = await fetch("/api/v1/admin/data/storage-stats", {
    credentials: "include",
  });
  if (!res.ok) throw new ApiError("Failed to load storage stats", res.status);
  return (await res.json()) as StorageStatsResponse;
}

export async function fetchRetention(): Promise<RetentionResponse> {
  const res = await fetch("/api/v1/admin/data/retention", {
    credentials: "include",
  });
  if (!res.ok) throw new ApiError("Failed to load retention", res.status);
  return (await res.json()) as RetentionResponse;
}

export interface IndicatorRow {
  client_slug: string;
  indicator_id: number;
  value: string;
  type: string;
  source: string;
  severity: string;
  confidence: number;
  context: string | null;
  first_seen: string;
  last_seen: string;
  hits: number;
  promoted_at: string | null;
}

export interface SearchIndicatorsResponse {
  results: IndicatorRow[];
  total_estimate: number;
  truncated: boolean;
  page_size: number;
  offset: number;
  tenants_searched: string[];
  step_up_expires_at: string | null;
}

export interface SearchIndicatorsArgs {
  tenants?: string[];
  query?: string;
  types?: string[];
  severities?: string[];
  sources?: string[];
  confidence_min?: number;
  confidence_max?: number;
  promoted_only?: boolean;
  include_deleted?: boolean;
  /** Per-tenant row ids — how a pulse `search_ref` resolves (pair with
   *  `tenants: [thatTenant]`). */
  indicator_ids?: number[];
  limit?: number;
  offset?: number;
}

export async function searchIndicators(
  args: SearchIndicatorsArgs,
): Promise<SearchIndicatorsResponse> {
  const res = await fetch("/api/v1/search/indicators", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(args),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { code?: string; message?: string }).code
        || (body as { message?: string }).message
        || "Indicator search failed",
      res.status,
    );
  }
  return (await res.json()) as SearchIndicatorsResponse;
}

export async function fetchThroughput(args?: {
  windowMinutes?: number;
  windowHours?: number;
  bucketMinutes?: number;
}): Promise<ThroughputResponse> {
  const q = new URLSearchParams();
  if (args?.windowMinutes !== undefined)
    q.set("window_minutes", String(args.windowMinutes));
  if (args?.windowHours !== undefined)
    q.set("window_hours", String(args.windowHours));
  if (args?.bucketMinutes !== undefined)
    q.set("bucket_minutes", String(args.bucketMinutes));
  const qs = q.toString();
  const res = await fetch(
    `/api/v1/dashboard/throughput${qs ? `?${qs}` : ""}`,
    { credentials: "include" },
  );
  if (!res.ok) throw new ApiError("Failed to load throughput", res.status);
  return (await res.json()) as ThroughputResponse;
}

// ---------------------------------------------------------------------------
// W1: dashboard integration health (analyst-friendly, no config surface).
// ---------------------------------------------------------------------------

export type IntegrationHealth = "ok" | "down" | "pending" | "unknown" | "degraded";

export interface IntegrationHealthRow {
  slug: string;
  name: string;
  category: string;
  health: IntegrationHealth;
  detail: string | null;
}

export async function fetchIntegrationHealth(): Promise<IntegrationHealthRow[]> {
  const res = await fetch("/api/v1/dashboard/integrations", {
    credentials: "include",
  });
  if (!res.ok) {
    throw new ApiError("Failed to load integration health", res.status);
  }
  const body = (await res.json()) as { items: IntegrationHealthRow[] };
  return body.items;
}

// ---------------------------------------------------------------------------
// W3: dashboard recent-events feed (metadata-only, analyst-friendly).
// ---------------------------------------------------------------------------

export interface RecentEventRow {
  event_id: number;
  client_slug: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  status: "open" | "acknowledged" | "resolved" | "suppressed";
  source: string;
  /** Headline for sources that present their alerts; else the event type. */
  title: string;
  /** Longer text under the title; may be multi-line. Render as text. */
  summary: string;
  occurred_at: string;
  device?: string | null;
  site?: string | null;
  /** Empty for a Viewer, and whenever a link could not be built exactly. */
  vendor_links?: import("@/contracts/alert").AlertVendorLink[];
  /** "Open device": resolved on click — see resolveVendorDeviceLink. */
  vendor_device_ref?: import("@/contracts/alert").VendorDeviceRef | null;
}

/**
 * Look the device's page up at the vendor — ONLY when the operator clicked
 * Open (the vendor rate-limits its API; the server caches the answer). The
 * server validates the vendor's address against the instance's portal host
 * and enforces role + tenant scope. Rejects with the server's sentence; the
 * caller then navigates nowhere.
 */
export async function resolveVendorDeviceLink(
  ref: Pick<import("@/contracts/alert").VendorDeviceRef, "client_slug" | "event_id">,
): Promise<string> {
  const res = await fetch("/api/v1/dashboard/vendor-device-link", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_slug: ref.client_slug, event_id: ref.event_id }),
  });
  const body = (await res.json().catch(() => ({}))) as {
    url?: unknown;
    message?: string;
    code?: string;
  };
  if (res.status === 401 && (body.code ?? "").startsWith("AUTH_SESSION_")) {
    // The console session is gone (expired / revoked) — not a vendor answer.
    // A 401 must hard-redirect to /login (internal rule: an invalid session redirects),
    // never sit under the button as a sentence the operator keeps retrying.
    window.location.href = "/login";
    throw new ApiError("Your session has expired — signing in again", 401, body.code);
  }
  if (!res.ok) {
    throw new ApiError(body.message || "The device page could not be looked up", res.status, body.code);
  }
  if (typeof body.url !== "string" || !body.url.startsWith("https://")) {
    throw new ApiError("The server did not return a usable device page address", res.status);
  }
  return body.url;
}

export async function fetchRecentEvents(args?: {
  limit?: number;
  minSeverity?: "info" | "low" | "medium" | "high" | "critical";
}): Promise<RecentEventRow[]> {
  const q = new URLSearchParams();
  if (args?.limit !== undefined) q.set("limit", String(args.limit));
  if (args?.minSeverity) q.set("min_severity", args.minSeverity);
  const qs = q.toString();
  const res = await fetch(
    `/api/v1/dashboard/recent-events${qs ? `?${qs}` : ""}`,
    { credentials: "include" },
  );
  if (!res.ok) {
    throw new ApiError("Failed to load recent events", res.status);
  }
  const body = (await res.json()) as { items: RecentEventRow[] };
  return body.items;
}

// ---------------------------------------------------------------------------
// W6: Devices Needing Attention — host-attention ranking.
// ---------------------------------------------------------------------------

export interface DeviceAttentionRow {
  tenant: string;
  host: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  reason: string;
  event_count: number;
  /** The widget's "open" target: resolved on click; null when none. */
  vendor_device_ref?: import("@/contracts/alert").VendorDeviceRef | null;
}

// ---------------------------------------------------------------------------
// W13: container/host CPU + memory feeds (3-feed bucket).
// ---------------------------------------------------------------------------

export interface HostMetricPoint {
  t: string;
  v: number;
}

export interface HostMetricsResponse {
  cpu_points: HostMetricPoint[];
  mem_points: HostMetricPoint[];
  window_minutes: number;
  bucket_minutes: number;
}

export async function fetchHostMetrics(args?: {
  windowMinutes?: number;
  bucketMinutes?: number;
}): Promise<HostMetricsResponse> {
  const q = new URLSearchParams();
  if (args?.windowMinutes !== undefined)
    q.set("window_minutes", String(args.windowMinutes));
  if (args?.bucketMinutes !== undefined)
    q.set("bucket_minutes", String(args.bucketMinutes));
  const qs = q.toString();
  const res = await fetch(
    `/api/v1/dashboard/host-metrics${qs ? `?${qs}` : ""}`,
    { credentials: "include" },
  );
  if (!res.ok) {
    throw new ApiError("Failed to load host metrics", res.status);
  }
  return (await res.json()) as HostMetricsResponse;
}

export async function fetchDevicesAttention(args?: {
  limit?: number;
  lookbackHours?: number;
}): Promise<DeviceAttentionRow[]> {
  const q = new URLSearchParams();
  if (args?.limit !== undefined) q.set("limit", String(args.limit));
  if (args?.lookbackHours !== undefined) {
    q.set("lookback_hours", String(args.lookbackHours));
  }
  const qs = q.toString();
  const res = await fetch(
    `/api/v1/dashboard/devices-attention${qs ? `?${qs}` : ""}`,
    { credentials: "include" },
  );
  if (!res.ok) {
    throw new ApiError("Failed to load devices needing attention", res.status);
  }
  const body = (await res.json()) as { items: DeviceAttentionRow[] };
  return body.items;
}

// ---------------------------------------------------------------------------
// DNS summary — buoy DNS telemetry (migration 036), domains MASKED.
// Analyst+: a Viewer gets 403 (ApiError.status) and the widget says so.
// ---------------------------------------------------------------------------

export async function fetchDnsSummary(args?: {
  hours?: number;
  top?: number;
  firstSeenLimit?: number;
}): Promise<DnsSummaryResponse> {
  const params = new URLSearchParams();
  if (args?.hours !== undefined) params.set("hours", String(args.hours));
  if (args?.top !== undefined) params.set("top", String(args.top));
  if (args?.firstSeenLimit !== undefined) {
    params.set("first_seen_limit", String(args.firstSeenLimit));
  }
  const qs = params.toString();
  const res = await fetch(
    `/api/v1/dashboard/dns-summary${qs ? `?${qs}` : ""}`,
    { credentials: "include", cache: "no-store" },
  );
  if (!res.ok) throw new ApiError("Failed to load the DNS summary", res.status);
  return (await res.json()) as DnsSummaryResponse;
}

// ---------------------------------------------------------------------------
// Threat-intel pulse — recently sighted indicators, values MASKED.
// Analyst+: a Viewer gets 403 (ApiError.status) and the widget says so.
// ---------------------------------------------------------------------------

export async function fetchTiPulse(args?: {
  limit?: number;
  lookbackDays?: number;
}): Promise<TiPulseResponse> {
  const q = new URLSearchParams();
  if (args?.limit !== undefined) q.set("limit", String(args.limit));
  if (args?.lookbackDays !== undefined) {
    q.set("lookback_days", String(args.lookbackDays));
  }
  const qs = q.toString();
  const res = await fetch(
    `/api/v1/dashboard/ti-pulse${qs ? `?${qs}` : ""}`,
    { credentials: "include" },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      "Failed to load the threat-intel pulse",
      res.status,
      (body as { code?: string }).code,
    );
  }
  return (await res.json()) as TiPulseResponse;
}

/**
 * Admin-driven password reset. Two modes:
 *   - `newPassword` provided → server sets it as a temporary password.
 *     Target keeps must_change_password=1 so they're forced to rotate at
 *     next sign-in.
 *   - `newPassword` omitted → server issues a one-time magic-link URL the
 *     caller hands off out-of-band.
 *
 * Either way, the target's existing sessions are revoked.
 */
export async function resetOperatorPassword(
  operatorId: number,
  reason?: string,
  newPassword?: string,
): Promise<ResetPasswordResult> {
  const payload: { reason: string; new_password?: string } = {
    reason: reason ?? "",
  };
  if (newPassword !== undefined) {
    payload.new_password = newPassword;
  }
  const res = await fetch(
    `/api/v1/admin/operators/${operatorId}/reset-password`,
    {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message || "Reset failed",
      res.status,
    );
  }
  return (await res.json()) as ResetPasswordResult;
}

// ---------------------------------------------------------------------------
// Agent query — operator-triggered "ask octo" calls (Slice 4 bridge)
// ---------------------------------------------------------------------------

/** Canned-query enum mirroring octo-llm's QueryKind. Closed set per
 * the octo-llm triage-taxonomy design decision — no freeform prompts. */
export type AskOctoQueryKind =
  | "tell_me_more"
  | "recognized_patterns"
  | "compare_recent"
  | "suggest_disposition"
  | "suggest_next_steps";

export interface AgentQueryRequest {
  client_slug: string;
  ref_kind: "event" | "ticket" | "indicator";
  ref_id: number;
  query_kind: AskOctoQueryKind;
  heuristic_note: string;
  signals?: string[];
}

export interface AgentQueryNoteRow {
  id: number;
  agent_id: string;
  note_text: string;
  confidence: number;
  created_at: string;
  updated_at: string | null;
  query_kind: string | null;
  ref_kind: string;
  ref_id: number;
}

export interface AgentQueryResponse {
  note: AgentQueryNoteRow;
  llm_took_ms: number;
  bridge_took_ms: number;
  /** v0.10: the tenant's effective AI policy when asked, and where the
   *  model ran — 'local' unless OCTO_LLM_URL points off the deployment. */
  effective_ai_policy?: "local" | "cloud";
  llm_locality?: "local" | "cloud";
}

// ---------------------------------------------------------------------------
// LLM status — universal visibility chip (Slice 5d-2)
// ---------------------------------------------------------------------------

export interface LlmStatusResponse {
  active_model: string;
  your_grant: boolean;
  your_preference: boolean;
  bundle_enabled: boolean;
  effectively_active: boolean;
  /** Slice 7l — live sibling state. Visible to every operator so
   * the topbar pill can render "ready" / "down" / "stub mode"
   * regardless of tier. */
  sibling_healthy: boolean;
  sibling_backend: string | null;
  sibling_model_version: string | null;
}

/** Resolved LLM status for the current operator. Every operator
 * sees this (viewers included) so they know whether their next
 * "ask octo" click will work. */
export async function getLlmStatus(): Promise<LlmStatusResponse> {
  const r = await fetch("/api/v1/account/llm-status", { credentials: "include" });
  if (!r.ok) {
    throw new ApiError("Failed to load LLM status", r.status);
  }
  return (await r.json()) as LlmStatusResponse;
}

/** Autonomous Triage L1 worker status (Task #119e). `online` is the
 * coarse up/down for the global topbar; `state` is the finer detail
 * (idle/triaging/error/disabled) for the /tickets feed pill. */
export interface AgentStatusResponse {
  state: "disabled" | "idle" | "triaging" | "error";
  online: boolean;
  last_tick_at: string | null;
  last_run: { processed: number; by_disposition: Record<string, number> } | null;
  last_error: string | null;
  consecutive_errors: number;
  interval_seconds: number | null;
  /** "uncalibrated" until an eval harness runs — confidence is advisory. */
  calibration_state?: string;
}
export async function getAgentStatus(): Promise<AgentStatusResponse> {
  const r = await fetch("/api/v1/agent/status", { credentials: "include" });
  if (!r.ok) {
    throw new ApiError("Failed to load agent status", r.status);
  }
  return (await r.json()) as AgentStatusResponse;
}

/** Dev-only synthetic-traffic control (Task #119f). Backend route exists
 * only on a dev data-root; the toggle UI is hidden outside Vite dev MODE. */
export interface SyntheticTrafficStatus {
  allowed: boolean;
  enabled: boolean;
  emitted_total: number;
  last_emit_at: string | null;
  interval_seconds: number | null;
}
export async function getSyntheticTraffic(): Promise<SyntheticTrafficStatus> {
  const r = await fetch("/api/v1/dev/synthetic-traffic", { credentials: "include" });
  if (!r.ok) throw new ApiError("Failed to load synthetic traffic status", r.status);
  return (await r.json()) as SyntheticTrafficStatus;
}
export async function setSyntheticTraffic(
  enabled: boolean,
): Promise<SyntheticTrafficStatus> {
  const r = await fetch("/api/v1/dev/synthetic-traffic", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
  if (!r.ok) throw new ApiError("Failed to set synthetic traffic", r.status);
  return (await r.json()) as SyntheticTrafficStatus;
}

// ---------------------------------------------------------------------------
// Factory model manifest — super_admin (Slice 7i)
// ---------------------------------------------------------------------------

export interface ManifestModelEntry {
  name: string;
  display_name: string;
  description: string;
  source_url: string | null;
  size_bytes_approx: number;
  sha256: string | null;
  license: string;
  publisher: string;
  tier: string | null;        // "dev" | "balanced" | "max"
  default: boolean;
  installed: boolean;
}

export interface ManifestResponse {
  manifest_version: number;
  models: ManifestModelEntry[];
}

export async function getLlmModelManifest(): Promise<ManifestResponse> {
  const r = await fetch("/api/v1/admin/llm/models/manifest", {
    credentials: "include",
  });
  if (!r.ok) {
    throw new ApiError("Failed to load model manifest", r.status);
  }
  return (await r.json()) as ManifestResponse;
}

// ---------------------------------------------------------------------------
// Octo-llm sibling probe — super_admin (Slice 7g)
// ---------------------------------------------------------------------------

export interface SiblingProbeResponse {
  reachable: boolean;
  error: string | null;
  octo_llm_url: string;
  backend: string | null;
  model_loaded: boolean | null;
  model_version: string | null;
  uptime_seconds: number | null;
  mem_used_mb: number | null;
}

// Slice 7j — factory-admin restart of the octo-llm sibling.
export interface RestartResponse {
  requested: boolean;
  method: string;          // "signal" | "docker" | "noop"
  detail: string;
  pid_killed: number | null;
}

export async function restartOctoLlm(): Promise<RestartResponse> {
  const r = await fetch("/api/v1/admin/llm/restart", {
    method: "POST",
    credentials: "include",
  });
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message ?? "Restart failed",
      r.status,
    );
  }
  return (await r.json()) as RestartResponse;
}

export async function probeOctoLlm(): Promise<SiblingProbeResponse> {
  const r = await fetch("/api/v1/admin/llm/probe", { credentials: "include" });
  if (!r.ok) {
    throw new ApiError("Failed to probe octo-llm", r.status);
  }
  return (await r.json()) as SiblingProbeResponse;
}

// ---------------------------------------------------------------------------
// Bundle-wide LLM config — super_admin (Slice 7a)
// ---------------------------------------------------------------------------

export interface LlmBundleConfig {
  l2_llm_enabled: boolean;
  l2_llm_active_model: string;
}

export async function getLlmBundleConfig(): Promise<LlmBundleConfig> {
  const r = await fetch("/api/v1/admin/bundle-config/llm", {
    credentials: "include",
  });
  if (!r.ok) {
    throw new ApiError("Failed to load bundle LLM config", r.status);
  }
  return (await r.json()) as LlmBundleConfig;
}

export async function putLlmBundleConfig(
  patch: Partial<LlmBundleConfig>,
): Promise<LlmBundleConfig> {
  const r = await fetch("/api/v1/admin/bundle-config/llm", {
    method: "PUT",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message ?? "Bundle config update failed",
      r.status,
    );
  }
  return (await r.json()) as LlmBundleConfig;
}

// ---------------------------------------------------------------------------
// LLM grant — admin-managed access (Slice 5d-2)
// ---------------------------------------------------------------------------

/** Grant or revoke another operator's LLM access. Requires caller's
 * tier ≥ target's tier. Factory's grant cannot be modified by others. */
export async function setLlmGrant(
  operatorId: number, granted: boolean,
): Promise<{ operator_id: number; granted: boolean }> {
  const r = await fetch(`/api/v1/admin/operators/${operatorId}/llm-grant`, {
    method: "PUT",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ granted }),
  });
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new ApiError(
      (body as { message?: string }).message ?? "LLM grant failed",
      r.status,
    );
  }
  return (await r.json()) as { operator_id: number; granted: boolean };
}

/** Slice 7h — fetch all agent notes attached to one (slug, ref_kind,
 * ref_id). Used by AgentNotesPanel on mount + when the displayed ref
 * changes so each alert/event/ticket sidebar shows only its own
 * enrichment history (no state bleed across selections). */
export async function fetchAgentNotesForRef(
  clientSlug: string,
  refKind: "event" | "ticket" | "indicator",
  refId: number,
): Promise<AgentQueryNoteRow[]> {
  const r = await fetch(
    `/api/v1/agent-notes/${encodeURIComponent(clientSlug)}/${refKind}/${refId}`,
    { credentials: "include" },
  );
  if (!r.ok) {
    throw new ApiError("Failed to load agent notes", r.status);
  }
  const body = await r.json() as { notes: AgentQueryNoteRow[] };
  return body.notes;
}

/** Fire an operator-triggered enrichment call. Returns the new
 * agent note row + timing. Throws ApiError with status 503 if
 * octo-llm is disabled, unhealthy, or unreachable — callers should
 * surface this gracefully ("octo unavailable; using heuristic only")
 * not as a hard error. Per §11.5, the LLM is value-add, never load-
 * bearing. */
export async function agentQuery(req: AgentQueryRequest): Promise<AgentQueryResponse> {
  const res = await fetch("/api/v1/agent-query", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    // Slice 7m — prefer the friendly message over the error code.
    // The bridge differentiates "octo-llm disabled in bundle_config",
    // "your account has not been granted L2 LLM access", "octo-llm
    // timeout", etc. — each tells the operator WHICH gate failed.
    // Previously we surfaced the code (SERVICE_UNAVAILABLE) which
    // was unhelpful.
    const b = body as { code?: string; message?: string };
    throw new ApiError(
      b.message || b.code || "Agent query failed",
      res.status,
    );
  }
  return (await res.json()) as AgentQueryResponse;
}

// ---------------------------------------------------------------------------
// Tenant lifecycle — Settings → Tenants + quarantine review (admin+).
// Mirrors apps/octo/api/routers/admin_tenants.py. Every mutation is audited
// server-side; reads are not. Errors carry the server's own message — it
// names the rule that refused ("two-person rule…", "set a kind before
// confirming") — and its code for control flow.
// ---------------------------------------------------------------------------

const TENANTS_BASE = "/api/v1/admin/tenants";
const QUARANTINE_BASE = "/api/v1/admin/quarantine";

async function tenantJson<T>(res: Response, fallback: string): Promise<T> {
  if (!res.ok) {
    const b = (await res.json().catch(() => ({}))) as { code?: string; message?: string };
    throw new ApiError(b.message || fallback, res.status, b.code);
  }
  return (await res.json()) as T;
}

function jsonInit(method: "POST" | "PATCH", body?: unknown): RequestInit {
  return {
    method,
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  };
}

export async function listTenants(): Promise<TenantListResponse> {
  const res = await fetch(`${TENANTS_BASE}?include_archived=1`, {
    credentials: "include",
    cache: "no-store",
  });
  const body = await tenantJson<Partial<TenantListResponse>>(res, "Failed to load tenants");
  return {
    tenants: Array.isArray(body.tenants) ? body.tenants : [],
    pending_review: body.pending_review ?? 0,
    quarantined: body.quarantined ?? 0,
    kinds: Array.isArray(body.kinds) ? body.kinds : [],
    compliance_tags: Array.isArray(body.compliance_tags) ? body.compliance_tags : [],
    ai_policies: Array.isArray(body.ai_policies) ? body.ai_policies : [],
  };
}

/** The dashboard's "needs review" counts — cheap and unaudited server-side. */
export async function fetchReviewSummary(): Promise<ReviewSummary> {
  const res = await fetch(`${TENANTS_BASE}/review-summary`, {
    credentials: "include",
    cache: "no-store",
  });
  return tenantJson<ReviewSummary>(res, "Failed to load review counts");
}

export async function createTenant(payload: CreateTenantPayload): Promise<Tenant> {
  const res = await fetch(TENANTS_BASE, jsonInit("POST", payload));
  return tenantJson<Tenant>(res, "Create tenant failed");
}

export async function patchTenant(slug: string, patch: PatchTenantPayload): Promise<Tenant> {
  const res = await fetch(`${TENANTS_BASE}/${encodeURIComponent(slug)}`, jsonInit("PATCH", patch));
  return tenantJson<Tenant>(res, "Update tenant failed");
}

/**
 * A refused bulk update (422 / 403): nothing was written. Carries the
 * server's per-row answer when it sent one, so the preview can show which
 * rows to fix or drop.
 */
export class BulkUpdateRefused extends ApiError {
  constructor(
    message: string,
    status: number,
    code: string | undefined,
    readonly result: BulkUpdateResponse | null,
  ) {
    super(message, status, code);
    this.name = "BulkUpdateRefused";
  }
}

/** POST /admin/tenants/bulk-update — `dryRun` answers the per-row diff and
 *  writes nothing; otherwise all-or-nothing. */
export async function bulkUpdateTenants(
  items: readonly BulkUpdateItem[],
  dryRun: boolean,
): Promise<BulkUpdateResponse> {
  const res = await fetch(`${TENANTS_BASE}/bulk-update`, jsonInit("POST", { items, dry_run: dryRun }));
  if (!res.ok) {
    const b = (await res.json().catch(() => ({}))) as Partial<BulkUpdateResponse> & {
      code?: string;
      message?: string;
    };
    const result: BulkUpdateResponse | null = Array.isArray(b.rows)
      ? {
          dry_run: false,
          applied: false,
          request_id: null,
          rows: b.rows,
          changed: b.changed ?? 0,
          unchanged: b.unchanged ?? 0,
          errors: b.errors ?? 0,
          refusal: b.refusal ?? (b.code ? { code: b.code, message: b.message ?? "" } : null),
        }
      : null;
    throw new BulkUpdateRefused(b.message || "Bulk update failed", res.status, b.code, result);
  }
  return (await res.json()) as BulkUpdateResponse;
}

/** The body of an offboard / merge: `{reason}` alone is the two-person
 *  request (the default, and an admin's only path); with `attested` it is a
 *  super admin's single-person exception. */
function lifecycleBody(reason: string, attested?: AttestedAction): Record<string, string> {
  if (!attested) return { reason };
  const mode: ApprovalMode = "single_attested";
  return { reason, approval_mode: mode, attestation: attested.attestation, confirm_subject: attested.confirm_subject };
}

/** Default: a two-person request (202). `attested` (super admin + step-up —
 *  a STEP_UP_REQUIRED ApiError asks for re-auth): applied now (200). */
export async function offboardTenant(slug: string, reason: string, attested?: AttestedAction): Promise<OffboardResponse> {
  const res = await fetch(
    `${TENANTS_BASE}/${encodeURIComponent(slug)}/offboard`,
    jsonInit("POST", lifecycleBody(reason, attested)),
  );
  return tenantJson<OffboardResponse>(res, "Offboard failed");
}

/** Default: a two-person request (202) a different super admin approves.
 *  `attested`: a super admin's single-person merge (200) — refused with
 *  SINGLE_PERSON_INELIGIBLE (409) when the guards say two people decide. */
export async function mergeTenant(
  slug: string,
  target: string,
  reason: string,
  attested?: AttestedAction,
): Promise<MergeResponse> {
  const res = await fetch(
    `${TENANTS_BASE}/${encodeURIComponent(slug)}/merge-into/${encodeURIComponent(target)}`,
    jsonInit("POST", lifecycleBody(reason, attested)),
  );
  return tenantJson<MergeResponse>(res, "Merge failed");
}

/** What a merge would do, leave behind, its caveats and whether one person
 *  may apply it (admin+, unaudited). */
export async function previewMerge(slug: string, target: string): Promise<MergePreview> {
  const res = await fetch(
    `${TENANTS_BASE}/${encodeURIComponent(slug)}/merge-into/${encodeURIComponent(target)}/preview`,
    { credentials: "include", cache: "no-store" },
  );
  return tenantJson<MergePreview>(res, "Failed to load the merge preview");
}

/** The after-the-fact review of a single-person change — admin+ other than
 *  the one who applied it, once. */
export async function postReviewChangeRequest(
  id: number,
  verdict: PostReviewVerdict,
  note: string,
): Promise<ChangeRequest> {
  const res = await fetch(`${TENANTS_BASE}/requests/${id}/post-review`, jsonInit("POST", { verdict, note: note.trim() }));
  return tenantJson<ChangeRequest>(res, "Could not record the post-review");
}

/** A tenant's cloud-AI sign-off history + the attestation template the
 *  sign-off dialog shows (admin+; unaudited read). */
export async function listComplianceSignoffs(slug: string): Promise<SignoffHistoryResponse> {
  const res = await fetch(`${TENANTS_BASE}/${encodeURIComponent(slug)}/compliance-signoffs`, {
    credentials: "include",
    cache: "no-store",
  });
  return tenantJson<SignoffHistoryResponse>(res, "Failed to load compliance sign-offs");
}

/** super_admin + step-up (a STEP_UP_REQUIRED ApiError asks for re-auth). */
export async function signComplianceSignoff(slug: string, payload: SignoffPayload): Promise<SignoffResult> {
  const res = await fetch(
    `${TENANTS_BASE}/${encodeURIComponent(slug)}/compliance-signoff`,
    jsonInit("POST", payload),
  );
  return tenantJson<SignoffResult>(res, "Sign-off failed");
}

/** super_admin + step-up. */
export async function revokeComplianceSignoff(slug: string, signoffId: number, reason: string): Promise<SignoffResult> {
  const res = await fetch(
    `${TENANTS_BASE}/${encodeURIComponent(slug)}/compliance-signoff/${signoffId}/revoke`,
    jsonInit("POST", { reason }),
  );
  return tenantJson<SignoffResult>(res, "Revoke failed");
}

export async function listChangeRequests(
  state: ChangeRequestState | "all" = "pending",
  approvalMode?: ApprovalMode,
): Promise<ChangeRequest[]> {
  const mode = approvalMode ? `&approval_mode=${encodeURIComponent(approvalMode)}` : "";
  const res = await fetch(`${TENANTS_BASE}/requests?state=${encodeURIComponent(state)}${mode}`, {
    credentials: "include",
    cache: "no-store",
  });
  const body = await tenantJson<{ requests?: ChangeRequest[] }>(res, "Failed to load requests");
  return Array.isArray(body.requests) ? body.requests : [];
}

// ---------------------------------------------------------------------------
// Operator notices (v0.10) — the caller's own; admin+.
// ---------------------------------------------------------------------------

const NOTICES_BASE = "/api/v1/admin/notices";

export async function listNotices(includeAcknowledged = false): Promise<NoticeListResponse> {
  const res = await fetch(`${NOTICES_BASE}${includeAcknowledged ? "?include_acknowledged=1" : ""}`, {
    credentials: "include",
    cache: "no-store",
  });
  const body = await tenantJson<Partial<NoticeListResponse>>(res, "Failed to load notices");
  return { notices: Array.isArray(body.notices) ? body.notices : [], open: body.open ?? 0 };
}

export async function acknowledgeNotice(id: number): Promise<OperatorNotice> {
  const res = await fetch(`${NOTICES_BASE}/${id}/acknowledge`, jsonInit("POST"));
  return tenantJson<OperatorNotice>(res, "Could not acknowledge the notice");
}

export async function decideChangeRequest(
  id: number,
  decision: "approve" | "reject" | "cancel",
  note?: string,
): Promise<ChangeRequest> {
  const res = await fetch(
    `${TENANTS_BASE}/requests/${id}/${decision}`,
    jsonInit("POST", note && note.trim() ? { note: note.trim() } : {}),
  );
  return tenantJson<ChangeRequest>(res, `Could not ${decision} the request`);
}

export interface QuarantineQuery {
  readonly instance_id?: number;
  readonly reason?: string;
  readonly vendor_tenant_id?: string;
  readonly state?: "held" | "routed" | "discarded" | "all";
  readonly limit?: number;
  readonly offset?: number;
}

export async function listQuarantine(q: QuarantineQuery = {}): Promise<QuarantineListResponse> {
  const params = new URLSearchParams();
  if (q.instance_id !== undefined) params.set("instance_id", String(q.instance_id));
  if (q.reason) params.set("reason", q.reason);
  if (q.vendor_tenant_id !== undefined) params.set("vendor_tenant_id", q.vendor_tenant_id);
  if (q.state) params.set("state", q.state);
  if (q.limit !== undefined) params.set("limit", String(q.limit));
  if (q.offset !== undefined) params.set("offset", String(q.offset));
  const qs = params.toString();
  const res = await fetch(`${QUARANTINE_BASE}${qs ? `?${qs}` : ""}`, {
    credentials: "include",
    cache: "no-store",
  });
  const body = await tenantJson<Partial<QuarantineListResponse>>(res, "Failed to load quarantine");
  return {
    rows: Array.isArray(body.rows) ? body.rows : [],
    total: body.total ?? 0,
    limit: body.limit ?? 0,
    offset: body.offset ?? 0,
    reasons: Array.isArray(body.reasons) ? body.reasons : [],
  };
}

/** One held event WITH its payload — opaque text. Callers render it as text. */
export async function getQuarantined(id: number): Promise<QuarantineDetail> {
  const res = await fetch(`${QUARANTINE_BASE}/${id}`, { credentials: "include", cache: "no-store" });
  const body = await tenantJson<Partial<QuarantineDetail>>(res, "Failed to load the held event");
  return { ...(body as QuarantineDetail), payload: typeof body.payload === "string" ? body.payload : "" };
}

export async function routeQuarantined(id: number, target: RouteTarget): Promise<RouteResponse> {
  const res = await fetch(`${QUARANTINE_BASE}/${id}/route`, jsonInit("POST", target));
  return tenantJson<RouteResponse>(res, "Route failed");
}

export async function bulkRouteQuarantined(args: {
  readonly instance_id: number;
  readonly vendor_tenant_id: string;
  readonly quarantine_reason?: string;
  readonly target: RouteTarget;
}): Promise<RouteResponse> {
  const { target, ...unit } = args;
  const res = await fetch(`${QUARANTINE_BASE}/bulk-route`, jsonInit("POST", { ...unit, ...target }));
  return tenantJson<RouteResponse>(res, "Bulk route failed");
}

export async function discardQuarantined(
  id: number,
  reason: string,
): Promise<{ id: number; discarded: boolean }> {
  const res = await fetch(`${QUARANTINE_BASE}/${id}/discard`, jsonInit("POST", { reason }));
  return tenantJson<{ id: number; discarded: boolean }>(res, "Discard failed");
}

export async function bulkDiscardQuarantined(args: {
  readonly instance_id: number;
  readonly vendor_tenant_id: string;
  readonly quarantine_reason?: string;
  readonly reason: string;
}): Promise<BulkDiscardResponse> {
  const res = await fetch(`${QUARANTINE_BASE}/bulk-discard`, jsonInit("POST", args));
  return tenantJson<BulkDiscardResponse>(res, "Bulk discard failed");
}
