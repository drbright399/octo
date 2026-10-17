/**
 * Mock adapter declarations for the Integrations UI. Replaced by a fetch
 * from the backend adapter registry once the API endpoint lands.
 *
 * NO real credentials live here. Field declarations only.
 */

import type {
  IntegrationDefinition,
  IntegrationInstance,
} from "@/contracts/integration";

export const MOCK_INTEGRATIONS: IntegrationDefinition[] = [
  {
    slug: "datto-rmm",
    name: "Datto RMM",
    category: "RMM",
    description:
      "Pulls device + alert telemetry from Datto RMM. Read-only API key recommended.",
    docs_url: "https://rmm.datto.com/help/en/Content/2SETUP/APIv2/APIv2.htm",
    fields: [
      {
        name: "endpoint",
        label: "API endpoint",
        kind: "url",
        required: true,
        placeholder: "https://exampleplat-api.centrastage.net",
        description: "Region-specific Datto RMM API URL.",
      },
      {
        name: "account_id",
        label: "Account ID",
        kind: "text",
        required: true,
        placeholder: "12345",
      },
      {
        name: "api_key",
        label: "API key",
        kind: "password",
        required: true,
        description: "From Datto RMM → Setup → Users → API.",
      },
      {
        name: "api_secret",
        label: "API secret",
        kind: "password",
        required: true,
      },
    ],
  },
  {
    slug: "unifi",
    name: "UniFi Network",
    category: "Network",
    description: "Pulls events + topology from a UniFi controller.",
    fields: [
      { name: "endpoint", label: "Controller URL", kind: "url", required: true, placeholder: "https://unifi.example.local:8443" },
      { name: "site", label: "Site name", kind: "text", required: true, placeholder: "default" },
      { name: "api_key", label: "API key", kind: "password", required: true },
    ],
  },
  {
    slug: "connectwise-rmm",
    name: "ConnectWise RMM",
    category: "RMM",
    description: "Pulls tickets + device telemetry from ConnectWise RMM.",
    fields: [
      { name: "endpoint", label: "API endpoint", kind: "url", required: true },
      { name: "company_id", label: "Company ID", kind: "text", required: true },
      { name: "public_key", label: "Public key", kind: "text", required: true },
      { name: "private_key", label: "Private key", kind: "password", required: true },
    ],
  },
  {
    slug: "wazuh",
    name: "Wazuh",
    category: "EDR / SIEM",
    description: "Forwards Wazuh manager alerts via the wazuh-octo-shim.",
    fields: [
      { name: "shim_url", label: "Shim URL", kind: "url", required: true, placeholder: "http://wazuh-octo-shim:8088/ingest" },
      { name: "tenant_token", label: "Tenant token", kind: "password", required: true },
    ],
  },
  {
    slug: "rocketcyber",
    name: "RocketCyber MDR",
    category: "MDR",
    description: "Pulls events from a RocketCyber tenant.",
    fields: [
      { name: "tenant_id", label: "Tenant ID", kind: "text", required: true },
      { name: "api_key", label: "API key", kind: "password", required: true },
    ],
  },
  {
    slug: "resend",
    name: "Resend",
    category: "Email",
    description:
      "Sends platform email (account, alerts, reports) via Resend and ingests delivery webhooks. Bring your own Resend API key + verified sending domain.",
    docs_url: "https://resend.com/docs/api-reference/introduction",
    fields: [
      { name: "RESEND_API_KEY", label: "Resend API key", kind: "password", required: true, placeholder: "re_...", description: "A sending-only API key from your Resend dashboard." },
      { name: "RESEND_DOMAIN", label: "Sending domain", kind: "text", required: true, placeholder: "example.com", description: "Must be added + verified in Resend; the test confirms its SPF/DKIM/DMARC." },
      { name: "RESEND_FROM", label: "Default from address", kind: "text", required: true, placeholder: "Acme Security <security@example.com>" },
      { name: "RESEND_WEBHOOK_SECRET", label: "Webhook signing secret", kind: "password", required: false, placeholder: "whsec_...", description: "Required for inbound events — without it delivery/bounce webhooks are rejected." },
    ],
  },
];

export const MOCK_INTEGRATION_STATE: Record<string, IntegrationInstance> = {
  "datto-rmm": { slug: "datto-rmm", status: "connected", status_detail: "v0.2 · 142/min", configured_at: "2026-04-12T09:31:00Z", last_test_at: "2026-05-06T13:25:00Z" },
  unifi: { slug: "unifi", status: "connected", status_detail: "v0.1 · 389/min", configured_at: "2026-04-15T11:00:00Z" },
  wazuh: { slug: "wazuh", status: "error", status_detail: "queue lag 4s", configured_at: "2026-04-08T18:00:00Z" },
  rocketcyber: { slug: "rocketcyber", status: "error", status_detail: "auth expired" },
  "connectwise-rmm": { slug: "connectwise-rmm", status: "disconnected" },
};
