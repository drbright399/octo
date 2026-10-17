import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { CatalogPopout } from "@/components/catalog-popout";
import type { CatalogAdapter, CatalogResponse } from "@/contracts/integration";

/**
 * The wizard when the server REFUSES the create (a Datto key whose API user
 * may read nothing → 400 SMOKE_TEST_FAILED). The operator must see the
 * actionable reason, keep what they typed, NOT be walked on to the mapping
 * step with a dead key — and a second Save, after fixing Datto, must work.
 *
 * The real `@/lib/api` runs against a stubbed fetch.
 */

const REFUSED =
  "Not saved — Datto accepted the API key, but this API user may not read the account " +
  "(HTTP 403). In Datto RMM open Setup > Users, click the API user and, next to Generate " +
  "API Keys, set its API Security Level (and API Component Level) to one that covers the " +
  "sites, devices and alerts Athena should read, then Save User. Then press Test connection " +
  "again — the same key pair keeps working; do not regenerate it.";

const DATTO: CatalogAdapter = {
  vendor_slug: "datto",
  vendor_display_name: "Datto RMM",
  vendor_logo_path: "",
  vendor_category: "rmm",
  auth_model: "api-key",
  delivery_mode: "poll",
  availability: "available",
  compliance_categories: [],
  credential_shape: [
    { name: "DATTO_API_KEY", label: "Datto API Key", kind: "password", required: true },
    { name: "DATTO_API_SECRET_KEY", label: "Datto API Secret Key", kind: "password", required: true },
  ],
  tenant_mapping_shape: {
    fetch_method: "api",
    vendor_tenant_id_field: "uid",
    vendor_tenant_label_field: "name",
    tenant_noun: "site",
    id_help: "The Datto site's UID. The site NAME never matches.",
  },
};

const CATALOG: CatalogResponse = {
  adapters: [DATTO],
  categories: [{ category: "rmm", display_label: "RMM", adapters: [DATTO] }],
};

const CREATE_URL = "/api/v1/admin/adapters/datto/instances";
const TENANTS_URL = "/api/v1/admin/adapters/instances/7/vendor-tenants";

function json(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function stubBackend() {
  const state = { creates: 0 };
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === CREATE_URL && init?.method === "POST") {
      state.creates += 1;
      if (state.creates === 1) {
        return json(400, { code: "SMOKE_TEST_FAILED", message: REFUSED });
      }
      return json(200, {
        instance: {
          id: 7,
          vendor_slug: "datto",
          status: "running",
          status_detail: "started",
          configured_at: "2026-01-01T00:00:00.000Z",
          last_test_at: "2026-01-01T00:00:00.000Z",
        },
        smoke_test_message: "ok",
        generated_webhook_secret: null,
      });
    }
    if (url === "/api/v1/admin/clients") return json(200, { clients: [] });
    if (url.includes("/mappings/tenants")) return json(200, { mappings: [] });
    if (url === TENANTS_URL) {
      return json(503, { code: "VENDOR_UNREACHABLE", message: "Could not reach Datto: fixture" });
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { state, fetchMock };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("CatalogPopout — a refused create", () => {
  it("shows the fix-it reason, keeps the form, and does not move on until a Save succeeds", async () => {
    const { state, fetchMock } = stubBackend();
    const onConfigured = vi.fn();
    render(
      <CatalogPopout open onClose={() => undefined} onConfigured={onConfigured} initialCatalog={CATALOG} />,
    );
    fireEvent.click(screen.getByTestId("catalog-adapter-datto"));
    const key = screen.getByLabelText(/Datto API Key/);
    const secret = screen.getByLabelText(/Datto API Secret Key/);
    fireEvent.change(key, { target: { value: "fixture-key" } });
    fireEvent.change(secret, { target: { value: "fixture-secret" } });
    fireEvent.click(screen.getByText("Save & encrypt"));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Setup > Users");
    expect(alert).toHaveTextContent("API Security Level");
    expect(alert).toHaveTextContent("do not regenerate");
    // Nothing self-contradictory, no internal jargon.
    expect(alert).not.toHaveTextContent(/rejected the credentials|smoke test/i);
    // The form is still there, with what was typed.
    expect(key).toHaveValue("fixture-key");
    expect(secret).toHaveValue("fixture-secret");
    // Not walked on with a dead key: no mapping step, nothing reported saved.
    expect(screen.queryByText(/map tenants to clients/i)).not.toBeInTheDocument();
    expect(onConfigured).not.toHaveBeenCalled();
    expect(fetchMock.mock.calls.some(([url]) => url === TENANTS_URL)).toBe(false);

    // The operator fixes the API user in Datto and presses Save again.
    fireEvent.click(screen.getByText("Save & encrypt"));
    await waitFor(() => expect(onConfigured).toHaveBeenCalledTimes(1));
    expect(state.creates).toBe(2);
    expect(await screen.findByText(/map tenants to clients/i)).toBeInTheDocument();
    expect(screen.queryByText(REFUSED)).not.toBeInTheDocument();

    // The wizard hands the adapter's shape to the mapping step: even when site
    // discovery FAILS there, the wording is "site", not a generic "tenant".
    expect(await screen.findByTestId("discovery-failed")).toHaveTextContent(
      "Could not load the site list from Datto RMM",
    );
  });
});
