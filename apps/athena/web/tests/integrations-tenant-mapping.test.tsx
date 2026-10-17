import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import IntegrationsTab from "@/pages/settings/integrations";
import { ApiError, listVendorTenants, setTenantMappings } from "@/lib/api";
import type { MeResponse } from "@/contracts/operator";

/**
 * Tenant mapping from the instance card. The mapping step used to exist only
 * inside the "+ Add integration" wizard, so a wrong mapping (site NAMES typed
 * as ids, in production) could be fixed only by Disable + re-add. The card now
 * re-opens it (admin+), with vendor site discovery.
 *
 * The real `@/lib/api` runs against a stubbed fetch.
 */

const TENANTS_URL = "/api/v1/admin/adapters/instances/7/vendor-tenants";
const MAPPINGS_URL = "/api/v1/integrations/datto/7/mappings/tenants";
const UNMATCHED_WARNING =
  "1 of 1 saved tenant mapping(s) do not match any Datto RMM site (checked " +
  "2026-01-01T00:00:00.000Z): 'Example Clinic'. Events will never route to them — open " +
  "Tenant mapping and pick the right site for each.";

const SHAPE = {
  fetch_method: "api",
  fetch_endpoint: "/api/v2/account/sites",
  vendor_tenant_id_field: "uid",
  vendor_tenant_label_field: "name",
  tenant_noun: "site",
  id_help: "The Datto site's UID. The site NAME never matches.",
};

function me(role: MeResponse["role"]): MeResponse {
  return { operator_id: 1, username: "alice", email: "alice@example.test", role } as MeResponse;
}

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function stubBackend(tenants: { status: number; body: Record<string, unknown> }) {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === "/api/v1/integrations") {
      return jsonResponse(200, {
        definitions: [{ slug: "datto", name: "Datto RMM", category: "rmm", description: "RMM alerts." }],
        instances: {
          datto: {
            slug: "datto",
            id: 7,
            status: "running",
            status_detail: null,
            configured_at: "2026-01-01T00:00:00.000Z",
            last_test_at: null,
            warnings: [UNMATCHED_WARNING],
            notes: [],
          },
        },
      });
    }
    if (url === "/api/v1/admin/adapters/catalog") {
      return jsonResponse(200, { adapters: [], categories: [] });
    }
    if (url === "/api/v1/admin/clients") {
      return jsonResponse(200, {
        clients: [{ slug: "example-clinic", display_name: "Example Clinic", status: "active" }],
      });
    }
    if (url === MAPPINGS_URL && init?.method === "PUT") {
      return jsonResponse(422, {
        code: "VALIDATION_FAILED",
        message: "mapping 1: client 'gone' does not exist — events mapped to it would be dropped.",
      });
    }
    if (url === MAPPINGS_URL) {
      return jsonResponse(200, {
        mappings: [
          { vendor_tenant_id: "Example Clinic", octo_client_slug: "example-clinic", vendor_tenant_label: null, match_source: "manual" },
        ],
      });
    }
    if (url === TENANTS_URL || url === `${TENANTS_URL}?refresh=true`) {
      return jsonResponse(tenants.status, tenants.body);
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const OK_TENANTS = {
  status: 200,
  body: {
    instance_id: 7,
    vendor_slug: "datto",
    vendor_display_name: "Datto RMM",
    supported: true,
    tenants: [{ id: "site-uid-0001", label: "Example Clinic" }],
    truncated: false,
    fetched_at: "2026-01-01T00:00:00.000Z",
    cached: false,
    tenant_mapping_shape: SHAPE,
  },
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("listVendorTenants (api helper)", () => {
  it("asks for a refresh only when told to and never caches the listing", async () => {
    const fetchMock = stubBackend(OK_TENANTS);
    const d = await listVendorTenants(7);
    // POST: this call decrypts credentials and contacts the vendor, and the
    // SameSite=Lax session cookie still rides on a cross-site GET navigation.
    expect(fetchMock).toHaveBeenLastCalledWith(TENANTS_URL, {
      method: "POST",
      credentials: "include",
      cache: "no-store",
    });
    expect(d.supported).toBe(true);
    expect(d.tenants).toEqual([{ id: "site-uid-0001", label: "Example Clinic" }]);
    expect(d.tenant_mapping_shape?.tenant_noun).toBe("site");

    await listVendorTenants(7, { refresh: true });
    expect(fetchMock).toHaveBeenLastCalledWith(`${TENANTS_URL}?refresh=true`, expect.anything());
  });

  it("rejects with the server's actionable message and code", async () => {
    stubBackend({
      status: 424,
      body: { code: "VENDOR_ACCESS_FORBIDDEN", message: "Datto accepted the API key but this API user is not allowed to read the account." },
    });
    const err = await listVendorTenants(7).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(424);
    expect((err as ApiError).code).toBe("VENDOR_ACCESS_FORBIDDEN");
    expect((err as ApiError).message).toMatch(/not allowed to read the account/);
  });

  it("treats a malformed body as 'no discovery', not as a list", async () => {
    stubBackend({ status: 200, body: { tenants: "nope" } });
    const d = await listVendorTenants(7);
    expect(d).toEqual({
      supported: false, tenants: [], truncated: false, fetched_at: null, tenant_mapping_shape: null,
    });
  });
});

describe("setTenantMappings (api helper)", () => {
  it("surfaces WHICH mapping the server refused", async () => {
    stubBackend(OK_TENANTS);
    await expect(setTenantMappings("datto", 7, [])).rejects.toThrow(
      /client 'gone' does not exist/,
    );
  });
});

describe("Integration card — Tenant mapping", () => {
  it("is admin+ only", async () => {
    stubBackend(OK_TENANTS);
    render(<IntegrationsTab me={me(["analyst"])} />);
    await screen.findByTestId("integration-card-datto");
    expect(screen.queryByTestId("tenant-mapping-datto")).not.toBeInTheDocument();
  });

  it("shows the backend's unmatched-mappings warning and re-opens the mapping step", async () => {
    const fetchMock = stubBackend(OK_TENANTS);
    render(<IntegrationsTab me={me(["admin"])} />);
    const card = await screen.findByTestId("integration-card-datto");
    expect(card).toHaveTextContent("1 of 1 saved tenant mapping(s) do not match any Datto RMM site");

    fireEvent.click(screen.getByTestId("tenant-mapping-datto"));
    const drawer = await screen.findByTestId("tenant-mapping-drawer");
    // The saved name-as-id row is flagged, with the uid on offer.
    const flag = await within(drawer).findByTestId("mapping-unmatched-0");
    expect(flag).toHaveTextContent("“Example Clinic” does not match any Datto RMM site");
    expect(within(flag).getByRole("button", { name: "use site-uid-0001" })).toBeInTheDocument();
    // Existing instance: nothing to "skip".
    expect(within(drawer).getByRole("button", { name: "Close without saving" })).toBeInTheDocument();
    expect(within(drawer).queryByRole("button", { name: "Skip for now" })).not.toBeInTheDocument();

    // Closing refreshes the card (its warning follows what was saved).
    const before = fetchMock.mock.calls.filter(([u]) => u === "/api/v1/integrations").length;
    fireEvent.click(within(drawer).getByRole("button", { name: "Close without saving" }));
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.filter(([u]) => u === "/api/v1/integrations").length,
      ).toBe(before + 1),
    );
    expect(screen.queryByTestId("tenant-mapping-drawer")).not.toBeInTheDocument();
  });
});
