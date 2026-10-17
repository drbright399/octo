import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { CatalogPopout } from "@/components/catalog-popout";
import type { CatalogAdapter, CatalogResponse } from "@/contracts/integration";

/**
 * The Add-integration wizard's NextDNS mapping step guards unsaved profile
 * choices exactly like the card's drawer: the backdrop and the ✕ ask before
 * discarding them; with nothing unsaved they close at once.
 *
 * The real `@/lib/api` runs against a stubbed fetch.
 */

const NEXTDNS: CatalogAdapter = {
  vendor_slug: "nextdns",
  vendor_display_name: "NextDNS",
  vendor_logo_path: "",
  vendor_category: "network",
  auth_model: "api-key",
  delivery_mode: "poll",
  availability: "available",
  compliance_categories: [],
  credential_shape: [
    { name: "NEXTDNS_API_KEY", label: "NextDNS API key", kind: "password", required: true },
  ],
};

const CATALOG: CatalogResponse = {
  adapters: [NEXTDNS],
  categories: [{ category: "network", display_label: "Network", adapters: [NEXTDNS] }],
};

const CREATE_URL = "/api/v1/admin/adapters/nextdns/instances";
const PROFILES_URL = "/api/v1/integrations/nextdns/12/profiles";

function json(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function stubBackend() {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === CREATE_URL && init?.method === "POST") {
      return json(200, {
        instance: {
          id: 12, vendor_slug: "nextdns", status: "running", status_detail: "started",
          configured_at: "2026-09-30T10:00:00.000Z", last_test_at: "2026-09-30T10:00:00.000Z",
        },
        smoke_test_message: "ok",
        generated_webhook_secret: null,
      });
    }
    if (url === "/api/v1/admin/clients") {
      return json(200, { clients: [{ slug: "acme-corp", display_name: "Acme Corp", status: "active" }] });
    }
    if (url === PROFILES_URL) {
      return json(200, {
        instance_id: 12, discovered: true, fetched_at: "2026-09-30T10:00:00.000Z",
        profiles: [{
          profile_id: "abc123", name: "Acme Corp Office", listed: true, tenant_slug: null,
          tenant_name: null, tenant_status: null, match_source: null, ignored: false,
          suggestion: { tenant_slug: "acme-corp", tenant_name: "Acme Corp", rule: "name-prefix" },
          state: null, state_since: null, queries_24h: null,
        }],
        counts: { known: 1, mapped: 0, ignored: 0, unmapped: 1, active: 0, pending: 0, lapsed: 0 },
      });
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

async function toTheMappingStep(onClose: () => void) {
  stubBackend();
  render(<CatalogPopout open onClose={onClose} onConfigured={() => undefined} initialCatalog={CATALOG} />);
  fireEvent.click(screen.getByTestId("catalog-adapter-nextdns"));
  fireEvent.change(screen.getByLabelText(/NextDNS API key/), { target: { value: "fixture-nd-key" } });
  fireEvent.click(screen.getByText("Save & encrypt"));
  await screen.findByTestId("nextdns-profile-abc123");
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("CatalogPopout — the NextDNS mapping step", () => {
  it("asks before the backdrop or ✕ discard unsaved profile choices", async () => {
    const onClose = vi.fn();
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    await toTheMappingStep(onClose);
    fireEvent.click(screen.getByTestId("nextdns-suggest-abc123"));      // an unsaved choice

    fireEvent.click(screen.getByTestId("catalog-popout-backdrop"));
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(onClose).not.toHaveBeenCalled();
    fireEvent.click(screen.getByLabelText("Close"));
    expect(confirm).toHaveBeenCalledTimes(2);
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByTestId("nextdns-profile-abc123")).toBeInTheDocument();

    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByLabelText("Close"));
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
  });

  it("closes at once when nothing is unsaved", async () => {
    const onClose = vi.fn();
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    await toTheMappingStep(onClose);
    fireEvent.click(screen.getByTestId("catalog-popout-backdrop"));
    expect(confirm).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
