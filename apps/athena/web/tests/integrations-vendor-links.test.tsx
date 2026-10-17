import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import IntegrationsTab from "@/pages/settings/integrations";
import type { MeResponse } from "@/contracts/operator";

/**
 * "Portal links" on the instance card: the admin-editable, non-secret settings
 * behind "Open in <vendor>" links. Offered only for an adapter that can build
 * such links, and only to admin+.
 *
 * The real `@/lib/api` runs against a stubbed fetch.
 */

const PORTAL = "https://exampleplat.rmm.datto.com";
const SETTINGS_URL = "/api/v1/integrations/datto/7/vendor-links";

function me(role: MeResponse["role"]): MeResponse {
  return { operator_id: 1, username: "alice", email: "alice@example.test", role } as MeResponse;
}

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function stubBackend(supportsVendorLinks: boolean) {
  const fetchMock = vi.fn(async (url: string) => {
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
            warnings: [],
            notes: [],
            supports_vendor_links: supportsVendorLinks,
          },
        },
      });
    }
    if (url === SETTINGS_URL) {
      return jsonResponse(200, {
        vendor_slug: "datto",
        instance_id: 7,
        portal_name: "Datto RMM",
        allowed_domain: "datto.com",
        placeholders: ["{alert_uid}", "{device_uid}", "{site_uid}"],
        overrides: { alert_path_template: "/alerts/{alert_uid}" },
        portal_base_url: PORTAL,
        alert_path_template: "/alerts/{alert_uid}",
        derived_portal_base_url: PORTAL,
        default_alert_path_template: "/alert/{alert_uid}",
        paths_verified: false,
        sample_alert_url: `${PORTAL}/alerts/ALERT-UID`,
        device_links_resolved: true,
        links_enabled: true,
        problem: null,
      });
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Integration card — Portal links", () => {
  it("is admin+ only", async () => {
    stubBackend(true);
    render(<IntegrationsTab me={me(["analyst"])} />);
    await screen.findByTestId("integration-card-datto");
    expect(screen.queryByTestId("vendor-links-datto")).not.toBeInTheDocument();
  });

  it("is not offered for an adapter that cannot build links", async () => {
    stubBackend(false);
    render(<IntegrationsTab me={me(["admin"])} />);
    await screen.findByTestId("integration-card-datto");
    expect(screen.queryByTestId("vendor-links-datto")).not.toBeInTheDocument();
  });

  it("opens the settings with the saved override filled in and the default as placeholder", async () => {
    stubBackend(true);
    render(<IntegrationsTab me={me(["admin"])} />);
    await screen.findByTestId("integration-card-datto");
    fireEvent.click(screen.getByTestId("vendor-links-datto"));

    const drawer = await screen.findByTestId("vendor-links-drawer");
    const alertPath = await within(drawer).findByTestId("vendor-links-alert_path_template");
    expect(alertPath).toHaveValue("/alerts/{alert_uid}");
    expect(alertPath).toHaveAttribute("placeholder", "/alert/{alert_uid}");
    expect(within(drawer).getByTestId("vendor-links-portal_base_url")).toHaveValue("");
    expect(within(drawer).getByTestId("vendor-links-sample-alert")).toHaveTextContent(
      `${PORTAL}/alerts/ALERT-UID`,
    );

    // Header ✕ and the panel's own Close both dismiss; use the first.
    fireEvent.click(within(drawer).getAllByRole("button", { name: "Close" })[0]!);
    expect(screen.queryByTestId("vendor-links-drawer")).not.toBeInTheDocument();
  });
});
