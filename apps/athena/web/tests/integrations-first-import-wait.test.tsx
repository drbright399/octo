import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import IntegrationsTab from "@/pages/settings/integrations";
import { listIntegrations } from "@/lib/api";
import type { MeResponse } from "@/contracts/operator";

/**
 * A new RocketCyber integration waits for the operator's customer mapping
 * before its first import (at most an hour). The card says so, and until
 * when — an empty feed then is expected, not a fault (v0.11 R1).
 *
 * The real `@/lib/api` runs against a stubbed fetch.
 */

const UNTIL = "2026-09-29T15:04:00.000Z";

function me(): MeResponse {
  return { operator_id: 1, username: "alice", email: "alice@example.test", role: ["admin"] } as MeResponse;
}

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function stubBackend(instance: Record<string, unknown>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url === "/api/v1/integrations") {
        return jsonResponse(200, {
          definitions: [{ slug: "rocketcyber", name: "RocketCyber", category: "soc", description: "SOC incidents." }],
          instances: { rocketcyber: instance },
        });
      }
      if (url === "/api/v1/admin/adapters/catalog") return jsonResponse(200, { adapters: [], categories: [] });
      return jsonResponse(404, {});
    }),
  );
}

const BASE = {
  slug: "rocketcyber",
  id: 9,
  status: "running",
  status_detail: null,
  configured_at: "2026-09-29T14:04:00.000Z",
  last_test_at: null,
  warnings: [],
  notes: [],
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("RocketCyber card — the first import waits for the customer mapping", () => {
  it("carries the wait through the API layer only when set", async () => {
    stubBackend({ ...BASE, first_import_waiting_until: UNTIL });
    expect((await listIntegrations()).instances.rocketcyber?.first_import_waiting_until).toBe(UNTIL);
    stubBackend({ ...BASE, first_import_waiting_until: null });
    expect("first_import_waiting_until" in ((await listIntegrations()).instances.rocketcyber ?? {})).toBe(false);
  });

  it("says it is waiting, that saving the mapping starts it, and when it starts anyway", async () => {
    stubBackend({ ...BASE, first_import_waiting_until: UNTIL });
    render(<IntegrationsTab me={me()} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-rocketcyber")));
    const line = card.getByTestId("integration-first-import-rocketcyber");
    expect(line).toHaveTextContent(
      /^Waiting for your customer mapping — imports start as soon as you save it, or automatically at .+\.$/,
    );
    expect(line.querySelector("time")?.getAttribute("dateTime")).toBe(UNTIL);
    expect(line.getAttribute("role")).toBe("status");         // information, not an alert
  });

  it("says nothing once it is importing", async () => {
    stubBackend({ ...BASE });
    render(<IntegrationsTab me={me()} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-rocketcyber")));
    expect(card.queryByTestId("integration-first-import-rocketcyber")).toBeNull();
  });
});
