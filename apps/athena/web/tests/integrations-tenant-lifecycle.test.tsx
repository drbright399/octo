import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import IntegrationsTab from "@/pages/settings/integrations";
import { listIntegrations } from "@/lib/api";
import { withoutLifecycleSentences } from "@/lib/integration-status";
import type { IntegrationInstance } from "@/contracts/integration";
import type { MeResponse } from "@/contracts/operator";

/**
 * The instance card says what its traffic left for a human — tenants
 * auto-created and awaiting review, events held in quarantine, auto-create
 * paused — with links into Settings → Tenants. The backend's sentence
 * warnings that say the same thing are not shown twice.
 *
 * The real `@/lib/api` runs against a stubbed fetch.
 */

const PENDING_SENTENCE =
  "3 tenant(s) were created from Datto RMM traffic and await review — tag what each one is (client / internal / dev / vendor / other) under Settings → Tenants.";
const HELD_SENTENCE =
  "90 event(s) from Datto RMM are held in quarantine pending review — they could not be attributed to a tenant. Nothing is lost: route or discard them under Settings → Tenants → Quarantine.";
const PAUSED_SENTENCE =
  "Auto-create is PAUSED for Datto RMM: the bound of 25 new tenants per hour / 200 awaiting review is reached. Traffic from further new sites is held in quarantine until tenants are reviewed (or the hour passes).";
const OTHER_WARNING = "Inbound webhooks are switched on but no secret is stored.";

function me(role: MeResponse["role"]): MeResponse {
  return { operator_id: 1, username: "alice", email: "alice@example.test", role } as MeResponse;
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
          definitions: [{ slug: "datto", name: "Datto RMM", category: "rmm", description: "RMM alerts." }],
          instances: { datto: instance },
        });
      }
      if (url === "/api/v1/admin/adapters/catalog") return jsonResponse(200, { adapters: [], categories: [] });
      return jsonResponse(404, {});
    }),
  );
}

const BASE = {
  slug: "datto",
  id: 7,
  status: "running",
  status_detail: null,
  configured_at: "2026-01-01T00:00:00.000Z",
  last_test_at: null,
  notes: [],
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("listIntegrations — lifecycle counters", () => {
  it("carries the counters only when positive / set", async () => {
    stubBackend({ ...BASE, warnings: [], auto_created_pending: 3, quarantined: 90, autocreate_limited: true });
    const r = await listIntegrations();
    expect(r.instances.datto).toMatchObject({ auto_created_pending: 3, quarantined: 90, autocreate_limited: true });
    stubBackend({ ...BASE, warnings: [], auto_created_pending: 0, quarantined: 0, autocreate_limited: false });
    const quiet = (await listIntegrations()).instances.datto as IntegrationInstance;
    expect("auto_created_pending" in quiet).toBe(false);
    expect("quarantined" in quiet).toBe(false);
    expect("autocreate_limited" in quiet).toBe(false);
  });
});

describe("withoutLifecycleSentences", () => {
  it("drops only the sentence whose structured counter is present", () => {
    const all = [PENDING_SENTENCE, HELD_SENTENCE, PAUSED_SENTENCE, OTHER_WARNING];
    const bare: IntegrationInstance = { slug: "datto", status: "connected" };
    expect(withoutLifecycleSentences(bare, all)).toEqual(all);
    expect(withoutLifecycleSentences({ ...bare, quarantined: 90 }, all)).toEqual([PENDING_SENTENCE, PAUSED_SENTENCE, OTHER_WARNING]);
    expect(
      withoutLifecycleSentences({ ...bare, auto_created_pending: 3, quarantined: 90, autocreate_limited: true }, all),
    ).toEqual([OTHER_WARNING]);
  });
});

describe("IntegrationsTab — tenant lifecycle lines", () => {
  it("shows the counts as links into the Tenants tab and the paused warning; the duplicate sentences are gone", async () => {
    stubBackend({
      ...BASE,
      warnings: [PENDING_SENTENCE, HELD_SENTENCE, PAUSED_SENTENCE, OTHER_WARNING],
      auto_created_pending: 3,
      quarantined: 90,
      autocreate_limited: true,
    });
    const push = vi.spyOn(window.history, "pushState");
    render(<IntegrationsTab me={me(["admin"])} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-datto")));
    const lines = within(card.getByTestId("integration-lifecycle-datto"));
    expect(lines.getByTestId("integration-autocreated-datto")).toHaveTextContent("3 tenants auto-created, awaiting review");
    expect(lines.getByTestId("integration-quarantined-datto")).toHaveTextContent("90 events in quarantine");
    expect(lines.getByTestId("integration-autocreate-limited-datto")).toHaveTextContent("Auto-create is paused");
    // The sentences saying the same thing are not repeated; unrelated ones stay.
    expect(card.queryByText(PENDING_SENTENCE)).toBeNull();
    expect(card.queryByText(HELD_SENTENCE)).toBeNull();
    expect(card.queryByText(PAUSED_SENTENCE)).toBeNull();
    expect(card.getByText(OTHER_WARNING)).toBeInTheDocument();

    fireEvent.click(lines.getByTestId("integration-autocreated-datto"));
    expect(push).toHaveBeenLastCalledWith({}, "", "/settings/tenants?filter=needs-review");
    fireEvent.click(lines.getByTestId("integration-quarantined-datto"));
    expect(push).toHaveBeenLastCalledWith({}, "", "/settings/tenants/quarantine?instance=7");
  });

  it("says nothing when nothing needs a human", async () => {
    stubBackend({ ...BASE, warnings: [OTHER_WARNING], auto_created_pending: 0, quarantined: 0, autocreate_limited: false });
    render(<IntegrationsTab me={me(["admin"])} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-datto")));
    expect(card.queryByTestId("integration-lifecycle-datto")).toBeNull();
    expect(card.getByText(OTHER_WARNING)).toBeInTheDocument();
  });

  it("an older backend without counters keeps its sentences", async () => {
    stubBackend({ ...BASE, warnings: [HELD_SENTENCE] });
    render(<IntegrationsTab me={me(["admin"])} />);
    const card = within(await waitFor(() => screen.getByTestId("integration-card-datto")));
    expect(card.getByText(HELD_SENTENCE)).toBeInTheDocument();
    expect(card.queryByTestId("integration-lifecycle-datto")).toBeNull();
  });
});
