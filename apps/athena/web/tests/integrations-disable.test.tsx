import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import IntegrationsTab from "@/pages/settings/integrations";
import { TenantMappingPanel } from "@/components/tenant-mapping-panel";
import { ApiError, disableIntegration, listIntegrations } from "@/lib/api";
import type { MeResponse } from "@/contracts/operator";

/**
 * "Disable, then Add integration again" is the ONE recovery path for anything
 * credential-shaped — so the control has to exist on the instance card, be
 * admin+ only, demand a reason, surface the server's message, and refresh.
 * Also here: the read-only Setup guide, neutral poll-only notes, and the
 * armed-but-no-ingest-hostname warning on the card.
 *
 * The real `@/lib/api` is exercised against a stubbed fetch, so the
 * `disableIntegration` / `listIntegrations` helpers are covered end to end.
 */

const DISABLE_URL = "/api/v1/admin/adapters/instances/7/disable";
const POLL_ONLY_NOTE =
  "Poll-only: real-time webhooks are off by choice. To turn them on: Settings → Integrations → Datto RMM → Disable, then Add integration again.";
const NO_INGEST_WARNING =
  "Real-time webhooks are switched on for this integration, but this deployment has no public ingest hostname, so Datto RMM has nowhere to send them.";

function me(role: MeResponse["role"]): MeResponse {
  return { operator_id: 1, username: "alice", email: "alice@example.test", role } as MeResponse;
}

interface Backend {
  instance: Record<string, unknown> | null;
  disable: { status: number; body: Record<string, unknown> };
}

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function stubBackend(backend: Backend) {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === "/api/v1/integrations") {
      return jsonResponse(200, {
        definitions: backend.instance
          ? [{ slug: "datto", name: "Datto RMM", category: "rmm", description: "RMM alerts." }]
          : [],
        instances: backend.instance ? { datto: backend.instance } : {},
      });
    }
    if (url === DISABLE_URL && init?.method === "POST") {
      if (backend.disable.status === 200) backend.instance = null;
      return jsonResponse(backend.disable.status, backend.disable.body);
    }
    if (url === "/api/v1/admin/adapters/catalog") {
      return jsonResponse(200, {
        adapters: [
          {
            vendor_slug: "datto",
            vendor_display_name: "Datto RMM",
            vendor_logo_path: "",
            vendor_category: "rmm",
            auth_model: "api-key",
            delivery_mode: "hybrid",
            availability: "available",
            compliance_categories: [],
            contract_version: "1",
            credential_shape: [],
            tenant_mapping_shape: null,
            onboarding: {
              summary: "Datto RMM connects in two parts.",
              webhook_url: "https://ingest.example.test/api/v1/webhooks/datto",
              webhook_url_problem: null,
              steps: [
                { title: "1 · Fill in the API keys and save", body: "Save first." },
                {
                  title: "4 · Alert-raised payload template",
                  body: "Raised body.",
                  code_sample: '{"event": "alert_raised"}',
                },
              ],
            },
          },
        ],
        categories: [],
      });
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function runningInstance(extra: Record<string, unknown> = {}) {
  return {
    slug: "datto",
    id: 7,
    status: "running",
    status_detail: null,
    configured_at: "2026-01-01T00:00:00.000Z",
    last_test_at: null,
    warnings: [],
    notes: [],
    ...extra,
  };
}

const OK_DISABLE = {
  status: 200,
  body: {
    instance_id: 7,
    vendor_slug: "datto",
    status: "disabled",
    already_disabled: false,
    tenant_mappings_not_carried_over: 2,
    message: "datto integration disabled; its poller is stopped and the vendor slot is free.",
  },
};

let backend: Backend;

beforeEach(() => {
  backend = { instance: runningInstance(), disable: OK_DISABLE };
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("disableIntegration (api helper)", () => {
  it("POSTs the reason to the instance's disable route and maps the result", async () => {
    const fetchMock = stubBackend(backend);
    const result = await disableIntegration(7, "webhook token lost");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(DISABLE_URL);
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("include");
    expect(JSON.parse(String(init.body))).toEqual({ reason: "webhook token lost" });
    expect(result).toEqual({
      instanceId: 7,
      alreadyDisabled: false,
      tenantMappingsNotCarriedOver: 2,
      message: OK_DISABLE.body.message,
    });
  });

  it("throws the SERVER's message (and code) on failure", async () => {
    backend.disable = {
      status: 403,
      body: { code: "ISOLATION_VIOLATION", message: "admin tier required to disable an integration" },
    };
    stubBackend(backend);
    const err = await disableIntegration(7, "because").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).message).toBe("admin tier required to disable an integration");
    expect((err as ApiError).status).toBe(403);
    expect((err as ApiError).code).toBe("ISOLATION_VIOLATION");
  });

  it("listIntegrations carries the instance id and the neutral notes", async () => {
    backend.instance = runningInstance({ notes: [POLL_ONLY_NOTE] });
    stubBackend(backend);
    const { instances } = await listIntegrations();
    expect(instances.datto?.id).toBe(7);
    expect(instances.datto?.notes).toEqual([POLL_ONLY_NOTE]);
    expect(instances.datto?.warnings).toBeUndefined();
  });
});

describe("Integrations page — Disable integration", () => {
  it("is offered to admin+ only", async () => {
    stubBackend(backend);
    const { unmount } = render(<IntegrationsTab me={me(["analyst"])} />);
    await screen.findByText("Datto RMM");
    expect(screen.queryByTestId("disable-integration-datto")).not.toBeInTheDocument();
    unmount();

    render(<IntegrationsTab />); // `me` not resolved yet → nothing privileged
    await screen.findByText("Datto RMM");
    expect(screen.queryByTestId("disable-integration-datto")).not.toBeInTheDocument();
  });

  it.each([["admin"], ["super_admin"]] as const)("is shown to %s", async (role) => {
    stubBackend(backend);
    render(<IntegrationsTab me={me([role])} />);
    expect(await screen.findByTestId("disable-integration-datto")).toHaveTextContent("Disable");
  });

  it("confirms, REQUIRES a reason, calls the route, refreshes the list and shows the server message", async () => {
    const fetchMock = stubBackend(backend);
    render(<IntegrationsTab me={me(["admin"])} />);
    fireEvent.click(await screen.findByTestId("disable-integration-datto"));

    const dialog = screen.getByTestId("disable-integration-dialog");
    expect(dialog).toHaveTextContent("Disable Datto RMM?");
    expect(dialog).toHaveTextContent(/Tenant mappings belong to this instance and are not carried over/);
    expect(dialog).toHaveTextContent(/Never paste a credential here/);
    const confirm = within(dialog).getByRole("button", { name: "Disable integration" });
    expect(confirm).toBeDisabled();

    // Too short for the backend's min_length=3 → still disabled, nothing sent.
    fireEvent.change(within(dialog).getByRole("textbox"), { target: { value: " x " } });
    expect(confirm).toBeDisabled();
    fireEvent.change(within(dialog).getByRole("textbox"), {
      target: { value: "  webhook token lost  " },
    });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);

    await waitFor(() =>
      expect(screen.queryByTestId("disable-integration-dialog")).not.toBeInTheDocument(),
    );
    const call = fetchMock.mock.calls.find(([u]) => u === DISABLE_URL);
    expect(JSON.parse(String((call?.[1] as RequestInit).body))).toEqual({
      reason: "webhook token lost",
    });
    expect(screen.getByTestId("integrations-notice")).toHaveTextContent(OK_DISABLE.body.message);
    // Refreshed: the list endpoint only carries active instances, so the card goes.
    await waitFor(() => expect(screen.queryByText("Datto RMM")).not.toBeInTheDocument());
    expect(fetchMock.mock.calls.filter(([u]) => u === "/api/v1/integrations")).toHaveLength(2);
    expect(screen.getByTestId("open-catalog-popout")).toBeInTheDocument();
  });

  it("cancel sends nothing", async () => {
    const fetchMock = stubBackend(backend);
    render(<IntegrationsTab me={me(["admin"])} />);
    fireEvent.click(await screen.findByTestId("disable-integration-datto"));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByTestId("disable-integration-dialog")).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([u]) => u === DISABLE_URL)).toBe(false);
    expect(screen.getByText("Datto RMM")).toBeInTheDocument();
  });

  it("shows the server's message on failure and keeps the dialog (and the card)", async () => {
    backend.disable = {
      status: 500,
      body: { code: "INTERNAL_ERROR", message: "audit log is unavailable — nothing was changed" },
    };
    stubBackend(backend);
    render(<IntegrationsTab me={me(["admin"])} />);
    fireEvent.click(await screen.findByTestId("disable-integration-datto"));
    const dialog = screen.getByTestId("disable-integration-dialog");
    fireEvent.change(within(dialog).getByRole("textbox"), { target: { value: "rotating key" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Disable integration" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "audit log is unavailable — nothing was changed",
    );
    expect(within(dialog).getByRole("button", { name: "Disable integration" })).toBeEnabled();
    expect(screen.getByText("Datto RMM")).toBeInTheDocument();
  });
});

describe("Integrations page — notes, warnings and the setup guide", () => {
  it("poll-only by choice is a neutral note, not an alert", async () => {
    backend.instance = runningInstance({ notes: [POLL_ONLY_NOTE] });
    stubBackend(backend);
    render(<IntegrationsTab me={me(["admin"])} />);
    const note = await screen.findByTestId("integration-note-datto");
    expect(note).toHaveTextContent(/off by choice/);
    expect(note).toHaveAttribute("role", "note");
    expect(note.className).not.toMatch(/text-warning|text-critical/);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("webhooks armed with no ingest hostname IS an alert on the card", async () => {
    backend.instance = runningInstance({ warnings: [NO_INGEST_WARNING] });
    stubBackend(backend);
    render(<IntegrationsTab me={me(["admin"])} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/no public ingest hostname/);
  });

  it("opens the setup guide read-only from an existing card: URL + templates, no secret, no form", async () => {
    const fetchMock = stubBackend(backend);
    render(<IntegrationsTab me={me(["analyst"])} />);
    fireEvent.click(await screen.findByTestId("setup-guide-datto"));

    const drawer = await screen.findByTestId("setup-guide-drawer");
    expect(drawer).toHaveTextContent(/Setup guide — read-only/);
    await within(drawer).findByText("https://ingest.example.test/api/v1/webhooks/datto");
    // The payload template is reachable again without re-creating anything.
    fireEvent.click(within(drawer).getByRole("button", { name: "Step 2: 4 · Alert-raised payload template" }));
    await within(drawer).findByText('{"event": "alert_raised"}');
    expect(drawer).toHaveTextContent(/The webhook token itself is not shown/);
    // The guide opens from ANY card, including one in error: it must not say
    // "connected" — the very word the broken integration's card used to show.
    expect(drawer).toHaveTextContent(/already saved — nothing here changes it/);
    expect(drawer).not.toHaveTextContent(/already connected/);
    expect(drawer).toHaveTextContent(
      "Settings → Integrations → Datto RMM → Disable, then Add integration again",
    );
    // Read-only: no inputs, no save.
    expect(drawer.querySelector("input, textarea, select")).toBeNull();
    expect(within(drawer).queryByRole("button", { name: /^save|encrypt/i })).not.toBeInTheDocument();
    // Only metadata routes were touched.
    expect(fetchMock.mock.calls.map(([u]) => u)).toEqual([
      "/api/v1/integrations",
      "/api/v1/admin/adapters/catalog",
    ]);

    fireEvent.click(within(drawer).getByRole("button", { name: "Close" }));
    expect(screen.queryByTestId("setup-guide-drawer")).not.toBeInTheDocument();
  });
});

describe("TenantMappingPanel — map before attach", () => {
  it("says so right next to 'Skip for now'", async () => {
    stubBackend(backend);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        jsonResponse(200, url.includes("/mappings/") ? { mappings: [] } : { clients: [] }),
      ),
    );
    render(
      <TenantMappingPanel vendorSlug="datto" instanceId={7} vendorName="Datto RMM" onDone={vi.fn()} />,
    );
    const hint = await screen.findByTestId("map-before-attach-hint");
    expect(hint).toHaveTextContent(
      "If you enabled real-time webhooks, map sites before attaching the webhook in Datto RMM",
    );
    expect(hint).toHaveTextContent(/alerts from unmapped sites create pending tenants or are held for review/);
    expect(hint.parentElement).toContainElement(screen.getByRole("button", { name: "Skip for now" }));
  });
});
