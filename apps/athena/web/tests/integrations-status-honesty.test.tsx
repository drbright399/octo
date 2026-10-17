import { afterEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import IntegrationsTab from "@/pages/settings/integrations";
import { listIntegrations } from "@/lib/api";
import { STATUS_REFRESH_MS } from "@/lib/integration-status";
import type { MeResponse } from "@/contracts/operator";

/**
 * Status honesty on the integration card. In production a Datto API user with
 * no access had every poll answered 403 while its card read "connected /
 * started". The backend now flips the instance to `error` with an actionable
 * detail; the card has to make that impossible to miss — not a grey line.
 *
 * The real `@/lib/api` runs against a stubbed fetch.
 */

const FORBIDDEN_DETAIL =
  "Datto accepted the API key, but this API user may not read the account (HTTP 403). " +
  "In Datto RMM open Setup > Users, click the API user and, next to Generate API Keys, set " +
  "its API Security Level (and API Component Level) to one that covers the sites, devices " +
  "and alerts Athena should read, then Save User. Do NOT regenerate the API keys: the " +
  "stored pair works as soon as the access level is fixed. Datto's own message: " +
  "\"Authenticated user doesn\u2019t have access to this resource.\"";

function me(): MeResponse {
  return { operator_id: 1, username: "alice", email: "alice@example.test", role: ["admin"] } as MeResponse;
}

function stubInstance(instance: Record<string, unknown>) {
  // Mutable: a test changes `current` to play "the poller reported since".
  const state = { current: instance, calls: 0 };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url !== "/api/v1/integrations") throw new Error(`unexpected fetch: ${url}`);
      state.calls += 1;
      const instance = state.current;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          definitions: [{ slug: "datto", name: "Datto RMM", category: "rmm", description: "RMM alerts." }],
          instances: {
            datto: {
              slug: "datto",
              id: 7,
              configured_at: "2026-01-01T00:00:00.000Z",
              last_test_at: "2026-01-01T00:00:00.000Z",
              warnings: [],
              notes: [],
              ...instance,
            },
          },
        }),
      };
    }),
  );
  return state;
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("listIntegrations — observed health", () => {
  it("maps backend `error` and carries the last successful contact", async () => {
    stubInstance({
      status: "error",
      status_detail: FORBIDDEN_DETAIL,
      last_contact_ok_at: "2026-01-02T03:04:05.000Z",
    });
    const { instances } = await listIntegrations();
    expect(instances.datto?.status).toBe("error");
    expect(instances.datto?.status_detail).toBe(FORBIDDEN_DETAIL);
    expect(instances.datto?.last_contact_ok_at).toBe("2026-01-02T03:04:05.000Z");
    expect(instances.datto).not.toHaveProperty("contact_failure_kind");
  });

  it("carries WHY it failed and whether webhooks are a separate path", async () => {
    stubInstance({
      status: "error",
      status_detail: FORBIDDEN_DETAIL,
      contact_failure_kind: "forbidden",
      receives_webhooks: true,
    });
    const { instances } = await listIntegrations();
    expect(instances.datto?.contact_failure_kind).toBe("forbidden");
    expect(instances.datto?.receives_webhooks).toBe(true);
  });

  it("omits the hint when the server has none", async () => {
    stubInstance({ status: "running", status_detail: "started", last_contact_ok_at: null });
    const { instances } = await listIntegrations();
    expect(instances.datto?.status).toBe("connected");
    expect(instances.datto).not.toHaveProperty("last_contact_ok_at");
  });
});

describe("Integration card — a failing integration is unmistakable", () => {
  it("shows an alert block with the actionable detail and the last good contact", async () => {
    stubInstance({
      status: "error",
      status_detail: FORBIDDEN_DETAIL,
      last_contact_ok_at: "2026-01-02T03:04:05.000Z",
    });
    render(<IntegrationsTab me={me()} />);

    const problem = await screen.findByTestId("integration-problem-datto");
    expect(problem).toHaveAttribute("role", "alert");
    // No poll was observed failing (no contact_failure_kind) and nothing else
    // can deliver (no webhooks): the strong claim is the honest one here.
    expect(problem).toHaveTextContent("Not working — no data is being collected");
    expect(problem).toHaveTextContent("Setup > Users");
    expect(problem).toHaveTextContent("HTTP 403");
    // Alert styling, not the quiet grey status line.
    expect(problem.className).toMatch(/border-critical/);
    expect(problem.className).toMatch(/bg-critical/);
    expect(problem.className).not.toMatch(/text-text-dim/);

    const hint = within(problem).getByTestId("integration-last-contact-datto");
    expect(hint).toHaveTextContent(/^Last successful contact: .*2026-01-02T03:04:05\.000Z/);
    expect(hint.querySelector("time")).toHaveAttribute("datetime", "2026-01-02T03:04:05.000Z");

    const card = screen.getByTestId("integration-card-datto");
    expect(card.className).toMatch(/border-critical/);
    expect(within(card).getByText("error").className).toMatch(/text-critical/);
    // Never both healthy and failing.
    expect(within(card).queryByText("connected")).not.toBeInTheDocument();
  });

  it("says so when there has been no successful contact at all", async () => {
    stubInstance({ status: "error", status_detail: FORBIDDEN_DETAIL, last_contact_ok_at: null });
    render(<IntegrationsTab me={me()} />);
    expect(await screen.findByTestId("integration-last-contact-datto")).toHaveTextContent(
      "No successful contact since the service last started.",
    );
  });

  it("still raises the alert when the backend recorded no detail", async () => {
    stubInstance({ status: "error", status_detail: null });
    render(<IntegrationsTab me={me()} />);
    expect(await screen.findByTestId("integration-problem-datto")).toHaveTextContent(
      /last contact with the vendor failed/,
    );
  });

  it("a healthy integration keeps the quiet status line and raises no alert", async () => {
    stubInstance({
      status: "running",
      status_detail: "connected — last contact with the vendor succeeded",
      last_contact_ok_at: "2026-01-02T03:04:05.000Z",
    });
    render(<IntegrationsTab me={me()} />);
    expect(
      await screen.findByText("connected — last contact with the vendor succeeded"),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("integration-problem-datto")).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByTestId("integration-card-datto").className).not.toMatch(/border-critical/);
  });
});

describe("Integration card — the headline claims only what was observed", () => {
  it("a failing POLLER is not 'no data is being collected' while webhooks still arrive", async () => {
    stubInstance({
      status: "error",
      status_detail: FORBIDDEN_DETAIL,
      contact_failure_kind: "forbidden",
      receives_webhooks: true,
    });
    render(<IntegrationsTab me={me()} />);
    const problem = await screen.findByTestId("integration-problem-datto");
    expect(problem).toHaveTextContent(
      "Polling is failing — alerts are not being pulled from Datto RMM",
    );
    expect(problem).not.toHaveTextContent("no data is being collected");
    // A separate path — but with nothing observed arriving, the card does not
    // claim that it works (tests/integrations-webhook-reachability.test.tsx).
    const separate = within(problem).getByTestId("integration-webhooks-unaffected-datto");
    expect(separate).toHaveTextContent(/Inbound webhooks are a separate path/);
    expect(separate).toHaveTextContent(/none has been received yet/);
    expect(separate).not.toHaveTextContent(/not affected/);
    // The saved-instance guidance never tells the operator to kill the key.
    expect(problem).toHaveTextContent("Do NOT regenerate the API keys");
  });

  it("a poll-only instance gets no line about webhooks", async () => {
    stubInstance({
      status: "error",
      status_detail: FORBIDDEN_DETAIL,
      contact_failure_kind: "transport",
      receives_webhooks: false,
    });
    render(<IntegrationsTab me={me()} />);
    const problem = await screen.findByTestId("integration-problem-datto");
    expect(problem).toHaveTextContent("Polling is failing");
    expect(
      screen.queryByTestId("integration-webhooks-unaffected-datto"),
    ).not.toBeInTheDocument();
  });

  it("a start failure with webhooks armed does not claim that nothing arrives", async () => {
    stubInstance({ status: "error", status_detail: "adapter.start() raised", receives_webhooks: true });
    render(<IntegrationsTab me={me()} />);
    const problem = await screen.findByTestId("integration-problem-datto");
    expect(problem).toHaveTextContent("Not working");
    expect(problem).not.toHaveTextContent("no data is being collected");
  });
});

describe("Integrations page — status is re-read, not remembered", () => {
  const CONNECTED = { status: "running", status_detail: "started" };
  const FAILED = {
    status: "error",
    status_detail: FORBIDDEN_DETAIL,
    contact_failure_kind: "forbidden",
    receives_webhooks: true,
  };
  const RECOVERED = {
    status: "running",
    status_detail: "connected — last contact with the vendor succeeded",
  };

  it("a card that loaded as 'connected' turns red by itself once the poller has failed", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const backend = stubInstance(CONNECTED);
    render(<IntegrationsTab me={me()} />);
    expect(await screen.findByText("connected")).toBeInTheDocument();
    expect(screen.queryByTestId("integration-problem-datto")).not.toBeInTheDocument();

    backend.current = FAILED;              // the first poll was refused
    await act(async () => {
      await vi.advanceTimersByTimeAsync(STATUS_REFRESH_MS + 50);
    });
    expect(await screen.findByTestId("integration-problem-datto")).toHaveTextContent(
      "Polling is failing",
    );
    expect(screen.queryByText("connected")).not.toBeInTheDocument();
  });

  it("a red card clears by itself after the operator fixes the vendor side", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const backend = stubInstance(FAILED);
    render(<IntegrationsTab me={me()} />);
    expect(await screen.findByTestId("integration-problem-datto")).toBeInTheDocument();

    backend.current = RECOVERED;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(STATUS_REFRESH_MS + 50);
    });
    await waitFor(() =>
      expect(screen.queryByTestId("integration-problem-datto")).not.toBeInTheDocument(),
    );
    expect(screen.getByText("connected")).toBeInTheDocument();
  });

  it("coming back to the tab re-reads at once, and a hidden tab does not poll", async () => {
    const backend = stubInstance(FAILED);
    render(<IntegrationsTab me={me()} />);
    await screen.findByTestId("integration-problem-datto");
    const before = backend.calls;

    backend.current = RECOVERED;
    fireEvent(window, new Event("focus"));
    await waitFor(() =>
      expect(screen.queryByTestId("integration-problem-datto")).not.toBeInTheDocument(),
    );
    expect(backend.calls).toBe(before + 1);

    const visibility = vi.spyOn(document, "visibilityState", "get").mockReturnValue("hidden");
    fireEvent(document, new Event("visibilitychange"));
    expect(backend.calls).toBe(before + 1);
    visibility.mockRestore();
  });

  it("'Refresh status' on the error block re-reads now", async () => {
    const backend = stubInstance(FAILED);
    render(<IntegrationsTab me={me()} />);
    const problem = await screen.findByTestId("integration-problem-datto");
    expect(problem).toHaveTextContent(`updates by itself every ${STATUS_REFRESH_MS / 1000}s`);

    backend.current = RECOVERED;
    fireEvent.click(within(problem).getByTestId("integration-refresh-datto"));
    await waitFor(() =>
      expect(screen.queryByTestId("integration-problem-datto")).not.toBeInTheDocument(),
    );
  });

  it("stops polling when the tab is unmounted", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const backend = stubInstance(CONNECTED);
    const view = render(<IntegrationsTab me={me()} />);
    await screen.findByText("connected");
    view.unmount();
    const before = backend.calls;
    await vi.advanceTimersByTimeAsync(STATUS_REFRESH_MS * 3);
    expect(backend.calls).toBe(before);
  });
});
