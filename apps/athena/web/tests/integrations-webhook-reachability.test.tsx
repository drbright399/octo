import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import IntegrationsTab from "@/pages/settings/integrations";
import { listIntegrations } from "@/lib/api";
import type { MeResponse } from "@/contracts/operator";

/**
 * Webhook reachability on the integration card. In production a vendor's
 * "Test Webhook" answered 403 although the request never reached Athena:
 * something in front of the ingest hostname blocked it, and nothing on the
 * card said "no webhook has ever reached me" — so it read as Athena's fault.
 *
 * The real `@/lib/api` and the real card run against a stubbed fetch. The
 * vendor here is deliberately NOT Datto: this is for every webhook adapter.
 */

const GUIDANCE = [
  "If the vendor's own webhook test reports 403, \"blocked\", a timeout or an HTML error page " +
    "while this still says none has reached Athena, the request is being stopped BEFORE Athena. " +
    "This webhook URL never answers 403.",
  "Check what sits in front of the ingest hostname — CDN, WAF, bot protection, access gate.",
  "Confirm the vendor was given the INGEST hostname, not the console hostname.",
];

const NEVER = {
  enabled: true,
  usable: true,
  last_accepted_at: null,
  last_rejected_at: null,
  last_reject_reason: null,
  ever_reached: false,
  accepted_since_start: 0,
  rejected_since_start: 0,
  rejected_recent: 0,
  recent_rejections: [],
  last_reject_detail: null,
  guidance: GUIDANCE,
};

const REJECT_LINE =
  "12 rejected in the last hour: the X-Webhook-Token header was missing or did not verify — " +
  "re-copy the header value into the vendor exactly as it was shown when this integration was created.";

function me(): MeResponse {
  return { operator_id: 1, username: "alice", email: "alice@example.test", role: ["admin"] } as MeResponse;
}

function stubInstance(instance: Record<string, unknown>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url !== "/api/v1/integrations") throw new Error(`unexpected fetch: ${url}`);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          definitions: [
            { slug: "acme-rmm", name: "Acme RMM", category: "rmm", description: "Alerts." },
          ],
          instances: {
            "acme-rmm": {
              slug: "acme-rmm",
              id: 7,
              status: "running",
              status_detail: "connected — last contact with the vendor succeeded",
              configured_at: "2026-01-01T00:00:00.000Z",
              last_test_at: "2026-01-01T00:00:00.000Z",
              receives_webhooks: true,
              warnings: [],
              notes: [],
              ...instance,
            },
          },
        }),
      };
    }),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("listIntegrations — webhook receipt", () => {
  it("carries the receipt for an instance with webhooks on", async () => {
    stubInstance({ webhook_receipt: { ...NEVER, rejected_recent: 3 } });
    const { instances } = await listIntegrations();
    const receipt = instances["acme-rmm"]?.webhook_receipt;
    expect(receipt?.ever_reached).toBe(false);
    expect(receipt?.rejected_recent).toBe(3);
    expect(receipt?.guidance).toEqual(GUIDANCE);
  });

  it("omits it for a poll-only instance and for a backend that predates it", async () => {
    stubInstance({ webhook_receipt: { enabled: false } });
    expect((await listIntegrations()).instances["acme-rmm"]).not.toHaveProperty("webhook_receipt");
    stubInstance({});
    expect((await listIntegrations()).instances["acme-rmm"]).not.toHaveProperty("webhook_receipt");
  });

  it("fills a partial receipt with 'nothing observed', never a guess", async () => {
    stubInstance({ webhook_receipt: { enabled: true } });
    const receipt = (await listIntegrations()).instances["acme-rmm"]?.webhook_receipt;
    expect(receipt).toMatchObject({
      usable: false,
      ever_reached: false,
      last_accepted_at: null,
      recent_rejections: [],
      guidance: [],
    });
  });
});

describe("Integration card — has a webhook ever reached Athena?", () => {
  it("nothing has arrived: says so calmly and shows where to look — not an error", async () => {
    stubInstance({ webhook_receipt: NEVER });
    render(<IntegrationsTab me={me()} />);

    const block = await screen.findByTestId("integration-webhook-receipt-acme-rmm");
    expect(within(block).getByTestId("integration-webhook-last-acme-rmm")).toHaveTextContent(
      "No webhook has reached Athena yet.",
    );
    const guidance = within(block).getByTestId("integration-webhook-guidance-acme-rmm");
    // <details> permits no explicit role but "group" (ARIA in HTML); it must
    // not carry role="note" or "alert" — guidance is not a fault.
    expect(guidance).not.toHaveAttribute("role");
    expect(guidance).toHaveTextContent("That is normal until the vendor sends one");
    expect(guidance).toHaveTextContent("stopped BEFORE Athena");
    expect(guidance).toHaveTextContent("CDN, WAF, bot protection, access gate");
    expect(guidance).toHaveTextContent("INGEST hostname, not the console hostname");
    expect(within(guidance).getAllByRole("listitem")).toHaveLength(GUIDANCE.length);
    // Folded by default: a quiet client sits in this state for days, and
    // four bullets of edge checklist would make the card the tallest in the
    // grid. The one-line state + a question to open stay in view.
    expect(guidance.tagName).toBe("DETAILS");
    expect(guidance).not.toHaveAttribute("open");
    const opener = within(guidance).getByText(/The vendor says it sent one but nothing arrived\?/);
    expect(opener.tagName).toBe("SUMMARY");
    fireEvent.click(opener);
    expect(guidance).toHaveAttribute("open");

    // Calm: nothing on the card is an alert, and the card is not red.
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(guidance.className).not.toMatch(/critical|warning/);
    expect(screen.getByTestId("integration-card-acme-rmm").className).not.toMatch(/border-critical/);
    expect(screen.getByText("connected")).toBeInTheDocument();
  });

  it("accepted: a quiet 'Last webhook received' with the time, and no checklist", async () => {
    stubInstance({
      webhook_receipt: {
        ...NEVER,
        last_accepted_at: "2026-01-02T03:04:05.000Z",
        ever_reached: true,
        accepted_since_start: 4,
        guidance: [],
      },
    });
    render(<IntegrationsTab me={me()} />);

    const line = await screen.findByTestId("integration-webhook-last-acme-rmm");
    expect(line).toHaveTextContent(/^Last webhook received: .*2026-01-02T03:04:05\.000Z/);
    expect(line.querySelector("time")).toHaveAttribute("datetime", "2026-01-02T03:04:05.000Z");
    expect(screen.queryByTestId("integration-webhook-guidance-acme-rmm")).not.toBeInTheDocument();
    expect(screen.queryByTestId("integration-webhook-rejections-acme-rmm")).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("arriving but rejected: a warning with the count and the reason — and NOT the edge checklist", async () => {
    stubInstance({
      webhook_receipt: {
        ...NEVER,
        last_rejected_at: "2026-01-02T03:04:05.000Z",
        last_reject_reason: "bad_token",
        ever_reached: true,
        rejected_since_start: 12,
        rejected_recent: 12,
        recent_rejections: [REJECT_LINE],
        last_reject_detail: "the X-Webhook-Token header was missing or did not verify",
        guidance: [],
      },
    });
    render(<IntegrationsTab me={me()} />);

    const block = await screen.findByTestId("integration-webhook-receipt-acme-rmm");
    expect(within(block).getByTestId("integration-webhook-last-acme-rmm")).toHaveTextContent(
      "No webhook has been accepted yet — requests are reaching Athena but are being rejected.",
    );
    const rejections = within(block).getByTestId("integration-webhook-rejections-acme-rmm");
    expect(rejections).toHaveAttribute("role", "alert");
    expect(rejections).toHaveTextContent("12 rejected in the last hour");
    expect(rejections).toHaveTextContent("re-copy the header value");
    expect(rejections.className).toMatch(/text-warning/);
    // The request got here, so the edge is not the problem.
    expect(screen.queryByTestId("integration-webhook-guidance-acme-rmm")).not.toBeInTheDocument();
    expect(block).not.toHaveTextContent("No webhook has reached Athena yet");
  });

  it("both: keeps the last received time next to the rejections", async () => {
    stubInstance({
      webhook_receipt: {
        ...NEVER,
        last_accepted_at: "2026-01-02T03:04:05.000Z",
        last_rejected_at: "2026-01-02T03:05:00.000Z",
        last_reject_reason: "unmapped",
        ever_reached: true,
        rejected_recent: 2,
        recent_rejections: ["2 rejected in the last hour: the request verified, but the event was DROPPED."],
        guidance: [],
      },
    });
    render(<IntegrationsTab me={me()} />);
    const block = await screen.findByTestId("integration-webhook-receipt-acme-rmm");
    expect(block).toHaveTextContent("Last webhook received:");
    expect(block).toHaveTextContent("2 rejected in the last hour");
  });

  it("after a restart: the persisted last rejection is information, not an alert", async () => {
    stubInstance({
      webhook_receipt: {
        ...NEVER,
        last_rejected_at: "2026-01-02T03:04:05.000Z",
        last_reject_reason: "bad_token",
        ever_reached: true,
        last_reject_detail: "the X-Webhook-Token header was missing or did not verify",
        guidance: [],
      },
    });
    render(<IntegrationsTab me={me()} />);
    const last = await screen.findByTestId("integration-webhook-last-rejected-acme-rmm");
    expect(last).toHaveTextContent(/^Last rejected request: .* — the X-Webhook-Token header/);
    expect(last.querySelector("time")).toHaveAttribute("datetime", "2026-01-02T03:04:05.000Z");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByTestId("integration-webhook-guidance-acme-rmm")).not.toBeInTheDocument();
  });

  it("a poll-only integration shows nothing about webhooks", async () => {
    stubInstance({ receives_webhooks: false, webhook_receipt: { enabled: false } });
    render(<IntegrationsTab me={me()} />);
    await screen.findByTestId("integration-card-acme-rmm");
    expect(screen.queryByTestId("integration-webhook-receipt-acme-rmm")).not.toBeInTheDocument();
  });
});

describe("Integration card — never claims a webhook path works that cannot", () => {
  const POLL_FAILING = {
    status: "error",
    status_detail: "The vendor refused the read (HTTP 403).",
    contact_failure_kind: "forbidden",
  };

  it("no usable secret: no 'separate path' reassurance, and the headline is about polling", async () => {
    stubInstance({
      ...POLL_FAILING,
      receives_webhooks: false,
      warnings: ["Webhook Token is not set — inbound Acme RMM webhooks are rejected (401) until it is fixed."],
      webhook_receipt: { ...NEVER, usable: false, guidance: [] },
    });
    render(<IntegrationsTab me={me()} />);

    const problem = await screen.findByTestId("integration-problem-acme-rmm");
    expect(screen.queryByTestId("integration-webhooks-unaffected-acme-rmm")).not.toBeInTheDocument();
    expect(problem).not.toHaveTextContent(/not affected|separate path/);
    expect(screen.getByText(/rejected \(401\) until it is fixed/)).toBeInTheDocument();
    // The fix is the secret, not the edge.
    expect(screen.queryByTestId("integration-webhook-guidance-acme-rmm")).not.toBeInTheDocument();
  });

  it("a start failure with no usable secret is 'no data is being collected'", async () => {
    stubInstance({
      status: "error",
      status_detail: "adapter.start() raised",
      receives_webhooks: false,
      webhook_receipt: { ...NEVER, usable: false, guidance: [] },
    });
    render(<IntegrationsTab me={me()} />);
    expect(await screen.findByTestId("integration-problem-acme-rmm")).toHaveTextContent(
      "Not working — no data is being collected",
    );
  });

  it("usable but nothing received: says the path is separate AND that nothing has arrived", async () => {
    stubInstance({ ...POLL_FAILING, webhook_receipt: NEVER });
    render(<IntegrationsTab me={me()} />);
    const line = await screen.findByTestId("integration-webhooks-unaffected-acme-rmm");
    expect(line).toHaveTextContent("none has been received yet");
    expect(line).not.toHaveTextContent(/not affected/);
    expect(screen.getByTestId("integration-webhook-guidance-acme-rmm")).toBeInTheDocument();
  });

  it("usable and received: says when — evidence, not an assumption", async () => {
    stubInstance({
      ...POLL_FAILING,
      webhook_receipt: {
        ...NEVER,
        last_accepted_at: "2026-01-02T03:04:05.000Z",
        ever_reached: true,
        guidance: [],
      },
    });
    render(<IntegrationsTab me={me()} />);
    expect(await screen.findByTestId("integration-webhooks-unaffected-acme-rmm")).toHaveTextContent(
      /the last one was received .* ago/,
    );
  });
});
