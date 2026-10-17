import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import SourceHealthPanel from "@/components/source-health-panel";
import type { SourceHealthResponse, SourceHealthRow } from "@/lib/source-health";

/**
 * The dashboard's Source health widget: one view of integrations, ingest
 * tokens and buoys (analyst+), or — for a viewer, a client user — only their
 * own tenants' "alerts last received …" lines, never a vendor, an instance
 * or a warning.
 */

const URL_ = "/api/v1/dashboard/source-health";

function row(overrides: Partial<SourceHealthRow>): SourceHealthRow {
  return {
    id: "adapter:1",
    kind: "adapter",
    name: "Datto RMM",
    vendor: "datto",
    tenant_slug: null,
    status: "ok",
    stale: false,
    detail: null,
    freshness_basis: "contact",
    stale_after_sec: 120,
    last_event_at: "2026-09-28T11:50:00.000Z",
    last_event_age_sec: 600,
    last_contact_at: "2026-09-28T11:59:40.000Z",
    last_contact_age_sec: 20,
    ...overrides,
  };
}

const ADAPTER = row({});
const TOKEN = row({
  id: "token:4", kind: "ingest_token", name: "shim-acme", vendor: "wazuh",
  tenant_slug: "acme-corp", freshness_basis: "event", stale_after_sec: 86400,
  last_event_age_sec: 240, last_contact_at: null, last_contact_age_sec: null,
});
const BUOY = row({
  id: "buoy:acme-corp", kind: "buoy", name: "buoy-acme", vendor: null,
  tenant_slug: "acme-corp", freshness_basis: "heartbeat", stale_after_sec: 120,
  last_contact_age_sec: 30,
});

function full(sources: SourceHealthRow[], tenants: SourceHealthResponse["tenants"] = []): SourceHealthResponse {
  return { view: "full", generated_at: "2026-09-28T12:00:00.000Z", sources, tenants };
}

function stub(body: unknown, status = 200) {
  const fetchMock = vi.fn(async () => ({ ok: status < 300, status, json: async () => body }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("SourceHealthPanel — full view (analyst+)", () => {
  it("renders all three source kinds with counts and receive-clock ages", async () => {
    const fetchMock = stub(full([ADAPTER, TOKEN, BUOY]));
    render(<SourceHealthPanel />);
    await waitFor(() => screen.getByTestId("source-health-full"));
    expect(fetchMock).toHaveBeenCalledWith(URL_, expect.objectContaining({ credentials: "include" }));
    expect(screen.getByTestId("source-count-ok")).toHaveTextContent("3");
    // Every source is in the rotation.
    for (const name of ["Datto RMM", "shim-acme", "buoy-acme"]) {
      expect(screen.getByLabelText(`Show ${name}`)).toBeInTheDocument();
    }
    // The integration's card: its last poll and its last event.
    fireEvent.click(screen.getByLabelText("Show Datto RMM"));
    const card = screen.getByLabelText(/Source: Datto RMM, status ok/);
    expect(within(card).getByText("INTEGRATION")).toBeInTheDocument();
    expect(within(card).getByText("last poll")).toBeInTheDocument();
    expect(within(card).getByText("20s ago")).toBeInTheDocument();
    expect(within(card).getByText("10m ago")).toBeInTheDocument();
    // No Manage button: only buoys have a page to open.
    expect(within(card).queryByRole("button", { name: /Manage/ })).toBeNull();
  });

  it("floats a stale source to the front and says what was expected", async () => {
    const stale = row({
      id: "token:9", kind: "ingest_token", name: "zz-quiet-shim", tenant_slug: "globex",
      status: "degraded", stale: true, freshness_basis: "event", stale_after_sec: 86400,
      last_event_age_sec: 30 * 3600, detail: "No data received within the expected interval.",
    });
    stub(full([ADAPTER, stale]));
    render(<SourceHealthPanel />);
    const card = await waitFor(() => screen.getByLabelText(/Source: zz-quiet-shim, status degraded/));
    expect(within(card).getByText("INGEST")).toBeInTheDocument();
    expect(within(card).getByText("30h ago · expected within 24h")).toBeInTheDocument();
    expect(within(card).getByText("No data received within the expected interval.")).toBeInTheDocument();
    expect(screen.getByTestId("source-count-degraded")).toHaveTextContent("1");
  });

  it("a token whose posts are refused shows its last request next to its last accepted event", async () => {
    const refused = row({
      id: "token:5", kind: "ingest_token", name: "shim-globex", vendor: "wazuh", tenant_slug: "globex",
      status: "degraded", stale: false, freshness_basis: "event", stale_after_sec: 86400,
      last_event_at: "2026-09-28T11:40:00.000Z", last_event_age_sec: 20 * 60,
      last_contact_at: "2026-09-28T11:59:55.000Z", last_contact_age_sec: 5,
      detail: "Posts are arriving but being refused.",
    });
    stub(full([refused]));
    render(<SourceHealthPanel />);
    const card = await waitFor(() => screen.getByLabelText(/Source: shim-globex, status degraded/));
    expect(within(card).getByText("last event")).toBeInTheDocument();
    expect(within(card).getByText("20m ago")).toBeInTheDocument();
    expect(within(card).getByText("last request")).toBeInTheDocument();
    expect(within(card).getByText("5s ago")).toBeInTheDocument();
    expect(within(card).getByText("Posts are arriving but being refused.")).toBeInTheDocument();
  });

  it("a buoy card opens the Fleet page", async () => {
    stub(full([BUOY]));
    const push = vi.spyOn(window.history, "pushState");
    render(<SourceHealthPanel />);
    const card = await waitFor(() => screen.getByLabelText(/Source: buoy-acme/));
    expect(within(card).getByText("last heartbeat")).toBeInTheDocument();
    fireEvent.click(within(card).getByRole("button", { name: "Manage buoy-acme" }));
    expect(push).toHaveBeenLastCalledWith({}, "", "/fleet?focus=acme-corp");
  });

  it("empty: says nothing is connected", async () => {
    stub(full([]));
    render(<SourceHealthPanel />);
    await waitFor(() => screen.getByText("No sources connected yet. Add an integration in Settings."));
    expect(screen.queryByRole("list", { name: "source health counts" })).toBeNull();
  });

  it("lists the tenants a failing source delivers into — not the merely quiet ones", async () => {
    stub(full([ADAPTER], [
      { slug: "globex", display_name: "Globex", last_event_at: null, last_event_age_sec: 3 * 3600,
        state: "degraded" },
      { slug: "initech", display_name: "Initech", last_event_at: null, last_event_age_sec: null,
        state: "degraded" },
      { slug: "acme-corp", display_name: "Acme Corp", last_event_at: null, last_event_age_sec: 30 * 3600,
        state: "ok" },
    ]));
    render(<SourceHealthPanel />);
    const affected = await waitFor(() => screen.getByTestId("affected-tenants"));
    expect(affected).toHaveTextContent(
      "2 tenants fed by a failing source: Globex (last alert 3h ago), Initech (no alerts yet)",
    );
    // Thirty quiet hours with healthy sources is not listed.
    expect(affected).not.toHaveTextContent("Acme Corp");
  });

  it("lists no tenant when every source is healthy", async () => {
    stub(full([ADAPTER], [
      { slug: "acme-corp", display_name: "Acme Corp", last_event_at: null, last_event_age_sec: 30 * 3600,
        state: "ok" },
    ]));
    render(<SourceHealthPanel />);
    await waitFor(() => screen.getByTestId("source-health-full"));
    expect(screen.queryByTestId("affected-tenants")).toBeNull();
  });

  it("a failed first load says so", async () => {
    stub({}, 500);
    render(<SourceHealthPanel />);
    await waitFor(() => screen.getByText("Source health is unavailable right now."));
  });
});

describe("SourceHealthPanel — tenant view (viewer)", () => {
  const tenants: SourceHealthResponse["tenants"] = [
    { slug: "acme-corp", display_name: "Acme Corp", last_event_at: "2026-09-28T11:56:00.000Z",
      last_event_age_sec: 240, state: "ok" },
    { slug: "acme-west", display_name: "Acme West", last_event_at: null,
      last_event_age_sec: 30 * 3600, state: "ok" },
    { slug: "acme-lab", display_name: "Acme Lab", last_event_at: null,
      last_event_age_sec: null, state: "none" },
  ];

  it("shows only when each of their tenants last received alerts", async () => {
    stub({ view: "tenant", generated_at: "2026-09-28T12:00:00.000Z", sources: [], tenants });
    render(<SourceHealthPanel />);
    await waitFor(() => screen.getByTestId("source-health-tenant"));
    expect(screen.getByTestId("tenant-freshness-acme-corp")).toHaveTextContent(
      "Acme Corpalerts last received 4m ago",
    );
    // A quiet day is information, not a warning: no "longer than expected",
    // no warning dot.
    const west = screen.getByTestId("tenant-freshness-acme-west");
    expect(west).toHaveTextContent("alerts last received 30h ago");
    expect(west).not.toHaveTextContent(/expected/i);
    expect(west.querySelector(".bg-warning")).toBeNull();
    expect(screen.getByTestId("tenant-freshness-acme-lab")).toHaveTextContent("no alerts received yet");
    expect(screen.queryByTestId("source-health-full")).toBeNull();
  });

  it("never renders a source, even if one were sent", async () => {
    stub({ view: "tenant", generated_at: "2026-09-28T12:00:00.000Z", sources: [ADAPTER, TOKEN], tenants });
    const { container } = render(<SourceHealthPanel />);
    await waitFor(() => screen.getByTestId("source-health-tenant"));
    const text = (container.textContent ?? "").toLowerCase();
    for (const needle of ["datto", "wazuh", "shim", "integration", "ingest"]) {
      expect(text).not.toContain(needle);
    }
  });

  it("renders a degraded row, were one ever sent, as neutral information", async () => {
    stub({ view: "tenant", generated_at: "2026-09-28T12:00:00.000Z", sources: [], tenants: [
      { slug: "acme-corp", display_name: "Acme Corp", last_event_at: null,
        last_event_age_sec: 3 * 3600, state: "degraded" },
    ] });
    render(<SourceHealthPanel />);
    const line = await waitFor(() => screen.getByTestId("tenant-freshness-acme-corp"));
    expect(line).toHaveTextContent("alerts last received 3h ago");
    expect(line).not.toHaveTextContent(/expected|fail|degraded/i);
    expect(line.querySelector(".bg-warning")).toBeNull();
  });

  it("empty: no feeds", async () => {
    stub({ view: "tenant", generated_at: "2026-09-28T12:00:00.000Z", sources: [], tenants: [] });
    render(<SourceHealthPanel />);
    await waitFor(() => screen.getByText("No feeds to show."));
  });
});
