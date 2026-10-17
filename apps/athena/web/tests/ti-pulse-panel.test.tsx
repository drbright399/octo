import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";

import TiPulsePanel, { type TiPulseState } from "@/components/ti-pulse-panel";
import type { TiPulseItem, TiPulseResponse } from "@/contracts/indicator";

afterEach(() => cleanup());

const NOW = new Date("2026-09-28T12:00:00Z");

const IP_ROW: TiPulseItem = {
  tenant: "acme-corp",
  type: "ip",
  masked_value: "203.0.x.x",
  severity: "high",
  first_seen: "2026-09-28T10:00:00.000Z",
  last_seen: "2026-09-28T11:56:00.000Z",
  count: 3,
  source_kind: "integration",
  search_ref: "acme-corp:42",
};

const DOMAIN_ROW: TiPulseItem = {
  ...IP_ROW,
  tenant: "globex",
  type: "domain",
  masked_value: "ex*****.test",
  severity: "medium",
  count: 1,
  last_seen: "2026-09-28T09:00:00.000Z",
  search_ref: "globex:7",
};

const ready = (over: Partial<TiPulseResponse>): TiPulseState => ({
  status: "ready",
  data: {
    items: [],
    pool_status: "not_running",
    empty_reason: null,
    empty_detail: null,
    unreadable_tenants: 0,
    lookback_days: 7,
    ...over,
  },
});

describe("TiPulsePanel", () => {
  it("says it is loading before the first response", () => {
    render(<TiPulsePanel state={{ status: "loading" }} onOpen={vi.fn()} />);
    expect(screen.getByText(/loading indicators/i)).toBeInTheDocument();
  });

  it("tells a viewer the pulse is for analysts (403), with no rows", () => {
    render(<TiPulsePanel state={{ status: "forbidden" }} onOpen={vi.fn()} />);
    expect(screen.getByText(/available to analysts and above/i)).toBeInTheDocument();
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("says a failed load will retry", () => {
    render(<TiPulsePanel state={{ status: "error" }} onOpen={vi.fn()} />);
    expect(screen.getByText(/couldn't load the threat-intel pulse/i)).toBeInTheDocument();
  });

  it.each([
    ["no_indicators", "No indicators recorded yet. Only Wazuh- and UniFi-sourced events carry one."],
    ["none_recent", "No indicator sighted in the last 7 days."],
    ["no_tenants", "No active tenants are in your scope."],
    ["unavailable", "The indicator store couldn't be read just now."],
  ] as const)("renders the server's reason for an empty pulse (%s)", (reason, detail) => {
    render(
      <TiPulsePanel
        state={ready({ empty_reason: reason, empty_detail: detail })}
        onOpen={vi.fn()}
        now={NOW}
      />,
    );
    expect(screen.getByText(detail)).toBeInTheDocument();
    // No filter box over nothing, and the pool status is always stated.
    expect(screen.queryByRole("searchbox")).toBeNull();
    expect(screen.getByText(/cross-msp pool not running/i)).toBeInTheDocument();
  });

  it("renders masked rows with type, tenant, severity, count, provenance and age", () => {
    render(
      <TiPulsePanel state={ready({ items: [IP_ROW, DOMAIN_ROW] })} onOpen={vi.fn()} now={NOW} />,
    );
    expect(screen.getByText("203.0.x.x")).toBeInTheDocument();
    expect(screen.getByText("ex*****.test")).toBeInTheDocument();
    expect(screen.getByText("4m ago")).toBeInTheDocument();
    expect(screen.getByText("3 sightings")).toBeInTheDocument();
    expect(screen.getByText("1 sighting")).toBeInTheDocument();
    expect(screen.getAllByText("via integration")).toHaveLength(2);
    expect(screen.getByText("acme-corp")).toBeInTheDocument();
    expect(screen.getByText("high")).toBeInTheDocument();
    expect(screen.getByText(/cross-msp pool not running/i)).toBeInTheDocument();
  });

  it("says when the list is partial: a tenant's store couldn't be read", () => {
    render(
      <TiPulsePanel state={ready({ items: [IP_ROW], unreadable_tenants: 1 })} onOpen={vi.fn()} now={NOW} />,
    );
    expect(screen.getByTestId("ti-pulse-partial")).toHaveTextContent(
      "1 tenant's indicators couldn't be read — retrying.",
    );
    cleanup();
    render(
      <TiPulsePanel state={ready({ items: [IP_ROW], unreadable_tenants: 3 })} onOpen={vi.fn()} now={NOW} />,
    );
    expect(screen.getByTestId("ti-pulse-partial")).toHaveTextContent(
      "3 tenants' indicators couldn't be read — retrying.",
    );
  });

  it("says nothing about partial reads when every store was read", () => {
    render(<TiPulsePanel state={ready({ items: [IP_ROW] })} onOpen={vi.fn()} now={NOW} />);
    expect(screen.queryByTestId("ti-pulse-partial")).toBeNull();
  });

  it("opens the clicked row (its search_ref) — never a value", () => {
    const onOpen = vi.fn();
    render(
      <TiPulsePanel state={ready({ items: [IP_ROW, DOMAIN_ROW] })} onOpen={onOpen} now={NOW} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /203\.0\.x\.x in acme-corp/i }));
    expect(onOpen).toHaveBeenCalledTimes(1);
    expect(onOpen).toHaveBeenCalledWith(IP_ROW);
  });

  it("filters the visible rows by tenant or type", () => {
    render(
      <TiPulsePanel state={ready({ items: [IP_ROW, DOMAIN_ROW] })} onOpen={vi.fn()} now={NOW} />,
    );
    const box = screen.getByRole("searchbox", { name: /filter threat-intel pulse/i });
    fireEvent.change(box, { target: { value: "globex" } });
    expect(screen.queryByText("203.0.x.x")).toBeNull();
    expect(screen.getByText("ex*****.test")).toBeInTheDocument();
    fireEvent.change(box, { target: { value: "domain" } });
    expect(screen.getByText("ex*****.test")).toBeInTheDocument();
    fireEvent.change(box, { target: { value: "nothing-like-it" } });
    expect(screen.getByText(/no indicators match "nothing-like-it"/i)).toBeInTheDocument();
  });
});
