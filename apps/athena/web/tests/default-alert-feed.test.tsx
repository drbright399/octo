import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, within } from "@testing-library/react";
import { DefaultAlertFeed } from "@widgets/default-alert-feed";
import type { AlertRow } from "@/contracts/alert";

const NOW = new Date("2026-05-06T13:30:00Z");

const ROW = (over: Partial<AlertRow> = {}): AlertRow => ({
  id: "a1",
  severity: "medium",
  status: "open",
  source: "test-source",
  tenant: "test-tenant",
  title: "Test alert",
  summary: "Test summary",
  occurred_at: "2026-05-06T13:25:00Z",
  ...over,
});

describe("DefaultAlertFeed", () => {
  it("renders an empty state when there are no rows", () => {
    render(<DefaultAlertFeed rows={[]} />);
    expect(screen.getByText("No alerts.")).toBeInTheDocument();
    expect(screen.getByTestId("alert-feed-count")).toHaveTextContent("0 alerts");
  });

  it("renders a loading state instead of the empty state", () => {
    render(<DefaultAlertFeed rows={[]} loading />);
    expect(screen.getByText("Loading alerts…")).toHaveAttribute("aria-busy", "true");
  });

  it("renders an error state above the list", () => {
    render(<DefaultAlertFeed rows={[ROW()]} error="bridge unreachable" />);
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("bridge unreachable");
    expect(screen.queryByRole("listitem")).not.toBeInTheDocument();
  });

  it("sorts rows by severity then by recency", () => {
    const rows: AlertRow[] = [
      ROW({ id: "low-old", severity: "low", occurred_at: "2026-05-06T10:00:00Z", title: "low-old" }),
      ROW({ id: "crit-new", severity: "critical", occurred_at: "2026-05-06T13:25:00Z", title: "crit-new" }),
      ROW({ id: "crit-old", severity: "critical", occurred_at: "2026-05-06T08:00:00Z", title: "crit-old" }),
      ROW({ id: "high-mid", severity: "high", occurred_at: "2026-05-06T12:00:00Z", title: "high-mid" }),
    ];
    render(<DefaultAlertFeed rows={rows} now={NOW} />);
    const items = screen.getAllByRole("listitem");
    expect(items).toHaveLength(4);
    expect(items[0]).toHaveTextContent("crit-new");
    expect(items[1]).toHaveTextContent("crit-old");
    expect(items[2]).toHaveTextContent("high-mid");
    expect(items[3]).toHaveTextContent("low-old");
  });

  it("respects maxRows", () => {
    const rows = Array.from({ length: 10 }, (_, i) =>
      ROW({ id: `r${i}`, title: `Alert ${i}` }),
    );
    render(<DefaultAlertFeed rows={rows} maxRows={3} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(screen.getByTestId("alert-feed-count")).toHaveTextContent("10 alerts");
  });

  it("invokes onSelect with the row on click", () => {
    const onSelect = vi.fn();
    const row = ROW({ id: "click-target", title: "click me" });
    render(<DefaultAlertFeed rows={[row]} onSelect={onSelect} />);
    fireEvent.click(screen.getByRole("button"));
    expect(onSelect).toHaveBeenCalledWith(row);
  });

  it("invokes onSelect on Enter key for a11y", () => {
    const onSelect = vi.fn();
    const row = ROW({ id: "kbd-target" });
    render(<DefaultAlertFeed rows={[row]} onSelect={onSelect} />);
    fireEvent.keyDown(screen.getByRole("button"), { key: "Enter" });
    expect(onSelect).toHaveBeenCalledWith(row);
  });

  it("does not render rows as button when onSelect is omitted", () => {
    render(<DefaultAlertFeed rows={[ROW()]} />);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("renders user-supplied content as text only (no HTML injection)", () => {
    const malicious = ROW({
      id: "xss",
      title: "<img src=x onerror=alert(1)>",
      summary: '<script>alert("xss")</script>',
    });
    const { container } = render(<DefaultAlertFeed rows={[malicious]} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    const item = screen.getByRole("listitem");
    expect(within(item).getByText(/<img src=x onerror=alert\(1\)>/)).toBeInTheDocument();
  });

  it("renders a relative time using the injected `now`", () => {
    const row = ROW({ occurred_at: "2026-05-06T13:25:00Z" });
    render(<DefaultAlertFeed rows={[row]} now={NOW} />);
    const time = screen.getByRole("listitem").querySelector("time");
    expect(time).toHaveTextContent("5m ago");
    expect(time).toHaveAttribute("datetime", "2026-05-06T13:25:00Z");
  });
});
