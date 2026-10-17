import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import {
  DefaultAttentionRotator,
  type RotatableSource,
} from "@widgets/default-attention-rotator";

const make = (
  id: string,
  services: RotatableSource["services"],
  overrides: Partial<RotatableSource> = {},
): RotatableSource => ({
  id,
  name: id,
  services,
  ...overrides,
});

describe("DefaultAttentionRotator", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders the empty state when there are no sources", () => {
    render(<DefaultAttentionRotator sources={[]} />);
    expect(screen.getByText("No sources.")).toBeInTheDocument();
  });

  it("floats a source with a 'down' service to the top", () => {
    const a = make("ok-buoy", [{ id: "s1", name: "OpenCanary", status: "ok" }]);
    const b = make("down-buoy", [{ id: "s1", name: "OpenCanary", status: "down" }]);
    const c = make("degraded-buoy", [{ id: "s1", name: "OpenCanary", status: "degraded" }]);
    render(<DefaultAttentionRotator sources={[a, b, c]} />);
    // First card visible should be the "down" buoy.
    expect(screen.getByLabelText(/Source: down-buoy/i)).toBeInTheDocument();
  });

  it("ranks down > degraded > pending > unknown > ok", () => {
    const sources = [
      make("ok", [{ id: "x", name: "x", status: "ok" }]),
      make("unknown", [{ id: "x", name: "x", status: "unknown" }]),
      make("pending", [{ id: "x", name: "x", status: "pending" }]),
      make("degraded", [{ id: "x", name: "x", status: "degraded" }]),
      make("down", [{ id: "x", name: "x", status: "down" }]),
    ];
    render(<DefaultAttentionRotator sources={sources} intervalMs={1000} />);
    expect(screen.getByLabelText(/Source: down/i)).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(screen.getByLabelText(/Source: degraded/i)).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(screen.getByLabelText(/Source: pending/i)).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(screen.getByLabelText(/Source: unknown/i)).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(screen.getByLabelText(/Source: ok/i)).toBeInTheDocument();
  });

  it("manual next advances and pauses the rotation", () => {
    const sources = [
      make("a", [{ id: "x", name: "x", status: "ok" }]),
      make("b", [{ id: "x", name: "x", status: "ok" }]),
      make("c", [{ id: "x", name: "x", status: "ok" }]),
    ];
    render(<DefaultAttentionRotator sources={sources} intervalMs={1000} />);
    expect(screen.getByLabelText(/Source: a/i)).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText("Next source"));
    expect(screen.getByLabelText(/Source: b/i)).toBeInTheDocument();
    expect(screen.getByText(/paused/)).toBeInTheDocument();

    // Advance time — should NOT auto-rotate because we paused.
    act(() => {
      vi.advanceTimersByTime(5000);
    });
    expect(screen.getByLabelText(/Source: b/i)).toBeInTheDocument();
  });

  it("auto-rotates through sources at intervalMs", () => {
    const sources = [
      make("a", [{ id: "x", name: "x", status: "ok" }]),
      make("b", [{ id: "x", name: "x", status: "ok" }]),
    ];
    render(<DefaultAttentionRotator sources={sources} intervalMs={1000} />);
    expect(screen.getByLabelText(/Source: a/i)).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(screen.getByLabelText(/Source: b/i)).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(screen.getByLabelText(/Source: a/i)).toBeInTheDocument();
  });

  it("pauses while hovered when pauseOnHover is true (default)", () => {
    const sources = [
      make("a", [{ id: "x", name: "x", status: "ok" }]),
      make("b", [{ id: "x", name: "x", status: "ok" }]),
    ];
    const { container } = render(
      <DefaultAttentionRotator sources={sources} intervalMs={1000} />,
    );
    const carousel = container.querySelector('[aria-roledescription="carousel"]');
    expect(carousel).not.toBeNull();
    fireEvent.mouseEnter(carousel!);
    act(() => {
      vi.advanceTimersByTime(3000);
    });
    expect(screen.getByLabelText(/Source: a/i)).toBeInTheDocument();
    fireEvent.mouseLeave(carousel!);
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(screen.getByLabelText(/Source: b/i)).toBeInTheDocument();
  });

  it("renders services sorted by status with a status pill per service", () => {
    const buoy = make("test", [
      { id: "ok-svc", name: "OK Service", status: "ok" },
      { id: "down-svc", name: "Down Service", status: "down", detail: "boom" },
      { id: "deg-svc", name: "Degraded Service", status: "degraded" },
    ]);
    render(<DefaultAttentionRotator sources={[buoy]} />);
    const list = screen.getAllByRole("list");
    // The first list is service rows (the page-dot bar uses role="tablist", not "list")
    const items = within(list[0]!).getAllByRole("listitem");
    expect(items).toHaveLength(3);
    expect(items[0]).toHaveTextContent("Down Service");
    expect(items[1]).toHaveTextContent("Degraded Service");
    expect(items[2]).toHaveTextContent("OK Service");
  });

  it("clicking a page dot jumps to that source", () => {
    const sources = [
      make("a", [{ id: "x", name: "x", status: "ok" }]),
      make("b", [{ id: "x", name: "x", status: "ok" }]),
      make("c", [{ id: "x", name: "x", status: "ok" }]),
    ];
    render(<DefaultAttentionRotator sources={sources} />);
    fireEvent.click(screen.getByLabelText("Show c"));
    expect(screen.getByLabelText(/Source: c/i)).toBeInTheDocument();
  });

  it("is single-source-safe (no rotation when only one source)", () => {
    const sources = [make("solo", [{ id: "x", name: "x", status: "ok" }])];
    render(<DefaultAttentionRotator sources={sources} intervalMs={500} />);
    expect(screen.getByText("1 of 1")).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(2000);
    });
    expect(screen.getByLabelText(/Source: solo/i)).toBeInTheDocument();
  });

  it("renders user-supplied source names as text only (no HTML injection)", () => {
    const malicious = make("xss", [{ id: "x", name: "<script>alert(1)</script>", status: "down" }], {
      name: "<img src=x onerror=alert(1)>",
    });
    const { container } = render(<DefaultAttentionRotator sources={[malicious]} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
  });

  it("renders the onSelect button only when onSelect is provided", () => {
    const source = make("buoy:acme", [{ id: "s", name: "wazuh-agent", status: "ok" }]);
    const { rerender } = render(<DefaultAttentionRotator sources={[source]} />);
    expect(screen.queryByText("Manage →")).toBeNull();

    rerender(
      <DefaultAttentionRotator sources={[source]} onSelect={() => undefined} />,
    );
    expect(screen.getByText("Manage →")).toBeInTheDocument();
  });

  it("calls onSelect with the current source when 'Manage →' is clicked", () => {
    const onSelect = vi.fn();
    const a = make("buoy:acme", [{ id: "s", name: "wazuh-agent", status: "ok" }]);
    const b = make("buoy:globex", [{ id: "s", name: "wazuh-agent", status: "down" }]);
    render(<DefaultAttentionRotator sources={[a, b]} onSelect={onSelect} />);
    // 'globex' floats to the top (worst status = down) — that's the
    // current card on first render.
    fireEvent.click(screen.getByText("Manage →"));
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect.mock.calls[0]![0].id).toBe("buoy:globex");
  });

  it("uses selectLabel override when provided", () => {
    const source = make("buoy:acme", [{ id: "s", name: "wazuh-agent", status: "ok" }]);
    render(
      <DefaultAttentionRotator
        sources={[source]}
        onSelect={() => undefined}
        selectLabel="Open drawer →"
      />,
    );
    expect(screen.getByText("Open drawer →")).toBeInTheDocument();
    expect(screen.queryByText("Manage →")).toBeNull();
  });
});
