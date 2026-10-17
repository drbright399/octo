import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";

import TopbarSyntheticToggle from "@/components/topbar-synthetic-toggle";

const ok = (body: object): Response =>
  new Response(JSON.stringify(body), { status: 200 });
const notFound = (): Response => new Response("nope", { status: 404 });

const STATUS = (over: Record<string, unknown> = {}) => ({
  allowed: true, enabled: false, emitted_total: 0,
  last_emit_at: null, interval_seconds: 10, ...over,
});

let originalFetch: typeof fetch;
beforeEach(() => { originalFetch = global.fetch; });
afterEach(() => { global.fetch = originalFetch; vi.restoreAllMocks(); });

describe("TopbarSyntheticToggle", () => {
  it("shows OFF then flips to ON when clicked", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(ok(STATUS({ enabled: false })))     // initial GET
      .mockResolvedValueOnce(ok(STATUS({ enabled: true })));     // POST toggle
    global.fetch = fetchMock;

    render(<TopbarSyntheticToggle />);
    await waitFor(() => expect(screen.getByText(/synth · off/i)).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => expect(screen.getByText(/synth · on/i)).toBeInTheDocument());

    // Second call was the POST with the toggled value.
    expect(fetchMock).toHaveBeenLastCalledWith(
      "/api/v1/dev/synthetic-traffic",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ enabled: true }),
      }),
    );
  });

  it("renders nothing when the backend route is unavailable (prod / non-dev)", async () => {
    global.fetch = vi.fn().mockResolvedValue(notFound());
    const { container } = render(<TopbarSyntheticToggle />);
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });
});
