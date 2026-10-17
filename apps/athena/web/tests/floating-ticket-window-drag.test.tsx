import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { FloatingTicketWindow } from "@/components/floating-ticket-window";
import type { TicketDetail } from "@/lib/tickets";

// Minimal fixture — with loading=true the body renders a skeleton, so only
// the header (drag handle) needs real fields. Cast keeps the test focused
// on drag behavior rather than the full ticket shape.
const ticket = {
  id: 7, severity: "low", client_slug: "acme", status: "open", title: "x",
} as unknown as TicketDetail;

let originalFetch: typeof fetch;
beforeEach(() => {
  originalFetch = global.fetch;
  // Any notes/detail fetch the body may attempt resolves to empty.
  global.fetch = vi.fn().mockResolvedValue(new Response("[]", { status: 200 }));
});
afterEach(() => { global.fetch = originalFetch; vi.restoreAllMocks(); });

describe("FloatingTicketWindow drag", () => {
  it("moves the window when the header is dragged", () => {
    // Regression: the old effect armed off a ref mutation (no re-render),
    // so pointerdown never attached the move listeners and dragging only
    // worked if an unrelated render happened to fire. This asserts a
    // pointerdown→pointermove actually repositions the window.
    render(
      <FloatingTicketWindow
        ticket={ticket} loading error={null}
        onClose={() => {}} onUpdated={() => {}}
      />,
    );
    const dialog = screen.getByRole("dialog");
    const handle = dialog.querySelector(".cursor-move") as HTMLElement;
    expect(handle).toBeTruthy();

    const before = dialog.style.left;
    // jsdom doesn't populate clientX/Y on PointerEvent; dispatch MouseEvents
    // (which do carry coords in jsdom) under the pointer event type names.
    fireEvent(handle, new MouseEvent("pointerdown",
      { clientX: 500, clientY: 300, bubbles: true }));
    fireEvent(window, new MouseEvent("pointermove",
      { clientX: 560, clientY: 360, bubbles: true }));
    const after = dialog.style.left;

    expect(after).not.toBe(before);
  });

  it("does not start a drag from the close button", () => {
    render(
      <FloatingTicketWindow
        ticket={ticket} loading error={null}
        onClose={() => {}} onUpdated={() => {}}
      />,
    );
    const dialog = screen.getByRole("dialog");
    const closeBtn = screen.getByText("✕");
    const before = dialog.style.left;
    fireEvent(closeBtn, new MouseEvent("pointerdown",
      { clientX: 500, clientY: 300, bubbles: true }));
    fireEvent(window, new MouseEvent("pointermove",
      { clientX: 560, clientY: 360, bubbles: true }));
    expect(dialog.style.left).toBe(before);  // no drag initiated
  });
});
