import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";

import AlertDrawer from "@/components/alert-drawer";
import type { AlertRow } from "@/contracts/alert";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const ALERT: AlertRow = {
  id: "acme:5001",
  severity: "critical",
  status: "open",
  source: "wazuh",
  tenant: "acme",
  title: "auth.brute_force",
  summary: "10 failed SSH attempts in 30s from 198.51.100.42",
  occurred_at: "2026-05-14T15:42:00Z",
};

describe("AlertDrawer", () => {
  it("renders metadata + summary", () => {
    render(<AlertDrawer alert={ALERT} onClose={vi.fn()} />);
    expect(screen.getByText("auth.brute_force")).toBeInTheDocument();
    expect(screen.getByText(/failed SSH attempts/i)).toBeInTheDocument();
    expect(screen.getByText(/wazuh/i)).toBeInTheDocument();
  });

  it("close button + Escape both call onClose", () => {
    const onClose = vi.fn();
    render(<AlertDrawer alert={ALERT} onClose={onClose} />);
    fireEvent.click(screen.getByLabelText(/close drawer/i));
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it("View-in-search pushes ?focus= URL + dispatches navigate event", () => {
    const navSpy = vi.fn();
    window.addEventListener("athena:navigate", navSpy);
    const pushSpy = vi.spyOn(window.history, "pushState");

    render(<AlertDrawer alert={ALERT} onClose={vi.fn()} />);
    fireEvent.click(screen.getByText(/view payload in \/search/i));

    // 2026-05-19: switched from localStorage stash → ?focus= URL param
    // so /search picks it up via URLSearchParams (matching the
    // ticket-window deep-link pattern). The encoded payload is the
    // alert.id verbatim ("acme:5001") with the `:` percent-encoded.
    expect(pushSpy).toHaveBeenCalledWith(
      {}, "",
      "/search/events?focus=acme%3A5001",
    );
    expect(navSpy).toHaveBeenCalled();
    window.removeEventListener("athena:navigate", navSpy);
    pushSpy.mockRestore();
  });

  it("Create-ticket stashes structured prefill payload + navigates", () => {
    const setItem = vi.spyOn(window.localStorage.__proto__, "setItem");
    const navSpy = vi.fn();
    window.addEventListener("athena:navigate", navSpy);

    render(<AlertDrawer alert={ALERT} onClose={vi.fn()} />);
    fireEvent.click(screen.getByText(/create ticket from this alert/i));

    // 2026-05-19: stashes a JSON-encoded NewTicketPrefill object under
    // `athena.tickets.create_from_alert`. /tickets consumes + clears it
    // on mount, opening the NewTicketModal pre-filled with these
    // fields so the operator reviews + posts.
    const stashed = setItem.mock.calls.find(
      (args) => args[0] === "athena.tickets.create_from_alert",
    );
    expect(stashed).toBeDefined();
    const parsed = JSON.parse(stashed![1] as string);
    expect(parsed.tenant).toBe(ALERT.tenant);
    expect(parsed.source_event_id).toBe(5001);
    expect(parsed.title).toBe(ALERT.title);
    expect(parsed.severity).toBe(ALERT.severity);
    expect(parsed.description).toContain(ALERT.source);

    expect(navSpy).toHaveBeenCalled();
    window.removeEventListener("athena:navigate", navSpy);
  });
});

describe("AlertDrawer — where / device only for the alerts entity resolution reads", () => {
  it("asks for a resolution on a NextDNS block, never on a Wazuh alert", async () => {
    const urls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      urls.push(url);
      return { ok: true, status: 200, json: async () => ({ notes: [] }) };
    }));
    try {
      render(<AlertDrawer alert={ALERT} onClose={vi.fn()} />);
      await new Promise((r) => setTimeout(r, 10));
      expect(urls.some((u) => u.includes("/entity/"))).toBe(false);
      cleanup();
      render(<AlertDrawer alert={{ ...ALERT, id: "acme:5002", source: "nextdns" }} onClose={vi.fn()} />);
      await new Promise((r) => setTimeout(r, 10));
      expect(urls.some((u) => u.includes("/entity/acme/events/5002/resolution"))).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
