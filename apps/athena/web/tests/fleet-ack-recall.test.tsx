/**
 * v0.17.5 — after an acknowledgement (Rick, 2026-10-08: he acknowledged a
 * client's alerts, then learned the context and could not go back to add
 * it): in the drawer's "show acknowledged" view an acknowledged row lists
 * its follow-up notes (newest last) and offers "add note" (inline, ≤ 500)
 * and "recall" (an in-app alertdialog: focus on Cancel, Esc cancels — the
 * drawer stays —, a reason of 10+ characters); either re-reads the list. An
 * open alert whose acknowledgement was recalled says who recalled it and
 * why. A client user gets none of it. Fixtures are made up: Example / Acme
 * names, TEST-NET addresses.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import type { FleetLayer, FleetSite, SiteAlert } from "@/contracts/fleet";
import FleetSiteDrawer from "@/components/fleet-site-drawer";
import { RECALL_EXPLAINED } from "@/components/site-alert-row";

const ok = (body: object, status = 200): Response =>
  new Response(JSON.stringify(body), { status });

function layer(name: string): FleetLayer {
  return { name: name as FleetLayer["name"], present: true, state: "ok", scope: "site",
           reasons: [], data: {}, as_of: "2026-10-08T12:00:00.000Z" };
}

function site(o: Partial<FleetSite> = {}): FleetSite {
  return {
    key: "u-00000000000000000003", kind: "site", name: "Example Bakery", tenant_slug: "example-bakery",
    tenant_name: "Example Bakery", console_name: "console-3", state: "ok", reason: "",
    reasons: [], location: null,
    layers: { threat: layer("threat"), network: layer("network"), security: layer("security"),
              endpoints: layer("endpoints"), buoy: { ...layer("buoy"), present: false, state: "absent" } },
    links: [], vendor_ref: null, tenant_sites: 1, partial: false, ...o,
  };
}

const ACKED: SiteAlert = {
  event_id: 44, occurred_at: "2026-10-08T11:00:00.000Z", severity: "high", source: "datto",
  title: "Example Datto alert", tenant_wide: false, status: "acknowledged", can_expect: true,
  network: false, rule: null, new_since_ack: 0,
  ack: { verdict_id: 9, by: 7, by_name: "Alice Example", at: "2026-10-08T11:30:00.000Z",
         note: "DNS agents gone", repeat_until: null, by_repeat: false, recalled: null,
         notes: [{ by: 8, by_name: "Bob Example", at: "2026-10-08T11:40:00.000Z", note: "partner removed them" },
                 { by: 7, by_name: "Alice Example", at: "2026-10-08T11:50:00.000Z", note: "ticket opened" }] },
};

const RECALLED: SiteAlert = {
  event_id: 45, occurred_at: "2026-10-08T10:00:00.000Z", severity: "high", source: "datto",
  title: "Another Datto alert", tenant_wide: false, status: "open", can_expect: true,
  network: false, rule: null, new_since_ack: 0,
  ack: { verdict_id: 10, by: 7, by_name: "Alice Example", at: "2026-10-08T10:30:00.000Z",
         note: "seen", repeat_until: null, by_repeat: false,
         recalled: { by: 8, by_name: "Bob Example", at: "2026-10-08T12:00:00.000Z",
                     reason: "the partner did NOT remove this one" },
         notes: [{ by: 8, by_name: "Bob Example", at: "2026-10-08T12:01:00.000Z", note: "asked the partner" }] },
};

let originalFetch: typeof fetch;
beforeEach(() => { originalFetch = global.fetch; });
afterEach(() => { global.fetch = originalFetch; cleanup(); vi.restoreAllMocks(); });

interface Call { method: string; url: string; body?: unknown }

function serve(items: SiteAlert[], calls: Call[], post?: () => Response): void {
  global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    calls.push({ method, url, ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}) });
    if (method === "POST") {
      return Promise.resolve(post ? post() : ok({ followup_id: 1, verdict_id: 9, event_id: 44,
        tenant_slug: "example-bakery", kind: "note", at: "2026-10-08T12:30:00.000Z" }));
    }
    if (url.includes("/alerts")) return Promise.resolve(ok({ key: "x", items, hidden: 0,
      include_acknowledged: url.endsWith("?include=acknowledged") }));
    return Promise.resolve(ok({}));
  }) as unknown as typeof fetch;
}

const lists = (calls: Call[]): number => calls.filter((c) => c.method === "GET" && c.url.includes("/alerts")).length;
const posts = (calls: Call[]): Call[] => calls.filter((c) => c.method === "POST");

async function openHandled(calls: Call[], items: SiteAlert[] = [ACKED, RECALLED],
                           extra: { onClose?: () => void; onIncidentChanged?: () => void } = {},
                           post?: () => Response): Promise<void> {
  serve(items, calls, post);
  render(<FleetSiteDrawer site={site()} view="operator" onClose={extra.onClose ?? (() => undefined)}
                          callerRole="analyst"
                          {...(extra.onIncidentChanged ? { onIncidentChanged: extra.onIncidentChanged } : {})} />);
  fireEvent.click(await screen.findByTestId("alerts-show-acknowledged"));
  await screen.findByTestId("site-alert-44");
  await waitFor(() => expect(calls.at(-1)!.url).toContain("?include=acknowledged"));
}

describe("after an acknowledgement", () => {
  it("lists the notes newest last and offers add note / recall on an acknowledged row only", async () => {
    const calls: Call[] = [];
    await openHandled(calls);
    const row = screen.getByTestId("site-alert-44");
    expect(within(row).getByTestId("alert-status-44"))
      .toHaveTextContent("acknowledged by Alice Example");
    expect(within(row).getByTestId("alert-status-44")).toHaveTextContent("DNS agents gone");
    const notes = Array.from(within(row).getByTestId("ack-notes-44").querySelectorAll("li"));
    expect(notes).toHaveLength(2);                                   // oldest first, newest last
    expect(notes[0]).toHaveTextContent("note by Bob Example");
    expect(notes[0]).toHaveTextContent("partner removed them");
    expect(notes[1]).toHaveTextContent("note by Alice Example");
    expect(notes[1]).toHaveTextContent("ticket opened");
    expect(within(row).getByTestId("followup-note-open-44")).toBeInTheDocument();
    expect(within(row).getByTestId("recall-open-44")).toBeInTheDocument();
    // The recalled one is OPEN again: who recalled it and why, its notes —
    // no second recall, no note form (it needs attention: acknowledge again).
    const back = screen.getByTestId("site-alert-45");
    expect(back).toHaveAttribute("data-status", "open");
    expect(within(back).getByTestId("alert-recalled-45"))
      .toHaveTextContent("acknowledgement recalled by Bob Example");
    expect(within(back).getByTestId("alert-recalled-45"))
      .toHaveTextContent("the partner did NOT remove this one");
    expect(within(back).getByTestId("alert-status-45")).toHaveTextContent("it was acknowledged by Alice Example");
    expect(within(back).getByTestId("ack-notes-45")).toHaveTextContent("asked the partner");
    expect(within(back).queryByTestId("recall-open-45")).toBeNull();
    expect(within(back).queryByTestId("followup-note-open-45")).toBeNull();
    expect(within(back).getByTestId("ack-open-45")).toBeInTheDocument();
  });

  it("adds a note (≤ 500, whitespace collapsed) and re-reads the list", async () => {
    const calls: Call[] = [];
    const changed = vi.fn();
    await openHandled(calls, [ACKED], { onIncidentChanged: changed });
    fireEvent.click(screen.getByTestId("followup-note-open-44"));
    const save = screen.getByTestId("followup-note-save-44");
    expect(save).toBeDisabled();                                   // nothing to say yet
    const box = screen.getByTestId("followup-note-44");
    expect(box).toHaveAttribute("maxLength", "500");
    fireEvent.change(box, { target: { value: "   " } });
    expect(save).toBeDisabled();
    fireEvent.change(box, { target: { value: "  the partner   confirmed by phone " } });
    const before = lists(calls);
    fireEvent.click(save);
    await waitFor(() => expect(changed).toHaveBeenCalled());
    expect(posts(calls)).toEqual([{
      method: "POST", url: "/api/v1/alerts/example-bakery/verdicts/9/notes",
      body: { note: "the partner confirmed by phone" } }]);
    await waitFor(() => expect(lists(calls)).toBe(before + 1));
    expect(calls.at(-1)!.url).toContain("?include=acknowledged");
    expect(screen.queryByTestId("followup-note-form-44")).toBeNull();
  });

  it("cancels a note without a call", async () => {
    const calls: Call[] = [];
    await openHandled(calls, [ACKED]);
    fireEvent.click(screen.getByTestId("followup-note-open-44"));
    fireEvent.change(screen.getByTestId("followup-note-44"), { target: { value: "never mind" } });
    fireEvent.click(screen.getByTestId("followup-note-cancel-44"));
    expect(screen.queryByTestId("followup-note-form-44")).toBeNull();
    expect(posts(calls)).toEqual([]);
  });
});

describe("the recall dialog", () => {
  it("is an alertdialog that says what a recall does, with focus on Cancel", async () => {
    const calls: Call[] = [];
    await openHandled(calls, [ACKED]);
    fireEvent.click(screen.getByTestId("recall-open-44"));
    const dialog = screen.getByRole("alertdialog", { name: "Recall this acknowledgement?" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveTextContent(RECALL_EXPLAINED);
    expect(RECALL_EXPLAINED).toBe("The alert returns to 'needs attention' and counts towards the site's colour again. The acknowledgement stays in the history.");
    expect(document.activeElement).toBe(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(within(dialog).queryByText(/repeats of this alert/)).toBeNull();
  });

  it("Esc cancels — the drawer stays open — and so does Cancel; nothing is sent", async () => {
    const calls: Call[] = [];
    const onClose = vi.fn();
    await openHandled(calls, [ACKED], { onClose });
    fireEvent.click(screen.getByTestId("recall-open-44"));
    fireEvent.change(screen.getByTestId("recall-reason-44"), { target: { value: "a reason long enough" } });
    fireEvent.keyDown(screen.getByTestId("recall-reason-44"), { key: "Escape" });
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByTestId("fleet-site-drawer")).toBeInTheDocument();
    expect(document.activeElement).toBe(screen.getByTestId("recall-open-44"));   // back to the opener
    fireEvent.click(screen.getByTestId("recall-open-44"));
    // A fresh dialog: the reason typed before is gone.
    expect(screen.getByTestId("recall-reason-44")).toHaveValue("");
    fireEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(posts(calls)).toEqual([]);
  });

  it("needs a reason of at least 10 characters", async () => {
    const calls: Call[] = [];
    await openHandled(calls, [ACKED]);
    fireEvent.click(screen.getByTestId("recall-open-44"));
    expect(screen.getByTestId("recall-reason-count-44")).toHaveTextContent("10 more characters needed");
    fireEvent.change(screen.getByTestId("recall-reason-44"), { target: { value: "  too    short " } });
    expect(screen.getByTestId("recall-reason-count-44")).toHaveTextContent("1 more character needed");
    fireEvent.click(screen.getByTestId("recall-dialog-44-recall"));
    expect(within(screen.getByRole("alertdialog")).getByRole("alert"))
      .toHaveTextContent("Give a reason of at least 10 characters.");
    expect(posts(calls)).toEqual([]);
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });

  it("recalls with the reason, closes and re-reads the list and the fleet", async () => {
    const calls: Call[] = [];
    const changed = vi.fn();
    await openHandled(calls, [ACKED], { onIncidentChanged: changed });
    fireEvent.click(screen.getByTestId("recall-open-44"));
    fireEvent.change(screen.getByTestId("recall-reason-44"),
      { target: { value: "  the partner   did not remove these " } });
    const before = lists(calls);
    fireEvent.click(screen.getByTestId("recall-dialog-44-recall"));
    await waitFor(() => expect(changed).toHaveBeenCalled());
    expect(posts(calls)).toEqual([{
      method: "POST", url: "/api/v1/alerts/example-bakery/verdicts/9/recall",
      body: { reason: "the partner did not remove these" } }]);
    await waitFor(() => expect(lists(calls)).toBe(before + 1));
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("keeps the dialog and says why when the server refuses", async () => {
    const calls: Call[] = [];
    await openHandled(calls, [ACKED], {}, () => ok(
      { code: "CONFLICT", message: "this acknowledgement is already recalled" }, 409));
    fireEvent.click(screen.getByTestId("recall-open-44"));
    fireEvent.change(screen.getByTestId("recall-reason-44"), { target: { value: "a reason long enough" } });
    fireEvent.click(screen.getByTestId("recall-dialog-44-recall"));
    const dialog = screen.getByRole("alertdialog");
    await waitFor(() => expect(within(dialog).getByRole("alert"))
      .toHaveTextContent("this acknowledgement is already recalled"));
    expect(within(dialog).getByTestId("recall-dialog-44-recall")).not.toBeDisabled();
  });

  it("says the repeats return too for a \"repeats for 24 h\" acknowledgement", async () => {
    const calls: Call[] = [];
    const repeat: SiteAlert = { ...ACKED, ack: { ...ACKED.ack!, repeat_until: "2026-10-09T11:30:00.000Z",
                                                 by_repeat: true } };
    await openHandled(calls, [repeat]);
    fireEvent.click(screen.getByTestId("recall-open-44"));
    expect(screen.getByRole("alertdialog")).toHaveTextContent(
      "It also covered repeats of this alert for 24 h — they return too.");
  });

  it("is not offered for an ack the server sent without its id (an older server)", async () => {
    const calls: Call[] = [];
    const old: SiteAlert = { ...ACKED, ack: { by: 7, by_name: "Alice Example", at: "2026-10-08T11:30:00.000Z",
                                              note: null, repeat_until: null, by_repeat: false } };
    await openHandled(calls, [old]);
    expect(screen.queryByTestId("recall-open-44")).toBeNull();
    expect(screen.queryByTestId("followup-note-open-44")).toBeNull();
  });
});

describe("a client user", () => {
  it("gets no list, no notes, no recall", () => {
    global.fetch = vi.fn() as unknown as typeof fetch;
    render(<FleetSiteDrawer site={site({ tenant_slug: null })} view="client" onClose={() => undefined} />);
    expect(screen.queryByTestId("site-alerts")).toBeNull();
    expect(screen.queryByText(/recall/i)).toBeNull();
    expect(screen.queryByText(/add note/i)).toBeNull();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(global.fetch).not.toHaveBeenCalled();
  });
});
