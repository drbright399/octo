/**
 * Settings → Threats (Tier Black slice 1): the rules are read only with
 * their coverage; an ANALYST may tag an asset life-safety (the tags that
 * change detection are not offered to them, and they get no clear button);
 * an admin sees the registries. Fixture names: Example / Acme.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import ThreatsTab from "@/pages/settings/threats";
import type { MeResponse } from "@/contracts/operator";

const ok = (body: object): Response => new Response(JSON.stringify(body), { status: 200 });

function me(role: MeResponse["role"]): MeResponse {
  return { operator_id: 1, username: "alice", email: "alice@example.test", display_name: null,
           role, scope_slugs: ["*"], must_change_password: false, mfa_enabled: true,
           backup_codes_remaining: 8, needs_setup: false };
}

const RULES = { rules: [
  { id: "B6", version: 1, tier: "black", stage: "live", kind: "human", title: "analyst-declared Black",
    inputs: ["analyst"], description: "", braked_until: null,
    coverage: { "acme-corp": { covered: true, missing: [] } } },
  { id: "R6", version: 1, tier: "red", stage: "shadow", kind: "automated",
    title: "credential tried on a decoy", inputs: ["buoy.opencanary"], description: "",
    braked_until: null, coverage: { "acme-corp": { covered: false, missing: ["no buoy at this client"] } } },
] };

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("Settings → Threats", () => {
  it("an analyst sees the rules and may tag life-safety, not the suppressive tags", async () => {
    const posted: string[] = [];
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/tiers/rules")) return Promise.resolve(ok(RULES));
      if (url.includes("/asset-tags") && init?.method === "POST") {
        posted.push(String(init.body));
        return Promise.resolve(ok({ tags: [] }));
      }
      if (url.includes("/asset-tags")) return Promise.resolve(ok({ tags: [] }));
      return Promise.resolve(ok({ rows: [], brakes: [] }));
    }) as unknown as typeof fetch;
    render(<ThreatsTab me={me(["analyst"])} />);
    const r6 = await screen.findByTestId("rule-R6");
    expect(r6).toHaveTextContent("shadow");
    expect(r6).toHaveTextContent("not covered at acme-corp");
    const select = screen.getByTestId("tag-select") as HTMLSelectElement;
    const options = [...select.options].map((o) => o.value);
    expect(options).toContain("life_safety");
    expect(options).not.toContain("lab");
    expect(options).not.toContain("evidence_hold");
    expect(screen.queryByTestId("threats-exceptions")).toBeNull();     // admin+ only
    const form = screen.getByTestId("tag-form");
    const inputs = within(form).getAllByRole("textbox");
    fireEvent.change(inputs[0]!, { target: { value: "acme-corp" } });
    fireEvent.change(inputs[1]!, { target: { value: "dispatch-01" } });
    fireEvent.change(inputs[2]!, { target: { value: "911 dispatch console" } });
    fireEvent.click(within(form).getByRole("button", { name: "tag" }));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(JSON.parse(posted[0]!)).toEqual({ tenant: "acme-corp", ref_kind: "device",
                                             device_ref: "dispatch-01", tag: "life_safety",
                                             reason: "911 dispatch console" });
  });

  it("an admin sees the registries (allowlist, exceptions, verdicts, remote access, brake)", async () => {
    global.fetch = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/tiers/rules")) return Promise.resolve(ok(RULES));
      if (url.includes("/asset-tags")) return Promise.resolve(ok({ tags: [] }));
      if (url.includes("/brake")) return Promise.resolve(ok({ brakes: [] }));
      return Promise.resolve(ok({ rows: [] }));
    }) as unknown as typeof fetch;
    render(<ThreatsTab me={me(["admin"])} />);
    for (const id of ["threats-allowlist", "threats-exceptions", "threats-verdicts",
                      "threats-registry", "threats-brake"]) {
      expect(await screen.findByTestId(id)).toBeInTheDocument();
    }
    const select = screen.getByTestId("tag-select") as HTMLSelectElement;
    expect([...select.options].map((o) => o.value)).toContain("lab");
  });
});

const WINDOW = {
  id: 11, tenant_slug: "acme-corp", tenant_name: "Acme Corp", incident_id: 7,
  origin_incident_id: 7, incident_tier: "black", incident_status: "closed", incident_open: false,
  incident_summary: "someone is controlling the screen", kind: "incident",
  start: "2026-10-01T06:00:00.000Z", end: "2026-10-04T09:00:00.000Z", open: false, held: true,
  opened_by: "1", opened_by_name: "Alice Example", opened_at: "2026-10-03T12:00:00.000Z",
  reason: "a confirmed threat (Red / Black)", released_at: null, released_by: null,
  released_by_name: null, release_reason: null, kept_rows: 1200,
  kept_counted_at: "2026-10-05T09:00:00.000Z", events_in_window: 100000, events_capped: true,
};

describe("Settings → Threats: evidence windows", () => {
  function serve(posted: { url: string; body: string }[], windows: object[]) {
    global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (init?.method === "POST") {
        posted.push({ url, body: String(init.body) });
        return Promise.resolve(ok(WINDOW));
      }
      if (url.includes("/evidence-windows")) return Promise.resolve(ok({ items: windows }));
      if (url.includes("/tiers/rules")) return Promise.resolve(ok(RULES));
      if (url.includes("/asset-tags")) return Promise.resolve(ok({ tags: [] }));
      if (url.includes("/brake")) return Promise.resolve(ok({ brakes: [] }));
      return Promise.resolve(ok({ rows: [] }));
    }) as unknown as typeof fetch;
  }

  it("an analyst sees each window and may widen it, never release it", async () => {
    const posted: { url: string; body: string }[] = [];
    serve(posted, [WINDOW]);
    const prompt = vi.spyOn(window, "prompt")
      .mockReturnValueOnce("2026-09-20T00:00")
      .mockReturnValueOnce("dwell time: the first beacon was on the 20th");
    render(<ThreatsTab me={me(["analyst"])} />);
    const row = await screen.findByTestId("evidence-row-11");
    expect(row).toHaveTextContent("Acme Corp");
    expect(row).toHaveTextContent("#7 BLACK · closed");
    expect(row).toHaveTextContent(
      "#11 · auto · 2026-10-01 06:00 UTC → 2026-10-04 09:00 UTC · 1,200 rows kept past retention · ~100,000+ events");
    expect(row).toHaveTextContent("held");
    expect(screen.queryByTestId("evidence-row-release-11")).toBeNull();
    fireEvent.click(screen.getByTestId("evidence-row-widen-11"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(prompt).toHaveBeenCalledTimes(2);
    expect(posted[0]!.url).toBe("/api/v1/incidents/acme-corp/7/evidence-window/11/widen");
    expect(JSON.parse(posted[0]!.body)).toEqual({
      start: "2026-09-20T00:00", reason: "dwell time: the first beacon was on the 20th" });
  });

  it("an admin releases a window after the all-clear — not while its incident is open", async () => {
    const posted: { url: string; body: string }[] = [];
    const open = { ...WINDOW, id: 12, incident_id: 8, incident_open: true,
                   incident_status: "open", end: null, open: true };
    serve(posted, [WINDOW, open]);
    vi.spyOn(window, "prompt").mockReturnValueOnce("the claim is settled");
    render(<ThreatsTab me={me(["admin"])} />);
    await screen.findByTestId("evidence-row-12");
    expect(screen.getByTestId("evidence-row-12")).toHaveTextContent("open (until the all-clear)");
    expect(screen.queryByTestId("evidence-row-release-12")).toBeNull();
    fireEvent.click(screen.getByTestId("evidence-row-release-11"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0]!.url).toBe("/api/v1/incidents/acme-corp/7/evidence-window/11/release");
    expect(JSON.parse(posted[0]!.body)).toEqual({ reason: "the claim is settled" });
  });

  it("filters held / released / all", async () => {
    const posted: { url: string; body: string }[] = [];
    serve(posted, []);
    render(<ThreatsTab me={me(["analyst"])} />);
    expect(await screen.findByText("No evidence window.")).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("evidence-state"), { target: { value: "released" } });
    await waitFor(() => expect((global.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls
      .some(([u]) => String(u).includes("/evidence-windows?state=released"))).toBe(true));
  });
});
