/**
 * Datto rows must be readable and link back to the vendor.
 *
 * Production defects this pins:
 *   - the feed showed a Datto alert as the title "alert" with nothing under it;
 *   - V1's vendor links sometimes "just went to the RMM home dashboard" — here
 *     the client only ever renders the exact URL the server built, as a
 *     new-tab rel="noopener noreferrer" link, or renders no link at all;
 *   - the "isolate" button looked live and did nothing.
 *
 * Verified against the live portal afterwards: a device page is
 * /device/<numeric id>, which no alert carries — so the DEVICE link is a
 * reference the server resolves (through the vendor API) only when the operator
 * clicks; a failure opens nothing and says why.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import AlertDrawer from "@/components/alert-drawer";
import { VendorLinksPanel } from "@/components/vendor-links-panel";
import type { AlertRow } from "@/contracts/alert";
import { DefaultAlertFeed } from "@widgets/default-alert-feed";
import { DefaultListWithActions } from "@widgets/default-list-with-actions";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const PORTAL = "https://exampleplat.rmm.datto.com";
const DETAIL = [
  "Logon Type: 3",
  "Account Name: alice",
  "Failure Reason: Unknown user name or bad password.",
  "Source Network Address: 192.0.2.44",
  "Source: Microsoft-Windows-Security-Auditing · Triggered 5 times",
].join("\n");

const DATTO_ROW: AlertRow = {
  id: "acme:41",
  severity: "high",
  status: "open",
  source: "datto",
  tenant: "acme",
  title: "Event log · Security 4625 — An account failed to log on",
  summary: DETAIL,
  occurred_at: "2026-09-21T14:13:20.000Z",
  device: "WS-EXAMPLE-01",
  site: "Example Site",
  vendor_links: [
    { kind: "alert", label: "Open in Datto RMM", vendor: "datto", url: `${PORTAL}/alert/alert-uid-0001` },
  ],
  vendor_device_ref: {
    vendor: "datto",
    label: "Open device in Datto RMM",
    client_slug: "acme",
    event_id: 41,
  },
};

const respond = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

const WAZUH_ROW: AlertRow = {
  id: "acme:7",
  severity: "medium",
  status: "open",
  source: "wazuh",
  tenant: "acme",
  title: "auth.failure",
  summary: "[authentication_failed] SSH brute force",
  occurred_at: "2026-09-21T14:00:00.000Z",
};

describe("alert feed row", () => {
  it("shows the headline, device, site and the detail clamped to two lines", () => {
    render(<DefaultAlertFeed rows={[DATTO_ROW]} />);
    const item = screen.getByRole("listitem");
    expect(within(item).getByRole("heading")).toHaveTextContent(
      "Event log · Security 4625 — An account failed to log on",
    );
    expect(within(item).getByTestId("alert-device")).toHaveTextContent("WS-EXAMPLE-01");
    expect(within(item).getByTestId("alert-site")).toHaveTextContent("Example Site");

    const summary = within(item).getByTestId("alert-summary");
    expect(summary.style.webkitLineClamp || summary.style.getPropertyValue("-webkit-line-clamp")).toBe("2");
    expect(summary.style.overflow).toBe("hidden");
    // The whole text is one hover away (and one click: the drawer).
    expect(summary).toHaveAttribute("title", DETAIL);
    // Inside the clamp the newlines would collapse to spaces and the
    // 'key: value' boundaries with them — so the facts are joined visibly.
    expect(summary.textContent).toBe(DETAIL.split("\n").join(" · "));
    expect(summary.textContent).not.toContain("\n");
  });

  it("a one-line summary is shown as it is", () => {
    render(<DefaultAlertFeed rows={[WAZUH_ROW]} />);
    expect(screen.getByTestId("alert-summary").textContent).toBe("[authentication_failed] SSH brute force");
  });

  it("the vendor link's tooltip says the portal needs its own sign-in", () => {
    render(<DefaultAlertFeed rows={[DATTO_ROW]} />);
    const link = screen.getByTestId("alert-vendor-link");
    expect(link).toHaveAttribute("title", expect.stringMatching(/needs an active Datto RMM sign-in in this browser/));
    expect(link).toHaveAttribute("title", expect.stringMatching(/sign in there and open the link again/));
    expect(link).toHaveAccessibleName("Open in Datto RMM");      // the name stays short
  });

  it("links to the ALERT in the vendor portal: new tab, noopener noreferrer", () => {
    render(<DefaultAlertFeed rows={[DATTO_ROW]} onSelect={vi.fn()} />);
    const link = screen.getByTestId("alert-vendor-link");
    expect(link).toHaveAttribute("href", `${PORTAL}/alert/alert-uid-0001`);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link).toHaveAccessibleName("Open in Datto RMM");
  });

  it("using the link never also opens the drawer", () => {
    const onSelect = vi.fn();
    render(<DefaultAlertFeed rows={[DATTO_ROW]} onSelect={onSelect} />);
    const link = screen.getByTestId("alert-vendor-link");
    fireEvent.click(link);
    fireEvent.keyDown(link, { key: "Enter" });
    expect(onSelect).not.toHaveBeenCalled();
    // The row itself still opens it.
    fireEvent.keyDown(screen.getByRole("button"), { key: "Enter" });
    expect(onSelect).toHaveBeenCalledWith(DATTO_ROW);
  });

  it("renders no link when the server sent none, or sent something that is not https", () => {
    const { rerender } = render(<DefaultAlertFeed rows={[{ ...DATTO_ROW, vendor_links: [] }]} />);
    expect(screen.queryByTestId("alert-vendor-link")).toBeNull();
    rerender(
      <DefaultAlertFeed
        rows={[{
          ...DATTO_ROW,
          vendor_links: [
            { kind: "alert", label: "x", vendor: "datto", url: "javascript:alert(1)" },
            { kind: "alert", label: "y", vendor: "datto", url: "http://exampleplat.rmm.datto.com/alert/1" },
          ],
        }]}
      />,
    );
    expect(screen.queryByTestId("alert-vendor-link")).toBeNull();
  });

  it("rows from other sources look as they did", () => {
    render(<DefaultAlertFeed rows={[WAZUH_ROW]} />);
    const item = screen.getByRole("listitem");
    expect(within(item).getByRole("heading")).toHaveTextContent("auth.failure");
    expect(within(item).getByTestId("alert-summary")).toHaveTextContent(
      "[authentication_failed] SSH brute force",
    );
    expect(within(item).queryByTestId("alert-device")).toBeNull();
    expect(within(item).queryByTestId("alert-site")).toBeNull();
    expect(within(item).queryByTestId("alert-vendor-link")).toBeNull();
  });

  it("an empty detail leaves no empty paragraph", () => {
    render(<DefaultAlertFeed rows={[{ ...WAZUH_ROW, summary: "" }]} />);
    expect(screen.queryByTestId("alert-summary")).toBeNull();
  });

  it("vendor text is text: markup in a headline or detail is never parsed", () => {
    const { container } = render(
      <DefaultAlertFeed
        rows={[{
          ...DATTO_ROW,
          title: "Component monitor — <img src=x onerror=alert(1)>",
          summary: "<script>alert(1)</script>\n<a href='https://evil.example.test'>click</a>",
        }]}
      />,
    );
    expect(container.querySelector("img, script")).toBeNull();
    // The only anchor is ours.
    expect(container.querySelectorAll("a")).toHaveLength(1);
    expect(screen.getByTestId("alert-summary").textContent).toContain("<script>alert(1)</script>");
  });
});

describe("alert drawer", () => {
  it("shows the whole detail with its line breaks, plus device and site", () => {
    render(<AlertDrawer alert={DATTO_ROW} onClose={vi.fn()} />);
    const summary = screen.getByTestId("alert-drawer-summary");
    expect(summary.textContent).toBe(DETAIL);
    expect(summary.className).toContain("whitespace-pre-wrap");
    expect(screen.getByText("WS-EXAMPLE-01")).toBeInTheDocument();
    expect(screen.getByText("Example Site")).toBeInTheDocument();
  });

  it("offers the alert link the server built, as a safe new-tab link", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<AlertDrawer alert={DATTO_ROW} onClose={vi.fn()} />);
    const alertLink = screen.getByTestId("alert-drawer-vendor-link-alert");
    expect(alertLink).toHaveAttribute("href", `${PORTAL}/alert/alert-uid-0001`);
    expect(alertLink).toHaveAttribute("target", "_blank");
    expect(alertLink).toHaveAttribute("rel", "noopener noreferrer");
    expect(alertLink).toHaveTextContent("Open in Datto RMM");
    // The device page is NOT a link yet — and showing the drawer resolved nothing.
    const device = screen.getByTestId("alert-drawer-vendor-device");
    expect(device.tagName).toBe("BUTTON");
    expect(device).toHaveTextContent("Open device in Datto RMM");
    expect(fetchMock.mock.calls.filter(([u]) => String(u).includes("vendor-device-link"))).toHaveLength(0);
  });

  it("says that the links need the vendor's own sign-in — the V1 'went to the home dashboard' cause", () => {
    render(<AlertDrawer alert={DATTO_ROW} onClose={vi.fn()} />);
    const note = screen.getByTestId("alert-drawer-vendor-session-note");
    expect(note).toHaveTextContent("needs an active Datto RMM sign-in in this browser");
    expect(note).toHaveTextContent("If Datto RMM shows its sign-in page, sign in there and open the link again");
    // The same sentence is the tooltip of both controls.
    expect(screen.getByTestId("alert-drawer-vendor-link-alert")).toHaveAttribute("title", note.textContent);
    expect(screen.getByTestId("alert-drawer-vendor-device")).toHaveAttribute("title", note.textContent);
    // No vendor link → no note about one.
    cleanup();
    render(<AlertDrawer alert={WAZUH_ROW} onClose={vi.fn()} />);
    expect(screen.queryByTestId("alert-drawer-vendor-session-note")).toBeNull();
  });

  it("an expired console session on the device lookup redirects to /login instead of a red sentence", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: RequestInfo | URL) =>
      String(url).includes("vendor-device-link")
        ? respond(401, { code: "AUTH_SESSION_INVALID", message: "session does not resolve or has expired" })
        : respond(404, {}),
    ));
    const open = vi.fn();
    vi.stubGlobal("open", open);
    const location = { href: "/" } as Location;
    vi.stubGlobal("location", location);
    render(<AlertDrawer alert={DATTO_ROW} onClose={vi.fn()} />);
    fireEvent.click(screen.getByTestId("alert-drawer-vendor-device"));
    await waitFor(() => expect(location.href).toBe("/login"));
    expect(open).not.toHaveBeenCalled();
    // A vendor-side 401-class refusal is NOT a session problem: no redirect.
    location.href = "/";
    vi.stubGlobal("fetch", vi.fn(async () =>
      respond(424, { code: "VENDOR_CREDENTIALS_REJECTED", message: "Datto rejected the stored credentials." }),
    ));
    cleanup();
    render(<AlertDrawer alert={DATTO_ROW} onClose={vi.fn()} />);
    fireEvent.click(screen.getByTestId("alert-drawer-vendor-device"));
    expect(await screen.findByTestId("alert-drawer-vendor-device-error")).toHaveTextContent(/rejected the stored credentials/);
    expect(location.href).toBe("/");
  });

  it("resolves the device page on click, opens it safely, and becomes a real link", async () => {
    const fetchMock = vi.fn(async (url: RequestInfo | URL, _init?: RequestInit) =>
      String(url).includes("vendor-device-link")
        ? respond(200, { url: `${PORTAL}/device/4242`, label: "Open device in Datto RMM", vendor: "datto", cached: false })
        : respond(404, {}),
    );
    vi.stubGlobal("fetch", fetchMock);
    const open = vi.fn();
    vi.stubGlobal("open", open);
    render(<AlertDrawer alert={DATTO_ROW} onClose={vi.fn()} />);
    fireEvent.click(screen.getByTestId("alert-drawer-vendor-device"));

    await waitFor(() => expect(open).toHaveBeenCalledTimes(1));
    expect(open).toHaveBeenCalledWith(`${PORTAL}/device/4242`, "_blank", "noopener,noreferrer");
    const link = await screen.findByRole("link", { name: /Open device in Datto RMM/ });
    expect(link).toHaveAttribute("href", `${PORTAL}/device/4242`);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    // window.open ran after an await (outside the click's activation), so a
    // browser may have blocked it silently: the control says what to do.
    expect(screen.getByTestId("alert-drawer-vendor-device-status")).toHaveTextContent(
      "Looked up. If a new tab did not open, click the link again.",
    );
    expect(screen.getByRole("status")).toBe(screen.getByTestId("alert-drawer-vendor-device-status"));

    const [url, init] = fetchMock.mock.calls.find(([u]) => String(u).includes("vendor-device-link"))!;
    expect(String(url)).toBe("/api/v1/dashboard/vendor-device-link");
    expect(init?.method).toBe("POST");
    // A reference to the stored event — never a device id, never a URL.
    expect(JSON.parse(String(init?.body))).toEqual({ client_slug: "acme", event_id: 41 });
  });

  it("a failed lookup opens nothing and shows the server's reason", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: RequestInfo | URL) =>
      String(url).includes("vendor-device-link")
        ? respond(503, {
            code: "VENDOR_UNREACHABLE",
            message: "Datto RMM returned a device page address that did not pass validation; no link was opened.",
          })
        : respond(404, {}),
    ));
    const open = vi.fn();
    vi.stubGlobal("open", open);
    render(<AlertDrawer alert={DATTO_ROW} onClose={vi.fn()} />);
    fireEvent.click(screen.getByTestId("alert-drawer-vendor-device"));

    expect(await screen.findByTestId("alert-drawer-vendor-device-error")).toHaveTextContent(
      /did not pass validation; no link was opened/,
    );
    expect(open).not.toHaveBeenCalled();
    expect(screen.queryByRole("link", { name: /Open device/ })).toBeNull();
    expect(screen.getByTestId("alert-drawer-vendor-device")).toBeEnabled();     // retry is possible
  });

  it.each([
    "javascript:alert(1)",
    "http://exampleplat.rmm.datto.com/device/4242",
    "//evil.example.test/device/1",
    "",
    null,
  ])("a 200 whose url is not https (%s) opens nothing either", async (bad) => {
    vi.stubGlobal("fetch", vi.fn(async (url: RequestInfo | URL) =>
      String(url).includes("vendor-device-link") ? respond(200, { url: bad }) : respond(404, {}),
    ));
    const open = vi.fn();
    vi.stubGlobal("open", open);
    render(<AlertDrawer alert={DATTO_ROW} onClose={vi.fn()} />);
    fireEvent.click(screen.getByTestId("alert-drawer-vendor-device"));
    expect(await screen.findByTestId("alert-drawer-vendor-device-error")).toBeInTheDocument();
    expect(open).not.toHaveBeenCalled();
    expect(screen.queryByRole("link", { name: /Open device/ })).toBeNull();
  });

  it("has no vendor link for a row without one", () => {
    render(<AlertDrawer alert={WAZUH_ROW} onClose={vi.fn()} />);
    expect(screen.queryByTestId("alert-drawer-vendor-link-alert")).toBeNull();
    expect(screen.queryByTestId("alert-drawer-vendor-device")).toBeNull();
    expect(screen.getByText(/SSH brute force/)).toBeInTheDocument();
  });
});

describe("devices needing attention actions", () => {
  interface Row {
    id: string;
    title: string;
    lookup?: (() => Promise<string>) | undefined;
    deviceLink?: string | undefined;
  }
  const lookup = vi.fn(async () => `${PORTAL}/device/4242`);
  const rows: Row[] = [
    { id: "acme:WS-1", title: "WS-1", lookup },
    { id: "acme:web-01", title: "web-01" },
  ];
  const actions = [
    {
      id: "open",
      label: "open",
      resolveHref: (r: Row) => r.lookup,
      disabledReason: "no vendor portal link for this device",
    },
    { id: "isolate", label: "isolate", disabled: true, disabledReason: "not available yet" },
  ];
  const hrefActions = [
    { id: "open", label: "open", href: (r: Row) => r.deviceLink, disabledReason: "no vendor portal link for this device" },
  ];

  it("open looks the page up on click only, and is honestly disabled where there is nothing to open", async () => {
    lookup.mockClear();
    const open = vi.fn();
    vi.stubGlobal("open", open);
    render(<DefaultListWithActions rows={rows} actions={actions} />);
    const [linked, unlinked] = screen.getAllByRole("listitem");
    expect(lookup).not.toHaveBeenCalled();                 // rendering rows resolves nothing
    expect(within(linked!).queryByRole("link")).toBeNull();

    const dead = within(unlinked!).getByRole("button", { name: "open" });
    expect(dead).toBeDisabled();
    expect(dead).toHaveAttribute("title", "no vendor portal link for this device");

    fireEvent.click(within(linked!).getByRole("button", { name: "open" }));
    await waitFor(() => expect(open).toHaveBeenCalledWith(`${PORTAL}/device/4242`, "_blank", "noopener,noreferrer"));
    expect(lookup).toHaveBeenCalledTimes(1);
    const link = await within(linked!).findByRole("link", { name: /open/ });
    expect(link).toHaveAttribute("href", `${PORTAL}/device/4242`);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("a lookup that fails opens nothing and says why", async () => {
    const open = vi.fn();
    vi.stubGlobal("open", open);
    const failing: Row[] = [{
      id: "acme:WS-1",
      title: "WS-1",
      lookup: async () => {
        throw new Error("Datto RMM does not know this device (any more).");
      },
    }];
    render(<DefaultListWithActions rows={failing} actions={actions} />);
    fireEvent.click(screen.getByRole("button", { name: "open" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/does not know this device/);
    expect(open).not.toHaveBeenCalled();
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("a static href is a real new-tab link, and only when it is https", () => {
    render(
      <DefaultListWithActions
        rows={[{ id: "a", title: "a", deviceLink: `${PORTAL}/device/4242` }, { id: "b", title: "b" }]}
        actions={hrefActions}
      />,
    );
    const [linked, unlinked] = screen.getAllByRole("listitem");
    const link = within(linked!).getByRole("link", { name: /open/ });
    expect(link).toHaveAttribute("href", `${PORTAL}/device/4242`);
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(within(unlinked!).getByRole("button", { name: "open" })).toBeDisabled();
  });

  it("isolate is disabled with a tooltip, on every row, and does nothing", () => {
    render(<DefaultListWithActions rows={rows} actions={actions} />);
    const buttons = screen.getAllByRole("button", { name: "isolate" });
    expect(buttons).toHaveLength(2);
    for (const b of buttons) {
      expect(b).toBeDisabled();
      expect(b).toHaveAttribute("title", "not available yet");
      fireEvent.click(b);
    }
  });

  it("a non-https target is never rendered as a link", () => {
    render(
      <DefaultListWithActions
        rows={[{ id: "x", title: "x", deviceLink: "javascript:alert(1)" }]}
        actions={hrefActions}
      />,
    );
    expect(screen.queryByRole("link")).toBeNull();
    expect(screen.getByRole("button", { name: "open" })).toBeDisabled();
  });
});

describe("portal link settings panel", () => {
  const SETTINGS = {
    vendor_slug: "datto",
    instance_id: 3,
    portal_name: "Datto RMM",
    allowed_domain: "datto.com",
    placeholders: ["{alert_uid}", "{device_uid}", "{site_uid}"],
    overrides: {},
    portal_base_url: PORTAL,
    alert_path_template: "/alert/{alert_uid}",
    derived_portal_base_url: PORTAL,
    default_alert_path_template: "/alert/{alert_uid}",
    paths_verified: true,
    sample_alert_url: `${PORTAL}/alert/ALERT-UID`,
    device_links_resolved: true,
    links_enabled: true,
    problem: null,
  };

  it("shows what is in use; there is no device path to set", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => respond(200, SETTINGS)));
    render(<VendorLinksPanel vendorSlug="datto" instanceId={3} vendorName="Datto RMM" onDone={vi.fn()} />);
    expect(await screen.findByTestId("vendor-links-device-note")).toHaveTextContent(
      /looked up when an operator clicks Open/,
    );
    expect(screen.queryByTestId("vendor-links-unverified")).toBeNull();      // the alert path IS verified
    expect(screen.queryByTestId("vendor-links-device_path_template")).toBeNull();
    expect(screen.getByTestId("vendor-links-sample-device")).toHaveTextContent("looked up on click");
    expect(screen.getByTestId("vendor-links-sample-alert")).toHaveTextContent(`${PORTAL}/alert/ALERT-UID`);
    expect(screen.getByTestId("vendor-links-portal_base_url")).toHaveAttribute("placeholder", PORTAL);
    expect(screen.queryByTestId("vendor-links-problem")).toBeNull();
    // Always shown (the alert path IS verified, so the 'wrong page' note is
    // not): the one remaining way an exact link lands on the home page.
    const session = screen.getByTestId("vendor-links-session-note");
    expect(session).toHaveTextContent("needs an active Datto RMM sign-in in this browser");
    expect(session).toHaveTextContent("still lands on the Datto RMM home page is that sign-in, not the link");
  });

  it("says so when a vendor's default path was never verified", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => respond(200, { ...SETTINGS, paths_verified: false })));
    render(<VendorLinksPanel vendorSlug="datto" instanceId={3} vendorName="Datto RMM" onDone={vi.fn()} />);
    expect(await screen.findByTestId("vendor-links-unverified")).toHaveTextContent(
      /has not been verified against the live Datto RMM portal/,
    );
  });

  it("says why there are no links", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => respond(200, {
      ...SETTINGS,
      portal_base_url: null,
      derived_portal_base_url: null,
      sample_alert_url: null,
      device_links_resolved: false,
      links_enabled: false,
      problem: "No Datto RMM links are shown: the portal address could not be derived.",
    })));
    render(<VendorLinksPanel vendorSlug="datto" instanceId={3} vendorName="Datto RMM" onDone={vi.fn()} />);
    expect(await screen.findByTestId("vendor-links-problem")).toHaveTextContent(/could not be derived/);
    expect(screen.getByTestId("vendor-links-sample-alert")).toHaveTextContent("— no link —");
    expect(screen.getByTestId("vendor-links-sample-device")).toHaveTextContent("— no link —");
  });

  it("saves the two fields and shows the server's refusal verbatim", async () => {
    const fetchMock = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) =>
      init?.method === "PUT"
        ? respond(422, {
            code: "VALIDATION_FAILED",
            message: "alert path template must contain {alert_uid} — without it every link would open the same page",
          })
        : respond(200, SETTINGS),
    );
    vi.stubGlobal("fetch", fetchMock);
    render(<VendorLinksPanel vendorSlug="datto" instanceId={3} vendorName="Datto RMM" onDone={vi.fn()} />);
    fireEvent.change(await screen.findByTestId("vendor-links-alert_path_template"), {
      target: { value: "/alerts" },
    });
    fireEvent.click(screen.getByTestId("vendor-links-save"));

    expect(await screen.findByTestId("vendor-links-error")).toHaveTextContent(
      /must contain \{alert_uid\}/,
    );
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    const [url, init] = fetchMock.mock.calls[1]!;
    expect(String(url)).toBe("/api/v1/integrations/datto/3/vendor-links");
    expect(JSON.parse(String(init?.body))).toEqual({
      portal_base_url: "",
      alert_path_template: "/alerts",
    });
  });
});
