import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { TenantMappingPanel } from "@/components/tenant-mapping-panel";

const listClients = vi.fn();
const getTenantMappings = vi.fn();
const setTenantMappings = vi.fn();
const createClient = vi.fn();
const listVendorTenants = vi.fn();

vi.mock("@/lib/api", () => ({
  listClients: (...a: unknown[]) => listClients(...a),
  getTenantMappings: (...a: unknown[]) => getTenantMappings(...a),
  setTenantMappings: (...a: unknown[]) => setTenantMappings(...a),
  createClient: (...a: unknown[]) => createClient(...a),
  listVendorTenants: (...a: unknown[]) => listVendorTenants(...a),
}));

const DATTO_SHAPE = {
  fetch_method: "api",
  fetch_endpoint: "/api/v2/account/sites",
  vendor_tenant_id_field: "uid",
  vendor_tenant_label_field: "name",
  tenant_noun: "site",
  id_help: "The Datto site's UID (API field 'uid') — the value alerts carry as siteUid. The site NAME never matches.",
};

const SITES = [
  { id: "site-uid-0002", label: "Example Bakery" },
  { id: "site-uid-0001", label: "Example Clinic" },
];

const FORBIDDEN =
  "Datto accepted the API key, but this API user may not read the account (HTTP 403). In " +
  "Datto RMM open Setup > Users, click the API user and, next to Generate API Keys, set its " +
  "API Security Level (and API Component Level). Do NOT regenerate the API keys: the stored " +
  "pair works as soon as the access level is fixed.";

function discovered(over: Record<string, unknown> = {}) {
  return {
    supported: true,
    tenants: SITES,
    truncated: false,
    fetched_at: "2026-01-01T00:00:00.000Z",
    tenant_mapping_shape: DATTO_SHAPE,
    ...over,
  };
}

const UNSUPPORTED = {
  supported: false,
  tenants: [],
  truncated: false,
  fetched_at: null,
  tenant_mapping_shape: null,
};

function renderPanel(onDone = vi.fn()) {
  render(
    <TenantMappingPanel vendorSlug="datto" instanceId={5} vendorName="Datto RMM" onDone={onDone} />,
  );
  return onDone;
}

beforeEach(() => {
  vi.clearAllMocks();
  listClients.mockResolvedValue([
    { slug: "acme-corp", display_name: "Acme Corp", status: "active" },
  ]);
  getTenantMappings.mockResolvedValue([]);
  setTenantMappings.mockResolvedValue([]);
  createClient.mockResolvedValue({ slug: "globex", display_name: "Globex", status: "active" });
  listVendorTenants.mockResolvedValue(UNSUPPORTED);
});

describe("TenantMappingPanel", () => {
  it("loads clients and saves a manually entered mapping (vendor without discovery)", async () => {
    const onDone = renderPanel();
    await waitFor(() => expect(screen.getByText(/Acme Corp/)).toBeInTheDocument());
    // Said out loud — not a silent free-text field.
    expect(await screen.findByTestId("discovery-unsupported")).toHaveTextContent(
      /Datto RMM cannot list its tenants here/,
    );

    fireEvent.change(screen.getByPlaceholderText("tenant id"), {
      target: { value: "site-1" },
    });
    fireEvent.change(screen.getByLabelText("client, row 1"), { target: { value: "acme-corp" } });
    fireEvent.click(screen.getByText("Save mappings"));

    await waitFor(() => expect(setTenantMappings).toHaveBeenCalled());
    const call = setTenantMappings.mock.calls[0];
    expect(call[0]).toBe("datto");
    expect(call[1]).toBe(5);
    expect(call[2]).toEqual([
      {
        vendor_tenant_id: "site-1",
        octo_client_slug: "acme-corp",
        vendor_tenant_label: null,
        match_source: "manual",
      },
    ]);
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });

  it("creates a new client inline", async () => {
    renderPanel();
    await waitFor(() => expect(screen.getByText(/Acme Corp/)).toBeInTheDocument());

    fireEvent.click(screen.getByText("+ new client"));
    fireEvent.change(screen.getByPlaceholderText("acme-corp"), { target: { value: "globex" } });
    fireEvent.change(screen.getByPlaceholderText("Acme Corp"), { target: { value: "Globex" } });
    fireEvent.click(screen.getByText("create"));

    await waitFor(() => expect(createClient).toHaveBeenCalledWith("globex", "Globex"));
  });

  it("never shows the old made-up placeholder; the wording comes from the adapter's shape", async () => {
    listVendorTenants.mockResolvedValue({ ...UNSUPPORTED, tenant_mapping_shape: DATTO_SHAPE });
    renderPanel();
    expect(await screen.findByPlaceholderText("site uid")).toBeInTheDocument();
    expect(screen.queryByPlaceholderText(/site-abc123/)).not.toBeInTheDocument();
    expect(screen.getByTestId("tenant-id-help")).toHaveTextContent("The site NAME never matches.");
  });
});

describe("TenantMappingPanel — vendor site discovery", () => {
  it("offers discovered sites as '<name> — <uid>' and picking one fills id + label", async () => {
    listVendorTenants.mockResolvedValue(discovered());
    renderPanel();

    const picker = await screen.findByLabelText("Datto RMM site, row 1");
    expect(picker.tagName).toBe("SELECT");
    expect(within(picker).getByText("Example Clinic — site-uid-0001")).toBeInTheDocument();
    expect(within(picker).getByText("Example Bakery — site-uid-0002")).toBeInTheDocument();
    expect(screen.getByTestId("discovery-ready")).toHaveTextContent("2 Datto RMM sites loaded");
    expect(listVendorTenants).toHaveBeenCalledWith(5, { refresh: false });

    fireEvent.change(picker, { target: { value: "site-uid-0001" } });
    expect(screen.getByLabelText("label, row 1")).toHaveValue("Example Clinic");

    fireEvent.change(screen.getByLabelText("client, row 1"), { target: { value: "acme-corp" } });
    fireEvent.click(screen.getByText("Save mappings"));
    await waitFor(() => expect(setTenantMappings).toHaveBeenCalled());
    expect(setTenantMappings.mock.calls[0][2]).toEqual([
      {
        vendor_tenant_id: "site-uid-0001",
        octo_client_slug: "acme-corp",
        vendor_tenant_label: "Example Clinic",
        match_source: "manual",
      },
    ]);
  });

  it("rows never overflow into each other: shrinkable columns, full-width fields", async () => {
    // Field report 2026-10-02: on the live console the Datto rows' dropdowns
    // overlapped. Plain `1fr` grid columns can't shrink below a <select>'s
    // longest option, so a long site or client name pushed a column into
    // its neighbour. Columns must be minmax(0,1fr) and fields full-width.
    listVendorTenants.mockResolvedValue(discovered({
      tenants: [{ id: "site-uid-0003", label: "An example site name far wider than its column ever is" }, ...SITES],
    }));
    renderPanel();
    const picker = await screen.findByLabelText("Datto RMM site, row 1");
    const grid = screen.getByTestId("mapping-row-0").querySelector("div.grid");
    expect(grid?.className).toContain("grid-cols-[minmax(0,1fr),minmax(0,1fr),minmax(0,1fr),auto]");
    expect(grid?.className).not.toContain("grid-cols-[1fr,");
    for (const el of [picker, screen.getByLabelText("client, row 1"), screen.getByLabelText("label, row 1")]) {
      expect(el.className).toContain("w-full");
      expect(el.className).toContain("min-w-0");
    }
  });

  it("refuses to save a half-filled row instead of dropping it in silence", async () => {
    // Three sites picked, a client chosen on two: Save used to PUT two rows,
    // succeed and close — the third site stayed unmapped, its alerts dropped.
    listVendorTenants.mockResolvedValue(discovered());
    const onDone = renderPanel();
    fireEvent.change(await screen.findByLabelText("Datto RMM site, row 1"), {
      target: { value: "site-uid-0001" },
    });
    fireEvent.change(screen.getByLabelText("client, row 1"), { target: { value: "acme-corp" } });
    fireEvent.click(screen.getByText("+ add mapping"));
    fireEvent.change(screen.getByLabelText("Datto RMM site, row 2"), {
      target: { value: "site-uid-0002" },
    });
    fireEvent.click(screen.getByText("Save mappings"));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Nothing was saved: row 2 \(Example Bakery\) has no client/,
    );
    expect(setTenantMappings).not.toHaveBeenCalled();
    expect(onDone).not.toHaveBeenCalled();

    // A client with no site is refused the same way…
    fireEvent.click(screen.getByText("+ add mapping"));
    fireEvent.change(screen.getByLabelText("client, row 3"), { target: { value: "acme-corp" } });
    fireEvent.click(screen.getByText("Save mappings"));
    expect(await screen.findByRole("alert")).toHaveTextContent(/row 3 has a client but no site/);
    expect(setTenantMappings).not.toHaveBeenCalled();

    // …finishing the rows saves all three; a fully BLANK row is still ignored.
    fireEvent.change(screen.getByLabelText("client, row 2"), { target: { value: "acme-corp" } });
    fireEvent.change(screen.getByLabelText("client, row 3"), { target: { value: "" } });
    fireEvent.click(screen.getByText("Save mappings"));
    await waitFor(() => expect(setTenantMappings).toHaveBeenCalled());
    const saved = (setTenantMappings.mock.calls[0]?.[2] ?? []) as { vendor_tenant_id: string }[];
    expect(saved.map((m) => m.vendor_tenant_id)).toEqual(["site-uid-0001", "site-uid-0002"]);
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });

  it("keeps manual entry possible, clearly secondary", async () => {
    listVendorTenants.mockResolvedValue(discovered());
    renderPanel();
    const picker = await screen.findByLabelText("Datto RMM site, row 1");
    // Secondary: the last option of the picker, not a field of its own.
    const options = within(picker).getAllByRole("option");
    expect(options[options.length - 1]).toHaveTextContent("Not listed — enter the id manually…");

    fireEvent.change(picker, { target: { value: "__manual__" } });
    const input = screen.getByPlaceholderText("site uid");
    fireEvent.change(input, { target: { value: "site-uid-0002" } });
    // A typed id that IS a real site is not flagged.
    expect(screen.queryByTestId("mapping-unmatched-0")).not.toBeInTheDocument();

    fireEvent.click(screen.getByText("pick from the list"));
    expect(screen.getByLabelText("Datto RMM site, row 1")).toHaveValue("site-uid-0002");
  });

  it("a site already mapped in another row cannot be picked twice", async () => {
    listVendorTenants.mockResolvedValue(discovered());
    getTenantMappings.mockResolvedValue([
      { vendor_tenant_id: "site-uid-0001", octo_client_slug: "acme-corp", vendor_tenant_label: "Example Clinic" },
    ]);
    renderPanel();
    await screen.findByLabelText("Datto RMM site, row 1");
    fireEvent.click(screen.getByText("+ add mapping"));
    const second = screen.getByLabelText("Datto RMM site, row 2");
    expect(within(second).getByText("Example Clinic — site-uid-0001")).toBeDisabled();
    expect(within(second).getByText("Example Bakery — site-uid-0002")).not.toBeDisabled();
  });

  it("SHOWS WHY when discovery fails — never a silent fall back to free text", async () => {
    listVendorTenants.mockRejectedValue(new Error(FORBIDDEN));
    getTenantMappings.mockResolvedValue([
      { vendor_tenant_id: "site-uid-0001", octo_client_slug: "acme-corp", vendor_tenant_label: null },
    ]);
    renderPanel();

    const failed = await screen.findByTestId("discovery-failed");
    expect(failed).toHaveAttribute("role", "alert");
    expect(failed).toHaveTextContent("Could not load the tenant list from Datto RMM");
    expect(failed).toHaveTextContent(FORBIDDEN);
    expect(failed).toHaveTextContent(/cannot be checked against Datto RMM/);
    // Saved mappings stay on screen, editable, and are NOT accused of anything
    // (nothing was discovered to compare them with).
    expect(screen.getByDisplayValue("site-uid-0001")).toBeInTheDocument();
    expect(screen.queryByTestId("mapping-unmatched-0")).not.toBeInTheDocument();

    // The operator fixes the security level in Datto and retries.
    listVendorTenants.mockResolvedValue(discovered());
    fireEvent.click(within(failed).getByText("Retry"));
    await screen.findByTestId("discovery-ready");
    expect(listVendorTenants).toHaveBeenLastCalledWith(5, { refresh: true });
    expect(screen.queryByTestId("discovery-failed")).not.toBeInTheDocument();
  });

  it("words the failure with the adapter's shape when the caller has it (wizard)", async () => {
    listVendorTenants.mockRejectedValue(new Error(FORBIDDEN));
    render(
      <TenantMappingPanel
        vendorSlug="datto"
        instanceId={5}
        vendorName="Datto RMM"
        shape={DATTO_SHAPE}
        onDone={vi.fn()}
      />,
    );
    expect(await screen.findByTestId("discovery-failed")).toHaveTextContent(
      "Could not load the site list from Datto RMM",
    );
    expect(screen.getByPlaceholderText("site uid")).toBeInTheDocument();
    expect(screen.getByTestId("tenant-id-help")).toHaveTextContent("The site NAME never matches.");
  });

  it("Reload asks the vendor again", async () => {
    listVendorTenants.mockResolvedValue(discovered());
    renderPanel();
    await screen.findByTestId("discovery-ready");
    fireEvent.click(screen.getByText("Reload"));
    await waitFor(() => expect(listVendorTenants).toHaveBeenLastCalledWith(5, { refresh: true }));
  });
});

describe("TenantMappingPanel — frozen mappings of a departed tenant", () => {
  const FROZEN = {
    vendor_tenant_id: "site-uid-0002",
    octo_client_slug: "gone-co",
    vendor_tenant_label: "Example Bakery",
    match_source: "auto",
    client_status: "offboarded",
    client_display_name: "Gone Co",
  };
  const ACTIVE = {
    vendor_tenant_id: "site-uid-0001",
    octo_client_slug: "acme-corp",
    vendor_tenant_label: "Example Clinic",
    match_source: "manual",
    client_status: "active",
    client_display_name: "Acme Corp",
  };

  beforeEach(() => {
    listVendorTenants.mockResolvedValue(discovered());
    getTenantMappings.mockResolvedValue([ACTIVE, FROZEN]);
  });

  it("renders the frozen row read-only with the departed tenant's name and status, and no remove control", async () => {
    renderPanel();
    const frozen = await screen.findByTestId("mapping-frozen-site-uid-0002");
    expect(frozen).toHaveTextContent("Example Bakery — site-uid-0002");
    expect(frozen).toHaveTextContent("Gone Co (gone-co) — offboarded");
    expect(frozen).toHaveTextContent(/frozen: traffic from this site is held in quarantine/);
    expect(frozen).toHaveTextContent(/route its held events under Quarantine/);
    // No picker, no input, no ✕ — nothing to "clean up".
    expect(within(frozen).queryByRole("combobox")).toBeNull();
    expect(within(frozen).queryByRole("textbox")).toBeNull();
    expect(within(frozen).queryByRole("button")).toBeNull();
    // The gone tenant is not an option (listClients is active-only), so the
    // old rendering was a BLANK client picker — there is exactly one editable
    // row now, and it is the active one, its picker filled.
    expect(screen.getAllByLabelText(/^client, row/)).toHaveLength(1);
    expect(screen.getByLabelText("client, row 1")).toHaveValue("acme-corp");
    expect(screen.getAllByLabelText("Remove row")).toHaveLength(1);
    // Nor can a new row pick the frozen site again.
    fireEvent.click(screen.getByText("+ add mapping"));
    const second = screen.getByLabelText("Datto RMM site, row 2");
    expect(within(second).getByText("Example Bakery — site-uid-0002")).toBeDisabled();
  });

  it("saving keeps the frozen row: it goes back verbatim beside the edited rows", async () => {
    const onDone = renderPanel();
    await screen.findByTestId("mapping-frozen-site-uid-0002");
    fireEvent.change(screen.getByLabelText("label, row 1"), { target: { value: "Example Clinic HQ" } });
    fireEvent.click(screen.getByText("Save mappings"));
    await waitFor(() => expect(setTenantMappings).toHaveBeenCalledTimes(1));
    expect(setTenantMappings.mock.calls[0][2]).toEqual([
      { vendor_tenant_id: "site-uid-0001", octo_client_slug: "acme-corp", vendor_tenant_label: "Example Clinic HQ", match_source: "manual" },
      FROZEN,   // untouched: same slug, same label, same match_source, same status fields
    ]);
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });

  it("removing every editable row still saves the frozen one", async () => {
    // The ✕ on a SAVED row asks first, then saves that removal at once.
    setTenantMappings.mockResolvedValue([FROZEN]);
    renderPanel();
    await screen.findByTestId("mapping-frozen-site-uid-0002");
    fireEvent.click(screen.getByLabelText("Remove row"));
    fireEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Remove mapping" }));
    await waitFor(() => expect(setTenantMappings).toHaveBeenCalledTimes(1));
    expect(setTenantMappings.mock.calls[0][2]).toEqual([FROZEN]);
    await waitFor(() => expect(screen.queryByLabelText(/^client, row/)).toBeNull());
    expect(screen.getByTestId("mapping-frozen-site-uid-0002")).toBeInTheDocument();
  });

  it("a typed id that equals a frozen site is refused with the route to take", async () => {
    renderPanel();
    await screen.findByTestId("mapping-frozen-site-uid-0002");
    fireEvent.click(screen.getByText("+ add mapping"));
    fireEvent.change(screen.getByLabelText("Datto RMM site, row 2"), { target: { value: "__manual__" } });
    fireEvent.change(screen.getByLabelText("Datto RMM site uid, row 2"), { target: { value: "site-uid-0002" } });
    fireEvent.change(screen.getByLabelText("client, row 2"), { target: { value: "acme-corp" } });
    fireEvent.click(screen.getByText("Save mappings"));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /"site-uid-0002" is frozen to Gone Co \(offboarded\) and cannot be mapped again here/,
    );
    expect(setTenantMappings).not.toHaveBeenCalled();
  });

  it("a map that is ONLY frozen rows shows them and one empty editable row", async () => {
    getTenantMappings.mockResolvedValue([FROZEN]);
    renderPanel();
    await screen.findByTestId("mapping-frozen-site-uid-0002");
    expect(screen.getAllByLabelText(/^client, row/)).toHaveLength(1);
    expect(screen.getByLabelText("client, row 1")).toHaveValue("");
  });
});

describe("TenantMappingPanel — saved mappings that cannot work", () => {
  beforeEach(() => {
    listVendorTenants.mockResolvedValue(discovered());
    // What the operator saved in production: the site NAME as the id.
    getTenantMappings.mockResolvedValue([
      { vendor_tenant_id: " example clinic ", octo_client_slug: "acme-corp", vendor_tenant_label: null },
      { vendor_tenant_id: "site-uid-0002", octo_client_slug: "acme-corp", vendor_tenant_label: "Example Bakery" },
      { vendor_tenant_id: "Somewhere Else", octo_client_slug: "acme-corp", vendor_tenant_label: null },
    ]);
  });

  it("flags a row whose id is no discovered site and suggests the uid when it is a site NAME", async () => {
    renderPanel();

    const flag = await screen.findByTestId("mapping-unmatched-0");
    expect(flag).toHaveAttribute("role", "alert");
    expect(flag).toHaveTextContent(
      "“example clinic” does not match any Datto RMM site — alerts will never route here.",
    );
    // Case-insensitive, trimmed name match → one-click suggestion of the uid.
    expect(within(flag).getByRole("button", { name: "use site-uid-0001" })).toBeInTheDocument();

    // A correct row is left alone; an unknown id with no namesake is flagged
    // but gets no guess.
    expect(screen.queryByTestId("mapping-unmatched-1")).not.toBeInTheDocument();
    const other = screen.getByTestId("mapping-unmatched-2");
    expect(other).toHaveTextContent("“Somewhere Else” does not match any Datto RMM site");
    expect(within(other).queryByRole("button")).not.toBeInTheDocument();

    expect(screen.getByTestId("mapping-save-state")).toHaveTextContent(
      "2 mappings match no Datto RMM site.",
    );
  });

  it("rewrites NOTHING without a click, and stores nothing without Save", async () => {
    renderPanel();
    await screen.findByTestId("mapping-unmatched-0");

    // Discovery arrived, suggestions are on screen — the row is untouched.
    expect(screen.getByLabelText("Datto RMM site uid, row 1")).toHaveValue(" example clinic ");
    expect(setTenantMappings).not.toHaveBeenCalled();
    expect(screen.getByTestId("mapping-save-state")).not.toHaveTextContent("Unsaved changes");

    // The operator confirms the suggestion…
    fireEvent.click(screen.getByRole("button", { name: "use site-uid-0001" }));
    expect(screen.getByLabelText("Datto RMM site, row 1")).toHaveValue("site-uid-0001");
    expect(screen.getByLabelText("label, row 1")).toHaveValue("Example Clinic");
    expect(screen.queryByTestId("mapping-unmatched-0")).not.toBeInTheDocument();
    // …which still only changed the form.
    expect(setTenantMappings).not.toHaveBeenCalled();
    expect(screen.getByTestId("mapping-save-state")).toHaveTextContent(
      "Unsaved changes — nothing is stored until you press Save mappings.",
    );

    // …then saves. The row they did not touch goes out exactly as it was.
    fireEvent.click(screen.getByText("Save mappings"));
    await waitFor(() => expect(setTenantMappings).toHaveBeenCalledTimes(1));
    expect(setTenantMappings.mock.calls[0][2]).toEqual([
      { vendor_tenant_id: "site-uid-0001", octo_client_slug: "acme-corp", vendor_tenant_label: "Example Clinic", match_source: "manual" },
      { vendor_tenant_id: "site-uid-0002", octo_client_slug: "acme-corp", vendor_tenant_label: "Example Bakery", match_source: "manual" },
      { vendor_tenant_id: "Somewhere Else", octo_client_slug: "acme-corp", vendor_tenant_label: null, match_source: "manual" },
    ]);
  });

  it("offers every site that shares the typed name, and picks none for the operator", async () => {
    listVendorTenants.mockResolvedValue(
      discovered({
        tenants: [...SITES, { id: "site-uid-0009", label: "EXAMPLE CLINIC" }],
      }),
    );
    renderPanel();
    const flag = await screen.findByTestId("mapping-unmatched-0");
    expect(within(flag).getByRole("button", { name: "use site-uid-0001" })).toBeInTheDocument();
    expect(within(flag).getByRole("button", { name: "use site-uid-0009" })).toBeInTheDocument();
    expect(screen.getByLabelText("Datto RMM site uid, row 1")).toHaveValue(" example clinic ");
  });

  it("does not accuse any row when the discovered list was capped", async () => {
    listVendorTenants.mockResolvedValue(discovered({ truncated: true }));
    renderPanel();
    expect(await screen.findByTestId("discovery-truncated")).toHaveTextContent(/incomplete/);
    expect(screen.queryByTestId("mapping-unmatched-0")).not.toBeInTheDocument();
    expect(screen.queryByTestId("mapping-unmatched-2")).not.toBeInTheDocument();
  });

  it("refuses to save the same site twice and shows the server's reason when a save is refused", async () => {
    getTenantMappings.mockResolvedValue([
      { vendor_tenant_id: "site-uid-0001", octo_client_slug: "acme-corp", vendor_tenant_label: null },
    ]);
    renderPanel();
    await screen.findByTestId("discovery-ready");
    fireEvent.click(screen.getByText("+ add mapping"));
    fireEvent.change(screen.getByLabelText("Datto RMM site, row 2"), {
      target: { value: "__manual__" },
    });
    fireEvent.change(screen.getByLabelText("Datto RMM site uid, row 2"), {
      target: { value: "site-uid-0001" },
    });
    fireEvent.change(screen.getByLabelText("client, row 2"), { target: { value: "acme-corp" } });
    fireEvent.click(screen.getByText("Save mappings"));
    expect(await screen.findByText(/"site-uid-0001" is mapped more than once/)).toBeInTheDocument();
    expect(setTenantMappings).not.toHaveBeenCalled();

    fireEvent.click(screen.getAllByLabelText("Remove row")[1]!);
    setTenantMappings.mockRejectedValue(new Error("mapping 1: client 'acme-corp' does not exist"));
    fireEvent.click(screen.getByText("Save mappings"));
    expect(await screen.findByText(/client 'acme-corp' does not exist/)).toBeInTheDocument();
  });
});

describe("TenantMappingPanel — name-matched mappings (the same-name rule)", () => {
  const AUTO_ROW = {
    vendor_tenant_id: "site-uid-0001", octo_client_slug: "acme-corp",
    vendor_tenant_label: "Example Clinic", match_source: "auto",
    client_status: "active", client_display_name: "Acme Corp",
  };

  it("marks a stored name match unconfirmed and sends it back unchanged", async () => {
    getTenantMappings.mockResolvedValue([AUTO_ROW]);
    listVendorTenants.mockResolvedValue(discovered());
    renderPanel();
    expect(await screen.findByTestId("mapping-unconfirmed-0")).toHaveTextContent(
      /Unconfirmed — mapped from a name match/);
    fireEvent.click(screen.getByText("Save mappings"));
    await waitFor(() => expect(setTenantMappings).toHaveBeenCalled());
    expect(setTenantMappings.mock.calls[0]![2]).toEqual([
      { vendor_tenant_id: "site-uid-0001", octo_client_slug: "acme-corp",
        vendor_tenant_label: "Example Clinic", match_source: "auto" },
    ]);
  });

  it("an auto-created tenant's own mapping (server: needs_review false) is not flagged and keeps its source", async () => {
    getTenantMappings.mockResolvedValue([{ ...AUTO_ROW, needs_review: false }]);
    listVendorTenants.mockResolvedValue(discovered());
    renderPanel();
    await screen.findByLabelText("client, row 1");
    await new Promise((r) => setTimeout(r, 10));
    expect(screen.queryByTestId("mapping-unconfirmed-0")).toBeNull();
    fireEvent.click(screen.getByText("Save mappings"));
    await waitFor(() => expect(setTenantMappings).toHaveBeenCalled());
    expect(setTenantMappings.mock.calls[0]![2][0]!.match_source).toBe("auto");
  });

  it("a row the server marks needs_review is flagged whatever its source", async () => {
    getTenantMappings.mockResolvedValue([{ ...AUTO_ROW, match_source: "auto-name", needs_review: true }]);
    listVendorTenants.mockResolvedValue(discovered());
    renderPanel();
    expect(await screen.findByTestId("mapping-unconfirmed-0")).toBeInTheDocument();
  });

  it("Confirm makes it the operator's decision ('manual')", async () => {
    getTenantMappings.mockResolvedValue([AUTO_ROW]);
    listVendorTenants.mockResolvedValue(discovered());
    renderPanel();
    fireEvent.click(await screen.findByTestId("mapping-confirm-0"));
    expect(screen.queryByTestId("mapping-unconfirmed-0")).toBeNull();
    fireEvent.click(screen.getByText("Save mappings"));
    await waitFor(() => expect(setTenantMappings).toHaveBeenCalled());
    expect(setTenantMappings.mock.calls[0]![2][0]!.match_source).toBe("manual");
  });

  it("re-pointing it to another client is a decision too ('manual')", async () => {
    listClients.mockResolvedValue([
      { slug: "acme-corp", display_name: "Acme Corp", status: "active" },
      { slug: "globex", display_name: "Globex", status: "active" },
    ]);
    getTenantMappings.mockResolvedValue([AUTO_ROW]);
    listVendorTenants.mockResolvedValue(discovered());
    renderPanel();
    await screen.findByTestId("mapping-unconfirmed-0");
    fireEvent.change(screen.getByLabelText("client, row 1"), { target: { value: "globex" } });
    expect(screen.queryByTestId("mapping-unconfirmed-0")).toBeNull();
    fireEvent.click(screen.getByText("Save mappings"));
    await waitFor(() => expect(setTenantMappings).toHaveBeenCalled());
    expect(setTenantMappings.mock.calls[0]![2][0]!).toMatchObject({
      octo_client_slug: "globex", match_source: "manual" });
  });
});

describe("TenantMappingPanel — the ✕ on a saved mapping (asks, then saves just that)", () => {
  const CLINIC = {
    vendor_tenant_id: "site-uid-0001", octo_client_slug: "acme-corp",
    vendor_tenant_label: "Example Clinic", match_source: "manual",
    client_status: "active", client_display_name: "Acme Corp",
  };
  const BAKERY = {
    vendor_tenant_id: "site-uid-0002", octo_client_slug: "acme-corp",
    vendor_tenant_label: "Example Bakery", match_source: "auto", needs_review: false,
    client_status: "active", client_display_name: "Acme Corp",
  };
  const HELD = {
    vendor_tenant_id: "site-uid-0003", octo_client_slug: "gone-co",
    vendor_tenant_label: "Example Depot", match_source: "manual",
    client_status: "offboarded", client_display_name: "Gone Co",
  };

  beforeEach(() => {
    listClients.mockResolvedValue([
      { slug: "acme-corp", display_name: "Acme Corp", status: "active" },
      { slug: "globex", display_name: "Globex", status: "active" },
    ]);
    listVendorTenants.mockResolvedValue(
      discovered({ tenants: [...SITES, { id: "site-uid-0003", label: "Example Depot" }] }),
    );
    getTenantMappings.mockResolvedValue([CLINIC, BAKERY, HELD]);
    setTenantMappings.mockResolvedValue([BAKERY, HELD]);
  });

  const openFor = async (n: number): Promise<{ x: HTMLElement; dialog: HTMLElement }> => {
    await screen.findByTestId("discovery-ready");
    const x = screen.getAllByLabelText("Remove row")[n - 1]!;
    x.focus();
    fireEvent.click(x);
    return { x, dialog: screen.getByRole("alertdialog") };
  };

  it("asks first, in words; Cancel and Escape change nothing and send nothing", async () => {
    const onDone = renderPanel();
    const { x, dialog } = await openFor(1);
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAccessibleName("Remove this mapping?");
    // Datto never drops an unmapped site's alerts (tenant_autocreate): it says so.
    expect(dialog).toHaveAccessibleDescription(
      /Events from Example Clinic will no longer route to Acme Corp — events from an unmapped site are not dropped: they create a new pending client for review, or are held in Quarantine\. Its past events stay with Acme Corp\. This is saved as soon as you choose\./,
    );
    expect(dialog).not.toHaveAccessibleDescription(/are dropped/);
    expect(dialog).toHaveTextContent(
      "Remove the mapping of Datto RMM site Example Clinic — site-uid-0001 to Acme Corp? Events from Example Clinic",
    );
    const cancel = within(dialog).getByRole("button", { name: "Cancel" });
    expect(cancel).toHaveFocus();

    fireEvent.click(cancel);
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(x).toHaveFocus();

    fireEvent.click(x);
    fireEvent.keyDown(screen.getByRole("button", { name: "Cancel" }), { key: "Escape" });
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(x).toHaveFocus();

    expect(setTenantMappings).not.toHaveBeenCalled();
    expect(screen.getByLabelText("label, row 1")).toHaveValue("Example Clinic");
    expect(screen.getAllByLabelText(/^client, row/)).toHaveLength(2);
    expect(screen.queryByTestId("mapping-save-state")).toBeNull();
    expect(onDone).not.toHaveBeenCalled();
  });

  it("saves the last server state minus that row (frozen verbatim) — other unsaved edits stay staged", async () => {
    const onDone = renderPanel();
    await screen.findByTestId("discovery-ready");
    // Staged, never saved by the ✕: a label edit and a new row.
    fireEvent.change(screen.getByLabelText("label, row 2"), { target: { value: "Bakery HQ" } });
    fireEvent.click(screen.getByText("+ add mapping"));
    fireEvent.change(screen.getByLabelText("client, row 3"), { target: { value: "globex" } });

    const { dialog } = await openFor(1);
    expect(dialog).toHaveAccessibleDescription(/Your other unsaved changes are not saved with it/);
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove mapping" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());

    expect(setTenantMappings).toHaveBeenCalledTimes(1);
    expect(setTenantMappings.mock.calls[0]![2]).toEqual([
      // As the server holds it: its stored label and source, not the staged edit.
      { vendor_tenant_id: "site-uid-0002", octo_client_slug: "acme-corp", vendor_tenant_label: "Example Bakery", match_source: "auto" },
      HELD,
    ]);
    expect(screen.getByTestId("mapping-removed")).toHaveTextContent(
      "Mapping removed and saved. Your other unsaved changes are still pending.",
    );
    // The removed row is gone; the staged edits are still on screen, unsaved.
    expect(screen.getAllByLabelText(/^client, row/)).toHaveLength(2);
    expect(screen.getByLabelText("Datto RMM site, row 1")).toHaveValue("site-uid-0002");
    expect(screen.getByLabelText("label, row 1")).toHaveValue("Bakery HQ");
    expect(screen.getByLabelText("client, row 2")).toHaveValue("globex");
    expect(screen.getByTestId("mapping-save-state")).toHaveTextContent("Unsaved changes");
    expect(screen.getByTestId("mapping-frozen-site-uid-0003")).toBeInTheDocument();
    // Its ✕ is gone with it: focus lands on "+ add mapping", the panel stays open.
    expect(screen.getByText("+ add mapping")).toHaveFocus();
    expect(onDone).not.toHaveBeenCalled();

    // A later Save sends the staged edits on top of the new server state.
    fireEvent.change(screen.getByLabelText("Datto RMM site, row 2"), { target: { value: "site-uid-0001" } });
    fireEvent.click(screen.getByText("Save mappings"));
    await waitFor(() => expect(setTenantMappings).toHaveBeenCalledTimes(2));
    expect(setTenantMappings.mock.calls[1]![2]).toEqual([
      { vendor_tenant_id: "site-uid-0002", octo_client_slug: "acme-corp", vendor_tenant_label: "Bakery HQ", match_source: "auto" },
      { vendor_tenant_id: "site-uid-0001", octo_client_slug: "globex", vendor_tenant_label: "Example Clinic", match_source: "manual" },
      HELD,
    ]);
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });

  it("with nothing else staged, says only that it saved", async () => {
    renderPanel();
    const { dialog } = await openFor(1);
    expect(dialog).not.toHaveAccessibleDescription(/other unsaved changes/);
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove mapping" }));
    expect(await screen.findByTestId("mapping-removed")).toHaveTextContent(/^Mapping removed and saved\.$/);
    expect(screen.queryByTestId("mapping-save-state")).toBeNull();
  });

  it("a refused removal changes nothing on screen and shows the server's reason in the dialog", async () => {
    let refuse: (e: Error) => void = () => undefined;
    setTenantMappings.mockReturnValue(new Promise((_, reject) => { refuse = reject; }));
    renderPanel();
    const { dialog } = await openFor(1);
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove mapping" }));
    // While it saves, every button is disabled and Escape does nothing.
    expect(within(dialog).getByRole("button", { name: "Removing…" })).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toBeDisabled();
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(screen.getByRole("alertdialog")).toBe(dialog);

    // The box holds the focus (a disabled button drops it in a browser), and
    // Save mappings behind the dialog waits.
    expect(dialog).toHaveFocus();
    expect(screen.getByText("Save mappings")).toBeDisabled();

    refuse(new Error("mapping 1: example refusal"));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("mapping 1: example refusal");
    expect(within(dialog).getByRole("button", { name: "Remove mapping" })).toBeEnabled();
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(screen.getByText("Save mappings")).toBeEnabled();
    expect(screen.getAllByLabelText(/^client, row/)).toHaveLength(2);
    expect(screen.getByLabelText("label, row 1")).toHaveValue("Example Clinic");
    expect(screen.queryByTestId("mapping-removed")).toBeNull();
    expect(setTenantMappings).toHaveBeenCalledTimes(1);
  });

  it("a new row that was never saved is removed without asking", async () => {
    renderPanel();
    await screen.findByTestId("discovery-ready");
    fireEvent.click(screen.getByText("+ add mapping"));
    expect(screen.getAllByLabelText("Remove row")).toHaveLength(3);
    fireEvent.click(screen.getAllByLabelText("Remove row")[2]!);
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(screen.getAllByLabelText("Remove row")).toHaveLength(2);
    expect(setTenantMappings).not.toHaveBeenCalled();
  });

  it("an integration that does not hold unmapped traffic says its events are dropped", async () => {
    render(<TenantMappingPanel vendorSlug="autotask" instanceId={5} vendorName="Autotask" onDone={vi.fn()} />);
    const { dialog } = await openFor(1);
    expect(dialog).toHaveAccessibleDescription(
      /Events from Example Clinic will no longer route to Acme Corp — events from an unmapped site are dropped\./,
    );
  });

  it("re-reads the server first: a mapping written elsewhere since the panel opened is kept, and shown", async () => {
    // An integration auto-created a tenant for a new site after the panel loaded.
    const NEWER = {
      vendor_tenant_id: "site-uid-0004", octo_client_slug: "globex", vendor_tenant_label: "Example Kiosk",
      match_source: "auto", needs_review: false, client_status: "active", client_display_name: "Globex",
    };
    getTenantMappings
      .mockResolvedValueOnce([CLINIC, BAKERY, HELD])
      .mockResolvedValueOnce([CLINIC, BAKERY, NEWER, HELD]);
    setTenantMappings.mockResolvedValue([BAKERY, NEWER, HELD]);
    listVendorTenants.mockResolvedValue(discovered({
      tenants: [...SITES, { id: "site-uid-0003", label: "Example Depot" }, { id: "site-uid-0004", label: "Example Kiosk" }],
    }));
    renderPanel();
    const { dialog } = await openFor(1);
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove mapping" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());

    expect(setTenantMappings).toHaveBeenCalledTimes(1);
    expect(setTenantMappings.mock.calls[0]![2]).toEqual([
      { vendor_tenant_id: "site-uid-0002", octo_client_slug: "acme-corp", vendor_tenant_label: "Example Bakery", match_source: "auto" },
      { vendor_tenant_id: "site-uid-0004", octo_client_slug: "globex", vendor_tenant_label: "Example Kiosk", match_source: "auto" },
      HELD,
    ]);
    expect(screen.getAllByLabelText(/^client, row/)).toHaveLength(2);
    expect(screen.getByLabelText("label, row 2")).toHaveValue("Example Kiosk");
    expect(screen.getByLabelText("client, row 2")).toHaveValue("globex");
    expect(screen.getByTestId("mapping-removed")).toHaveTextContent(/^Mapping removed and saved\.$/);
    expect(screen.queryByTestId("mapping-save-state")).toBeNull();
  });

  it("saves nothing when that very mapping changed since the panel opened, and shows what it is now", async () => {
    const REPOINTED = { ...CLINIC, octo_client_slug: "globex", client_display_name: "Globex" };
    getTenantMappings
      .mockResolvedValueOnce([CLINIC, BAKERY, HELD])
      .mockResolvedValueOnce([REPOINTED, BAKERY, HELD]);
    renderPanel();
    const { dialog } = await openFor(1);
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove mapping" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());

    expect(setTenantMappings).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Nothing was saved: the mapping of Example Clinic changed since this list was read — it now points to Globex. Check it and try again.",
    );
    expect(screen.getByLabelText("client, row 1")).toHaveValue("globex");
    expect(screen.queryByTestId("mapping-removed")).toBeNull();
    // Its ✕ is still there and has the focus back.
    expect(screen.getAllByLabelText("Remove row")[0]).toHaveFocus();
  });

  it("a failure AFTER the server stored the removal: the re-read shows the truth, and the next Save does not restore it", async () => {
    getTenantMappings
      .mockResolvedValueOnce([CLINIC, BAKERY, HELD])
      .mockResolvedValueOnce([CLINIC, BAKERY, HELD])
      .mockResolvedValueOnce([BAKERY, HELD]);
    setTenantMappings.mockRejectedValueOnce(new Error("Save failed (example)"));
    const onDone = renderPanel();
    await screen.findByTestId("discovery-ready");
    fireEvent.change(screen.getByLabelText("label, row 2"), { target: { value: "Bakery HQ" } });
    const { dialog } = await openFor(1);
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove mapping" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Save failed (example) — yet the mapping of Example Clinic to Acme Corp is no longer stored. The list shows what is stored now.",
    );
    expect(screen.getAllByLabelText(/^client, row/)).toHaveLength(1);
    expect(screen.getByLabelText("label, row 1")).toHaveValue("Bakery HQ");      // still staged
    expect(screen.getByText("+ add mapping")).toHaveFocus();

    setTenantMappings.mockResolvedValue([]);
    fireEvent.click(screen.getByText("Save mappings"));
    await waitFor(() => expect(setTenantMappings).toHaveBeenCalledTimes(2));
    expect(setTenantMappings.mock.calls[1]![2]).toEqual([
      { vendor_tenant_id: "site-uid-0002", octo_client_slug: "acme-corp", vendor_tenant_label: "Bakery HQ", match_source: "auto" },
      HELD,
    ]);
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });
});
