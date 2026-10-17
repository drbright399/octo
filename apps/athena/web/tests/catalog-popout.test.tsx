import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { CatalogPopout } from "@/components/catalog-popout";
import type { CatalogResponse } from "@/contracts/integration";

const CATALOG: CatalogResponse = {
  adapters: [
    {
      vendor_slug: "wazuh",
      vendor_display_name: "Wazuh",
      vendor_logo_path: "",
      vendor_category: "siem",
      auth_model: "api-key",
      delivery_mode: "poll",
      availability: "available",
      compliance_categories: [],
      credential_shape: [
        {
          name: "WAZUH_API_KEY",
          label: "API key",
          kind: "password",
          required: true,
        },
      ],
    },
    {
      vendor_slug: "datto",
      vendor_display_name: "Datto RMM",
      vendor_logo_path: "",
      vendor_category: "rmm",
      auth_model: "api-key",
      delivery_mode: "poll",
      availability: "available",
      compliance_categories: [],
      credential_shape: [
        { name: "DATTO_API_KEY", label: "API key", kind: "password", required: true },
      ],
    },
    {
      vendor_slug: "unifi",
      vendor_display_name: "UniFi Network",
      vendor_logo_path: "",
      vendor_category: "network",
      auth_model: "api-key",
      delivery_mode: "poll",
      availability: "available",
      compliance_categories: [],
      credential_shape: [
        { name: "UNIFI_API_KEY", label: "API key", kind: "password", required: true },
      ],
    },
  ],
  categories: [
    {
      category: "rmm",
      display_label: "RMM",
      adapters: [
        {
          vendor_slug: "datto",
          vendor_display_name: "Datto RMM",
          vendor_logo_path: "",
          vendor_category: "rmm",
          auth_model: "api-key",
          delivery_mode: "poll",
          availability: "available",
          compliance_categories: [],
          credential_shape: [
            { name: "DATTO_API_KEY", label: "API key", kind: "password", required: true },
          ],
        },
      ],
    },
    {
      category: "siem",
      display_label: "SIEM",
      adapters: [
        {
          vendor_slug: "wazuh",
          vendor_display_name: "Wazuh",
          vendor_logo_path: "",
          vendor_category: "siem",
          auth_model: "api-key",
          delivery_mode: "poll",
          availability: "available",
          compliance_categories: [],
          credential_shape: [
            {
              name: "WAZUH_API_KEY",
              label: "API key",
              kind: "password",
              required: true,
            },
          ],
        },
      ],
    },
    {
      category: "network",
      display_label: "Network",
      adapters: [
        {
          vendor_slug: "unifi",
          vendor_display_name: "UniFi Network",
          vendor_logo_path: "",
          vendor_category: "network",
          auth_model: "api-key",
          delivery_mode: "poll",
          availability: "available",
          compliance_categories: [],
          credential_shape: [
            {
              name: "UNIFI_API_KEY",
              label: "API key",
              kind: "password",
              required: true,
            },
          ],
        },
      ],
    },
  ],
};

describe("CatalogPopout — browse step", () => {
  it("renders nothing when closed", () => {
    render(
      <CatalogPopout
        open={false}
        onClose={() => undefined}
        onConfigured={() => undefined}
        initialCatalog={CATALOG}
      />,
    );
    expect(screen.queryByTestId("catalog-popout")).not.toBeInTheDocument();
  });

  it("lists every category from the seeded catalog plus an All bucket", () => {
    render(
      <CatalogPopout
        open
        onClose={() => undefined}
        onConfigured={() => undefined}
        initialCatalog={CATALOG}
      />,
    );
    const nav = screen.getByLabelText("Adapter categories");
    expect(within(nav).getByText("All")).toBeInTheDocument();
    expect(within(nav).getByText("RMM")).toBeInTheDocument();
    expect(within(nav).getByText("SIEM")).toBeInTheDocument();
    expect(within(nav).getByText("Network")).toBeInTheDocument();
  });

  it("defaults to the All bucket — every adapter is visible on open", () => {
    render(
      <CatalogPopout
        open
        onClose={() => undefined}
        onConfigured={() => undefined}
        initialCatalog={CATALOG}
      />,
    );
    const list = screen.getByTestId("catalog-adapter-list");
    expect(within(list).getByTestId("catalog-adapter-datto")).toBeInTheDocument();
    expect(within(list).getByTestId("catalog-adapter-wazuh")).toBeInTheDocument();
    expect(within(list).getByTestId("catalog-adapter-unifi")).toBeInTheDocument();
  });

  it("switches the right pane when a different category is picked", () => {
    render(
      <CatalogPopout
        open
        onClose={() => undefined}
        onConfigured={() => undefined}
        initialCatalog={CATALOG}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /SIEM/ }));
    const list = screen.getByTestId("catalog-adapter-list");
    expect(within(list).getByTestId("catalog-adapter-wazuh")).toBeInTheDocument();
    expect(within(list).queryByTestId("catalog-adapter-datto")).not.toBeInTheDocument();
  });

  it("shows every adapter when the All bucket is picked", () => {
    render(
      <CatalogPopout
        open
        onClose={() => undefined}
        onConfigured={() => undefined}
        initialCatalog={CATALOG}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /All/ }));
    const list = screen.getByTestId("catalog-adapter-list");
    expect(within(list).getByTestId("catalog-adapter-wazuh")).toBeInTheDocument();
    expect(within(list).getByTestId("catalog-adapter-datto")).toBeInTheDocument();
    expect(within(list).getByTestId("catalog-adapter-unifi")).toBeInTheDocument();
  });

  it("filters the visible adapters by the search box", () => {
    render(
      <CatalogPopout
        open
        onClose={() => undefined}
        onConfigured={() => undefined}
        initialCatalog={CATALOG}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /All/ }));
    fireEvent.change(screen.getByPlaceholderText("Filter adapters…"), {
      target: { value: "datto" },
    });
    const list = screen.getByTestId("catalog-adapter-list");
    expect(within(list).getByTestId("catalog-adapter-datto")).toBeInTheDocument();
    expect(within(list).queryByTestId("catalog-adapter-wazuh")).not.toBeInTheDocument();
    expect(within(list).queryByTestId("catalog-adapter-unifi")).not.toBeInTheDocument();
  });
});

describe("CatalogPopout — step transition", () => {
  it("advances to the configure step when an adapter card is clicked", () => {
    render(
      <CatalogPopout
        open
        onClose={() => undefined}
        onConfigured={() => undefined}
        initialCatalog={CATALOG}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /SIEM/ }));
    fireEvent.click(screen.getByTestId("catalog-adapter-wazuh"));
    // Configure step shows the adapter name in the header + a cred input
    expect(screen.getAllByText("Wazuh").length).toBeGreaterThan(0);
    expect(screen.getByLabelText(/API key/)).toBeInTheDocument();
    // Back button is present so the operator can pick a different adapter
    expect(screen.getByRole("button", { name: /Back to catalog/ })).toBeInTheDocument();
  });

  it("returns to the browse step when the back link is clicked", () => {
    render(
      <CatalogPopout
        open
        onClose={() => undefined}
        onConfigured={() => undefined}
        initialCatalog={CATALOG}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /SIEM/ }));
    fireEvent.click(screen.getByTestId("catalog-adapter-wazuh"));
    fireEvent.click(screen.getByRole("button", { name: /Back to catalog/ }));
    expect(screen.getByTestId("catalog-adapter-list")).toBeInTheDocument();
  });

  it("calls onClose when the overlay is clicked", () => {
    const onClose = vi.fn();
    render(
      <CatalogPopout
        open
        onClose={onClose}
        onConfigured={() => undefined}
        initialCatalog={CATALOG}
      />,
    );
    fireEvent.click(screen.getByLabelText("Close"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
