import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { CatalogPopout } from "@/components/catalog-popout";
import { OnboardingGuide } from "@/components/onboarding-guide";
import { OneTimeSecretPanel } from "@/components/one-time-secret-panel";
import type {
  CatalogAdapter,
  CatalogResponse,
  GeneratedWebhookSecret,
  Onboarding,
} from "@/contracts/integration";

// The mapping step talks to its own endpoints; it is not under test here.
vi.mock("@/components/tenant-mapping-panel", () => ({
  TenantMappingPanel: () => <div data-testid="tenant-mapping-stub" />,
}));

const TOKEN = "fixture-generated-token-0123456789abcdefghijklmnopqrstuvwxyz-AB";
const INGEST_URL = "https://ingest.example.test/api/v1/webhooks/datto";
const NO_INGEST =
  "No public ingest hostname is configured for this deployment — real-time webhooks cannot work until one is set.";

const RECOVERY = "Settings → Integrations → Datto RMM → Disable, then Add integration again";

const SECRET: GeneratedWebhookSecret = {
  credential_field: "DATTO_WEBHOOK_SECRET",
  credential_label: "Webhook Token",
  header_name: "X-Webhook-Token",
  header_value: TOKEN,
  webhook_url: INGEST_URL,
  webhook_url_problem: null,
};

const DATTO: CatalogAdapter = {
  vendor_slug: "datto",
  vendor_display_name: "Datto RMM",
  vendor_logo_path: "",
  vendor_category: "rmm",
  auth_model: "api-key",
  delivery_mode: "hybrid",
  availability: "available",
  compliance_categories: [],
  credential_shape: [
    { name: "DATTO_API_KEY", label: "API key", kind: "password", required: true },
    {
      name: "DATTO_WEBHOOK_SECRET",
      label: "Webhook Token",
      kind: "password",
      required: false,
      secret_origin: "platform",
      webhook_header: "X-Webhook-Token",
    },
  ],
};

const RESEND: CatalogAdapter = {
  ...DATTO,
  vendor_slug: "resend",
  vendor_display_name: "Resend",
  vendor_category: "other",
  delivery_mode: "push",
  credential_shape: [
    { name: "RESEND_API_KEY", label: "API key", kind: "password", required: true },
    {
      name: "RESEND_WEBHOOK_SECRET",
      label: "Webhook Signing Secret",
      kind: "password",
      required: false,
      secret_origin: "vendor",
    },
  ],
};

const CATALOG: CatalogResponse = {
  adapters: [DATTO, RESEND],
  categories: [
    { category: "rmm", display_label: "RMM", adapters: [DATTO] },
    { category: "other", display_label: "Other", adapters: [RESEND] },
  ],
};

function everythingPersistent(): string {
  return [
    JSON.stringify({ ...window.localStorage }),
    JSON.stringify({ ...window.sessionStorage }),
    window.location.href,
    document.cookie,
  ].join("\n");
}

function mockCreate(generated: GeneratedWebhookSecret | null) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => ({
      instance: {
        id: 7,
        vendor_slug: "datto",
        status: "running",
        status_detail: null,
        configured_at: "2026-01-01T00:00:00.000Z",
        last_test_at: null,
        warnings: [],
      },
      smoke_test_message: "ok",
      generated_webhook_secret: generated,
    }),
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function sentBody(fetchMock: ReturnType<typeof vi.fn>): Record<string, unknown> {
  const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
  return JSON.parse(String(init.body)) as Record<string, unknown>;
}

beforeEach(() => {
  window.localStorage.clear();
  window.sessionStorage.clear();
  Object.assign(navigator, {
    clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("OneTimeSecretPanel", () => {
  it("shows the header name, masks the value, and says it is shown once", () => {
    render(<OneTimeSecretPanel vendorName="Datto RMM" secret={SECRET} onContinue={() => undefined} />);
    expect(screen.getByText("X-Webhook-Token")).toBeInTheDocument();
    expect(screen.getByText(INGEST_URL)).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(/shown once/i);
    expect(screen.getByRole("alert")).toHaveTextContent(/cannot be displayed again/i);
    // Recovery is named by its exact click path — the control exists.
    expect(screen.getByRole("alert")).toHaveTextContent(RECOVERY);
    // Store it safely NOW; do NOT attach before sites are mapped.
    expect(screen.getByRole("alert")).toHaveTextContent(/somewhere SAFE now \(a password manager\)/);
    expect(screen.getByRole("alert")).toHaveTextContent(
      /Do NOT attach the webhook to a Datto RMM monitor until you have mapped your sites on the next screen/,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      /alerts from unmapped sites create pending tenants or are held for review/,
    );
    expect(document.body).not.toHaveTextContent(/into Datto RMM now/i);
    // Operator-facing text uses the field LABEL, never the env-style name.
    expect(document.body).toHaveTextContent("Webhook Token");
    expect(document.body.innerHTML).not.toContain("DATTO_WEBHOOK_SECRET");
    // Masked by default: the token is nowhere in the DOM.
    expect(screen.getByTestId("one-time-secret-value")).not.toHaveTextContent(TOKEN);
    expect(document.body.innerHTML).not.toContain(TOKEN);
  });

  it("reveals and re-hides the value on demand", () => {
    render(<OneTimeSecretPanel vendorName="Datto RMM" secret={SECRET} onContinue={() => undefined} />);
    fireEvent.click(screen.getByRole("button", { name: "reveal" }));
    expect(screen.getByTestId("one-time-secret-value")).toHaveTextContent(TOKEN);
    fireEvent.click(screen.getByRole("button", { name: "hide" }));
    expect(document.body.innerHTML).not.toContain(TOKEN);
  });

  it("copies the real value (even while masked), the header name and the URL", async () => {
    render(<OneTimeSecretPanel vendorName="Datto RMM" secret={SECRET} onContinue={() => undefined} />);
    fireEvent.click(screen.getByRole("button", { name: "Copy header value" }));
    expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith(TOKEN);
    fireEvent.click(screen.getByRole("button", { name: "Copy header name" }));
    expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith("X-Webhook-Token");
    fireEvent.click(screen.getByRole("button", { name: "Copy webhook URL" }));
    expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith(INGEST_URL);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Copy webhook URL" })).toHaveTextContent("copied ✓"),
    );
    // A successful copy never reveals the token.
    expect(document.body.innerHTML).not.toContain(TOKEN);
    expect(screen.queryByTestId("token-copy-failed")).not.toBeInTheDocument();
  });

  it("says 'copied' only AFTER the clipboard write resolves", async () => {
    let resolveWrite: () => void = () => undefined;
    const writeText = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolveWrite = resolve;
        }),
    );
    Object.assign(navigator, { clipboard: { writeText } });
    render(<OneTimeSecretPanel vendorName="Datto RMM" secret={SECRET} onContinue={() => undefined} />);
    const button = screen.getByRole("button", { name: "Copy header value" });
    fireEvent.click(button);
    expect(writeText).toHaveBeenCalledWith(TOKEN);
    expect(button).toHaveTextContent("copy");
    expect(button).not.toHaveTextContent("copied");
    await act(async () => {
      resolveWrite();
    });
    expect(button).toHaveTextContent("copied ✓");
  });

  it("a REJECTED clipboard write never says 'copied': it reveals the token and says copy manually", async () => {
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockRejectedValue(new Error("NotAllowedError")) },
    });
    render(<OneTimeSecretPanel vendorName="Datto RMM" secret={SECRET} onContinue={() => undefined} />);
    expect(document.body.innerHTML).not.toContain(TOKEN);
    const button = screen.getByRole("button", { name: "Copy header value" });
    fireEvent.click(button);

    expect(await screen.findByTestId("token-copy-failed")).toHaveTextContent(
      /copy failed — select it and copy manually/i,
    );
    expect(button).not.toHaveTextContent("copied");
    expect(button).toHaveTextContent(/copy failed/i);
    // Auto-revealed so it CAN be selected by hand.
    expect(screen.getByTestId("one-time-secret-value")).toHaveTextContent(TOKEN);
    expect(screen.getByRole("button", { name: "hide" })).toBeInTheDocument();
    // Still nowhere persistent.
    expect(everythingPersistent()).not.toContain(TOKEN);
  });

  it("an UNDEFINED clipboard API (plain-HTTP / LAN console) is a failed copy, not a silent one", async () => {
    Object.assign(navigator, { clipboard: undefined });
    render(<OneTimeSecretPanel vendorName="Datto RMM" secret={SECRET} onContinue={() => undefined} />);
    const button = screen.getByRole("button", { name: "Copy header value" });
    fireEvent.click(button);

    expect(await screen.findByTestId("token-copy-failed")).toHaveTextContent(
      /copy failed — select it and copy manually/i,
    );
    expect(button).not.toHaveTextContent("copied");
    expect(screen.getByTestId("one-time-secret-value")).toHaveTextContent(TOKEN);
  });

  it("keeps the payload templates on screen with the token — collapsed, each with a copy button", async () => {
    const steps = [
      { title: "1 · Fill in the API keys and save", body: "Save first." },
      {
        title: "4 · Alert-raised payload template",
        body: "Raised body.",
        code_sample: '{"event": "alert_raised"}',
      },
      {
        title: "5 · Alert-resolved payload template",
        body: "Resolved body.",
        code_sample: '{"event": "alert_resolved"}',
      },
    ];
    render(
      <OneTimeSecretPanel vendorName="Datto RMM" secret={SECRET} steps={steps} onContinue={() => undefined} />,
    );
    const section = screen.getByTestId("secret-panel-templates");
    const blocks = section.querySelectorAll("details");
    expect(blocks).toHaveLength(2); // only the steps that carry a template
    blocks.forEach((d) => expect(d.open).toBe(false));
    expect(section).toHaveTextContent("4 · Alert-raised payload template");
    expect(section).toHaveTextContent(/Settings → Integrations → Datto RMM → Setup guide/);

    const copyResolved = "Copy template: 5 · Alert-resolved payload template";
    fireEvent.click(screen.getByRole("button", { name: copyResolved, hidden: true }));
    expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith('{"event": "alert_resolved"}');
    await waitFor(() =>
      expect(screen.getByRole("button", { name: copyResolved, hidden: true })).toHaveTextContent(
        "copied ✓",
      ),
    );
  });

  it("renders no template section when the adapter has none", () => {
    render(<OneTimeSecretPanel vendorName="Datto RMM" secret={SECRET} onContinue={() => undefined} />);
    expect(screen.queryByTestId("secret-panel-templates")).not.toBeInTheDocument();
  });

  it("says so — and offers no URL — when no ingest hostname is configured", () => {
    render(
      <OneTimeSecretPanel
        vendorName="Datto RMM"
        secret={{ ...SECRET, webhook_url: null, webhook_url_problem: NO_INGEST }}
        onContinue={() => undefined}
      />,
    );
    expect(screen.getByTestId("no-ingest-host-notice")).toHaveTextContent(
      /no public ingest hostname is configured/i,
    );
    expect(screen.queryByRole("button", { name: "Copy webhook URL" })).not.toBeInTheDocument();
  });
});

describe("OnboardingGuide — no ingest hostname", () => {
  const ONB: Onboarding = {
    summary: "Connect Datto in two parts.",
    webhook_url: null,
    webhook_url_problem: NO_INGEST,
    steps: [{ title: "Add the webhook", body: "Configure it in Datto.", copy_value: null }],
  };

  it("shows the explicit notice instead of any webhook URL", () => {
    render(<OnboardingGuide onboarding={ONB} deliveryMode="hybrid" />);
    expect(screen.getByTestId("no-ingest-host-notice")).toHaveTextContent(
      /real-time webhooks cannot work until one is set/i,
    );
    expect(screen.queryByText(/paste this into the vendor/i)).not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain("/api/v1/webhooks/");
  });

  it("stays quiet for poll adapters and when a URL exists", () => {
    const { unmount } = render(<OnboardingGuide onboarding={ONB} deliveryMode="poll" />);
    expect(screen.queryByTestId("no-ingest-host-notice")).not.toBeInTheDocument();
    unmount();
    render(
      <OnboardingGuide
        onboarding={{ ...ONB, webhook_url: INGEST_URL, webhook_url_problem: null }}
        deliveryMode="hybrid"
      />,
    );
    expect(screen.queryByTestId("no-ingest-host-notice")).not.toBeInTheDocument();
    expect(screen.getByText(/paste this into the vendor/i)).toBeInTheDocument();
  });
});

describe("CatalogPopout — platform-generated webhook token", () => {
  const openDatto = (onClose = () => undefined) => {
    const view = render(
      <CatalogPopout open onClose={onClose} onConfigured={() => undefined} initialCatalog={CATALOG} />,
    );
    fireEvent.click(screen.getByTestId("catalog-adapter-datto"));
    fireEvent.change(screen.getByLabelText(/API key/), { target: { value: "fixture-api-key" } });
    return view;
  };

  it("defaults to real-time webhooks ON and asks the platform to generate the token", async () => {
    const fetchMock = mockCreate(SECRET);
    openDatto();
    expect(screen.getByRole("checkbox", { name: /Enable real-time webhooks/ })).toBeChecked();

    fireEvent.click(screen.getByRole("button", { name: "Save & encrypt" }));
    await screen.findByTestId("one-time-secret-panel");

    const body = sentBody(fetchMock);
    expect(body.enable_webhook).toBe(true);
    expect((body.credentials as Record<string, string>).DATTO_WEBHOOK_SECRET).toBe("");
    expect((fetchMock.mock.calls[0]?.[1] as RequestInit).cache).toBe("no-store");

    // Header to configure on the vendor side, masked value, reveal on demand.
    expect(screen.getByText("X-Webhook-Token")).toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(TOKEN);
    fireEvent.click(screen.getByRole("button", { name: "reveal" }));
    expect(screen.getByTestId("one-time-secret-value")).toHaveTextContent(TOKEN);

    // Component state only — never storage, URL or cookies.
    expect(everythingPersistent()).not.toContain(TOKEN);
  });

  it("drops the token when the operator continues", async () => {
    mockCreate(SECRET);
    openDatto();
    fireEvent.click(screen.getByRole("button", { name: "Save & encrypt" }));
    await screen.findByTestId("one-time-secret-panel");
    fireEvent.click(screen.getByRole("button", { name: "reveal" }));

    fireEvent.click(screen.getByRole("button", { name: /continue/i }));
    await screen.findByTestId("tenant-mapping-stub");
    expect(screen.queryByTestId("one-time-secret-panel")).not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(TOKEN);
    expect(everythingPersistent()).not.toContain(TOKEN);
  });

  it("drops the token when the wizard closes, and reopening cannot show it", async () => {
    mockCreate(SECRET);
    const props = { onConfigured: () => undefined, initialCatalog: CATALOG };
    const { rerender } = render(<CatalogPopout open onClose={() => undefined} {...props} />);
    fireEvent.click(screen.getByTestId("catalog-adapter-datto"));
    fireEvent.change(screen.getByLabelText(/API key/), { target: { value: "fixture-api-key" } });
    fireEvent.click(screen.getByRole("button", { name: "Save & encrypt" }));
    await screen.findByTestId("one-time-secret-panel");
    fireEvent.click(screen.getByRole("button", { name: "reveal" }));

    rerender(<CatalogPopout open={false} onClose={() => undefined} {...props} />);
    expect(document.body.innerHTML).not.toContain(TOKEN);
    rerender(<CatalogPopout open onClose={() => undefined} {...props} />);
    await waitFor(() => expect(screen.getByTestId("catalog-adapter-list")).toBeInTheDocument());
    expect(screen.queryByTestId("one-time-secret-panel")).not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(TOKEN);
  });

  it("does not let a stray backdrop click discard the one-time token", async () => {
    mockCreate(SECRET);
    const onClose = vi.fn();
    openDatto(onClose);
    fireEvent.click(screen.getByRole("button", { name: "Save & encrypt" }));
    await screen.findByTestId("one-time-secret-panel");
    const backdrop = document.querySelector('[aria-hidden="true"].fixed');
    expect(backdrop).not.toBeNull();
    fireEvent.click(backdrop as Element);
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByTestId("one-time-secret-panel")).toBeInTheDocument();
  });

  it("the header ✕ on the secret step asks first — declining keeps the token on screen", async () => {
    mockCreate(SECRET);
    const onClose = vi.fn();
    const confirmMock = vi.fn().mockReturnValue(false);
    vi.stubGlobal("confirm", confirmMock);
    openDatto(onClose);
    fireEvent.click(screen.getByRole("button", { name: "Save & encrypt" }));
    await screen.findByTestId("one-time-secret-panel");

    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(confirmMock).toHaveBeenCalledWith("The token cannot be shown again — close anyway?");
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByTestId("one-time-secret-panel")).toBeInTheDocument();

    // Confirming is an explicit decision: then it closes.
    confirmMock.mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("the header ✕ closes without asking on every other step", () => {
    const onClose = vi.fn();
    const confirmMock = vi.fn().mockReturnValue(false);
    vi.stubGlobal("confirm", confirmMock);
    openDatto(onClose);
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(confirmMock).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("the secret screen carries the adapter's payload templates", async () => {
    mockCreate(SECRET);
    const withGuide: CatalogAdapter = {
      ...DATTO,
      onboarding: {
        summary: "Connect Datto.",
        webhook_url: INGEST_URL,
        steps: [
          { title: "1 · Save", body: "Save first." },
          {
            title: "4 · Alert-raised payload template",
            body: "b",
            code_sample: '{"event": "alert_raised"}',
          },
        ],
      },
    };
    render(
      <CatalogPopout
        open
        onClose={() => undefined}
        onConfigured={() => undefined}
        initialCatalog={{ adapters: [withGuide], categories: [] }}
      />,
    );
    fireEvent.click(screen.getByTestId("catalog-adapter-datto"));
    fireEvent.change(screen.getByLabelText(/API key/), { target: { value: "fixture-api-key" } });
    fireEvent.click(screen.getByRole("button", { name: "Save & encrypt" }));
    await screen.findByTestId("one-time-secret-panel");
    expect(screen.getByTestId("secret-panel-templates")).toHaveTextContent(
      "4 · Alert-raised payload template",
    );
  });

  it("no ingest hostname: webhooks default OFF and the form says what to do, in plain words", async () => {
    const fetchMock = mockCreate(null);
    const noHost: CatalogAdapter = {
      ...DATTO,
      onboarding: {
        summary: "Connect Datto.",
        webhook_url: null,
        webhook_url_problem: NO_INGEST,
        steps: [{ title: "1 · Save", body: "Save first." }],
      },
    };
    render(
      <CatalogPopout
        open
        onClose={() => undefined}
        onConfigured={() => undefined}
        initialCatalog={{ adapters: [noHost], categories: [] }}
      />,
    );
    fireEvent.click(screen.getByTestId("catalog-adapter-datto"));
    expect(screen.getByRole("checkbox", { name: /Enable real-time webhooks/ })).not.toBeChecked();
    const hint = screen.getByTestId("no-ingest-host-webhook-hint");
    expect(hint).toHaveTextContent(/no public ingest hostname/i);
    expect(hint).toHaveTextContent(/start poll-only/i);
    expect(hint).toHaveTextContent(/compose file/i);
    expect(hint).toHaveTextContent(/docker-compose\.yml/);
    expect(hint).toHaveTextContent(/recreate the octo-core container/i);
    expect(hint).toHaveTextContent(/bundle deploy guide \(docs\/operations\/bundle\.md\)/);
    expect(hint).toHaveTextContent(RECOVERY);

    fireEvent.change(screen.getByLabelText(/API key/), { target: { value: "fixture-api-key" } });
    fireEvent.click(screen.getByRole("button", { name: "Save & encrypt" }));
    await screen.findByTestId("tenant-mapping-stub");
    expect(sentBody(fetchMock).enable_webhook).toBe(false);
  });

  it("the form no longer claims the browser never holds a value it is about to show", () => {
    openDatto();
    expect(document.body).not.toHaveTextContent(/browser never holds/i);
    expect(document.body).toHaveTextContent(/The browser does not store them/);
    // One product name inside the wizard; a short token-field label.
    expect(document.body).not.toHaveTextContent(/\bOCTO\b/);
    expect(document.body).not.toHaveTextContent(/The platform/);
    expect(screen.getByLabelText(/Webhook Token/)).toBeInTheDocument();
    expect(document.body).toHaveTextContent("Webhook Token (optional)");
    expect(document.body).not.toHaveTextContent(/blank = generate it for me/);
  });

  it("poll-only: hides the token field, sends enable_webhook=false and no token", async () => {
    const fetchMock = mockCreate(null);
    openDatto();
    fireEvent.change(screen.getByLabelText(/Webhook Token/), {
      target: { value: "typed-then-abandoned-token-0123456789abcdef" },
    });
    fireEvent.click(screen.getByRole("checkbox", { name: /Enable real-time webhooks/ }));
    expect(screen.queryByLabelText(/Webhook Token/)).not.toBeInTheDocument();
    expect(screen.getByText(/Poll-only/)).toBeInTheDocument();
    // "Turn it on later" names the exact recovery path.
    expect(screen.getByText(/Poll-only/)).toHaveTextContent(RECOVERY);

    fireEvent.click(screen.getByRole("button", { name: "Save & encrypt" }));
    await screen.findByTestId("tenant-mapping-stub");
    const body = sentBody(fetchMock);
    expect(body.enable_webhook).toBe(false);
    expect((body.credentials as Record<string, string>).DATTO_WEBHOOK_SECRET).toBe("");
    expect(screen.queryByTestId("one-time-secret-panel")).not.toBeInTheDocument();
  });

  it("an operator-supplied token skips the one-time screen", async () => {
    const fetchMock = mockCreate(null);
    openDatto();
    const own = "operator-supplied-token-0123456789abcdef";
    fireEvent.change(screen.getByLabelText(/Webhook Token/), { target: { value: own } });
    fireEvent.click(screen.getByRole("button", { name: "Save & encrypt" }));
    await screen.findByTestId("tenant-mapping-stub");
    const body = sentBody(fetchMock);
    expect(body.enable_webhook).toBe(true);
    expect((body.credentials as Record<string, string>).DATTO_WEBHOOK_SECRET).toBe(own);
  });

  it("vendor-issued secrets (Resend) get no generate toggle — paste only", async () => {
    const fetchMock = mockCreate(null);
    render(
      <CatalogPopout open onClose={() => undefined} onConfigured={() => undefined} initialCatalog={CATALOG} />,
    );
    fireEvent.click(screen.getByTestId("catalog-adapter-resend"));
    expect(screen.queryByRole("checkbox", { name: /Enable real-time webhooks/ })).not.toBeInTheDocument();
    expect(screen.getByText(/issued by the vendor/i)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/API key/), { target: { value: "fixture-api-key" } });
    fireEvent.click(screen.getByRole("button", { name: "Save & encrypt" }));
    await screen.findByTestId("tenant-mapping-stub");
    expect("enable_webhook" in sentBody(fetchMock)).toBe(false);
  });
});
