import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import OperatorsTab from "@/pages/settings/operators";
import type { MeResponse, OperatorListEntry } from "@/contracts/operator";
import type { ClientEntry } from "@/lib/api";

/**
 * Settings → Operators: a viewer is a CLIENT user. The invite form makes
 * the admin pick the viewer's tenant(s) from the active tenants (no '*', no
 * empty scope, no tenant still carrying its vendor-named placeholder); the
 * scope editor never saves a viewer as '*' or empty; the "+ role" menu
 * never grants viewer on '*'. analyst+ keep the '*' default. The server
 * refuses all of it too — its message is shown in full when it does.
 *
 * The real `@/lib/api` runs against a stubbed fetch.
 */

const OPS = "/api/v1/admin/operators";
const CLIENTS = "/api/v1/admin/clients";

const ME = { operator_id: 1, username: "alice", email: "alice@example.test", role: ["admin"] } as unknown as MeResponse;

function op(over: Partial<OperatorListEntry> & { id: number; username: string }): OperatorListEntry {
  return {
    email: `${over.username}@example.test`,
    roles: ["analyst"],
    scope_slugs: ["*"],
    mfa_enabled: true,
    must_change_password: false,
    disabled_at: null,
    last_login_at: null,
    created_at: "2026-09-01T00:00:00.000Z",
    is_factory: false,
    l2_llm_granted: false,
    ...over,
  };
}

const CLIENT_LIST: ClientEntry[] = [
  { slug: "acme-corp", display_name: "Acme Corp", status: "active" },
  { slug: "globex", display_name: "Globex", status: "active" },
  { slug: "datto-site-1a2b3c4d", display_name: "datto site 1a2b3c4d", status: "active", placeholder_name: true, placeholder_slug: true },
  { slug: "datto-site-9f8e7d6c", display_name: "Widget West", status: "active", placeholder_slug: true },
];

function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

interface Call { url: string; method: string; body: Record<string, unknown> | undefined }

function stubBackend(operators: OperatorListEntry[], refuse: string | null = null): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, opts?: RequestInit) => {
    const method = opts?.method ?? "GET";
    const body = typeof opts?.body === "string" ? JSON.parse(opts.body) : undefined;
    calls.push({ url, method, body });
    if (url === OPS && method === "GET") return jsonResponse(200, { operators });
    if (url === CLIENTS && method === "GET") return jsonResponse(200, { clients: CLIENT_LIST });
    if (refuse && method === "POST") {
      return jsonResponse(422, { code: "VALIDATION_FAILED", message: refuse });
    }
    if (url === OPS && method === "POST") {
      return jsonResponse(200, {
        operator_id: 9, username: body.username, email: body.email, role: body.role,
        state: "pending", activation_path: "deliver it",
        magic_link_url: "https://athena.example.test/login/magic?token=x",
        magic_link_expires_at: "2026-09-29T00:00:00.000Z",
      });
    }
    if (/\/role\/grant$/.test(url) && method === "POST") {
      return jsonResponse(200, { operator_id: 2, granted: body.role, scope_slugs: body.scope_slugs });
    }
    return jsonResponse(404, { code: "NOT_FOUND", message: `unexpected ${method} ${url}` });
  }));
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function openCreate(): Promise<ReturnType<typeof within>> {
  fireEvent.click(await screen.findByText("+ New operator"));
  const form = screen.getByText("Create operator", { selector: "h2" }).closest("form")!;
  const f = within(form);
  fireEvent.change(f.getAllByRole("textbox")[0]!, { target: { value: "bob" } });
  fireEvent.change(form.querySelector('input[type="email"]')!, { target: { value: "bob@example.test" } });
  return f;
}

describe("OperatorsTab — inviting a viewer", () => {
  it("picks the viewer's tenants from the active ones; placeholders can't be picked", async () => {
    const calls = stubBackend([]);
    render(<OperatorsTab me={ME} />);
    const f = await openCreate();
    fireEvent.change(f.getByRole("combobox"), { target: { value: "viewer" } });

    const picker = within(await waitFor(() => screen.getByTestId("viewer-tenant-picker")));
    await waitFor(() => picker.getByLabelText("invite to acme-corp"));
    // No free-text scope, no '*' anywhere to type or tick.
    expect(f.queryByText(/Scope slugs/)).toBeNull();
    expect(picker.queryByLabelText(/all tenants/)).toBeNull();
    expect(picker.getByLabelText("invite to datto-site-1a2b3c4d")).toBeDisabled();
    expect(picker.getByText("placeholder name — rename it under Tenants first")).toBeInTheDocument();
    expect(picker.getByLabelText("invite to datto-site-9f8e7d6c")).toBeDisabled();
    expect(picker.getByText(/placeholder slug — merge it/)).toBeInTheDocument();

    // Nothing picked: Create stays off.
    const submit = f.getByRole("button", { name: "Create operator" });
    expect(submit).toBeDisabled();
    fireEvent.click(picker.getByLabelText("invite to globex"));
    fireEvent.click(picker.getByLabelText("invite to acme-corp"));
    expect(submit).toBeEnabled();
    fireEvent.click(submit);

    await waitFor(() => expect(calls.some((c) => c.url === OPS && c.method === "POST")).toBe(true));
    const post = calls.find((c) => c.url === OPS && c.method === "POST")!;
    expect(post.body).toEqual({
      username: "bob", email: "bob@example.test", role: "viewer", scope_slugs: ["acme-corp", "globex"],
    });
  });

  it("an analyst keeps the all-tenants default", async () => {
    const calls = stubBackend([]);
    render(<OperatorsTab me={ME} />);
    const f = await openCreate();
    expect(screen.queryByTestId("viewer-tenant-picker")).toBeNull();
    fireEvent.click(f.getByRole("button", { name: "Create operator" }));
    await waitFor(() => expect(calls.some((c) => c.url === OPS && c.method === "POST")).toBe(true));
    const post = calls.find((c) => c.url === OPS && c.method === "POST")!;
    expect(post.body).toMatchObject({ role: "analyst", scope_slugs: ["*"] });
  });
});

describe("OperatorsTab — changing a viewer's scope", () => {
  const VIEWER = op({ id: 2, username: "carol", roles: ["viewer"], scope_slugs: ["acme-corp"] });

  it("never saves a viewer as all tenants or as nothing", async () => {
    const calls = stubBackend([VIEWER]);
    render(<OperatorsTab me={ME} />);
    fireEvent.click(await screen.findByTestId("scope-editor-carol"));
    const menu = within(screen.getByRole("menu"));
    await waitFor(() => menu.getByLabelText("scope globex"));
    expect(menu.getByLabelText("all tenants")).toBeDisabled();
    expect(menu.getByLabelText("scope datto-site-9f8e7d6c")).toBeDisabled();

    // Untick the only tenant: Save is off and says why.
    fireEvent.click(menu.getByLabelText("scope acme-corp"));
    const save = menu.getByRole("button", { name: "Save scope" });
    expect(save).toBeDisabled();
    expect(menu.getByRole("alert")).toHaveTextContent(/viewer is a client user/);
    fireEvent.click(save);
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);

    // Another named tenant: saved through the viewer's own role.
    fireEvent.click(menu.getByLabelText("scope globex"));
    expect(save).toBeEnabled();
    fireEvent.click(save);
    await waitFor(() => expect(calls.some((c) => /\/role\/grant$/.test(c.url))).toBe(true));
    const grant = calls.find((c) => /\/role\/grant$/.test(c.url))!;
    expect(grant.url).toBe(`${OPS}/2/role/grant`);
    expect(grant.body).toEqual({ role: "viewer", scope_slugs: ["globex"] });
  });

  it("a viewer scoped '*' before the rule can be narrowed — not saved as is", async () => {
    const calls = stubBackend([op({ id: 3, username: "dave", roles: ["viewer"], scope_slugs: ["*"] })]);
    render(<OperatorsTab me={ME} />);
    fireEvent.click(await screen.findByTestId("scope-editor-dave"));
    const menu = within(screen.getByRole("menu"));
    await waitFor(() => menu.getByLabelText("scope globex"));
    const save = menu.getByRole("button", { name: "Save scope" });
    expect(save).toBeDisabled();
    fireEvent.click(menu.getByLabelText("scope globex"));     // enabled for a viewer despite '*'
    expect(save).toBeEnabled();
    fireEvent.click(save);
    await waitFor(() => expect(calls.some((c) => /\/role\/grant$/.test(c.url))).toBe(true));
    expect(calls.find((c) => /\/role\/grant$/.test(c.url))!.body).toEqual({
      role: "viewer", scope_slugs: ["globex"],
    });
  });

  it("drops a tenant since offboarded (not listed, so not untickable) on save", async () => {
    const calls = stubBackend([op({ id: 8, username: "ivy", roles: ["viewer"], scope_slugs: ["acme-corp", "gone-co"] })]);
    render(<OperatorsTab me={ME} />);
    fireEvent.click(await screen.findByTestId("scope-editor-ivy"));
    const menu = within(screen.getByRole("menu"));
    await waitFor(() => menu.getByLabelText("scope globex"));
    fireEvent.click(menu.getByLabelText("scope globex"));
    fireEvent.click(menu.getByRole("button", { name: "Save scope" }));
    await waitFor(() => expect(calls.some((c) => /\/role\/grant$/.test(c.url))).toBe(true));
    expect(calls.find((c) => /\/role\/grant$/.test(c.url))!.body).toEqual({
      role: "viewer", scope_slugs: ["acme-corp", "globex"],
    });
  });

  it("an analyst's editor still offers all tenants", async () => {
    stubBackend([op({ id: 4, username: "erin", roles: ["analyst"], scope_slugs: ["acme-corp"] })]);
    render(<OperatorsTab me={ME} />);
    fireEvent.click(await screen.findByTestId("scope-editor-erin"));
    const menu = within(screen.getByRole("menu"));
    expect(menu.getByLabelText("all tenants")).toBeEnabled();
  });
});

describe("OperatorsTab — granting viewer from the role menu", () => {
  it("refuses locally on an all-tenants operator; carries a concrete scope over", async () => {
    const calls = stubBackend([
      op({ id: 5, username: "frank", roles: ["analyst"], scope_slugs: ["*"] }),
      op({ id: 6, username: "gina", roles: ["analyst"], scope_slugs: ["acme-corp"] }),
    ]);
    render(<OperatorsTab me={ME} />);

    fireEvent.click(await screen.findByTestId("grant-role-frank"));
    fireEvent.click(within(screen.getByRole("menu")).getByRole("menuitem", { name: "Viewer" }));
    expect(await screen.findByTestId("operator-error-frank")).toHaveTextContent(
      /viewer is a client user and needs specific tenants/,
    );
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);

    fireEvent.click(screen.getByTestId("grant-role-gina"));
    fireEvent.click(within(screen.getByRole("menu")).getByRole("menuitem", { name: "Viewer" }));
    await waitFor(() => expect(calls.some((c) => /\/role\/grant$/.test(c.url))).toBe(true));
    expect(calls.find((c) => /\/role\/grant$/.test(c.url))!.body).toEqual({
      role: "viewer", scope_slugs: ["acme-corp"],
    });
  });

  it("shows the server's refusal in full, not a bare 'error'", async () => {
    const message = "tenant 'globex' still has the placeholder name it was auto-created with";
    stubBackend([op({ id: 7, username: "hank", roles: ["viewer"], scope_slugs: ["acme-corp"] })], message);
    render(<OperatorsTab me={ME} />);
    fireEvent.click(await screen.findByTestId("scope-editor-hank"));
    const menu = within(screen.getByRole("menu"));
    await waitFor(() => menu.getByLabelText("scope globex"));
    fireEvent.click(menu.getByLabelText("scope globex"));
    fireEvent.click(menu.getByRole("button", { name: "Save scope" }));
    expect(await screen.findByTestId("operator-error-hank")).toHaveTextContent(message);
  });
});
