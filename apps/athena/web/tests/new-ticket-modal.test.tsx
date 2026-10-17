import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

import NewTicketModal from "@/components/new-ticket-modal";
import * as ticketsLib from "@/lib/tickets";
import type { TicketDetail } from "@/lib/tickets";

let metaSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  // The live default: PSA writes switched OFF.
  metaSpy = vi.spyOn(ticketsLib, "fetchTicketsMeta")
    .mockResolvedValue({ psa_writes_enabled: false });
});

afterEach(() => {
  vi.restoreAllMocks();
  cleanup();
});

const STUB_TICKET: TicketDetail = {
  id: 42,
  client_slug: "acme",
  autotask_id: null,
  title: "stub",
  severity: "medium",
  status: "new",
  assignee_operator_id: null,
  queue: null,
  source_event_id: null,
  opened_at: "2026-05-14T00:00:00Z",
  updated_at: "2026-05-14T00:00:00Z",
  agent_note_count: 0,
  description: "",
  closed_at: null,
  last_autotask_sync_at: null,
  due_at: null,
  push_to_autotask: false,
  is_billable: true,
  billing_code_id: null,
  contract_id: null,
  charges: [],
  push_state: null,
  status_history: [],
  agent_insights: [],
  agent_pattern_links: [],
};

describe("NewTicketModal", () => {
  it("creates a ticket with title + severity defaults and forwards to onCreated", async () => {
    const createSpy = vi.spyOn(ticketsLib, "createTicket")
      .mockResolvedValue(STUB_TICKET);
    const onCreated = vi.fn();
    const onClose = vi.fn();

    render(
      <NewTicketModal
        tenants={["acme", "demo-co"]}
        onClose={onClose}
        onCreated={onCreated}
      />,
    );

    fireEvent.change(screen.getByPlaceholderText(/Short summary of the issue/i), {
      target: { value: "Database CPU at 95%" },
    });
    fireEvent.click(screen.getByRole("button", { name: /create ticket/i }));

    await waitFor(() => expect(createSpy).toHaveBeenCalled());
    expect(createSpy).toHaveBeenCalledWith("acme", expect.objectContaining({
      title: "Database CPU at 95%",
      severity: "medium",
    }));
    await waitFor(() => expect(onCreated).toHaveBeenCalledWith(STUB_TICKET));
  });

  it("does not submit when title is blank", () => {
    const createSpy = vi.spyOn(ticketsLib, "createTicket")
      .mockResolvedValue(STUB_TICKET);

    render(
      <NewTicketModal
        tenants={["acme"]}
        onClose={vi.fn()}
        onCreated={vi.fn()}
      />,
    );

    const submit = screen.getByRole("button", { name: /create ticket/i });
    expect(submit).toBeDisabled();
    fireEvent.click(submit);
    expect(createSpy).not.toHaveBeenCalled();
  });

  it("surfaces backend errors and keeps the form open", async () => {
    vi.spyOn(ticketsLib, "createTicket")
      .mockRejectedValue(new Error("ISOLATION_VIOLATION"));
    const onCreated = vi.fn();

    render(
      <NewTicketModal
        tenants={["acme"]}
        onClose={vi.fn()}
        onCreated={onCreated}
      />,
    );

    fireEvent.change(screen.getByPlaceholderText(/Short summary of the issue/i), {
      target: { value: "test" },
    });
    fireEvent.click(screen.getByRole("button", { name: /create ticket/i }));

    await waitFor(() =>
      expect(screen.getByRole("alert"))
        .toHaveTextContent("ISOLATION_VIOLATION"),
    );
    expect(onCreated).not.toHaveBeenCalled();
  });

  it("warns when the operator has no tenants in scope", () => {
    render(
      <NewTicketModal
        tenants={[]}
        onClose={vi.fn()}
        onCreated={vi.fn()}
      />,
    );
    expect(screen.getByText(/no tenants in scope/i)).toBeInTheDocument();
  });

  it("new-ticket-modal hides push when disabled", async () => {
    const createSpy = vi.spyOn(ticketsLib, "createTicket")
      .mockResolvedValue(STUB_TICKET);
    const pushSpy = vi.spyOn(ticketsLib, "requestAutotaskPush");

    render(
      <NewTicketModal
        tenants={["acme"]}
        onClose={vi.fn()}
        onCreated={vi.fn()}
      />,
    );
    await waitFor(() => expect(metaSpy).toHaveBeenCalled());

    fireEvent.click(screen.getByText(/autotask options/i));
    expect(await screen.findByTestId("psa-writes-off")).toHaveTextContent(/switched off/i);
    expect(screen.queryByLabelText(/Push this ticket to Autotask/i)).toBeNull();
    expect(screen.queryByText(/push on/i)).toBeNull();

    fireEvent.change(screen.getByPlaceholderText(/Short summary of the issue/i), {
      target: { value: "Printer offline" },
    });
    fireEvent.click(screen.getByRole("button", { name: /create ticket/i }));

    await waitFor(() => expect(createSpy).toHaveBeenCalled());
    expect(createSpy).toHaveBeenCalledWith("acme", expect.objectContaining({
      push_to_autotask: false,
    }));
    expect(pushSpy).not.toHaveBeenCalled();
  });

  it("hides push when the switch cannot be read (fails closed)", async () => {
    metaSpy.mockRejectedValue(new Error("503"));
    render(
      <NewTicketModal
        tenants={["acme"]}
        onClose={vi.fn()}
        onCreated={vi.fn()}
      />,
    );
    await waitFor(() => expect(metaSpy).toHaveBeenCalled());
    fireEvent.click(screen.getByText(/autotask options/i));
    expect(await screen.findByTestId("psa-writes-off")).toBeInTheDocument();
    expect(screen.queryByLabelText(/Push this ticket to Autotask/i)).toBeNull();
  });

  it("sends Autotask opts + inline charges + fires push when checkbox set", async () => {
    metaSpy.mockResolvedValue({ psa_writes_enabled: true });
    const createSpy = vi.spyOn(ticketsLib, "createTicket")
      .mockResolvedValue(STUB_TICKET);
    const pushSpy = vi.spyOn(ticketsLib, "requestAutotaskPush")
      .mockResolvedValue({
        state: "pending", attempts: 0,
        last_attempt_at: null, last_error: null,
        autotask_ticket_id: null,
        queued_at: "2026-05-14T00:00:00Z",
        queued_by_operator_id: 1,
      });

    render(
      <NewTicketModal
        tenants={["acme"]}
        onClose={vi.fn()}
        onCreated={vi.fn()}
      />,
    );

    fireEvent.change(screen.getByPlaceholderText(/Short summary of the issue/i), {
      target: { value: "Replaced UPS battery" },
    });

    // Expand the Autotask options panel + enable push (offered once the
    // server says writes are on).
    fireEvent.click(screen.getByText(/autotask options/i));
    fireEvent.click(await screen.findByLabelText(/Push this ticket to Autotask/i));
    expect(screen.queryByTestId("psa-writes-off")).toBeNull();

    // Add a single charge line.
    fireEvent.click(screen.getByRole("button", { name: /\+ line/i }));
    fireEvent.change(screen.getByPlaceholderText(/APC RBC11/i), {
      target: { value: "APC RBC11 battery" },
    });

    fireEvent.click(screen.getByRole("button", { name: /create ticket/i }));

    await waitFor(() => expect(createSpy).toHaveBeenCalled());
    expect(createSpy).toHaveBeenCalledWith("acme", expect.objectContaining({
      push_to_autotask: true,
      is_billable: true,
      charges: [expect.objectContaining({ name: "APC RBC11 battery" })],
    }));
    await waitFor(() => expect(pushSpy).toHaveBeenCalledWith("acme", 42));
  });

  it("does NOT call requestAutotaskPush when push checkbox is left off", async () => {
    vi.spyOn(ticketsLib, "createTicket").mockResolvedValue(STUB_TICKET);
    const pushSpy = vi.spyOn(ticketsLib, "requestAutotaskPush")
      .mockResolvedValue({
        state: "pending", attempts: 0,
        last_attempt_at: null, last_error: null,
        autotask_ticket_id: null, queued_at: null,
        queued_by_operator_id: null,
      });

    render(
      <NewTicketModal
        tenants={["acme"]}
        onClose={vi.fn()}
        onCreated={vi.fn()}
      />,
    );
    fireEvent.change(screen.getByPlaceholderText(/Short summary of the issue/i), {
      target: { value: "Athena-only ticket" },
    });
    fireEvent.click(screen.getByRole("button", { name: /create ticket/i }));

    await waitFor(() =>
      expect(ticketsLib.createTicket).toHaveBeenCalled(),
    );
    expect(pushSpy).not.toHaveBeenCalled();
  });
});
