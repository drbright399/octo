import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import AgentNotesPanel from "@/components/agent-notes-panel";

/**
 * Ask-Octo says where the model ran (v0.10): the console never leaves an
 * operator guessing whether a tenant "cleared for cloud" had its data sent
 * to a cloud model — the bridge answers `llm_locality`, and the reply line
 * shows it. The real `@/lib/api` runs against a stubbed fetch.
 */

function stub(locality: "local" | "cloud" | undefined) {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    if (url.startsWith("/api/v1/agent-notes/")) {
      return { ok: true, status: 200, json: async () => ({ notes: [] }) };
    }
    return {
      ok: true, status: 200,
      json: async () => ({
        note: {
          id: 7, agent_id: "octo", note_text: "More context.", confidence: 0.5,
          created_at: "2026-09-28T10:00:00.000Z", updated_at: null, query_kind: "tell_me_more",
          ref_kind: "event", ref_id: 3,
        },
        llm_took_ms: 42, bridge_took_ms: 50, effective_ai_policy: "cloud",
        ...(locality ? { llm_locality: locality } : {}),
      }),
    };
  }));
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("AgentNotesPanel — Ask Octo reply", () => {
  it.each([
    ["local", "octo replied (+42ms · local model)"],
    ["cloud", "octo replied (+42ms · cloud model)"],
    [undefined, "octo replied (+42ms · local model)"],   // an older bridge
  ] as const)("names where the model ran (%s)", async (locality, text) => {
    stub(locality);
    render(
      <AgentNotesPanel
        notes={[]} clientSlug="acme-corp" refKind="event" refId={3}
        heuristicNote="Three failed logins" askBarStartOpen
      />,
    );
    fireEvent.click(screen.getByText("Tell me more"));
    await waitFor(() => expect(screen.getByText(text)).toBeInTheDocument());
  });
});
