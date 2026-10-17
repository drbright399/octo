/**
 * The Tickets agent-activity feed's query_kind chip (v0.11): "ask:<kind>"
 * only for the closed set of operator questions; a vendor-originated note
 * (RocketCyber's PSA ticket recorded later — query_kind 'vendor_update') is
 * "vendor update", never "Operator asked"; autonomous and unknown kinds get
 * no chip.
 */
import { describe, expect, it } from "vitest";

import { agentNoteKindChip } from "@/lib/tickets";

describe("agentNoteKindChip", () => {
  it("labels an operator question as ask:<kind>", () => {
    expect(agentNoteKindChip("suggest_next_steps")).toEqual({
      label: "ask:suggest-next-steps", title: "Operator asked: suggest next steps", tone: "ask",
    });
  });

  it("labels a vendor-originated note as a vendor update, not an ask", () => {
    const chip = agentNoteKindChip("vendor_update");
    expect(chip).toEqual({
      label: "vendor update",
      title: "Recorded from a vendor update (not an operator question)", tone: "vendor",
    });
    expect(chip?.title).not.toMatch(/Operator asked/);
  });

  it("shows nothing for autonomous or unknown kinds", () => {
    expect(agentNoteKindChip(null)).toBeNull();
    expect(agentNoteKindChip(undefined)).toBeNull();
    expect(agentNoteKindChip("auto_enrich")).toBeNull();
    expect(agentNoteKindChip("something_new")).toBeNull();
  });
});
