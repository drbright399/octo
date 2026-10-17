import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  INDICATOR_TYPES,
  INDICATOR_TYPE_LABEL,
  indicatorSearchHref,
  parseIndicatorRef,
} from "@/contracts/indicator";

// The indicators.db schema the contract mirrors (migration 002).
const MIGRATION = resolve(
  __dirname, "../../../octo/migrations/002-initialize-client-dbs.sql",
);

describe("indicator contract", () => {
  it("IndicatorType is exactly the indicators.db CHECK list", () => {
    const sql = readFileSync(MIGRATION, "utf8");
    const m = /type\s+TEXT NOT NULL\s+CHECK \(type IN \(([^)]*)\)\)/.exec(sql);
    expect(m, "indicators.type CHECK list not found").not.toBeNull();
    const check = m![1]!.split(",").map((t) => t.trim().replace(/'/g, ""));
    expect([...INDICATOR_TYPES].sort()).toEqual([...check].sort());
    // Every type has a label (no raw slug leaking into the widget).
    for (const t of INDICATOR_TYPES) expect(INDICATOR_TYPE_LABEL[t]).toBeTruthy();
  });

  it("parses a search_ref into tenant + row id, rejecting anything else", () => {
    expect(parseIndicatorRef("acme-corp:42")).toEqual({ tenant: "acme-corp", id: 42 });
    for (const bad of [null, undefined, "", "acme-corp", ":42", "acme-corp:",
                       "acme-corp:0", "acme-corp:-3", "acme-corp:4.5",
                       "acme-corp:203.0.113.5"]) {
      expect(parseIndicatorRef(bad)).toBeNull();
    }
  });

  it("links a search_ref to the step-up-gated indicator search", () => {
    expect(indicatorSearchHref("acme-corp:42"))
      .toBe("/search/indicators?indicator=acme-corp%3A42");
  });
});
