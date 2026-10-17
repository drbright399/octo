/**
 * KnownBenignPanel — the operator-editable list that DOWNGRADES specific
 * blocked domains for specific reasons (never an allowlist: NextDNS keeps
 * blocking; Athena files the alert at the rule's level, labelled "known
 * benign"). Seeded with the Samsung connectivity probe.
 *
 * Everyone who can see it reads it; admins add / edit / disable (a reason is
 * required, every change is audited). Patterns: an exact name, a suffix, or
 * a restricted regex the server validates (letters, digits, '-', '.', a
 * [class], ? * + {n,m} — nothing that can run away). Text nodes only.
 */
import { type FC, useCallback, useEffect, useState } from "react";

import type { KnownBenignInput, KnownBenignRule } from "@/contracts/entity";
import { createKnownBenign, listKnownBenign, updateKnownBenign } from "@/lib/entity";

const input =
  "rounded-sm border border-border bg-bg-card px-1 py-0.5 text-[11px] text-text-primary";
const btn =
  "rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[10px] text-text-secondary hover:border-border-bright disabled:opacity-50";

const EMPTY: KnownBenignInput = {
  vendor: "nextdns", match_kind: "suffix", pattern: "", reasons: ["threat-intelligence-feeds"],
  level: "low", label: "", note: "", enabled: true, reason: "",
};

export const KnownBenignPanel: FC<{ readonly canEdit: boolean }> = ({ canEdit }) => {
  const [rules, setRules] = useState<KnownBenignRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState<KnownBenignInput>(EMPTY);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setRules(await listKnownBenign());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "The rules could not be loaded");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async (fn: () => Promise<KnownBenignRule[]>): Promise<void> => {
    setBusy(true);
    try {
      setRules(await fn());
      setError(null);
      setDraft(EMPTY);
    } catch (e) {
      setError(e instanceof Error ? e.message : "The rule was not saved");
    } finally {
      setBusy(false);
    }
  };

  const toggle = (r: KnownBenignRule): void => {
    const why = window.prompt(r.enabled ? "Why disable this rule?" : "Why enable this rule?") ?? "";
    if (why.trim().length < 3) return;
    void save(() => updateKnownBenign(r.id, {
      vendor: r.vendor, match_kind: r.match_kind, pattern: r.pattern, reasons: [...r.reasons],
      level: r.level, label: r.label, note: r.note, enabled: !r.enabled, reason: why.trim(),
    }));
  };

  return (
    <section data-testid="known-benign-panel" className="rounded-lg border border-border bg-bg-surface p-4 text-[12px]">
      <h2 className="text-sm font-semibold text-text-primary">Known-benign lookups</h2>
      <p className="mb-2 text-[11px] text-text-dim">
        A matching block is filed at the rule's level with its label — and stays BLOCKED at the vendor. Never an allowlist.
      </p>
      {error ? <p role="alert" className="mb-2 text-[11px] text-critical">{error}</p> : null}
      <table className="w-full text-left text-[11px]">
        <thead className="text-text-dim">
          <tr><th>Label</th><th>Match</th><th>Reasons</th><th>Level</th><th>State</th><th /></tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.id} data-testid={`kb-rule-${r.id}`} className="border-t border-border">
              <td className="py-1 text-text-primary" title={r.note}>{r.label}</td>
              <td className="font-mono">{r.match_kind}: {r.pattern}</td>
              <td>{r.reasons.join(", ")}</td>
              <td className="uppercase">{r.level}</td>
              <td>{r.enabled ? "on" : "off"}</td>
              <td>{canEdit ? (
                <button type="button" className={btn} disabled={busy} onClick={() => toggle(r)}
                  data-testid={`kb-toggle-${r.id}`}>
                  {r.enabled ? "Disable" : "Enable"}
                </button>
              ) : null}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {canEdit ? (
        <div className="mt-3 flex flex-wrap items-center gap-1" data-testid="kb-new">
          <select aria-label="match kind" className={input} value={draft.match_kind}
            onChange={(e) => setDraft({ ...draft, match_kind: e.target.value as KnownBenignInput["match_kind"] })}>
            <option value="exact">exact</option>
            <option value="suffix">suffix</option>
            <option value="regex">regex</option>
          </select>
          <input aria-label="pattern" className={input} placeholder="pattern" maxLength={200}
            value={draft.pattern} onChange={(e) => setDraft({ ...draft, pattern: e.target.value })} />
          <input aria-label="reasons" className={input} placeholder="reason ids, comma-separated" maxLength={300}
            value={draft.reasons.join(",")}
            onChange={(e) => setDraft({ ...draft, reasons: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) })} />
          <input aria-label="label" className={input} placeholder="label" maxLength={120}
            value={draft.label} onChange={(e) => setDraft({ ...draft, label: e.target.value })} />
          <input aria-label="why" className={input} placeholder="why (required)" maxLength={500}
            value={draft.reason} onChange={(e) => setDraft({ ...draft, reason: e.target.value })} />
          <button type="button" className={btn} data-testid="kb-add"
            disabled={busy || !draft.pattern || draft.label.length < 3 || draft.reason.trim().length < 3}
            onClick={() => void save(() => createKnownBenign(draft))}>
            Add rule
          </button>
        </div>
      ) : null}
    </section>
  );
};

export default KnownBenignPanel;
