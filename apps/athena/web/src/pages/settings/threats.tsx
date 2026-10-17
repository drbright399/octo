/**
 * Settings → Threats (Tier Black slice 1): the tier rules (read only — a
 * rule is code, promoted by release), per-client rule coverage, the ASSET
 * TAGS (911 / life-safety first: an analyst may tag an asset `life_safety`
 * — every lockdown request carves it out; the tags that change what
 * detection does need an admin; clearing any tag needs an admin), and the
 * registry views: exceptions (a super_admin creates one, with step-up,
 * ≤ 90 d), analyst verdicts (written by a false-positive close), the
 * remote-access registry (read view), the canary scanner allowlist, the
 * storm brake. EVIDENCE WINDOWS (Rick, 2026-10-05: a confirmed threat's first
 * detection → its all-clear is evidence, kept by every retention path until
 * an admin releases it): each window's start, end or "open", rows kept and
 * ~events; an analyst may WIDEN one back (a reason), an admin RELEASE one
 * after the all-clear (step-up, a reason; the other admins are told). Every
 * change is audited on the server BEFORE it is written, with the reason
 * typed here.
 *
 * v0.17.2 — EXPECTED CONDITIONS (analyst+): every condition an analyst made
 * from a Fleet alert ("this is expected"), its review date (≤ 90 days; on it
 * the condition stops — no renewal), the reason, who made it; REVOKE (a
 * reason, audited, the other admins are told). Active by default, "all"
 * shows the expired and revoked ones too.
 */
import { type FC, useCallback, useEffect, useState } from "react";

import type { ExpectedRule } from "@/contracts/fleet";
import type { EvidenceWindow } from "@/contracts/incidents";
import type { MeResponse } from "@/contracts/operator";
import { ApiError } from "@/lib/api";
import { fetchExpectedRules, revokeExpectedRule } from "@/lib/fleet";
import {
  ASSET_TAGS,
  addAllowlist,
  addAssetTag,
  addException,
  clearAssetTag,
  fetchAssetTags,
  fetchBrakes,
  fetchEvidenceWindows,
  fetchRegistry,
  fetchRestrictedSettings,
  fetchRules,
  putRestrictedSettings,
  releaseEvidenceWindow,
  setBrake,
  utc,
  widenEvidenceWindow,
  windowLine,
  type AssetTag,
  type RestrictedSettings,
  type RuleRow,
} from "@/lib/incidents";

const SUPPRESSIVE = new Set(["lab", "evidence_hold", "dev", "kiosk", "hands_off"]);
const input = "rounded-sm border border-border bg-bg-input px-1.5 py-0.5 text-[11px]";
const button = "rounded-sm border border-border bg-bg-card px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest text-accent hover:border-accent disabled:opacity-50";

const Section: FC<{ title: string; testid: string; children: React.ReactNode }> = ({
  title, testid, children,
}) => (
  <section data-testid={testid} className="flex flex-col gap-2 rounded-sm border border-border bg-bg-surface p-3">
    <h3 className="font-mono text-[10px] uppercase tracking-widest text-text-dim">{title}</h3>
    {children}
  </section>
);

function err(e: unknown, fallback: string): string {
  return e instanceof ApiError ? e.message : fallback;
}

const Rows: FC<{ rows: Record<string, unknown>[]; cols: string[]; empty: string }> = ({
  rows, cols, empty,
}) => rows.length === 0 ? <div className="text-[11px] text-text-dim">{empty}</div> : (
  <table className="w-full text-left text-[11px]">
    <thead><tr>{cols.map((c) => <th key={c} className="font-mono text-[9px] uppercase text-text-dim">{c}</th>)}</tr></thead>
    <tbody>
      {rows.map((r, i) => (
        <tr key={String(r.id ?? i)}>{cols.map((c) => <td key={c} className="pr-2">{String(r[c] ?? "—")}</td>)}</tr>
      ))}
    </tbody>
  </table>
);

const ThreatsTab: FC<{ me: MeResponse | null }> = ({ me }) => {
  const roles = me?.role ?? [];
  const admin = roles.includes("admin") || roles.includes("super_admin");
  const superAdmin = roles.includes("super_admin");
  const [rules, setRules] = useState<RuleRow[]>([]);
  const [tags, setTags] = useState<AssetTag[]>([]);
  const [registry, setRegistry] = useState<Record<string, Record<string, unknown>[]>>({});
  const [brakes, setBrakes] = useState<Record<string, unknown>[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [tag, setTag] = useState({ tenant: "", ref_kind: "device" as "device" | "path",
                                   device_ref: "", tag: "life_safety", reason: "" });
  const [allow, setAllow] = useState({ tenant: "", ip: "", label: "", reason: "" });
  const [exc, setExc] = useState({ tenant: "", binding_kind: "path_prefix", binding: "",
                                   rule_id: "R2-W", days: 30, reason: "" });
  const [brake, setBrakeForm] = useState({ rule_id: "R6", hours: 4, reason: "" });
  const [windows, setWindows] = useState<EvidenceWindow[]>([]);
  const [windowState, setWindowState] = useState<"held" | "released" | "all">("held");
  const [restrictedSettings, setRestrictedSettings] = useState<RestrictedSettings | null>(null);
  const [restrictedReason, setRestrictedReason] = useState("");
  const allScope = (me?.scope_slugs ?? []).includes("*");
  const [expected, setExpected] = useState<ExpectedRule[]>([]);
  const [expectedState, setExpectedState] = useState<"active" | "all">("active");

  const load = useCallback(() => {
    fetchRules().then(setRules).catch((e: unknown) => setError(err(e, "rules not loaded")));
    fetchAssetTags().then(setTags).catch((e: unknown) => setError(err(e, "tags not loaded")));
    fetchEvidenceWindows(windowState).then(setWindows)
      .catch((e: unknown) => setError(err(e, "evidence windows not loaded")));
    fetchExpectedRules(expectedState).then(setExpected)
      .catch((e: unknown) => setError(err(e, "expected conditions not loaded")));
    if (admin) {
      for (const t of ["exceptions", "verdicts", "remote-access", "canary-allowlist"] as const) {
        fetchRegistry(t).then((r) => setRegistry((prev) => ({ ...prev, [t]: r })))
          .catch(() => undefined);
      }
      fetchBrakes().then(setBrakes).catch(() => undefined);
      fetchRestrictedSettings().then(setRestrictedSettings).catch(() => undefined);
    }
  }, [admin, windowState, expectedState]);
  useEffect(() => { load(); }, [load]);

  const act = (fn: () => Promise<unknown>): void => {
    setError(null);
    fn().then(load).catch((e: unknown) => setError(err(e, "The change was refused")));
  };

  return (
    <div className="flex flex-col gap-3" data-testid="threats-tab">
      {error && <div className="rounded-sm border border-critical/40 bg-critical/10 px-3 py-1.5 text-[11px] text-critical">{error}</div>}

      <Section title="tier rules (code — no switch)" testid="threats-rules">
        <table className="w-full text-left text-[11px]">
          <thead><tr>{["rule", "tier", "stage", "kind", "coverage"].map((c) =>
            <th key={c} className="font-mono text-[9px] uppercase text-text-dim">{c}</th>)}</tr></thead>
          <tbody>
            {rules.map((r) => {
              const missing = Object.entries(r.coverage).filter(([, c]) => !c.covered);
              return (
                <tr key={r.id} data-testid={`rule-${r.id}`}>
                  <td>{r.id}@{r.version} · {r.title}</td>
                  <td>{r.tier}</td>
                  <td>{r.stage}{r.braked_until ? ` · braked until ${r.braked_until}` : ""}</td>
                  <td>{r.kind}</td>
                  <td>{missing.length === 0 ? "covered" : `not covered at ${missing.map(([t]) => t).join(", ")}`}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Section>

      <Section title="asset tags — 911 / life-safety systems are never blocked" testid="threats-tags">
        <Rows rows={tags as unknown as Record<string, unknown>[]}
              cols={["tenant_slug", "ref_kind", "device_ref", "tag", "reason", "set_at"]}
              empty="No asset tagged yet." />
        {admin && tags.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {tags.map((t) => (
              <button key={t.id} type="button" className={button} data-testid={`tag-clear-${t.id}`}
                      onClick={() => {
                        const reason = window.prompt(`Clear '${t.tag}' on ${t.device_ref}? Reason:`);
                        if (reason) act(() => clearAssetTag(t.id, reason));
                      }}>clear {t.tag} · {t.device_ref}</button>
            ))}
          </div>
        )}
        <form className="flex flex-wrap items-center gap-1" data-testid="tag-form"
              onSubmit={(e) => { e.preventDefault(); act(() => addAssetTag(tag)); }}>
          <input className={input} placeholder="tenant slug" value={tag.tenant}
                 onChange={(e) => setTag({ ...tag, tenant: e.target.value })} />
          <select className={input} value={tag.ref_kind}
                  onChange={(e) => setTag({ ...tag, ref_kind: e.target.value as "device" | "path" })}>
            <option value="device">device</option><option value="path">path / network</option>
          </select>
          <input className={input} placeholder={tag.ref_kind === "path" ? "address or network (192.0.2.0/24)" : "host name or address"} value={tag.device_ref}
                 onChange={(e) => setTag({ ...tag, device_ref: e.target.value })} />
          <select className={input} value={tag.tag} data-testid="tag-select"
                  onChange={(e) => setTag({ ...tag, tag: e.target.value })}>
            {ASSET_TAGS.filter((t) => admin || !SUPPRESSIVE.has(t)).map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input className={input} placeholder="reason (required)" value={tag.reason}
                 onChange={(e) => setTag({ ...tag, reason: e.target.value })} />
          <button type="submit" className={button}
                  disabled={!tag.tenant || !tag.device_ref || tag.reason.trim().length < 3}>tag</button>
        </form>
        {!admin && (
          <div className="text-[10px] text-text-dim">
            Tags that change what detection does (lab, evidence hold, dev, kiosk, hands-off) and
            clearing a tag need an admin.
          </div>
        )}
      </Section>

      <Section title="expected conditions — matching alerts stay grey until the review date (no renewal)"
               testid="threats-expected">
        <div className="flex items-center gap-1 text-[11px]">
          <select className={input} value={expectedState} data-testid="expected-state"
                  onChange={(e) => setExpectedState(e.target.value as "active" | "all")}>
            <option value="active">active</option>
            <option value="all">all</option>
          </select>
          <span className="text-text-dim">
            Made from a Fleet alert with &quot;this is expected&quot;; never for a CSAM lookup or
            anything a Red / Black rests on.
          </span>
        </div>
        {expected.length === 0 ? (
          <div className="text-[11px] text-text-dim">No expected condition.</div>
        ) : (
          <table className="w-full text-left text-[11px]">
            <thead><tr>{["#", "client", "what", "reason", "made", "review", "state", ""].map((c) =>
              <th key={c} className="font-mono text-[9px] uppercase text-text-dim">{c}</th>)}</tr></thead>
            <tbody>
              {expected.map((r) => (
                <tr key={r.id} data-testid={`expected-row-${r.id}`}>
                  <td className="pr-2">#{r.id}</td>
                  <td className="pr-2">{r.tenant_slug}</td>
                  <td className="pr-2" title={`${r.signature_key} · ${r.device_key}`}>
                    {r.label}{r.remote ? ` · from ${r.remote}` : ""}
                  </td>
                  <td className="pr-2">{r.reason}</td>
                  <td className="pr-2">{r.created_by_name ?? `#${r.created_by}`} · {utc(r.created_at)}</td>
                  <td className="pr-2">{r.review_at.slice(0, 10)}</td>
                  <td className="pr-2">
                    {r.status === "revoked"
                      ? `revoked${r.revoked_by_name ? ` by ${r.revoked_by_name}` : ""}`
                      : r.status}
                  </td>
                  <td>
                    {r.status === "active" && (
                      <button type="button" className={button} data-testid={`expected-revoke-${r.id}`}
                              onClick={() => {
                                const reason = window.prompt(
                                  `Revoke expected condition #${r.id} (${r.label})? Matching alerts turn the site yellow again. Reason:`);
                                if (reason) act(() => revokeExpectedRule(r.id, reason));
                              }}>revoke</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section title="evidence windows — a confirmed threat's first detection → its all-clear, kept until released"
               testid="threats-evidence">
        <div className="flex items-center gap-1 text-[11px]">
          <select className={input} value={windowState} data-testid="evidence-state"
                  onChange={(e) => setWindowState(e.target.value as "held" | "released" | "all")}>
            <option value="held">held</option>
            <option value="released">released</option>
            <option value="all">all</option>
          </select>
          <span className="text-text-dim">
            Everything of the client inside a held window is kept by every retention path;
            ingestion never stops for one.
          </span>
        </div>
        {windows.length === 0 ? (
          <div className="text-[11px] text-text-dim">No evidence window.</div>
        ) : (
          <table className="w-full text-left text-[11px]">
            <thead><tr>{["client", "incident", "window", "state", ""].map((c) =>
              <th key={c} className="font-mono text-[9px] uppercase text-text-dim">{c}</th>)}</tr></thead>
            <tbody>
              {windows.map((w) => (
                <tr key={`${w.tenant_slug}-${w.id}`} data-testid={`evidence-row-${w.id}`}>
                  <td className="pr-2">{w.tenant_name}</td>
                  <td className="pr-2">
                    #{w.incident_id}{w.incident_tier ? ` ${w.incident_tier.toUpperCase()}` : ""}
                    {w.incident_open === null ? "" : w.incident_open ? " · open" : " · closed"}
                  </td>
                  <td className="pr-2">
                    #{w.id} · {w.kind === "incident" ? "auto" : "manual"} · {windowLine(w)}
                  </td>
                  <td className="pr-2">
                    {w.held ? "held" : `released ${utc(w.released_at ?? "")}${w.released_by_name ? ` by ${w.released_by_name}` : ""}`}
                  </td>
                  <td>
                    {w.held && (
                      <span className="inline-flex gap-1">
                        <button type="button" className={button} data-testid={`evidence-row-widen-${w.id}`}
                                onClick={() => {
                                  const start = window.prompt(`Widen window #${w.id} back to (UTC, before ${utc(w.start)}):`, w.start);
                                  if (!start) return;
                                  const reason = window.prompt("Why does it start earlier? (required)");
                                  if (reason) act(() => widenEvidenceWindow(w.tenant_slug, w.incident_id, w.id, start, reason));
                                }}>widen</button>
                        {admin && w.incident_open === false && (
                          <button type="button" className={button} data-testid={`evidence-row-release-${w.id}`}
                                  onClick={() => {
                                    const reason = window.prompt(
                                      `Release window #${w.id} (${windowLine(w)})? Its rows then age out normally; the other admins are told. Reason:`);
                                    if (reason) act(() => releaseEvidenceWindow(w.tenant_slug, w.incident_id, w.id, reason));
                                  }}>release (step-up)</button>
                        )}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {!admin && (
          <div className="text-[10px] text-text-dim">
            Releasing a window (after the all-clear) needs an admin with a fresh sign-in check.
          </div>
        )}
      </Section>

      {admin && (
        <>
          <Section title="restricted incidents (CSAM, B7) — what the client sees"
                   testid="threats-restricted">
            <div className="text-[11px] text-text-secondary">
              {restrictedSettings?.help
                ?? "Restricted (CSAM) incidents are admin-only; the client sees nothing by default."}
            </div>
            <div className="text-[11px]" data-testid="restricted-state">
              Client notice: <strong>{restrictedSettings === null ? "…"
                : restrictedSettings.csam_client_notice ? "ON — the neutral line only"
                  : "OFF — suppressed (default)"}</strong>
            </div>
            {allScope ? (
              <form className="flex flex-wrap items-center gap-1" data-testid="restricted-form"
                    onSubmit={(e) => {
                      e.preventDefault();
                      if (!restrictedSettings) return;
                      const target = !restrictedSettings.csam_client_notice;
                      act(() => putRestrictedSettings(target, restrictedReason.trim())
                        .then((s) => { setRestrictedSettings(s); setRestrictedReason(""); }));
                    }}>
                <input className={input} placeholder="reason (required)" value={restrictedReason}
                       data-testid="restricted-reason"
                       onChange={(e) => setRestrictedReason(e.target.value)} />
                <button type="submit" className={button} data-testid="restricted-toggle"
                        disabled={restrictedSettings === null || restrictedReason.trim().length < 3}>
                  {restrictedSettings?.csam_client_notice ? "turn off" : "turn on"}
                </button>
              </form>
            ) : (
              <div className="text-[10px] text-text-dim">
                An MSP-wide switch: an admin with every client in scope changes it.
              </div>
            )}
          </Section>

          <Section title="canary scanner allowlist (R6's precondition)" testid="threats-allowlist">
            <Rows rows={registry["canary-allowlist"] ?? []} cols={["tenant_slug", "ip", "label", "added_at"]}
                  empty="No scanner allowlisted — R6 is not covered anywhere." />
            <form className="flex flex-wrap items-center gap-1"
                  onSubmit={(e) => { e.preventDefault(); act(() => addAllowlist(allow)); }}>
              <input className={input} placeholder="tenant slug" value={allow.tenant}
                     onChange={(e) => setAllow({ ...allow, tenant: e.target.value })} />
              <input className={input} placeholder="scanner IP" value={allow.ip}
                     onChange={(e) => setAllow({ ...allow, ip: e.target.value })} />
              <input className={input} placeholder="label" value={allow.label}
                     onChange={(e) => setAllow({ ...allow, label: e.target.value })} />
              <input className={input} placeholder="reason (required)" value={allow.reason}
                     onChange={(e) => setAllow({ ...allow, reason: e.target.value })} />
              <button type="submit" className={button} disabled={allow.reason.trim().length < 3}>add</button>
            </form>
          </Section>

          <Section title="exceptions (≤ 90 days; never cancel hostile facts)" testid="threats-exceptions">
            <Rows rows={registry.exceptions ?? []}
                  cols={["tenant_slug", "rule_id", "binding_kind", "binding", "expires_at", "revoked_at"]}
                  empty="No exception." />
            {superAdmin && (
              <form className="flex flex-wrap items-center gap-1"
                    onSubmit={(e) => { e.preventDefault(); act(() => addException(exc)); }}>
                <input className={input} placeholder="tenant slug" value={exc.tenant}
                       onChange={(e) => setExc({ ...exc, tenant: e.target.value })} />
                <select className={input} value={exc.binding_kind}
                        onChange={(e) => setExc({ ...exc, binding_kind: e.target.value })}>
                  <option value="path_prefix">path prefix</option>
                  <option value="product_instance">product + instance</option>
                  <option value="signature">signature</option>
                </select>
                <input className={input} placeholder="binding" value={exc.binding}
                       onChange={(e) => setExc({ ...exc, binding: e.target.value })} />
                <input className={input} placeholder="rule" value={exc.rule_id}
                       onChange={(e) => setExc({ ...exc, rule_id: e.target.value })} />
                <input className={input} type="number" min={1} max={90} value={exc.days}
                       onChange={(e) => setExc({ ...exc, days: Number(e.target.value) })} />
                <input className={input} placeholder="reason (required)" value={exc.reason}
                       onChange={(e) => setExc({ ...exc, reason: e.target.value })} />
                <button type="submit" className={button} disabled={exc.reason.trim().length < 3}>
                  create (step-up)
                </button>
              </form>
            )}
          </Section>

          <Section title="analyst verdicts (false-positive closes)" testid="threats-verdicts">
            <Rows rows={registry.verdicts ?? []}
                  cols={["tenant_slug", "rule_id", "verdict_key", "reason", "expires_at"]}
                  empty="No verdict." />
          </Section>

          <Section title="remote-access registry (read view)" testid="threats-registry">
            <Rows rows={registry["remote-access"] ?? []}
                  cols={["tenant_slug", "product", "instance_key", "relay_host", "relationship",
                         "confirmed_on"]}
                  empty="Nothing registered yet (slice 2 seeds it)." />
          </Section>

          <Section title="storm brake (one automated rule at Red, ≤ 24 h)" testid="threats-brake">
            <Rows rows={brakes} cols={["rule_id", "set_at", "expires_at", "reason", "released_at"]}
                  empty="No brake." />
            {superAdmin && (
              <form className="flex flex-wrap items-center gap-1"
                    onSubmit={(e) => { e.preventDefault(); act(() => setBrake(brake)); }}>
                <select className={input} value={brake.rule_id}
                        onChange={(e) => setBrakeForm({ ...brake, rule_id: e.target.value })}>
                  {rules.filter((r) => r.kind === "automated" && !r.restricted).map((r) => <option key={r.id} value={r.id}>{r.id}</option>)}
                </select>
                <input className={input} type="number" min={1} max={24} value={brake.hours}
                       onChange={(e) => setBrakeForm({ ...brake, hours: Number(e.target.value) })} />
                <input className={input} placeholder="reason (required)" value={brake.reason}
                       onChange={(e) => setBrakeForm({ ...brake, reason: e.target.value })} />
                <button type="submit" className={button} disabled={brake.reason.trim().length < 3}>
                  brake (step-up)
                </button>
              </form>
            )}
          </Section>
        </>
      )}
    </div>
  );
};

export default ThreatsTab;
