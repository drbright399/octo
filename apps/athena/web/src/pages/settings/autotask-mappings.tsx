/**
 * Settings → Integrations → Autotask Mappings (P4-b2).
 *
 * super_admin populates two tables:
 *   - Tenant slug ↔ Autotask companyID (+ homepage URL)
 *   - Athena operator ↔ Autotask resourceID
 *
 * Both tables fetch their current state via the P4-b1 GET endpoints,
 * let the operator edit inline, and save via bulk PUT.
 *
 * Per the Option C strategy doc, this page is the FIRST place the
 * MSP gets after-the-fact configuration of the Autotask integration.
 * The same component should mount inside the onboarding wizard's
 * "Connect your PSA" step (P5 — onboarding workstream).
 *
 * For Autotask side data we offer two paths per row:
 *   1. Dropdown — fetched live from the configured instance via the
 *      proxy endpoints. Picking sets the id + display name.
 *   2. Manual id entry — fallback when the dropdown can't load (e.g.,
 *      operator's still configuring the integration creds).
 */
import { type FC, useCallback, useEffect, useState } from "react";
import {
  type AutotaskCompanyOption,
  type AutotaskResourceOption,
  type OperatorMapping,
  type TenantMapping,
  getOperatorMappings,
  getTenantMappings,
  listAutotaskCompanies,
  listAutotaskResources,
  putOperatorMappings,
  putTenantMappings,
} from "@/lib/autotask";
import { listClients, listOperators } from "@/lib/api";

interface Props {
  /** The adapter_instance_id of the configured Autotask integration. */
  instanceId: number;
}

interface ClientOption { slug: string; display_name: string | null }
interface OperatorOption { id: number; username: string }

const AutotaskMappingsPage: FC<Props> = ({ instanceId }) => {
  // Athena-side data (local — populated unconditionally)
  const [athenaTenants, setAthenaTenants] = useState<ClientOption[]>([]);
  const [athenaOperators, setAthenaOperators] = useState<OperatorOption[]>([]);

  // Autotask-side data (live — best-effort load, may fail if integration unhealthy)
  const [autotaskCompanies, setAutotaskCompanies] = useState<AutotaskCompanyOption[]>([]);
  const [autotaskResources, setAutotaskResources] = useState<AutotaskResourceOption[]>([]);
  const [autotaskLoadError, setAutotaskLoadError] = useState<string | null>(null);

  // Mapping rows (working copies — edited in place, saved via bulk PUT)
  const [tenantRows, setTenantRows] = useState<TenantMapping[]>([]);
  const [operatorRows, setOperatorRows] = useState<OperatorMapping[]>([]);

  const [loading, setLoading] = useState(true);
  const [savingTenants, setSavingTenants] = useState(false);
  const [savingOperators, setSavingOperators] = useState(false);
  const [tenantSaveError, setTenantSaveError] = useState<string | null>(null);
  const [operatorSaveError, setOperatorSaveError] = useState<string | null>(null);

  const refresh = useCallback(async (): Promise<void> => {
    setLoading(true);
    try {
      const [clients, operators, tenants, ops] = await Promise.all([
        listClients(),
        listOperators(),
        getTenantMappings(instanceId),
        getOperatorMappings(instanceId),
      ]);
      setAthenaTenants(clients.map((c) => ({
        slug: c.slug,
        display_name: c.display_name ?? null,
      })));
      setAthenaOperators(operators.map((o) => ({
        id: o.id,
        username: o.username,
      })));
      setTenantRows(tenants);
      setOperatorRows(ops);
    } finally {
      setLoading(false);
    }

    // Autotask side — best effort. Failures (auth, network, etc) show
    // a one-line banner above the dropdowns; manual-id entry still
    // works in that state.
    try {
      const [companies, resources] = await Promise.all([
        listAutotaskCompanies(instanceId),
        listAutotaskResources(instanceId),
      ]);
      setAutotaskCompanies(companies);
      setAutotaskResources(resources);
      setAutotaskLoadError(null);
    } catch (e) {
      setAutotaskLoadError(e instanceof Error ? e.message : String(e));
    }
  }, [instanceId]);

  useEffect(() => { void refresh(); }, [refresh]);

  // ---- tenant table mutators ----
  const addTenantRow = (): void => {
    setTenantRows((prev) => [
      ...prev,
      {
        tenant_slug: "",
        autotask_company_id: 0,
        autotask_company_name: null,
        autotask_homepage_url: null,
        updated_at: null,
        updated_by_operator_id: null,
      },
    ]);
  };
  const removeTenantRow = (idx: number): void => {
    setTenantRows((prev) => prev.filter((_, i) => i !== idx));
  };
  const updateTenantRow = (idx: number, patch: Partial<TenantMapping>): void => {
    setTenantRows((prev) =>
      prev.map((r, i) => (i === idx ? { ...r, ...patch } : r)),
    );
  };

  const saveTenants = async (): Promise<void> => {
    setSavingTenants(true);
    setTenantSaveError(null);
    try {
      const payload = tenantRows.map((r) => ({
        tenant_slug: r.tenant_slug,
        autotask_company_id: r.autotask_company_id,
        autotask_company_name: r.autotask_company_name,
        autotask_homepage_url: r.autotask_homepage_url,
      }));
      const fresh = await putTenantMappings(instanceId, payload);
      setTenantRows(fresh);
    } catch (e) {
      setTenantSaveError(e instanceof Error ? e.message : String(e));
    } finally {
      setSavingTenants(false);
    }
  };

  // ---- operator table mutators ----
  const addOperatorRow = (): void => {
    setOperatorRows((prev) => [
      ...prev,
      {
        operator_id: 0,
        autotask_resource_id: 0,
        autotask_resource_email: null,
        autotask_resource_name: null,
        updated_at: null,
        updated_by_operator_id: null,
      },
    ]);
  };
  const removeOperatorRow = (idx: number): void => {
    setOperatorRows((prev) => prev.filter((_, i) => i !== idx));
  };
  const updateOperatorRow = (idx: number, patch: Partial<OperatorMapping>): void => {
    setOperatorRows((prev) =>
      prev.map((r, i) => (i === idx ? { ...r, ...patch } : r)),
    );
  };

  const saveOperators = async (): Promise<void> => {
    setSavingOperators(true);
    setOperatorSaveError(null);
    try {
      // Only send rows with valid operator + resource ids.
      const payload = operatorRows
        .filter((r) => r.operator_id > 0 && r.autotask_resource_id > 0)
        .map((r) => ({
          operator_id: r.operator_id,
          autotask_resource_id: r.autotask_resource_id,
          autotask_resource_email: r.autotask_resource_email,
          autotask_resource_name: r.autotask_resource_name,
        }));
      const fresh = await putOperatorMappings(instanceId, payload);
      setOperatorRows(fresh);
    } catch (e) {
      setOperatorSaveError(e instanceof Error ? e.message : String(e));
    } finally {
      setSavingOperators(false);
    }
  };

  if (loading) {
    return (
      <div className="p-6 text-[12px] text-text-dim">
        loading Autotask mappings…
      </div>
    );
  }

  return (
    <section className="flex flex-col gap-6 p-6">
      <header>
        <h1 className="text-lg font-semibold uppercase tracking-wider text-text-primary">
          ✦ Autotask Mappings
        </h1>
        <p className="text-[11px] text-text-dim">
          Bridge Athena and Autotask. Edit the tables below, then save —
          changes are bulk-applied and audit-logged.
        </p>
      </header>

      {autotaskLoadError && (
        <div role="alert" className="rounded-sm border border-critical/40 bg-critical/10 px-3 py-2 text-[11px] text-critical">
          Could not load Autotask data: {autotaskLoadError}. You can still
          enter IDs manually below.
        </div>
      )}

      {/* ----- Tenant ↔ Company table ----- */}
      <section className="rounded-sm border border-border bg-bg-surface">
        <header className="flex items-baseline justify-between border-b border-border bg-bg-card px-3 py-2">
          <div>
            <h2 className="font-mono text-[10px] uppercase tracking-widest text-accent">
              ·· tenant ↔ company ··
            </h2>
            <p className="mt-0.5 text-[10px] text-text-dim">
              Maps each Athena tenant slug to its Autotask companyID. Pulled
              tickets are routed to the matching tenant's tickets.db.
            </p>
          </div>
          <button
            type="button"
            onClick={addTenantRow}
            className="rounded-sm border border-accent/60 bg-bg-surface px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-accent hover:border-accent"
          >
            + row
          </button>
        </header>

        <table className="w-full border-collapse text-[11px]">
          <thead className="border-b border-border bg-bg-card text-left text-[10px] uppercase tracking-widest text-text-dim">
            <tr>
              <th className="px-3 py-2 font-mono">athena tenant</th>
              <th className="px-3 py-2 font-mono">autotask company</th>
              <th className="px-3 py-2 font-mono">homepage url</th>
              <th className="px-3 py-2 font-mono"></th>
            </tr>
          </thead>
          <tbody>
            {tenantRows.length === 0 && (
              <tr>
                <td colSpan={4} className="px-3 py-3 text-[10px] text-text-dim">
                  No mappings yet — click <kbd className="rounded-sm border border-border px-1">+ row</kbd> to add one.
                </td>
              </tr>
            )}
            {tenantRows.map((row, idx) => (
              <tr key={idx} className="border-b border-border/60">
                <td className="px-3 py-2 align-top">
                  <select
                    value={row.tenant_slug}
                    onChange={(e) => updateTenantRow(idx, {
                      tenant_slug: e.target.value,
                    })}
                    className="w-full rounded-sm border border-border bg-bg-surface px-2 py-1 text-[11px] text-text-primary focus:border-accent focus:outline-none"
                  >
                    <option value="">— pick tenant —</option>
                    {athenaTenants.map((t) => (
                      <option key={t.slug} value={t.slug}>
                        {t.slug}{t.display_name ? ` · ${t.display_name}` : ""}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="px-3 py-2 align-top">
                  <div className="flex flex-col gap-1">
                    {autotaskCompanies.length > 0 ? (
                      <select
                        value={row.autotask_company_id || ""}
                        onChange={(e) => {
                          const id = parseInt(e.target.value, 10) || 0;
                          const picked = autotaskCompanies.find((c) => c.id === id);
                          updateTenantRow(idx, {
                            autotask_company_id: id,
                            autotask_company_name: picked?.name ?? null,
                          });
                        }}
                        className="w-full rounded-sm border border-border bg-bg-surface px-2 py-1 text-[11px] text-text-primary focus:border-accent focus:outline-none"
                      >
                        <option value="">— pick company —</option>
                        {autotaskCompanies.map((c) => (
                          <option key={c.id} value={c.id}>
                            #{c.id}{c.name ? ` · ${c.name}` : ""}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        type="number"
                        value={row.autotask_company_id || ""}
                        placeholder="company id"
                        onChange={(e) => updateTenantRow(idx, {
                          autotask_company_id: parseInt(e.target.value, 10) || 0,
                        })}
                        className="w-full rounded-sm border border-border bg-bg-surface px-2 py-1 text-[11px] text-text-primary focus:border-accent focus:outline-none"
                      />
                    )}
                  </div>
                </td>
                <td className="px-3 py-2 align-top">
                  <input
                    type="text"
                    value={row.autotask_homepage_url ?? ""}
                    placeholder="https://ww12.autotask.net/Mvc/Company/N"
                    onChange={(e) => updateTenantRow(idx, {
                      autotask_homepage_url: e.target.value || null,
                    })}
                    className="w-full rounded-sm border border-border bg-bg-surface px-2 py-1 text-[11px] text-text-primary focus:border-accent focus:outline-none"
                  />
                </td>
                <td className="px-3 py-2 align-top text-right">
                  <button
                    type="button"
                    onClick={() => removeTenantRow(idx)}
                    aria-label="remove row"
                    className="rounded-sm border border-border bg-bg-card px-2 py-1 text-[11px] text-text-secondary hover:border-critical/60 hover:text-critical"
                  >
                    ✕
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {tenantSaveError && (
          <div role="alert" className="border-t border-critical/40 bg-critical/10 px-3 py-2 text-[10px] text-critical">
            {tenantSaveError}
          </div>
        )}

        <footer className="flex justify-end gap-2 border-t border-border bg-bg-card px-3 py-2">
          <button
            type="button"
            onClick={() => void saveTenants()}
            disabled={savingTenants}
            className="rounded-sm border border-accent bg-accent px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-text-on-accent hover:bg-accent/80 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {savingTenants ? "saving…" : "save tenant mappings"}
          </button>
        </footer>
      </section>

      {/* ----- Operator ↔ Resource table ----- */}
      <section className="rounded-sm border border-border bg-bg-surface">
        <header className="flex items-baseline justify-between border-b border-border bg-bg-card px-3 py-2">
          <div>
            <h2 className="font-mono text-[10px] uppercase tracking-widest text-accent">
              ·· operator ↔ resource ··
            </h2>
            <p className="mt-0.5 text-[10px] text-text-dim">
              Maps each Athena operator to their Autotask Resource. Used when
              Athena pushes ticket creates / notes on the operator's behalf
              (P4-c2 write-back).
            </p>
          </div>
          <button
            type="button"
            onClick={addOperatorRow}
            className="rounded-sm border border-accent/60 bg-bg-surface px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-accent hover:border-accent"
          >
            + row
          </button>
        </header>

        <table className="w-full border-collapse text-[11px]">
          <thead className="border-b border-border bg-bg-card text-left text-[10px] uppercase tracking-widest text-text-dim">
            <tr>
              <th className="px-3 py-2 font-mono">athena operator</th>
              <th className="px-3 py-2 font-mono">autotask resource</th>
              <th className="px-3 py-2 font-mono"></th>
            </tr>
          </thead>
          <tbody>
            {operatorRows.length === 0 && (
              <tr>
                <td colSpan={3} className="px-3 py-3 text-[10px] text-text-dim">
                  No mappings yet.
                </td>
              </tr>
            )}
            {operatorRows.map((row, idx) => (
              <tr key={idx} className="border-b border-border/60">
                <td className="px-3 py-2 align-top">
                  <select
                    value={row.operator_id || ""}
                    onChange={(e) => updateOperatorRow(idx, {
                      operator_id: parseInt(e.target.value, 10) || 0,
                    })}
                    className="w-full rounded-sm border border-border bg-bg-surface px-2 py-1 text-[11px] text-text-primary focus:border-accent focus:outline-none"
                  >
                    <option value="">— pick operator —</option>
                    {athenaOperators.map((o) => (
                      <option key={o.id} value={o.id}>
                        #{o.id} · {o.username}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="px-3 py-2 align-top">
                  {autotaskResources.length > 0 ? (
                    <select
                      value={row.autotask_resource_id || ""}
                      onChange={(e) => {
                        const id = parseInt(e.target.value, 10) || 0;
                        const picked = autotaskResources.find((r) => r.id === id);
                        updateOperatorRow(idx, {
                          autotask_resource_id: id,
                          autotask_resource_email: picked?.email ?? null,
                          autotask_resource_name: picked?.name ?? null,
                        });
                      }}
                      className="w-full rounded-sm border border-border bg-bg-surface px-2 py-1 text-[11px] text-text-primary focus:border-accent focus:outline-none"
                    >
                      <option value="">— pick resource —</option>
                      {autotaskResources.map((r) => (
                        <option key={r.id} value={r.id}>
                          #{r.id}{r.name ? ` · ${r.name}` : ""}
                          {r.email ? ` · ${r.email}` : ""}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      type="number"
                      value={row.autotask_resource_id || ""}
                      placeholder="resource id"
                      onChange={(e) => updateOperatorRow(idx, {
                        autotask_resource_id: parseInt(e.target.value, 10) || 0,
                      })}
                      className="w-full rounded-sm border border-border bg-bg-surface px-2 py-1 text-[11px] text-text-primary focus:border-accent focus:outline-none"
                    />
                  )}
                </td>
                <td className="px-3 py-2 align-top text-right">
                  <button
                    type="button"
                    onClick={() => removeOperatorRow(idx)}
                    aria-label="remove row"
                    className="rounded-sm border border-border bg-bg-card px-2 py-1 text-[11px] text-text-secondary hover:border-critical/60 hover:text-critical"
                  >
                    ✕
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {operatorSaveError && (
          <div role="alert" className="border-t border-critical/40 bg-critical/10 px-3 py-2 text-[10px] text-critical">
            {operatorSaveError}
          </div>
        )}

        <footer className="flex justify-end gap-2 border-t border-border bg-bg-card px-3 py-2">
          <button
            type="button"
            onClick={() => void saveOperators()}
            disabled={savingOperators}
            className="rounded-sm border border-accent bg-accent px-3 py-1 font-mono text-[10px] uppercase tracking-wider text-text-on-accent hover:bg-accent/80 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {savingOperators ? "saving…" : "save operator mappings"}
          </button>
        </footer>
      </section>
    </section>
  );
};

export default AutotaskMappingsPage;
