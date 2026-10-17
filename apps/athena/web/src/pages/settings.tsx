import { type FC, useEffect, useState } from "react";
import { useRoute, useSearchParam } from "@/lib/router";
import { getMe } from "@/lib/api";
import { canManageRole, type MeResponse } from "@/contracts/operator";
import { reviewFilterFromParam } from "@/contracts/tenant";
import AccountTab from "@/pages/settings/account";
import AppearanceTab from "@/pages/settings/appearance";
import IntegrationsTab from "@/pages/settings/integrations";
import AutotaskMappingsPage from "@/pages/settings/autotask-mappings";
import OperatorsTab from "@/pages/settings/operators";
import SystemTab from "@/pages/settings/system";
import TenantsTab from "@/pages/settings/tenants";
import ThreatsTab from "@/pages/settings/threats";

type SubRoute = "account" | "appearance" | "integrations" | "tenants" | "operators" | "system"
  | "threats";

function resolveSub(route: string): SubRoute {
  if (route.startsWith("/settings/appearance")) return "appearance";
  if (route.startsWith("/settings/integrations")) return "integrations";
  if (route.startsWith("/settings/tenants")) return "tenants";
  if (route.startsWith("/settings/operators")) return "operators";
  if (route.startsWith("/settings/system")) return "system";
  if (route.startsWith("/settings/threats")) return "threats";
  return "account";
}

const SettingsPage: FC = () => {
  const [route, navigate] = useRoute();
  const [me, setMe] = useState<MeResponse | null>(null);
  const [meLoaded, setMeLoaded] = useState(false);

  useEffect(() => {
    getMe()
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setMeLoaded(true));
  }, []);

  const sub = resolveSub(route);
  // The Operators tab is only visible to admin+ callers. Server enforces
  // the same gate; this is just UX hygiene.
  const showOperators = me ? canManageRole(me.role, "analyst") ||
                              canManageRole(me.role, "admin") : false;
  // Tenants tab — admin+ only (viewers are CLIENT users and must never see
  // other tenants, quarantine or the request queue; analysts have no
  // business there either). The server answers 403 below admin and the
  // tab component itself refuses to render data for them.
  const showTenants = me ? canManageRole(me.role, "admin") : false;
  // System tab — super_admin only. Backend enforces the same gate
  // (session_super_admin dep on every /admin/data/* route). `me.role`
  // is a list per the wire contract.
  const showSystem = me?.role?.includes("super_admin") ?? false;
  // Threats tab (Tier Black: rules, asset tags — life-safety first — and the
  // registries) — analyst+; a client user never sees it.
  const showThreats = me ? canManageRole(me.role, "analyst") : false;
  // Deep links into the Tenants tab (integration card, dashboard notice).
  // Re-read on every navigation: this page stays mounted across tab clicks,
  // so the Tenants tab follows the URL rather than a value seeded once.
  const filterParam = useSearchParam("filter");
  const instanceParam = useSearchParam("instance");
  const clientParam = useSearchParam("client");

  // If the user navigated directly to a gated tab without rights,
  // snap them back to /settings/account once `me` resolves.
  useEffect(() => {
    if (!meLoaded) return;
    if (sub === "operators" && !showOperators) {
      navigate("/settings/account");
    }
    if (sub === "tenants" && !showTenants) {
      navigate("/settings/account");
    }
    if (sub === "system" && !showSystem) {
      navigate("/settings/account");
    }
    if (sub === "threats" && !showThreats) {
      navigate("/settings/account");
    }
  }, [meLoaded, sub, showOperators, showTenants, showSystem, showThreats, navigate]);

  return (
    <div className="flex flex-col gap-4">
      <nav className="flex gap-1 border-b border-border" role="tablist">
        <SubTab
          label="Account"
          active={sub === "account"}
          onClick={() => navigate("/settings/account")}
        />
        <SubTab
          label="Appearance"
          active={sub === "appearance"}
          onClick={() => navigate("/settings/appearance")}
        />
        <SubTab
          label="Integrations"
          active={sub === "integrations"}
          onClick={() => navigate("/settings/integrations")}
        />
        {showTenants && (
          <SubTab
            label="Tenants"
            active={sub === "tenants"}
            onClick={() => navigate("/settings/tenants")}
          />
        )}
        {showOperators && (
          <SubTab
            label="Operators"
            active={sub === "operators"}
            onClick={() => navigate("/settings/operators")}
          />
        )}
        {showSystem && (
          <SubTab
            label="System"
            active={sub === "system"}
            onClick={() => navigate("/settings/system")}
          />
        )}
        {showThreats && (
          <SubTab
            label="Threats"
            active={sub === "threats"}
            onClick={() => navigate("/settings/threats")}
          />
        )}
      </nav>

      {sub === "account" && <AccountTab />}
      {sub === "appearance" && <AppearanceTab />}
      {sub === "integrations" && (() => {
        // Sub-path /settings/integrations/autotask/<instance_id> → mapping editor.
        // Default integrations grid otherwise.
        const m = route.match(/^\/settings\/integrations\/autotask\/(\d+)/);
        if (m) {
          return <AutotaskMappingsPage instanceId={parseInt(m[1] ?? "0", 10)} />;
        }
        return <IntegrationsTab me={me} />;
      })()}
      {sub === "tenants" && showTenants && (
        <TenantsTab
          me={me}
          view={route.startsWith("/settings/tenants/quarantine") ? "quarantine"
            : route.startsWith("/settings/tenants/links") ? "links" : "tenants"}
          onNavigate={navigate}
          reviewFilter={reviewFilterFromParam(filterParam)}
          initialInstanceId={
            instanceParam && /^\d+$/.test(instanceParam) ? parseInt(instanceParam, 10) : undefined
          }
          initialClient={clientParam ?? undefined}
        />
      )}
      {sub === "operators" && showOperators && <OperatorsTab me={me} />}
      {sub === "system" && showSystem && <SystemTab />}
      {sub === "threats" && showThreats && <ThreatsTab me={me} />}
    </div>
  );
};

const SubTab: FC<{ label: string; active: boolean; onClick: () => void }> = ({
  label,
  active,
  onClick,
}) => (
  <button
    type="button"
    role="tab"
    aria-selected={active}
    onClick={onClick}
    className={[
      "-mb-px border-b-2 px-4 py-2 text-sm transition-colors",
      active
        ? "border-accent text-accent"
        : "border-transparent text-text-secondary hover:text-text-primary",
    ].join(" ")}
  >
    {label}
  </button>
);

export default SettingsPage;
