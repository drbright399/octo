/**
 * Mock data for the dashboard preview. Replaced by live bridge data once
 * the bridge client wiring lands. Intentionally clearly labeled as mock so
 * nothing here ends up read as real telemetry by accident.
 *
 * No real credentials, no real customer data — synthetic only. Tenant
 * slugs come from the fictional fleet used across the fixtures (acme,
 * globex, initech, umbrella, hooli).
 */

import type { AlertRow } from "@/contracts/alert";

export const NOW = new Date("2026-05-06T13:30:00Z");
export const REFRESH_INTERVAL_SEC = 15;

export const MOCK_ALERTS: AlertRow[] = [
  {
    id: "alert-001",
    severity: "critical",
    status: "open",
    source: "rmm",
    tenant: "acme",
    title: "Ransomware behavior detected on workstation WS-04",
    summary:
      "EDR flagged mass file rename in Documents share within 12s. Process: encsvc.exe (unsigned).",
    occurred_at: "2026-05-06T13:28:14Z",
  },
  {
    id: "alert-002",
    severity: "high",
    status: "acknowledged",
    source: "network",
    tenant: "globex",
    title: "Unusual outbound traffic to non-allowlisted ASN",
    summary: "Sustained 4MB/s from VLAN 30 → AS14061 over 8 minutes.",
    occurred_at: "2026-05-06T13:11:02Z",
  },
  {
    id: "alert-003",
    severity: "medium",
    status: "open",
    source: "buoy.opencanary",
    tenant: "initech",
    title: "Honeypot SSH login attempt",
    summary: "Single attempt, root user, source 198.51.100.7. No follow-up.",
    occurred_at: "2026-05-06T12:47:55Z",
  },
  {
    id: "alert-004",
    severity: "low",
    status: "resolved",
    source: "wazuh",
    tenant: "hooli",
    title: "Failed sudo on backup host",
    summary: "User 'maint' fat-fingered password twice. Cleared on third try.",
    occurred_at: "2026-05-06T11:32:18Z",
  },
  {
    id: "alert-005",
    severity: "info",
    status: "resolved",
    source: "system.audit",
    tenant: "msp_root",
    title: "Operator session opened",
    summary: "Operator logged in via TOTP. Nothing anomalous.",
    occurred_at: "2026-05-06T08:01:00Z",
  },
];

export const MOCK_TRAFFIC_SOURCES = [
  { id: "rmm", name: "RMM", events_per_min: 142, status: "ok" as const },
  { id: "network", name: "Network", events_per_min: 389, status: "ok" as const },
  { id: "wazuh", name: "Wazuh / OSSEC", events_per_min: 28, status: "degraded" as const, detail: "queue lag 4s" },
  { id: "buoy.opencanary", name: "Buoy honeypots", events_per_min: 2, status: "ok" as const },
  { id: "mdr", name: "MDR", events_per_min: 0, status: "down" as const, detail: "auth expired" },
];

export const MOCK_SOURCE_THROUGHPUT = [
  3, 4, 5, 6, 8, 7, 6, 5, 4, 6, 9, 12, 14, 11, 9, 8, 10, 12, 15, 13, 11, 9, 8, 10,
].map((v, i) => ({ t: `t-${24 - i}`, v }));

export const MOCK_DEVICES = [
  {
    id: "ws-04",
    title: "WS-04 (acme)",
    subtitle: "Windows 11 · agent v6.4.1 · last seen 12s ago",
    meta: "🔴 P1",
  },
  {
    id: "fw-01",
    title: "FW-01 (globex)",
    subtitle: "UDM-Pro · firmware 4.0.21 · last seen 38s ago",
    meta: "🟡 P2",
  },
  {
    id: "buoy-initech",
    title: "buoy-initech",
    subtitle: "small ARM appliance · last heartbeat 8s ago",
    meta: "🟢 ok",
  },
];

export const MOCK_INTEGRATION_STATUS = [
  { id: "rmm", name: "RMM", status: "ok" as const, detail: "v0.2 · 142/min" },
  { id: "network", name: "Network", status: "ok" as const, detail: "v0.1 · 389/min" },
  { id: "wazuh", name: "Wazuh", status: "degraded" as const, detail: "queue lag 4s" },
  { id: "mdr", name: "MDR", status: "down" as const, detail: "auth expired" },
  { id: "psa", name: "PSA", status: "unknown" as const, detail: "not configured" },
];
