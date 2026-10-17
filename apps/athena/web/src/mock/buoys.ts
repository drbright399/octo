/**
 * Mock buoy fleet data for the Source health rotator. Synthetic only —
 * no real customer telemetry. Replaced by the bridge `fleet_health` query
 * once the buoy registry endpoint lands.
 *
 * Tenant slugs and buoy names come from the fictional fleet used across the
 * fixtures (acme, globex, initech, umbrella, hooli).
 */

import type { RotatableSource } from "@widgets/default-attention-rotator";

export const MOCK_BUOY_FLEET: RotatableSource[] = [
  {
    id: "buoy-acme",
    name: "buoy-acme",
    tenant: "acme",
    tags: ["HIPAA"],
    events_per_min: 142,
    last_seen: "3s ago",
    services: [
      { id: "opencanary", name: "OpenCanary", status: "ok" },
      { id: "wazuh-agent", name: "Wazuh agent", status: "degraded", detail: "queue lag 4s" },
      { id: "tailnet", name: "Mesh agent", status: "ok" },
      { id: "network-syslog", name: "Network syslog", status: "ok" },
    ],
  },
  {
    id: "buoy-mdr-relay",
    name: "buoy-mdr-relay",
    tenant: "msp_root",
    events_per_min: 0,
    last_seen: "8m ago",
    services: [
      { id: "relay", name: "MDR relay", status: "down", detail: "auth expired" },
      { id: "tailnet", name: "Mesh agent", status: "ok" },
      { id: "node-exporter", name: "node_exporter", status: "ok" },
    ],
  },
  {
    id: "buoy-initech",
    name: "buoy-initech",
    tenant: "initech",
    events_per_min: 28,
    last_seen: "5s ago",
    services: [
      { id: "opencanary", name: "OpenCanary", status: "ok" },
      { id: "wazuh-agent", name: "Wazuh agent", status: "ok" },
      { id: "tailnet", name: "Mesh agent", status: "ok" },
    ],
  },
  {
    id: "buoy-globex",
    name: "buoy-globex",
    tenant: "globex",
    tags: ["PCI"],
    events_per_min: 89,
    last_seen: "2s ago",
    services: [
      { id: "opencanary", name: "OpenCanary", status: "ok" },
      { id: "wazuh-agent", name: "Wazuh agent", status: "ok" },
      { id: "tailnet", name: "Mesh agent", status: "ok" },
      { id: "network-syslog", name: "Network syslog", status: "ok" },
    ],
  },
  {
    id: "buoy-umbrella",
    name: "buoy-umbrella",
    tenant: "umbrella",
    events_per_min: 31,
    last_seen: "9s ago",
    services: [
      { id: "opencanary", name: "OpenCanary", status: "ok" },
      { id: "wazuh-agent", name: "Wazuh agent", status: "ok" },
      { id: "tailnet", name: "Mesh agent", status: "ok" },
    ],
  },
  {
    id: "buoy-hooli",
    name: "buoy-hooli",
    tenant: "hooli",
    events_per_min: 47,
    last_seen: "12s ago",
    services: [
      { id: "opencanary", name: "OpenCanary", status: "ok" },
      { id: "wazuh-agent", name: "Wazuh agent", status: "pending", detail: "post-restart probe" },
      { id: "tailnet", name: "Mesh agent", status: "ok" },
    ],
  },
];
