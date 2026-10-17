# UniFi connector adapter

The whole UniFi fleet through UniFi's cloud: ONE Site Manager API key
(`api.ui.com`, header `X-API-KEY`) reaches every console of the account through
the connector proxy (`/v1/connector/consoles/{hostId}/proxy/network/...`). No
port forward, no local controller URL. Read-only.

Replaces the retired local-controller adapter (same vendor slug `unifi`) — see
"Migration" below.

## Keys: `(hostId, siteId)`, always

Site ids COLLIDE across consoles (verified live across a production fleet: every single-site
console has the same integration site id and the internal reference
`default`), and the integration site id DIFFERS from the fleet `siteId` on
every console (second live probe) — the clients endpoint always takes the id
the console's own `integration/v1/sites` lists for the site's internal
reference (tested on every console). Every site is therefore keyed
`"<hostId>/<siteId>"` — in the tenant map, the ignore list, the coalescing
ledger, the system-log cursor, the feeds.
A bare site id (what the old adapter stored) is never polled.

There is no default tenant: a site that is not mapped to an ACTIVE tenant
(unmapped, ignored, its tenant offboarded) is read only as part of the fleet
list, and nothing about it is written anywhere.

## What is read, and how often

All calls go through ONE limiter per API key (`limiter.py`): at least 1 s
apart, process-wide; strict priority with aging (system log → client
snapshots → fleet → discovery / networks); HTTP 429 = throttled (15 s doubling
to 10 min, `Retry-After` honoured), never "broken key".

| Feed | Call | Cadence | Goes to |
|---|---|---|---|
| Fleet | `GET /v1/hosts` + `GET /v1/sites` (2 calls for every console; `{data, httpStatusCode, traceId}`, no `nextToken` at a few dozen consoles — paging tolerated, never depended on) | 5 min | discovery listing (mapping panel), card, `on_site_report` per mapped site |
| System log | `POST v2/api/site/{internalReference}/system-log/all` (NEWEST FIRST, live) | 5 min per mapped site (5–10 configurable) | signals (`events.db`), roll-ups (`telemetry.db`), lease / WAN boundaries (`on_log_events`) |
| Clients | `GET integration/v1/sites/{id}/clients` (all pages) | 5 min per mapped site whose tenant takes them (entity switch shadow / on — none while off) | `on_client_snapshot` (whole or nothing) |
| Networks | `GET api/s/{internalReference}/rest/networkconf` | daily per mapped site whose tenant takes them (entity switch shadow / on — not read at all while off); marked read only when taken, per site AND tenant | `on_networks` (allowlisted fields only) |

The integration site id the clients endpoint takes is found per console
(`integration/v1/sites`, cached a day) by the site's internal reference — and
ONLY by it: a site the console does not list is a per-site failure, never the
console's only listed site (on a multi-site console that is another site,
maybe another tenant's). A fleet site without a valid internal reference
(`meta.name`) is dropped, never guessed as `default`.

Site names: UniFi calls a console's first site "Default" unless it was
renamed; such a site takes its CONSOLE's name (on a console with several
sites, "<console> — Default"), in the mapping panel, the card and entity
resolution's site label (which an admin can rename; the vendor's name then
never replaces it).

Failures: a 401 / 403 / 3xx on a CONNECTOR call is that console's (its site
waits on its own backoff, the others go on); 401 / 403 on the fleet calls is
the key. Sites are walked from a start that rotates every cycle. A mapped
site missing from the fleet list waits for the next fleet poll (it never
spins the cycle). The card's "consoles offline" counts only consoles that
host a mapped site. The system-log progress handed to entity resolution is
the window's end minus the 5-minute re-read overlap (what is guaranteed read
whole).

Budget: 24 calls/h for the fleet + 12 calls/h per mapped site (system log),
+12/h per site whose tenant takes client lists (≈ 17/min for ~40 sites all
switched on, well inside the 1 call/s pace; ≈ 9/min with every switch off).

## The boundary: nothing secret gets in

`sanitize.strip` runs on EVERY answer before it is parsed, recursively: any
key starting `x_`, `utm_token`, and any key containing pass / psk / secret /
token / key / credential / private / cert / `auth_` is dropped; a string value
carrying a PEM block or a raw base64 key is dropped whatever its field. The
fleet paging cursor `nextToken` is the one explicit exception. The network
list additionally keeps only an allowlist of fields (`client.NETWORK_FIELDS`).
Tests scan every stored payload, ledger row and feed call for secret keys.

## Signals, roll-ups, OCSF

`catalogue.py` classifies every system-log event; `ocsf.py` maps each kind to
one OCSF 1.3.0 class at the boundary (the build rule). Every signal payload
carries its `ocsf` object.

| Kind | Events | Level | OCSF |
|---|---|---|---|
| `ips_threat` | THREAT_DETECTED / THREAT_BLOCKED | high (detected-not-blocked ranks first) | Detection Finding 2004, disposition Detected 15 / Blocked 2; analytic = the threat's name |
| `rogue_ap` | ROGUE_AP_DETECTED | medium | Detection Finding 2004 |
| `admin_activity` | ADMIN_ACCESS, GENERATED | low (audit) | Authentication 3002 |
| `config_change` | MADE_CHANGES | medium (audit) | Entity Management 3004 |
| `wan_down` / `wan_failover` / `wan_restored` | NETWORK_WAN_FAILED(_MULTIPLE_TIMES) / FAILED_OVER_TO_BACKUP_WAN / WAN_RESTORED | medium / medium / low | Network Activity 4001 (best fit) |
| `vpn_down` | VPN_SITE_TO_SITE_DISCONNECTED | medium | Network Activity 4001 |
| `system_event` | anything unknown the vendor rates HIGH / VERY_HIGH (fail-safe) | medium | Base Event 0 |
| `mac_anomaly` | DERIVED by entity resolution (possible MAC impersonation) | medium | Detection Finding 2004 |
| `isp_outage` → `fleet.isp_outage` | DERIVED by the Fleet v2 correlator (`apps/octo/fleet/isp_outage.py`): >= 3 mapped sites on ONE ISP ASN down within 10 min — ONE incident in the internal tenant | high | Incident Finding 2005 (`ocsf.project_isp_outage`; one finding per affected site) |

Signals are COALESCED per site + subject per clock hour (IPS: the LAN client +
the threat): the first creates one alert, later hits only count
(`unifi_signal_buckets`; the alerts feed shows "Seen N times in the hour").

IPS events, as the live API answers them (9 sampled): `SRC_IP` / `DST_IP`
`{id, name, not_actionable}`, `DEVICE` (the REPORTING GATEWAY — "Reported
by …", never the client), `INITIATOR_ID`, `CONSOLE_NAME`,
`CONSOLE_WITH_DEVICE_NAME` — no signature, category or client parameter. The
LAN side is whichever of SRC_IP / DST_IP is a local address (read from ip /
id / name, or an address inside the text): the alert names the device by
that address until entity resolution names it. The threat's name is read
from `title_raw` / `message_raw` as TEMPLATES (`catalogue.threat_name`: a
Suricata-style "ET …" name, a quoted name, the text after the last colon, a
non-generic title — placeholders dropped), so the same threat from two
remote addresses is one name and one bucket; with no name in the text, the
coalescing key is a digest of the templates (never the rendered text). An
older CLIENT / SIGNATURE / CATEGORY shape is still read when present.

Roll-ups only (hourly counts in `unifi_hourly`, never rows in `events.db`):
firewall blocks, client connect / disconnect / roam, ISP latency / loss, WAN
flaps, device events, other.

## Restart safety: exactly once

Per site, in the TENANT's own `telemetry.db` (migration 039):
`unifi_syslog_cursor` holds the newest event time processed, the end of the
last window read whole and the event ids inside the 5-minute re-read overlap.
One window's roll-up counts, signal claims and the cursor move in ONE
transaction. A new bucket's first event is claimed with its payload as an
outbox row; the alert is stored right after and the outbox cleared — a crash
between the two is finished on the next pass (never lost, never doubled). A
newly mapped site back-fills 24 hours, in 6-hour windows; a busy window has
its new part halved until it fits. The log answers NEWEST FIRST: a window's
items are kept by id, pages are read up to the LATEST answer's page count (a
write landing mid-read pushes the list down a slot — the oldest items move
past the first count; they used to be lost), and past `HARD_MAX_LOG_PAGES`
the part not yet covered is asked for as its own range, never dropped.

## Feeds for entity resolution (`feed.py`)

Per MAPPED site, with that site's tenant slug: `on_site_report` (egress IPs +
ASN per WAN, its NAT kind — `direct` / `cgnat` / `double_nat` / `unknown`, from
the console's WAN interface address against the cloud-observed one —
location, time zone, gateway / console state, and ONE bit per WAN
`shared_external` — the same public address belongs to another OWNER in the
fleet snapshot: another tenant, or a console no tenant's site is on (owners
are counted by tenant, so two clients on one multi-site console behind one
WAN are flagged, two sites of one client are not); nothing about the other
site is passed. A dual-stack single-site console adds its WAN's IPv6
address ("<WAN>/v6", /128) and, when `/v1/hosts` gives one, the prefix
delegated to its LAN ("<WAN>/pd")), `on_client_snapshot` /
`on_client_snapshot_failed`, `on_log_events` (lease / WAN boundaries),
`on_log_progress` (the system log is read whole up to there — after every
window), `on_networks`. Entity resolution (`apps/octo/entity`) registers its
consumer at start-up; a consumer that raises never stops the poller.

DERIVED SIGNALS: a consumer may hand back the MAC-anomaly rule's findings
(one MAC with two IPs in a poll window, or wired and wireless at once, while
the client stayed connected); the poller stores each as a `unifi.mac_anomaly`
signal (MEDIUM, OCSF Detection Finding 2004, coalesced per site + MAC + hour)
— the mapping stays here, at the adapter boundary.

## Mapping (wizard step and card)

`GET/PUT /api/v1/integrations/unifi/{id}/sites` (admin+, audited, never a UniFi
call): every site with its console, LOCATION, time zone, WAN addresses and
gateway state. Many sites may map to one tenant; "Ignore" for personal and
non-client consoles. NO bulk accept: a same-name suggestion (legal suffixes
kept) is offered on its row only, and every mapping is saved as the operator's
decision (`manual`) — two businesses can share a name.

## Fleet v2 (`fleet_health`, the ISP-outage correlator)

The fleet poll also keeps each site's network statistics (`SiteInfo.stats`,
`poller.py::site_stats`): device / offline gateway counts, pending updates,
critical notifications, the site's ISP (name + ASN), and the
`internetIssues` / per-WAN `wanIssues` entries as stable keys (`index` when
present, else a digest — the entry shape was not sampled live). They are NOT
in the entity feed's site report. `poller.fleet_health()` hands the last
fleet poll (report + stats + counts, its time and interval) to the Fleet API
— a read of memory, never a UniFi call. Its stats add `issues_new_at` /
`issues_recent`: an issue key that appeared between two FRESH fleet polls
(recent for an hour) — the lists may be histories, so only a new entry
makes the Fleet's network layer warn. The correlator counts FAILURE POINTS
(an unreachable console once, however many sites it carries; a public WAN
address once), and the note it adds to a client's own WAN alert names only
that client's provider. After every fleet poll the poller
runs the ISP-outage correlator over its MAPPED sites
(`poller.isp_outages()` = its incidents); the incident's payload and OCSF
Incident Finding are built here, at the adapter boundary
(`catalogue.isp_outage_payload`), and stored with source `unifi`, event type
`fleet.isp_outage` (presented "ISP outage: <ISP> — N sites"; L1 escalates it
HIGH once).

## Deep links, L1

"Open in UniFi Site Manager": `https://unifi.ui.com/consoles/{hostId}/network/{internalReference}/dashboard`
— verified 2026-10-08 against a live portal address. The hostId
(`<hex>:<digits>`) keeps its `:` (`LINK_SPEC.keep_unencoded`): encoded as
`%3A` the portal answers "Access denied". A host id with a `:` that is not of
that shape gets NO link (never a guessed one).
L1 (`agent/heuristic_l1.py`, rule 1d): IPS detected-not-blocked escalates
critical, blocked escalates high; rogue AP and audit events are patterns; WAN
/ VPN down escalate; WAN restored is noise.

## Migration from the local-controller adapter

Same vendor slug, so stored events stay attributed and still read (the
presenter knows the old `key` / `msg` payloads). An instance saved with a
controller URL is refused at start with what to do: Disable it, Add UniFi
again with a Site Manager API key, map the sites. Its old site mappings (bare
site ids) are listed in the panel as retired and never polled. Nothing is
deleted.

## Not verified live (marked `fixture:` in the fake)

The WORDING of an IPS event's `title_raw` / `message_raw` (only that the
threat is named there — `threat_name` reads several shapes), the
delegated-prefix key on `/v1/hosts` wans[] (`ipv6Prefix` and others read
tolerantly), `pageSize` / `nextToken` paging past one page (none at 43
consoles), the "Open in UniFi" deep-link path, a two-WAN console's NAT kind,
the rate limit (no headers; paced at 1/s), whether `connectedAt` resets on an
SSID / VLAN move. Verified live (2026-10-01): the IPS parameter keys, the
system log's newest-first order, the integration id ≠ fleet siteId.

## Tests

`tests/fake_unifi.py` is the cloud + connector at the transport layer on a
fake clock; everything else is real (client, limiter, poller, sink, registry,
telemetry store). `PYTHONPATH=. python -m pytest apps/octo/adapters/unifi/tests`.
