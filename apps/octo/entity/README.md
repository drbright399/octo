# Entity resolution — slice 1 (as built)

"Which site, which device, how sure, and why" for an alert, from per-client
time-interval lookups. Design of record: the 2026-10-01 entity-resolution
design note, kept outside the repository (B as the base, A's invariants
grafted on, the adversarial review G1-G11 folded in, Rick's decisions of
2026-10-01: MAC auto-link with the MAC-anomaly safeguard, NO masking of
device names, response actions out of scope).

## Where it lives

`clients/<slug>/entities.db` — one file per client (migration 040,
`-- @target: entities`; in `paths.CLIENT_DB_NAMES`, created EAGERLY at client
provisioning (an empty file is ~280 KB) and lazily for older clients, backed
up and restored with the other tenant files). No table holds a
slug. `TenantDB.for_tenant(slug)` refuses any path outside `clients/<slug>/`;
no function takes two slugs (a static test checks the package). Reads probe
`sqlite_master` and answer "unresolved", never a 500.

The switch (registry `clients.entity_resolution`): `off` (default — nothing is
read, written or fetched for the client: no UniFi client list, no networks, no
NextDNS device / IP reads), `shadow` (computed and stored, the alert panel
does not show it, no entity alert is raised), `on`. Switching off → shadow /
on (PUT /entity/{slug}/mode) starts the sweep at the client's NEWEST event —
`OCTO_ENTITY_SWEEP_HISTORY_DAYS=N` (0 default, ≤ 30) starts it N days back;
it never resolves the whole history (lookups only exist from switch-on).

## Feeds → lookups

| Feed (adapter) | Lookup | Notes |
|---|---|---|
| UniFi fleet report (5 min) | `site` + `site_vendor_ref` (L-UNIFI, confirmed for a `manual` mapping), `lk_site_egress` (externalIp per WAN, NAT kind from the console's WAN interface, `shared_external` bit — owners counted by TENANT per address; on a single-site console also the WAN's IPv6 address (/128, "<WAN>/v6") and the delegated LAN prefix ("<WAN>/pd", when /v1/hosts gives one — its key was not seen live)) | An offline console or gateway is NOT an observation: nothing closes, the per-site watermark does not move (G7). The Athena site belongs to the UniFi SCOPE, not to the adapter instance: a key rotation (or an unmap and re-map) re-attaches to it — only the ref is new |
| UniFi clients (5 min, whole or nothing; only while the client takes them) | `lk_ip_lease` | Honest slack on sampled edges (G10), reconnect splits, gap rule (never bridged), day-chunked at 00:00Z, `connectedAt` = exact start |
| UniFi system log | `lk_join` (CLIENT_* joins: MAC, IP, name, uplink, time), exact disconnects, `lk_ip_conflict` (time-bounded), the system-log watermark (the window end minus the 5-minute re-read overlap: what is guaranteed whole) | ±20 s join heuristic; ghosts (a join of the subject address no lease covers, [T − one poll, T + 20 s]) at query time |
| UniFi networks (daily, only while the client takes them) | `lk_site_subnet` (CIDR, VLAN, purpose, DHCP DNS path: gateway / nextdns / other / unknown) | the candidate filter — `other` (filtered) ONLY when every DHCP DNS server is public and not a NextDNS resolver (`OCTO_NEXTDNS_RESOLVER_NETS`; unset: never); a LAN resolver (a DC, a Pi-hole) or a mixed list is `unknown` (kept). Networks arriving late fix open leases' guest mark |
| Datto inventory (30 min since v0.17.2, read-only; every Datto-mapped tenant) | `inv_device` (uid, hostname, type, online + `online_since`, lastSeen, LAN IP, WAN IP (046), OS, domain; v0.17.3 / 047: `serial`, `manufacturer`, `model`, `audit_at` from the device AUDIT — ≤ 40 a round, again after 7 days) | NEVER a UDF (dropped at the client); from the audit ONLY the BIOS / base-board serial, the maker and the model (never the user, interfaces / MACs, URLs, software); a placeholder serial is NULL; OCSF Device Inventory Info at the adapter boundary (`hw_info.serial_number`, `vendor_name`, `model`); readers probe the columns (a file not yet at 047 = no serial) |
| NextDNS devices (hourly, per profile) | `ndns_device`, `ndns_device_hour`, `ndns_presence_hour` | analytics/devices; per profile, after 3 refusals in a row, one log page per hour (complete only when the page held the whole hour), re-probed every 6 h |
| NextDNS seed (once, the 14 days before the feed started) | `ndns_device_day`, `ndns_seed_day` | one analytics/devices read per profile and day: a PC whose app was already dead at switch-on is known, linked and watched |
| NextDNS IPs (daily, per profile) | `ndns_ip_day` | only THIS client's egress addresses are stored; IPv6 addresses inside a delegated prefix are counted under the PREFIX (never one by one); the rest is a count |

## Rules

Site: S1 policy (confirmed refs only when any exist — G8), S2 located (direct
85, operator 95, double NAT stable 7 d 80, CGNAT / unknown 60, -20 in a margin),
S-AGREE 99 only from an egress that may corroborate (never CGNAT, unknown or
`shared_external` — G4; an operator-asserted address another UniFi network of
the fleet also uses is flagged `shared_external` too), S-NARROW and its mirror
(one egress shared by several of the client's sites, a policy ref naming one of
them), `not_located` (renamed from off-site), S-CONFLICT,
S3 subnet 60. A T after the site's last fresh report is `provisional`; a T in a
feed hole is `data_gap` — never "elsewhere". IPv6 (S2 v2): an address matches
the gateway's WAN /128 or a delegated prefix; with no delegated prefix known
for the site, an IPv6 address that matches nothing is location UNKNOWN
(`location_unknown` + `ipv6_unknown`, no device list) — never `not_located`.

Device: D5 (the NextDNS app named it: at most 80 — G3), D4 (a buoy's Pi-hole
within ±5 s: 88 / 80), D3 (one lease: 85 exact start / 80 sampled; a conflict,
a MAC anomaly, a reconnect hole, a ghost join, a MAC that differs from the
alert's, or two rows → candidates), D7 (the connected set, filtered by DHCP DNS
path and — for a gateway-sourced line — the NextDNS app devices that reported
directly in T's OWN hour, matched by NAME (never by a LAN address seen
anywhere); until T's hour is read the answer waits for it and excludes
nothing; ranked F1 / F2 (not for clients connected over 24 h) / F3
(rule-resolved only) / FJ (joined within ±20 s); `min(50, 100/n) + 10` per
feature, capped at 69). Names only ever "also consistent". Rules stop at 99;
EXACT needs an operator.

MAC anomaly (M1, Rick's safeguard): one global MAC with two IPs in one poll
window, or wired and wireless at once, while UniFi kept the client connected;
or a WIRED MAC switching between the same two uplinks more than twice in an
hour (a clone on another switch: same IP, same medium — wireless roaming is
not counted). Every join is checked once, whenever its log line arrives. The
finding is time-bounded (`lk_mac_anomaly`: no D3 pick for the MAC within an
hour of it — never a flag a rollover would carry on), answers that already
picked the MAC are re-queued, and the UniFi poller stores ONE MEDIUM
`unifi.mac_anomaly` signal per episode (OCSF Detection Finding).

Links (worker, every minute, idempotent; a registry that cannot be read changes
nothing; an unmapped UniFi site's lookups close at their LAST observation,
never at the moment the unmap was noticed): L-SOLE (`auto` 90 only for a manual
mapping with ≥ 80 % of 7-day traffic from the site's egress on ≥ 3 days, else
`suggested`), L-EGRESS (`suggested` 85), N-SITE (`suggested` ≤ 45, its own tab)
— these three give OPINIONS, and each (site, profile) gets ONE combined
suggestion: the strongest (auto > score > L-SOLE > L-EGRESS > N-SITE), every
agreeing rule kept as provenance (`evidence.rules` / `evidence.also`), written
only when that effective state changes (drifted coverage counts are refreshed
silently at most once a day). Routing sanity (traffic from none of the
client's egresses on 3 of 7 days → Conflict + notice): a Resolve STICKS until
the evidence materially changes (the client's own egress addresses change, or
the condition went away and came back after 3 days); "Accept as expected" (a
branch office without UniFi, roaming laptops) suppresses it for that profile
(optionally until a date; Reopen ends it); seeing it again is never a change.
NextDNS app device ↔ Datto device (unique name in the client: `suggested` 45;
+ the same LAN address: `auto` 80).

Operator wins on INSERT, UPDATE and DELETE (triggers); a refused rule INSERT
is a Conflicts card and one `entity_review` notice; a rejected pair is
suppressed (an expired rejection comes back only as `suggested`). Every
conflict an operator resolved stays resolved until its MATERIAL evidence
changes (routing: the profile + the client's egress; site_conflict: the two
sites; operator_decision: the rule + wanted site / state; device_link: the
wanted device + rule) — then it reopens with a new notice.

## The device-silence check

"NextDNS stopped reporting from a PC that Datto says is online": a watched
link (auto / confirmed) whose NextDNS device has a baseline (≥ 8 reporting
hours on ≥ 2 days in 14), 0 queries in each of the last 4 hours read WHOLE,
while Datto shows the PC online since before those hours (inventory fresher
than 45 min) → ONE `nextdns.device_silent` (MEDIUM) per episode, a
`nextdns.device_restored` (LOW) when it reports again. Unknown hours never
count as silent. A device whose app was already dead at switch-on is found by
the 14-day seed (baseline: ≥ 20 queries on ≥ 2 seed days). The alert says when
the device LAST reported (an hour, or a seed day) and how long the silence is
verified. Shadow: tracked, never raised — a silence still holding when the
switch goes `on` is raised then.

## Call math

* NextDNS, per mapped profile (never per device): 1 analytics/devices call
  per closed hour + 1 analytics/ips call per day = 25 calls/profile/day (+14
  once, the seed). Device reads of every profile first, from a start that
  rotates each cycle, then the seed, then the per-IP reads; a refused per-IP
  day is not asked again; a 403 on one of these reads holds that profile's
  read alone, and the whole feed runs after the cycle's lapse decisions. 50
  watched profiles → 1,250/day ≈ 52/h ≈ 0.9/min, through the key's one
  limiter (≥ 2 s apart: 1,800 calls/h capacity) → ~3 % of it, at health
  priority, yielding to security checks. Fallback (endpoint refused): the same
  count of log calls (one page, limit 1000). Catch-up after a stop: at most 6
  hours back, 2 per profile per cycle.
* Datto: 1 call per mapped site per 15 min (+1 per extra 250 devices): 50
  sites ≈ 200/h ≈ 3.3/min against Datto's documented 600 reads/min. Paced
  ≥ 1 s apart; never on the alerts poller's path.
* UniFi: no new calls (the feeds ride on the existing reads).

## Storage math (measured row sizes; volumes of one mid-sized MSP fleet)

| Table | Row (incl. indexes) | Volume | Kept | Size |
|---|---|---|---|---|
| `lk_ip_lease` | ~610 B | 2,300-5,000 rows/day (lease rollover of the fleet's network clients + connects / IP changes) | 90 d (guest 7) | ~125-275 MB |
| `lk_join` | ~250 B | ~600-1,800/day | 90 d | 14-40 MB |
| `resolution` | ~4.8 KB (5 hops, 9 candidates) | 50-200/day | 365 d (candidates cut at 90) | 90-350 MB |
| `ndns_device_hour` | ~100 B | 24/day per app device | 90 d | ~20 MB per 100 devices |
| egress, subnets, inventory, links | — | small | 90-400 d | < 5 MB |

## Retention

`entity_lookup_lease` 90 d (guest 7), `entity_lookup_egress` 400,
`entity_resolution` 365, `entity_links` 400 after ending, `entity_inventory` 90
— in the nightly retention job (`entity/retention.py`). When leases go, every
answer that pointed at them keeps its count and chain, never the list (G11).

## Worker records

A pass writes a `resolution_run` row and a global audit row ONLY when it
changed something (an answer stored, a link changed, a notice raised; the
audit row carries the non-zero counts). A quiet client gets at most one
`heartbeat` run row an hour in its own file, and the worker one
`entity_worker_heartbeat` global audit row an hour (passes, clients, recorded
runs, errors). Before round 3, L-SOLE and N-SITE rewrote one suggestion every
minute: a run row and a 670-byte audit row per client per minute (about 1 MB
of global audit a day per client).

## Worker re-runs

A provisional answer is redone when a feed it waited for moved; after 30
minutes — or, while it waits for T's NextDNS presence hour, once that hour is
due (~65 min after it starts, the NextDNS poller's hourly delay) + 20 minutes
— it is finalised with `lookup_stale` (no stale pill before that). A stale answer is backfilled
(7 days) only once EVERY wait reached what it NEEDED (stored with the answer:
`<source>:<scope>=<had>|<needed>`) — never merely T — and a backfill that
would store the same answer writes nothing.

## Known limits (documented, not fixed)

* M1 cannot see a MAC clone on the SAME switch: UniFi gives the uplink device,
  not the port, so a rogue on another port of the victim's switch (same MAC,
  same DHCP lease) triggers neither `uplink_flap` nor `two_ips`.
* `two_ips` may fire when a laptop keeps its hardware MAC and moves SSID / VLAN
  (a new IP) IF UniFi keeps `connectedAt` across that move — not verified live.
* The NextDNS poller's per-cycle entity work (mapping re-check, hours /
  seed / day needs per profile) is ~15x the OFF cycle (p95 331 ms vs 20 ms,
  ~3.4 % of a core, measured at under 100 profiles); linear in profiles.

## Not in slice 1

Device entities across vendors (Datto ↔ UniFi by MAC, K1-K6), `event_observable`,
the LLM note (AT-R16) and its validator, replay diffs (AT16), incident merge by
site, response actions (out of scope, Rick's decision). NextDNS analytics/devices
and analytics/ips are not verified live (read tolerantly, with a fallback).
