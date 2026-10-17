# OCTO — Operations Center for Telemetry & Observation

OCTO is the data-plane half of the Athena/OCTO bundle. It owns:

- **The credential vault** that holds the MSP-customer-side API keys + secrets
  (Datto, RocketCyber, UniFi, Wazuh API tokens, etc.). Per-bundle, never
  cross-MSP.
- **The adapter framework** that polls those upstreams and normalizes
  events into a canonical `events.db` per OCTO client (tenant).
- **The auth surface** (`/api/v1/auth/*`) that issues + validates session
  cookies for Athena Console operators. Backed by PBKDF2 password hashes,
  Fernet-encrypted TOTP secrets, and a hash-chained audit log.
- **The admin API** (`/api/v1/admin/*`) used by the Console UI for
  operator management, integration onboarding, and client (tenant)
  administration.
- **The bridge contract surface** (work-in-progress) that Athena Control
  calls into for read-only query templates.

Athena Console (the operator UI) lives in `apps/athena/web/` and talks to
OCTO over the `/api/v1/*` namespace.

---

## Layout

```
apps/octo/
├── adapters/               # Source-adapter implementations (one folder per vendor)
│   ├── wazuh/              # bundled Wazuh manager → CanonicalEvent
│   ├── datto/              # Datto RMM alerts
│   ├── rocketcyber/        # RocketCyber MDR incidents
│   ├── nextdns/            # NextDNS security blocks + per-site DNS protection health
│   └── unifi/              # UniFi fleet via the cloud connector (IPS / audit / WAN signals, OCSF, entity feeds)
├── fleet/                  # Fleet v2: site model (4 layers, worst state, locations), ISP-outage correlation
├── api/
│   ├── __init__.py         # create_app(): FastAPI factory + middleware install
│   ├── auth_helpers.py     # Bearer + cookie helpers
│   ├── errors.py           # APIError + error-code → HTTP-status table
│   ├── event_stream.py     # SSE broker for live event push
│   ├── rate_limit.py       # Per-route fixed-window limiter
│   ├── role_gates.py       # session_admin_plus / session_super_admin deps
│   ├── setup_gate.py       # Force-setup middleware (must_change_password / mfa_enabled)
│   └── routers/
│       ├── auth.py         # /auth/*  (password, TOTP, magic-link, passkey, sessions, profile)
│       ├── admin_ops.py    # /admin/operators/*  (create / disable / role grant / reset)
│       ├── admin_clients.py# /admin/clients      (list bundle tenants)
│       ├── adapters.py     # /admin/adapters/*   (catalog / smoke / instances)
│       ├── integrations.py # /integrations       (aggregator UI feed)
│       └── whoami.py       # /whoami             (bearer introspection)
├── auth/
│   ├── audit.py            # Hash-chained audit log writer
│   ├── bootstrap.py        # init_data_root() — apply migrations, create dirs
│   ├── config.py           # Env-driven config: data root, pepper, RP-ID, origin
│   ├── core.py             # PBKDF2 password hashing + bearer token primitives
│   ├── crypto.py           # MFA-key Fernet wrapper for at-rest TOTP secrets
│   ├── email_sender.py     # Outbound Postfix relay (best-effort)
│   ├── operators.py        # create_operator + lookup helpers
│   └── sessions.py         # Session issue + validate + revoke
├── credentials/            # Per-bundle adapter-credentials vault
│   ├── __init__.py
│   └── vault.py            # store / load / ensure_key_file
├── framework/              # Adapter framework runtime
│   ├── registry.py         # AdapterRegistry (class registration + lifecycle states)
│   ├── lifecycle.py        # State machine + valid transitions
│   ├── discovery.py        # Walk apps/octo/adapters/* and auto-register
│   ├── bridge_server.py    # BridgeServer Protocol impl
│   ├── bridge_router.py    # /bridge HTTP surface
│   └── sqlite_registry.py  # SQLite-backed RegistryBackend
├── ingest/                 # Per-client event sink + indicator sink
│   └── sink.py             # SqliteIngestSink + SSE publish
├── instances/              # Runtime owner of persisted adapter_instances rows
│   └── manager.py          # InstanceManager — boot-time auto-start + per-row lifecycle
├── migrations/             # Numbered .sql files; runner in apps/octo/migration.py
│   └── 00N-name.sql        # 001 through 008
├── tests/                  # pytest suite (428 tests as of 2026-05-12)
├── db.py                   # SQLite connection helper (WAL, foreign-keys on)
├── migration.py            # Migration runner
├── paths.py                # Canonical path helpers — registry.db, client_db, etc.
├── Dockerfile              # Production container build
└── requirements.txt
```

---

## Bedrock concepts in plain English

### Per-bundle credential vault (`apps/octo/credentials/`)

Each Athena/OCTO bundle is self-contained for one MSP (per the per-MSP
bundle architecture decision). The MSP's customer credentials —
Datto API keys, UniFi controller passwords, etc. — live in this bundle's
own vault. They NEVER touch any host outside the bundle. The vault is a
Fernet-encrypted blob keyed off `<secrets-dir>/adapter-credentials-key.env`,
generated automatically on first boot, mode 600.

The vault exposes a tiny surface:
- `credentials.store(values_dict) -> ref_string`
- `credentials.load(ref_string) -> values_dict`
- `credentials.ensure_key_file()` — bootstrap helper

The opaque `ref_string` is what gets persisted in
`adapter_instances.cred_ref`. No cleartext credential ever appears in the
database or its backups.

When OpenBao replaces Fernet later (a planned change), only `vault.py` changes — the call
sites stay identical.

### Adapter framework (`apps/octo/framework/` + `apps/octo/adapters/`)

A `SourceAdapter` implementation maps one upstream vendor's API onto our
`CanonicalEvent` shape. Each adapter declares:

- `vendor_slug` / `vendor_display_name` / `vendor_category`
- `credential_shape()` — which fields the wizard collects
- `tenant_mapping_shape()` — how the vendor names its customers
- `smoke_test(creds)` — verify creds without persisting
- `start(instance_config)` / `stop()` — lifecycle hooks
- `extract_event(raw)` — map a vendor envelope to CanonicalEvent
- `route_to_tenant(raw)` — vendor customer → OCTO client slug
- `severity_map(raw)` / `human_summary(event)` / `deep_link(...)`

The framework's `AdapterRegistry` (in-memory + SQLite-backed) tracks
which adapter CLASSES are registered. The sibling **`InstanceManager`**
(`apps/octo/instances/`) tracks which configured upstreams are
RUNNING — one row per `adapter_instances` table entry, decrypted creds
held in memory, poller spawned via `asyncio.create_task`.

Boot flow:
1. `bootstrap.init_data_root()` applies migrations + creates dirs.
2. `create_app()` calls `_wire_adapter_runtime(app)` which:
   - Ensures the adapter-credentials key file exists
   - Builds an `AdapterRegistry`
   - Runs `discover_adapters("apps.octo.adapters", registry)` to walk
     the adapters package and register every concrete class
   - Builds an `InstanceManager(adapter_registry=registry)`
   - Calls `manager.start_all_persisted()` so every non-disabled row
     in `adapter_instances` spins up its poller
3. The HTTP surface comes up and starts serving requests.

If a single adapter fails to start, the boot log warns but the bundle
stays up. The failed row's `status` column flips to `error` with the
exception message; the operator can fix and retry via a future re-test
endpoint.

### NextDNS integration (`apps/octo/adapters/nextdns/`)

DNS filtering per client site, WITHOUT the DNS firehose: Athena asks the
cheap question first.

- **One credential** — the NextDNS account API key (`NEXTDNS_API_KEY`),
  entered in the Integrations wizard, stored in the credential vault like
  every adapter's. Never logged, never in a health detail, an audit row or
  an error message. No webhooks (NextDNS has none).
- **Mapping** — a NextDNS *profile* maps to a tenant; several profiles may
  map to one tenant (one per site). Discovery is ONE call (the profile
  list), with name-match suggestions and an **Ignore** choice for personal /
  test profiles (`GET/PUT /api/v1/integrations/nextdns/{id}/profiles`,
  admin+, audited). **Unmapped and ignored profiles are never polled**, and
  NextDNS never auto-creates a tenant. Nothing is polled until a profile is
  mapped; a newly mapped profile back-fills 24 h of SECURITY blocks only.
- **Polling, per mapped profile** — every 10 min: analytics *reasons* for
  the window since the last check (5-min overlap for analytics lag); ONLY if
  a signal-class reason has a count, the blocked logs of that window (paged,
  bounded per profile, per cycle, per profile-hour and per window; a cursor
  that stops making progress ends the window), keeping only signal lines.
  NextDNS counts EVERY reason of a multi-reason block (verified live
  2026-09-30: reason counts summed to roughly twice the blocked-query count
  on the busiest profile), so a signal behind a blocklist always triggers
  the pull; `limit=500` is accepted and the whole list is one page.
  Hourly: analytics *status* (+ reasons when anything was blocked) →
  `nextdns_hourly` in the tenant's `telemetry.db` (retention class
  `telemetry_rollup`, 180 d). A profile without ≥ 100 queries in 24 h is
  PENDING (unless it was dark for a day after a busy week — see
  Protection health): one 24-h read every 6 h (+ its logging settings at most daily: logging off at NextDNS
  is shown as such, not as "rollout pending"). The mapping is re-read
  before every profile task (unmapped mid-cycle = dropped at once; an
  unreadable tenant map polls nothing). Discovery (the profile list): first
  thing after a start, every 10 min while no profile is active or lapsed,
  then every 6 h.
- **Failures stay with their profile** — a profile whose calls time out /
  fail, or whose tenant's telemetry store cannot be written, backs off on
  its own (60 s → 15 min; store 10 min → 1 h) and is shown with its problem
  on the card, the mapping panel and in source health — the other profiles
  are polled as usual. A **403 on one profile** counts against the
  ENDPOINT CLASS that got it, each with its own streak and backoff (the
  interval, doubling to an hour while it lasts) — an answer on one class
  never resets another's: on its reads (security checks, log pulls, the
  24-h / 7-day / settings reads) it holds back EVERY read of the profile;
  on its hourly roll-up reads, its roll-ups only (its security checks go
  on); on its history call, that call only (its roll-ups go on). One
  refused profile never stalls the others' roll-ups or lapse detection. It
  is read as rate limiting at first (no lapse — never for the history call
  inside a roll-up) unless the profile list — asked at low priority, at
  most once per profile per 30 min — no longer shows it: then it is NOT
  ACCESSIBLE (shown, one lapse if it was active, re-probed every 6 h and
  when the list shows it again). A 403 that keeps coming back on one class
  of that profile ALONE (3 in a row, no other refusal on the key between
  them, the key answering other calls — a repeat 403 of a profile class
  already refused once does not count, so several profiles refused at
  once, e.g. un-shared together by one owner account, are each alone)
  while the list still shows it is the profile's own problem: **"NextDNS
  refuses this profile — check sharing/permissions"** (its reads) or
  **"NextDNS refuses this profile's hourly analytics — check
  sharing/permissions"** (its roll-ups: its blocks are still read, its
  protection cannot be judged) on the card, the panel and source health,
  retried hourly, no lapse, and the key is not called rate limited; an
  answer on that class clears it (the roll-ups then catch up — up to 24 h —
  and an outage they hid lapses). On the history call it is a **failed
  read** instead (local learning, asked again a day later — no problem
  shown). A profile being refused is left out of the roll-up lag and of
  the vendor-gap readiness from its first 403 on its reads or roll-ups.
  One 404 is re-checked next interval; a second asks the same list: still
  listed = a vendor-side failure (backoff, shown, no lapse — a short 404
  storm on listed profiles is not N lapses); no longer listed = MISSING
  (the same as not accessible). Only a throttle, a rejected key, or
  transport failures across several profiles in a row end a cycle.
- **NextDNS unreachable** — whatever the fleet size (each profile backs
  off on its own, so a small fleet's failures are spread over many
  cycles): when no NextDNS call has succeeded for 2 poll intervals since
  calls started failing (connection errors, timeouts, 5xx, malformed
  answers — a throttle, a 404 or a rejected key are answers), the instance
  row turns 'error': **"NextDNS unreachable since <time>"** (card, source
  health, `unreachable_since` in the health detail). The next successful
  call clears it. Three such failures in a row inside one cycle still say
  so at once (and end the cycle).
- **Signals** (`classification.py`, one table): HIGH threat-intel / Safe
  Browsing / cryptojacking / DGA / CSAM / tunnelling & exfiltration; MEDIUM
  AI threat detection, typosquatting, homographs, new / dynamic / parked /
  free-hosting domains, **bypass-methods** (VPN / proxy / Tor evasion); LOW
  DNS-rebinding protection; blocklists, TLDs, the denylist, trackers and
  parental controls (categories AND the ~40 service ids: tiktok, roblox, …)
  are counted, never alerted. An unknown non-list reason is a LOW signal
  (fail-safe).
- **Coalescing** (owner decision 2026-09-30, "split by severity") — one
  `nextdns.security_block` alert per bucket: **HIGH** per (profile, device
  or client IP, ROOT domain, reason) per CLOCK HOUR; **DGA** per (profile,
  device, reason) per hour, any domain; **MEDIUM / LOW** ONE per (profile,
  device, reason) per UTC DAY, whatever the domain — a busy site is about
  one alert per device per reason per day. Later hits are counted in
  `nextdns_signal_buckets` (the alert is never rewritten), shown live in
  the alerts feed ("N lookups across M domains") and noted on the alert
  when the span closes: lookups, distinct domains, up to 5 masked samples
  (each masked form once — masking keeps two letters and the TLD, so many
  domains look alike). The note waits until the profile's lines are read
  up to the span's end (a log backlog after downtime, a throttle or the
  profile's own backoff across midnight), so its counts are complete.
- **The site's week** (owner decisions A + B, 2026-09-30) — every rule
  judges an hour against the SAME HOUR OF THE WEEK on the previous 3
  weeks: the profile's own roll-ups, and — so there is no first-weeks
  blind spot — its NextDNS history. When a profile is first watched (and
  whenever its own roll-ups cover less than 3 weeks) Athena reads
  `analytics/status;series?from=-21d&interval=3600` ONCE (verified live:
  504 hourly buckets in one call), through the limiter at health priority,
  at most once per profile ID per 24 h (a failed attempt counts; the
  budget is kept in the global state row, so unmapping and re-mapping a
  profile within the day makes no second call — its seed is kept for the
  day and reused). Only closed buckets are used, from where the profile's
  SUSTAINED traffic starts (the first 24 h with ≥ 100 queries; a profile
  that never reaches that, from its first query): a stray test query weeks
  before the gateway rollout does not make those weeks the site's quiet
  week — they are unknown. It is kept compactly in its own state row
  (`nextdns_state:b:<id>`: the busy hours — ≥ 10 queries — and the hours
  with any query as one bitmask each, plus the busiest 24 h of its last
  week; ≈ 400 bytes, no counts, no raw series). The profile's own roll-up
  of an hour replaces the history's as they accumulate; the seed is
  dropped once nothing can reach it (23 days), and read again (once it is a
  day old) when it no longer reaches the profile's own roll-ups — a
  profile re-mapped to another tenant, whose roll-ups start afresh there.
  The hours inside a profile's LAPSES (from the lapse's `since` to the
  restore; "before Athena watched": from the history's last query) that
  it normally has queries in are UNKNOWN to its baseline (`dark_hours`,
  one bitmask over 22 days in its row): an outage or a holiday closure is
  never learnt as the site's normal week, so a site that goes dark again
  after a long outage, or the week after a two-week closure, still lapses.
  Its normally silent hours stay known (a weekend inside a closure is
  still a weekend), and so does every hour of a lapse decided without a
  baseline (the plain rule's silent day may have been a normal closed
  day). A series call that fails
  (error, timeout, 404 on the series alone, malformed answer) is not the
  profile's problem: it learns locally as before (the hourly rule after 7
  days of roll-ups, the plain whole-day backstop before that) and the
  history is asked again a day later. A THROTTLE on it is no answer: the
  attempt does not count, the profile is left as it was (a newly mapped
  one is not judged "before Athena watched" without its history) and the
  history is asked again once the backoff is over — a 403 on it inside a
  roll-up holds that call only: the profile's roll-ups go on. A 403 on the
  history call ALONE, 3 times
  (the profile still listed, the key answering), is a failed read (asked
  again a day later).
- **Protection health** — PENDING → ACTIVE (≥ 100 queries / 24 h; 1–99
  a day stay PENDING: no alert, never active). An ACTIVE profile raises ONE
  `nextdns.protection_lapsed` (medium: "DNS filtering stopped reporting —
  check the site's UniFi DNS/NextDNS setup") ONLY when it is silent while
  it NORMALLY has traffic: (a) the hourly rule — 2 zero hours IN A ROW at
  hours it is normally busy (≥ half of the same hours of the previous
  weeks with ≥ 10 queries; a closed hour between two quiet shoulder hours
  breaks the run; since = the run's first busy zero hour); or (b) the
  whole-day backstop — no queries in the trailing 24 h AND at least 2 of
  those hours the site normally has queries in (any query on ≥ half of the
  same hours of the previous weeks), for sites too quiet for the hourly
  rule; since = the first of those hours. A weekend-closed or part-week
  office that is always silent then never lapses for it — from day one —
  and a real outage on a normally-busy day lapses once. Without a baseline
  for the day (no history and < 7 days of roll-ups, or < half the day's
  hours known) the backstop is the plain rule: any silent day (since the
  run's first zero hour). Its FLOOR: 7 × 24 rolled-up zero hours in a row
  lapse an ever-active profile whatever its baseline (since the run's
  first zero hour) — "silent forever" never passes, and a weekend or a
  long weekend never reaches it. Queries resuming raise ONE
  `nextdns.protection_restored` (low) with an L1 note linking the lapse; a
  restore needs 25 queries in the hour or 2 non-zero hours in a row; a
  lapse within 24 h of the last restore is the same episode (notes on the
  earlier alerts). A site with 0 queries in 24 h and ≥ 100 in the 7 days
  before mapping starts LAPSED ("before Athena watched") only when its
  history says it normally has queries in at least 2 of those 24 hours (a
  truly dark site, mapped any day); silent now as it normally is (a
  weekend-closed office mapped on a Sunday) raises nothing — ACTIVE when
  its busiest 24 h of the last week reach 100, else PENDING (a low-volume
  profile). Without history the 7-day rule decides alone, and a "before
  Athena watched" profile that wakes up with fewer than 100 queries in 24 h
  goes back to PENDING (a note on that alert, no restore alert). A profile
  the key no longer sees, or with logging turned off, lapses with that
  cause named; after a visibility lapse the restore is dated when the
  profile is seen again, never before the lapse.
- **Known limitations (owner decisions, 2026-09-30)** — (1) a public
  holiday on a normally-busy day may lapse a closed office (and, if half
  the sites close, raise the fleet signal) — accepted. (2) **Partial loss
  is out of scope here** (decision C): a site whose clients stop using
  NextDNS while its gateway keeps resolving through it (a handful of queries
  an hour instead of hundreds) never lapses — every rule needs exactly zero queries. It
  will be detected by the UniFi / Fleet v2 cross-check (UniFi client count
  vs NextDNS devices), not by the NextDNS poller. (3) A site already dark
  when mapped in a window it is normally silent in (dark since Thursday,
  mapped on a Sunday) is lapsed at its first normally-busy silent hours
  (Monday), dated from then — not as "before Athena watched". (4) A site
  whose only traffic of the day is ONE normally-busy hour is never lapsed
  for missing it (both rules need 2 such hours). (5) Without its history
  (the series call failed, or a throttle hit it at mapping — retried a day
  later) the first-week rules apply: a weekend can lapse a closed office
  and a Sunday mapping can be "before Athena watched" (a throttle on that
  call is retried after the backoff instead). (6) A quiet stretch in a
  profile's history BEFORE Athena watched it (a closure inside the 3
  seeded weeks) is learnt as its week — only its own lapses are unknown —
  so an outage that matches it is caught by the 7-day floor, not sooner.
- **Vendor-side gaps and fleet outages** — a zero hour most ACTIVE profiles
  share (≥ 3, and ≥ half of those normally busy then when NextDNS gave
  evidence — a read for that hour FAILED: an error, a timeout, a 5xx, a
  malformed answer — or ≥ 80 % without) is a NextDNS-side gap. An EMPTY
  data array is NOT evidence: it is what a silent hour normally looks like
  (verified live: `{"data": [], "meta": {"pagination": {"cursor":
  null}}}`). No lapse for a gap hour, the card says so — for
  AT MOST 2 hours in a row. A third expires it: the sites lapse (since the
  first silent hour). When at least half of the watched sites are dark at
  once, ONE `nextdns.fleet_dns_outage` (HIGH: "N sites stopped reporting to
  NextDNS — check NextDNS status and the UniFi DNS template") goes to the
  operator's own tenant — the ACTIVE client of kind **internal** (none:
  shown on the card and in source health, not stored) — and every site's
  lapse carries the grouping (its L1 note is a pattern, not one escalation
  per site; client tenants never see the internal tenant's name or ids).
  "Dark" is any lapse that leaves the site unseen — no queries, logging
  turned off, or the profile no longer visible to the key (the account
  un-sharing many profiles at once is ONE incident too). The incident
  closes when fewer than half are dark, with a note counting the sites
  that REALLY report again and those still silent; within 24 h it reopens
  as the same incident.
- **Rate limit** — NextDNS answers a burst with a blanket HTTP 403 and sends
  no rate-limit headers. Every call made with the key goes through ONE
  limiter (`limiter.py`): ≥ 2 s apart (never below 1 s), priority security
  > investigation > hourly health > discovery with a starvation guard (a
  waiting call moves up one level per 4 s, so the panel's Reload and an
  analyst's search always get a slot within seconds); a 403 from a key that
  has EVER worked (persisted `key_ok_at`) = **throttled** (backoff 15 s →
  10 min, as long as it lasts; the card and source health say "throttled",
  never failed; after an hour a hint to check the key — never "re-add it");
  401, or 403 from a key that never worked = auth error. When the planned
  calls do not fit the limiter (beyond ≈ 200 active profiles at 2 s) the cycle stretches
  (logged once; the card shows the roll-up lag — a profile failing on its
  own is left out of it); it never bursts. Budget at 50 active + 25 pending
  profiles (example): ≈ 405 calls/h (+ log pulls only where signals occurred, + ONE
  history read per profile when it is first watched).
- **Restart-safe, without churn** — ONE `adapter_poller_state` row per
  profile (`nextdns_state:p:<id>`), its history seed in a row of its own
  (`nextdns_state:b:<id>`, written once per seed; an unmapped profile's is
  kept a day) and a global row (`nextdns_state`, with the history-call
  budget per profile ID for a day);
  only CHANGED rows are written, in one transaction, at the end of a cycle
  and at most every 30 s (≈ 3 MB/day of state at 50 active profiles in the
  fleet simulation, ≈ 3.2 MB/day for offices dark every night — the 48 h of
  per-hour evidence is packed as one bitmask per list; it was ≈ 540 MB).
  The next window starts at the stored mark minus the
  overlap however long Athena was down; the bucket ledger + the sink's
  identity keep re-read lines duplicate-free; protection / fleet signals go
  through an outbox in that state — written only once the state that
  decided them is stored, re-delivered after a crash, never doubled.
- **Investigation** — `POST /api/v1/search/nextdns` (analyst+, step-up,
  tenant-scoped, audited `search.nextdns`): a live logs query by domain
  and/or device over ≤ 7 days through the same limiter; domains masked, NOT
  stored. Budget per integration: one search at a time, 60 NextDNS calls
  per rolling hour, 60 s per search (refusals are 503s, audited) — a
  looping searcher cannot hold the poller back. API only this release.
- **Links** — "Open in NextDNS" = the profile's logs page
  (`https://my.nextdns.io/<profile>/logs`).

### Fleet v2 (`apps/octo/fleet/`, `api/routers/fleet.py`)

The Fleet tab is SITE-centric. `GET /api/v1/fleet/sites` answers every UniFi
site mapped to an active client (and one client-level entry for a client
without UniFi), each with four layers — **network** (UniFi fleet statistics),
**security** (UniFi IPS 24 h, NextDNS protection + threat blocks, RocketCyber
open incidents), **endpoints** (Datto inventory), **buoy** — and the worst of
them as the pin colour, with the reason. Data older than two polls of its
feed is *unknown*, never *ok*. It is built only from what the pollers already
store (no vendor call on a page load), cached 30 s and built under a time
bound. Locations: the UniFi console's own, else an admin-set manual location
(`/api/v1/fleet/locations/{slug}`, audited), else none — never from an IP; a
console carrying several sites reports the CONSOLE's place, so the manual
location wins for its sites (and without one only a console that is one
client's alone pins them). Operators (analyst+) see locations, vendor names
and deep links; a client user sees only their own sites, as a list (no map,
no buoys mode), with neutral wording and each site's own name only (never
the mapping label or the console's name).

The UniFi poller runs the ISP-outage correlator after every fleet poll:
three or more FAILURE POINTS on ONE ISP (ASN) losing their internet within
10 minutes (observed onsets only, the newest within 10 minutes of now) raise
ONE `fleet.isp_outage` signal (HIGH, OCSF Incident Finding) in the internal
tenant. A point is a console (one unreachable multi-site console is one, not
N sites), a public WAN address, or a site. Each site's own WAN alerts are
linked to it (the client's note names only its own provider — no count); it
closes with a note on recovery. A fleet-wide wave (half the sites, 3+ ISPs)
raises nothing and stays suppressed while it lasts. Restart-safe (state +
outbox in `adapter_poller_state`).

| Variable | What it does | Default |
|---|---|---|
| `OCTO_FLEET_ISP_OUTAGE_MIN_SITES` | Failure points (consoles / WAN addresses / sites) of one ASN that make an ISP outage (2..50) | `3` |
| `OCTO_FLEET_ISP_OUTAGE_WINDOW_MIN` | Onsets within this many minutes (5..60) | `10` |
| `OCTO_FLEET_CACHE_SEC` | Fleet model cache (0..300 s) | `30` |
| `OCTO_FLEET_BUILD_BUDGET_SEC` | Time bound of one build (0.5..30 s) | `5` |

### Datto RMM quick-job relay + job banner (`adapters/datto/job_output.py`)

`build_relay_wrapper()` wraps a quick-job script (PowerShell or POSIX) so its
stdout / stderr are POSTed to `POST /api/v1/webhooks/datto/job-output` (scoped
write-only `DATTO_JOB_OUTPUT_TOKEN`, header only), keyed by `jobUid`, and still
echoed for the RMM UI.

Every wrapped job carries a **banner that IDENTIFIES the job and never vouches
for it** — a comment on the first line and the first output line:

```
<# ATHENA AUTOMATION | job <job id> | RMM tenant <tenant> - identification only: verify this job ID ran on this device in the RMM job log. A banner without a matching job record is not ours. #>
"=== ATHENA AUTOMATION | job=$ATHENA_JOB | verify in the RMM job log | <UTC> ==="
```

(POSIX: `# …` on the line after `#!/bin/bash`, and `echo "=== … ==="`.) The
PowerShell banner is a one-line `<# … #>` block so that if the script is ever
pasted into the RMM UI, which collapses newlines, it fails to parse — loudly —
instead of a `#` comment silently swallowing the whole script; the wrapper is
NOT flatten-safe, so dispatch it as a multi-line quick-job / component script.
The job
id is the `job_name` Athena generates; Datto assigns its own job uid only once
the job exists, so the dispatch layer must send that exact name as the quick
job's `jobName` — it is what the RMM job log shows. The dispatch layer takes it
from `new_job_id()` (`athena-<UTC yyyymmddThhmmssZ>-<16 hex>`): a fresh ID per
dispatch, never reused, with a random part, so one ID = one job record. Without
a tenant the `| RMM tenant …` part is left out. The relay's User-Agent is
`AthenaRMM/2` (PowerShell) / `AthenaRMM-shell/2` (POSIX).

> **Operators — tell your SOC: verify an Athena job in the RMM job log, never
> by the banner text.** It is ours only if the RMM job log has a job with
> **this job ID** that ran **on this device** at **the time of the alert**
> (the first output line prints the job's UTC start). The banner is public (it
> is in this repository) and any script can carry a copy of it — including a
> real job ID copied from an earlier job (script-block logs, the RMM agent's
> cache). So a banner whose job ID has no record, or whose record ran on
> another device or at another time, is not yours. (Until 2026-10-09 the
> banner read "RUN WITH ATHENA — authorized automated action … not an
> intrusion … sanctioned activity" with User-Agent `AthenaRMM/1.0`; treat that
> text as carrying no meaning at all.)

Per deployment (env; validated when a wrapper is built — an invalid value
refuses to build the job, naming the variable):

| Variable | What it does | Default |
|---|---|---|
| `OCTO_JOB_BANNER_LABEL` | The banner's label (1–48 chars: letters, digits, space, `. _ : / + ( ) -`; must not claim anything — "authorized", "sanctioned", "expected", "safe", "trusted", "not an intrusion" … are refused) | `ATHENA AUTOMATION` |
| `OCTO_JOB_USER_AGENT` | PowerShell relay User-Agent (1–64 chars: letters, digits, space, `. _ : / + ( ) ; -`; same no-claims rule) | `AthenaRMM/2` |
| `OCTO_JOB_USER_AGENT_SHELL` | POSIX relay User-Agent (same rules) | `AthenaRMM-shell/2` |
| `OCTO_JOB_RMM_TENANT` | The RMM account the jobs run under (e.g. the Datto account UID), shown as `RMM tenant …`; the caller's `rmm_tenant` wins | unset (left out) |
| `OCTO_JOB_OUTPUT_DIR` | Where relayed job output is stored | `/var/lib/octo/state/datto-job-output` |

The job name and tenant are shown verbatim in the banner, so they must be
identifiers: 1–128 characters, a letter or digit first, then only letters,
digits and `. _ : -` (no spaces or quotes), and no claim word (the same list as
the label) — otherwise the job is not built.

### Auth surface (`apps/octo/api/routers/auth.py`)

Password + TOTP is the canonical sign-in path. The two-step ceremony:

1. `POST /auth/password/begin` — verify password → return stateless
   Fernet-encrypted `challenge_id` (5 min TTL).
2. `POST /auth/password/totp` — verify TOTP code → issue session cookie.

When an operator has no MFA enrolled yet (e.g., they just received a
temp password from an admin), step 1 short-circuits and issues a
`bootstrap`-authmethod session directly. The setup-gate middleware
(`setup_gate.py`) keeps that session confined to a tight allowlist —
only `/auth/me`, `/auth/me/profile`, `/auth/password/change`,
`/auth/totp/enroll/*`, `/auth/backup-codes/regenerate`,
`/auth/sessions{,/revoke-others}` are reachable until the operator
finishes setup (`must_change_password=0` AND `mfa_enabled=1`).

Other sign-in paths:
- `POST /auth/magic-link/{request,verify}` — admin issues a token to
  another operator; target consumes it to bootstrap a session.
- `POST /auth/passkey/{begin,complete}` — WebAuthn (registration +
  authentication). Operator-facing UI not yet built in V3.

Sessions are stored in `sessions` table (`registry.db`). 24h absolute
cap, 8h idle window. `GET /auth/sessions` returns ACTIVE sessions only;
revoke a session with `DELETE /auth/sessions/{prefix}` (12-char id
prefix per the response shape).

### Setup-gate middleware (`setup_gate.py`)

Defense-in-depth for the forced first-login flow. Every cookie-authed
request resolves the session, looks up the operator, and refuses with
`403 SETUP_REQUIRED` unless the path is on the setup-allowlist OR
`must_change_password=0` AND `mfa_enabled=1`. Bearer-token routes
(buoy ingest, admin tokens) bypass — they're not subject to operator
setup state.

---

## Running tests

```bash
cd /path/to/Athena-OCTO
PYTHONPATH=. packages/.venv/bin/pytest apps/octo --asyncio-mode=auto -q
```

428 tests as of 2026-05-12. All green. Test layout:

- `apps/octo/tests/auth/` — auth router suites (password+TOTP,
  magic-link, passkey, sessions, password reset, profile update,
  admin ops, adapter endpoints, end-to-end pipes)
- `apps/octo/tests/credentials/` — vault round-trip + key-file hygiene
- `apps/octo/tests/instances/` — InstanceManager lifecycle
- `apps/octo/adapters/{wazuh,datto,rocketcyber,unifi}/tests/` — per-
  adapter unit tests (extract_event, route_to_tenant, severity_map,
  smoke_test, start/stop)
- `apps/octo/framework/tests/` — registry + discovery
- `apps/octo/ingest/tests/` — SqliteIngestSink

---

## Environment variables

### Required for any deploy

| Variable | What it does | Default |
|---|---|---|
| `OCTO_DATA_ROOT` | Base path for `registry.db`, `clients/`, etc. | `~/octo/data` of the account the API runs as (single-host layout); the bundle image sets `/var/lib/octo/state` |
| `OCTO_PEPPER_PATH` | Pepper file path (PII hashing salt-prefix) | `~/octo/secrets/pepper.env` of that account; the bundle image sets `/var/lib/octo/secrets/pepper.env` |
| `OCTO_MFA_KEY_PATH` | Fernet key for TOTP secret encryption | sibling of pepper |
| `OCTO_ADAPTER_CREDENTIALS_KEY_PATH` | Fernet key for the adapter-credentials vault | sibling of pepper |
| `ATHENA_RP_ID` | WebAuthn RP-ID (deployment hostname) | `athena.local` |
| `ATHENA_ORIGIN` | Browser origin the auth cookie is set for | `https://athena.local` |

### Production-only (leave at default in prod)

| Variable | What it does | Default |
|---|---|---|
| `OCTO_COOKIE_SECURE` | `Secure` flag on session cookies (`0` to disable) | `1` |

The dev script sets `OCTO_COOKIE_SECURE=0` because browsers refuse to
store Secure cookies on `http://localhost`. **Never** set this to `0` in
any deployment that handles real credentials (there are no auth
shortcuts, even in dev).

### Notification relay (best-effort)

| Variable | What it does | Default |
|---|---|---|
| `POSTFIX_RELAY_HOST` | SMTP relay for outbound notifications | `postfix-relay.local` |
| `POSTFIX_RELAY_PORT` | Relay port | `2525` |
| `POSTFIX_RELAY_FROM` | Default From: address | `notifications@athena.local` |
| `POSTFIX_RELAY_TIMEOUT` | Connection timeout (seconds) | `10` |

When the relay is unreachable (e.g., local dev), `send_email()` logs
a warning and returns False — never raises. Failed emails are
captured in the audit log so admins can re-issue magic links manually.

---

## Local dev pair

The one-command flow for local development:

```bash
cd /path/to/Athena-OCTO
./scripts/dev.sh
```

This kills any running backend/frontend, then starts both fresh with
interleaved `[backend]` / `[frontend]` prefixes:

- Backend (uvicorn `--reload`) on `127.0.0.1:8001`
- Vite dev server on `localhost:5173` (proxies `/api/* → 127.0.0.1:8001`)

First run provisions the dev root (`$OCTO_DEV_ROOT`, default
`~/.octo-dev/`: data + secrets; anything but a dev root, the same check as
the other dev tools in `apps/octo/dev/dev_root.py`, is refused before
anything is created) and creates a `dev-admin` super_admin
operator. It has no static or documented password: it gets a random one
generated for that run, or `$OCTO_DEV_PASSWORD` if you set it (at least 12
characters; set it without shell history via
`read -rs OCTO_DEV_PASSWORD && export OCTO_DEV_PASSWORD`). The password and
the TOTP enrollment (secret + otpauth URI) are handed over exactly once and
never logged:

- run directly in an interactive terminal, `start-dev-backend.sh` prints
  them there;
- otherwise (stdout piped or logged, which includes `./scripts/dev.sh` and
  `scripts/dev_up.sh`) it writes them to
  `<dev-root>/secrets/dev-admin.initial-credentials` (mode 600) and prints
  only that path. Read the file, enroll the TOTP, sign in once, then delete
  the file (later runs remind you while it still exists).

Subsequent runs reuse the persisted state. Blow away the dev root to
reset (the next run provisions a new operator and new credentials).

Ctrl+C in the terminal cleans up both children.

See `scripts/start-dev-backend.sh` for the underlying provisioning logic.

---

## Architecture cross-references

- `docs/architecture.md` — the Athena ↔ OCTO split, per-bundle self-containment,
  file-level isolation for client data
- `docs/adrs/0002-octo-data-substrate.md` — OCTO as the data substrate
- `docs/NON-NEGOTIABLES.md` — security rules, incl. tenant isolation (rule 6)

Design rules these follow (internal decisions, summarised): each bundle is
self-contained for one MSP; client data is isolated per database file; roles
are super_admin / admin / analyst / viewer, and viewer accounts are ephemeral
customer accounts; no auth shortcuts ever, even in dev; auth TTLs default to
minutes; security invariants are copied verbatim when code is ported.
