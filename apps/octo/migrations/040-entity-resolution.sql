-- Migration 040: entity resolution, slice 1 — the per-tenant entities.db, the
-- per-tenant rollout switch, the known-benign registry, entity retention
-- classes and the `entity_review` operator notice.
--
-- Design of record: 2026-10-01-entity-resolution-design.md (B as the base,
-- grafts from A, the adversarial review G1-G11 folded in, Rick's decisions of
-- 2026-10-01: MAC auto-link with the MAC-anomaly safeguard, NO masking of
-- device names, response actions out of scope).
--
-- entities section (clients/<slug>/entities.db — ONE file per tenant; created
-- eagerly at client provisioning and lazily by `entity.db.ensure_db()`, the
-- telemetry pattern; every read path probes sqlite_master first and answers
-- "unresolved", never a 500). No table holds a tenant slug: isolation is the
-- file. auto_vacuum = INCREMENTAL is set by ensure_db before the first table.
--
--   site                   a place of THIS tenant (anchored on a UniFi site,
--                          or — no UniFi — on a Datto site / NextDNS profile /
--                          an operator assertion).
--   site_vendor_ref        "vendor scope X belongs to site Y" with a state
--                          (auto | suggested | confirmed | rejected | retired),
--                          a score, the rule + version, evidence and who
--                          decided. UniFi scopes are '<hostId>/<siteId>' (site
--                          ids COLLIDE across consoles). OPERATOR WINS (G8):
--                          triggers refuse a rule's UPDATE of a confirmed or
--                          rejected row, a rule's INSERT for a scope an
--                          operator confirmed (or for the very pair an
--                          operator rejected), and any DELETE of an operator
--                          decision except the retention job's (`maint`).
--   lk_site_egress         public IP of a site as an interval (UniFi
--                          externalIp, an operator assertion), with NAT kind,
--                          `shared_external` (another console has the same WAN
--                          address — one bit, nothing about the other) and
--                          honest slack on sampled edges (G10).
--   lk_ip_lease            LAN IP ↔ MAC / UniFi client at a site as an
--                          interval. DAY-CHUNKED (no row spans 00:00Z) so every
--                          "at T" scan is bounded. Sampled edges carry slack;
--                          a reconnect between polls splits the row (G10);
--                          `conflict` = never a pick (IP conflict, MAC
--                          anomaly).
--   lk_site_subnet         LAN subnets, VLAN, purpose and the DNS path a
--                          network's DHCP hands out (gateway | nextdns | other
--                          …) — the candidate filter.
--   lk_watermark           "this feed is complete through X" per (source,
--                          scope) — PER SITE, also for the fleet feed (G7).
--   lk_join                system-log CLIENT_* join events (MAC, IP, name,
--                          time): exact lease edges and the ±20 s join
--                          heuristic (the join is logged AFTER DHCP; the first
--                          lookup can precede it by seconds).
--                          A join no lease covers is a GHOST: a D3 pick near
--                          it drops to candidates (G10; computed at query time
--                          from lk_join, so arrival order never matters).
--   lk_mac_anomaly         the MAC-anomaly rule's findings (G2 / M1): one MAC,
--                          two IPs in one poll window; wired and wireless at
--                          once. Leases in the window are `conflict`.
--   resolution(+_dep)      the stored answer for one event: site + basis +
--                          score, device / candidates, tier, the provenance
--                          CHAIN, status (final | provisional | stale |
--                          superseded). NEVER a device name (G11): candidates
--                          reference lease rows + tokens; names are read from
--                          the leases while they exist.
--   link_suppression       "these are NOT the same" (operator reject).
--   link_conflict          a rule that ran into an operator decision (its
--                          INSERT aborted at the trigger), two sites claiming
--                          one event, a profile whose traffic comes from none
--                          of the tenant's sites: the Conflicts tab + one
--                          `entity_review` notice each. Resolved stays
--                          resolved until the evidence materially changes;
--                          'accepted' (expected) suppresses it.
--   resolver_cursor        the sweep's resume point per source store.
--   resolution_run         one row per worker pass that CHANGED something
--                          (counts, notes / diffs), plus at most one
--                          'heartbeat' row an hour for a quiet tenant.
--   inv_device             the Datto inventory feed (read-only, NEVER UDFs):
--                          uid, hostname, device type, online, lastSeen, LAN
--                          IP, OS, domain — current state + online_since.
--   ndns_device / _hour    NextDNS devices (the app's device name / id) and
--   ndns_presence_hour     per-hour query counts; which hours were READ (and
--                          read whole) — unknown hours never count as silent.
--   ndns_ip_day            per (profile, day): queries from this tenant's own
--                          egress addresses vs. all (the L-EGRESS statistic;
--                          other public IPs are never stored).
--   device_link            NextDNS device ↔ Datto device (unique name in ONE
--                          tenant: suggested; + the same LAN IP: auto),
--                          operator-wins like site_vendor_ref.
--   device_watch           the "NextDNS stopped reporting from a PC Datto says
--                          is online" state per link, with an outbox.
--   maint                  one row: the retention job's delete permission
--                          (set and cleared inside its own transaction).
--
-- registry section
--   clients.entity_resolution  'off' (default) | 'shadow' | 'on' — off: no
--     entity read or write for the tenant; shadow: computed and stored, not
--     shown on alerts; on: shown.
--   known_benign_rules — an operator-editable list that DOWNGRADES specific
--     blocked domains for specific reasons (never allowlists: still blocked).
--     Seeded with the Samsung connectivity probe ("www.g" + many "o" +
--     "gle.com" on a NextDNS threat-intelligence feed since 2026-09-24).
--   operator_notices gains kind 'entity_review' (a conflict a rule hit against
--     an operator decision; "profile may belong to another client") — the
--     table is rebuilt (038's pattern), every row and id kept.
--   bundle_config_retention: entity_lookup_lease (90 d; guest networks 7 d),
--     entity_lookup_egress (400), entity_resolution (365), entity_links (400
--     after retired / rejected), entity_inventory (90).

PRAGMA foreign_keys = ON;

-- @target: entities

CREATE TABLE IF NOT EXISTS maint (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    allow_operator_delete INTEGER NOT NULL DEFAULT 0 CHECK (allow_operator_delete IN (0, 1))
);
INSERT OR IGNORE INTO maint (id, allow_operator_delete) VALUES (1, 0);

CREATE TABLE IF NOT EXISTS site (
    site_id      TEXT PRIMARY KEY,
    label        TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 200),
    anchor       TEXT NOT NULL CHECK (anchor IN ('unifi','datto','nextdns','operator')),
    tz           TEXT,
    lat REAL, lng REAL, geo_radius_m REAL, geo_text TEXT,
    geo_source   TEXT CHECK (geo_source IN ('unifi','manual')),
    status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','merged','retired')),
    merged_into  TEXT REFERENCES site(site_id),
    created_at   TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    -- 'operator:<id>' once an operator renamed the site: the vendor's name
    -- no longer replaces the label (NULL: the label follows the vendor).
    label_by     TEXT,
    CHECK ((status = 'merged') = (merged_into IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS site_vendor_ref (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id             TEXT NOT NULL REFERENCES site(site_id),
    vendor              TEXT NOT NULL CHECK (vendor IN ('unifi','datto','nextdns','buoy','wazuh')),
    adapter_instance_id INTEGER NOT NULL DEFAULT 0,
    vendor_scope_id     TEXT NOT NULL CHECK (length(vendor_scope_id) BETWEEN 1 AND 320),
    vendor_scope_alt    TEXT,
    state               TEXT NOT NULL CHECK (state IN ('auto','suggested','confirmed','rejected','retired')),
    score               INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    rule_id             TEXT NOT NULL,
    rule_version        INTEGER NOT NULL,
    evidence            TEXT NOT NULL DEFAULT '{}',
    inputs_sha256       TEXT NOT NULL,
    valid_from          TEXT NOT NULL,
    valid_to            TEXT,
    decided_by          TEXT NOT NULL,
    decided_at          TEXT NOT NULL,
    reason              TEXT,
    created_at          TEXT NOT NULL,
    -- Names are a SUGGESTION only, capped at 45 (N-SITE): never auto.
    CHECK (rule_id NOT LIKE 'N-%' OR (state IN ('suggested','rejected','retired','confirmed')
                                      AND (state = 'confirmed' OR score <= 45)))
);
CREATE INDEX IF NOT EXISTS ix_svr_scope ON site_vendor_ref(vendor, adapter_instance_id, vendor_scope_id, state);
CREATE INDEX IF NOT EXISTS ix_svr_site ON site_vendor_ref(site_id, state);
-- A UniFi site is exactly one Athena site at a time.
CREATE UNIQUE INDEX IF NOT EXISTS ux_svr_unifi ON site_vendor_ref(adapter_instance_id, vendor_scope_id)
    WHERE vendor = 'unifi' AND state IN ('auto','confirmed') AND valid_to IS NULL;

-- OPERATOR WINS (G8) — on UPDATE, INSERT and DELETE.
CREATE TRIGGER IF NOT EXISTS svr_operator_wins_update BEFORE UPDATE ON site_vendor_ref
WHEN OLD.state IN ('confirmed','rejected') AND NEW.decided_by NOT LIKE 'operator:%'
BEGIN SELECT RAISE(ABORT, 'operator decisions change only by operator'); END;

CREATE TRIGGER IF NOT EXISTS svr_operator_wins_insert BEFORE INSERT ON site_vendor_ref
WHEN NEW.decided_by NOT LIKE 'operator:%' AND (
    EXISTS (SELECT 1 FROM site_vendor_ref r
             WHERE r.vendor = NEW.vendor AND r.adapter_instance_id = NEW.adapter_instance_id
               AND r.vendor_scope_id = NEW.vendor_scope_id AND r.state = 'confirmed'
               AND r.valid_to IS NULL)
    OR EXISTS (SELECT 1 FROM site_vendor_ref r
                WHERE r.vendor = NEW.vendor AND r.adapter_instance_id = NEW.adapter_instance_id
                  AND r.vendor_scope_id = NEW.vendor_scope_id AND r.site_id = NEW.site_id
                  AND r.state = 'rejected' AND r.valid_to IS NULL))
BEGIN SELECT RAISE(ABORT, 'operator decision stands for this scope'); END;

CREATE TRIGGER IF NOT EXISTS svr_operator_wins_delete BEFORE DELETE ON site_vendor_ref
WHEN OLD.state IN ('confirmed','rejected')
     AND (SELECT allow_operator_delete FROM maint WHERE id = 1) IS NOT 1
BEGIN SELECT RAISE(ABORT, 'operator decisions are never deleted'); END;

CREATE TABLE IF NOT EXISTS lk_site_egress (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id         TEXT NOT NULL REFERENCES site(site_id),
    vendor_scope_id TEXT NOT NULL DEFAULT '',
    addr            TEXT NOT NULL,
    prefix_len      INTEGER NOT NULL,
    wan             TEXT,
    nat_kind        TEXT NOT NULL DEFAULT 'unknown'
                      CHECK (nat_kind IN ('direct','cgnat','double_nat','unknown')),
    asn INTEGER, isp TEXT,
    source          TEXT NOT NULL CHECK (source IN ('unifi.sites','unifi.hosts','datto.extIp','buoy.heartbeat','operator')),
    valid_from      TEXT NOT NULL,
    from_exact      INTEGER NOT NULL DEFAULT 0,
    from_slack_s    INTEGER NOT NULL DEFAULT 0,
    valid_to        TEXT,
    to_exact        INTEGER NOT NULL DEFAULT 0,
    to_slack_s      INTEGER NOT NULL DEFAULT 0,
    close_reason    TEXT CHECK (close_reason IN ('changed','absent','failover','gap','operator','unmapped')),
    flags           TEXT NOT NULL DEFAULT '[]',
    samples         INTEGER NOT NULL DEFAULT 1,
    source_ref      TEXT NOT NULL,
    asserted_by     TEXT,
    reason          TEXT
);
CREATE INDEX IF NOT EXISTS ix_egress_addr ON lk_site_egress(addr, prefix_len, valid_from);
CREATE INDEX IF NOT EXISTS ix_egress_site ON lk_site_egress(site_id, valid_from);
CREATE INDEX IF NOT EXISTS ix_egress_open ON lk_site_egress(vendor_scope_id, wan) WHERE valid_to IS NULL;

CREATE TABLE IF NOT EXISTS lk_ip_lease (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id          TEXT NOT NULL REFERENCES site(site_id),
    vendor_scope_id  TEXT NOT NULL,
    net_id           TEXT,
    ip               TEXT NOT NULL,
    mac              TEXT,
    mac_tok          TEXT,
    mac_kind         TEXT NOT NULL CHECK (mac_kind IN ('global','random','virtual','none')),
    vendor_client_id TEXT,
    name_obs         TEXT,
    name_tok         TEXT,
    conn             TEXT NOT NULL DEFAULT 'unknown'
                       CHECK (conn IN ('wired','wireless','vpn','teleport','unknown')),
    is_guest         INTEGER NOT NULL DEFAULT 0 CHECK (is_guest IN (0,1)),
    ssid TEXT,
    uplink_ref TEXT,
    connected_at     TEXT,
    valid_from       TEXT NOT NULL,
    from_exact       INTEGER NOT NULL DEFAULT 0,
    from_slack_s     INTEGER NOT NULL DEFAULT 0,
    valid_to         TEXT,
    to_exact         INTEGER NOT NULL DEFAULT 0,
    to_slack_s       INTEGER NOT NULL DEFAULT 0,
    close_reason     TEXT CHECK (close_reason IN
                       ('absent','ip_changed','mac_changed','disconnect_event','rollover','gap',
                        'unmapped','operator','reconnect')),
    conflict         INTEGER NOT NULL DEFAULT 0 CHECK (conflict IN (0,1)),
    source           TEXT NOT NULL,
    source_ref       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_lease_ip  ON lk_ip_lease(site_id, ip, valid_from);
CREATE INDEX IF NOT EXISTS ix_lease_at  ON lk_ip_lease(site_id, valid_from);
CREATE INDEX IF NOT EXISTS ix_lease_mac ON lk_ip_lease(mac, valid_from) WHERE mac IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_lease_open ON lk_ip_lease(vendor_scope_id) WHERE valid_to IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_lease_open ON lk_ip_lease(site_id, mac, ip) WHERE valid_to IS NULL;

CREATE TABLE IF NOT EXISTS lk_site_subnet (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id     TEXT NOT NULL REFERENCES site(site_id),
    vendor_scope_id TEXT NOT NULL DEFAULT '',
    net_id      TEXT,
    name        TEXT,
    cidr        TEXT NOT NULL,
    vlan        INTEGER,
    purpose     TEXT NOT NULL DEFAULT 'unknown'
                  CHECK (purpose IN ('corporate','guest','vpn','iot','unknown')),
    dns_path    TEXT NOT NULL DEFAULT 'unknown'
                  CHECK (dns_path IN ('gateway','nextdns','buoy','other','unknown')),
    valid_from  TEXT NOT NULL,
    valid_to    TEXT,
    source      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_subnet_site ON lk_site_subnet(site_id, valid_from);

CREATE TABLE IF NOT EXISTS lk_watermark (
    source          TEXT NOT NULL,
    scope           TEXT NOT NULL,
    last_ok_at      TEXT,
    prev_ok_at      TEXT,
    last_attempt_at TEXT NOT NULL,
    last_error      TEXT,
    PRIMARY KEY (source, scope)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS lk_join (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id         TEXT NOT NULL REFERENCES site(site_id),
    vendor_scope_id TEXT NOT NULL,
    event           TEXT NOT NULL,
    mac             TEXT,
    ip              TEXT,
    name_obs        TEXT,
    uplink          TEXT,
    at              TEXT NOT NULL,
    vendor_event_id TEXT NOT NULL,
    -- The MAC-anomaly rule has given its verdict on this join (it is checked
    -- against the first client snapshot at or after it — whenever the log
    -- arrives, so a late log line is never missed).
    checked         INTEGER NOT NULL DEFAULT 0 CHECK (checked IN (0,1)),
    UNIQUE (vendor_scope_id, vendor_event_id)
);
CREATE INDEX IF NOT EXISTS ix_join_at ON lk_join(site_id, at);
CREATE INDEX IF NOT EXISTS ix_join_mac ON lk_join(mac, at);
CREATE INDEX IF NOT EXISTS ix_join_unchecked ON lk_join(vendor_scope_id, at) WHERE checked = 0;

-- CLIENT_IP_CONFLICT as a TIME-BOUNDED fact (never a flag on a whole lease
-- row, which a day rollover would carry on for as long as the device stays):
-- D3 gives no pick for that address within ±10 minutes of it.
CREATE TABLE IF NOT EXISTS lk_ip_conflict (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id         TEXT NOT NULL REFERENCES site(site_id),
    vendor_scope_id TEXT NOT NULL,
    ip              TEXT NOT NULL,
    at              TEXT NOT NULL,
    vendor_event_id TEXT NOT NULL,
    UNIQUE (vendor_scope_id, vendor_event_id)
);
CREATE INDEX IF NOT EXISTS ix_ipconf ON lk_ip_conflict(site_id, ip, at);

-- Uplink CHANGES of wired global MACs (the switch a client hangs off, from
-- client snapshots and from wired join events — each source compared with
-- itself): the MAC-anomaly rule's "keeps switching between two uplinks"
-- trigger (a clone on another switch). Only changes are written.
CREATE TABLE IF NOT EXISTS lk_uplink (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id         TEXT NOT NULL REFERENCES site(site_id),
    vendor_scope_id TEXT NOT NULL,
    mac             TEXT NOT NULL,
    source          TEXT NOT NULL CHECK (source IN ('snapshot','log')),
    uplink          TEXT NOT NULL,
    prev_uplink     TEXT,
    at              TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_uplink_mac ON lk_uplink(vendor_scope_id, mac, source, at);

CREATE TABLE IF NOT EXISTS lk_mac_anomaly (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id     TEXT NOT NULL REFERENCES site(site_id),
    vendor_scope_id TEXT NOT NULL,
    mac         TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('two_ips','wired_and_wireless','uplink_flap','agent_offline')),
    from_ts     TEXT NOT NULL,
    to_ts       TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '{}',
    signaled    INTEGER NOT NULL DEFAULT 0 CHECK (signaled IN (0,1)),
    created_at  TEXT NOT NULL,
    UNIQUE (site_id, mac, kind, from_ts)
);
CREATE INDEX IF NOT EXISTS ix_anomaly_mac ON lk_mac_anomaly(mac, from_ts);

CREATE TABLE IF NOT EXISTS resolution (
    res_id           TEXT PRIMARY KEY,
    event_id         INTEGER,
    event_source     TEXT,
    subject_type     TEXT NOT NULL,
    subject_tok      TEXT NOT NULL,
    subject_root     TEXT,
    tok_key_version  TEXT NOT NULL,
    at               TEXT NOT NULL,
    time_quality     TEXT NOT NULL CHECK (time_quality IN ('vendor','sensor','receive')),
    site_id          TEXT,
    site_basis       TEXT CHECK (site_basis IN ('located','policy','both','not_located','none')),
    site_score       INTEGER,
    site_tier        TEXT,
    device_ref       TEXT,
    tier             TEXT NOT NULL CHECK (tier IN
                       ('exact','strong','medium','weak','candidate','suggest','conflict','none')),
    score            INTEGER NOT NULL,
    n_candidates     INTEGER NOT NULL DEFAULT 0,
    chain            TEXT NOT NULL,
    candidates       TEXT NOT NULL DEFAULT '[]',
    flags            TEXT NOT NULL DEFAULT '[]',
    resolver_version TEXT NOT NULL,
    lookup_watermark TEXT NOT NULL,
    mode             TEXT NOT NULL DEFAULT 'sweep',
    bucket_last_seen TEXT,
    status           TEXT NOT NULL CHECK (status IN ('final','provisional','stale','superseded')),
    superseded_by    TEXT,
    created_at       TEXT NOT NULL,
    created_by       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_res_event ON resolution(event_id) WHERE status <> 'superseded';
CREATE INDEX IF NOT EXISTS ix_res_open  ON resolution(status, created_at) WHERE status IN ('provisional','stale');
CREATE INDEX IF NOT EXISTS ix_res_created ON resolution(created_at);
CREATE INDEX IF NOT EXISTS ix_res_device ON resolution(device_ref, at) WHERE device_ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS resolution_dep (
    dep_kind TEXT NOT NULL,
    dep_id   TEXT NOT NULL,
    res_id   TEXT NOT NULL,
    PRIMARY KEY (dep_kind, dep_id, res_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_dep_res ON resolution_dep(res_id);

CREATE TABLE IF NOT EXISTS link_suppression (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    a_type      TEXT NOT NULL,
    a_value     TEXT NOT NULL,
    b_type      TEXT NOT NULL,
    b_value     TEXT NOT NULL,
    rule_id     TEXT,
    reason      TEXT NOT NULL CHECK (length(reason) BETWEEN 3 AND 500),
    decided_by  TEXT NOT NULL,
    decided_at  TEXT NOT NULL,
    expires_at  TEXT
);
CREATE INDEX IF NOT EXISTS ix_supp_a ON link_suppression(a_type, a_value);

CREATE TABLE IF NOT EXISTS link_conflict (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL CHECK (kind IN ('operator_decision','site_conflict','routing',
                                              'device_link')),
    subject     TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '{}',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    hits        INTEGER NOT NULL DEFAULT 1,
    notified    INTEGER NOT NULL DEFAULT 0 CHECK (notified IN (0,1)),
    resolved_at TEXT,
    resolved_by TEXT,
    -- How an operator closed it: 'resolved' (it stays closed until its
    -- evidence MATERIALLY changes — `basis`, the material part of the detail
    -- when it was closed) or 'accepted' (expected: a branch office without
    -- UniFi, a second site — the rule is suppressed for that subject in
    -- link_suppression). `cleared_at` (routing): when the condition was
    -- last seen NOT to hold after it was closed — it reopens only when it
    -- comes back after staying away for days.
    resolution  TEXT CHECK (resolution IN ('resolved','accepted')),
    basis       TEXT,
    cleared_at  TEXT,
    UNIQUE (kind, subject)
);

CREATE TABLE IF NOT EXISTS resolver_cursor (
    store         TEXT PRIMARY KEY,
    last_event_id INTEGER NOT NULL,
    updated_at    TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS resolution_run (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- 'heartbeat': a quiet tenant's hourly summary (a pass that changed
    -- nothing writes no row of its own).
    mode TEXT NOT NULL CHECK (mode IN ('sweep','revisit','bucket_close','nightly','replay','backfill',
                                       'heartbeat')),
    resolver_version TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    scanned INTEGER NOT NULL DEFAULT 0,
    final INTEGER NOT NULL DEFAULT 0,
    provisional INTEGER NOT NULL DEFAULT 0,
    suggested INTEGER NOT NULL DEFAULT 0,
    conflicts INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    notes TEXT
);

-- Datto inventory (read-only; the allowlisted fields only — NEVER a UDF).
CREATE TABLE IF NOT EXISTS inv_device (
    adapter_instance_id INTEGER NOT NULL,
    device_uid      TEXT NOT NULL,
    site_uid        TEXT NOT NULL,
    hostname        TEXT,
    hostname_key    TEXT,
    device_type     TEXT,
    online          INTEGER CHECK (online IN (0,1)),
    online_since    TEXT,
    last_seen       TEXT,
    int_ip          TEXT,
    os              TEXT,
    domain          TEXT,
    first_seen_at   TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    missing_since   TEXT,
    PRIMARY KEY (adapter_instance_id, device_uid)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_inv_host ON inv_device(hostname_key);

-- NextDNS devices and per-hour presence (the app's own device name).
CREATE TABLE IF NOT EXISTS ndns_device (
    profile_id   TEXT NOT NULL,
    device_id    TEXT NOT NULL,
    name         TEXT,
    name_key     TEXT,
    model        TEXT,
    client       TEXT,
    local_ip     TEXT,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    PRIMARY KEY (profile_id, device_id)
) WITHOUT ROWID;

-- The SEED: the 14 days before a profile's feed started, read once per UTC
-- day (analytics/devices per day) — so a device whose app was ALREADY dead
-- when the client was switched on is known, linked and watched.
CREATE TABLE IF NOT EXISTS ndns_device_day (
    profile_id   TEXT NOT NULL,
    device_id    TEXT NOT NULL,
    day          TEXT NOT NULL,
    queries      INTEGER NOT NULL CHECK (queries >= 0),
    PRIMARY KEY (profile_id, device_id, day)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS ndns_seed_day (
    profile_id   TEXT NOT NULL,
    day          TEXT NOT NULL,
    devices      INTEGER NOT NULL DEFAULT 0,
    read_at      TEXT NOT NULL,
    PRIMARY KEY (profile_id, day)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_ndns_device_name ON ndns_device(name_key);

CREATE TABLE IF NOT EXISTS ndns_device_hour (
    profile_id   TEXT NOT NULL,
    device_id    TEXT NOT NULL,
    hour         TEXT NOT NULL,
    queries      INTEGER NOT NULL CHECK (queries >= 0),
    PRIMARY KEY (profile_id, device_id, hour)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_ndns_hour ON ndns_device_hour(hour);

CREATE TABLE IF NOT EXISTS ndns_presence_hour (
    profile_id   TEXT NOT NULL,
    hour         TEXT NOT NULL,
    complete     INTEGER NOT NULL CHECK (complete IN (0,1)),
    method       TEXT NOT NULL CHECK (method IN ('analytics','logs')),
    devices      INTEGER NOT NULL DEFAULT 0,
    total_queries INTEGER,
    read_at      TEXT NOT NULL,
    PRIMARY KEY (profile_id, hour)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS ndns_ip_day (
    profile_id   TEXT NOT NULL,
    day          TEXT NOT NULL,
    egress_queries INTEGER NOT NULL DEFAULT 0,
    total_queries  INTEGER NOT NULL DEFAULT 0,
    egress_ips     TEXT NOT NULL DEFAULT '[]',
    read_at      TEXT NOT NULL,
    PRIMARY KEY (profile_id, day)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS device_link (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    a_type      TEXT NOT NULL CHECK (a_type IN ('nextdns_device')),
    a_value     TEXT NOT NULL,
    b_type      TEXT NOT NULL CHECK (b_type IN ('datto_device')),
    b_value     TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('auto','suggested','confirmed','rejected','retired')),
    score       INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    rule_id     TEXT NOT NULL,
    rule_version INTEGER NOT NULL,
    evidence    TEXT NOT NULL DEFAULT '{}',
    valid_from  TEXT NOT NULL,
    valid_to    TEXT,
    decided_by  TEXT NOT NULL,
    decided_at  TEXT NOT NULL,
    reason      TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_dlink_a ON device_link(a_type, a_value, state);
CREATE INDEX IF NOT EXISTS ix_dlink_b ON device_link(b_type, b_value, state);

CREATE TRIGGER IF NOT EXISTS dlink_operator_wins_update BEFORE UPDATE ON device_link
WHEN OLD.state IN ('confirmed','rejected') AND NEW.decided_by NOT LIKE 'operator:%'
BEGIN SELECT RAISE(ABORT, 'operator decisions change only by operator'); END;

CREATE TRIGGER IF NOT EXISTS dlink_operator_wins_insert BEFORE INSERT ON device_link
WHEN NEW.decided_by NOT LIKE 'operator:%' AND EXISTS (
    SELECT 1 FROM device_link l
     WHERE l.valid_to IS NULL AND (
           (l.a_value = NEW.a_value AND l.state = 'confirmed')
        OR (l.b_value = NEW.b_value AND l.state = 'confirmed')
        OR (l.a_value = NEW.a_value AND l.b_value = NEW.b_value AND l.state = 'rejected')))
BEGIN SELECT RAISE(ABORT, 'operator decision stands for this device'); END;

CREATE TRIGGER IF NOT EXISTS dlink_operator_wins_delete BEFORE DELETE ON device_link
WHEN OLD.state IN ('confirmed','rejected')
     AND (SELECT allow_operator_delete FROM maint WHERE id = 1) IS NOT 1
BEGIN SELECT RAISE(ABORT, 'operator decisions are never deleted'); END;

CREATE TABLE IF NOT EXISTS device_watch (
    link_id          INTEGER PRIMARY KEY,
    state            TEXT NOT NULL DEFAULT 'ok' CHECK (state IN ('ok','silent')),
    since            TEXT,
    last_report_hour TEXT,
    alert_event_id   INTEGER,
    restore_event_id INTEGER,
    pending_kind     TEXT CHECK (pending_kind IN ('device_silent','device_restored')),
    pending_payload  TEXT,
    updated_at       TEXT NOT NULL
);

PRAGMA user_version = 40;

-- @target: registry

BEGIN IMMEDIATE;

ALTER TABLE clients ADD COLUMN entity_resolution TEXT NOT NULL DEFAULT 'off'
    CHECK (entity_resolution IN ('off','shadow','on'));

-- A re-upgrade takes back a switch a rollback kept (036's pattern).
CREATE TABLE IF NOT EXISTS clients_entity_resolution_rolled_back_040 (
    slug TEXT NOT NULL, entity_resolution TEXT NOT NULL);
UPDATE clients SET entity_resolution = (
    SELECT k.entity_resolution FROM clients_entity_resolution_rolled_back_040 k
     WHERE k.slug = clients.slug AND k.entity_resolution IN ('off','shadow','on')
     ORDER BY k.rowid DESC LIMIT 1)
 WHERE slug IN (SELECT slug FROM clients_entity_resolution_rolled_back_040
                 WHERE entity_resolution IN ('off','shadow','on'));
-- Taken back: the kept rows are spent (a LATER rollback keeps the state of
-- THEN — an operator's change in between is never undone by old rows).
DELETE FROM clients_entity_resolution_rolled_back_040;

CREATE TABLE IF NOT EXISTS known_benign_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor          TEXT NOT NULL CHECK (vendor IN ('nextdns')),
    match_kind      TEXT NOT NULL CHECK (match_kind IN ('exact','suffix','regex')),
    pattern         TEXT NOT NULL CHECK (length(pattern) BETWEEN 1 AND 200),
    reasons         TEXT NOT NULL DEFAULT '[]',
    level           TEXT NOT NULL DEFAULT 'low' CHECK (level IN ('low','medium')),
    label           TEXT NOT NULL CHECK (length(label) BETWEEN 3 AND 120),
    note            TEXT NOT NULL DEFAULT '' CHECK (length(note) <= 1000),
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    created_by      INTEGER,
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_by      INTEGER
);
CREATE TABLE IF NOT EXISTS known_benign_rules_rolled_back_040
    AS SELECT * FROM known_benign_rules WHERE 0;
INSERT OR IGNORE INTO known_benign_rules
    (id, vendor, match_kind, pattern, reasons, level, label, note, enabled, created_at,
     created_by, updated_at, updated_by)
SELECT k.id, k.vendor, k.match_kind, k.pattern, k.reasons, k.level, k.label, k.note,
       k.enabled, k.created_at, k.created_by, k.updated_at, k.updated_by
  FROM known_benign_rules_rolled_back_040 k
 WHERE k.rowid = (SELECT MAX(q.rowid) FROM known_benign_rules_rolled_back_040 q WHERE q.id = k.id);
DELETE FROM known_benign_rules_rolled_back_040;
-- The seed: the Samsung connectivity probe. "www.g" + three or more "o" +
-- "gle.com", blocked by a NextDNS threat-intelligence feed since 2026-09-24:
-- LOW, labelled known-benign, STILL BLOCKED (never an allowlist).
INSERT INTO known_benign_rules (vendor, match_kind, pattern, reasons, level, label, note)
SELECT 'nextdns', 'regex', 'www\.go{3,}gle\.com', '["threat-intelligence-feeds"]', 'low',
       'Samsung connectivity probe (google typosquat)',
       'Samsung phones and TVs look up www.g…gle.com spellings with extra o''s as a '
       || 'connectivity check. A NextDNS threat-intelligence feed lists them since '
       || '2026-09-24. Downgraded to LOW in Athena; NextDNS keeps blocking them (never '
       || 'allowlisted).'
 WHERE NOT EXISTS (SELECT 1 FROM known_benign_rules WHERE vendor = 'nextdns'
                     AND pattern = 'www\.go{3,}gle\.com');

INSERT OR IGNORE INTO bundle_config_retention
    (data_class, retention_days, legal_baseline_days, regulator_basis, editable, description, updated_by)
VALUES
    ('entity_lookup_lease', 90, 7,
     'Operational baseline (no regulator citation); minimisation — leases name people''s devices',
     1,
     'Who had which LAN address when (entities.db lk_ip_lease, joins, ghosts, MAC anomalies). Guest networks are kept 7 days whatever this says.',
     NULL),
    ('entity_lookup_egress', 400, 30,
     'Operational baseline (no regulator citation)',
     1,
     'Which public address was each site''s internet connection when (entities.db lk_site_egress, subnets). No personal data; places year-old signals.',
     NULL),
    ('entity_resolution', 365, 30,
     'Follows the signal events it explains',
     1,
     'Stored answers ("which site, which device, how sure, why") for alerts. Candidate details are cut to a count when the leases behind them are pruned.',
     NULL),
    ('entity_links', 400, 30,
     'Operational baseline (no regulator citation)',
     1,
     'Retired and rejected links and expired suppressions, counted from when they ended. Active links are never pruned.',
     NULL),
    ('entity_inventory', 90, 7,
     'Operational baseline (no regulator citation)',
     1,
     'Datto device inventory rows not seen for this long, and NextDNS device presence hours.',
     NULL);

CREATE TABLE IF NOT EXISTS operator_notices_040 (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id        INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    kind                TEXT NOT NULL
                          CHECK (kind IN ('single_attested_merge','single_attested_offboard',
                                          'mapping_review','entity_review')),
    actor_id            INTEGER NOT NULL,
    subject_slug        TEXT NOT NULL,
    target_slug         TEXT,
    change_request_id   INTEGER REFERENCES tenant_change_requests(id) ON DELETE SET NULL,
    title               TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    body                TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 2000),
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    acknowledged_at     TEXT,
    email_state         TEXT NOT NULL DEFAULT 'pending'
                          CHECK (email_state IN
                            ('pending','sent','failed','not_configured','no_address')),
    email_attempted_at  TEXT,
    request_id          TEXT NOT NULL,
    UNIQUE (recipient_id, change_request_id)
);
INSERT INTO operator_notices_040 (
    id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
    title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id)
SELECT id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
       title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id
  FROM operator_notices;
DROP INDEX IF EXISTS idx_operator_notices_open;
DROP INDEX IF EXISTS idx_operator_notices_change;
DROP INDEX IF EXISTS idx_operator_notices_request;
DROP TABLE operator_notices;
ALTER TABLE operator_notices_040 RENAME TO operator_notices;
CREATE INDEX IF NOT EXISTS idx_operator_notices_open
    ON operator_notices(recipient_id, id) WHERE acknowledged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_operator_notices_change
    ON operator_notices(change_request_id);
CREATE INDEX IF NOT EXISTS idx_operator_notices_request
    ON operator_notices(kind, request_id, recipient_id);
CREATE TABLE IF NOT EXISTS operator_notices_rolled_back_040
    AS SELECT * FROM operator_notices WHERE 0;
INSERT OR IGNORE INTO operator_notices (
    id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
    title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id)
SELECT k.id, k.recipient_id, k.kind, k.actor_id, k.subject_slug, k.target_slug, NULL,
       k.title, k.body, k.created_at, k.acknowledged_at, k.email_state,
       k.email_attempted_at, k.request_id
  FROM operator_notices_rolled_back_040 k
 WHERE k.kind = 'entity_review'
   AND k.recipient_id IN (SELECT id FROM operators)
   AND k.rowid = (SELECT MAX(q.rowid) FROM operator_notices_rolled_back_040 q
                   WHERE q.id = k.id);
DELETE FROM operator_notices_rolled_back_040;

PRAGMA user_version = 40;

COMMIT;
