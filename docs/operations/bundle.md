# Deploying the OCTO bundle

How to deploy, upgrade and roll back the two-container OCTO bundle
(octo-core + octo-llm). Hosts are named by role: **the bundle host** runs
the bundle, **the operator's machine** holds the private keys. Code,
scripts and console messages cite this page as `docs/operations/bundle.md`.

The compose template (`docker-compose.yml.template`) and `rehome.sh` (moves
a deployed bundle to a new public **console** hostname; it never touches the
ingest hostname) are deploy files kept in the private deploy tree
(`ops/octo-bundle/`); they are not part of the public copy. Everything the
container runs, including the operator scripts below, is in the image.

## Why the template is shaped this way

Two findings of the 2026-05-22 LLM-pipeline review (archived outside the
repo) shaped it:

- **C4: production restart policy.** The in-product "restart octo-llm"
  button no longer shells out to the docker socket: it makes the sibling
  exit non-zero, and compose's `restart: unless-stopped` brings it back up.
  octo-core needs no docker socket mount.

- **P4: network egress lockdown.** octo-llm runs on a network with
  `internal: true`, so it has no default gateway and can ONLY reach
  octo-core. Together with the sha256 check of the model at load time, a
  compromised octo-llm container cannot pull replacement weights from
  outside or exfiltrate data.

## Applying

On the bundle host (as root). The container runs as **uid/gid 1000**; the
state + secrets dirs must be *owned* by it (bootstrap chmods the data root —
write access alone is not enough). Keep state on fast local storage (SQLite
WAL) — not a FUSE/network share, and not a RAM-backed rootfs.

```bash
export BUNDLE_HOST_IP=<the host's private address>
export BUNDLE_STATE_DIR=/opt/athena-octo/state
export BUNDLE_SECRETS_DIR=/opt/athena-octo/secrets
export BUNDLE_MODELS_DIR=/opt/athena-octo/models
export BUNDLE_PUBLIC_HOST=<public console hostname>
# OPTIONAL — the vendor-facing ingest hostname (see "Template variables").
# Leave it empty for a poll-only deployment; it must still be exported so
# envsubst renders it (as "").
export BUNDLE_PUBLIC_INGEST_HOST=<public ingest hostname, or empty>

for v in BUNDLE_HOST_IP BUNDLE_STATE_DIR BUNDLE_SECRETS_DIR BUNDLE_MODELS_DIR BUNDLE_PUBLIC_HOST; do
  [ -n "${!v}" ] || { echo "unset: $v"; exit 1; }     # envsubst renders unset as ""
done

mkdir -p "$BUNDLE_STATE_DIR" "$BUNDLE_SECRETS_DIR" "$BUNDLE_MODELS_DIR"
chown -R 1000:1000 "$BUNDLE_STATE_DIR" "$BUNDLE_SECRETS_DIR"
chmod 700 "$BUNDLE_SECRETS_DIR"

envsubst '$BUNDLE_HOST_IP $BUNDLE_STATE_DIR $BUNDLE_SECRETS_DIR $BUNDLE_MODELS_DIR $BUNDLE_PUBLIC_HOST $BUNDLE_PUBLIC_INGEST_HOST' \
  < docker-compose.yml.template > /opt/athena-octo/docker-compose.yml
cd /opt/athena-octo

# First run ONLY — secrets, data root, migrations, factory super_admin.
# Prints the factory super_admin's single-use setup link (24h) to this
# terminal exactly once. There is no default password — see below.
# Refuses to run (and creates nothing) if ownership or the public host is wrong.
docker compose run --rm octo-core python -m apps.octo.bundle_bootstrap

docker compose up -d          # octo-core only; add `--profile llm` for octo-llm
docker compose ps             # (healthy) = /readyz green: secrets parse,
                              # registry schema current, data root writable
```

### Template variables

| Variable | Required | What it sets |
|----------|----------|--------------|
| `BUNDLE_HOST_IP` | yes | Host address octo-core's port 8001 binds to |
| `BUNDLE_STATE_DIR` | yes | SQLite state (owned by uid/gid 1000) |
| `BUNDLE_SECRETS_DIR` | yes | Pepper / MFA / adapter-credential keys (mode 700) |
| `BUNDLE_MODELS_DIR` | yes | GGUF models, mounted read-only into octo-core |
| `BUNDLE_PUBLIC_HOST` | yes | The **console** name: `ATHENA_RP_ID`, `ATHENA_ORIGIN`, `OCTO_PUBLIC_BASE_URL` |
| `BUNDLE_PUBLIC_INGEST_HOST` | no | The **vendor-facing ingest** name: `OCTO_PUBLIC_INGEST_BASE_URL` |

**Two public names, on purpose.** The console name is for operators and may sit
behind an interactive access gate. The ingest name is what vendors POST to; at
the edge it must route **only** `/api/v1/webhooks` and `/api/v1/ingest` to
octo-core, with no interactive gate in front (those routes authenticate every
request themselves — webhook secret / ingest token — and fail closed).

Webhook URLs shown in the integration wizard are built from the ingest name
**only**. If `BUNDLE_PUBLIC_INGEST_HOST` is empty the wizard says "no public
ingest hostname is configured … real-time webhooks cannot work yet", offers no
URL and defaults "Enable real-time webhooks" to OFF (poll-only); it never falls
back to the console name, because a vendor posting to a gated console is
silently blocked. Polling works either way. An integration whose webhooks were
switched on anyway shows a warning on its card until the name exists. A value
still containing a literal `${...}` (the variable was missing from the
`envsubst` list) is treated as unset.

To add the ingest name later: set `OCTO_PUBLIC_INGEST_BASE_URL` in
`docker-compose.yml`, make sure the name reaches the ingest edge, and
`docker compose up -d octo-core`. Integrations created poll-only in the
meantime have no webhook token: Settings → Integrations → <vendor> → Disable,
then Add integration again (and map sites again — mappings belong to the
instance). Integrations that already hold a token keep it; their webhook URL
appears under "Setup guide" on the card.

`rehome.sh` moves the **console** name and deliberately leaves
`OCTO_PUBLIC_INGEST_BASE_URL` alone. Re-homing ingest is a separate act,
because every vendor portal holds that URL: bring the new ingest name up at the
edge, edit that one line, recreate octo-core, update the webhook URL in each
vendor portal, and only then retire the old name.

### Edge requirements for the ingest hostname

Whatever fronts the ingest name (CDN, WAF, reverse proxy, tunnel) has to let a
vendor's **server** through. Webhook senders are not browsers: they cannot
solve a challenge, follow a login redirect or keep a cookie, and they
originate from cloud address space that bot scoring tends to distrust.

| Requirement | Why |
|-------------|-----|
| **Path-restricted** — route only `/api/v1/webhooks` and `/api/v1/ingest` (POST) to octo-core; everything else on this name is refused at the edge | The console and admin API must never be reachable through the un-gated name |
| **No interactive access gate** — no SSO / sign-in page, managed or JavaScript challenge, or CAPTCHA on this name | The sender gets a block page or a redirect instead of octo-core. The routes authenticate every request themselves (webhook secret / ingest token) and fail closed |
| **WAF managed rule sets exempted for this hostname + webhook path** | OWASP-style anomaly scoring routinely trips on a vendor's machine-to-machine JSON POST (headers + body together cross the threshold) and answers 403. Skip the managed rule set only for `host = <ingest name> AND path starts with /api/v1/webhooks/`; keep every other host fully protected. The edge's security events name the rule and carry a request ID — the fastest diagnosis is that ID |
| **Bot protection off, or exempted, for this hostname** | Server-to-server POSTs from a vendor's cloud are commonly classed as automated traffic and answered 403. Some CDN plans cannot exempt a single hostname from bot protection — then use a plan or rule set that can, or serve ingest from a name where it is off |
| **Body size cap** of 1 MB at the edge | octo-core refuses larger webhook bodies anyway (422); refusing them earlier keeps them off the origin |
| **Real client IP header** — the edge SETS `X-Forwarded-For` to the connecting client's address, overwriting whatever the client sent | octo-core attributes a request to this address when the proxy is in `OCTO_TRUSTED_PROXIES` (next section): per-caller rate limits, the failed-authentication limiter and step-up binding. If a client-supplied value were passed through, a sender could pick its own address; the same holds for anything that can reach the reverse proxy without going through the edge (next section, "The trust chain") |

**Telling an edge block from an Athena reject.** The webhook URLs never answer
`403`: they answer `2xx`, `401`, `422` or `429` (a `5xx` only if storing the
event failed), always as JSON. A `403`, an HTML page, a redirect or a timeout
in the vendor's own "test webhook" result was produced in front of octo-core. Each integration's card (Settings → Integrations) shows
**Last webhook received**, or **No webhook has reached Athena yet**, and counts
requests that arrived but were rejected, with the reason — so "the vendor says
it failed" plus "none has reached Athena" means: look at the edge's security
events for the ingest hostname, not at the integration. A test POST from
inside your own network (or from a workstation) proves little: it is not
scored the way the vendor's cloud is.

Also confirm the vendor was given the **ingest** URL shown under "Setup guide",
not the console name.

### Client addresses behind the proxy (`OCTO_TRUSTED_PROXIES`)

octo-core is reached three ways on the bundle host:

1. **Ingest name**: edge → tunnel → reverse proxy → octo-core. The proxy
   route sets `X-Forwarded-For` to the edge's client header
   (`header_up X-Forwarded-For {http.request.header.CF-Connecting-IP}` in
   Caddy terms), overwriting whatever the client sent.
2. **Console**: edge → tunnel → reverse proxy → athena-console → octo-core.
   The console (`auth-proxy.js`) forwards the `X-Forwarded-For` it received
   with its own peer (the reverse proxy) appended.
3. **Published port** (`$BUNDLE_HOST_IP:8001`, the tailnet): buoys and
   operator tools connect directly; docker keeps their source address, and
   they can send any `X-Forwarded-For`.

The socket peer is the only address nobody can forge, so octo-core believes
`X-Forwarded-For` only from peers in **`OCTO_TRUSTED_PROXIES`** (IP
addresses or CIDR networks, separated by commas or spaces; unset or empty =
trust nobody). From a trusted peer it takes the right-most entry that is not
itself a trusted proxy; anything that is not a bare IP address stops the
walk. `CF-Connecting-IP` is never read by octo-core: the proxy copies it into
`X-Forwarded-For`, and believing it too would give direct callers a second
way to name their own address.

**A value octo-core cannot use stops it from starting**, instead of quietly
trusting fewer proxies than you meant (or none), or more. Refused: an entry
that is not an address or a network (a network *name*, `;` as separator),
an entry with host bits set (`192.0.2.10/24` is neither one address nor a
network: write `192.0.2.10/32` or `192.0.2.0/24`; it is never widened),
`/0`, and an IPv4-mapped IPv6 entry (`::ffff:192.0.2.10`: octo-core compares
such peers as plain IPv4, so it would never match; write the IPv4 form).
`docker logs octo-core` then ends with
`TrustedProxiesError: OCTO_TRUSTED_PROXIES is not valid, so octo-core will not start: entry 2 ...`
(entries are named by position; one that is not an address is not
repeated), and the container restarts until the value is fixed.

That address keys the per-route rate limits for requests without a bearer
token (a bearer request is bucketed by a hash of its whole token; sign-in,
step-up and webhook routes always by address, whatever `Authorization` header
they carry) and the **failed-authentication limiter**: 30 failed credentials
(a 401 on a bearer request, or on a sign-in / TOTP / magic-link / passkey /
password / email-change / step-up check) within 10 minutes from one address
→ that address's credential attempts get `429` + `Retry-After` for 15
minutes, before they reach auth. Attempts still in flight count toward the
30, so parallel guesses are held to it too. A token retried with the same
value counts once; every failed sign-in counts; successes never count and
never reset the count. Never held back: signed-in sessions (except their own
step-up / password / backup-code checks), webhooks, and tokens that
authenticated on a bearer route in the last 24 h. Tune with
`OCTO_AUTH_FAILURE_LIMIT` (0 = off, else at least 5),
`OCTO_AUTH_FAILURE_WINDOW_SEC` and `OCTO_AUTH_FAILURE_COOLDOWN_SEC`
(60–86400), set like `OCTO_TRUSTED_PROXIES` below (an `environment:` line in
`docker-compose.yml`; the template has them commented out). The per-account
sign-in lockout (5 failures, 15 minutes) is separate and unchanged.

**The failed-auth limiter is off while `OCTO_TRUSTED_PROXIES` is empty**, and
it never counts or holds back a request whose client address is itself a
trusted proxy (the chain named no client). Without a declared proxy the
"address" of every console user is the console's, and a per-address
cool-down there would be a switch anyone could flip: 30 wrong passwords and
nobody can sign in or step up for 15 minutes. (A deployment with no reverse
proxy at all can turn it on with `OCTO_TRUSTED_PROXIES=127.0.0.1/32`.)

**Search step-up binds to the same address.** An elevation is tied to the
network it was granted from (`SEARCH_STEP_UP_IP_BINDING`, default the /24,
or /48 for IPv6), and that network is now the client address above, never
the left-most `X-Forwarded-For` entry (which a stolen session on the tailnet
could set to the victim's address). With the setting empty that is the
socket peer: on the console path the console's own address, one constant
network for every operator, as the tunnel's address was before; on the
published port, the caller. What operators notice: an elevation granted
before the upgrade may ask for the password and code once more
(`STEP_UP_NETWORK_CHANGED`), and once the setting is applied step-up follows
each operator's real address, so changing network, or the browser switching
between IPv4 and IPv6 towards the edge, asks again. Audit rows still record
the socket peer (on the proxied paths, the reverse proxy's or the console's
address).

#### The trust chain: the reverse proxy is reachable only through the tunnel

Everything octo-core believes about a proxied client comes from the edge's
`CF-Connecting-IP`, which the reverse proxy copies. That header is only as
good as the path into the reverse proxy, so **the reverse proxy must accept
connections from the tunnel only**:

- no published host ports on it: `docker port <reverse proxy container>`
  prints nothing;
- nothing on its docker networks that is not your own (the tunnel, the
  console, octo-core, the shim).

Anything else that can open a connection to it can name any client address,
which includes putting someone else's address into a cool-down, or send no
`CF-Connecting-IP` and be taken for the proxy itself, which the failed-auth
limiter never counts. If something else must be able to reach the reverse
proxy, make it believe `CF-Connecting-IP` from the tunnel only (Caddy:
`trusted_proxies static <the tunnel's address range>` and
`client_ip_headers CF-Connecting-IP` in the global `servers` block, then
`header_up X-Forwarded-For {client_ip}` on every route in place of the
`CF-Connecting-IP` line), or leave `OCTO_TRUSTED_PROXIES` empty.

#### The setting: the subnet of a proxy network of their own

The reverse proxy and the console reach octo-core, and the reverse proxy
reaches the console, over a small docker network that **only those three
containers** join, created `--internal`. `OCTO_TRUSTED_PROXIES` is that
network's subnet. Why not the shared network's subnet, or the two
containers' /32 addresses on it:

- The shared network also carries the tunnel, the Wazuh shim and whatever
  else the host runs there, and its gateway address. Trusting its subnet
  lets any of them name any client.
- /32 addresses only work while they stay put, which takes pinning
  (`ipv4_address:`), and a pinned address is held only while its container
  is running: while the console is stopped or being recreated, docker can
  hand that address to the next container that starts on the network, which
  is then a trusted proxy without anyone noticing. Pinning also needs a
  network created with an explicit subnet, which an existing one may not
  have.
- On a network of its own, trust follows membership: a container is
  trusted only if its compose file (or `docker network connect`) puts it on
  that network, and no restart moves anything in or out. A hop that
  arrives over another network is not believed, and its log line names it.
- `--internal` keeps docker's port publishing and port proxy off it (they
  use a container's gateway network, which an internal network never is),
  so callers of the published ports `:8001` and `:9870` never arrive from an
  address on it. If docker gives the host an address on the network, that
  gateway address, where processes on the bundle host itself (and
  containers in host network mode) would connect from, is trusted along
  with the subnet: the bundle host is inside the trust boundary anyway.

Each container that is called over this network has a name that exists
only there: `octo-core-proxied` and `athena-console-proxied`. The reverse
proxy and the console use only those names. (The plain container names
resolve on the shared network too, and a hop over the shared network comes
from an address octo-core does not trust: those users would count as one
client again, and while the setting is applied 30 failed sign-ins among them
would hold all of them back.)

**Order on the bundle host.** Each step is safe on its own; what octo-core
believes changes only at step 6.

1. Create the network, once, and note its subnet:

   ```bash
   # A free private range of your choice (a /28 is plenty); docker refuses
   # one that overlaps an existing network.
   SUBNET='<free private range>'
   docker network create --driver bridge --internal --subnet "$SUBNET" octo-proxy-net
   docker network inspect octo-proxy-net --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}'
   #   → that range; 192.0.2.0/28 stands for it below (a placeholder)
   ```

   Pin the subnet. Without `--subnet` docker picks a free range, and if the
   network is ever removed and created again (a `docker network prune` while
   all three containers are stopped, say) it may get another one, which
   `OCTO_TRUSTED_PROXIES` no longer covers: every proxied request then
   counts as coming from the reverse proxy or the console (the checks after
   step 6 show it).

   Another name works too: put `BUNDLE_PROXY_NETWORK=<name>` in
   `/opt/athena-octo/.env` and export it when rendering the console template.

2. **octo-core joins it.** The repo's `ops/bundle-host/docker-compose.bundle-host.yml`
   already carries these lines: replacing the deployed overlay with it does
   this step. To edit a deployed copy by hand instead (skip this if it
   already has a `proxy` network), octo-core's `networks:` becomes

   ```yaml
       networks:
         shared:
         proxy:
           aliases:
             - octo-core-proxied
   ```

   and the file's top-level `networks:` gets

   ```yaml
     proxy:
       name: ${BUNDLE_PROXY_NETWORK:-octo-proxy-net}
       external: true
   ```

   Then `docker compose -f docker-compose.yml -f docker-compose.bundle-host.yml up -d octo-core`.

3. **The console.** Deploy `ops/bundle-host/athena-console-overrides/auth-proxy.js`
   to the console's `src-overrides/`. Render the console's compose file
   again from `ops/bundle-host/athena-console-overrides/docker-compose.yml.template`
   (its header has the command) with `BUNDLE_PROXY_NETWORK` exported and
   `OCTO_BACKEND_BASE_URL=http://octo-core-proxied:8001`; compare it with the
   deployed file first and keep any local edits. `docker compose up -d` in
   the console's directory. Check:
   `docker exec athena-console printenv OCTO_BASE_URL` →
   `http://octo-core-proxied:8001`.
4. **The reverse proxy.** Join it to the network (in its compose file: the
   network as `external: true` under the same name; it needs no alias).
   In its configuration the API route's upstream becomes
   `octo-core-proxied:8001` and the console routes' upstream
   `athena-console-proxied:9870`, and the console routes get the line the
   API route has: `header_up X-Forwarded-For {http.request.header.CF-Connecting-IP}`.
   Reload it. Until then the proxy's default `X-Forwarded-For` on the
   console routes names the tunnel, the same for every console user.
5. **Check who is on the network**: exactly three containers, octo-core, the
   console and the reverse proxy. Anything else listed would be trusted
   too: disconnect it.

   ```bash
   docker network inspect octo-proxy-net \
     --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{println}}{{end}}'
   ```

6. **Set `OCTO_TRUSTED_PROXIES`.** It takes two lines, because compose reads
   `.env` only to fill `${...}` placeholders in the compose file; it does
   not pass `.env` into containers, and a `docker-compose.yml` rendered
   before this setting existed has no placeholder for it.

   ```bash
   cd /opt/athena-octo
   # a) .env (placeholder value: the subnet printed in step 1):
   #      OCTO_TRUSTED_PROXIES=192.0.2.0/28
   # b) docker-compose.yml, in octo-core's `environment:` (6 spaces in, next
   #    to OCTO_COOKIE_SECURE), unless `grep -n OCTO_TRUSTED_PROXIES docker-compose.yml`
   #    already finds it (a file rendered from the current template has it):
   #      OCTO_TRUSTED_PROXIES: "${OCTO_TRUSTED_PROXIES:-}"
   docker compose -f docker-compose.yml -f docker-compose.bundle-host.yml config | grep OCTO_TRUSTED_PROXIES
   #   → OCTO_TRUSTED_PROXIES: 192.0.2.0/28        (compose filled it in)
   docker compose -f docker-compose.yml -f docker-compose.bundle-host.yml up -d octo-core
   docker exec octo-core printenv OCTO_TRUSTED_PROXIES
   #   → 192.0.2.0/28                              (the container has it)
   docker logs --since 10m octo-core 2>&1 | grep 'client addresses'
   #   → client addresses: X-Forwarded-For believed only from OCTO_TRUSTED_PROXIES =
   #     192.0.2.0/28 (1 network); failed-auth limiter on: 30 failures in 600 s
   #     from one address -> 900 s cool-down
   ```

   `printenv` printing nothing, or a log line saying
   `OCTO_TRUSTED_PROXIES is empty`, means the value did not reach the
   container: line a) or b) is missing. A value octo-core cannot use stops
   it (see above); `docker logs octo-core 2>&1 | tail -n 3` shows why.

**Check that nobody else is believed.** From a tailnet machine that is not
the bundle host, right after the restart:

```bash
# <bundle host address>: the host's tailnet address (BUNDLE_HOST_IP when the
# template was rendered; that variable is not set on this machine)
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H 'X-Forwarded-For: 198.51.100.1' "http://<bundle host address>:8001/healthz"
#   → 200  (anything else, or a curl error: the request never reached
#           octo-core, and the log check below proves nothing)
# on the bundle host:
docker logs --since 10m octo-core 2>&1 | grep 'X-Forwarded-For from'
#   → "X-Forwarded-For from <that machine's tailnet address> ignored: ..."
```

One line per caller per start. No line at all after a `200` means the caller
arrived from a trusted address: check step 5.

**Check that every hop uses the proxy network.** Open the console and sign
in, then on the bundle host:

```bash
docker logs --since 10m octo-core 2>&1 | grep -E "X-Forwarded-For from|is a private address"
```

A line naming the reverse proxy or the console means one hop goes over the
shared network: `X-Forwarded-For from <address> ignored` is a hop INTO
octo-core (the upstream name in step 3 or 4), `client address <address>,
named by trusted proxy ..., is a private address` the reverse proxy reaching
the console (its console upstream in step 4). Fix it at once: until then
every user behind that hop shares one address, and 30 failed sign-ins among
them hold all of them back. Each line appears once per address per start.
After a host or array restart, step 5 and these checks are all there is to
repeat: the setting names a network, not addresses. If the network was ever
created again, first compare its subnet (step 1's `inspect`) with
`docker exec octo-core printenv OCTO_TRUSTED_PROXIES`.

**What changes on each path.**

| Path | `OCTO_TRUSTED_PROXIES` empty (default) | Set, after the steps above |
|------|------------------------------------------|------------------------------|
| 1 — ingest name | Throughput buckets as before: per client, by the proxy's header, scoped to the proxy's address. Bearer buckets: whole-token hash (was the token's first 8 characters). Failed-auth limiter off | Per client for every limit (the header from the trusted proxy) |
| 2 — console | Throughput as before: every console user shares one address. Failed-auth limiter off. Step-up binds to the console's address (one network for everybody) | Per client for every limit and for step-up. A request whose chain names no client (proxy hops only) is never counted or held back |
| 3 — published port | The caller is its socket peer; its header can split only its OWN throughput buckets (it could pick any bucket before, including someone else's), never reach another caller's. Failed-auth limiter off. Step-up binds to the caller | The header is ignored: one caller, one address, for every limit and for step-up |

### First sign-in (factory super_admin)

The factory account (`Root`) is **magic-link-only**: it is created with no
password, no TOTP secret and no backup codes, and there is no default
credential to document or rotate. The bootstrap prints a username and one
single-use link, valid 24 hours:

1. Open the link in a browser.
2. Set a password (12+ characters).
3. Scan the QR code with an authenticator app (Google / Microsoft
   Authenticator, Duo, …), enter the code, and save the backup codes shown.

The console refuses everything except this wizard until steps 2 **and** 3
are complete. Until the link is used, treat it like a password — it is the
account's only credential. Password sign-in and "forgot password" do
nothing for this account before setup (and "forgot password" stays off
while its email is the `root@athena.local` placeholder — set a real one in
Settings).

**Lost your authenticator?** At the code prompt, enter one of the backup
codes saved during setup (single use; dashes optional). Then re-enrol under
Settings → Account → Reset TOTP and regenerate the codes.

**Took more than 5 minutes between password and code?** The sign-in times
out, says so, and returns to the password step — it is not a wrong code.

**Closed the browser mid-setup?** After the password step, sign in with that
password: you land back in the wizard to finish 2FA. (The wizard enforces
password first precisely so this always works.)

**Locked out / link expired.** If the link expired or was lost, or the
factory password, authenticator AND backup codes are gone and no other
super_admin can help, run on the bundle host:

```bash
docker compose run --rm octo-core \
    python -m apps.octo.bundle_bootstrap --reset-factory-admin
```

This returns the factory account to the pre-setup state — password and MFA
cleared, backup codes and passkeys revoked, every session signed out, any
earlier link dead, the account re-enabled and `super_admin` re-granted if
someone had disabled or demoted it — and prints a fresh 24h link (plus a
terminal QR) for the same wizard. Host
shell access is the authorisation; the reset is audit-logged
(`factory_recovery_initiated`). On a bundle provisioned before this change
(factory account already has a password + TOTP) nothing happens until you
run this command; running it is how you move that account onto
authenticator-enrolled 2FA.

**Escrow `$BUNDLE_SECRETS_DIR` off-box the same day.** Losing `mfa-key.env`
destroys every operator's TOTP enrolment + backup codes; losing
`adapter-credentials-key.env` makes every vaulted vendor credential
undecryptable (all integrations must be re-entered). Password and token
hashes are self-contained (PBKDF2, per-row salt) and do not depend on this
dir; `pepper.env` is provisioned for legacy compatibility only — nothing in
the bedrock API reads it. Back this dir up separately from state.

### Operator scripts (shipped in the image)

```bash
# Mint an ingest token (shown once — straight into the caller's config + vault)
docker compose exec octo-core python /app/scripts/mint_client_token.py \
    --slug <tenant-slug> --label "<caller>" [--kind buoy]

# Online backup of every SQLite DB / audit hash-chain verification
docker compose exec octo-core python /app/scripts/backup_databases.py --data-root /var/lib/octo/state --help
docker compose exec octo-core python /app/scripts/verify_audit_chain.py --data-root /var/lib/octo/state

# Datto RMM normalization self-check (no server, no credentials)
docker compose exec octo-core python /app/scripts/verify_datto_ingest.py --dry

# One-off after upgrading to alert presentation: re-derive summary + event_type
# for Datto rows stored before it existed (payloads untouched; idempotent).
# The dashboard feed already reads such rows fine — this is for search/export
# and the triage worker, which read the columns. Dry-run first.
docker compose exec octo-core python /app/scripts/backfill_event_presentation.py --dry-run
docker compose exec octo-core python /app/scripts/backfill_event_presentation.py
```

Schedule backup + audit verification from the host's cron / user-scripts
facility. (Retention is the exception: octo-core runs it itself — next
section.)

### Retention, telemetry tiering and the cold archive (migration 036)

**What changed.** Every ingested event is now filed as a **signal**
(`clients/<slug>/events.db`, the `events` retention — a year) or as
**telemetry** (`clients/<slug>/telemetry.db`): answered Pi-hole lookups and
Suricata DNS / TLS / HTTP / flow metadata. Blocked lookups, every alert,
honeypot hits and anything unrecognised stay signals. telemetry.db keeps raw
rows 7 days (`telemetry_raw`), hourly counts per domain and device 180 days
(`telemetry_rollup`) and a first-seen-domain ledger; new tenants get it at
creation, existing ones on their first telemetry write. The dashboard's **DNS summary** widget reads
it (domains masked; full values via the step-up `POST /api/v1/search/dns`,
which also answers "who looked this name up?" given a `domain` — hourly
sightings per device for 180 days, raw lookups for 7). **The events search
does not cover answered DNS any more** — only blocked lookups (signals).

**Retention is enforced** — nightly, inside octo-core, when
`OCTO_RETENTION_SCHEDULE=1` (the template ships it **"0"**: switch it on as
the LAST step of the upgrade order below; hour = `OCTO_RETENTION_HOUR_UTC`,
default 9). Per tenant and class it deletes what
has expired (never below a class's legal baseline; a tenant's own
`retention_days` can only lengthen `events`), writes a
`retention_enforce` audit row for each tenant that has something to delete
BEFORE deleting it, and ONE `retention_run` row per run after (what was
actually deleted, held or blocked, per tenant — quiet tenants listed by
name; a quiet night is one row), never touches the audit chain's existing
rows, and records the run for Settings → System.

**Age = arrival.** A row's age is measured from when Athena RECEIVED it (its
`ingested_at`), never from the vendor's timestamp — which stays stored and
shown: history a vendor hands over late (a months-old incident RocketCyber
lists today) is kept a full retention period from its arrival. Rows stored
before 036 have no arrival time; the one-off move (see "Upgrade order")
stamps them with the best estimate there is: their stored `received_at`,
but never earlier than the arrival of a row stored before them (ids are in
arrival order — late history stored between live rows gets about their
arrival, not its old vendor time), never earlier than the tenant's
onboarding (`clients.onboarded_at` — a tenant whose FIRST rows were old
alerts listed oldest-first keeps them a full period from its onboarding)
and never later than the move. After a
downgrade and re-upgrade (036 rolled back and applied again) each row gets
back the arrival the rollback kept for it; the rollback also keeps, and the
re-upgrade restores, a changed telemetry retention and the pollers' state.
Until it has run for a tenant, that tenant's signals and telemetry are not
pruned at all (the run reports `partial` and names the tenant). An event
a ticket, agent note, pattern link or incident cites is **held** as
evidence (reported, never deleted while cited). A registry it cannot read
fails the run — it never falls back to default retentions. A bundle that has
never run it waits for the scheduled hour after a start (dry-run first); a
host that missed a night catches up 5 minutes after start (the one-off
move's run does not count as a retention run here). **Clock check:** a
scheduled run whose clock is more than 3 days after the last retention run
on record — or, with none on record, more than a day after the newest
arrival of any row — refuses and does nothing (a host clock stepped forward
would move every cutoff with it and delete everything in one night); it is
logged as an error and shown on Settings → System. After a deliberate
pause, catch up by hand (dry run first). Changing a retention in Settings →
System needs re-authentication (step-up): the nightly job enforces it. The
script runs the same job by hand (a deleting run needs `--reason`, recorded
with the OS user and host in the audit; it is not clock-checked); a run
that finds another in progress does nothing:

```bash
docker compose exec octo-core python /app/scripts/enforce_retention.py --dry-run
docker compose exec octo-core python /app/scripts/enforce_retention.py --reason "<why>"
```

The nightly run also **sweeps** answered lookups that ingest had to store in
events.db (the telemetry store refused the write — Settings → System and the
DNS summary widget show it) into telemetry.db. It resumes from the last
sweep that completed, so an outage of any length is caught up by the first
good night — no manual step.

**Cold archive (optional, recommended).** With `OCTO_ARCHIVE_ROOT` set, raw
telemetry is appended to one gzip JSONL file per tenant per UTC day
(`telemetry/<slug>/<YYYY>/<slug>-telemetry-<day>.jsonl.gz` + a `.sha256`
sidecar + `manifest.json`) BEFORE it is pruned; a failed write — or a
configured root that is missing / not writable (an unmounted share) — keeps
those rows in place. Unset = pruned without a copy, and every run's output
and audit rows say so. Athena never deletes from the archive. It holds
UNMASKED DNS history with device names for every tenant: Athena creates its
folders 0700 and files 0600 whatever the umask, and warns (Settings →
System, the scripts) when the root itself is open to other users.

Mount it from **bulk array storage, not the SSD cache** that holds the state
dir: the archive grows by a few MB per tenant per day, is written once a
night, and is exactly the data you keep for its long tail. On a NAS / array
host that means a dedicated share that never uses the cache pool (so nothing
moves it onto the cache), not exported over the network, owned by uid 1000:

```bash
A=<archive share path>/telemetry-archive   # the array-backed share's path on the host
mkdir -p "$A" && chown 1000:1000 "$A" && chmod 700 "$A"
# docker-compose.yml, octo-core:
#   environment:  OCTO_ARCHIVE_ROOT: /var/lib/octo/archive
#   volumes:      - <A>:/var/lib/octo/archive
docker compose up -d octo-core
```

Read a day back for forensics — into a NEW scratch file, never the live
store (checksums verified first):

```bash
docker compose exec octo-core python /app/scripts/restore_telemetry_archive.py \
    --tenant <slug> --day 2026-09-20 --out /tmp/<slug>-dns-0920.db
```

**Archive encryption.** File modes are
the only protection of a plaintext archive on an unencrypted array share.
With encryption on, every NEW archive file is encrypted with
[age](https://age-encryption.org/v1) (X25519) to the operator's PUBLIC
key(s), after compression: one part per tenant per day per run,
`<slug>-telemetry-<day>.p001.jsonl.gz.age` (+ a `.sha256` sidecar over the
ciphertext). Key custody is the operator's (decision of 2026-09-29): the
private key lives in the operator's vault, **never on the bundle host** —
Athena gets the public key only, so it can write the archive but never read
an encrypted file back. (It dedupes later runs from a plaintext row-id
ledger per day, `<day>.ids` — row ids only, no payload.) **Losing every copy
of the private key loses the encrypted archive** — keep an escrow key (a
second recipient) or an escrowed copy. An Athena-managed key with a recovery
kit is a later first-run-wizard option, not built.

`OCTO_ARCHIVE_ENCRYPTION`: `required` | `off` — **set it explicitly** (step 3
below). Unset = `required` as soon as the recipients file exists (or
`OCTO_ARCHIVE_RECIPIENTS_PATH` is set) or the archive already holds
encrypted files (Athena writes `telemetry/.archive-encrypted` before its
first one), else `off` — so once the archive is encrypted, a recipients file
that goes missing (moved aside in a key rotation, a secrets dir restored
without it) fails it closed, never back to plaintext; plaintext again only
by `OCTO_ARCHIVE_ENCRYPTION: "off"`. `required` with a missing / invalid recipients file = the archive is
**UNUSABLE**: nothing is archived and raw telemetry is NOT pruned (exactly
like an unmounted share) — Settings → System, `enforce_retention.py
--dry-run` and the move script's dry run say why. `off` = plaintext as
before, and every run says "archive NOT encrypted". The recipients file
(`/var/lib/octo/secrets/archive-recipients.txt`, i.e.
`$BUNDLE_SECRETS_DIR/archive-recipients.txt`) holds `age1…` lines, `#`
comments allowed (the `age -R` format); it is refused when group- or
world-writable, and refused outright — with a message to treat the key as
exposed — when it holds a private key (`AGE-SECRET-KEY-…`) anywhere.

Turn it on:

```bash
# 1. ON THE OPERATOR'S MACHINE — never on the bundle host. age ≥ 1.1.
age-keygen -o archive-identity.txt      # prints "Public key: age1…"
#    The identity file (AGE-SECRET-KEY-1…) goes straight into the operator's
#    vault; delete the local copy once the vault round-trip is checked.
#    Optional escrow recipient: a second key pair, its private key escrowed
#    separately.
# 2. ON THE BUNDLE HOST — public key(s) only, owner-only:
S=<BUNDLE_SECRETS_DIR>
printf '# operator (vault)\nage1…\n# escrow\nage1…\n' > "$S/archive-recipients.txt"
chown 1000:1000 "$S/archive-recipients.txt" && chmod 600 "$S/archive-recipients.txt"
# 3. docker-compose.yml, octo-core environment:
#      OCTO_ARCHIVE_ENCRYPTION: "required"
docker compose up -d octo-core
# 4. Check: Settings → System → cold archive · encryption must say
#    "required — new files encrypted (age X25519) to N recipient(s): age1…"
#    with the short form / fingerprint of YOUR public key (never "UNUSABLE").
#    The same from the shell:
docker compose exec octo-core python /app/scripts/enforce_retention.py --dry-run | grep archive:
```

Restore an encrypted day (a day split over a plaintext file and encrypted
parts loads as one day). The decrypted scratch DB is unmasked DNS with
device names — **as sensitive as the plaintext archive** — so neither it
nor the identity ever touches the array, the cache or app data (an unlink
there is not a secure erase): both go on tmpfs (`/dev/shm`, RAM — `df -h
/dev/shm` first for a long range), the identity owner uid 1000, 0600 (a
file group or others can read is refused; key material is never printed).
The identity is removed as soon as the restore has run, the scratch DB as
soon as the analysis is done:

```bash
install -m 600 -o 1000 -g 1000 <identity from the vault> /dev/shm/archive-identity.txt
R=/dev/shm/<slug>-restore
mkdir -m 700 "$R" && chown 1000:1000 "$R"
docker compose run --rm --no-deps \
    -v /dev/shm/archive-identity.txt:/run/archive-identity.txt:ro \
    -v "$R":/restore \
    octo-core python /app/scripts/restore_telemetry_archive.py \
    --tenant <slug> --day 2026-10-08 --out /restore/<slug>-dns-1008.db \
    --identity /run/archive-identity.txt
rm /dev/shm/archive-identity.txt          # the private key off the host — now
# ... query "$R/<slug>-dns-1008.db" (or copy it to the analyst's machine) ...
rm -rf "$R"                               # the decrypted copy, when done
```

Or entirely off the host (the private key never comes onto it at all): copy
the `.age` files to the operator's machine and `age -d -i
archive-identity.txt <file>.jsonl.gz.age | gunzip` (standard age — no Athena
needed).

Convert the plaintext archive written before encryption was switched on — four
runs, in this order, each one checked before the next (nothing is deleted
until a decrypt round-trip with the operator's key has been recorded). The
identity is on the host for the `--verify` run only — removed right after
it, before anything else:

```bash
docker compose exec octo-core python /app/scripts/encrypt_archive.py              # dry run
docker compose exec octo-core python /app/scripts/encrypt_archive.py --apply      # <day>.jsonl.gz.age beside each plaintext; plaintext KEPT
install -m 600 -o 1000 -g 1000 <identity from the vault> /dev/shm/archive-identity.txt
docker compose run --rm --no-deps -v /dev/shm/archive-identity.txt:/run/archive-identity.txt:ro \
    octo-core python /app/scripts/encrypt_archive.py --verify --identity /run/archive-identity.txt
rm /dev/shm/archive-identity.txt          # the private key off the host — now
docker compose exec octo-core python /app/scripts/encrypt_archive.py --delete-plaintext
```

`--delete-plaintext` unlinks only a plaintext whose encrypted copy has a
verify record matching both files as they are NOW (a plaintext that grew
since — encryption was off for a night — is kept until `--apply` and
`--verify` run again). It also removes the temp files interrupted writes
left (`.<file>.tmp-<hex>` — a plaintext append killed mid-write, e.g. by a
container recreate, leaves a full plaintext copy of the day there; its rows
were never counted as archived, so they are in the archive or still in
telemetry.db). The dry run lists them, and Settings → System counts them
with the plaintext files. It is an unlink, **not a secure erase**: on a NAS /
array host's parity array, a copy-on-write filesystem, a snapshot or a backup
the old plaintext may persist — treat those copies as plaintext until they age
out. Each writing step takes the retention run lock (a nightly run in progress
= exit 3, try again).

**Upgrade order** (existing bundle) — in this order; the schedule is
switched on LAST:

0. Take a backup — the move in step 4 deletes rows from events.db once
   they are copied. Use the NEW image's `backup_databases.py`: the v0.10
   script (the running container's, and the nightly job's until the
   upgrade) leaves out every tenant's `tickets.db`, so a restore of it
   loses all tickets, ticket notes and Autotask push state. With the new
   tag already in `docker-compose.yml` but BEFORE `up -d`, run it in a
   one-off container (read-only on the data; nothing migrates):
   `docker compose run --rm --no-deps octo-core python /app/scripts/backup_databases.py --data-root /var/lib/octo/state`
   (plus the `--backups-root` / `--remote-dest` your nightly job uses) —
   or copy `clients/*/tickets.db` yourself (`sqlite3 <db> ".backup <copy>"`).
   Every backup taken before the upgrade lacks tickets.db: remember that
   before restoring one.
1. Archive mount — if raw DNS history is to be kept (recommended): create
   the array share and add the archive volume + `OCTO_ARCHIVE_ROOT` to the
   rendered `docker-compose.yml` (above). Leave `OCTO_RETENTION_SCHEDULE`
   at `"0"`. On an image with archive encryption, set it up now too
   ("Archive encryption" above: key pair off the host, the public key in
   the recipients file, `OCTO_ARCHIVE_ENCRYPTION: "required"`), so the
   move's first archive files are already encrypted.
2. Deploy the image (`docker compose up -d octo-core`). Migration 036
   applies to the registry at start; from then on buoy telemetry goes to
   telemetry.db and every new row carries its arrival time. Nothing is
   pruned yet. Until step 4 the DNS summary widget shows, per buoy tenant,
   "N answered lookups from before the upgrade still in the events store"
   — expected, not a fault (a real telemetry-store fault says "Telemetry
   store fault"; Settings → System says "writes accepted").
3. Move dry run — the telemetry stored before 036, out of events.db:
   `docker compose exec octo-core python /app/scripts/move_telemetry_out_of_events.py --dry-run`
   — it prints what would move, the disk it needs (telemetry.db grows by
   about three times the moved payload — raw rows, indexes, roll-ups —
   before the prune shrinks it) against the free space there, how many
   rows it would stamp with an arrival estimate, and how many raw rows
   older than 7 days the prune would then delete, **archived** or
   **WITHOUT a copy**.
4. Move (the backfill): the same without `--dry-run` (idempotent, resumable,
   short transactions — safe with ingest running; it holds the retention run
   lock). Per tenant it then stamps what is left in events.db (signals)
   with its arrival estimate (above) and builds the arrival index
   — one scan of what is left, a few seconds on SSD, during which signal
   writes to that file wait. It refuses when the free space is under twice its estimate, and —
   with the archive disabled and old rows to prune — until you pass
   `--prune-without-archive` (accepting the loss) or set the archive first.
   **After this step the console's events search no longer finds answered
   DNS lookups** (only blocked ones — signals). "Who looked this name up?"
   has no console page in v0.11: it is the API `POST /api/v1/search/dns`
   (re-authentication; raw lookups 7 days, hourly sightings 180 days).
5. `enforce_retention.py --dry-run` — read what the first nightly run will
   do. No tenant may say "arrival backfill pending" (re-run step 4 for it).
6. THEN switch the schedule on: `OCTO_RETENTION_SCHEDULE: "1"` in
   `docker-compose.yml`, `docker compose up -d octo-core`. The first run is
   at the scheduled hour (the move's run is not counted as a retention
   run, so there is no catch-up run minutes after `up -d`). (Had it been on
   early, the nightly run would still refuse to prune any tenant whose
   backfill has not run — it reports `partial` and names the tenant.)

A NEW bundle (no data from before 036) needs only steps 1, 5 and 6.

**Buoys (separate from the bundle deploy — v0.11 does not touch them).**
Two buoy-side fixes only take effect once redeployed to each buoy:
  * the buoy forwarder (`apps/octo/buoy/forwarder/`): Pi-hole status labels
    follow FTL's documented codes (T6) — Athena's own classification never
    depended on them;
  * the heartbeat daemon (`apps/octo/buoy/heartbeat.py` + `services.py`):
    reports each watched unit's `is-enabled` state (B1). Until it is
    redeployed a buoy sends no enablement, the old verdict stands (a
    stopped unit is degraded) and the fleet does NOT turn green for the
    retired octo-forwarder. After it, a unit shows grey "retired" only if
    it is disabled AND on the bundle's `OCTO_BUOY_RETIRED_UNITS` list
    (default `octo-forwarder`); any other disabled unit is a fault. Keep
    each buoy's `SERVICES` override while it runs the parallel-run unit
    names (`buoy-forwarder-${BUNDLE_NAME}`, where `BUNDLE_NAME` is the
    deployment's name suffix, default `bundle`; the legacy `buoy-forwarder`
    stopped and disabled): the
    template default watches `buoy-forwarder`, so without the override
    the real forwarder would not be watched and the legacy unit would
    show as disabled (a fault).

7. Optional, per tenant, with **octo-core stopped**: `--convert-vacuum`
   returns the space the move freed in events.db to the disk. It is one full
   VACUUM per file: the file's write lock is held for the whole rewrite, so
   with the app up every signal write to it fails after its 10 s busy
   timeout and a poller moves its cursor past what it could not store —
   never run it with octo-core up. It needs free space of about **twice**
   the file in the tenant directory (the temp copy is written there, not
   into the container layer or the Docker image store):

   ```bash
   docker compose stop octo-core
   docker compose run --rm octo-core python /app/scripts/enforce_retention.py --convert-vacuum --slug <slug>
   docker compose up -d octo-core
   ```

   Pollers catch up from their cursors on start; buoys retry what they
   queued. Without it events.db stops growing but does not shrink. Tenants
   created from 036 on need none of this.

Backups (`backup_databases.py`) now include every tenant's telemetry.db —
and tickets.db, which earlier runs had silently left out.

**Restore** (a backup is not a backup until it has been restored — do this once
on every new install). Always into an EMPTY directory, then swap:

```bash
docker compose run --rm -v <backups-dir>:/backup:ro -v <empty-dir>:/restore octo-core \
    python /app/scripts/restore_databases.py \
    --backup-run /backup/<timestamp> --data-root /restore
```

The data root holds `registry.db`, `global/{audit,patterns,quarantine}.db` and
`clients/<slug>/{events,indicators,audit,tickets,telemetry,entities}.db`. `global/quarantine.db` appears the first time an
integration event cannot be attributed to a tenant (it is HELD there for
review under Settings → Tenants, never dropped); its schema is the
`@target: quarantine` section of the migrations and is applied on first use.
The backup script picks it up like the other global DBs.

Database backups deliberately exclude `$BUNDLE_SECRETS_DIR`; restore the keys
from your escrow copy. Without the original `mfa-key.env` every operator
re-enrols 2FA (`--reset-factory-admin` gets the first admin back in). Without
the original `entity-hmac.env` (v0.13) every token stored in the clients'
`entities.db` (device handles in stored answers, ranking history) stops
matching: answers are still read, new ones start a fresh history.
`archive-recipients.txt` holds public keys only: recreate it from the public
key in the operator's vault (with `OCTO_ARCHIVE_ENCRYPTION=required` — or
unset, once the archive holds encrypted files — and the file missing,
nothing is archived or pruned until it is back).

### v0.12 — NextDNS (migration 037)

**Upgrade** (existing v0.11 bundle):

0. Back up first (`backup_databases.py`, as above).
1. Deploy the new image and console (`docker compose up -d octo-core` with
   the new tag). Migration 037 applies to the registry at start; each
   tenant's `telemetry.db` gets the two NextDNS tables lazily, the first
   time anything is written there. Nothing else changes: **no new
   environment variable, no compose change**, octo-core already has egress
   (it needs `api.nextdns.io:443`), and the whole `/api/v1` is already
   proxied.
2. Settings → Integrations → Add NextDNS: paste the account API key, Test
   connection (ONE call), then map profiles to clients (or Ignore them).
   Nothing is polled until you save a mapping.
3. Expect, right after saving: a first pass of a few minutes (about 2 s per
   NextDNS call: each profile's 24-hour read — and a 7-day read for one
   with none — then its security check, and ONE read of each active
   profile's last 3 weeks of hourly history — at most once a day per
   profile, also when you unmap and re-map it), then a burst of back-filled
   alerts — the last 24 hours of SECURITY blocks of every active profile,
   coalesced (high: per device, domain and reason per hour; medium / low:
   per device and reason per day). Athena judges every site against its
   own week from the first day (that history): a site lapses only when it
   is silent while it normally has traffic — nights, weekends and closed
   days it is always silent in never count. Sites already dark when mapped
   (0 queries in 24 h, ≥ 100 in 7 days, at a time they normally have
   queries) raise one "stopped reporting" each; mapping a weekend-closed
   office on a Sunday raises nothing. If NextDNS does not give a profile's
   history (asked again a day later), that profile learns its week
   locally: for its first 7 days it is only lapsed after a WHOLE day
   without queries. Whatever a site's week, 7 days without a single
   query always lapse it. A site whose clients stop using NextDNS while its
   gateway still does is NOT caught by this integration (planned: the
   UniFi / Fleet v2 cross-check).
4. Optional but recommended: set your own tenant's kind to **internal**
   (Settings → Tenants). A fleet-wide outage (half the sites dark at once)
   raises ONE high alert there; without an internal tenant the card and
   source health still say so, but no alert is stored for it.
5. What the card says when NextDNS itself is the problem: "NextDNS
   unreachable since <time>" (red) once no call has succeeded for 20
   minutes (2 poll intervals) — it clears on the next answer; a profile
   NextDNS keeps refusing while still listing it is named on its own row
   ("NextDNS refuses this profile …" / "… this profile's hourly analytics
   — check sharing/permissions"), never as the whole key rate limited.

**Rollback** to v0.11 after onboarding: the `adapter_instances` row for
NextDNS and its tenant-map rows stay in the registry, and v0.11 does not
know the vendor — it marks the instance `error` ("not registered"), shows a
NextDNS source as **down** and every tenant a NextDNS profile maps to as
**degraded** until you re-upgrade. Either accept that (red NextDNS source,
degraded tenants) for the rollback's duration, or disable the integration
first — knowing that disabling does NOT carry the profile mappings and
ignores over to a re-added instance (all profiles must be decided again).
`037-rollback.sql` is optional: v0.11 never reads the NextDNS tables, and
there is no script to apply its telemetry section to every tenant's
`telemetry.db` (tables left in place are harmless). A re-upgrade resumes
from the persisted marks, so it back-fills the WHOLE rollback period's
security blocks (not just 24 h) — expect that burst.

### v0.13 — UniFi connector + entity resolution (migrations 038–040)

**Upgrade** (existing v0.12 bundle):

0. Back up first (`backup_databases.py`, as above) and keep the backup: 038
   rebuilds the operator-notice table, 040 adds the per-client
   `entities.db` (backed up and restored with the other client files from
   now on).
1. Compose (`docker-compose.yml`, octo-core `environment:`), from the
   template:
   * `OCTO_ENTITY_HMAC_PATH: /var/lib/octo/secrets/entity-hmac.env` — the
     entity token key, on the SECRETS mount (never the state volume a backup
     copies). Run the bootstrap once after the deploy
     (`docker compose run --rm octo-core python -m apps.octo.bundle_bootstrap
     --skip-factory-admin`) to create it, then ESCROW it with `mfa-key.env`
     and the credentials key.
   * `OCTO_NEXTDNS_RESOLVER_NETS` (optional): NextDNS's own resolver ranges,
     comma-separated CIDRs, copied from NextDNS's published anycast list. Only
     with it set does a UniFi network whose DHCP hands out a public resolver
     that is NOT NextDNS (a guest VLAN on the ISP's DNS) drop out of a
     NextDNS alert's device list; unset, no network is ever classed as
     bypassing NextDNS (longer lists, never a wrong "no device").
2. Egress: octo-core needs `api.ui.com:443` (the UniFi Site Manager API and
   its connector).
3. Deploy the new image and console. 038–040 apply to the registry at start;
   every client's `entities.db` is created at provisioning (an empty file is
   ~280 KB; existing clients get theirs at first use) — empty and unread
   while the client's switch is off. After start, an admin gets ONE `mapping_review` notice
   listing the tenant mappings an earlier version made from a name match
   (Settings → Integrations → each card's Tenant mapping: confirm or re-map);
   the integrations' own auto-created tenants are not on it.
4. The legacy UniFi instance (a local controller URL) is refused at start
   with what to do: Disable it, Add UniFi with a Site Manager API key,
   map the sites one by one (location shown; Ignore personal consoles). Its
   old bare-site-id mappings are listed as retired and never polled. A key
   rotation later is the same path: the clients' sites, links and history
   carry over to the new instance (the Athena site belongs to the UniFi
   site, never to the instance).
5. Expect, after mapping: a first back-fill of each mapped site's last 24
   hours of system log (IPS / rogue AP / admin / WAN alerts, coalesced per
   hour), ONE system-log call per mapped site per 5 minutes after that, and —
   only for clients switched to shadow / on — one client-list call per site
   per 5 minutes and one networks read per site per day. UniFi IPS alerts
   name the LAN device by its address (the live event carries no client
   name; entity resolution names it) and the threat from the event's text.
6. Entity resolution is OFF for every client until an admin switches it
   (Settings → Tenants → Links to review: off / shadow / on, with a reason,
   audited). Recommended: a week of SHADOW per UniFi-mapped client, then on.
   Switching a client on reads its NextDNS profiles' last 14 days once (one
   analytics call per profile and day, spread over cycles) so a PC whose
   NextDNS app is ALREADY dead is watched — its "stopped reporting" alert
   comes once Datto has shown it online for 4 read hours. The switch starts
   the alert sweep at the client's NEWEST alert (older alerts have no lookups
   behind them); `OCTO_ENTITY_SWEEP_HISTORY_DAYS=N` (0–30, default 0) starts
   it N days back instead. The worker writes a run row + a global audit row
   only when a pass changed something (plus one heartbeat an hour): expect
   well under 1 MB of global audit a day for a few dozen clients. A profile whose
   traffic legitimately comes from elsewhere (a branch office without UniFi,
   roaming laptops) raises one routing Conflicts card: "Accept as expected"
   (with a reason, optionally until a date) stops the check for that
   profile; "Mark resolved" sticks until the evidence materially changes.
7. Retention of entity data (leases 90 days, guest networks 7, answers 365
   with candidate lists cut to a count when their leases go) runs ONLY in the
   nightly retention job — `OCTO_RETENTION_SCHEDULE` is `0` on a bundle that
   has not done the 036 sequence. Until it is `1`, device-name leases and
   candidate lists of clients in shadow / on are kept indefinitely: switch a
   client to shadow only once the retention schedule is on, or accept that.

**Rollback** to v0.12. FAST (no data loss): the v0.12 image on the 040
schema (v0.12 ignores entities.db and the 039 telemetry tables). SQL
(optional, bundle stopped, fresh backup): roll back 040, then 039, then 038
(newest first; `040-rollback.sql` keeps every client's switch, the
known-benign rules and the entity-review notices for a re-upgrade;
`entities.db` files are LEFT in place — v0.12 never reads them) — one
command, from the v0.13 image, dry run first:

```bash
docker compose run --rm octo-core python /app/scripts/rollback_v013.py           # plan
docker compose run --rm octo-core python /app/scripts/rollback_v013.py --apply   # do it
```
 v0.12's UniFi adapter requires a controller URL:
the cloud-key UniFi instance is refused at start (the UniFi source shows
**down**, its mapped tenants **degraded**) until you re-upgrade. Disabling it
before the rollback avoids that but loses its site mappings and ignores (a
re-added instance starts with nothing mapped — every site must be decided
again). The token key stays on the secrets mount; keep it for the
re-upgrade.

### v0.14 — Fleet v2: site-centric fleet + ISP-outage correlation (migration 041)

**Upgrade** (existing v0.13 bundle):

0. Back up first (`backup_databases.py`) and keep the backup: 041 adds one
   registry table (`tenant_locations`, the manual map locations).
1. Compose: nothing required. Optional (template, commented, defaults
   shown): `OCTO_FLEET_ISP_OUTAGE_MIN_SITES` (3; 2..50) and
   `OCTO_FLEET_ISP_OUTAGE_WINDOW_MIN` (10; 5..60) — how many sites of ONE ISP
   (ASN) losing their internet within the window make one ISP-outage
   incident (counted by failure point: one multi-site console, or one shared
   WAN address, counts once); `OCTO_FLEET_CACHE_SEC` (30) and `OCTO_FLEET_BUILD_BUDGET_SEC` (5)
   for the Fleet page. No new egress: the Fleet never calls a vendor on a
   page load, and the correlation reads the UniFi fleet poll that already
   runs (two calls every 5 minutes).
2. Deploy the new image and console. 041 applies to the registry at start.
3. The ISP-outage incident is written into the operator's INTERNAL tenant
   (the oldest active tenant of kind `internal`). Without one it is shown on
   the Fleet tab and never written: check Settings → Tenants has the MSP's
   own tenant with kind *internal* before relying on it.
4. Expect on the Fleet tab: one pin per UniFi site MAPPED to a client (an
   unmapped, non-ignored site is only counted: map or ignore it under
   Integrations → UniFi), one entry per client without UniFi that has another
   source. Right after a start the layers read **unknown** until each feed
   has polled once (UniFi fleet ~at start, RocketCyber within 5 minutes,
   NextDNS per its interval) — stale data is never shown as ok. Endpoints
   (Datto inventory) appear only for clients with entity resolution in
   shadow / on (the inventory is not read otherwise — until v0.17.2, which
   reads it for every Datto-mapped client). Client users (viewers)
   see their own sites as a list, with no location, no map, no buoys mode
   and no vendor names. Freshness follows each instance's own interval
   (RocketCyber `poll_interval_sec`, Datto `inventory_interval_sec`, NextDNS
   its effective security round — pending profiles by their status check).
5. A client without a UniFi console location — or whose sites sit on a
   console that carries several sites (a hosted / multi-site controller
   reports the CONSOLE's place, not each site's): Settings → Tenants →
   **Location…** (admin+, with a reason, audited). Never derived from an IP.

**Rollback** to v0.13. FAST (no data loss): the v0.13 image on the 041
schema (v0.13 never reads `tenant_locations`; the `isp_outage` poller-state
row is ignored; stored `fleet.isp_outage` alerts read as UniFi events). SQL
(optional, bundle stopped, fresh backup) — 041 only, from the v0.14 image,
dry run first; it keeps every manual location for a re-upgrade:

```bash
docker compose run --rm octo-core python /app/scripts/rollback_v014.py           # plan
docker compose run --rm octo-core python /app/scripts/rollback_v014.py --apply   # do it
```

To go back to v0.12 as well, run `rollback_v013.py` AFTER it (it refuses a
registry still at 41).

### v0.17.2 — acknowledge / expected, alert enrichment, Datto devices for every client (migration 046)

**Order:** 046 must be applied AFTER v0.17.1's 045 (a file at 46 never
applies a 45 section). Deploy v0.17.1 first, or merge both before deploying.

**Upgrade** (existing v0.17 / v0.17.1 bundle):

0. Back up first (`backup_databases.py`). 046 adds three registry tables
   (`alert_verdict`, `expected_condition`, `enrichment_cache`), one column to
   each tenant's telemetry.db (`unifi_signal_buckets.remotes`, applied lazily
   on the next UniFi write) and one to each entities.db (`inv_device.ext_ip`).
1. Compose: nothing required. NEW EGRESS (on by default): remote-IP
   enrichment — DNS-over-HTTPS to `1.1.1.1` / `8.8.8.8` BY IP (port 443),
   RDAP over HTTPS to `data.iana.org` and the five RIRs' RDAP servers
   (resolved over that DoH, never the local resolver; the remote address
   itself is never contacted), ≤ 20 lookups a minute, cached 7 days.
   `OCTO_IP_ENRICHMENT=off` turns it off (cached answers still show).
2. The Datto device list is now read for EVERY Datto-mapped client (one
   devices call per site per 30 minutes, paginated; the inventory interval's
   floor is 30 minutes) — the Fleet's Endpoints layer shows counts for all of
   them. Identity linking still needs the client's entity switch in shadow /
   on. UDFs are never read (allowlisted fields only).
3. Expect: the drawer's list is "needs attention" (acknowledged / expected
   alerts behind "show acknowledged"); Settings → Threats lists the expected
   conditions; the admins get one notice 7 days before each review date.
   The counts shown (to client users too) stay every hit — an ack or an
   expected condition changes the site's colour and reasons, not the
   numbers. A RocketCyber incident names no device: it is acknowledged one
   incident at a time (never "expected", never "repeats for 24 h").

**Rollback** to v0.17. FAST (no data loss): the v0.17 image on the 046
schema (it never reads the new tables; the two new columns are nullable and
named in none of its statements — every alert counts towards Yellow again,
and Datto devices of switched-off clients are kept but unread). SQL
(optional, bundle stopped, fresh backup), from the v0.17.2 image, dry run
first; it keeps the column values aside for a re-upgrade:

```bash
docker compose run --rm octo-core python /app/scripts/rollback_v0172.py           # plan
docker compose run --rm octo-core python /app/scripts/rollback_v0172.py --apply   # do it
```

Then `rollback_v017.py` to go further back (it refuses a registry at 46).

### v0.17.3 — Datto serial numbers, RocketCyber acknowledge-only, DNOC keys by service (migration 047)

**Upgrade** (existing v0.17.2 bundle):

0. Back up first (`backup_databases.py`). 047 adds four nullable columns to
   each tenant's entities.db (`inv_device.serial`, `manufacturer`, `model`,
   `audit_at` — applied lazily, at the client's next inventory write) and
   moves the registry to 47 (nothing else there).
1. **Before deploying**, check for acknowledgements / expected conditions on
   Datto NOC SERVICE or DISK alerts — their signature changes (keyed by the
   affected services / the drive now), so such rows stop matching:

   ```bash
   docker compose exec octo-core python -c "import sqlite3; \
   c = sqlite3.connect('file:/var/lib/octo/state/registry.db?mode=ro', uri=True); \
   k = \"signature_key LIKE 'datto:eventlog_ctx|%|dnoc%'\"; \
   print(c.execute('SELECT COUNT(*) FROM alert_verdict WHERE ' + k).fetchone()[0], \
         c.execute('SELECT COUNT(*) FROM expected_condition WHERE revoked_at IS NULL AND ' + k).fetchone()[0])"
   ```

   Non-zero: tell the bundle owner before the deploy — those alerts come back
   to "needs attention" and need re-marking (memory / CPU NOC keys do not
   change).
2. Compose: nothing. Egress: nothing new (the same Datto API host). NEW
   DATTO CALL (read-only): `GET /api/v2/audit/device/{deviceUid}` from the
   INVENTORY poller, after its device lists — at most 40 a round (rounds are
   30 minutes), only for listed, non-missing devices (not ESXi hosts,
   printers, network devices) whose audit was never read or is older than 7
   days. Only the BIOS / base-board serial, the manufacturer and the model
   are kept (dropped at the client: user names, interfaces / MACs /
   addresses, UDFs, URLs, software). A 429 on an audit holds the inventory
   exactly like a 429 on a device list; the alerts poller is never held.
3. **Verify the first live round** (the audit's live shape was not probed
   when this was built): within 30 minutes of the start,

   ```bash
   docker compose logs octo-core | grep "datto-inventory\] audits read"
   ```

   should read e.g. `audits read 40 · serials found 37 · failed 0`. `read 0 ·
   failed N` on every round = Datto refuses the call (the API user's level)
   or answers another shape — a shape this build does not read also logs
   `N audits answered in a shape this build does not read` (those devices
   are NOT stamped: they are asked again next round, so a fixed build reads
   them at once). `serials found 0` on every round while `read` is > 0 =
   the fields are there but empty — also worth a look. Either way the alert
   drawer just shows no serial; tell the developer. The lines never carry a
   serial, model or uid.
4. Expect: a Datto alert's device line in the drawer (operators only) reads
   "<manufacturer> <model> · SN <serial> · site … · LAN … · WAN …"; the
   shared-hostname warning names the other devices' serials. At 40 audits a
   30-minute round it fills in about 80 devices an hour (a fleet of N
   devices takes about N / 80 hours). A RocketCyber alert offers Acknowledge
   only — never "this is expected", never "repeats for 24 h", whatever host
   it names. A Datto NOC service alert's "expected" covers exactly that set
   of services on that device (every service name the report gives, digits
   kept — two BeyondTrust Jump Clients or MSSQL$PROD1 / $PROD2 are two
   services; a report naming fewer services than it says are affected is
   keyed by a digest of its names and shape).

**Rollback** to v0.17.2. FAST (no data loss): the v0.17.2 image on the 047
schema (it never names the four columns; DNOC keys revert to code + source +
log, so v0.17.3-made acks on DNOC service / disk alerts stop matching and
v0.17.2's match again). SQL (optional, bundle stopped, fresh backup), from
the v0.17.3 image, dry run first; it keeps the four columns' values aside for
a re-upgrade:

```bash
docker compose run --rm octo-core python /app/scripts/rollback_v0173.py           # plan
docker compose run --rm octo-core python /app/scripts/rollback_v0173.py --apply   # do it
```

Then `rollback_v0172.py` to go further back (it refuses a registry at 47).

### v0.17.5 — recall an acknowledgement, notes under it (migration 048)

**Upgrade** (existing v0.17.4 bundle):

0. Back up first (`backup_databases.py`). 048 adds ONE registry table,
   `alert_verdict_followup` (append-only: notes and recalls on
   acknowledgements; the ack rows themselves are never touched), registry →
   48. No tenant file changes.
1. Compose: nothing. Egress: nothing new.
2. Expect: in the drawer's "show acknowledged" view an acknowledged alert
   offers **add note** (shown under the ack, newest last; the original note
   stays) and **recall** (a reason of 10+ characters, with a confirmation):
   the alert is back in "needs attention" and counts towards the site's
   colour again — so do the other rows of the same vendor alert and the
   alerts its "repeats for 24 h" covered. A recall is final (acknowledging
   again is a new ack — this row or another row of the same vendor alert —
   and covers it again; no ack made before the recall does). Audit actions:
   `alert.ack_recall`, `alert.ack_note` (written before the row,
   `<action>_failed` if the row is not). 048 also refuses an insert that
   names an existing id (a SQL `REPLACE`) on the follow-ups and on 046's
   `alert_verdict` / `expected_condition` — hand-run SQL included; those
   two triggers stay after a rollback (nothing writes an id).

**Rollback** to v0.17.4. FAST: the v0.17.4 image on the 048 schema — it
never reads the table, so a RECALLED acknowledgement covers its alert again
(quieter) and notes are not shown; a re-upgrade applies every recall again.
The SQL rollback's dry run counts the recalled acks (`recalled_acks`):
non-zero → tell the bundle owner which alerts go quiet on the rolled-back bundle. SQL
(optional, bundle stopped, fresh backup), from the v0.17.5 image, dry run
first; the table is LEFT as it is:

```bash
docker compose run --rm octo-core python /app/scripts/rollback_v0175.py           # plan
docker compose run --rm octo-core python /app/scripts/rollback_v0175.py --apply   # do it
```

Then `rollback_v0173.py` to go further back (it refuses a registry at 48).

After the bundle is up, drop GGUF files into `$BUNDLE_MODELS_DIR`
to make them visible to octo-llm. The in-product model picker
(super_admin Settings → System) reads the same directory (mounted
read-only into octo-core).

## Verifying P4 lockdown

```bash
# Should succeed — octo-llm can reach octo-core
docker compose exec octo-llm python -c \
  "import urllib.request; urllib.request.urlopen('http://octo-core:8001/healthz', timeout=3)"

# Should FAIL — octo-llm has no route off-network
docker compose exec octo-llm python -c \
  "import urllib.request; urllib.request.urlopen('https://example.com', timeout=3)" \
  && echo "ERROR: P4 not enforced" \
  || echo "OK: P4 egress lockdown working"
```

## Restart-button flow

1. super_admin clicks "restart octo-llm" in Settings → System.
2. octo-core's admin endpoint sends SIGTERM to the sibling (or, in
   future, just exits the inference loop via an internal RPC).
3. octo-llm exits non-zero.
4. compose's `restart: unless-stopped` brings the container back.
5. octo-core polls `/v1/healthz` until 200, then re-enables the
   "Ask Octo" UI surface.

No docker socket required.
