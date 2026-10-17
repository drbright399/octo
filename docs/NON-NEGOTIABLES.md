# Non-Negotiables

These are rules that any agent (human or AI) working on Athena/OCTO
must follow. They are not preferences. They are not "guidelines."
They are non-negotiable, because the cost of violating them is data
loss, audit failure, or the compounding kind of bug where nobody can
later figure out what happened.

If a rule below seems wrong for a given situation, **stop, surface
the conflict to a human operator, and wait for explicit authorization
before proceeding** — do not improvise.

---

## Rules

### 1. Leaked credentials are removed and logged, never silently rotated

**Rule:** If a credential or sensitive detail leaks into the public
repository (or any other public surface), the response is:

- Remove the leaked value from the online repository (and from any
  caches / forks where possible).
- Record the event in `docs/leak-events/YYYY-MM-DD-<short-slug>.md`
  with: what leaked, when, who/what introduced it, when it was
  removed, what the canonical live value is now (vault path
  reference only — never the value itself), and any rotation
  decision the operator subsequently made.
- **Do not rotate the credential autonomously.** Surface the leak to
  the operator and let them decide.

**Why:** Reactive rotation without a record creates the worst
failure mode in this project — a credential changes silently and
nobody can find where the new one lives. Auditing a leak requires
the audit trail more than it requires the rotation. The trail is
the work product.

### 2. This is high-security-risk software and is treated as such

**Rule:** Every edit is logged in commit history with a clear
description of *what* and *why*. Every change is tested before
landing. Every change has a rollback plan ready on demand
(branch/tag of pre-change state, or a documented revert path).

**Why:** Athena/OCTO holds tenant security telemetry under HIPAA,
CJIS, BIPA, GLBA, and similar regulatory regimes. A bug here can
create a notifiable incident at a customer organization. Treating
edits casually is not an option.

### 3. Never refactor or delete a repository or codebase

**Rule:** No `git reset --hard` against shared branches. No
"let me start over" rewrites of working code. No `rm -rf` of
directories that contain or reference customer data. No
force-pushes to `main`. No squash-rewrite of historical commits
once they've been pushed.

If existing code is genuinely confusing, the response is to
**read it, ask the operator, document its purpose, and patch
forward** — not to rewrite from scratch.

**Why:** Our job is to protect data. Replacing working code with
a "cleaner" version risks breaking tenant isolation, audit chains,
or invariants whose purpose the rewrite didn't appreciate. Bugs
in working code can be fixed; loss of working code cannot be
undone safely.

### 4. Treat the repository as if ready to be audited or pen-tested at all times

**Rule:** No customer-bearing strings in committed source. No
credentials in any form (even sample/test ones — use placeholders
like `sk-REPLACE_ME`). No commented-out code that hints at past
deployments. No "TODO: clean this up later" comments without an
issue link. The pre-commit hook at `.githooks/pre-commit` is your
first line of defense; do not bypass it.

**Why:** This codebase will be audited and pen-tested. Possibly by
a customer's auditor, possibly by a regulator, possibly by the
team that acquires this work. The bar is "what would a security
vendor's VP of Engineering, on first read of a single file, conclude
about the team behind this?"

### 5. Keep it clean. Explain what you did and why you did it clearly

**Rule:** Code, commits, PRs, and comments are written so a human
or another agent can understand them cold. The *what* is in the
diff. The *why* is in the description, the comment, or the ADR.
Don't leave reasoning in chat history that future readers can't
see.

**Why:** Multiple agents and humans will work on this. Anyone
landing in this repo six months from now has to be able to
understand why a piece of code exists without context from a
conversation that already evaporated.

### 6. Tenant isolation is never crossed

**Rule:** Per-tenant data lives in per-tenant SQLite files
(file-path-level isolation, not `WHERE tenant_id = …` in shared
tables). No code path may open another tenant's DB by string
templating, path composition, or any non-explicit lookup.
Cross-tenant queries (e.g., super_admin pool fetches) require an
explicit, audit-logged path that is reviewable by file inspection.

**Why:** Architectural defense in depth. If a cross-tenant bug
ships, the wrong file simply isn't open — the worst case is "no
results" instead of "leaked across tenants." This invariant only
holds while we never write code that crosses it.

### 7. No bypassing verification gates without explicit operator authorization

**Rule:** Do not use `--no-verify`, `--force`, `--no-gpg-sign`,
`git reset --hard <shared-ref>`, `git push --force-with-lease`
against `main`, etc., unless the operator has authorized the
specific action in plain words. Quote the authorization verbatim
in the commit message body.

**Why:** Verification gates exist because past incidents made
them necessary. An agent that bypasses them without record turns
a known-good repo state into an unknown one, with no trail.

### 8. Server enforces, UI presents

**Rule:** Security and authorization checks live in the backend.
Front-end components render correctly regardless of whether the
data they received should have been allowed in the first place.
The UI never refuses to render based on its own assumption about
authorization — by the time data reached the UI, the backend
already filtered.

**Why:** Defense in depth. UI-level checks are a UX nicety, not
a security boundary. A compromised front-end (or a curious user
opening DevTools) trivially bypasses front-end checks; the
backend is the only enforcement layer that matters.

### 9. New runtime dependencies require justification

**Rule:** Every new `pip install` / `npm install` of a runtime
dependency must include in the PR description: why this dep, why
not write it inline, the maintainer's track record, the supply-
chain risk assessment. Devtool deps (linters, test runners)
get more latitude but still warrant a one-line justification.

**Why:** Each runtime dep is supply-chain surface. The npm
ecosystem in particular has a long history of compromise via
typosquatting, dependency-confusion, and maintainer takeover.
Dependencies are a tax we pay forever; we should pay it
deliberately.

### 10. Test isolation: tests never touch production paths

**Rule:** Tests use `tmp_path`, `:memory:` SQLite, or mock
servers. No test writes to `/var/lib/octo`, makes a network call
to a live OCTO instance, or reads from a real vault file. CI
runs with production credentials explicitly absent from the
environment.

**Why:** A test that accidentally writes to a prod path during
local development corrupts state in subtle ways. A test that
makes live network calls means the test passes only when the
network agrees, defeating the purpose. Tests are the safety net;
they have to be safe.

### 11. Decisions live in artifacts, not chat

**Rule:** When an agent picks an approach over alternatives, the
*why* goes in: code comments (when the why is non-obvious from
the code), commit messages, PR descriptions, or ADRs. Not in
chat history.

**Why:** Future agents and auditors read the repository. They do
not have access to your chat. A decision whose reasoning lives
only in a transcript is a decision that can't be defended six
months later.

### 12. Leak event protocol is documented and predictable

**Rule:** When a leak happens, the recovery follows the same
predictable shape every time:

1. Remove from public surface
2. Create `docs/leak-events/YYYY-MM-DD-<short>.md` with: what
   leaked, severity, when introduced, when discovered, when
   removed, vault path of canonical live value, operator decision
   on rotation
3. Update `docs/leak-events/INDEX.md` with one-line entry
4. Surface to operator for rotation/escalation decision

This rule pairs with rule 1 (don't silently rotate) by giving
that rule a concrete, repeatable execution shape.

**Why:** Without a documented protocol, leak handling becomes
ad-hoc. Different agents respond differently, audit trails get
inconsistent, and the institutional memory of "how we handled
the X leak" lives in chat history (see rule 11).

### 13. Design for disclosure: push & publish rules

**Rule:** Write everything that touches this repository (private or
public) as if it will be published tomorrow. Concretely:

1. **Never in any repo:** platform keys, tokens, passwords, key files,
   vaults, `.env` files with values, databases, backups. Real values
   live only in env vars or the host's owner-only secrets directory.
2. **No real client data, anywhere:** names, slugs, ticket numbers,
   tenant/profile IDs, real IPs, device names, person names. That
   includes **commit messages and branch/tag names**. Fixtures are
   fictional: `acme` / `globex` / `alice` / `bob`, RFC 5737 addresses
   (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`), `T20000101.0001`, keys
   generated at test time.
3. **No live posture detail in tracked files:** host weaknesses,
   ACL/firewall rules, key-escrow locations, fleet counts. Those belong
   in the private ops runbooks, which still never hold credentials or
   client data.
4. **No control may depend on text staying secret.** A marker, banner or
   phrase identifies; proof lives in an authoritative record an attacker
   can't write to (e.g. the RMM job log for a job ID).
5. **Gates, in order:** the pre-commit, commit-msg and pre-push hooks
   (`scripts/install_hooks.sh`, once per clone, re-run when a hook says
   the scanner is newer); then the operator's explicit go before any
   push. `--no-verify` is for emergencies and never for a push.
6. **Pushed history is not rewritten** (this is a development platform
   and is never made public). Unpushed commits that break rules 1-3 are
   reworded or fixed before the push.
7. **Public copies only via `scripts/publish_public.sh`** from a commit
   of this repo: allowlisted export (`ops/public/allowlist.txt`), local
   replacement map, strictest scan, one commit (noreply author, UTC
   date, no trailers, no signature), re-scan. The first copy is one
   orphan commit in a NEW repository (`--out`). Every later copy is one
   commit on top of the public main (`--onto <a clean, full clone of the
   public repository>`): its tree is exactly the new export (files the
   export no longer holds are removed and listed), it is built and
   re-scanned (what it adds and its message) in a scratch repository, and
   the clone's main only fast-forwards once every check passed, so a
   refusal leaves the clone as it was. `--onto` refuses a clone that is
   dirty, not on main, not at its upstream, or whose history holds a
   commit the script did not make. A human pushes it (a plain push, never
   a force-push) after an independent second check and the operator's
   review. The public copy is licensed Apache-2.0 (`LICENSE`, `NOTICE`).
   Never publish this repository's history; never commit, merge or edit
   in a public repository by hand or on the hosting site (its Dependabot
   and code-scanning alerts are fixed here, then published); never
   hand-make a "sanitized clone".
8. **If something slips:** a credential is treated as exposed and
   rotated (rule 1, rule 12); a public repository is made private at
   once, then deleted and re-published clean from this tree with
   `scripts/publish_public.sh --out` (a force-push leaves old commits
   reachable).

**Why:** a sanitizing pass over file contents alone is not enough. It
misses an old design doc that retells a client story, real-looking test
keys, internal posture notes, the git history, and a job banner a SOC
could mistake for authorization. Each item above closes one of those
classes of miss. Anyone (human or agent) working in this repo must have
these rules and the hooks in place first.

---

## No clients or private infra; role labels only (2026-10-16)

**Rule (Rick, 2026-10-16):** "I don't mind if me or Zack are mentioned,
but no clients or private infra." This applies to the private tree as
much as to any public copy (rule 13), and it replaces the earlier note
that tolerated work-side host names in docs.

- **May be named:** Rick Benson, Zack (Zackary) Hille, and Micro-IT, the
  company.
- **Never named, anywhere:** clients; client look-alike pseudonyms (a
  fake that keeps a client's distinctive word, its industry + region, or
  a numbered pair); client stories or incidents retold recognisably (a
  date, a place, a symptom and a vendor together identify one); and
  private-infrastructure detail: host nicknames, hardware models and
  specs, host ports tied to our hosts, live fleet counts (profiles,
  sites, buoys, tenants, orgs), container / unit / tunnel names of our
  hosts, storage share and boot paths, host user names and uids, tailnet
  tags, addresses and ACL details, host security-posture weaknesses,
  vendor support case numbers, and internal note paths. Where a number
  carries the meaning, use a synthetic or relative figure ("a few
  tenants", "thousands of rows", "every fleet buoy").
- **Role labels only.** Docs and code name a host by what it does, never
  by a real hostname, nickname, tailnet address or vendor-tenant URL:

  | Role label | What it is |
  |---|---|
  | the bundle host | runs the OCTO container bundle (production) |
  | the legacy host | ran OCTO as host services before the bundle; now the frozen compliance archive |
  | the backup vault | pulls sealed (ciphertext-only) backup runs off the source host and keeps them; holds no decryption key |
  | the source host | the host the backup vault pulls from (the bundle host today) |
  | the operator workstation | where the operator and their agents work |
  | the reverse proxy | the public edge in front of the console and ingest |

  Ops directories carry the same role names: `ops/bundle-host/`,
  `ops/legacy-host/`, `ops/backup-vault/`. Env vars or a single
  `deployment.yaml` drive the actual names per deploy. Anything customer-
  or site-specific belongs in the operator's own (gitignored)
  `docs/internal/` or `.githooks/.local-block`.
- **Fixtures** use the synthetic fleet (`acme`, `globex`, `initech`,
  `umbrella`, `hooli`, the `dev-buoy-*` names) and the neutral
  coordinates the other fixtures already use.
- **Historical docs live outside the repo.** Session notes, reviews,
  handoffs, the build-state log that filled `STATE.md` (now a short
  current-state doc, not part of the public copy), the pre-public scrub
  inventory and dated runbooks written before this rule were moved to a
  private archive outside the repo
  (Rick's decision, 2026-10-16). Current docs were rewritten with role
  labels. Do not bring archived text back; write new text that follows
  this rule.
- **Publishing.** The public copy is Apache-2.0 and is made only with
  `scripts/publish_public.sh` from a commit of this tree (rule 13). The
  earlier public repository is deleted by Rick and the public copy is
  re-published from this tree; later copies go on top of it as one
  commit each (`--onto`). A public repository is never patched in place:
  a fix lands here first, then the next publish carries it.

**Why:** the bundle is built to ship to other MSPs, and everything in
this repository is written as if it will be published tomorrow. A host
nickname or a client clue in a tracked file is one careless export away
from being public. New text follows this rule from the start.

> The pre-public scrub inventory is archived outside the repo. What it
> drove is in place: vendor-tenant quicklink URLs come from env vars, not
> source, and the local `.githooks/.local-block` blocks work vendor-tenant
> URLs and the internal LAN subnet going forward.

---

## How these are enforced

- **Pre-commit and pre-push hooks** (`.githooks/`) block credential
  shapes, never-commit files and customer-name patterns on every commit
  and again on every push, with one scanner (`scripts/scan_sensitive.py`).
  Install per clone: `scripts/install_hooks.sh`. Public copies only via
  `scripts/publish_public.sh`. See `SECURITY.md`.
- **PR review:** Rick and Zack review PRs, catching edits that
  violate scope, refactor working code, or skip tests.
- **CI** (when wired up) runs the test suite on every push.
- **Operator (you) reviewing this file periodically** is the
  ultimate enforcement. These rules are only as strong as the
  habit of reading them when something feels off.
