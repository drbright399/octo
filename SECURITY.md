# Security Policy

## Supported versions

Athena / OCTO is pre-1.0. Security fixes land on `main` and in the most
recent tagged release.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub's "Report a vulnerability" button on this
repository (Security → Advisories → Report a vulnerability). Reports are
handled by the security maintainer, **Richard Benson** (see
[`MAINTAINERS.md`](MAINTAINERS.md)).

What to include: affected component (console, OCTO core, a specific
adapter, buoy forwarder), version or commit, reproduction steps, and
impact. Encrypted reports are welcome; ask for a key in the advisory.

## What to expect

- Acknowledgement within **3 business days**.
- Triage and severity assessment within **10 business days**.
- Coordinated disclosure: we ask for up to **90 days** to ship a fix
  before public details, shorter by agreement if a fix is ready sooner.
- Credit in the advisory and release notes unless you prefer otherwise.

## Scope notes

The multi-tenant boundary and the five bridge invariants
(`packages/shared-bridge/shared_bridge/invariants.py`) are the core of
the security model. Cross-tenant data exposure, audit-chain bypass,
template-set escape, and credential-vault weaknesses are the highest
priority classes. Findings in third-party vendor APIs (Datto, Autotask,
Wazuh, etc.) should go to those vendors.

## Keys, tokens and client data

Athena / OCTO holds tenant security telemetry and the API keys of the
vendor platforms it reads (RMM, EDR, PSA, DNS, network). This file covers
how those keys are kept out of code and out of every copy of it.

### Reporting an exposed key, token or client detail

If you think a key, a token, a password or a client detail has been
exposed (in this repository, in a public copy, in job output, in a ticket,
in a chat transcript):

- **Tell a maintainer ([MAINTAINERS.md](MAINTAINERS.md)) privately and at
  once.** Do not open a public issue, do not paste the value anywhere, do
  not "test" it.
- If you are a human operator: rotate the key at the vendor first, then
  record what happened (see [docs/secret-exposure.md](docs/secret-exposure.md)).
- If you are an agent: stop, surface the exposure to the operator, and do
  not rotate anything yourself (non-negotiable rule 1: an agent never
  rotates a key on its own; the operator decides).

### Secrets never in code or copies

**At rest.** Adapter keys enter through the console form and are
Fernet-encrypted server-side before they are stored; the key file lives
outside the repository, mode 600 (`apps/octo/credentials/vault.py`). The
browser never sees a stored key again.

**The risk is copies.** A key that is safe in the vault leaks when a copy of
it lands somewhere else: a commit, a public export, a job's output. The
guardrails below share ONE set of detectors,
`apps/octo/security/secret_patterns.py`, so a shape added there is caught
everywhere.

| Guardrail | What it does |
|---|---|
| `scripts/scan_sensitive.py` | The scanner. Private keys, cloud / SaaS tokens, JWTs, bearer and basic auth headers, credentials in URLs, secret-named assignments with real-looking values (also on the next line after `(` or a YAML `\|` / `>-`, JSON-escaped, or in an HTML `<input name=... value=...>`), vendor credentials by name (Datto, Autotask, RocketCyber, NextDNS, UniFi, Resend, Cloudflare, ...), `whsec_` webhook signing secrets, 32-byte keys in base64 (Fernet, WireGuard), IT Glue `ITG.` keys, Telegram bot tokens, Cloudflare tunnel tokens, secret labels in prose (`Signing key: ...`), passwords on command lines (`cli-password`: `sshpass -p`, `curl -u user:...`, `mysql -p...`, `net use ... /user:...`, `smbclient -U user%...`, `PGPASSWORD=`, `rdesktop -p` / `xfreerdp /p:` / `-p:`, `ldapsearch -w`, `cmdkey /pass:`, `psexec -p`, `ConvertTo-SecureString '...' -AsPlainText`, `plink` / `pscp` / `psftp -pw`, `sqlcmd` / `bcp` / `ipmitool` / `zip` / `unzip -P`, `winrs -p:`, `docker login -p`, `7z -p...`, `redis-cli -a`, `REDISCLI_AUTH=`; each option shape is its own detector, so one that does not apply never hides another; `$VAR`, `${VAR}`, `%VAR%`, `<pw>`, `****` and visibly fake words pass, and so do what PowerShell, sh and cmd expand (`$(...)`, `${...}`, a bare `(...)`, `$script:Name` / `$using:Name` / `$env:Name`, `!NAME!`), though redaction scrubs those too), dash-grouped license keys, `reg query` secret values, high-entropy strings, BitLocker recovery passwords, Wi-Fi keys, and files that are never committed (`.env` with values, `*.gpg`, `*.pem`, `*.key`, `id_*`, databases outside fixtures, backups). Reads file names too, UTF-16 / UTF-32 text (Windows PowerShell's default), UTF-8 text with a stray NUL, and the strings inside binary files. With `--publish` (what every hook runs) it also refuses the never-public values: LAN / tailnet / public IPs (documentation ranges excepted; also where `_` joins them to a name: `nmap_<ip>.xml`, `fix_<ip>`), home and `/mnt` paths, memory links and paths into an agent memory store (`memory-path`), `*.ts.net` names, e-mail addresses (not in dependency lockfiles), NextDNS profile ids, opaque tokens in URL paths, PSA ticket numbers (`psa-ticket-id`; `T20000101.0001` is the one fixture) and binary files that are not images or fonts. Prints `file:line: [detector] col N:` and a masked excerpt: every hit, every other word of 8+ characters on that line (prose punctuation and paired brackets aside) that mixes two of letters, digits and symbols (`Xxxxxx1!` as its own CSV field) unless it is a plain name, a version, a date, a host, a path or an option, whatever is glued to a hit, and in a word that holds a hit every piece of 6+ characters between field separators (`, ; / \ @ = :`) that is not a plain name or a number (a password next to an IP in a CSV row or a `user:pw@host`) are masked, and so is a never-public value in a file name; never a full value. A run of non-blanks with a quote inside it (`Xk9m'Q2p!zR`) is judged as one word, a short value after `name=` / `name:` (`aa=9#^aa$a`) together with its name, and a short core in brackets or before a comma (`(Xk9mQ2p)`, `Xk9#mQ2,`) with them, so no password is printed in pieces too short to count; `port=5432`, `host=dc01`, `shouldn't`, CSV and JSON fields stay readable. Letters alone are read as words (a mixed-case password of letters only is printed). Blobs are read by object id (`diff --raw`), and a file name that is not UTF-8 is kept byte for byte and printed with U+FFFD for the bad bytes; a file whose content cannot be read (a blob git cannot produce, a `--tree` file that cannot be opened or vanished without git knowing it was deleted) is a finding (`unreadable-file`), never skipped. `--all-history` sweeps every object the repository holds (all refs, reflogs, every worktree's index, unreachable commits, trees and blobs), scanning each blob once under the name with the strictest rules among all the names history gave it. A detector check that raises on some input is a bug, never a crash: that candidate is no finding (redaction scrubs it instead), a warning names the detector and never the value; any other internal error refuses with exit 2 and the exception's type only. Every detector, every program check and the whole pipeline are timed on generated hostile lines of 50 to 200 kB (`apps/octo/tests/security/hostile.py`), among them runs of candidates in one token (`--key=/--key=/...`, `xoxb-xoxb-...`, `password=<v>;password=<v>;...`: a value the check refuses is searched again one character later, an accepted one is scrubbed to the end of its word) and job-output option runs at 400 kB (one stream's cap), so a pattern that backtracks exponentially or quadratically fails the test suite. Values are bounded (an option's value at 400 characters, redaction then goes on to the end of the word) or a token shape cannot start inside its own value. |
| `.githooks/pre-commit` | Scans the lines a commit adds (`--staged --publish`). A file the diff shows whole (a pure rename, a mode change) is checked whole: touch an old file, clean it. Each staged blob is read by its object id, so a file name that is not UTF-8 (a Windows zip unpacked on Linux) is checked like any other; a blob that cannot be read refuses the commit. |
| `.githooks/commit-msg` | Scans the commit message (`--message --publish`), including lines that start with `#`: `git commit -m` / `-F` keeps them. Only when an editor ran and git's own template says it strips comment lines are they skipped. The comment string is git's own, read from its configuration (`core.commentChar` / `core.commentString`, `#` by default; `auto`: one of git's candidate characters), never one a line names; `commit.cleanup=whitespace` / `verbatim` strips nothing. The `git commit -v` diff is skipped only below git's own scissors block (the cut line and git's two explanation lines under it), and only when git's -v diff follows it (after comment lines only), or, with `commit.cleanup=scissors` configured, when only comment lines do; a scissors line or block typed or pasted into a message is kept by git, so the text after it is checked. Likewise only the last "will be ignored" hint counts, right under git's "Please enter the commit message" line, and none when git's "will be kept" hint is there too (`--cleanup=whitespace`): a hint line typed above git's template cannot make other lines comments. A `--cleanup=` option git writes no hint for (`--no-status`) is invisible to the hook; the pre-push hook checks what was stored. With a translated git (another language) the block is not recognized and the diff is checked too: commit without `-v`, or with `LC_ALL=C`. |
| `.githooks/pre-push` | Scans every commit a push would send (`--range --publish`): the lines it adds (each blob read by its object id; one that cannot be read refuses), its message, and the name and message of a pushed annotated tag. A commit made with `--no-verify`, in another clone, or before the hooks were installed is still caught before it leaves the machine. A commit the remote already holds under any of its refs (a branch fast-forwarded to commits pushed elsewhere) is not checked again. What the remote holds is asked of the remote itself, once per push (`git ls-remote` of the URL being pushed to, passed as `--remote-tips`), never taken from this clone's remote-tracking refs: those can be stale, so a commit whose branch was deleted or force-pushed away elsewhere is checked again before it goes back. A listed branch or tag tip this clone does not have (another clone pushed since the last fetch) is fetched first, objects only (`git fetch --no-tags --no-write-fetch-head --refmap=`: no ref, no `FETCH_HEAD` is written), so commits the remote already holds are still left out; if that fetch fails, a refusal says the clone is behind: run `git fetch <remote>` and push again. A push to another remote, a `pushurl` or a bare URL checks everything that location does not hold. If the remote cannot be listed nothing is assumed to be there: an update checks exactly its range, a new branch its whole history. First it checks the name the push creates on the remote (`--ref-name --publish`): a branch or tag name with a `.local-block` term, a token shape or a never-public value (an IP, an e-mail address, a ticket number) is refused (push it as `<branch>:refs/heads/<neutral>`); deleting a remote ref is never refused. An annotated tag records its own name inside the tag object, so a neutral refspec does not hide it: re-create the tag under a neutral name. A scanner error (exit 2) refuses the push like a finding does. |
| `.githooks/.local-block` | Per-machine, gitignored list of terms that must never be committed: client names, host names, tailnet ids. One term or regex per line. Honoured in every mode, including commit and tag messages, file names and pushed branch / tag names; a term cannot be allowed inline. Found in the checkout, in the main checkout of a linked worktree, or at `$SCAN_SENSITIVE_LOCAL_BLOCK`; that variable (or `--local-block`) naming a missing file is an error that refuses the commit / push. **Without the file the hooks check secret shapes only** and the scanner prints a warning on every run: create it in every clone. A term with word boundaries (`\<acme\>`, `\bacme\b`) does not match where `_` or a digit joins it to the next word (`acme_fix`, `acme2`) in file contents and messages, as with `grep -E`; ref and tag names are also checked with `_` and digits read as separators. Where that matters in contents, write the term without boundaries or with letter-only lookarounds (`(?<![A-Za-z])acme(?![A-Za-z])`). |
| `scripts/publish_public.sh` | The only supported way to make a public copy. Exports only what `ops/public/allowlist.txt` lists, applies the gitignored replacement map `.githooks/.publish-map`, scans the result with `--publish` (the never-public values above, as the hooks do), refuses on any hit, and makes one orphan commit with a neutral GitHub-noreply identity, dated in UTC, with no trailers, or, with `--onto <clone of the public repo>`, as one commit on top of the public `main` whose tree is exactly the export (built and re-scanned before the clone's `main` moves). It never pushes. |
| Job-output redaction | Datto quick-job output is redacted (`[REDACTED:<detector>]`) before it is stored or read back (`apps/octo/adapters/datto/job_output.py`), including `reg query` values, `Format-List` `*Key :` lines (also when wrapped onto the next line), `/ACCT_KEY=` / `--key` / `--license` arguments and JSON-escaped values. The PowerShell relay asks for 4096-character lines so a long value is not wrapped in the first place. Linear in the output however many option or assignment candidates one token holds (job output is attacker-influenced): the next candidate is searched after a scrubbed span, never inside it. |

**Install the hooks once per clone, every collaborator and every agent:**

```bash
scripts/install_hooks.sh
```

It copies ("pins") the hooks and the scanner into the clone's shared git
directory and points `core.hooksPath` there
(`<git-common-dir>/athena-guardrails/hooks`), so every worktree and every
branch is guarded, including branches that predate the guardrails. Each run
installs a fresh versioned copy and swaps the `athena-guardrails` symlink to
it in one rename, so `core.hooksPath` never names a missing directory (git
would then run no hooks at all) while other worktrees commit. Runs that
overlap (parallel agents) are serialized by a lock directory,
`<git-common-dir>/athena-guardrails.lock`: a run waits for it (up to
`ATHENA_GUARDRAILS_LOCK_WAIT` seconds, default 120) and breaks it only when
its owner process is gone or it is older than `ATHENA_GUARDRAILS_LOCK_STALE`
seconds (default 300); the copy git currently uses is never removed. At the
end the script checks that `core.hooksPath` names a directory holding every
hook and the scanner, and fails loudly (exit 1) if git would not find them
(for example an environment override of `core.hooksPath`). When a branch
carries a newer scanner the hooks say so; run the script again from that
branch.

Hooks are client-side: `--no-verify` skips the pre-commit and commit-msg
hooks and `git push --no-verify` skips the pre-push hook. Do not use either on
this repository. The server-side backstop is GitHub's own secret scanning
with push protection (below).

**GitHub settings (the account / repository owner).**

1. Every collaborator's own account: *Settings → Code security → Push
   protection for yourself*: on. It blocks a push of a token GitHub
   recognizes to any public repository, from any clone.
2. Each repository: *Settings → Advanced Security* (older UI: *Code security
   and analysis*): turn on **Secret scanning** (*Secret Protection*) and
   **Push protection**. Free on a public repository; on a private one they
   need a plan that includes GitHub Secret Protection. Where they are not
   offered, the hooks are the only gate for that repository.
3. The public repository: also **Private vulnerability reporting**, so a
   reporter has a private channel.

Push protection knows token shapes GitHub's partners register; it does not
know client names, host names or vendor keys without a known shape, which is
what the hooks and the publish gate are for.

**A test needs a secret-shaped value?** Generate it at runtime (see
`apps/octo/tests/security/fakes.py`), or make it visibly fake
(`your-api-key`, `fixture-...`, `${TOKEN}`). If a literal really must stay,
put `scan-sensitive: allow <why it is safe>` on that line, or alone on the
comment line above it. The reason is required and is read from the comment
alone (text after `*/` or `-->` is code, not a reason); a bare marker is
itself a finding. A bare `allow` covers the secret detectors only; an IP, an
e-mail address, a home path or another publish-only finding is allowed only
by naming it: `scan-sensitive: allow[ip-private,email-address] <why>`. In a
commit, a marker on the line above covers its value only when the marker
line is part of the same change, so an old marker never approves a new
value. `scripts/scan_sensitive.py --list-detectors` lists the names.

**A commit or push refused for a never-public value?** The private
repository meets the public standard too (2026-10-15), so an IP address, an
e-mail address, a home path, a ticket number or a tailnet name is refused in
files, file names, commit messages and branch / tag names, even though none
of them is a secret. Replace it with a documentation value: an address in
`192.0.2.0/24`, `198.51.100.0/24` or `203.0.113.0/24`, an `example.com`
address, `/home/<user>`, the ticket number `T20000101.0001`. If the real
value has to stay (a published scanner range, a vendor's support address),
name the detector in the marker: `scan-sensitive: allow[ip-public] <why it is
public>`; a bare `allow` does not cover these. A file or branch name cannot
carry a marker: rename it. A message is fixed with `git commit --amend`
before the push; a branch that already reached the remote with such commits
is not checked again when another branch moves to them.

**Something slipped through anyway?** Treat the value as exposed the moment it
left the machine, whatever was pushed afterwards: history keeps it. Rotate
first, clean up second.

### Other baselines

- No tokens in `localStorage` / `sessionStorage`; auth is httpOnly cookies.
- All UI content is rendered as text nodes.
- Client addresses: `X-Forwarded-For` is believed only from peers listed in
  `OCTO_TRUSTED_PROXIES` (default: nobody; the socket peer is the client),
  walked from the right (`apps/octo/api/client_ip.py`). A value with an
  unusable entry (not an address or network, host bits set, `/0`) stops
  octo-core from starting rather than trusting less or more than meant; on
  the bundle host it is the subnet of an internal docker network that only
  the reverse proxy, the console and octo-core join, and the reverse proxy
  must be reachable only through the tunnel. Search step-up binds to the
  same address, never to the left-most `X-Forwarded-For` entry. Rate-limit
  buckets hold a keyed hash of the whole bearer token, never the token or a
  prefix of it, and their number is capped (oldest idle dropped first);
  sign-in, step-up and webhook routes are bucketed by address
  whatever `Authorization` header they carry. Failed authentications are
  limited per address (30 in 10 minutes, in-flight attempts included, then
  429 for 15 minutes) on top of the per-account sign-in lockout
  (`apps/octo/api/rate_limit.py`); that limiter acts only once
  `OCTO_TRUSTED_PROXIES` is set and only on addresses that name one client,
  so nobody can hold back everyone behind a shared proxy address.
  Deployment: docs/operations/bundle.md, "Client addresses behind the
  proxy".
