# Suspected key exposure: rotate first

For operators (humans). Applies to every vendor platform key Athena holds
(Datto RMM / EDR, Autotask, RocketCyber, NextDNS, UniFi, Resend, Cloudflare,
Wazuh, ...) and to Athena's own secrets (webhook secrets, the job-output
relay token, the vault key file).

**Suspected is enough.** A key that appeared in a commit, a public copy, a
pushed branch, a ticket, a chat, a screenshot or a job's output is exposed.
Do not wait to prove it was seen; history and caches keep what was removed.

1. **Rotate at the vendor, now.** Revoke the exposed key and mint a new one in
   the vendor's console. Revoke, do not just add a second key.
2. **Re-enter the new key in Athena** through the integration's credential
   form (it is encrypted server-side; never put it in a file, an env var or
   a commit). For the Datto job-output relay token (`DATTO_JOB_OUTPUT_TOKEN`,
   the one secret embedded on endpoints) rotate it on its own; the alert
   webhook secret is separate.
3. **Check what the old key did** while it was out: the vendor's API / audit
   log for calls you did not make.
4. **Remove the copy** where you can (the public repository, the ticket, the
   job output) and **record the event** in
   `docs/leak-events/YYYY-MM-DD-<slug>.md`: what leaked, when, how, when it
   was removed and rotated, and where the live value is now (a vault path,
   never the value). See `docs/NON-NEGOTIABLES.md` rule 1.

Agents do not rotate. An agent that finds an exposure stops, tells the
operator, and waits.

How the copies are kept from happening in the first place: `SECURITY.md`,
"Secrets never in code or copies".
