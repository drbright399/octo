"""Effective AI policy — the ONE answer to "may a model reason over this
tenant's data, and where?" (v0.10, migration 034).

`clients.ai_policy` is the INTENT an admin stored ('none' | 'local' |
'cloud'). What actually runs is `effective_ai_policy(slug)`:

  requested 'none'   → 'none'
  requested 'local'  → 'local'
  requested 'cloud'  → 'cloud' only when cloud needs no sign-off (the tenant
                       is tagged exactly ["none"]) or a LIVE sign-off covers
                       EXACTLY its current compliance flags — otherwise
                       'local' (owner decision 2026-09-28: unsigned cloud
                       DEGRADES TO LOCAL, never to none, never stays cloud).
  an offboarded or archived tenant → 'none', whatever it asked for.
  unknown tenant / unknown value / a registry this code cannot read → 'none'.

Where a model runs is its LOCALITY: 'local' (octo-llm, the bundle's own
sibling on an internal network) or 'cloud' (the data leaves the deployment
— no such path exists in OCTO yet). `ai_allowed(slug, locality)` is the gate
every model call asks, and the only one: 'local' needs an effective policy
of local or cloud; 'cloud' needs exactly cloud. ANY future cloud path calls
it with locality='cloud'.

Sign-offs (`tenant_compliance_signoffs`, append-only): a super_admin records,
under the agreements that cover it, that the tenant's data may go to a cloud
model. A
sign-off is LIVE while it is not revoked, not expired, and its
`flags_covered` equals the tenant's current flags. Flags compare in
canonical form (known tags, sorted, unique): '[]' ("never tagged") is its
own value and REQUIRES a sign-off — fail closed; '["none"]' ("we checked, no
regime applies") needs none. A flag change therefore stops the old sign-off
matching by itself; the write paths (PATCH, bulk review, merge) ALSO revoke
it explicitly (`invalidate_signoffs`) so the history and the audit chain
say why. Signing again supersedes the previous row (at most one unrevoked
sign-off per tenant — a partial unique index).

Default term: 12 months (`SIGNOFF_TERM_MONTHS_DEFAULT`) — the annual cycle
BAAs and HIPAA risk evaluations already run on, so a sign-off never outlives
the review that justified it by more than a year. The API accepts a shorter
term (a BAA ending sooner), never a longer one, and never "no expiry".

A sign-off names ONE agreement per regime it covers (`AGREEMENT_INSTRUMENTS`:
a HIPAA BAA does not cover CJIS, PCI, GLBA, BIPA or FERPA data — each has its
own instrument), stored as a JSON object in the `baa_reference` column; a
never-tagged tenant names its data-processing agreement.

Fail closed on data this code did not write: a stored `compliance_flags`
value that is not exactly a list of known tags ('none' alone) — unparseable,
wrong case, a newer vocabulary, 'none' mixed with a regime — matches no
sign-off and never reads as "no regime applies" (`flags_readable`). An
offboarded or archived tenant runs as 'none' whatever it asked for: the
relationship, and the consent, ended.

"Cloud" here means CLEARED for a cloud model. No cloud model is wired into
OCTO yet: every model call today is octo-llm, the bundle's local sibling.

Nothing here decides who may sign; the routes do (super_admin + step-up).
Nor who may make a tenant run as cloud by other means: the tenant routes
hold PATCH / bulk edits that do so to the same bar.
"""

from __future__ import annotations

import calendar
import hashlib
import ipaddress
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import urlsplit

from apps.octo import paths
from apps.octo.db import connect
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.instances.tenant_lifecycle import (
    AI_POLICIES,
    COMPLIANCE_TAGS,
    compliance_flags_json,
    parse_compliance_flags,
)

# Least → most permissive. The merge eligibility rule ("the target may not be
# more permissive than the subject") compares EFFECTIVE policies by this.
POLICY_ORDER: tuple[str, ...] = ("none", "local", "cloud")
LOCALITIES: tuple[str, ...] = ("local", "cloud")
assert set(POLICY_ORDER) == set(AI_POLICIES)

SIGNOFF_STATES: tuple[str, ...] = (
    "not_required", "required", "live", "expired", "revoked", "flags_changed",
)
# How a sign-off stopped: by an operator, by a flag change, by a merge that
# added flags to the tenant, or by a newer sign-off. (The table's CHECK.)
REVOKED_KINDS: tuple[str, ...] = ("operator", "flags_changed", "merge_added_flags", "superseded")

# Tenant statuses whose data no model reasons over any more (the client left,
# or was merged away): effective 'none', whatever was asked for.
RETIRED_STATUSES: tuple[str, ...] = ("offboarded", "archived")

SIGNOFF_TERM_MONTHS_DEFAULT = 12
SIGNOFF_TERM_MONTHS_MAX = 12
ATTESTATION_MIN_CHARS = 40
ATTESTATION_MAX_CHARS = 2000
REVOKE_REASON_MIN_CHARS = 3
REVOKE_REASON_MAX_CHARS = 500

# The agreement a sign-off must name for each regime it covers — one each,
# because no single agreement covers them all (a BAA is HIPAA's instrument;
# CJIS needs the Security Addendum, BIPA a written release, …). A tenant
# never tagged ([]) names the data-processing agreement its data falls under.
UNTAGGED_AGREEMENT_KEY = "untagged"
AGREEMENT_INSTRUMENTS: dict[str, str] = {
    "hipaa": "HIPAA business associate agreement (BAA)",
    "cjis": "CJIS Security Addendum",
    "pci": "PCI DSS service-provider responsibility agreement",
    "glba": "GLBA service-provider contract",
    "bipa": "BIPA written release",
    "ferpa": "FERPA school-official or data-sharing agreement",
    UNTAGGED_AGREEMENT_KEY: "data-processing agreement",
}
assert set(AGREEMENT_INSTRUMENTS) == (set(COMPLIANCE_TAGS) - {"none"}) | {UNTAGGED_AGREEMENT_KEY}
AGREEMENT_REFERENCE_MAX_CHARS = 120          # one reference
AGREEMENT_REFERENCES_MAX_CHARS = 1000        # the stored JSON object (the column's CHECK)

# The statement the console shows above the typed attestation. A version's
# text never changes once shipped (a test pins its hash): new wording is a
# new version, and a sign-off records the version its signer was shown.
# v1 asked for one "BAA reference" for every regime; v2 asks for the
# instrument each regime requires, one reference per regime.
ATTESTATION_VERSION = "2026-09-28.v2"
ATTESTATION_TEMPLATES: dict[str, str] = {
    "2026-09-28.v1": (
        "I am an Athena Admin for this MSP. I am recording that this tenant's "
        "data may be processed by a cloud AI model, outside this deployment. "
        "The business associate agreement (or equivalent data-processing "
        "agreement) referenced here covers that processing for every compliance "
        "regime listed for the tenant, and I have checked that list today. This "
        "sign-off stops applying when the tenant's compliance tags change, when "
        "it expires, or when it is revoked."
    ),
    "2026-09-28.v2": (
        "I am an Athena Admin for this MSP. I am recording that this tenant's "
        "data may be processed by a cloud AI model, outside this deployment. "
        "For every compliance regime listed for the tenant, the agreement "
        "referenced here for that regime is the instrument that regime requires "
        "(HIPAA: a business associate agreement; CJIS: the CJIS Security "
        "Addendum; PCI DSS: a service-provider responsibility agreement; GLBA: a "
        "service-provider contract; BIPA: a written release; FERPA: a "
        "school-official or data-sharing agreement; a tenant never tagged: a "
        "data-processing agreement), and it covers that processing. I have "
        "checked the list today. This sign-off stops applying when the tenant's "
        "compliance tags change, when it expires, or when it is revoked."
    ),
}


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

def canonical_flags(raw: Any) -> list[str]:
    """A `compliance_flags` / `flags_covered` value (JSON text or a list) →
    the known tags, sorted, unique. Unknown values are DROPPED here — so the
    status path never trusts this alone: `flags_readable` says whether the
    stored value was exactly what this form shows."""
    return parse_compliance_flags(raw)


def flags_readable(raw: Any) -> bool:
    """Is a stored `compliance_flags` value exactly a list of known tags,
    'none' only on its own — what every writer here stores? False for
    anything else (not JSON, not a list, 'HIPAA', a tag a newer build knows,
    'none' next to a regime): such a value matches no sign-off and never
    counts as "no regime applies", so the tenant runs as local at most until
    someone re-tags it. Order and repeats are harmless."""
    try:
        values = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return False
    if not isinstance(values, list):
        return False
    if any(not isinstance(v, str) or v not in COMPLIANCE_TAGS for v in values):
        return False
    return not ("none" in values and len(set(values)) > 1)


def signoff_required(flags: Iterable[str]) -> bool:
    """Cloud needs a sign-off unless the tenant is tagged exactly ["none"].
    [] ("never tagged") requires one: nobody has said no regime applies."""
    return sorted(set(flags)) != ["none"]


def flags_label(flags: Iterable[str]) -> str:
    return "[" + ", ".join(flags) + "]"


def regimes_not_covered(subject_flags: Iterable[str], target_flags: Iterable[str]) -> list[str]:
    """The compliance regimes the subject carries and the target does not.
    'none' is not a regime, and an untagged subject ([]) carries none — a
    merge asserts the two are the same business, so the target's own tags
    are what govern the combined data unless the subject names more."""
    subject = {f for f in subject_flags if f != "none"}
    target = {f for f in target_flags if f != "none"}
    return sorted(subject - target)


def merged_flags(subject_flags: Iterable[str], target_flags: Iterable[str]) -> list[str]:
    """The target's flags once the subject is merged into it: the union of
    the regimes when the subject adds any ('none' dropped — "no regime
    applies" is no longer true). An UNTAGGED subject ([]: nobody has said
    which regimes its data carries) merged into a target tagged 'none'
    drops the 'none' too — the combined data is no longer known to carry no
    regime, so it goes back to [] and cloud needs a sign-off again (fail
    closed; the owner's rule that '[]' requires one survives a merge).
    Otherwise the target's flags are unchanged."""
    subject = sorted(set(subject_flags))
    target = sorted(set(target_flags))
    added = regimes_not_covered(subject, target)
    if added:
        return sorted({f for f in target if f != "none"} | set(added))
    if not subject and target == ["none"]:
        return []
    return target


def policy_rank(policy: str) -> int:
    """Position in POLICY_ORDER; an unknown value ranks as 'none'."""
    return POLICY_ORDER.index(policy) if policy in POLICY_ORDER else 0


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SignoffStatus:
    """Where the tenant stands for cloud AI, independent of what it asks for."""
    state: str                              # one of SIGNOFF_STATES
    signoff_id: int | None = None           # the live row, or the one that lapsed
    signed_by: int | None = None
    signed_at: str | None = None
    expires_at: str | None = None
    flags_covered: tuple[str, ...] | None = None
    revoked_at: str | None = None
    revoked_kind: str | None = None


@dataclass(frozen=True)
class AiPolicyStatus:
    slug: str
    requested: str                          # clients.ai_policy as stored
    effective: str                          # what actually runs
    flags: tuple[str, ...]                  # canonical current flags
    signoff: SignoffStatus
    # Why effective is what it is, in one sentence for the console; None for
    # a plain 'none' / 'local'.
    reason: str | None

    @property
    def degraded(self) -> bool:
        return self.effective != self.requested


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _expired(expires_at: str | None, now: datetime) -> bool:
    """NULL = no expiry. An unreadable timestamp counts as expired."""
    if expires_at is None:
        return False
    when = _parse_iso(expires_at)
    return when is None or when <= now


def _signoff_rows(conn: sqlite3.Connection, slug: str) -> list[Mapping[str, Any]]:
    """The tenant's sign-offs, newest first. [] on a registry before 034."""
    try:
        cur = conn.execute(
            "SELECT * FROM tenant_compliance_signoffs WHERE slug = ? ORDER BY id DESC", (slug,),
        )
    except sqlite3.OperationalError:
        return []
    names = [d[0] for d in cur.description]
    return [dict(zip(names, r)) for r in cur.fetchall()]


def _status_from(row: Mapping[str, Any], state: str) -> SignoffStatus:
    return SignoffStatus(
        state=state,
        signoff_id=int(row["id"]),
        signed_by=int(row["signed_by"]),
        signed_at=row["signed_at"],
        expires_at=row["expires_at"],
        flags_covered=tuple(canonical_flags(row["flags_covered"])),
        revoked_at=row["revoked_at"],
        revoked_kind=row["revoked_kind"],
    )


def signoff_status(
    conn: sqlite3.Connection, slug: str, flags: list[str], *, now: datetime | None = None,
    assume_flags_changed: bool = False, readable: bool = True,
) -> SignoffStatus:
    """`assume_flags_changed`: answer as if the tenant's unrevoked sign-offs
    had just been revoked for a flag change — what a PREVIEW of a flag edit
    must show, since applying it revokes them (`invalidate_signoffs`).
    `readable` False (`flags_readable`): the stored flags are not what
    `flags` shows — nothing matches, and a sign-off is 'required'."""
    now = now or utcnow()
    if not readable:
        return SignoffStatus(state="required")
    if not signoff_required(flags):
        return SignoffStatus(state="not_required")
    rows = _signoff_rows(conn, slug)
    if assume_flags_changed:
        rows = [
            {**r, "revoked_at": format_utc_ms(now), "revoked_kind": "flags_changed"}
            if r["revoked_at"] is None else r
            for r in rows
        ]
    for r in rows:
        if (r["revoked_at"] is None and not _expired(r["expires_at"], now)
                and canonical_flags(r["flags_covered"]) == flags):
            return _status_from(r, "live")
    if not rows:
        return SignoffStatus(state="required")
    latest = rows[0]
    if latest["revoked_at"] is not None:
        state = ("flags_changed" if latest["revoked_kind"] in ("flags_changed", "merge_added_flags")
                 else "revoked")
    elif canonical_flags(latest["flags_covered"]) != flags:
        state = "flags_changed"
    else:
        state = "expired"
    return _status_from(latest, state)


def why_not_cloud(flags: Iterable[str], s: SignoffStatus) -> str | None:
    """Why cloud is not honoured for these flags + sign-off status, in one
    phrase — None when it is (no sign-off needed, or a live one)."""
    flags = list(flags)
    if s.state in ("not_required", "live"):
        return None
    if s.state == "required":
        return (
            "sign-off required: the tenant has never been tagged (compliance flags [])"
            if not flags else f"sign-off required for {flags_label(flags)}"
        )
    if s.state == "expired":
        return f"sign-off #{s.signoff_id} expired {(s.expires_at or '')[:10]} — sign off again"
    if s.state == "flags_changed":
        return (
            f"compliance flags changed since sign-off #{s.signoff_id} (signed for "
            f"{flags_label(s.flags_covered or ())}, now {flags_label(flags)}) — sign off again"
        )
    return f"sign-off #{s.signoff_id} was revoked — sign off again"


def _reason(
    requested: str, effective: str, flags: list[str], s: SignoffStatus, *,
    readable: bool = True, retired: str | None = None,
) -> str | None:
    """"cloud" in these sentences is what the tenant is CLEARED for — no
    cloud model is wired in yet (the module docstring)."""
    if retired is not None and requested in ("local", "cloud"):
        return f"tenant {retired} — no model reasons over a departed tenant's data"
    if requested != "cloud":
        return None if requested in POLICY_ORDER else f"unknown ai_policy {requested!r} — runs as none"
    if effective == "cloud":
        if s.state == "not_required":
            return "cloud permitted — tagged 'none' (no compliance regime applies); no sign-off needed"
        until = f"until {s.expires_at[:10]}" if s.expires_at else "with no expiry"
        return f"cloud permitted — sign-off #{s.signoff_id} covers {flags_label(flags)} {until}"
    if not readable:
        return (
            "cloud requested — degraded to local: the stored compliance flags are not a list "
            "of known tags — re-tag the tenant, then sign off"
        )
    return f"cloud requested — degraded to local: {why_not_cloud(flags, s)}"


def _row_value(row: Mapping[str, Any], key: str) -> Any:
    """`row[key]`, or None when a would-be row (a preview's dict) or a
    narrow SELECT does not carry it."""
    try:
        return row[key]
    except (KeyError, IndexError):
        return None


def status_for_row(
    conn: sqlite3.Connection, row: Mapping[str, Any], *, now: datetime | None = None,
    assume_flags_changed: bool = False,
) -> AiPolicyStatus:
    """The status of a `clients` row (slug, ai_policy, compliance_flags,
    status) — on the caller's connection, so a list or a bulk preview reads
    the registry once. `row` may be a would-be row (a preview): pass
    `assume_flags_changed` when its flags differ from the stored ones. An
    offboarded or archived tenant runs as 'none'; stored flags that are not
    exactly a list of known tags match no sign-off (`flags_readable`)."""
    slug = row["slug"]
    requested = row["ai_policy"]
    raw_flags = row["compliance_flags"]
    flags = canonical_flags(raw_flags)
    readable = flags_readable(raw_flags)
    tenant_status = _row_value(row, "status")
    retired = tenant_status if tenant_status in RETIRED_STATUSES else None
    s = signoff_status(
        conn, slug, flags, now=now, assume_flags_changed=assume_flags_changed, readable=readable,
    )
    if retired is not None:
        effective = "none"
    elif requested == "cloud":
        effective = "cloud" if s.state in ("not_required", "live") else "local"
    elif requested in ("none", "local"):
        effective = requested
    else:
        effective = "none"
    return AiPolicyStatus(
        slug=slug, requested=requested, effective=effective, flags=tuple(flags),
        signoff=s, reason=_reason(requested, effective, flags, s, readable=readable, retired=retired),
    )


def policy_status(slug: str, *, now: datetime | None = None) -> AiPolicyStatus | None:
    """`status_for_row` for one tenant from the registry; None when the tenant
    is unknown or the registry predates migration 033."""
    if not paths.SLUG_RE.match(slug or ""):
        return None
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        try:
            cur = reg.execute(
                "SELECT slug, ai_policy, compliance_flags, status FROM clients WHERE slug = ?",
                (slug,),
            )
        except sqlite3.OperationalError:
            return None
        found = cur.fetchone()
        if found is None:
            return None
        return status_for_row(reg, dict(zip([d[0] for d in cur.description], found)), now=now)
    finally:
        reg.close()


def effective_ai_policy(slug: str, *, now: datetime | None = None) -> str:
    """'none' | 'local' | 'cloud' — what may actually run for this tenant.
    Fail closed: an unknown tenant or unreadable registry is 'none'."""
    try:
        status = policy_status(slug, now=now)
    except Exception:  # noqa: BLE001 — never let a read error open a gate
        return "none"
    return status.effective if status is not None else "none"


def locality_allows(effective: str, locality: str) -> bool:
    """Does an EFFECTIVE policy permit a model at `locality`? 'cloud' only
    for cloud; 'local' for local or cloud (a tenant cleared for the cloud is
    cleared for the bundle's own model); nothing for 'none'."""
    if locality not in LOCALITIES:
        raise ValueError(f"locality must be one of {', '.join(LOCALITIES)}")
    if locality == "cloud":
        return effective == "cloud"
    return effective in ("local", "cloud")


# The deployment's own networks: RFC 1918 and IPv6 unique-local addresses
# (loopback and link-local are checked by their own flags). Not "is_private":
# that also counts documentation and reserved ranges.
_LOCAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
))


# A DNS label that starts with a letter — never an integer/hex IPv4 form.
_SERVICE_LABEL = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,62}")


def locality_of_url(url: str) -> str:
    """Where a model endpoint runs, from its URL alone (never a DNS lookup):
    'local' for a loopback or private address (RFC 1918, ULA, link-local),
    'localhost', or a single-label host name — a container service name such
    as the default 'octo-llm', which resolves only on the bundle's internal
    network; 'cloud' for anything else, including a dotted host name that
    happens to resolve inside (fail closed: an operator who points
    OCTO_LLM_URL off the deployment has made every call a cloud call, and
    the tenant gate then asks for 'cloud')."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return "cloud"
    if not host:
        return "cloud"
    if host == "localhost":
        return "local"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # A single-label NAME (a container service such as 'octo-llm') is
        # local. A single label that is not a name — all digits or 0x-hex —
        # is an IPv4 address in integer form ('134744072' is a public
        # address; the resolver accepts it with no DNS lookup): fail closed.
        if "." not in host and _SERVICE_LABEL.fullmatch(host):
            return "local"
        return "cloud"
    if ip.is_loopback or ip.is_link_local:
        return "local"
    return "local" if any(ip in net for net in _LOCAL_NETWORKS) else "cloud"


def ai_allowed(slug: str, locality: str, *, now: datetime | None = None) -> bool:
    """May a model at `locality` ('local' | 'cloud') reason over this
    tenant's data? `locality_allows(effective_ai_policy(slug), locality)` —
    the gate every model call site asks."""
    return locality_allows(effective_ai_policy(slug, now=now), locality)


# ---------------------------------------------------------------------------
# Writes — inside the CALLER's registry transaction; the caller audits.
# ---------------------------------------------------------------------------

def add_months(dt: datetime, months: int) -> datetime:
    """Calendar months, the day clamped to the target month's length."""
    y, m = divmod(dt.month - 1 + months, 12)
    year, month = dt.year + y, m + 1
    return dt.replace(year=year, month=month, day=min(dt.day, calendar.monthrange(year, month)[1]))


def attestation_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def unrevoked_signoff_ids(conn: sqlite3.Connection, slug: str) -> list[int]:
    """The tenant's not-yet-revoked sign-offs (live or expired) — what a flag
    change or a merge that adds flags would revoke. [] before migration 034."""
    try:
        return [int(r[0]) for r in conn.execute(
            "SELECT id FROM tenant_compliance_signoffs WHERE slug = ? AND revoked_at IS NULL "
            "ORDER BY id", (slug,),
        ).fetchall()]
    except sqlite3.OperationalError:
        return []


def invalidate_signoffs(
    conn: sqlite3.Connection, slug: str, *, operator_id: int, kind: str, reason: str,
    now: datetime | None = None,
) -> list[int]:
    """Revoke every unrevoked sign-off of `slug` (kind ∈ REVOKED_KINDS);
    returns their ids, [] when there were none (or no table yet)."""
    if kind not in REVOKED_KINDS:
        raise ValueError(f"revoked kind must be one of {', '.join(REVOKED_KINDS)}")
    ids = unrevoked_signoff_ids(conn, slug)
    if ids:
        conn.execute(
            "UPDATE tenant_compliance_signoffs SET revoked_at = ?, revoked_by = ?, "
            "revoked_kind = ?, revoke_reason = ? WHERE slug = ? AND revoked_at IS NULL",
            (format_utc_ms(now or utcnow()), operator_id, kind, reason[:REVOKE_REASON_MAX_CHARS], slug),
        )
    return ids


def revoke_signoff(
    conn: sqlite3.Connection, signoff_id: int, *, operator_id: int, reason: str,
    now: datetime | None = None,
) -> bool:
    """An operator's revocation of one row. False when it was already
    revoked (the table's trigger would refuse the second write anyway)."""
    cur = conn.execute(
        "UPDATE tenant_compliance_signoffs SET revoked_at = ?, revoked_by = ?, "
        "revoked_kind = 'operator', revoke_reason = ? WHERE id = ? AND revoked_at IS NULL",
        (format_utc_ms(now or utcnow()), operator_id, reason[:REVOKE_REASON_MAX_CHARS], signoff_id),
    )
    return cur.rowcount == 1


def agreement_keys(flags: Iterable[str]) -> list[str]:
    """The agreements a sign-off for `flags` names: one per regime, or the
    data-processing agreement of a never-tagged tenant."""
    regimes = sorted({f for f in flags if f != "none"})
    return regimes or [UNTAGGED_AGREEMENT_KEY]


def agreement_references_json(refs: Mapping[str, str]) -> str:
    """The stored form (the `baa_reference` column): a JSON object, sorted."""
    return json.dumps(dict(sorted(refs.items())), ensure_ascii=False, separators=(",", ":"))


def parse_agreement_references(raw: Any) -> dict[str, str]:
    """The stored `baa_reference` column → {regime: reference}. A value that
    is not such an object (a sign-off recorded before references were per
    regime) reads as {"reference": <the text>}."""
    try:
        value = json.loads(raw) if isinstance(raw, str) else None
    except ValueError:
        value = None
    if isinstance(value, dict) and value and all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    ):
        return dict(value)
    return {"reference": str(raw)} if raw else {}


def record_signoff(
    conn: sqlite3.Connection, slug: str, *, flags: list[str],
    agreement_references: Mapping[str, str], attestation_text: str, attestation_version: str,
    operator_id: int, request_id: str, term_months: int = SIGNOFF_TERM_MONTHS_DEFAULT,
    now: datetime | None = None,
) -> tuple[int, list[int]]:
    """Append a sign-off covering `flags` (already checked against the
    tenant by the caller), naming one agreement per `agreement_keys(flags)`.
    Any unrevoked earlier row is superseded first — one unrevoked sign-off
    per tenant. Returns (new id, superseded ids)."""
    if not 1 <= term_months <= SIGNOFF_TERM_MONTHS_MAX:
        raise ValueError(f"term_months must be 1–{SIGNOFF_TERM_MONTHS_MAX}")
    if sorted(agreement_references) != agreement_keys(flags) or not all(
        isinstance(v, str) and v.strip() for v in agreement_references.values()
    ):
        raise ValueError(
            "agreement_references must name one agreement for each of: "
            + ", ".join(agreement_keys(flags))
        )
    now = now or utcnow()
    superseded = invalidate_signoffs(
        conn, slug, operator_id=operator_id, kind="superseded",
        reason=f"superseded by a newer sign-off (request {request_id})", now=now,
    )
    cur = conn.execute(
        "INSERT INTO tenant_compliance_signoffs (slug, policy, flags_covered, baa_reference, "
        "attestation_text, attestation_sha256, attestation_version, signed_by, signed_at, "
        "expires_at, request_id) VALUES (?, 'cloud', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            slug, compliance_flags_json(flags), agreement_references_json(agreement_references),
            attestation_text,
            attestation_sha256(attestation_text), attestation_version, operator_id,
            format_utc_ms(now), format_utc_ms(add_months(now, term_months)), request_id,
        ),
    )
    return int(cur.lastrowid), superseded


def list_signoffs(conn: sqlite3.Connection, slug: str) -> list[Mapping[str, Any]]:
    """Every sign-off of the tenant, newest first (history — revoked and
    expired rows included)."""
    return _signoff_rows(conn, slug)


def status_json(status: Optional[AiPolicyStatus]) -> dict[str, Any] | None:
    """The audited shape of a status (no free text beyond the reason)."""
    if status is None:
        return None
    return {
        "requested": status.requested, "effective": status.effective,
        "flags": list(status.flags), "signoff_state": status.signoff.state,
        "signoff_id": status.signoff.signoff_id,
    }

