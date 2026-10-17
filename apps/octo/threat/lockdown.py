"""Lockdown requests — LIFE-SAFETY FIRST.

Rick (2026-10-02 23:21): "911 and life saving systems should NEVER be
blocked. They should be isolated and protected above all else. Even if a
network is compromised they need to continue operating and then recover when
the situation is handled."

So every lockdown request — a client's "Lock down my network and contact my
analyst", an analyst's request — is BUILT here and nowhere else, and:
  * EXCLUDES every `life_safety`-tagged asset and path of the tenant,
    explicitly, by name, in the record (`excluded`), whatever the caller
    asked for: an asked-for target that IS one of them — under any spelling
    — is moved to `excluded`, never kept in `scope`;
  * compares CANONICAL identities, never raw strings: a device by its short
    host name (case-blind; `DISPATCH-01`, `dispatch-01.example.local` and
    `CORP\\dispatch-01` are one host), an address or network by what it covers
    (`192.0.2.167` and `192.0.0.0/16` both touch a tagged `192.0.2.0/24`);
  * FAILS CLOSED twice over:
      - when the tag list cannot be read, no request is built
        (`LockdownRefused`) — a request that might include a 911 system is
        never written;
      - a target that cannot be CHECKED against the list — a reference with
        no host name or address in it (a vendor device id), a host name at a
        tenant whose life-safety assets are tagged by address, an address at
        a tenant whose are tagged by name (nothing here resolves one into
        the other) — is kept OUT of `scope` and listed in `excluded` as
        "needs an analyst's check" (`unverified`), never assumed clear;
  * SAYS SO: the record's `notice` is LIFE_SAFETY_NOTICE;
  * EXECUTES NOTHING in slice 1 (`executes: False`; the record's
    `executed` column is CHECKed to 0). Building a protective enclave for
    those systems is a future project, planned with the tenant and the
    relevant authorities — never improvised by Athena.

A perimeter target (the site's or the tenant's gateway) is never itself a
life-safety asset: it stays in `scope`, and the `excluded` list names the
paths the perimeter block must keep open.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from apps.octo.threat import registry
from apps.octo.threat.identity import Network, canonical

LIFE_SAFETY_NOTICE = "911 / life-safety systems are never blocked"
UNVERIFIED_WHY = ("could not be checked against the 911 / life-safety list — an analyst "
                  "confirms it is not one of them before anything is blocked")
PERIMETER_KINDS = ("site_perimeter", "tenant_perimeter")


class LockdownRefused(Exception):
    """The life-safety list could not be read — no request is built."""


def _overlaps(a: Network, b: Network) -> bool:
    return a.version == b.version and a.overlaps(b)


@dataclass
class _Protected:
    hosts: set[str] = field(default_factory=set)
    nets: list[Network] = field(default_factory=list)

    def check(self, ref: Any) -> str:
        """'protected' (a life-safety asset or path) | 'clear' | 'unverified'."""
        ident = canonical(ref)
        if ident is None:
            return "unverified"
        if ident.kind == "host":
            if ident.host in self.hosts:
                return "protected"
            # A name cannot be checked against an address-tagged path here.
            return "unverified" if self.nets else "clear"
        assert ident.net is not None
        if any(_overlaps(ident.net, n) for n in self.nets):
            return "protected"
        # An address cannot be checked against a name-tagged device here.
        return "unverified" if self.hosts else "clear"


def _protected(tagged: list[registry.AssetTag]) -> _Protected:
    out = _Protected()
    for t in tagged:
        ident = canonical(t.device_ref)
        if ident is None:
            # An uncomparable tag would make every target uncheckable: the
            # tag API refuses one; an old row is matched by its text only.
            out.hosts.add(str(t.device_ref).strip().lower())
        elif ident.kind == "host":
            out.hosts.add(ident.host)
        else:
            assert ident.net is not None
            out.nets.append(ident.net)
    return out


@dataclass
class LockdownRequest:
    scope: list[dict[str, Any]] = field(default_factory=list)
    excluded: list[dict[str, Any]] = field(default_factory=list)
    notice: str = LIFE_SAFETY_NOTICE
    executes: bool = False

    @property
    def needs_review(self) -> bool:
        """A target was kept out because it could not be checked."""
        return any(e.get("unverified") for e in self.excluded)

    def as_dict(self) -> dict[str, Any]:
        return {"scope": list(self.scope), "excluded": list(self.excluded),
                "notice": self.notice, "executes": self.executes,
                "needs_review": self.needs_review}


def _tagged(slug: str) -> list[registry.AssetTag]:
    try:
        return registry.life_safety(slug)
    except registry.RegistryUnavailable:
        raise LockdownRefused("the life-safety asset list could not be read — no lockdown "
                              "request was built (911 / life-safety systems are never "
                              "blocked)") from None


def build(slug: str, *, device_ref: Optional[str], site_key: Optional[str],
          extra_targets: Optional[list[dict[str, Any]]] = None) -> LockdownRequest:
    """The request for one incident: its device (else its site's perimeter,
    else the tenant's), plus any `extra_targets` ({kind, ref}) — minus every
    life-safety asset and path, which are listed in `excluded`, and minus
    every target that cannot be checked against them (listed in `excluded`
    as `unverified`)."""
    tagged = _tagged(slug)
    guard = _protected(tagged)
    excluded = [{"kind": t.ref_kind, "ref": t.device_ref, "tag": registry.LIFE_SAFETY,
                 "why": LIFE_SAFETY_NOTICE} for t in tagged]
    wanted: list[dict[str, Any]] = []
    if device_ref:
        wanted.append({"kind": "device", "ref": device_ref.strip()})
    elif site_key:
        wanted.append({"kind": "site_perimeter", "ref": site_key})
    else:
        wanted.append({"kind": "tenant_perimeter", "ref": slug})
    for t in extra_targets or []:
        if isinstance(t, dict) and isinstance(t.get("ref"), str) and t["ref"].strip():
            kind = t.get("kind") if t.get("kind") in ("device", "path") else "device"
            wanted.append({"kind": kind, "ref": t["ref"].strip()})
    scope: list[dict[str, Any]] = []
    for t in wanted:
        listed = {str(e["ref"]).lower() for e in excluded}
        if t in scope or t["ref"].lower() in listed:
            continue                          # already in scope, or already carved out
        verdict = "clear" if t["kind"] in PERIMETER_KINDS else guard.check(t["ref"])
        if verdict == "protected":
            # Another spelling of a tagged asset (an FQDN, another case, an
            # address on a tagged path): named too, so the record shows why
            # the asked-for target is not in scope.
            excluded.append({**t, "tag": registry.LIFE_SAFETY, "why": LIFE_SAFETY_NOTICE,
                             "matched": True})
        elif verdict == "unverified":
            excluded.append({**t, "why": UNVERIFIED_WHY, "unverified": True})
        else:
            scope.append(t)
    return LockdownRequest(scope=scope, excluded=excluded)


def never_includes_life_safety(req: LockdownRequest, slug: str) -> bool:
    """The invariant, checked again just before a request is written, with
    the SAME canonical comparison and a fresh read of the list: no target
    in `scope` is a life-safety asset or path, or could not be checked."""
    guard = _protected(_tagged(slug))
    return all(t.get("kind") in PERIMETER_KINDS or guard.check(t.get("ref")) == "clear"
               for t in req.scope)
