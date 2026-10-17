"""Effective AI policy + compliance sign-offs (v0.10, migration 034) — on a
real registry built by the real migrations.

The truth table: requested none / local / cloud × compliance flags [] /
["none"] / ["hipaa"] / ["hipaa","pci"] × sign-off none on record / live /
expired / revoked / signed for other flags. Owner decisions pinned here:
unsigned cloud DEGRADES TO LOCAL; '[]' (never tagged) REQUIRES a sign-off;
'["none"]' does not. Also: the append-only table refuses anything but one
revocation, flags compare canonically (and stored flags that are not
exactly a list of known tags match nothing), a sign-off is dead AT its
expiry, an offboarded / archived tenant runs as 'none', a sign-off names
one agreement per regime, the merge flag algebra, and where a model URL
runs.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.client_provisioning import create_client
from apps.octo.db import connect, transaction
from apps.octo.instances import ai_policy
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401

TEXT = (
    "I have checked this tenant's compliance tags today and the BAA on file "
    "covers cloud processing for them."
)
POLICIES = ("none", "local", "cloud")
FLAG_SETS = ([], ["none"], ["hipaa"], ["hipaa", "pci"])
SCENARIOS = ("no-signoff", "live", "expired", "revoked", "other-flags")


def _refs(flags: list[str]) -> dict[str, str]:
    return {k: f"AGR-{k}-0001" for k in ai_policy.agreement_keys(flags)}


def _sign(slug: str, flags: list[str], *, days_ago: int = 0, term: int = 12,
          now: datetime | None = None) -> int:
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            sid, _ = ai_policy.record_signoff(
                reg, slug, flags=flags, agreement_references=_refs(flags), attestation_text=TEXT,
                attestation_version=ai_policy.ATTESTATION_VERSION, operator_id=1,
                request_id=f"req-{slug}", term_months=term,
                now=now or datetime.now(timezone.utc) - timedelta(days=days_ago),
            )
        return sid
    finally:
        reg.close()


def _revoke(sid: int) -> None:
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            assert ai_policy.revoke_signoff(reg, sid, operator_id=1, reason="client withdrew")
    finally:
        reg.close()


def _tenant(slug: str, policy: str, flags: list[str]) -> None:
    create_client(slug, slug, kind="client", ai_policy=policy,
                  compliance_flags_json=json.dumps(flags))


def _arrange(slug: str, flags: list[str], scenario: str) -> None:
    if scenario == "live":
        _sign(slug, flags)
    elif scenario == "expired":
        _sign(slug, flags, days_ago=400)                 # 12-month term → lapsed
    elif scenario == "revoked":
        _revoke(_sign(slug, flags))
    elif scenario == "other-flags":
        _sign(slug, ["cjis"])                            # never matched these flags


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_effective_policy_truth_table(bedrock_root, scenario):  # noqa: F811
    for policy in POLICIES:
        for flags in FLAG_SETS:
            slug = f"t-{policy}-{len(flags)}-{'n' if flags == ['none'] else 'x'}"
            _tenant(slug, policy, flags)
            _arrange(slug, flags, scenario)
            status = ai_policy.policy_status(slug)
            assert status is not None
            case = (policy, flags, scenario)

            # The sign-off standing depends on flags + record, never on policy.
            if flags == ["none"]:
                expected_state = "not_required"
            else:
                expected_state = {
                    "no-signoff": "required", "live": "live", "expired": "expired",
                    "revoked": "revoked", "other-flags": "flags_changed",
                }[scenario]
            assert status.signoff.state == expected_state, case

            cloud_ok = expected_state in ("not_required", "live")
            expected = {"none": "none", "local": "local",
                        "cloud": "cloud" if cloud_ok else "local"}[policy]
            assert status.requested == policy, case
            assert status.effective == expected, case
            assert ai_policy.effective_ai_policy(slug) == expected, case
            assert ai_policy.ai_allowed(slug, "local") is (expected != "none"), case
            assert ai_policy.ai_allowed(slug, "cloud") is (expected == "cloud"), case

            if policy == "cloud" and not cloud_ok:
                assert status.degraded
                assert status.reason and status.reason.startswith(
                    "cloud requested — degraded to local: "), case
            elif policy == "cloud":
                assert status.reason and status.reason.startswith("cloud permitted — "), case
            else:
                assert status.reason is None, case


def test_degraded_reasons_name_the_flags_and_the_signoff(bedrock_root):  # noqa: F811
    _tenant("hip-co", "cloud", ["hipaa"])
    assert ai_policy.policy_status("hip-co").reason == (
        "cloud requested — degraded to local: sign-off required for [hipaa]")
    _tenant("untagged-co", "cloud", [])
    assert "never been tagged (compliance flags [])" in ai_policy.policy_status("untagged-co").reason
    _tenant("multi-co", "cloud", ["hipaa", "pci"])
    sid = _sign("multi-co", ["hipaa"])
    assert ai_policy.policy_status("multi-co").reason == (
        f"cloud requested — degraded to local: compliance flags changed since sign-off #{sid} "
        "(signed for [hipaa], now [hipaa, pci]) — sign off again")


def test_flags_compare_canonically_and_corrupt_flags_fail_closed(bedrock_root):  # noqa: F811
    create_client("ordered-co", "Ordered", kind="client", ai_policy="cloud",
                  compliance_flags_json='["pci","hipaa","pci"]')
    _sign("ordered-co", ["hipaa", "pci"])
    assert ai_policy.effective_ai_policy("ordered-co") == "cloud"
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET compliance_flags = 'not json' WHERE slug = 'ordered-co'")
    reg.close()
    # Unreadable flags match no sign-off: a sign-off is required, and the
    # reason says to re-tag first.
    status = ai_policy.policy_status("ordered-co")
    assert (status.effective, status.signoff.state) == ("local", "required")
    assert "not a list of known tags — re-tag the tenant" in status.reason


@pytest.mark.parametrize("stored", [
    '["none","HIPAA"]',          # wrong case next to 'none': used to read as ["none"] → cloud
    '["none","hipaa"]',          # 'none' next to a regime (no writer allows it)
    '["none","fedramp"]',        # a tag a newer build knows
    '{"none": true}',            # not a list
    '[null]',
])
def test_stored_flags_that_are_not_known_tags_never_read_as_none(bedrock_root, stored):  # noqa: F811
    """Data this code did not write (bare SQL, a legacy or newer writer —
    compliance_flags has no CHECK): 'none' mixed with anything, or any
    unknown element, must never make cloud need no sign-off."""
    create_client("mixed-co", "Mixed", kind="client", ai_policy="cloud",
                  compliance_flags_json='["none"]')
    assert ai_policy.effective_ai_policy("mixed-co") == "cloud"
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET compliance_flags = ? WHERE slug = 'mixed-co'", (stored,))
    reg.commit()
    reg.close()
    assert ai_policy.flags_readable(stored) is False
    status = ai_policy.policy_status("mixed-co")
    assert (status.effective, status.signoff.state) == ("local", "required"), stored
    assert ai_policy.ai_allowed("mixed-co", "cloud") is False


def test_a_signoff_for_untagged_does_not_cover_flags_that_read_as_untagged(bedrock_root):  # noqa: F811
    """A tenant signed for [] (never tagged) whose stored flags later hold
    something canonical_flags drops ('["HIPAA"]' from a manual fix) must not
    stay cloud: the drop reads as [], which used to equal the sign-off's."""
    _tenant("untagged-co", "cloud", [])
    _sign("untagged-co", [])
    assert ai_policy.effective_ai_policy("untagged-co") == "cloud"
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET compliance_flags = '[\"HIPAA\"]' WHERE slug = 'untagged-co'")
    reg.commit()
    reg.close()
    assert ai_policy.canonical_flags('["HIPAA"]') == []
    status = ai_policy.policy_status("untagged-co")
    assert (status.effective, status.signoff.state) == ("local", "required")
    # Duplicates and order are harmless: still readable.
    assert ai_policy.flags_readable('["pci","hipaa","pci"]') is True
    assert ai_policy.flags_readable('["none","none"]') is True
    assert ai_policy.flags_readable("[]") is True


def test_a_signoff_is_dead_exactly_at_its_expiry(bedrock_root):  # noqa: F811
    """expires_at is the first instant it no longer applies: 1 ms before,
    the tenant runs as cloud; at expires_at exactly, as local."""
    _tenant("edge-co", "cloud", ["hipaa"])
    signed = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
    _sign("edge-co", ["hipaa"], term=1, now=signed)
    expires = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)
    assert ai_policy.policy_status("edge-co", now=expires).signoff.expires_at == (
        "2026-10-28T12:00:00.000Z")
    just_before = ai_policy.policy_status("edge-co", now=expires - timedelta(milliseconds=1))
    assert (just_before.effective, just_before.signoff.state) == ("cloud", "live")
    at = ai_policy.policy_status("edge-co", now=expires)
    assert (at.effective, at.signoff.state) == ("local", "expired")
    assert ai_policy.effective_ai_policy("edge-co", now=expires) == "local"
    assert ai_policy.ai_allowed("edge-co", "cloud", now=expires - timedelta(milliseconds=1)) is True
    assert ai_policy.ai_allowed("edge-co", "cloud", now=expires) is False


@pytest.mark.parametrize("status_", ["offboarded", "archived"])
def test_a_departed_tenant_runs_as_none_whatever_it_asked_for(bedrock_root, status_):  # noqa: F811
    """The relationship — and the consent — ended: a live sign-off or a
    'none' tag no longer clears anything, and not even the local model
    reasons over the departed tenant's data."""
    _tenant("signed-co", "cloud", ["hipaa"])
    _sign("signed-co", ["hipaa"])
    _tenant("none-co", "cloud", ["none"])
    _tenant("local-co", "local", [])
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = ?", (status_,))
    reg.commit()
    reg.close()
    for slug in ("signed-co", "none-co", "local-co"):
        status = ai_policy.policy_status(slug)
        assert status.effective == "none", slug
        assert status.reason == f"tenant {status_} — no model reasons over a departed tenant's data"
        assert ai_policy.ai_allowed(slug, "local") is False
        assert ai_policy.ai_allowed(slug, "cloud") is False


def test_unknown_tenant_and_bad_input_are_none(bedrock_root):  # noqa: F811
    assert ai_policy.effective_ai_policy("nope-co") == "none"
    assert ai_policy.effective_ai_policy("../etc") == "none"
    assert ai_policy.ai_allowed("nope-co", "local") is False
    with pytest.raises(ValueError):
        ai_policy.ai_allowed("nope-co", "moon")


def test_signing_again_supersedes_and_one_unrevoked_row_per_tenant(bedrock_root):  # noqa: F811
    _tenant("acme-corp", "cloud", ["hipaa"])
    first = _sign("acme-corp", ["hipaa"])
    second = _sign("acme-corp", ["hipaa"])
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        rows = {r["id"]: r for r in reg.execute("SELECT * FROM tenant_compliance_signoffs")}
        assert rows[first]["revoked_kind"] == "superseded" and rows[first]["revoked_at"]
        assert rows[second]["revoked_at"] is None
        # The partial unique index: a second unrevoked row is refused.
        with pytest.raises(sqlite3.IntegrityError):
            reg.execute(
                "INSERT INTO tenant_compliance_signoffs (slug, flags_covered, baa_reference, "
                "attestation_text, attestation_sha256, attestation_version, signed_by, "
                "request_id) VALUES ('acme-corp', '[\"hipaa\"]', 'B', ?, ?, 'v', 1, 'r')",
                (TEXT, "a" * 64),
            )
    finally:
        reg.close()
    assert ai_policy.policy_status("acme-corp").signoff.signoff_id == second


def test_signoff_table_is_append_only(bedrock_root):  # noqa: F811
    _tenant("acme-corp", "cloud", ["hipaa"])
    sid = _sign("acme-corp", ["hipaa"])
    reg = connect(paths.registry_db_path())
    try:
        for sql in (
            "DELETE FROM tenant_compliance_signoffs WHERE id = ?",
            "UPDATE tenant_compliance_signoffs SET baa_reference = 'other' WHERE id = ?",
            "UPDATE tenant_compliance_signoffs SET expires_at = '2099-01-01T00:00:00.000Z' WHERE id = ?",
            "UPDATE tenant_compliance_signoffs SET flags_covered = '[\"pci\"]' WHERE id = ?",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                reg.execute(sql, (sid,))
        # Revocation must set all four fields at once (the table's CHECK).
        with pytest.raises(sqlite3.IntegrityError):
            reg.execute(
                "UPDATE tenant_compliance_signoffs SET revoked_at = '2026-09-28T00:00:00.000Z' "
                "WHERE id = ?", (sid,),
            )
    finally:
        reg.close()
    _revoke(sid)
    reg = connect(paths.registry_db_path())
    try:
        # Once revoked, nothing about the row changes again — not even the reason.
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            reg.execute(
                "UPDATE tenant_compliance_signoffs SET revoke_reason = 'rewritten' WHERE id = ?",
                (sid,),
            )
        assert ai_policy.revoke_signoff(reg, sid, operator_id=2, reason="again") is False
        row = reg.execute(
            "SELECT revoked_by, revoke_reason, attestation_sha256 FROM tenant_compliance_signoffs "
            "WHERE id = ?", (sid,),
        ).fetchone()
    finally:
        reg.close()
    assert tuple(row) == (1, "client withdrew", hashlib.sha256(TEXT.encode()).hexdigest())


def test_invalidate_revokes_every_unrevoked_row_with_its_kind(bedrock_root):  # noqa: F811
    _tenant("acme-corp", "cloud", ["hipaa"])
    sid = _sign("acme-corp", ["hipaa"])
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            assert ai_policy.invalidate_signoffs(
                reg, "acme-corp", operator_id=7, kind="flags_changed", reason="flags changed",
            ) == [sid]
            assert ai_policy.invalidate_signoffs(
                reg, "acme-corp", operator_id=7, kind="flags_changed", reason="flags changed",
            ) == []
        with pytest.raises(ValueError):
            ai_policy.invalidate_signoffs(reg, "acme-corp", operator_id=7, kind="whim", reason="x")
    finally:
        reg.close()
    status = ai_policy.policy_status("acme-corp")
    assert (status.effective, status.signoff.state) == ("local", "flags_changed")


@pytest.mark.parametrize("subject, target, added, merged", [
    ([], ["hipaa"], [], ["hipaa"]),                   # an untagged duplicate adds nothing
    (["none"], ["hipaa"], [], ["hipaa"]),             # 'none' is not a regime
    (["hipaa"], ["hipaa", "pci"], [], ["hipaa", "pci"]),
    (["pci"], ["hipaa"], ["pci"], ["hipaa", "pci"]),
    (["pci"], ["none"], ["pci"], ["pci"]),            # "no regime" stops being true
    (["pci"], [], ["pci"], ["pci"]),
    # Untagged data into a 'none' target: "no regime applies" no longer
    # holds for the combined data — back to [], which needs a sign-off.
    ([], ["none"], [], []),
    (["none"], ["none"], [], ["none"]),
    (["none"], [], [], []),
])
def test_merge_flag_algebra(subject, target, added, merged):
    assert ai_policy.regimes_not_covered(subject, target) == added
    assert ai_policy.merged_flags(subject, target) == merged


def test_policy_order_and_term_arithmetic():
    assert [ai_policy.policy_rank(p) for p in ("none", "local", "cloud", "weird")] == [0, 1, 2, 0]
    jan31 = datetime(2027, 1, 31, 12, 0, tzinfo=timezone.utc)
    assert ai_policy.add_months(jan31, 1) == datetime(2027, 2, 28, 12, 0, tzinfo=timezone.utc)
    assert ai_policy.add_months(jan31, 12) == datetime(2028, 1, 31, 12, 0, tzinfo=timezone.utc)
    assert ai_policy.SIGNOFF_TERM_MONTHS_DEFAULT == 12


def test_attestation_template_text_is_pinned_per_version():
    """A shipped version's wording never changes: new wording = new version
    (a sign-off records the version its signer was shown). v2 names the
    instrument each regime requires — a BAA is HIPAA's, not CJIS's."""
    text = ai_policy.ATTESTATION_TEMPLATES["2026-09-28.v1"]
    assert hashlib.sha256(text.encode()).hexdigest() == (
        "79febf86ad321ac65621541bd526e204bcc0bb00d8c328a897fa23e30df1c6f4"
    )
    assert ai_policy.ATTESTATION_VERSION == "2026-09-28.v2"
    v2 = ai_policy.ATTESTATION_TEMPLATES["2026-09-28.v2"]
    assert hashlib.sha256(v2.encode()).hexdigest() == (
        "c54b4bd2bee9683415a68a0ab3883b9dd8797f06881d6aa8cb3e1b27534f12d3"
    )
    for instrument in ("business associate agreement", "CJIS Security Addendum",
                       "service-provider responsibility agreement", "written release",
                       "data-processing agreement"):
        assert instrument in v2



def test_a_signoff_names_one_agreement_per_regime(bedrock_root):  # noqa: F811
    assert ai_policy.agreement_keys(["pci", "hipaa"]) == ["hipaa", "pci"]
    assert ai_policy.agreement_keys([]) == ["untagged"]
    _tenant("multi-co", "cloud", ["cjis", "hipaa"])
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            for refs in ({"hipaa": "BAA-1"}, {"hipaa": "BAA-1", "cjis": "  "},
                         {"hipaa": "BAA-1", "cjis": "CSA-1", "pci": "X"}):
                with pytest.raises(ValueError, match="one agreement for each of: cjis, hipaa"):
                    ai_policy.record_signoff(
                        reg, "multi-co", flags=["cjis", "hipaa"], agreement_references=refs,
                        attestation_text=TEXT, attestation_version=ai_policy.ATTESTATION_VERSION,
                        operator_id=1, request_id="r",
                    )
    finally:
        reg.close()
    sid = _sign("multi-co", ["cjis", "hipaa"])
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        stored = reg.execute(
            "SELECT baa_reference FROM tenant_compliance_signoffs WHERE id = ?", (sid,),
        ).fetchone()[0]
    finally:
        reg.close()
    assert json.loads(stored) == {"cjis": "AGR-cjis-0001", "hipaa": "AGR-hipaa-0001"}
    assert ai_policy.parse_agreement_references(stored) == json.loads(stored)
    # A pre-v2 row (one free-text reference) still reads.
    assert ai_policy.parse_agreement_references("BAA-2026-001") == {"reference": "BAA-2026-001"}


@pytest.mark.parametrize("url, locality", [
    ("http://octo-llm:8101", "local"),            # the bundle's service name (the default)
    ("http://127.0.0.1:8101", "local"),
    ("http://localhost:8101", "local"),
    # scan-sensitive: allow[ip-private] synthetic RFC 1918 address: the private-reads-as-local case under test
    ("http://10.0.0.2:8101", "local"),
    ("http://[::1]:8101", "local"),
    ("http://[fd12::5]:8101", "local"),
    ("https://llm.example.test/v1", "cloud"),     # a dotted name — never resolved here
    ("http://203.0.113.9:8101", "cloud"),
    # Shared address space (100.64/10) reads as cloud. The address is made up, in the /23
    # Tailscale never assigns, so it can never be a real tailnet node.
    # scan-sensitive: allow[ip-tailnet] made-up CGNAT address in the block Tailscale never assigns
    ("http://100.115.92.4:8101", "cloud"),        # shared address space: not this network
    ("http://0.0.0.0:8101", "cloud"),
    ("not a url", "cloud"),
    ("", "cloud"),
    # Integer / hex IPv4 forms have no dot but are ADDRESSES, not service
    # names — the resolver accepts them without DNS (134744072 = a public
    # address). They must not read as a local container name.
    ("http://134744072:8101", "cloud"),
    ("http://0x7f000001:8101", "cloud"),
    ("http://2130706433:8101", "cloud"),
    ("http://llm2:8101", "local"),                # another single-label service name
])
def test_where_a_model_url_runs(url, locality):
    assert ai_policy.locality_of_url(url) == locality
