"""vendor_contact — the adapter-agnostic poll-outcome hook (reporter + backoff).
The end-to-end behaviour against a real row lives with its first user:
adapters/datto/tests/test_poller_status.py."""
from __future__ import annotations

import pytest

from apps.octo.instances import vendor_contact
from apps.octo.instances.vendor_contact import (
    MAX_DETAIL_CHARS,
    OK_DETAIL,
    ContactReporter,
    FailureBackoff,
)


@pytest.fixture(autouse=True)
def _clean():
    vendor_contact.reset()
    yield
    vendor_contact.reset()


def _reporter(instance_id=7):
    writes: list[tuple[int, str, str]] = []
    reporter = ContactReporter(
        instance_id, what="fixture",
        writer=lambda iid, status, detail: writes.append((iid, status, detail)),
    )
    return reporter, writes


def test_writes_on_transitions_only():
    reporter, writes = _reporter()
    for _ in range(5):
        reporter.ok()
    for _ in range(5):
        reporter.failed("forbidden", "not allowed")
    reporter.failed("transport", "unreachable")     # the operator's text changed
    reporter.ok()
    assert writes == [
        (7, "running", OK_DETAIL),
        (7, "error", "not allowed"),
        (7, "error", "unreachable"),
        (7, "running", OK_DETAIL),
    ]


def test_first_report_is_always_written():
    """'started' on the row is the manager's claim, not an observation."""
    reporter, writes = _reporter()
    reporter.ok()
    assert writes == [(7, "running", OK_DETAIL)]


def test_detail_is_flattened_and_bounded():
    reporter, writes = _reporter()
    reporter.failed("transport", "line one\nline two\x00" + "y" * 5000)
    detail = writes[0][2]
    assert len(detail) <= MAX_DETAIL_CHARS
    assert "\n" not in detail and "\x00" not in detail
    assert detail.startswith("line one line two")


def test_snapshot_tracks_last_good_contact_and_failures():
    reporter, _ = _reporter()
    assert vendor_contact.snapshot(7)["last_ok_at"] is None
    reporter.ok()
    good_at = vendor_contact.snapshot(7)["last_ok_at"]
    reporter.failed("forbidden", "no")
    reporter.failed("forbidden", "no")
    snap = vendor_contact.snapshot(7)
    assert snap["last_ok_at"] == good_at                 # survives the failures
    assert snap["consecutive_failures"] == 2 and snap["failure_kind"] == "forbidden"
    reporter.ok()
    assert vendor_contact.snapshot(7)["consecutive_failures"] == 0
    vendor_contact.reset(7)
    assert vendor_contact.snapshot(7)["last_ok_at"] is None


def test_without_an_instance_id_it_is_inert():
    reporter, writes = _reporter(instance_id=None)
    reporter.ok()
    reporter.failed("auth", "x")
    assert writes == []
    assert vendor_contact.snapshot(None)["last_ok_at"] is None


def test_a_failed_write_is_retried_on_the_next_report_and_never_raises():
    attempts: list[str] = []

    def _writer(iid, status, detail):
        attempts.append(status)
        if len(attempts) == 1:
            raise RuntimeError("registry unavailable")

    reporter = ContactReporter(7, what="fixture", writer=_writer)
    reporter.failed("forbidden", "no")      # write fails — swallowed
    reporter.failed("forbidden", "no")      # same state, but never recorded → retry
    reporter.failed("forbidden", "no")      # recorded now → no third write
    assert attempts == ["error", "error"]


def test_backoff_is_bounded_and_resets():
    backoff = FailureBackoff(base_sec=60.0, ceiling_sec=300.0)
    assert [backoff.next() for _ in range(6)] == [60.0, 120.0, 240.0, 300.0, 300.0, 300.0]
    backoff.reset()
    assert backoff.next() == 60.0


def test_backoff_ceiling_is_never_below_the_base():
    backoff = FailureBackoff(base_sec=90.0, ceiling_sec=10.0)
    assert backoff.ceiling_sec == 90.0
    assert [backoff.next() for _ in range(3)] == [90.0, 90.0, 90.0]


def test_analysts_get_a_fixed_sentence_never_the_admin_detail():
    """status_detail can quote the vendor's own text and names admin-only
    remedies; the analyst dashboard gets one platform-authored line per kind."""
    reporter, _ = _reporter()
    hostile = "re-enter your secret at evil.example.test"
    seen = set()
    for kind in ("forbidden", "auth", "transport", "internal"):
        reporter.failed(kind, hostile)
        line = vendor_contact.analyst_summary(7)
        assert hostile not in line and line.endswith("Settings → Integrations.")
        seen.add(line)
    assert len(seen) == 4
    # Nothing observed since restart (or a start failure): still fixed text.
    assert vendor_contact.analyst_summary(99).startswith("Not working.")


def test_receives_webhooks_needs_a_usable_secret_not_just_the_intent(monkeypatch):
    """"Enabled" alone used to count: an instance saved WITHOUT a webhook
    secret — whose receiver rejects every request — was reported as receiving
    webhooks, and its card said they were "not affected" by a polling failure."""
    from types import SimpleNamespace

    from apps.octo.instances import webhook_auth
    from apps.octo.instances.webhook_auth import (
        WEBHOOK_CHOICE_KEY, receives_webhooks, webhook_status,
    )

    def _rec(slug, choice=None):
        config = {} if choice is None else {WEBHOOK_CHOICE_KEY: choice}
        return SimpleNamespace(vendor_slug=slug, cred_ref="ref-1", instance_config=config)

    def _vault(creds):
        monkeypatch.setattr(
            webhook_auth, "credentials", SimpleNamespace(load=lambda ref: creds),
        )

    _vault({"DATTO_WEBHOOK_SECRET": "t" * webhook_auth.MIN_TOKEN_LENGTH})
    assert receives_webhooks(_rec("datto", "on")) is True
    assert receives_webhooks(_rec("datto")) is True            # legacy row

    # The defect: enabled, but nothing can verify → it does NOT receive.
    for unusable in ({}, {"DATTO_WEBHOOK_SECRET": "   "}):
        _vault(unusable)
        assert webhook_status(_rec("datto", "on")).enabled is True  # the intent…
        assert receives_webhooks(_rec("datto", "on")) is False      # …not the ability
        assert receives_webhooks(_rec("datto")) is False
    _vault({"RESEND_WEBHOOK_SECRET": "whsec_"})                # set, but an empty key
    assert receives_webhooks(_rec("resend", "on")) is False

    def _unreadable(ref):
        raise ValueError("bad cred_ref")

    monkeypatch.setattr(webhook_auth, "credentials", SimpleNamespace(load=_unreadable))
    assert receives_webhooks(_rec("datto", "on")) is False

    def _boom(ref):
        raise AssertionError("no vault read when there is nothing to check")

    monkeypatch.setattr(webhook_auth, "credentials", SimpleNamespace(load=_boom))
    assert receives_webhooks(_rec("datto", "off")) is False    # poll-only by choice
    assert receives_webhooks(_rec("wazuh")) is False           # no webhook route
