"""notify_threat() — the paging ladder: the analysts IN SCOPE are paged (not
only admins), each step fires once (idempotent request ids, whatever reruns),
T+60 is audited, an acknowledgement stops the ladder and a raise clears it
(the ladder restarts), Red pages again at T+4 h inside business hours and
then in the daily 08:00 digest. E-mails go through a fake mailer and never
name the client, a device or an indicator."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from apps.octo.threat import engine, notify, store
from apps.octo.threat.tests.conftest import (
    A,
    B,
    add_operator,
    audit_rows,
    disable_operator,
    notices,
)

# A Saturday 03:00 in the bundle's zone (UTC 08:00): outside business hours.
T0 = datetime(2026, 10, 3, 8, 0, tzinfo=timezone.utc)


@pytest.fixture
def ops(troot):
    return {
        "alice": add_operator("alice", "analyst", [A]),          # in scope
        "bob": add_operator("bob", "analyst", [B]),              # another tenant
        "carol": add_operator("carol", "admin"),                 # '*'
        "dave": add_operator("dave", "super_admin"),
        "erin": add_operator("erin", "viewer", [A]),             # a client user: never
        "frank": add_operator("frank", "analyst", [A]),
    }


def _black(at: datetime = T0, key: str = "acme-corp|ws-01|analyst|") -> store.Incident:
    return store.open_incident(A, tier="black", rule_id="B6", rule_version=1, key=key,
                               summary="someone is controlling the screen", scope="device",
                               opened_by="1", reason="the client called", device_ref="ws-01",
                               now=at).incident


def _red(at: datetime = T0) -> store.Incident:
    return store.open_incident(A, tier="red", rule_id="R8", rule_version=1,
                               key="acme-corp|ws-02|analyst|event:9",
                               summary="confirmed threat", scope="device", opened_by="1",
                               reason="a confirmed malware verdict on ws-02",
                               device_ref="ws-02", now=at).incident


def _run(inc: store.Incident, at: datetime) -> list[notify.Sent]:
    fresh = store.get(A, inc.id)
    return engine.page_now(fresh, tenant_name="Acme Corp", now=at)


def test_analysts_in_scope_are_paged_with_admins_and_super_admins(ops, mailer):
    disable_operator(ops["frank"])
    inc = _black()
    (sent,) = _run(inc, T0)
    who = set(sent.recipients)
    assert who == {ops["alice"], ops["carol"], ops["dave"]}
    assert ops["bob"] not in who and ops["erin"] not in who and ops["frank"] not in who
    rows = notices("threat_black")
    assert {r["recipient_id"] for r in rows} == who
    assert all("Acme Corp" in r["title"] for r in rows)       # in-app names the client
    # The e-mail copy never names the client, a device or the summary.
    assert len(mailer.sent) == 3
    for _to, subject, body in mailer.sent:
        text = f"{subject}\n{body}".lower()
        assert "acme" not in text and "ws-01" not in text and "controlling" not in text
        assert "black" in text


def test_each_black_step_fires_once(ops, mailer):
    inc = _black()
    assert len(_run(inc, T0)) == 1
    assert _run(inc, T0) == []                                     # same time: nothing new
    assert _run(inc, T0 + timedelta(minutes=2)) == []
    (step2,) = _run(inc, T0 + timedelta(minutes=5))
    assert step2.request_id.startswith(f"inc:{A}:{inc.id}:step2@")
    (step3,) = _run(inc, T0 + timedelta(minutes=15))
    assert set(step3.recipients) == {ops["dave"]}                 # the super_admins
    (step4,) = _run(inc, T0 + timedelta(minutes=30))
    assert ops["alice"] in step4.recipients and ops["carol"] in step4.recipients
    assert _run(inc, T0 + timedelta(minutes=31)) == []
    (step5,) = _run(inc, T0 + timedelta(minutes=60))
    assert step5.request_id.startswith(f"inc:{A}:{inc.id}:step5@")
    assert store.get(A, inc.id).escalation_step == 5
    # Re-sending a step's notices directly is idempotent per recipient.
    again = notify.send(A, kind="threat_black", title="x", body="y",
                        request_id=step2.request_id)
    assert again.notices == []


def test_a_missed_run_pages_t0_and_only_the_latest_step(ops, mailer):
    inc = _black()
    sent = _run(inc, T0 + timedelta(minutes=95))                   # the worker was down
    assert [s.request_id.split(":")[3].split("@")[0] for s in sent] == ["step1", "step6"]
    assert len(audit_rows("incident.unacked_60m")) == 1


def test_t_plus_60_is_audited_once(ops, mailer):
    inc = _black()
    _run(inc, T0)
    _run(inc, T0 + timedelta(minutes=59))
    assert audit_rows("incident.unacked_60m") == []
    _run(inc, T0 + timedelta(minutes=60))
    _run(inc, T0 + timedelta(minutes=90))
    (row,) = audit_rows("incident.unacked_60m")
    assert row["actor"] == "system:tier-engine" and row["actor_kind"] == "system"
    assert row["client_slug"] == A and row["target_id"] == str(inc.id)


def test_ack_stops_the_ladder_and_a_raise_clears_it(ops, mailer):
    inc = _red()
    _run(inc, T0)
    store.ack(A, inc.id, by=str(ops["alice"]), now=T0 + timedelta(minutes=1))
    assert _run(inc, T0 + timedelta(hours=6)) == []                # acknowledged: silent
    assert audit_rows("incident.unacked_60m") == []
    raised = store.raise_to_black(A, inc.id, by=str(ops["carol"]), reason="the client called",
                                  now=T0 + timedelta(hours=7))
    assert not raised.acked and raised.escalation_step == 0
    (t0,) = _run(raised, T0 + timedelta(hours=7))                 # the Black ladder at T0
    assert t0.request_id.startswith(f"inc:{A}:{inc.id}:step1@2026-10-03T15:00")
    assert {r["kind"] for r in notices()} >= {"threat_red", "threat_black"}


def test_red_pages_at_t0_then_t_plus_4h_in_business_hours(ops, mailer, monkeypatch):
    monkeypatch.setenv(notify.TZ_ENV, "America/Chicago")
    inc = _red()                                                   # Saturday 03:00 local
    (t0,) = _run(inc, T0)
    assert {n["kind"] for n in notices()} == {"threat_red"}
    # T+4 h is Saturday 07:00 local: the page waits for Monday 08:00.
    assert _run(inc, T0 + timedelta(hours=4)) == []
    assert _run(inc, T0 + timedelta(hours=30)) == []               # Sunday
    monday = datetime(2026, 10, 5, 13, 0, tzinfo=timezone.utc)     # 08:00 CDT
    (again,) = _run(inc, monday)
    assert again.request_id.split(":")[3].startswith("step3")
    assert len(audit_rows("incident.unacked_60m")) == 1            # Red is audited too


def test_the_daily_digest_lists_unacknowledged_reds_once_a_day(ops, mailer, monkeypatch):
    monkeypatch.setenv(notify.TZ_ENV, "America/Chicago")
    inc = _red()
    early = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)       # 07:00 CDT
    assert notify.red_digest({A: [store.get(A, inc.id)]}, early,
                             tenant_names={A: "Acme Corp"}) == []
    at = datetime(2026, 10, 4, 13, 5, tzinfo=timezone.utc)          # 08:05 CDT
    (d,) = notify.red_digest({A: [store.get(A, inc.id)]}, at, tenant_names={A: "Acme Corp"})
    assert d.request_id == f"digest:2026-10-04:{A}" and d.recipients
    assert notify.red_digest({A: [store.get(A, inc.id)]}, at + timedelta(hours=2),
                             tenant_names={A: "Acme Corp"})[0].notices == []
    store.ack(A, inc.id, by=str(ops["alice"]), now=at)
    nxt = datetime(2026, 10, 5, 13, 5, tzinfo=timezone.utc)
    assert notify.red_digest({A: [store.get(A, inc.id)]}, nxt,
                             tenant_names={A: "Acme Corp"}) == []


def test_an_acknowledged_idle_black_reminds_then_reescalates(ops, mailer):
    inc = _black()
    _run(inc, T0)
    acked = store.ack(A, inc.id, by=str(ops["alice"]), now=T0 + timedelta(minutes=3))
    at = T0 + timedelta(minutes=3)
    assert notify.acked_followup(acked, at + timedelta(hours=1), last_activity=at,
                                 tenant_name="Acme Corp") == []
    (remind,) = notify.acked_followup(acked, at + timedelta(hours=2), last_activity=at,
                                      tenant_name="Acme Corp")
    assert remind.recipients == [ops["alice"]]
    sent = notify.acked_followup(acked, at + timedelta(hours=4), last_activity=at,
                                 tenant_name="Acme Corp")
    assert [s.recipients for s in sent][-1] == sorted([ops["carol"], ops["dave"]])


def test_no_mailer_configured_records_not_configured(ops, mailer):
    mailer.configured = False
    _run(_black(), T0)
    assert {n["email_state"] for n in notices("threat_black")} == {"not_configured"}
    assert mailer.sent == []


def test_a_page_that_could_not_be_written_is_sent_again(ops, mailer, monkeypatch):
    """A step is DONE only when its page was written: the T0 notice failing
    (the registry busy past its timeout) leaves the ladder at step 0 — the
    next pass pages T0 again (never lost), audited as a failed page."""
    inc = _black()
    real_send = notify.send
    monkeypatch.setattr(notify, "send", lambda *a, **kw: notify.Sent(
        request_id=kw.get("request_id", ""), error="OperationalError"))
    (failed,) = _run(inc, T0)
    assert failed.error == "OperationalError"
    assert store.get(A, inc.id).escalation_step == 0
    assert notices("threat_black") == []
    assert audit_rows("incident.page_failed")
    assert audit_rows("incident.escalate_step") == []
    monkeypatch.setattr(notify, "send", real_send)
    (sent,) = _run(inc, T0 + timedelta(minutes=1))
    assert sent.error is None and sent.recipients
    assert store.get(A, inc.id).escalation_step == 1
    assert notices("threat_black")


def test_the_step_is_audited_before_it_is_recorded(ops, mailer, monkeypatch):
    inc = _black()

    def broken(*_a, **_kw):
        raise store.StoreError("disk full")

    monkeypatch.setattr(store, "set_ladder", broken)
    _run(inc, T0)
    assert audit_rows("incident.escalate_step")          # the row came first …
    assert audit_rows("incident.escalate_step_failed")   # … and says it was not recorded
    assert store.get(A, inc.id).escalation_step == 0


def test_admin_notices_mail_a_fixed_neutral_text(ops, mailer):
    """A registry / incident change told to the other admins: the in-app
    notice carries the detail; the e-mail (a third-party provider) never the
    tenant, a device, a binding or anyone's free text."""
    sent = notify.notify_admins(kind="threat_registry", slug=A, exclude=ops["carol"],
                                title="Asset tag 'life_safety' set on dispatch-01",
                                body="Operator #3 tagged dispatch-01 at acme-corp: the 911 "
                                     "console in the back office",
                                request_id="tag:1:set")
    assert sent.recipients == [ops["dave"]]
    (_to, subject, body) = mailer.sent[-1]
    text = f"{subject}\n{body}".lower()
    for word in ("acme", "dispatch-01", "911 console", "back office", "life_safety"):
        assert word not in text
    assert "sign in to athena" in text
    # And a send() with no e-mail text of its own never mails its in-app text.
    notify.send(A, kind="threat_registry", title="dispatch-01 at Acme Corp",
                body="dispatch-01 at Acme Corp", request_id="x:1")
    assert all("dispatch-01" not in f"{s}{b}" for _t, s, b in mailer.sent)
