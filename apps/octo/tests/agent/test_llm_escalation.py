"""Tests for LLM-on-uncertain escalation (Task #119c)."""
from __future__ import annotations

import sqlite3

from apps.octo.agent import llm_escalation as esc
from apps.octo.agent.heuristic_l1 import TriageFeatures


def _row(**fields) -> sqlite3.Row:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    cols = ", ".join(fields)
    qs = ", ".join(["?"] * len(fields))
    conn.execute(f"CREATE TABLE e ({cols})")
    conn.execute(f"INSERT INTO e VALUES ({qs})", tuple(fields.values()))
    return conn.execute("SELECT * FROM e").fetchone()


UNCERTAIN_FEATURES = TriageFeatures(severity="medium", has_indicator=False)
CLEAR_FEATURES = TriageFeatures(severity="critical", has_indicator=False)
EVENT = _row(id=1, severity="medium", event_type="alert",
             source_host="web-01", source="datto", summary="")

LLM_OK = {
    "disposition": "escalate", "disposition_reason": "coordinated scan pattern",
    "confidence": 0.82, "suggested_severity": "high",
    "model_version": "granite-3b", "took_ms": 120,
}


# --- AutonomousRateLimiter -------------------------------------------------

def test_rate_limiter_caps_per_tenant():
    t = [0.0]
    lim = esc.AutonomousRateLimiter(per_tenant_per_min=2, bundle_per_min=99,
                                    clock=lambda: t[0])
    assert lim.allow("a") and lim.allow("a")   # 2 allowed
    assert lim.allow("a") is False             # 3rd capped
    assert lim.allow("b") is True              # different tenant ok


def test_rate_limiter_window_slides():
    t = [0.0]
    lim = esc.AutonomousRateLimiter(per_tenant_per_min=1, bundle_per_min=99,
                                    clock=lambda: t[0])
    assert lim.allow("a") is True
    assert lim.allow("a") is False
    t[0] = 61.0                                # past the 60s window
    assert lim.allow("a") is True


def test_rate_limiter_bundle_ceiling():
    t = [0.0]
    lim = esc.AutonomousRateLimiter(per_tenant_per_min=99, bundle_per_min=2,
                                    clock=lambda: t[0])
    assert lim.allow("a") and lim.allow("b")
    assert lim.allow("c") is False             # bundle ceiling hit


# --- escalate_uncertain ----------------------------------------------------

def test_escalate_returns_decision_on_success(monkeypatch):
    monkeypatch.setattr(esc, "_call_octo_llm_triage", lambda payload: LLM_OK)
    d = esc.escalate_uncertain(EVENT, UNCERTAIN_FEATURES, "acme")
    assert d is not None
    assert d.disposition == "escalate"
    assert d.suggested_severity == "high"
    assert d.confidence == 0.82
    assert d.rationale.startswith("(LLM)")
    assert d.note_text() == "[escalate] (LLM) coordinated scan pattern"


def test_escalate_fail_closed_on_error(monkeypatch):
    def boom(payload):
        raise RuntimeError("octo-llm down")
    monkeypatch.setattr(esc, "_call_octo_llm_triage", boom)
    assert esc.escalate_uncertain(EVENT, UNCERTAIN_FEATURES, "acme") is None


def test_escalate_fail_closed_on_malformed(monkeypatch):
    monkeypatch.setattr(esc, "_call_octo_llm_triage", lambda payload: {"nope": 1})
    assert esc.escalate_uncertain(EVENT, UNCERTAIN_FEATURES, "acme") is None


def test_escalate_rejects_bad_disposition(monkeypatch):
    bad = {**LLM_OK, "disposition": "delete_everything"}
    monkeypatch.setattr(esc, "_call_octo_llm_triage", lambda payload: bad)
    assert esc.escalate_uncertain(EVENT, UNCERTAIN_FEATURES, "acme") is None


def test_event_summary_synthesized_when_blank():
    s = esc._event_summary(EVENT)
    assert "web-01" in s and "datto" in s and "medium" in s


# --- make_llm_decider routing ----------------------------------------------

def _decider(monkeypatch, *, bundle=True, consent=True, llm=LLM_OK, calls=None):
    monkeypatch.setattr(esc, "bundle_llm_enabled", lambda: bundle)
    monkeypatch.setattr(esc, "tenant_ai_consumption_allowed", lambda slug, **kw: consent)

    def fake_call(payload):
        if calls is not None:
            calls.append(payload)
        if isinstance(llm, Exception):
            raise llm
        return llm
    monkeypatch.setattr(esc, "_call_octo_llm_triage", fake_call)
    return esc.make_llm_decider()


def test_decider_skips_llm_for_clear_disposition(monkeypatch):
    calls: list = []
    decide = _decider(monkeypatch, calls=calls)
    d = decide(CLEAR_FEATURES, EVENT, "acme")
    assert d.disposition == "escalate"
    assert calls == []  # model never consulted for a clear case


def test_decider_keeps_heuristic_when_bundle_off(monkeypatch):
    calls: list = []
    decide = _decider(monkeypatch, bundle=False, calls=calls)
    d = decide(UNCERTAIN_FEATURES, EVENT, "acme")
    assert d.disposition == "uncertain"
    assert calls == []


def test_decider_keeps_heuristic_without_consent(monkeypatch):
    calls: list = []
    decide = _decider(monkeypatch, consent=False, calls=calls)
    d = decide(UNCERTAIN_FEATURES, EVENT, "acme")
    assert d.disposition == "uncertain"
    assert calls == []


def test_decider_uses_llm_on_uncertain(monkeypatch):
    calls: list = []
    decide = _decider(monkeypatch, calls=calls)
    d = decide(UNCERTAIN_FEATURES, EVENT, "acme")
    assert d.disposition == "escalate"          # LLM refined it
    assert d.rationale.startswith("(LLM)")
    assert len(calls) == 1


def test_decider_fail_closed_on_llm_error(monkeypatch):
    decide = _decider(monkeypatch, llm=RuntimeError("down"))
    d = decide(UNCERTAIN_FEATURES, EVENT, "acme")
    assert d.disposition == "uncertain"         # heuristic preserved


def test_decider_respects_rate_cap(monkeypatch):
    monkeypatch.setattr(esc, "bundle_llm_enabled", lambda: True)
    monkeypatch.setattr(esc, "tenant_ai_consumption_allowed", lambda slug, **kw: True)
    calls: list = []
    monkeypatch.setattr(esc, "_call_octo_llm_triage",
                        lambda p: calls.append(p) or LLM_OK)

    class _NoBudget:
        def allow(self, slug): return False
    decide = esc.make_llm_decider(rate_limiter=_NoBudget())
    d = decide(UNCERTAIN_FEATURES, EVENT, "acme")
    assert d.disposition == "uncertain"
    assert calls == []                          # rate-capped → no call


# --- gates against a real (empty) registry ---------------------------------

def test_bundle_llm_disabled_by_default(triage_data_root):
    assert esc.bundle_llm_enabled() is False     # no bundle_config row


def test_consent_is_opt_in_per_tenant(triage_data_root):
    """The EFFECTIVE AI policy (v0.10) gates escalation: 'none' by default →
    no escalation; 'local' escalates to the local octo-llm. 'cloud' is
    honoured only with a live compliance sign-off — the tenant here has no
    flags ('[]', never tagged), which REQUIRES one, so an unsigned 'cloud'
    runs as 'local': it still escalates to the LOCAL model, and a cloud
    model would be refused. Tagged ["none"] needs no sign-off: cloud is
    honoured. Unknown tenant → fail closed everywhere."""
    import sqlite3 as _sqlite

    from apps.octo import paths
    from apps.octo.tests.auth.test_search_events import _register_client

    assert esc.tenant_ai_consumption_allowed("acme") is False   # unknown tenant
    assert esc.tenant_ai_consumption_allowed("acme", locality="cloud") is False
    _register_client("acme")
    assert esc.tenant_ai_consumption_allowed("acme") is False   # default 'none'
    cases = (
        # (ai_policy, compliance_flags, local allowed, cloud allowed)
        ("local", "[]", True, False),
        ("cloud", "[]", True, False),          # unsigned cloud → local
        ("cloud", '["hipaa"]', True, False),   # unsigned cloud → local
        ("cloud", '["none"]', True, True),     # no regime: cloud honoured
        ("none", '["none"]', False, False),
    )
    for policy, flags, local_ok, cloud_ok in cases:
        conn = _sqlite.connect(paths.registry_db_path())
        conn.execute(
            "UPDATE clients SET ai_policy = ?, compliance_flags = ? WHERE slug = 'acme'",
            (policy, flags),
        )
        conn.commit(); conn.close()
        assert esc.tenant_ai_consumption_allowed("acme") is local_ok, (policy, flags)
        assert esc.tenant_ai_consumption_allowed("acme", locality="local") is local_ok
        assert esc.tenant_ai_consumption_allowed("acme", locality="cloud") is cloud_ok, (policy, flags)


def test_decider_escalates_to_the_local_model_on_the_effective_policy(triage_data_root, monkeypatch):
    """The real gate (only the octo-llm socket is faked): the decider asks
    for the LOCAL locality. A tenant that asked for 'cloud' without a
    sign-off is degraded to local — it escalates (octo-llm is local); a
    'none' tenant never does."""
    import sqlite3 as _sqlite

    from apps.octo import paths
    from apps.octo.tests.auth.test_search_events import _register_client

    monkeypatch.setattr(esc, "bundle_llm_enabled", lambda: True)
    calls: list = []
    monkeypatch.setattr(esc, "_call_octo_llm_triage", lambda p: calls.append(p) or LLM_OK)
    _register_client("acme")
    _register_client("globex")
    conn = _sqlite.connect(paths.registry_db_path())
    conn.execute("UPDATE clients SET ai_policy = 'cloud', compliance_flags = '[\"hipaa\"]' "
                 "WHERE slug = 'acme'")
    conn.commit(); conn.close()
    decide = esc.make_llm_decider()
    assert decide(UNCERTAIN_FEATURES, EVENT, "acme").disposition == "escalate"
    assert [c["tenant_scope_slug"] for c in calls] == ["acme"]
    assert decide(UNCERTAIN_FEATURES, EVENT, "globex").disposition == "uncertain"   # 'none'
    assert len(calls) == 1
    assert esc.octo_llm_locality() == "local"


def test_an_off_deployment_llm_url_escalates_only_tenants_cleared_for_cloud(
    triage_data_root, monkeypatch,
):
    """OCTO_LLM_URL pointed off the deployment: every escalation is a cloud
    call, so a tenant degraded to local (cloud asked, no sign-off) or plain
    local keeps its heuristic decision; one tagged 'none' and asking for
    cloud (cleared, no sign-off needed) escalates. No env var opens the
    sign-off gate."""
    import sqlite3 as _sqlite

    from apps.octo import paths
    from apps.octo.tests.auth.test_search_events import _register_client

    monkeypatch.setattr(esc, "bundle_llm_enabled", lambda: True)
    monkeypatch.setenv("OCTO_LLM_URL", "https://llm.example.test")
    calls: list = []
    monkeypatch.setattr(esc, "_call_octo_llm_triage", lambda p: calls.append(p) or LLM_OK)
    for slug in ("acme", "globex", "initech"):
        _register_client(slug)
    conn = _sqlite.connect(paths.registry_db_path())
    conn.execute("UPDATE clients SET ai_policy = 'cloud', compliance_flags = '[\"hipaa\"]' "
                 "WHERE slug = 'acme'")
    conn.execute("UPDATE clients SET ai_policy = 'local' WHERE slug = 'globex'")
    conn.execute("UPDATE clients SET ai_policy = 'cloud', compliance_flags = '[\"none\"]' "
                 "WHERE slug = 'initech'")
    conn.commit(); conn.close()
    assert esc.octo_llm_locality() == "cloud"
    decide = esc.make_llm_decider()
    assert decide(UNCERTAIN_FEATURES, EVENT, "acme").disposition == "uncertain"
    assert decide(UNCERTAIN_FEATURES, EVENT, "globex").disposition == "uncertain"
    assert decide(UNCERTAIN_FEATURES, EVENT, "initech").disposition == "escalate"
    assert [c["tenant_scope_slug"] for c in calls] == ["initech"]


def test_worker_uses_llm_decider_end_to_end(triage_data_root, monkeypatch):
    """Full path: worker → LLM decider → octo-llm (mocked) → agent_note
    carries the model-reasoned disposition + (LLM) rationale."""
    import sqlite3 as _sqlite

    from apps.octo.agent.worker import process_tenant_once
    from apps.octo.tests.auth.test_search_events import (
        _apply_events_db_migration, _register_client,
    )

    _register_client("acme")
    cdir = triage_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    # A single medium-severity event → heuristic says 'uncertain' → LLM path.
    conn = _sqlite.connect(cdir / "events.db")
    conn.execute(
        "INSERT INTO events (received_at, source, source_host, event_type, "
        "severity, payload, payload_sha256, summary) VALUES "
        "(strftime('%Y-%m-%dT%H:%M:%fZ','now'),'datto','h','alert','medium','{}',?, '')",
        ("a" * 64,),
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(esc, "bundle_llm_enabled", lambda: True)
    monkeypatch.setattr(esc, "tenant_ai_consumption_allowed", lambda slug, **kw: True)
    monkeypatch.setattr(esc, "_call_octo_llm_triage", lambda payload: LLM_OK)

    result = process_tenant_once("acme", decide=esc.make_llm_decider(), backfill=True)
    assert result.processed == 1
    assert result.by_disposition == {"escalate": 1}  # LLM upgraded it

    conn = _sqlite.connect(cdir / "events.db")
    conn.row_factory = _sqlite.Row
    try:
        note = conn.execute(
            "SELECT disposition, note_text FROM agent_notes "
            "WHERE query_kind='auto_enrich'"
        ).fetchone()
    finally:
        conn.close()
    assert note["disposition"] == "escalate"
    assert "(LLM)" in note["note_text"]
