"""The Ask-Octo bridge (POST /api/v1/agent-query) honours the tenant's
EFFECTIVE AI policy (v0.10) — on the real app, registry and audit chain;
only the octo-llm socket is faked (httpx in the router).

  - 'none' (the default for every tenant) → 412, audited
    'octo_llm_query_tenant_ai_none', and octo-llm is never called;
  - 'local' → answered by the local octo-llm;
  - 'cloud' without a live compliance sign-off → degraded to 'local' and
    answered LOCALLY (octo-llm is the bundle's own sibling), the response
    and the audit row saying so;
  - 'cloud' with a live sign-off → answered, still locally: there is no
    cloud model in OCTO, so nothing leaves the deployment either way;
  - an OCTO_LLM_URL pointing OFF the deployment makes octo-llm a cloud
    endpoint: only a tenant cleared for cloud is answered — an environment
    variable never opens the sign-off gate.
"""
from __future__ import annotations

import json

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.instances import ai_policy
from apps.octo.tests.auth.test_agent_query import (
    _ensure_client,
    _ensure_events_db,
    _login,
    _MockOctoLLM,
    _patch_octo_llm,
    _set_llm_flag,
)

QUERY = {
    "ref_kind": "event", "ref_id": 7, "query_kind": "tell_me_more",
    "heuristic_note": "Three failed SSH logins in 30s from one host",
}


def _sign(slug: str, flags: list[str]) -> None:
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            ai_policy.record_signoff(
                reg, slug, flags=flags,
                agreement_references={k: f"AGR-{k}-0002" for k in ai_policy.agreement_keys(flags)},
                attestation_text="Checked the tags today; the agreements cover cloud processing.",
                attestation_version=ai_policy.ATTESTATION_VERSION, operator_id=1,
                request_id=f"r-{slug}",
            )
    finally:
        reg.close()


def _set_policy(slug: str, policy: str, flags: str = "[]") -> None:
    reg = connect(paths.registry_db_path())
    try:
        reg.execute("UPDATE clients SET ai_policy = ?, compliance_flags = ? WHERE slug = ?",
                    (policy, flags, slug))
        reg.commit()
    finally:
        reg.close()


def _audit(action_prefix: str) -> list[dict]:
    g = connect(paths.global_audit_db_path(), read_only=True)
    try:
        return [
            {**dict(r), "after": json.loads(r["after_state"]) if r["after_state"] else None}
            for r in g.execute("SELECT * FROM audit_log WHERE action LIKE ? ORDER BY id",
                               (action_prefix + "%",))
        ]
    finally:
        g.close()


def _analyst(client) -> None:
    op = client.provision_operator(
        "alice", "Hunter22!Hunter22!", role="analyst", athena_role="analyst",
        scope_slugs=["*"], l2_llm_granted=True,
    )
    _login(client, op)


def _ask(client, slug: str):
    mock = _MockOctoLLM()
    with _patch_octo_llm(mock):
        r = client.post("/api/v1/agent-query", json={"client_slug": slug, **QUERY})
    return r, mock


def test_a_none_tenant_gets_no_llm_answer_and_the_refusal_is_audited(auth_client):
    _ensure_client("acme")
    _ensure_events_db("acme")
    _set_policy("acme", "none")
    _analyst(auth_client)
    _set_llm_flag(True)

    r, mock = _ask(auth_client, "acme")
    assert r.status_code == 412, r.text
    assert "effective AI policy 'none'" in r.json()["message"]
    assert mock.enrich_calls == []                         # octo-llm never saw it
    (row,) = _audit("octo_llm_query_tenant_ai_none")
    assert row["target_id"] == "acme:event:7"
    assert row["after"] == {"query_kind": "tell_me_more", "effective_ai_policy": "none"}
    assert _audit("octo_llm_query_tell_me_more") == []
    edb = paths.client_dir("acme") / "events.db"
    conn = connect(edb, read_only=True)
    try:
        assert conn.execute("SELECT COUNT(*) FROM agent_notes").fetchone()[0] == 0
    finally:
        conn.close()


def test_an_unsigned_cloud_tenant_is_answered_as_local(auth_client):
    _ensure_client("acme")
    _ensure_events_db("acme")
    _set_policy("acme", "cloud", '["hipaa"]')              # no sign-off on record
    assert ai_policy.effective_ai_policy("acme") == "local"
    _analyst(auth_client)
    _set_llm_flag(True)

    r, mock = _ask(auth_client, "acme")
    assert r.status_code == 200, r.text
    assert (r.json()["effective_ai_policy"], r.json()["llm_locality"]) == ("local", "local")
    assert len(mock.enrich_calls) == 1
    (row,) = _audit("octo_llm_query_tell_me_more")
    assert (row["after"]["effective_ai_policy"], row["after"]["llm_locality"]) == ("local", "local")


def test_local_and_signed_cloud_tenants_are_answered_by_the_local_model(auth_client):
    for slug in ("acme", "globex"):
        _ensure_client(slug)
        _ensure_events_db(slug)
    _set_policy("acme", "local")
    _set_policy("globex", "cloud", '["pci"]')
    _sign("globex", ["pci"])
    _analyst(auth_client)
    _set_llm_flag(True)

    r, _ = _ask(auth_client, "acme")
    assert r.status_code == 200 and r.json()["effective_ai_policy"] == "local"
    r, mock = _ask(auth_client, "globex")
    assert r.status_code == 200, r.text
    assert (r.json()["effective_ai_policy"], r.json()["llm_locality"]) == ("cloud", "local")
    assert len(mock.enrich_calls) == 1


def test_an_off_deployment_llm_url_is_a_cloud_endpoint(auth_client, monkeypatch):
    """OCTO_LLM_URL pointed at a hosted endpoint: the call leaves the
    deployment, so the tenant gate asks for 'cloud'. A local tenant — and a
    'cloud' tenant degraded to local for want of a sign-off — is refused
    (412, audited, octo-llm never called); a tenant cleared for cloud is
    answered, the response and audit row saying the model ran in the cloud."""
    for slug in ("acme", "globex", "initech"):
        _ensure_client(slug)
        _ensure_events_db(slug)
    _set_policy("acme", "local")
    _set_policy("initech", "cloud", '["hipaa"]')          # unsigned → runs as local
    _set_policy("globex", "cloud", '["pci"]')
    _sign("globex", ["pci"])
    _analyst(auth_client)
    _set_llm_flag(True)
    monkeypatch.setenv("OCTO_LLM_URL", "https://llm.example.test")

    for slug in ("acme", "initech"):
        r, mock = _ask(auth_client, slug)
        assert r.status_code == 412, r.text
        assert "outside this deployment" in r.json()["message"]
        assert mock.enrich_calls == []
    refused = _audit("octo_llm_query_tenant_ai_locality")
    assert [row["target_id"] for row in refused] == ["acme:event:7", "initech:event:7"]
    assert refused[0]["after"] == {"query_kind": "tell_me_more", "effective_ai_policy": "local",
                                   "llm_locality": "cloud"}

    r, mock = _ask(auth_client, "globex")
    assert r.status_code == 200, r.text
    assert (r.json()["effective_ai_policy"], r.json()["llm_locality"]) == ("cloud", "cloud")
    assert len(mock.enrich_calls) == 1
    (row,) = _audit("octo_llm_query_tell_me_more")
    assert (row["after"]["effective_ai_policy"], row["after"]["llm_locality"]) == ("cloud", "cloud")
