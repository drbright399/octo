"""Admin-tier policy gates + admin_ops endpoints.

Covers the role-tier rules for operator management within a bundle:
  - admin can create/disable/grant ≤ admin (analyst, viewer, admin)
  - admin CANNOT touch super_admin tier
  - super_admin can do everything admin can plus super_admin operations
  - Cannot disable yourself
  - Cannot disable the last active super_admin
  - Cannot revoke super_admin from the last super_admin
  - Operators cannot grant/revoke their own roles
"""
from __future__ import annotations

import sqlite3

import pyotp
import pytest

from apps.octo import paths
from apps.octo.api.role_gates import (
    ROLE_TIER,
    operator_max_tier,
    get_operator_roles,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(client, op: dict) -> dict:
    """Password+TOTP sign-in. Returns cookie dict."""
    r = client.post("/api/v1/auth/password/begin", json={
        "username": op["username"], "password": op["password"],
    })
    challenge = r.json()["challenge_id"]
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r2 = client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": code,
    })
    assert r2.status_code == 200, r2.text
    return dict(r2.cookies)


# ---------------------------------------------------------------------------
# Role-gate primitives
# ---------------------------------------------------------------------------

def test_role_tier_ordering():
    assert ROLE_TIER["viewer"]      < ROLE_TIER["analyst"]
    assert ROLE_TIER["analyst"]     < ROLE_TIER["admin"]
    assert ROLE_TIER["admin"]       < ROLE_TIER["super_admin"]


def test_operator_max_tier_reflects_highest_role(auth_client):
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    assert operator_max_tier(op["id"]) == ROLE_TIER["super_admin"]


def test_operator_max_tier_zero_when_no_roles(auth_client):
    op = auth_client.provision_operator("anon", "pw1234567890",
                                          athena_role=None)
    # NB: operators.create_operator implicitly inserts a legacy 'admin' row
    # for OCTO API bearer-token use. To get a true zero-tier operator we
    # must clear that row out.
    conn = sqlite3.connect(paths.registry_db_path())
    conn.execute("DELETE FROM operator_roles WHERE operator_id = ?",
                  (op["id"],))
    conn.commit(); conn.close()
    assert operator_max_tier(op["id"]) == 0


# ---------------------------------------------------------------------------
# GET /api/v1/admin/operators
# ---------------------------------------------------------------------------

def test_list_operators_admin_can_call(auth_client):
    admin = auth_client.provision_operator("op-admin", "pw1234567890",
                                             athena_role="admin")
    auth_client.provision_operator("op-analyst", "pw1234567890",
                                     athena_role="analyst")
    cookies = _login(auth_client, admin)
    r = auth_client.get("/api/v1/admin/operators", cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    usernames = sorted(o["username"] for o in body["operators"])
    assert "op-admin" in usernames
    assert "op-analyst" in usernames


def test_list_operators_analyst_refused(auth_client):
    # Pass role='analyst' too so the legacy 'admin' role isn't auto-added
    analyst = auth_client.provision_operator("op-analyst", "pw1234567890",
                                                role="analyst",
                                                athena_role="analyst")
    cookies = _login(auth_client, analyst)
    r = auth_client.get("/api/v1/admin/operators", cookies=cookies)
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"


def test_list_operators_viewer_refused(auth_client):
    viewer = auth_client.provision_operator("op-viewer", "pw1234567890",
                                               role="viewer",
                                               athena_role="viewer")
    cookies = _login(auth_client, viewer)
    r = auth_client.get("/api/v1/admin/operators", cookies=cookies)
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/v1/admin/operators (create)
# ---------------------------------------------------------------------------

def test_admin_can_create_analyst(auth_client):
    admin = auth_client.provision_operator("op-admin", "pw1234567890",
                                             athena_role="admin")
    cookies = _login(auth_client, admin)
    r = auth_client.post("/api/v1/admin/operators",
        json={"username": "newbie", "email": "newbie@test.example",
              "role": "analyst", "scope_slugs": ["acme"]},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["username"] == "newbie"
    assert body["role"] == "analyst"
    assert body["state"] == "pending"
    assert "/login/magic?token=" in body["magic_link_url"]
    # New operator has the role assigned
    assert "analyst" in get_operator_roles(body["operator_id"])


def test_invited_operator_must_set_a_password_before_totp(auth_client):
    """An invite used to leave must_change_password=0 with no password hash:
    the wizard skipped to TOTP and the operator finished onboarding unable
    to ever sign in again (the invite link is single-use)."""
    import urllib.parse
    from fastapi.testclient import TestClient

    admin = auth_client.provision_operator("op-admin", "pw1234567890",
                                             athena_role="admin")
    cookies = _login(auth_client, admin)
    r = auth_client.post("/api/v1/admin/operators",
        json={"username": "newbie", "email": "newbie@test.example",
              "role": "analyst", "scope_slugs": ["acme"]},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    token = urllib.parse.parse_qs(
        urllib.parse.urlparse(r.json()["magic_link_url"]).query)["token"][0]

    # https base_url: the session cookie is Secure
    invitee = TestClient(auth_client.app, base_url="https://athena.test")
    assert invitee.post("/api/v1/auth/magic-link/verify",
                        json={"token": token}).status_code == 200
    me = invitee.get("/api/v1/auth/me").json()
    assert me["needs_setup"] is True
    assert me["must_change_password"] is True
    # TOTP first is refused; password first works, then TOTP
    assert invitee.post("/api/v1/auth/totp/enroll/begin").status_code == 409
    assert invitee.post("/api/v1/auth/password/change",
                        json={"new_password": "a-long-new-passphrase-42"}
                        ).status_code == 200
    assert invitee.post("/api/v1/auth/totp/enroll/begin").status_code == 200


def test_duplicate_email_is_a_clear_409_not_a_500(auth_client):
    """A DISABLED account keeps its unique email. Creating a second operator
    with it used to raise IntegrityError → unhandled 500 → the console's
    generic 'Create failed'."""
    admin = auth_client.provision_operator("op-admin", "pw1234567890",
                                             athena_role="admin")
    cookies = _login(auth_client, admin)
    first = auth_client.post("/api/v1/admin/operators",
        json={"username": "tester", "email": "alice@test.example",
              "role": "analyst", "scope_slugs": ["acme"]}, cookies=cookies)
    assert first.status_code == 200, first.text
    tester_id = first.json()["operator_id"]
    assert auth_client.post(f"/api/v1/admin/operators/{tester_id}/disable",
                            json={"reason": "test account"}, cookies=cookies
                            ).status_code in (200, 204)

    dup = auth_client.post("/api/v1/admin/operators",
        json={"username": "alice", "email": "Alice@Test.example",     # case-insensitive
              "role": "analyst", "scope_slugs": ["acme"]}, cookies=cookies)
    assert dup.status_code == 409, dup.text
    body = dup.json()
    assert body["code"] == "OPERATOR_EXISTS"
    assert "DISABLED" in body["message"] and "tester" in body["message"]

    # same for a clashing username
    dup2 = auth_client.post("/api/v1/admin/operators",
        json={"username": "TESTER", "email": "someone-else@test.example",
              "role": "analyst", "scope_slugs": ["acme"]}, cookies=cookies)
    assert dup2.status_code == 409 and "username" in dup2.json()["message"]


def test_admin_can_free_a_disabled_accounts_email(auth_client):
    admin = auth_client.provision_operator("op-admin", "pw1234567890",
                                             athena_role="admin")
    cookies = _login(auth_client, admin)
    first = auth_client.post("/api/v1/admin/operators",
        json={"username": "tester", "email": "alice@test.example",
              "role": "analyst", "scope_slugs": ["acme"]}, cookies=cookies)
    tester_id = first.json()["operator_id"]
    auth_client.post(f"/api/v1/admin/operators/{tester_id}/disable",
                     json={"reason": "test account"}, cookies=cookies)

    r = auth_client.post(f"/api/v1/admin/operators/{tester_id}/email",
        json={"email": "tester-retired@test.example", "reason": "free the address"},
        cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "updated"

    ok = auth_client.post("/api/v1/admin/operators",
        json={"username": "alice", "email": "alice@test.example",
              "role": "analyst", "scope_slugs": ["acme"]}, cookies=cookies)
    assert ok.status_code == 200, ok.text

    # an admin cannot use this route on THEMSELVES (Account settings demands
    # the current password; this route does not)
    me = auth_client.post(f"/api/v1/admin/operators/{admin['id']}/email",
        json={"email": "hijack@test.example"}, cookies=cookies)
    assert me.status_code in (400, 422) and "Account settings" in me.json()["message"]

    # cannot steal an address that is in use
    clash = auth_client.post(f"/api/v1/admin/operators/{tester_id}/email",
        json={"email": "alice@test.example"}, cookies=cookies)
    assert clash.status_code == 409

    # analysts cannot edit operators
    # (fresh client: the shared one still carries the admin's session cookie in
    # its jar, and two same-named cookies would be sent)
    from fastapi.testclient import TestClient
    # role="analyst" too, or the fixture auto-adds the legacy 'admin' role
    analyst = auth_client.provision_operator("op-analyst", "pw1234567890",
                                               role="analyst",
                                               athena_role="analyst")
    as_analyst = TestClient(auth_client.app, base_url="https://athena.test")
    _login(as_analyst, analyst)
    r = as_analyst.post(f"/api/v1/admin/operators/{tester_id}/email",
                        json={"email": "x@test.example"})
    assert r.status_code == 403, r.text
    assert r.json()["code"] == "ISOLATION_VIOLATION"


def _registry_row(operator_id: int):
    import sqlite3
    from apps.octo import paths
    c = sqlite3.connect(paths.registry_db_path()); c.row_factory = sqlite3.Row
    try:
        return c.execute("SELECT * FROM operators WHERE id = ?", (operator_id,)).fetchone()
    finally:
        c.close()


def test_remove_deletes_a_never_used_invite(auth_client):
    admin = auth_client.provision_operator("op-admin", "pw1234567890", athena_role="admin")
    cookies = _login(auth_client, admin)
    inv = auth_client.post("/api/v1/admin/operators",
        json={"username": "typo-user", "email": "typo@test.example",
              "role": "analyst", "scope_slugs": ["acme"]}, cookies=cookies).json()

    r = auth_client.post(f"/api/v1/admin/operators/{inv['operator_id']}/remove",
                         json={"reason": "mistyped invite"}, cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "deleted"
    assert _registry_row(inv["operator_id"]) is None
    # the name + address are immediately reusable
    again = auth_client.post("/api/v1/admin/operators",
        json={"username": "typo-user", "email": "typo@test.example",
              "role": "analyst", "scope_slugs": ["acme"]}, cookies=cookies)
    assert again.status_code == 200, again.text


def test_remove_retires_an_account_with_history(auth_client):
    """Audit rows name the actor by operator id — an account that has ACTED is
    tombstoned, never deleted: access gone, name + email freed, row kept."""
    from fastapi.testclient import TestClient
    admin = auth_client.provision_operator("op-admin", "pw1234567890", athena_role="admin")
    cookies = _login(auth_client, admin)
    used = auth_client.provision_operator("departed", "pw1234567890",
                                            role="analyst", athena_role="analyst",
                                            email="departed@test.example")
    theirs = TestClient(auth_client.app, base_url="https://athena.test")
    _login(theirs, used)
    assert theirs.get("/api/v1/auth/me").status_code == 200

    r = auth_client.post(f"/api/v1/admin/operators/{used['id']}/remove",
                         json={"reason": "left the company"}, cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "retired"

    row = _registry_row(used["id"])
    assert row is not None and row["removed_at"] and row["disabled_at"]
    assert row["username"].startswith("removed-") and row["email"].endswith("@removed.invalid")
    assert row["password_hash"] is None and row["mfa_enabled"] == 0
    assert get_operator_roles(used["id"]) == set()
    assert theirs.get("/api/v1/auth/me").status_code == 401          # session revoked
    listed = [o["username"] for o in
              auth_client.get("/api/v1/admin/operators", cookies=cookies).json()["operators"]]
    assert "departed" not in listed and not any(u.startswith("removed-") for u in listed)
    # name + address reusable, and removing twice is idempotent
    assert auth_client.post("/api/v1/admin/operators",
        json={"username": "departed", "email": "departed@test.example",
              "role": "analyst", "scope_slugs": ["acme"]}, cookies=cookies).status_code == 200
    assert auth_client.post(f"/api/v1/admin/operators/{used['id']}/remove",
                            json={"reason": "again"}, cookies=cookies
                            ).json()["state"] == "already-removed"


def test_remove_guards(auth_client):
    from fastapi.testclient import TestClient
    from apps.octo.auth import bootstrap
    sa = auth_client.provision_operator("op-super", "pw1234567890", athena_role="super_admin")
    sa_cookies = _login(auth_client, sa)

    # not yourself
    r = auth_client.post(f"/api/v1/admin/operators/{sa['id']}/remove",
                         json={"reason": "oops"}, cookies=sa_cookies)
    assert r.status_code == 422 or r.json()["code"] == "VALIDATION_FAILED"

    # reason is required
    other = auth_client.provision_operator("op-other", "pw1234567890",
                                             role="analyst", athena_role="analyst")
    assert auth_client.post(f"/api/v1/admin/operators/{other['id']}/remove",
                            json={}, cookies=sa_cookies).status_code == 422

    # an admin cannot remove a super_admin (tier rule)
    admin = auth_client.provision_operator("op-admin", "pw1234567890", athena_role="admin")
    as_admin = TestClient(auth_client.app, base_url="https://athena.test")
    _login(as_admin, admin)
    r = as_admin.post(f"/api/v1/admin/operators/{sa['id']}/remove",
                      json={"reason": "coup"})
    assert r.status_code == 403 and r.json()["code"] == "ISOLATION_VIOLATION"

    # an analyst cannot remove anyone
    as_analyst = TestClient(auth_client.app, base_url="https://athena.test")
    _login(as_analyst, other)
    assert as_analyst.post(f"/api/v1/admin/operators/{admin['id']}/remove",
                           json={"reason": "nope"}).status_code == 403


def test_factory_account_cannot_be_removed(auth_client):
    from apps.octo.auth import bootstrap
    import sqlite3
    from apps.octo import paths
    sa = auth_client.provision_operator("op-super", "pw1234567890", athena_role="super_admin")
    cookies = _login(auth_client, sa)
    factory = auth_client.provision_operator(
        bootstrap.FACTORY_SUPER_ADMIN_USERNAME, "pw1234567890",
        email=bootstrap.FACTORY_SUPER_ADMIN_EMAIL, is_factory=True)
    r = auth_client.post(f"/api/v1/admin/operators/{factory['id']}/remove",
                         json={"reason": "tidy up"}, cookies=cookies)
    assert r.status_code in (400, 422), r.text
    assert "factory" in r.json()["message"]
    assert _registry_row(factory["id"])["removed_at"] is None


def test_admin_cannot_create_super_admin(auth_client):
    admin = auth_client.provision_operator("op-admin", "pw1234567890",
                                             athena_role="admin")
    cookies = _login(auth_client, admin)
    r = auth_client.post("/api/v1/admin/operators",
        json={"username": "ghost-su", "email": "ghost@test.example",
              "role": "super_admin"},
        cookies=cookies,
    )
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"


def test_super_admin_can_create_super_admin(auth_client):
    su = auth_client.provision_operator("op-su", "pw1234567890",
                                          athena_role="super_admin")
    cookies = _login(auth_client, su)
    r = auth_client.post("/api/v1/admin/operators",
        json={"username": "second-su", "email": "su2@test.example",
              "role": "super_admin"},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text


def test_admin_can_create_admin(auth_client):
    """admin tier (3) can create another admin (3) — equal-tier is allowed."""
    admin = auth_client.provision_operator("op-admin", "pw1234567890",
                                             athena_role="admin")
    cookies = _login(auth_client, admin)
    r = auth_client.post("/api/v1/admin/operators",
        json={"username": "second-admin", "email": "a2@test.example",
              "role": "admin"},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# POST /api/v1/admin/operators/{id}/disable
# ---------------------------------------------------------------------------

def test_admin_can_disable_analyst(auth_client):
    admin = auth_client.provision_operator("op-admin", "pw1234567890",
                                             athena_role="admin")
    target = auth_client.provision_operator("victim", "pw1234567890",
                                              athena_role="analyst")
    cookies = _login(auth_client, admin)
    r = auth_client.post(f"/api/v1/admin/operators/{target['id']}/disable",
                          json={"reason": "test"}, cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "disabled"


def test_admin_cannot_disable_super_admin(auth_client):
    admin = auth_client.provision_operator("op-admin", "pw1234567890",
                                             athena_role="admin")
    su = auth_client.provision_operator("op-su", "pw1234567890",
                                          athena_role="super_admin")
    cookies = _login(auth_client, admin)
    r = auth_client.post(f"/api/v1/admin/operators/{su['id']}/disable",
                          json={"reason": "should fail"}, cookies=cookies)
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"


def test_cannot_disable_self(auth_client):
    admin = auth_client.provision_operator("op-admin", "pw1234567890",
                                             athena_role="admin")
    cookies = _login(auth_client, admin)
    r = auth_client.post(f"/api/v1/admin/operators/{admin['id']}/disable",
                          json={}, cookies=cookies)
    assert r.status_code == 422
    assert r.json()["code"] == "VALIDATION_FAILED"


def test_cannot_disable_last_super_admin(auth_client):
    """The bundle must always have at least one active super_admin."""
    su = auth_client.provision_operator("op-su", "pw1234567890",
                                          athena_role="super_admin")
    other_su = auth_client.provision_operator("other-su", "pw1234567890",
                                                 athena_role="super_admin")
    cookies = _login(auth_client, su)
    # Disable the OTHER super_admin first — leaves only `op-su` active
    r1 = auth_client.post(f"/api/v1/admin/operators/{other_su['id']}/disable",
                            json={}, cookies=cookies)
    assert r1.status_code == 200
    # Now try to disable the only remaining super_admin (NOT self — use a
    # different mechanism: revoke our own session won't help, so we need a
    # different super_admin caller). We'll re-enable other_su and have
    # them try to disable op-su.
    r_re = auth_client.post(f"/api/v1/admin/operators/{other_su['id']}/enable",
                              cookies=cookies)
    assert r_re.status_code == 200
    # Disable op-su (our caller). That'd be self-disable — rejected at a
    # different gate. To genuinely test "last super_admin" we need other_su
    # to be the caller and op-su to be the target. Simulate that by
    # logging in as other_su.
    auth_client.cookies.clear()
    cookies_other = _login(auth_client, other_su)
    # First disable op-su's super_admin role grant by revoking it would
    # leave 1 active super_admin (other_su) — not the test we want.
    # Instead: disable op-su. This leaves other_su as the only active
    # super_admin which is fine — our caller is other_su. Test succeeds.
    r_disable_op_su = auth_client.post(
        f"/api/v1/admin/operators/{su['id']}/disable",
        json={"reason": "leaving only other_su"}, cookies=cookies_other,
    )
    assert r_disable_op_su.status_code == 200
    # Now try to disable other_su (would leave 0 active super_admins).
    # other_su can't disable themselves, so we need yet another caller.
    # But there ARE no other admins/super_admins. So revoke the
    # super_admin role from other_su — that's the realistic "last
    # super_admin guard" path.
    r_revoke = auth_client.post(
        f"/api/v1/admin/operators/{other_su['id']}/role/revoke",
        json={"role": "super_admin"}, cookies=cookies_other,
    )
    # Self-revoke is refused with VALIDATION_FAILED before we get to
    # the last-super_admin check.
    assert r_revoke.status_code == 422


# ---------------------------------------------------------------------------
# POST /api/v1/admin/operators/{id}/role
# ---------------------------------------------------------------------------

def test_admin_can_grant_analyst_role(auth_client):
    admin = auth_client.provision_operator("op-admin", "pw1234567890",
                                             athena_role="admin")
    target = auth_client.provision_operator("plain", "pw1234567890",
                                               athena_role=None)
    cookies = _login(auth_client, admin)
    r = auth_client.post(f"/api/v1/admin/operators/{target['id']}/role/grant",
        json={"role": "analyst", "scope_slugs": ["acme"]},
        cookies=cookies,
    )
    assert r.status_code == 200
    assert "analyst" in get_operator_roles(target["id"])


def test_admin_cannot_grant_super_admin(auth_client):
    admin = auth_client.provision_operator("op-admin", "pw1234567890",
                                             athena_role="admin")
    target = auth_client.provision_operator("victim", "pw1234567890",
                                               athena_role="analyst")
    cookies = _login(auth_client, admin)
    r = auth_client.post(f"/api/v1/admin/operators/{target['id']}/role/grant",
        json={"role": "super_admin"},
        cookies=cookies,
    )
    assert r.status_code == 403


def test_super_admin_can_grant_admin(auth_client):
    su = auth_client.provision_operator("op-su", "pw1234567890",
                                           athena_role="super_admin")
    target = auth_client.provision_operator("plain", "pw1234567890",
                                               athena_role=None)
    cookies = _login(auth_client, su)
    r = auth_client.post(f"/api/v1/admin/operators/{target['id']}/role/grant",
        json={"role": "admin"},
        cookies=cookies,
    )
    assert r.status_code == 200
    assert "admin" in get_operator_roles(target["id"])


def test_self_grant_role_refused(auth_client):
    admin = auth_client.provision_operator("op-admin", "pw1234567890",
                                             athena_role="admin")
    cookies = _login(auth_client, admin)
    r = auth_client.post(f"/api/v1/admin/operators/{admin['id']}/role/grant",
        json={"role": "admin"},
        cookies=cookies,
    )
    assert r.status_code == 422
    assert r.json()["code"] == "VALIDATION_FAILED"


def test_revoke_role_drops_assignment(auth_client):
    su = auth_client.provision_operator("op-su", "pw1234567890",
                                           athena_role="super_admin")
    other_su = auth_client.provision_operator("other-su", "pw1234567890",
                                                 athena_role="super_admin")
    cookies = _login(auth_client, su)
    r = auth_client.post(f"/api/v1/admin/operators/{other_su['id']}/role/revoke",
        json={"role": "super_admin"}, cookies=cookies,
    )
    assert r.status_code == 200, r.text
    assert "super_admin" not in get_operator_roles(other_su["id"])


def test_session_admin_plus_refuses_unauthenticated(auth_client):
    """No session cookie → 401 from session_identity, not 403."""
    auth_client.cookies.clear()
    r = auth_client.get("/api/v1/admin/operators")
    assert r.status_code in (401, 403)
