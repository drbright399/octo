"""Admin operator management.

Operators are humans with admin bearer tokens. Created via explicit CLI call;
plaintext returned exactly once, stored at PBKDF2 hash.
"""
from __future__ import annotations

import json
import uuid
from typing import Optional

from apps.octo import paths
from apps.octo.auth import audit
from apps.octo.auth import core as core_auth
from apps.octo.db import connect, transaction


def create_operator(
    *, username: str, email: str, role: str = "admin",
    scope_slugs: Optional[list[str]] = None,
    actor: str = "system", reason: Optional[str] = None,
) -> dict:
    scope = scope_slugs or ["*"]
    plaintext = core_auth.generate_token()
    h = core_auth.hash_token(plaintext)
    prefix = core_auth.token_prefix(plaintext)
    request_id = str(uuid.uuid4())

    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            cur = reg.execute(
                """
                INSERT INTO operators (username, email, token_hash, token_prefix)
                VALUES (?, ?, ?, ?)
                """,
                (username, email, h, prefix),
            )
            operator_id = cur.lastrowid
            # Verify the role exists
            rrow = reg.execute(
                "SELECT name FROM roles WHERE name = ?", (role,)
            ).fetchone()
            if rrow is None:
                raise ValueError(f"unknown role: {role}")
            reg.execute(
                """
                INSERT INTO operator_roles (operator_id, role_name, scope_slugs)
                VALUES (?, ?, ?)
                """,
                (operator_id, role, json.dumps(scope)),
            )
    finally:
        reg.close()

    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=actor, actor_kind="human" if actor != "system" else "system",
            action="operator_create", target_kind="operator",
            target_id=str(operator_id), client_slug="global",
            after_state={"username": username, "email": email,
                         "role": role, "scope_slugs": scope,
                         "prefix": prefix},
            reason=reason, request_id=request_id,
        ))
    finally:
        g_audit.close()

    return {
        "operator_id": operator_id, "username": username, "email": email,
        "role": role, "scope_slugs": scope, "prefix": prefix,
        "plaintext": plaintext,
    }
