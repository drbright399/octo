"""Readiness probe — can this bundle actually serve, not merely "is the
process up".

`/healthz` stays a pure liveness check. `/readyz` is what the container
healthcheck probes: MFA + credential-vault keys present, registry schema current,
data root writable. Without it a bundle with a missing secrets mount or a
failed boot migration reported (healthy) while every auth + DB route 500'd.

The response names failing CHECKS only — never paths or values.
"""
from __future__ import annotations

import os
import sqlite3

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from apps.octo import paths


def _check_mfa_key() -> None:
    from apps.octo.auth import crypto
    crypto.load_mfa_key()


def _check_credentials_key() -> None:
    from apps.octo.credentials import key_file_path
    if not os.access(key_file_path(), os.R_OK):
        raise FileNotFoundError("adapter credentials key unreadable")


def _check_registry_schema() -> None:
    from apps.octo.auth.bootstrap import _registry_migration_numbers
    expected = max(_registry_migration_numbers())
    conn = sqlite3.connect(
        f"file:{paths.registry_db_path()}?mode=ro", uri=True, timeout=3
    )
    try:
        current = conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()
    if current < expected:
        raise RuntimeError(f"registry at v{current}, code expects v{expected}")


def _check_data_root_writable() -> None:
    if not os.access(paths.data_root(), os.W_OK | os.X_OK):
        raise PermissionError("data root not writable")


_CHECKS = (
    ("mfa_key", _check_mfa_key),
    ("credentials_key", _check_credentials_key),
    ("registry_schema", _check_registry_schema),
    ("data_root_writable", _check_data_root_writable),
)


def run_checks() -> dict[str, bool]:
    results: dict[str, bool] = {}
    for name, check in _CHECKS:
        try:
            check()
            results[name] = True
        except Exception:  # noqa: BLE001 — any failure = not ready
            results[name] = False
    return results


def install_readiness_route(app: FastAPI) -> None:
    @app.get("/readyz", tags=["meta"])
    def readyz():
        checks = run_checks()
        ready = all(checks.values())
        return JSONResponse(
            status_code=200 if ready else 503,
            content={"ready": ready, "checks": checks},
        )
