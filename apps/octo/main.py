"""OCTO core — application entrypoint.

This is what the `octo-core` container's uvicorn process runs:

    uvicorn apps.octo.main:app --host 0.0.0.0 --port 8001

The factory pattern (`create_app(config)`) keeps the deployment story
testable: tests construct an app with in-memory backends + tmp paths;
production reads `OctoConfig` from environment variables.

Boot order:
  1. Load OctoConfig (from env or explicit kwargs).
  2. Construct persistence backends per config (SQLite paths or in-memory).
  3. Run boot_framework() → adapter discovery, widget extraction, system
     widget discovery. AdapterRegistry uses the SQLite backend, so any
     instances persisted in a previous run are restored.
  4. Construct BridgeServerImpl wired to the SQLite audit backend +
     a TemplateExecutor (currently the no-op StubExecutor; real OCTO
     query routing wires here in a later phase).
  5. Construct FastAPI app + mount the bridge router.
  6. Return the app for uvicorn to serve.

This entrypoint runs in a single octo-core container alongside (eventually)
ingest paths + Layer 2 LLM. v1 ships only the bridge surface; ingest
adapters land as `apps/octo/adapters/<slug>/` packages and are picked
up automatically by discovery.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from shared_bridge import (
    QueryTemplate,
    SessionContext,
    TemplateRegistry,
)

from apps.athena.framework.boot import boot_framework
from apps.octo.framework.bridge_router import (
    BearerTokenResolver,
    StaticTokenResolver,
    create_bridge_router,
)
from apps.octo.framework.bridge_server import (
    BridgeServerImpl,
    InMemoryAuditLogBackend,
    TemplateExecutor,
)
from apps.octo.framework.registry import (
    AdapterRegistry,
    InMemoryRegistryBackend,
    RegistryBackend,
)
from apps.octo.framework.sqlite_audit import SqliteAuditLogBackend
from apps.octo.framework.sqlite_registry import SqliteRegistryBackend


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OctoConfig:
    """Runtime configuration for the octo-core entrypoint.

    Production reads from env vars via `OctoConfig.from_env()`. Tests
    construct directly with explicit values.
    """

    # Persistence paths. ":memory:" is supported for tests.
    registry_db_path: str = "/var/lib/octo/state/registry.db"
    audit_db_path: str = "/var/lib/octo/state/bridge_audit.db"

    # Discovery roots. Defaults match the in-repo layout per ADR-005/ADR-006.
    adapters_package: str = "apps.octo.adapters"
    system_widgets_package: str = "apps.athena.widgets.system"

    # Optional: path to a directory the framework should ensure exists on
    # boot (creates registry_db_path's parent if missing). Production sets
    # this to /var/lib/octo/state.
    state_dir: str | None = None

    # Bearer-token bootstrap. v1 only supports static tokens via env; the
    # auth-core integration ships in a later phase. Format:
    #   OCTO_BOOTSTRAP_TOKENS="<token-1>=10:viewer:client_a:sess1,<token-2>=12:admin:client_b:sess2"
    # Each token must be >= BOOTSTRAP_TOKEN_MIN_LENGTH random characters
    # with no whitespace, e.g.
    #   python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
    # A weak token or a malformed entry stops the boot (fail closed).
    # Unset / empty = no bootstrap tokens (the production default).
    bootstrap_tokens_raw: str = ""

    # Hard fault on adapter discovery failure. Default False (log-and-keep-
    # going) lets one bad adapter not take down the whole platform; ops can
    # set OCTO_FAIL_ON_DISCOVERY_FAILURE=1 for stricter staging environments.
    fail_on_discovery_failure: bool = False

    extra: dict[str, Any] = field(default_factory=dict)
    """Reserved for future config that doesn't warrant a top-level field."""

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> OctoConfig:
        e = env if env is not None else os.environ
        return cls(
            registry_db_path=e.get(
                "OCTO_REGISTRY_DB_PATH", cls.__dataclass_fields__["registry_db_path"].default,
            ),
            audit_db_path=e.get(
                "OCTO_AUDIT_DB_PATH", cls.__dataclass_fields__["audit_db_path"].default,
            ),
            adapters_package=e.get(
                "OCTO_ADAPTERS_PACKAGE", cls.__dataclass_fields__["adapters_package"].default,
            ),
            system_widgets_package=e.get(
                "OCTO_SYSTEM_WIDGETS_PACKAGE",
                cls.__dataclass_fields__["system_widgets_package"].default,
            ),
            state_dir=e.get("OCTO_STATE_DIR") or None,
            bootstrap_tokens_raw=e.get("OCTO_BOOTSTRAP_TOKENS", ""),
            fail_on_discovery_failure=_parse_bool(
                e.get("OCTO_FAIL_ON_DISCOVERY_FAILURE", "0"),
            ),
        )


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


#: Minimum length of an OCTO_BOOTSTRAP_TOKENS bearer token. A bootstrap
#: token is a static credential that maps straight to a session (up to
#: super_admin), so it has to carry real entropy: 32 characters of
#: `secrets.token_urlsafe` output is ~190 bits.
BOOTSTRAP_TOKEN_MIN_LENGTH = 32

#: Roles a bootstrap session may carry (SessionContext.operator_role).
BOOTSTRAP_TOKEN_ROLES = ("super_admin", "admin", "analyst", "viewer")

_BOOTSTRAP_ENTRY_FORMAT = "token=operator_id:role:tenant:session_id"
# ASCII digits only (int() alone would also take ' 7', '+7', '1_0' and
# non-ASCII digits), and few enough that int() can never refuse them.
_OPERATOR_ID_RE = re.compile(r"[0-9]{1,18}")


class BootstrapTokenConfigError(ValueError):
    """OCTO_BOOTSTRAP_TOKENS holds an entry that must not be accepted.

    Raised at startup (fail closed: the app does not boot) for a weak
    token and for a malformed entry alike. The message names the entry's
    1-based position in the comma-separated list and the rule it broke,
    never the token or any other part of the entry: a malformed entry
    may have the token in an unexpected place.
    """


def _bootstrap_entry_error(position: int, problem: str) -> BootstrapTokenConfigError:
    return BootstrapTokenConfigError(
        f"OCTO_BOOTSTRAP_TOKENS entry {position}: {problem}"
    )


def _check_bootstrap_token(token: str, position: int) -> None:
    """Raise BootstrapTokenConfigError if `token` is unusable.

    `position` is the 1-based index of the entry in the comma-separated
    OCTO_BOOTSTRAP_TOKENS value. The token is deliberately left out of
    the message (and of any exception context) so a startup crash log
    cannot leak it.
    """
    if any(ch.isspace() for ch in token):
        raise _bootstrap_entry_error(
            position,
            "the token contains whitespace. A bootstrap token must be one "
            f"unbroken string of at least {BOOTSTRAP_TOKEN_MIN_LENGTH} random "
            "characters.",
        )
    if len(token) < BOOTSTRAP_TOKEN_MIN_LENGTH:
        raise _bootstrap_entry_error(
            position,
            "the token is shorter than the minimum of "
            f"{BOOTSTRAP_TOKEN_MIN_LENGTH} characters. Generate one with: "
            "python3 -c 'import secrets; print(secrets.token_urlsafe(32))'",
        )


def _parse_bootstrap_tokens(raw: str) -> dict[str, SessionContext]:
    """Parse a comma-separated tokens string into a {token: SessionContext} dict.

    Format: 'token=operator_id:role:tenant:session_id,token2=...'
    Empty / whitespace-only inputs return an empty dict (no bootstrap
    tokens: the production default). Whitespace around a whole entry
    (e.g. after a comma) is ignored, and so is an empty entry (a
    trailing or doubled comma): neither carries a token.

    Every other entry must be complete and valid, or the whole value is
    refused with BootstrapTokenConfigError (fail closed, nothing is
    skipped silently):
      - the entry has a '=' between the token and its session fields;
      - the token is at least BOOTSTRAP_TOKEN_MIN_LENGTH characters with
        no whitespace, and appears only once in the list;
      - there are exactly four ':'-separated session fields;
      - operator_id is a positive whole number (ASCII digits);
      - role is one of BOOTSTRAP_TOKEN_ROLES;
      - tenant and session_id are non-empty with no whitespace.
    The error names the entry's position and the rule, never a value.
    """
    tokens: dict[str, SessionContext] = {}
    first_position: dict[str, int] = {}
    raw = raw.strip()
    if not raw:
        return tokens
    for position, entry in enumerate(raw.split(","), start=1):
        entry = entry.strip()
        if not entry:
            continue
        if "=" not in entry:
            raise _bootstrap_entry_error(
                position,
                f"no '=' between the token and its session fields "
                f"(expected {_BOOTSTRAP_ENTRY_FORMAT}).",
            )
        token, payload = entry.split("=", 1)
        _check_bootstrap_token(token, position)
        if token in first_position:
            raise _bootstrap_entry_error(
                position,
                f"the token repeats the one in entry {first_position[token]}; "
                "each bootstrap token must be unique.",
            )
        parts = payload.split(":")
        if len(parts) != 4:
            raise _bootstrap_entry_error(
                position,
                f"expected 4 ':'-separated session fields after '=' "
                f"({_BOOTSTRAP_ENTRY_FORMAT}), found {len(parts)}.",
            )
        op_id_str, role, tenant, session_id = parts
        if not _OPERATOR_ID_RE.fullmatch(op_id_str) or int(op_id_str) < 1:
            raise _bootstrap_entry_error(
                position,
                "operator_id must be a positive whole number (ASCII digits only).",
            )
        op_id = int(op_id_str)
        if role not in BOOTSTRAP_TOKEN_ROLES:
            raise _bootstrap_entry_error(
                position,
                f"unknown role; expected one of {', '.join(BOOTSTRAP_TOKEN_ROLES)}.",
            )
        for field_name, value in (("tenant", tenant), ("session_id", session_id)):
            if not value or any(ch.isspace() for ch in value):
                raise _bootstrap_entry_error(
                    position,
                    f"{field_name} must be non-empty with no whitespace.",
                )
        first_position[token] = position
        tokens[token] = SessionContext(
            operator_id=op_id,
            operator_role=role,  # type: ignore[arg-type]
            session_tenant=tenant,
            session_id=session_id,
        )
    return tokens


# ---------------------------------------------------------------------------
# Default executor — placeholder for v1
# ---------------------------------------------------------------------------

class _UnsupportedExecutor:
    """v1 default — every template execution returns a structured 501-style
    error message via empty rows + a rejection_reason in audit.

    Real OCTO query routing wires a TemplateExecutor that reads from the
    appropriate per-tenant SQLite database based on the template definition.
    That ships in a later phase (Phase G.2 — per-source DB segregation, #43).
    For now the executor is a placeholder so the bridge surface can be
    exercised without data being available.
    """

    def execute(
        self,
        template: QueryTemplate,
        params: dict[str, Any],  # noqa: ARG002
        session: SessionContext,  # noqa: ARG002
    ) -> list[dict[str, Any]]:
        return []


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app(
    config: OctoConfig | None = None,
    *,
    executor: TemplateExecutor | None = None,
    token_resolver: BearerTokenResolver | None = None,
    template_registry: TemplateRegistry | None = None,
) -> FastAPI:
    """Build the OCTO FastAPI app.

    Args:
        config: OctoConfig; defaults to OctoConfig.from_env().
        executor: TemplateExecutor; production wires the SQLite query
            executor here. Defaults to _UnsupportedExecutor.
        token_resolver: BearerTokenResolver; defaults to StaticTokenResolver
            seeded from `OCTO_BOOTSTRAP_TOKENS`. Production deployments
            should swap in an auth-core-backed resolver.
        template_registry: TemplateRegistry; defaults to an empty registry.
            Adapters that bring templates will register them here at boot
            in a later phase.

    Returns:
        FastAPI app ready to be served by uvicorn.

    Raises:
        BootstrapTokenConfigError: OCTO_BOOTSTRAP_TOKENS holds a token
            that is too short, contains whitespace or repeats, or an
            entry that is malformed (see `_parse_bootstrap_tokens`).
            Checked first, so a bad value stops the boot before any state
            is touched (also when a `token_resolver` is passed and the
            value is unused).
    """
    cfg = config or OctoConfig.from_env()

    # Validate the bootstrap tokens before anything else: a weak static
    # bearer token or a malformed entry must stop the boot loudly, before
    # any state dir or DB file is created.
    bootstrap_sessions = _parse_bootstrap_tokens(cfg.bootstrap_tokens_raw)

    # State directory — make sure it exists if persistence paths are real
    if cfg.state_dir:
        Path(cfg.state_dir).mkdir(parents=True, exist_ok=True)

    # Persistence backends
    registry_backend: RegistryBackend
    if cfg.registry_db_path == ":memory:":
        registry_backend = InMemoryRegistryBackend()
    else:
        Path(cfg.registry_db_path).parent.mkdir(parents=True, exist_ok=True)
        # Apply any pending forward migrations BEFORE handing the path off
        # to SqliteRegistryBackend — the backend assumes the schema it
        # queries is present. Idempotent; no-op when the DB is already at
        # the latest user_version. Without this, a bundle running with an
        # older registry.db file (e.g. when octo-updater rolls forward
        # but `init_data_root` is never re-run) silently 500s on any
        # endpoint that touches a not-yet-applied table.
        from apps.octo.auth.bootstrap import ensure_registry_migrations_applied
        ensure_registry_migrations_applied(cfg.registry_db_path)
        registry_backend = SqliteRegistryBackend(cfg.registry_db_path)

    if cfg.audit_db_path == ":memory:":
        audit_backend = InMemoryAuditLogBackend()
    else:
        Path(cfg.audit_db_path).parent.mkdir(parents=True, exist_ok=True)
        audit_backend = SqliteAuditLogBackend(cfg.audit_db_path)

    # Boot the framework — wires registries + runs all three discovery passes
    adapter_registry = AdapterRegistry(backend=registry_backend)
    booted = boot_framework(
        adapters_package=cfg.adapters_package,
        system_widgets_package=cfg.system_widgets_package,
        adapter_registry=adapter_registry,
    )

    if cfg.fail_on_discovery_failure and booted.report.has_failures():
        # Surface failure summary in the exception so logs make it actionable
        details = "\n".join(booted.report.summary_lines())
        msg = f"OCTO boot failed (fail_on_discovery_failure=True):\n{details}"
        raise RuntimeError(msg)

    # Bridge surface
    server = BridgeServerImpl(
        templates=template_registry or TemplateRegistry(),
        executor=executor or _UnsupportedExecutor(),
        audit=audit_backend,
    )

    # Token resolution. v1 default: static tokens from env.
    resolver = token_resolver or StaticTokenResolver(bootstrap_sessions)

    app = FastAPI(
        title="OCTO Core",
        description="Athena/OCTO data plane — bridge contract surface.",
        version="0.1.0",
    )

    # Stash boot artifacts on app.state so health endpoints, ops tooling,
    # and integration tests can read them out without going through globals.
    app.state.octo_config = cfg
    app.state.booted_framework = booted
    app.state.bridge_server = server
    app.state.audit_backend = audit_backend
    app.state.registry_backend = registry_backend

    # Mount the bridge router
    app.include_router(create_bridge_router(server=server, token_resolver=resolver))

    # Top-level liveness — no auth, no bridge involvement, just confirms
    # the process is up. /bridge/v1/health confirms the bridge surface
    # itself; this confirms the Python process is up regardless of bridge
    # state.
    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict[str, Any]:
        return {
            "ok": True,
            "service": "octo-core",
            "boot_failures": booted.report.has_failures(),
            "adapter_count": len(booted.report.adapters.registered),
            "system_widget_count": len(booted.report.system_widgets.registered),
        }

    return app


# ---------------------------------------------------------------------------
# Module-level app for uvicorn
# ---------------------------------------------------------------------------

# `uvicorn apps.octo.main:app` resolves this attribute when the worker
# starts. Lazy via __getattr__ so plain imports of create_app + OctoConfig
# don't trigger discovery + DB file creation as a side effect.
_cached_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    global _cached_app
    if name == "app":
        if _cached_app is None:
            _cached_app = create_app()
        return _cached_app
    raise AttributeError(f"module 'apps.octo.main' has no attribute {name!r}")
