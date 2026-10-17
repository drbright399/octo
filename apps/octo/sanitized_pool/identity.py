"""M2 — Sanitized-pool client identity (HMAC, not peppered hash).

The pool's per-tenant identity primitive. Each tenant slug is reduced
to a 64-hex-char HMAC-SHA256 digest using a per-bundle 32-byte secret.
Cross-tenant aggregates join on the HMAC. Source-tenant identity is
not recoverable without the secret.

Why HMAC (not salt+hash, not pepper+hash):

  A salted hash with the salt stored beside the hash is reversible
  by anyone who can read the table. A "pepper" + hash protects
  against THAT specific attack but does NOT defeat the own-tenant
  pre-image attack: an operator with write access to ONE tenant can
  inject a unique known IOC, observe the resulting hash, and
  thereafter recognize that tenant's hash anywhere it appears.

  HMAC with a server-held secret defeats that attack — without the
  secret, the operator cannot compute hashes for any tenant slug
  (including their own). They can only see the side-channel of
  "this hash matched this IOC I queried for."

  This was the centerpiece consensus finding across the 2026-05-20
  external review (Gemini, Grok, Deepseek independently raised the
  own-tenant pre-image scenario). M2 in the safety envelope.

The secret material:

  - 32 bytes random.
  - Lives in `<data_root>/secrets/sanitized-pool-hmac.env`, mode 600,
    owned by the OCTO service user.
  - Versioned: each rotation increments the version. Pool rows
    carry the version that produced their HMAC so a rotation can
    be detected + drive a re-extract.
  - Override via `OCTO_SANITIZED_POOL_HMAC_PATH` env var (tests +
    sandboxed deploys).
  - OpenBao-swappable in ~20 lines: app secrets are read through one
    load function (`load_hmac_secret`), per the internal decision to keep
    every application secret behind a single load path.
  - It must sit on disk in usable form: the raw bytes ARE the HMAC key
    (an encrypted copy would only move the problem to the key that
    decrypts it). The protection is the file: created owner-only (0600)
    by `auth.bootstrap.write_secret_file` — never readable by another
    local user, not even while it is being written — in a 0700 directory
    when the directory is new.

The env-file shape mirrors mfa-key.env:

    SANITIZED_POOL_HMAC_VERSION=v1
    SANITIZED_POOL_HMAC_BASE64=<urlsafe-base64-encoded 32-byte secret>
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path
from typing import Optional


# Length constraint on the raw secret material. 32 bytes = 256 bits,
# matching SHA-256's output. Anything shorter materially weakens the
# HMAC; anything longer is allowed but unnecessary.
SECRET_BYTES = 32


def hmac_secret_path() -> Path:
    """Return path to sanitized-pool-hmac.env.

    Defaults to a sibling of the MFA key. Override with the
    OCTO_SANITIZED_POOL_HMAC_PATH env var for tests or sandbox deploys.
    """
    override = os.environ.get("OCTO_SANITIZED_POOL_HMAC_PATH")
    if override:
        return Path(override).resolve()
    # Sibling of mfa-key.env / pepper.env. Same secrets dir.
    from apps.octo.auth.crypto import mfa_key_path
    return mfa_key_path().parent / "sanitized-pool-hmac.env"


def load_hmac_secret() -> tuple[str, bytes]:
    """Return (version_id, secret_bytes). Hard-fail if unreadable.

    Version is the line `SANITIZED_POOL_HMAC_VERSION=v<N>`. Secret is
    the urlsafe-base64-decoded bytes of `SANITIZED_POOL_HMAC_BASE64`.
    """
    path = hmac_secret_path()
    if not path.exists():
        raise FileNotFoundError(
            f"Sanitized-pool HMAC secret not found at {path}. "
            "Set OCTO_SANITIZED_POOL_HMAC_PATH or provision via "
            "`provision_hmac_secret()` during bundle init.",
        )
    text = path.read_text()
    version: Optional[str] = None
    secret_b64: Optional[str] = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k == "SANITIZED_POOL_HMAC_VERSION":
            version = v
        elif k == "SANITIZED_POOL_HMAC_BASE64":
            secret_b64 = v
    if not version or not secret_b64:
        raise ValueError(
            f"HMAC secret file {path} must set "
            "SANITIZED_POOL_HMAC_VERSION and SANITIZED_POOL_HMAC_BASE64",
        )
    try:
        secret_bytes = base64.urlsafe_b64decode(secret_b64)
    except Exception as exc:
        raise ValueError(
            f"SANITIZED_POOL_HMAC_BASE64 is not valid urlsafe-base64: {exc}",
        ) from exc
    if len(secret_bytes) != SECRET_BYTES:
        raise ValueError(
            f"SANITIZED_POOL_HMAC_BASE64 must decode to {SECRET_BYTES} bytes "
            f"(got {len(secret_bytes)})",
        )
    return version, secret_bytes


def generate_hmac_secret() -> bytes:
    """Generate a fresh random 32-byte secret. urlsafe-b64-encode the
    return value before writing to the env file."""
    return secrets.token_bytes(SECRET_BYTES)


def provision_hmac_secret(*, force: bool = False) -> dict[str, str]:
    """Write a fresh secret file. Refuses to overwrite an existing file
    unless `force=True` (which is a deliberate, audited rotation —
    losing the prior secret breaks every existing tenant_hmac).

    Returns a dict with `path` + `version` + `bytes_written`. Plaintext
    is NOT returned — it lives only in the file (mode 600, created that
    way: see the module docstring).

    Mirrors the `provision_mfa_key()` shape so the bootstrap flow can
    be uniform — and writes through the same `write_secret_file`.
    """
    # Deferred like `hmac_secret_path`'s crypto import: the pool's import
    # graph stays free of the auth/bootstrap modules until a provision runs.
    from apps.octo.auth.bootstrap import write_secret_file

    path = hmac_secret_path()
    already = (
        f"HMAC secret already exists at {path}. Refusing to overwrite. "
        "Pass force=True to deliberately rotate (this invalidates every "
        "tenant_hmac currently in the pool — a full re-extract under the "
        "new secret is required; see M9 rotation procedure)."
    )
    if path.exists() and not force:
        raise FileExistsError(already)
    secret = generate_hmac_secret()
    secret_b64 = base64.urlsafe_b64encode(secret).decode()
    text = (
        "SANITIZED_POOL_HMAC_VERSION=v1\n"
        f"SANITIZED_POOL_HMAC_BASE64={secret_b64}\n"
    )
    try:
        write_secret_file(path, text, replace=force)
    except FileExistsError:
        if not os.path.lexists(path):
            raise           # not the secret (e.g. a file where the dir should be)
        # Provisioned by someone else after the check above: theirs stands
        # (overwriting it would orphan every tenant_hmac written under it).
        raise FileExistsError(already) from None
    return {
        "path": str(path),
        "version": "v1",
        "bytes_written": str(len(text)),
    }


# ---------------------------------------------------------------------------
# Identity primitive
# ---------------------------------------------------------------------------

# Module-level memoization. The secret never changes within a process
# lifetime (rotation triggers a service restart), so caching is safe +
# avoids the file-read cost per call.
_CACHED_SECRET: Optional[tuple[str, bytes]] = None


def _get_cached_secret() -> tuple[str, bytes]:
    global _CACHED_SECRET
    if _CACHED_SECRET is None:
        _CACHED_SECRET = load_hmac_secret()
    return _CACHED_SECRET


def reset_cache() -> None:
    """Test/dev helper: force re-load of the secret on next call.
    Production code never calls this — a rotation must restart the
    service."""
    global _CACHED_SECRET
    _CACHED_SECRET = None


def tenant_hmac(slug: str) -> str:
    """Compute the per-bundle HMAC for a tenant slug. Returns the
    64-char lowercase hex digest.

    This is the only function that should appear on any code path that
    writes the source-tenant identity into the pool. The raw slug must
    never appear in `patterns.*`, `sanitization_rejects`, or any other
    pool table column intended for cross-tenant reads.
    """
    if not isinstance(slug, str) or not slug:
        raise ValueError("tenant slug must be a non-empty string")
    _, secret = _get_cached_secret()
    return hmac.new(secret, slug.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_version() -> str:
    """Return the version label of the currently-loaded HMAC secret.

    Recorded on every pool write so a rotation is detectable: a row
    whose `hmac_version` doesn't match the current secret's version
    needs to be re-extracted (see M9 rotation procedure).
    """
    version, _ = _get_cached_secret()
    return version
