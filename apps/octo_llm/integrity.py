"""Model-file integrity verification for octo-llm.

Slice 9d (consensus reviewer C5): every model load verifies the
file's sha256 against the pinned hash in `apps/octo_llm/manifest.json`
BEFORE handing the bytes to llama-cpp. A mismatch raises so the
sibling refuses to come up rather than serving a poisoned model.

Verification policy:
  * If the manifest entry has a pinned `sha256` → require an exact
    match, refuse to load on mismatch.
  * If the manifest entry has `sha256: null` → treat as BYOM
    (operator-supplied) and log a WARNING, but allow load. BYOM
    files don't have a factory-blessed hash to compare against; the
    download-broker workstream (slice 5d / #50) will eventually pin
    these.
  * If the model file isn't in the manifest at all → also BYOM with
    a warning, same rationale.

The hash is computed by streaming the file in 4MB chunks so the
8B-parameter ~4.5GB file doesn't blow up memory. Computation is
~30s on a modest CPU for the largest file we ship; this only runs
once per process startup, so the cost is amortized across every
subsequent request.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Optional

_LOG = logging.getLogger("octo_llm.integrity")

# Path to the manifest, relative to this file. octo_llm/integrity.py
# → octo_llm/manifest.json (same directory).
_MANIFEST_PATH = Path(__file__).resolve().parent / "manifest.json"

# Streaming chunk size for sha256 computation. 4MB is a comfortable
# trade-off: small enough to not flood the cache, large enough that
# the syscall overhead is negligible on a 4GB file.
_CHUNK_BYTES = 4 * 1024 * 1024


class ModelIntegrityError(RuntimeError):
    """The on-disk file's sha256 doesn't match the pinned manifest
    entry. Surfacing this as a distinct exception lets the server
    layer log it with a clear cause (model tampered with / wrong
    file dropped / partial download) instead of a generic load
    failure."""


def _read_manifest() -> dict:
    """Parse the manifest. Returns {"manifest_version": ..., "models": [...]}.

    If the manifest file is missing or malformed, returns an empty
    skeleton. Verification then falls into BYOM-warn mode rather
    than blocking startup on a missing manifest — the operator
    might be running a development branch where manifest.json was
    intentionally cleared."""
    try:
        return json.loads(_MANIFEST_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        _LOG.warning(
            "manifest.json not readable (%s); skipping integrity check",
            exc,
        )
        return {"manifest_version": 0, "models": []}


def _pinned_sha256(model_name: str) -> Optional[str]:
    """Look up the pinned sha256 for `model_name` in the manifest.
    Returns the hex digest as a lowercase string, or None if the
    model isn't pinned (either absent from manifest or sha256
    field is null)."""
    manifest = _read_manifest()
    for entry in manifest.get("models", []):
        if entry.get("name") == model_name:
            sha = entry.get("sha256")
            if isinstance(sha, str) and len(sha) == 64:
                return sha.lower()
            return None
    return None


def compute_sha256(path: Path) -> str:
    """Stream-hash a file and return the lowercase hex digest. Used
    by both the verifier AND the model-list endpoint so the UI can
    show 'manifest hash' next to 'computed hash' for super_admin
    diagnostics."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(_CHUNK_BYTES)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def verify_or_raise(model_name: str, path: Path) -> dict:
    """Verify the file at `path` matches the manifest's pinned
    sha256 for `model_name`. Returns a diagnostic dict describing
    the verification result; raises ModelIntegrityError on mismatch.

    Diagnostic dict shape:
      {
        "model_name": "qwen-2.5-3b-q4",
        "status": "verified" | "byom_no_pin" | "byom_unknown_model",
        "expected_sha256": "..." | None,
        "computed_sha256": "...",
      }

    The status field is what the operator surfaces on the
    super_admin model-list endpoint. `verified` is the happy path;
    the two byom_* values warn but don't block.
    """
    if not path.exists():
        raise ModelIntegrityError(
            f"model file not found at {path}",
        )

    expected = _pinned_sha256(model_name)
    computed = compute_sha256(path)

    if expected is None:
        # Either the model isn't in the manifest, or its sha256 field
        # is still null (BYOM path). Warn loudly but allow boot.
        # Caller's responsibility is to surface this to the operator
        # in /v1/healthz so they know they're running an unverified
        # binary.
        in_manifest = any(
            e.get("name") == model_name
            for e in _read_manifest().get("models", [])
        )
        status = "byom_no_pin" if in_manifest else "byom_unknown_model"
        _LOG.warning(
            "octo-llm loading unpinned model %r (status=%s, "
            "computed_sha256=%s) — model integrity NOT verified",
            model_name, status, computed,
        )
        return {
            "model_name": model_name,
            "status": status,
            "expected_sha256": None,
            "computed_sha256": computed,
        }

    if computed != expected:
        raise ModelIntegrityError(
            f"model {model_name!r} sha256 mismatch: "
            f"expected {expected}, computed {computed}. "
            f"Refusing to load — the file at {path} differs from "
            f"the factory-pinned binary."
        )

    _LOG.info(
        "octo-llm verified model %r against pinned sha256 %s",
        model_name, expected,
    )
    return {
        "model_name": model_name,
        "status": "verified",
        "expected_sha256": expected,
        "computed_sha256": computed,
    }
