"""Adapter-credential vault implementation.

The encrypt/decrypt primitives are copied verbatim from
`apps.octo.auth.crypto` (Fernet, `v<n>:<token>` framing) per the
security-invariants memory — algorithm preserved, key separated.

Key file format (mirrors mfa-key.env shape):

    ADAPTER_CREDENTIALS_KEY_VERSION=v1
    ADAPTER_CREDENTIALS_KEY_BASE64=<urlsafe-base64 32-byte Fernet key>

Path: `<secrets-dir>/adapter-credentials-key.env`, overridable via the
`OCTO_ADAPTER_CREDENTIALS_KEY_PATH` env var. Always mode 600.

`ensure_key_file()` auto-generates the key on first boot — distinct
from MFA key handling, which requires a separate provisioning script.
Reason: the MFA key was bootstrapped manually during G.1 launch; the
adapter credentials vault has no installed-base, and asking operators
to run a provisioning script before the first integration is friction
we don't need. Auto-generation still writes mode 600 and never
overwrites an existing file.
"""
from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path

from cryptography.fernet import Fernet

from apps.octo.auth.config import pepper_path

_VERSIONED_RE = re.compile(r"^(v\d+):(.+)$")


def key_file_path() -> Path:
    """Return path to adapter-credentials-key.env. Override via
    `OCTO_ADAPTER_CREDENTIALS_KEY_PATH` for tests."""
    override = os.environ.get("OCTO_ADAPTER_CREDENTIALS_KEY_PATH")
    if override:
        return Path(override).resolve()
    return pepper_path().parent / "adapter-credentials-key.env"


def ensure_key_file() -> Path:
    """Create the credentials key file (mode 600) if it doesn't already
    exist. Returns the path. Safe to call repeatedly — never overwrites
    an existing file."""
    path = key_file_path()
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key().decode()
    body = (
        "# Adapter credentials vault key. Generated automatically on first boot.\n"
        "# Rotating this key invalidates every stored cred_ref — handle deliberately.\n"
        "ADAPTER_CREDENTIALS_KEY_VERSION=v1\n"
        f"ADAPTER_CREDENTIALS_KEY_BASE64={key}\n"
    )
    # Write+chmod atomically via O_CREAT|O_EXCL so concurrent boots don't
    # race. If another process won the race, fall through and read theirs.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return path
    try:
        os.write(fd, body.encode())
    finally:
        os.close(fd)
    # Belt-and-suspenders chmod in case the process umask widened mode.
    os.chmod(path, 0o600)
    return path


def _load_key() -> tuple[str, bytes]:
    """Return (version_id, fernet_key_bytes). Hard-fail if missing."""
    path = key_file_path()
    if not path.exists():
        raise FileNotFoundError(
            f"Adapter credentials key not found at {path}. "
            "Call ensure_key_file() at boot or set "
            "OCTO_ADAPTER_CREDENTIALS_KEY_PATH."
        )
    text = path.read_text()
    version: str | None = None
    key_b64: str | None = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if k == "ADAPTER_CREDENTIALS_KEY_VERSION":
            version = v
        elif k == "ADAPTER_CREDENTIALS_KEY_BASE64":
            key_b64 = v
    if not version or not key_b64:
        raise ValueError(
            f"Adapter credentials key file {path} must set "
            "ADAPTER_CREDENTIALS_KEY_VERSION + ADAPTER_CREDENTIALS_KEY_BASE64"
        )
    try:
        key_bytes = base64.urlsafe_b64decode(key_b64)
    except Exception as exc:
        raise ValueError(
            f"ADAPTER_CREDENTIALS_KEY_BASE64 is not valid urlsafe-base64: {exc}"
        ) from exc
    if len(key_bytes) != 32:
        raise ValueError(
            f"ADAPTER_CREDENTIALS_KEY_BASE64 must decode to 32 bytes "
            f"(got {len(key_bytes)})"
        )
    return version, key_b64.encode()


def _encrypt_at_rest(plaintext: bytes) -> str:
    version, key = _load_key()
    f = Fernet(key)
    return f"{version}:{f.encrypt(plaintext).decode()}"


def _decrypt_at_rest(ciphertext: str) -> bytes:
    m = _VERSIONED_RE.match(ciphertext)
    if not m:
        raise ValueError("cred_ref is not in 'v<n>:<token>' format")
    version, token = m.group(1), m.group(2)
    current_version, key = _load_key()
    if version != current_version:
        raise ValueError(
            f"cred_ref version {version!r} != current key version "
            f"{current_version!r}; key rotation handler not yet implemented"
        )
    f = Fernet(key)
    return f.decrypt(token.encode())


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

def store(values: dict) -> str:
    """Encrypt a credentials dict at rest. Returns a `cred_ref` opaque
    string the caller stashes in `adapter_instances.cred_ref`."""
    if not isinstance(values, dict):
        raise TypeError("store() expects a dict of credential fields")
    blob = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    return _encrypt_at_rest(blob)


def load(ref: str) -> dict:
    """Decrypt a `cred_ref` back into the original credentials dict.
    Raises if the ref is malformed, tampered with, or encrypted under a
    key we no longer hold."""
    if not isinstance(ref, str) or not ref:
        raise ValueError("load() requires a non-empty cred_ref string")
    plaintext = _decrypt_at_rest(ref)
    out = json.loads(plaintext.decode())
    if not isinstance(out, dict):
        raise ValueError("decrypted cred_ref did not contain a JSON object")
    return out
