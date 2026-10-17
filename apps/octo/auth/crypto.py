"""Symmetric at-rest encryption for MFA secrets and backup-code sets.

Distinct from the existing pepper (which is a salt-prefix used by the
sanitizer for PII hashing). MFA secrets need to be reversibly encrypted
because each TOTP verification has to recover the b32 secret to recompute
the HMAC; backup-code sets need to be reversibly encrypted so a single-code
consumption can re-encrypt the remaining set without exposing the others.

Key layout
----------

The key file is loaded from `OCTO_MFA_KEY_PATH` (env override) or
`<secrets-dir>/mfa-key.env` by default. Format mirrors `pepper.env`:

    MFA_KEY_VERSION=v1
    MFA_KEY_BASE64=<urlsafe-base64-encoded 32-byte Fernet key>

Ciphertext is stored with a version prefix: `v1:<fernet-token>`. This
permits future re-keying — a new `v2` key co-existing with `v1` for a
migration window — without changing the column shape.

Failure mode
------------

`load_mfa_key()` hard-fails if the key file is missing. This is intentional;
silently disabling at-rest encryption would be a CWE-311 footgun. Bootstrap
provisions the key file as part of the OCTO install (Phase G.1 deploy).
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from apps.octo.auth.config import pepper_path

_VERSIONED_RE = re.compile(r"^(v\d+):(.+)$")


def mfa_key_path() -> Path:
    """Return path to mfa-key.env. Override via OCTO_MFA_KEY_PATH for tests."""
    override = os.environ.get("OCTO_MFA_KEY_PATH")
    if override:
        return Path(override).resolve()
    # Default: sibling of pepper.env
    return pepper_path().parent / "mfa-key.env"


def load_mfa_key() -> tuple[str, bytes]:
    """Return (version_id, fernet_key_bytes). Hard-fail if unreadable."""
    path = mfa_key_path()
    if not path.exists():
        raise FileNotFoundError(
            f"MFA key not found at {path}. "
            "Set OCTO_MFA_KEY_PATH or provision the key with the first-run "
            "bootstrap (`python -m apps.octo.bundle_bootstrap`)."
        )
    text = path.read_text()
    version: Optional[str] = None
    key_b64: Optional[str] = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k == "MFA_KEY_VERSION":
            version = v
        elif k == "MFA_KEY_BASE64":
            key_b64 = v
    if not version or not key_b64:
        raise ValueError(
            f"MFA key file {path} must set MFA_KEY_VERSION and MFA_KEY_BASE64"
        )
    try:
        key_bytes = base64.urlsafe_b64decode(key_b64)
    except Exception as exc:
        raise ValueError(f"MFA_KEY_BASE64 is not valid urlsafe-base64: {exc}") from exc
    if len(key_bytes) != 32:
        raise ValueError(
            f"MFA_KEY_BASE64 must decode to 32 bytes (got {len(key_bytes)})"
        )
    return version, key_b64.encode()  # Fernet wants the urlsafe-b64 form


def generate_mfa_key() -> bytes:
    """Generate a fresh Fernet key (urlsafe-base64 encoded 32 bytes)."""
    return Fernet.generate_key()


def encrypt_at_rest(plaintext: bytes) -> str:
    """Encrypt with the current MFA key. Returns 'v<n>:<fernet-token>'."""
    version, key = load_mfa_key()
    f = Fernet(key)
    return f"{version}:{f.encrypt(plaintext).decode()}"


def decrypt_at_rest(ciphertext: str) -> bytes:
    """Decrypt a versioned ciphertext. Raises InvalidToken on tamper / wrong key."""
    m = _VERSIONED_RE.match(ciphertext)
    if not m:
        raise ValueError("ciphertext is not in 'v<n>:<token>' format")
    version, token = m.group(1), m.group(2)
    current_version, key = load_mfa_key()
    # In v1 we only have one key. Future re-keying: look up older keys here.
    if version != current_version:
        raise ValueError(
            f"ciphertext version {version!r} != current MFA key version "
            f"{current_version!r}; key rotation handler not yet implemented"
        )
    f = Fernet(key)
    return f.decrypt(token.encode())


# ---------------------------------------------------------------------------
# Backup-code helpers
# ---------------------------------------------------------------------------

BACKUP_CODE_COUNT = 8                       # standard practice: 8-10 codes
BACKUP_CODE_BYTES = 6                       # 6 bytes → 12 hex chars; rendered as XXXX-XXXX-XXXX

# Codes are PBKDF2-hashed (matching admin-token primitives) so verify is
# constant-time. The plaintext set is held in the encrypted blob to support
# "show me my unused codes again" within the operator's own session.


def generate_backup_codes(n: int = BACKUP_CODE_COUNT) -> list[str]:
    """Generate `n` backup codes formatted as XXXX-XXXX-XXXX (uppercase hex)."""
    out = []
    for _ in range(n):
        raw = secrets.token_hex(BACKUP_CODE_BYTES).upper()  # 12 chars
        out.append(f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}")
    return out


def encode_backup_code_set(codes: list[str]) -> str:
    """Build the encrypted JSON blob stored in `backup_code_sets.codes_enc`.

    Returned blob is a Fernet ciphertext over JSON of:
        {
          "version": 1,
          "plaintext": ["XXXX-XXXX-XXXX", ...],     (only present if not consumed yet)
          "consumed": [<index>, ...],
          "hashes": ["pbkdf2_sha256$...", ...]      (parallel to plaintext)
        }

    On a single-code consumption: decrypt, mark the index in `consumed`,
    optionally NULL out `plaintext[index]`, re-encrypt, write back.
    """
    from apps.octo.auth.core import hash_token  # avoid circular import at module load
    payload = {
        "version": 1,
        "plaintext": list(codes),
        "consumed": [],
        "hashes": [hash_token(c) for c in codes],
    }
    return encrypt_at_rest(json.dumps(payload).encode())


def decode_backup_code_set(blob: str) -> dict:
    """Decrypt + parse a `codes_enc` blob into the dict above."""
    return json.loads(decrypt_at_rest(blob).decode())


def consume_backup_code(blob: str, presented_code: str) -> tuple[bool, str]:
    """Verify `presented_code` against the set; mark consumed if match.

    Returns (matched, new_blob). If `matched` is False, `new_blob == blob`
    (caller still writes back to update last-tried timestamp via separate
    field — at-rest blob is unchanged).
    """
    from apps.octo.auth.core import verify_token
    payload = decode_backup_code_set(blob)
    consumed: set[int] = set(payload.get("consumed", []))
    for idx, h in enumerate(payload["hashes"]):
        if idx in consumed:
            continue
        if verify_token(presented_code, h):
            payload["consumed"] = sorted(consumed | {idx})
            # Strip the plaintext for consumed codes to limit exposure
            if "plaintext" in payload and idx < len(payload["plaintext"]):
                payload["plaintext"][idx] = None
            return True, encrypt_at_rest(json.dumps(payload).encode())
    return False, blob
