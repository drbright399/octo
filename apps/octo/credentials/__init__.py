"""Per-bundle credential vault — encrypted at-rest storage for MSP
customer-side credentials (Datto API keys, Wazuh API tokens, UniFi
controller keys, etc.).

Distinct from the MFA key vault (`apps.octo.auth.crypto`). MFA secrets
and customer credentials have different blast radius and different
rotation lifecycles, so they get their own key files. The encryption
primitive (Fernet, versioned ciphertext) is intentionally identical
between the two — `apps.octo.auth.crypto` is the proven pattern; this
module is a sibling that points at a different key.

Bundle credential store rule: this is the deployed bundle's OWN
credential vault. Customer / MSP credentials NEVER reach any
personal-infrastructure credential store outside the bundle.

Public surface (kept tiny so the future OpenBao swap stays narrow):
    store(values: dict) -> str   — JSON-encode + encrypt, returns
                                   versioned ciphertext (the `cred_ref`).
    load(ref: str) -> dict       — decrypt + JSON-decode.
    ensure_key_file()            — bootstrap: create the key file with
                                   mode 600 if it doesn't exist. Called
                                   from entrypoint boot.

Storage location: the encrypted ciphertext is meant to live in
`registry.db.adapter_instances.cred_ref` (caller's responsibility);
this module is purely a (de)serializer.
"""
from __future__ import annotations

from apps.octo.credentials.vault import (
    ensure_key_file,
    key_file_path,
    load,
    store,
)

__all__ = ["ensure_key_file", "key_file_path", "load", "store"]
