"""Per-tenant keyed tokens (design 2.5 / 7.3; isolation invariant I4).

ONE master key, `entity-hmac.env` (mode 600, versioned) on the SECRETS
mount — a sibling of mfa-key.env, like the sanitized pool's HMAC secret — so
a state backup never carries the key next to the tokens it keys.
`OCTO_ENTITY_HMAC_PATH` overrides (the bundle sets it; tests, sandboxes);
with neither it nor OCTO_MFA_KEY_PATH set (a dev box) it falls back to
`<data_root>/secrets/`. Provisioned by the bundle bootstrap, else created on
first use. Escrow it with the other secrets: a new key makes every stored
token (mac_tok, device_ref, F3 history) stop matching. Each tenant gets its
own key, never stored:

    K_t = HKDF-SHA256(K_master, info = "athena-entity-v1:" + slug)

and a token is

    <prefix>_ + base32(HMAC-SHA256(K_t, type | scope | normalised value))[:20]

so the same value reads the same everywhere INSIDE one tenant (API, audit,
LLM input) and differently in any other tenant: a MAC seen by two clients
cannot be joined across them. Device names are not masked (Rick, 2026-10-01)
— the tokens exist for equality search without a raw value, for the LLM
boundary, and as the stable handle stored in resolutions instead of names.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import threading
import uuid
from pathlib import Path
from typing import Optional

from apps.octo import paths

SECRET_BYTES = 32
VERSION_KEY = "ENTITY_HMAC_VERSION"
SECRET_KEY = "ENTITY_HMAC_BASE64"
INFO_PREFIX = b"athena-entity-v1:"
PREFIX = {
    "mac": "mc", "ip": "ip", "public_ip": "ip", "lan_ip": "ip", "name": "nm",
    "hostname": "hn", "unifi_client": "cl", "nextdns_device": "nd", "datto_device": "dd",
    "site": "st",
}

_lock = threading.Lock()
_cache: dict[str, tuple[str, bytes]] = {}


def key_path() -> Path:
    override = os.environ.get("OCTO_ENTITY_HMAC_PATH")
    if override:
        return Path(override).resolve()
    if os.environ.get("OCTO_MFA_KEY_PATH"):
        # The secrets mount (never the state volume a backup copies).
        from apps.octo.auth.crypto import mfa_key_path

        return mfa_key_path().parent / "entity-hmac.env"
    return paths.data_root() / "secrets" / "entity-hmac.env"


def _provision(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    secret = base64.urlsafe_b64encode(secrets.token_bytes(SECRET_BYTES)).decode()
    tmp = path.with_suffix(path.suffix + f".new.{uuid.uuid4().hex[:8]}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(f"{VERSION_KEY}=v1\n{SECRET_KEY}={secret}\n")
    try:
        # Never replace an existing key (a concurrent first use wins).
        os.link(tmp, path)
    except FileExistsError:
        pass
    finally:
        os.unlink(tmp)


def _load(path: Path) -> tuple[str, bytes]:
    version: Optional[str] = None
    secret: Optional[bytes] = None
    for line in path.read_text().splitlines():
        if "=" not in line or line.strip().startswith("#"):
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        if k == VERSION_KEY:
            version = v
        elif k == SECRET_KEY:
            secret = base64.urlsafe_b64decode(v)
    if not version or secret is None or len(secret) != SECRET_BYTES:
        raise ValueError(f"entity token key file {path} is malformed")
    return version, secret


def master() -> tuple[str, bytes]:
    """(version, master key), creating the key file on first use."""
    path = key_path()
    k = str(path)
    with _lock:
        if k in _cache:
            return _cache[k]
        if not path.exists():
            _provision(path)
        loaded = _load(path)
        _cache[k] = loaded
        return loaded


def reset_cache() -> None:
    with _lock:
        _cache.clear()


def _hkdf(master_key: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(b"\x00" * 32, master_key, hashlib.sha256).digest()
    out, block, n = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([n]), hashlib.sha256).digest()
        out += block
        n += 1
    return out[:length]


def tenant_key(slug: str) -> bytes:
    paths.validate_slug(slug)
    return _hkdf(master()[1], INFO_PREFIX + slug.encode("utf-8"))


def key_version() -> str:
    return master()[0]


def token(slug: str, kind: str, value: str, scope: str = "") -> str:
    """The tenant's token for (kind, scope, value) — the value must already
    be normalised (`normalize.*`)."""
    mac_ = hmac.new(tenant_key(slug), f"{kind}|{scope}|{value}".encode("utf-8"),
                    hashlib.sha256).digest()
    return f"{PREFIX.get(kind, 'tk')}_" + base64.b32encode(mac_).decode("ascii")[:20]
