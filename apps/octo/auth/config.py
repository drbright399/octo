"""Configuration — data root, pepper, defaults.

All paths resolve relative to OCTO_DATA_ROOT (env override; every bundle
deploy and every test sets it). Without it, the default is the single-host
layout under the home directory of the account the process runs as:
``~/octo/data`` and ``~/octo/secrets/pepper.env``, resolved at call time so
no host-specific path is baked into the code.
"""
from __future__ import annotations

import os
from pathlib import Path


_NO_HOME = (
    "cannot resolve the default OCTO layout (~/octo): the account has no "
    "usable home directory; set OCTO_DATA_ROOT and OCTO_PEPPER_PATH"
)


def _default_octo_dir() -> Path:
    """``~/octo`` of the account the process runs as (single-host layout).

    Refuses (RuntimeError) rather than guessing when there is no usable
    home: none at all, a relative one, or ``/`` (an empty ``HOME``, or a
    service account such as a systemd DynamicUser whose home is the root
    directory), so the default never lands in ``/octo`` or the cwd."""
    try:
        home = Path.home()
    except RuntimeError as e:  # no HOME and no passwd entry
        raise RuntimeError(_NO_HOME) from e
    if not home.is_absolute() or home == Path(home.anchor):
        raise RuntimeError(_NO_HOME)
    return home / "octo"


def default_data_root() -> Path:
    """Data root used when OCTO_DATA_ROOT is unset: ``~/octo/data``."""
    return _default_octo_dir() / "data"


def default_pepper_path() -> Path:
    """Pepper file used when OCTO_PEPPER_PATH is unset:
    ``~/octo/secrets/pepper.env``."""
    return _default_octo_dir() / "secrets" / "pepper.env"

PBKDF2_ITERATIONS = 600_000
PBKDF2_SALT_BYTES = 16
PBKDF2_KEY_BYTES = 32

TOKEN_PLAINTEXT_BYTES = 32          # base64url-encoded → 43 chars
TOKEN_PREFIX_CHARS = 8

DEFAULT_RETENTION_DAYS = 365
DEFAULT_NOTIFICATION_SLA_HOURS = 24

GUARD_THRESHOLD_HITS_PER_24H = 10

RESERVED_SLUGS = frozenset({"_archive", "_backups", "global", ""})

# Athena Console identity / WebAuthn / TOTP branding.
#
# Defaults are placeholders. Production deploys MUST set ATHENA_RP_ID
# and ATHENA_ORIGIN to the MSP's actual Console hostname; the WebAuthn
# spec ties credentials to RP_ID so the per-bundle hostname is part of
# the security boundary. Leaving these at the defaults would allow no
# real authentication to succeed.
ATHENA_RP_ID_DEFAULT      = "athena.local"
ATHENA_ORIGIN_DEFAULT     = "https://athena.local"
ATHENA_RP_NAME            = "Athena"
ATHENA_TOTP_ISSUER        = "Athena"


# Reverse proxies whose X-Forwarded-For octo-core believes: IP addresses or
# CIDR networks separated by commas and/or whitespace (a bare address is a
# /32 or /128). Unset or empty = trust nobody, so the socket peer is the
# client. An unusable entry (not an address, host bits set, /0) stops the app
# from starting. On the bundle host this is the subnet of the internal proxy
# network that only the reverse proxy, the console and octo-core join
# (docs/operations/bundle.md, "Client addresses behind the proxy"). Parsed and
# applied by `apps.octo.api.client_ip`.
TRUSTED_PROXIES_ENV = "OCTO_TRUSTED_PROXIES"


def trusted_proxies_setting() -> str:
    """The raw OCTO_TRUSTED_PROXIES value ("" when unset), read per call."""
    return os.environ.get(TRUSTED_PROXIES_ENV, "")


def athena_rp_id() -> str:
    return os.environ.get("ATHENA_RP_ID", ATHENA_RP_ID_DEFAULT)


def athena_origin() -> str:
    return os.environ.get("ATHENA_ORIGIN", ATHENA_ORIGIN_DEFAULT)


def data_root() -> Path:
    """Return OCTO data root. OCTO_DATA_ROOT env var overrides for tests."""
    override = os.environ.get("OCTO_DATA_ROOT")
    return Path(override).resolve() if override else default_data_root()


def pepper_path() -> Path:
    override = os.environ.get("OCTO_PEPPER_PATH")
    return Path(override).resolve() if override else default_pepper_path()


def load_pepper() -> tuple[str, bytes]:
    """Return (version_id, pepper_bytes). Hard-fail if unreadable.

    Expected file format (simple env syntax):
        PEPPER_VERSION=pepper_v1
        PEPPER_HEX=<64 hex chars>
    """
    path = pepper_path()
    if not path.exists():
        raise FileNotFoundError(
            f"Pepper not found at {path}. "
            "Set OCTO_PEPPER_PATH or provision the pepper per spec §3.5."
        )
    version: str | None = None
    hexval: str | None = None
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k == "PEPPER_VERSION":
            version = v
        elif k == "PEPPER_HEX":
            hexval = v
    if not version or not hexval:
        raise ValueError(f"Pepper file {path} must set PEPPER_VERSION and PEPPER_HEX")
    return version, bytes.fromhex(hexval)
