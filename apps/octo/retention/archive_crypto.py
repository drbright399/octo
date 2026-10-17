"""Encryption of the cold archive — the standard age v1 format, X25519.

Why (Rick, 2026-10-07): the archive holds raw DNS with device names for
every tenant on an unencrypted array share, protected only by file modes.
"Permission only is fine for now but we do want to make sure encryption is
built in for future archives."

Format: age v1 (https://age-encryption.org/v1) to X25519 recipients, via
`pyrage` (bindings to the `age` crate) — never hand-rolled. A file Athena
writes decrypts with the stock CLI:

    age -d -i <identity file> <file>.jsonl.gz.age | gunzip

KEY CUSTODY — option (b), Rick's standing decision of 2026-09-29 for this
bundle: the OPERATOR holds the private key OFF the machine (their vault);
Athena gets PUBLIC keys only, in a recipients file on the secrets mount
(`OCTO_ARCHIVE_RECIPIENTS_PATH`, default `DEFAULT_RECIPIENTS_PATH`):

    # comments and blank lines allowed (the `age -R` format)
    age1...        the operator's key
    age1...        an escrow key (optional; any number of recipients)

So Athena can WRITE the archive but never read an encrypted file back: the
dedupe of a later run reads a plaintext row-id ledger instead
(`archive.py`), and a restore needs the operator's identity file
(`scripts/restore_telemetry_archive.py --identity`).

Policy — `OCTO_ARCHIVE_ENCRYPTION`:
  required  every new archive file is encrypted; recipients missing or
            invalid = the archive is UNUSABLE: nothing is pruned (fail
            closed, exactly like an unmounted root) and the reason is shown
            wherever the archive state is (Settings → System, the scripts).
  off       today's plaintext gzip; every run says "archive NOT encrypted".
  (unset)   `required` when recipients are configured (the recipients path
            is set explicitly, or the default file exists) OR the archive
            already holds encrypted files (its marker — `archive.py`), else
            `off`. So a recipients file that goes missing later (moved aside
            in a key rotation, a secrets dir restored without it) fails the
            archive CLOSED instead of quietly turning it back to plaintext;
            plaintext again is only ever `off`, said explicitly.
  Any other value is a configuration error: unusable, like `required`
  with bad recipients.

The recipients file is refused when group- or world-writable (someone else
could add their own key and read every later file) and — a HARD refusal —
when it holds a private key anywhere (`AGE-SECRET-KEY-…`, or any PEM
private key): the private key must never be on this machine. Errors name
the line number, never the line. A key-file PATH that is itself a private
key (pasted into `OCTO_ARCHIVE_RECIPIENTS_PATH` or `--identity` by mistake)
is refused without being echoed — it would otherwise end up in the status,
the logs and the audit.

SEAM — option (a), an Athena-managed key with a recovery kit (a later
first-run-wizard feature, NOT built): a new custody kind beside
`CUSTODY_OPERATOR` in `_CUSTODY_LOADERS` that yields the same
`ArchiveEncryption` (recipients = Athena's own public key + the recovery
kit's), plus an identity source for restores that is not the operator's
file. Nothing else in the archive needs to change: it only ever sees
recipients for writing and `AgeIdentities` for reading.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

SCHEME = "age-x25519"
POLICY_ENV = "OCTO_ARCHIVE_ENCRYPTION"
RECIPIENTS_ENV = "OCTO_ARCHIVE_RECIPIENTS_PATH"
DEFAULT_RECIPIENTS_PATH = Path("/var/lib/octo/secrets/archive-recipients.txt")
MODES = ("required", "off")
CUSTODY_OPERATOR = "operator"
# A recipients / identity file is a few lines; anything bigger is not one.
MAX_KEY_FILE_BYTES = 64 * 1024

# Private key material in a file that must hold public keys only. age
# secret keys are Bech32 (case-insensitive); the PEM marker catches an SSH
# or other private key pasted by mistake.
_PRIVATE_MARKERS = re.compile(r"AGE-SECRET-KEY-|PRIVATE KEY-----", re.IGNORECASE)

PRIVATE_KEY_PATH_REFUSAL = (
    "is a PRIVATE key, not a file path — it is not shown here. Treat that key "
    "pair as exposed (it sat in a setting / on a command line): generate a new "
    "one OFF this host (age-keygen) and give the path of a file instead"
)

PRIVATE_KEY_REFUSAL = (
    "it contains a PRIVATE key — the private key must never be on this machine. "
    "Remove the file's private key line(s) now, keep the private key only in the "
    "operator's vault, and treat that key pair as exposed: generate a new one OFF "
    "this host (age-keygen) and put only its public key (age1…) in this file"
)


class EncryptionConfigError(Exception):
    """The archive's encryption configuration is unusable. The message never
    carries key material (line numbers only)."""


class DecryptionError(Exception):
    """An encrypted archive file could not be decrypted with the identities
    given. The message never carries key material."""


def _pyrage():
    try:
        import pyrage  # noqa: PLC0415 — only needed once encryption is in play
    except ImportError as exc:      # pragma: no cover — pinned in requirements.txt
        raise EncryptionConfigError(
            "the age library (pyrage) is not installed in this image") from exc
    return pyrage


# ---------------------------------------------------------------------------
# Public keys (recipients)
# ---------------------------------------------------------------------------

def recipient_short(recipient: str) -> str:
    """`age1abcdefgh…uvwxyz` — enough to tell keys apart on a screen."""
    return f"{recipient[:12]}…{recipient[-6:]}" if len(recipient) > 20 else recipient


def recipient_fingerprint(recipient: str) -> str:
    """A short, stable fingerprint of a PUBLIC key (sha256 of its text)."""
    return hashlib.sha256(recipient.encode("ascii")).hexdigest()[:16]


def describe_recipients(recipients) -> list[dict[str, str]]:
    return [{"short": recipient_short(r), "fingerprint": recipient_fingerprint(r)}
            for r in recipients]


def _lines(text: str):
    """(line number, stripped line) of every line that is not blank or a
    `#` comment — the `age -R` / `age -i` file format."""
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line and not line.startswith("#"):
            yield n, line


def parse_recipients(text: str) -> tuple[str, ...]:
    """The X25519 public keys in a recipients file's text, canonical form,
    in file order, without duplicates. EncryptionConfigError for a private
    key anywhere (comments too), a line that is not an `age1…` X25519 public
    key (named by line number), or no recipient at all."""
    if _PRIVATE_MARKERS.search(text):
        raise EncryptionConfigError(f"the recipients file is refused: {PRIVATE_KEY_REFUSAL}")
    pyrage = _pyrage()
    out: list[str] = []
    for n, line in _lines(text):
        if not line.lower().startswith("age1"):
            raise EncryptionConfigError(
                f"recipients file line {n} is not an age public key (age1…) — "
                "only public keys belong in it, one per line")
        try:
            canonical = str(pyrage.x25519.Recipient.from_str(line))
        except Exception:  # noqa: BLE001 — pyrage's errors are opaque; never echo the line
            raise EncryptionConfigError(
                f"recipients file line {n} is not a valid age X25519 public key "
                "(age1…, as printed by age-keygen)") from None
        if canonical not in out:
            out.append(canonical)
    if not out:
        raise EncryptionConfigError("the recipients file holds no public key (age1…)")
    return tuple(out)


def _refuse_key_as_path(value: str, what: str) -> None:
    """A path that is really a private key: refused, never echoed."""
    if _PRIVATE_MARKERS.search(value or ""):
        raise EncryptionConfigError(f"the {what} path given {PRIVATE_KEY_PATH_REFUSAL}")


def _read_key_file(path: Path, *, what: str, refuse_bits: int, refusal: str) -> str:
    _refuse_key_as_path(str(path), what)
    try:
        st = path.stat()
    except FileNotFoundError:
        raise EncryptionConfigError(f"{what} {path} does not exist") from None
    except OSError as exc:
        raise EncryptionConfigError(f"{what} {path} cannot be read ({type(exc).__name__})") from None
    if not stat.S_ISREG(st.st_mode):
        raise EncryptionConfigError(f"{what} {path} is not a regular file")
    mode = st.st_mode & 0o777
    if mode & refuse_bits:
        raise EncryptionConfigError(f"{what} {path} is refused: {refusal} (mode {mode:04o})")
    if st.st_size > MAX_KEY_FILE_BYTES:
        raise EncryptionConfigError(f"{what} {path} is too large to be a key file")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EncryptionConfigError(f"{what} {path} cannot be read ({type(exc).__name__})") from None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise EncryptionConfigError(f"{what} {path} is not a text file") from None


def load_recipients(path: Path) -> tuple[str, ...]:
    """The public keys in the recipients file at `path` (EncryptionConfigError
    when it is missing, writable by others, holds a private key, or a line is
    not a public key)."""
    text = _read_key_file(
        Path(path), what="recipients file", refuse_bits=0o022,
        refusal=("it is writable by group or other users — anyone who can add a "
                 "line can read every archive file written after: chmod 600 it"),
    )
    try:
        return parse_recipients(text)
    except EncryptionConfigError as exc:
        raise EncryptionConfigError(f"{path}: {exc}") from None


# ---------------------------------------------------------------------------
# The policy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ArchiveEncryption:
    """What new archive files get. `mode` 'required' | 'off'; `error` = why
    a required encryption is unusable (the archive then prunes nothing);
    `recipients` = public keys only."""
    mode: str = "off"
    # 'env' (OCTO_ARCHIVE_ENCRYPTION) | 'default' | 'archive' (unset, and the
    # archive already holds encrypted files: required, sticky)
    source: str = "default"
    custody: str = CUSTODY_OPERATOR
    recipients_path: Optional[Path] = None
    recipients: tuple[str, ...] = ()
    error: Optional[str] = None
    recipients_error: Optional[str] = None   # the file's problem, whatever the mode
    _recipient_objs: tuple = field(default=(), repr=False, compare=False)

    @property
    def required(self) -> bool:
        return self.mode == "required"

    @property
    def active(self) -> bool:
        """New files are encrypted (required and usable)."""
        return self.required and self.error is None and bool(self.recipients)

    def note(self) -> Optional[str]:
        """The one line every run says when files are written in plaintext."""
        if self.required:
            return None
        if self.source == "env":
            why = f"{POLICY_ENV}=off"
        else:
            why = (f"no recipients configured ({RECIPIENTS_ENV}: "
                   f"{self.recipients_path or DEFAULT_RECIPIENTS_PATH} not found)")
        return f"archive NOT encrypted — {why}: new files are plaintext gzip"

    def status(self) -> dict[str, Any]:
        return {
            "mode": self.mode, "source": self.source, "custody": self.custody,
            "scheme": SCHEME, "encrypted": self.active,
            "recipients_path": str(self.recipients_path) if self.recipients_path else None,
            "recipients": describe_recipients(self.recipients),
            "error": self.error,
            "recipients_error": self.recipients_error,
            "note": self.note(),
        }

    def encrypt(self, data: bytes) -> bytes:
        """`data` as an age v1 file to every recipient."""
        if not self.active:
            raise EncryptionConfigError(self.error or "archive encryption is not active")
        pyrage = _pyrage()
        objs = self._recipient_objs or tuple(
            pyrage.x25519.Recipient.from_str(r) for r in self.recipients)
        try:
            return pyrage.encrypt(data, list(objs))
        except Exception as exc:  # noqa: BLE001
            raise EncryptionConfigError(f"age encryption failed ({type(exc).__name__})") from None

    def encrypt_stream(self, reader: Any, writer: Any) -> None:
        """Stream `reader` (a readable binary file object) into `writer`
        (anything with `write(bytes)`) as ONE age v1 file to every recipient,
        chunk by chunk: neither the plaintext nor the ciphertext is ever held
        whole in memory (`scripts/seal_backup_runs.py` seals ~0.5 GB backup
        runs this way). A failure of the reader or the writer surfaces as
        EncryptionConfigError naming only the exception type; callers that
        need the cause keep it on their reader / writer."""
        if not self.active:
            raise EncryptionConfigError(self.error or "archive encryption is not active")
        pyrage = _pyrage()
        objs = self._recipient_objs or tuple(
            pyrage.x25519.Recipient.from_str(r) for r in self.recipients)
        try:
            pyrage.encrypt_io(reader, writer, list(objs))
        except Exception as exc:  # noqa: BLE001
            raise EncryptionConfigError(f"age encryption failed ({type(exc).__name__})") from None


def with_recipients(recipients: tuple[str, ...], *, mode: str = "required",
                    source: str = "env", path: Optional[Path] = None) -> ArchiveEncryption:
    """An ArchiveEncryption for these (already validated) public keys."""
    pyrage = _pyrage()
    objs = tuple(pyrage.x25519.Recipient.from_str(r) for r in recipients)
    return ArchiveEncryption(mode=mode, source=source, recipients_path=path,
                             recipients=tuple(recipients), _recipient_objs=objs)


def _operator_recipients(env: Mapping[str, str]) -> tuple[Optional[Path], bool]:
    """Custody (b): the operator's public keys in a file on the secrets
    mount. (path, configured): configured = the path is set explicitly, or
    the default file exists. EncryptionConfigError (the value not echoed)
    when the setting holds a private key instead of a path."""
    raw = (env.get(RECIPIENTS_ENV) or "").strip()
    if raw:
        try:
            _refuse_key_as_path(raw, "recipients file")
        except EncryptionConfigError as exc:
            raise EncryptionConfigError(f"{RECIPIENTS_ENV}: {exc}") from None
        return Path(raw), True
    return DEFAULT_RECIPIENTS_PATH, DEFAULT_RECIPIENTS_PATH.exists()


# custody kind → where the recipients come from. Option (a) (an Athena-
# managed key + recovery kit) plugs in here — not built.
_CUSTODY_LOADERS: dict[str, Callable[[Mapping[str, str]], tuple[Optional[Path], bool]]] = {
    CUSTODY_OPERATOR: _operator_recipients,
}


def load_policy(env: Optional[Mapping[str, str]] = None, *,
                in_use: bool = False) -> ArchiveEncryption:
    """The archive encryption the environment asks for, recipients loaded
    and validated. Never raises: a problem is `error` (required → unusable).
    `in_use`: the archive already holds encrypted files
    (`ColdArchive.encryption_in_use`) — with the mode unset that makes it
    `required` even when no recipients file is found (fail closed: a
    missing file never turns an encrypted archive back into plaintext)."""
    env = os.environ if env is None else env
    recipients: tuple[str, ...] = ()
    recipients_error: Optional[str] = None
    try:
        path, configured = _CUSTODY_LOADERS[CUSTODY_OPERATOR](env)
    except EncryptionConfigError as exc:
        path, configured, recipients_error = None, True, str(exc)
    raw_mode = (env.get(POLICY_ENV) or "").strip().lower()
    objs: tuple = ()
    if configured and path is not None:
        try:
            recipients = load_recipients(path)
            pyrage = _pyrage()
            objs = tuple(pyrage.x25519.Recipient.from_str(r) for r in recipients)
        except EncryptionConfigError as exc:
            recipients, recipients_error = (), str(exc)
    if raw_mode:
        source = "env"
        if raw_mode not in MODES:
            # Never echo the value: whatever was typed there is not shown.
            return ArchiveEncryption(
                mode="required", source=source, recipients_path=path,
                recipients=recipients, recipients_error=recipients_error,
                error=f"{POLICY_ENV} must be 'required' or 'off'", _recipient_objs=objs,
            )
        mode = raw_mode
    elif configured:
        source, mode = "default", "required"
    elif in_use:
        source, mode = "archive", "required"
    else:
        source, mode = "default", "off"
    error = None
    if mode == "required":
        if recipients_error:
            error = recipients_error
        elif source == "archive":
            error = (f"the archive already holds encrypted files, but no recipients file "
                     f"is configured ({RECIPIENTS_ENV}; {path} not found) — put the "
                     f"operator's PUBLIC key back there, or set {POLICY_ENV}=off to write "
                     "plaintext on purpose")
        elif not configured or not recipients:
            error = (f"no recipients file ({RECIPIENTS_ENV}, default "
                     f"{DEFAULT_RECIPIENTS_PATH}) — put the operator's PUBLIC key there")
    return ArchiveEncryption(
        mode=mode, source=source, recipients_path=path, recipients=recipients,
        error=error, recipients_error=recipients_error, _recipient_objs=objs,
    )


# ---------------------------------------------------------------------------
# Private keys (identities) — brought by the operator for a restore / verify
# ---------------------------------------------------------------------------

class AgeIdentities:
    """The X25519 identities of an operator's age identity file, held for
    one restore / verify. Its repr / str never show key material; only the
    matching PUBLIC keys are exposed."""

    def __init__(self, identities: list, public_keys: list[str], path: Path) -> None:
        self._identities = identities
        self.public_keys = tuple(public_keys)
        self.path = path

    def __repr__(self) -> str:
        return f"<AgeIdentities {len(self.public_keys)} key(s) from {self.path}>"

    __str__ = __repr__

    def describe(self) -> list[dict[str, str]]:
        return describe_recipients(self.public_keys)

    def decrypt(self, data: bytes, where: str = "") -> bytes:
        pyrage = _pyrage()
        try:
            return pyrage.decrypt(data, list(self._identities))
        except Exception as exc:  # noqa: BLE001 — opaque library errors; never echoed
            raise _decryption_error(exc, where) from None

    def decrypt_stream(self, reader: Any, writer: Any, where: str = "") -> None:
        """Stream the age file read from `reader` (a readable binary file
        object) into `writer` (anything with `write(bytes)`), chunk by chunk
        (`scripts/unseal_backup_run.py`: a sealed backup run). Plaintext may
        already have been written when it fails — truncated or tampered
        ciphertext is detected at the damaged chunk — so a caller discards
        the writer's output on DecryptionError."""
        pyrage = _pyrage()
        try:
            pyrage.decrypt_io(reader, writer, list(self._identities))
        except Exception as exc:  # noqa: BLE001 — opaque library errors; never echoed
            raise _decryption_error(exc, where) from None


def _decryption_error(exc: Exception, where: str) -> DecryptionError:
    label = f"{where}: " if where else ""
    if "no matching keys" in str(exc).lower():
        return DecryptionError(f"{label}none of the identities given can decrypt it "
                               "(it was encrypted to other public keys)")
    return DecryptionError(f"{label}not a readable age file ({type(exc).__name__})")


def load_identities(path: Path) -> AgeIdentities:
    """The operator's age identity file (`age-keygen` output). Refused when
    group or other users have any access to it; a line that is not an
    X25519 identity is named by number, never shown."""
    path = Path(path)
    text = _read_key_file(
        path, what="identity file", refuse_bits=0o077,
        refusal=("group or other users can access it — it is the archive's PRIVATE "
                 "key: chmod 600 it (and keep it off the bundle host when done)"),
    )
    pyrage = _pyrage()
    identities, public = [], []
    for n, line in _lines(text):
        try:
            ident = pyrage.x25519.Identity.from_str(line)
        except Exception:  # noqa: BLE001 — never echo the line
            raise EncryptionConfigError(
                f"identity file {path} line {n} is not an age X25519 identity "
                "(AGE-SECRET-KEY-1…)") from None
        identities.append(ident)
        public.append(str(ident.to_public()))
    del text
    if not identities:
        raise EncryptionConfigError(f"identity file {path} holds no identity (AGE-SECRET-KEY-1…)")
    return AgeIdentities(identities, public, path)
