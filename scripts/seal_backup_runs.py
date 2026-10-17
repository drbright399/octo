#!/usr/bin/env python3
"""seal_backup_runs.py — seal every backup run into ONE age file for the backup vault.

The backup vault design (2026-10-12, section 3, "seal at source"; Rick's decision
2): the vault pulls only CIPHERTEXT. After the nightly backup and the audit-chain
check, this step turns each backup run (a `backup_databases.py` run
directory) that is not sealed yet into four files under the sealed root:

    <stamp>.tar.age          the run as an uncompressed tar (its files are
                             already .gz), age v1 to EVERY recipient in the
                             recipients file (public keys only)
    <stamp>.tar.age.sha256   sha256 of the CIPHERTEXT, `sha256sum` format
    <stamp>.meta.json        run_stamp, kind, backup_rc, chain_rc, db_files,
                             plaintext_bytes, ciphertext_bytes,
                             recipients_count, sealed_at_utc, tool_version:
                             NO tenant name and NO path
    <stamp>.complete         written LAST, holding the same sha256 line. A
                             run is sealed when (and only when) all four are
                             regular files and .complete matches .sha256;
                             the vault pulls a run only once .complete exists.

Inside the tar (restore on the operator workstation: `scripts/unseal_backup_run.py`, which
decrypts and extracts it safely, then
`restore_databases.py --backup-run <dir>/<stamp>`; never `tar -x` a sealed
run, it may be a forgery):

    <stamp>/<file>           every file of the run directory, byte for byte
                             (from this release on, that includes the run's
                             own `backup-report.json`)
    report/<report name>     the backup report (--report), only when it is
                             THIS run's report (its dest_dir names the run)
    bundle/<name>            each --config-file (compose files, the host
                             script), as it is at SEAL time

Safety:
  - plaintext never touches the sealed root: the tar is generated chunk by
    chunk and streamed through the age encryptor (pyrage, via
    `archive_crypto.ArchiveEncryption.encrypt_stream`); only ciphertext is
    written, to `<stamp>.tar.age.tmp`, fsynced, then renamed;
  - the backups root is only ever READ (mount it read-only); retention here
    prunes sealed outputs only;
  - the recipients file is loaded and validated by `archive_crypto` (missing,
    group/world-writable, a private key anywhere, a bad line, no key at all
    = refused; errors name line numbers, never key material);
  - the sealed root must not be inside the backups root, or vice versa, and
    is refused when group or other users can write it (they could plant a
    `.complete`, or a run for the vault to pull);
  - a run is a directory whose name is the backup tool's run stamp
    (`backup_databases.RUN_STAMP_FORMAT`, e.g. 20261012T060001Z); any other
    directory is skipped with a warning, loose files (the report, a status
    file) are not runs. A run directory that is a symlink, or holds a
    symlink / subdirectory / special file, is REFUSED (exit 1) and never
    sealed; files are opened O_NOFOLLOW relative to the run directory. An
    EMPTY run directory (a backup that is starting, or one that stopped
    early) is not sealed: a warning, not a failure;
  - idempotent: a sealed run is never sealed again; leftovers of an
    interrupted seal (`*.tmp`, outputs without a matching `.complete`, a
    lone `.complete`) are removed, `.complete` first, and the run is sealed
    again from scratch;
  - one seal at a time: flock on `<sealed root>/.seal.lock`; a seal waits up
    to 60 minutes for another to finish (then exit 3). A filesystem without
    flock is refused (exit 2): two seals at once could destroy each other's
    output;
  - disk space: expired outputs are pruned BEFORE anything is sealed; the
    run being sealed now goes first, then the others newest first; a run
    is started only when the sealed root has room for it plus a 5 GiB
    reserve, and sealing stops at the first "no space left";
  - Ctrl-C / SIGINT stops the whole tool (after removing the partial
    `.tmp`); it is never counted as one failed run.

A run is FINISHED, and only then sealed, when:
  - it holds `backup-report.json` (`backup_databases.RUN_REPORT_NAME`): the
    backup's own last step, a positive "done" signal; or
  - the backup report (--report) names it (the report is written at the end
    of a backup: covers runs from releases before the marker); or
  - neither, but its stamp is at least 6 hours old and nothing in it changed
    for 10 minutes: a legacy run, or a backup that died; it is sealed as
    found (said in the output).
Anything else may still be being written: deferred to a later seal (a note,
not a failure).

Which run gets --backup-rc / --chain-rc / --kind ("the run being sealed
now"): the run the backup report names, when its stamp is at or after
--current-since (the host records the time just before the backup starts)
and it is not sealed yet. Otherwise (the backup failed before writing a
report, the report names an older run, that run is refused or already
sealed) the codes are recorded for NO run, never for a neighbour. Every
other unsealed run (a catch-up after a failed seal, or --backfill) records
"unknown" for both codes.

Kind:
  nightly | adhoc   given explicitly (the host decides: the cron entry sets
                    SEAL_KIND=nightly; a hand run is adhoc): applies to the
                    run being sealed now;
  auto (default)    "nightly" when the run's stamp falls in the 20 minutes
                    after 23:00 America/Los_Angeles (the bundle host's cron
                    time for the nightly, = 01:00 US Central), DST-aware;
                    else "adhoc". Catch-up and backfill runs are always
                    classified this way. If the cron moves, change
                    NIGHTLY_TZ / NIGHTLY_START here.

Retention (--retention-days, default 14, at least 1): sealed outputs whose
run stamp is older than N days are deleted, `.complete` first; nothing else
in the sealed root is touched, and a run already past that horizon is not
sealed at all (it would only be pruned again).

Exit codes: 0 done (or nothing to do) · 1 a run failed / was refused, a
prune failed, or the disk filled (the other runs were still sealed) · 2
setup / usage refusal (nothing written) · 3 another seal held the lock for
60 minutes.

Usage (inside the bundle image; the host step is
ops/bundle-host/nightly-backup.seal-step.patch.md):
    python /app/scripts/seal_backup_runs.py --backups-root /backup \\
        --sealed-root /sealed --recipients /var/lib/octo/secrets/archive-recipients.txt \\
        --backup-rc 0 --chain-rc 0 --current-since 20261012T060000Z \\
        --kind nightly --retention-days 14 \\
        --config-file /bundle-config/docker-compose.yml [--dry-run]
    python /app/scripts/seal_backup_runs.py ... --backfill [--dry-run]
"""
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import time
from dataclasses import dataclass, field
from datetime import datetime, time as dtime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, Callable, Iterator, NoReturn, Optional, Union

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
if _REPO_ROOT.is_dir() and str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_HERE) not in sys.path:
    sys.path.append(str(_HERE))      # appended: never shadows anything else

# The run-dir name and the run's "finished" marker: one source.
from backup_databases import RUN_REPORT_NAME, RUN_STAMP_FORMAT  # noqa: E402
from apps.octo.retention import archive_crypto  # noqa: E402

TOOL_VERSION = "seal_backup_runs-1"
UNKNOWN = "unknown"
KINDS = ("auto", "nightly", "adhoc")
# --kind auto: "nightly" when the run's stamp, in the bundle host's cron time
# zone, is in [NIGHTLY_START, NIGHTLY_START + NIGHTLY_SPAN).
NIGHTLY_TZ = "America/Los_Angeles"
NIGHTLY_START = dtime(23, 0)
NIGHTLY_SPAN = timedelta(minutes=20)
CLOCK_SKEW = timedelta(minutes=10)
# A run that is not marked finished: sealed as found once its stamp is this
# old AND nothing in it changed for QUIET_PERIOD.
UNFINISHED_GRACE = timedelta(hours=6)
QUIET_PERIOD = timedelta(minutes=10)
# A run is started only with this much free space left over after it.
FREE_SPACE_RESERVE = 5 * 1024 ** 3
LOCK_WAIT_SECONDS = 60 * 60
LOCK_POLL_SECONDS = 5.0
DISK_FULL_ERRNOS = frozenset({errno.ENOSPC, errno.EDQUOT})
# fsync of a DIRECTORY is not supported everywhere (some FUSE / network
# filesystems): the files themselves are fsynced; carry on.
_DIR_FSYNC_UNSUPPORTED = frozenset({errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS})

SUFFIX_AGE = ".tar.age"
SUFFIX_SHA = ".tar.age.sha256"
SUFFIX_META = ".meta.json"
SUFFIX_COMPLETE = ".complete"
TMP = ".tmp"
OUTPUT_SUFFIXES = (SUFFIX_AGE, SUFFIX_SHA, SUFFIX_META, SUFFIX_COMPLETE)
LOCK_NAME = ".seal.lock"
DEFAULT_REPORT_NAME = "last-report.json"
META_KEYS = ("run_stamp", "kind", "backup_rc", "chain_rc", "db_files", "plaintext_bytes",
             "ciphertext_bytes", "recipients_count", "sealed_at_utc", "tool_version")

MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_REPORT_BYTES = 32 * 1024 * 1024
CHUNK = 1024 * 1024
BLOCK = tarfile.BLOCKSIZE          # 512
RECORD = tarfile.RECORDSIZE        # 20 blocks, what tarfile pads to on close

EXIT_OK, EXIT_FAILED, EXIT_SETUP, EXIT_LOCKED = 0, 1, 2, 3

_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_NEW_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC

# Tests swap these.
_sleep: Callable[[float], None] = time.sleep
_monotonic: Callable[[], float] = time.monotonic

RC = Union[int, str]


class SealError(Exception):
    """One run could not be sealed; the message is the one-line reason."""


class DiskFull(SealError):
    """The sealed root ran out of space: no later run can be sealed either."""


class SetupError(Exception):
    """The invocation is refused before anything is written."""


class Locked(Exception):
    """Another seal held the lock for the whole wait."""


# ---------------------------------------------------------------------------
# Names, kinds
# ---------------------------------------------------------------------------

def parse_stamp(name: str) -> Optional[datetime]:
    """The UTC start time a run directory name stands for, or None when the
    name is not EXACTLY the backup tool's stamp (round trip through
    RUN_STAMP_FORMAT: no padding variants, no other digits, nothing else)."""
    try:
        when = datetime.strptime(name, RUN_STAMP_FORMAT)
    except (ValueError, TypeError):
        return None
    if when.strftime(RUN_STAMP_FORMAT) != name:
        return None
    return when.replace(tzinfo=timezone.utc)


_NIGHTLY_ZONE: Optional[tzinfo] = None


def nightly_zone() -> tzinfo:
    """The cron's time zone (SetupError when this image has no tzdata)."""
    global _NIGHTLY_ZONE
    if _NIGHTLY_ZONE is None:
        try:
            from zoneinfo import ZoneInfo  # noqa: PLC0415
            _NIGHTLY_ZONE = ZoneInfo(NIGHTLY_TZ)
        except Exception:  # noqa: BLE001 — ZoneInfoNotFoundError, a missing tzdata
            raise SetupError(f"the time zone {NIGHTLY_TZ} is not available in this image "
                             "(tzdata): --kind auto cannot classify runs") from None
    return _NIGHTLY_ZONE


def classify_kind(when: datetime) -> str:
    """--kind auto: "nightly" when the run started within NIGHTLY_SPAN after
    NIGHTLY_START, wall-clock time in NIGHTLY_TZ (so DST-aware)."""
    local = when.astimezone(nightly_zone())
    start = datetime.combine(local.date(), NIGHTLY_START)
    wall = local.replace(tzinfo=None)
    return "nightly" if start <= wall < start + NIGHTLY_SPAN else "adhoc"


def _show(name: str) -> str:
    """A directory-entry name as it may be printed (bounded, escaped)."""
    text = repr(name)
    return text if len(text) <= 80 else text[:77] + "..."


def _why(exc: BaseException) -> str:
    if isinstance(exc, (SealError, SetupError)):
        return str(exc)
    if isinstance(exc, OSError) and exc.strerror:
        return exc.strerror
    return type(exc).__name__


def _is_disk_full(exc: BaseException) -> bool:
    return isinstance(exc, DiskFull) or (
        isinstance(exc, OSError) and exc.errno in DISK_FULL_ERRNOS)


def _gib(n: float) -> str:
    return f"{n / 1024 ** 3:.2f} GiB"


# ---------------------------------------------------------------------------
# Inputs: run directories, the report, the bundle config
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Run:
    stamp: str
    when: datetime


@dataclass
class BackupsScan:
    runs: list[Run] = field(default_factory=list)                    # oldest first
    refused: list[tuple[str, str]] = field(default_factory=list)     # (stamp, reason)
    skipped: list[tuple[str, str]] = field(default_factory=list)     # (name, reason)


def scan_backups(root: Path) -> BackupsScan:
    out = BackupsScan()
    with os.scandir(root) as it:
        entries = sorted(it, key=lambda e: e.name)
    for entry in entries:
        when = parse_stamp(entry.name)
        if entry.is_symlink():
            if when is not None:
                out.refused.append((entry.name, "refused: the run directory is a symlink"))
            else:
                out.skipped.append((entry.name, "a symlink, not a backup run"))
            continue
        if entry.is_dir(follow_symlinks=False):
            if when is not None:
                out.runs.append(Run(entry.name, when))
            else:
                out.skipped.append((entry.name, "not a backup run name"))
        elif when is not None:
            out.skipped.append((entry.name, "named like a run but not a directory"))
        # any other loose file (the report, a status file) is not a run
    return out


@dataclass(frozen=True)
class Extra:
    """A non-run member of the tar (the report, a bundle config file)."""
    arcname: str
    data: bytes
    mtime: int


def _read_regular(path: Path, *, limit: int, what: str) -> tuple[bytes, int]:
    """(bytes, mtime) of a regular file, opened without following a final
    symlink. SetupError naming `what` (never the content)."""
    try:
        fd = os.open(path, _READ_FLAGS)
    except FileNotFoundError:
        raise SetupError(f"{what} {path} does not exist") from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SetupError(f"{what} {path} is a symlink — give the file itself") from None
        raise SetupError(f"{what} {path} cannot be read ({_why(exc)})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SetupError(f"{what} {path} is not a regular file")
        parts, total = [], 0
        while True:
            chunk = os.read(fd, CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise SetupError(f"{what} {path} is larger than {limit} bytes")
            parts.append(chunk)
        return b"".join(parts), int(st.st_mtime)
    finally:
        os.close(fd)


def load_config_files(paths: list[Path]) -> list[Extra]:
    extras: list[Extra] = []
    seen: set[str] = set()
    for path in paths:
        name = path.name
        if not name or name in (".", ".."):
            raise SetupError(f"config file {path} has no file name")
        if name in seen:
            raise SetupError(f"two config files are named {_show(name)} — each lands in "
                             "bundle/<name>, so their names must differ")
        seen.add(name)
        data, mtime = _read_regular(path, limit=MAX_CONFIG_BYTES, what="config file")
        extras.append(Extra(f"bundle/{name}", data, mtime))
    return extras


def load_report(path: Path) -> tuple[Optional[str], Optional[Extra], Optional[str]]:
    """(stamp of the run it reports on, its tar member, a warning). A missing
    report is not a warning: a failed backup may not have written one."""
    if not path.exists() and not path.is_symlink():
        return None, None, None
    try:
        data, mtime = _read_regular(path, limit=MAX_REPORT_BYTES, what="backup report")
    except SetupError as exc:
        return None, None, f"{exc}; not included"
    try:
        dest = json.loads(data.decode("utf-8")).get("dest_dir")
        stamp = Path(str(dest)).name if dest else None
    except (ValueError, UnicodeDecodeError, AttributeError):
        return None, None, f"backup report {path} is not a backup report (JSON); not included"
    if not stamp or parse_stamp(stamp) is None:
        return None, None, f"backup report {path} names no run; not included"
    return stamp, Extra(f"report/{path.name}", data, mtime), None


@dataclass
class OpenRun:
    """A run directory opened for reading: its fd, its files (sorted), its
    own mtime, the newest mtime of anything in it and its files' total size."""
    dfd: int
    names: list[str]
    dir_mtime: int
    newest_mtime: float
    total_bytes: int = 0

    @property
    def finished(self) -> bool:
        """The backup wrote its last step (its own report) into the run."""
        return RUN_REPORT_NAME in self.names

    def close(self) -> None:
        if self.dfd >= 0:
            os.close(self.dfd)
            self.dfd = -1


def open_run(backups_root: Path, stamp: str) -> OpenRun:
    """SealError when the run directory is a symlink, or holds anything but
    regular files (a symlink, a subdirectory, a special file). An empty run
    has no names (the caller decides)."""
    try:
        dfd = os.open(backups_root / stamp,
                      os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise SealError("refused: the run directory is a symlink or not a directory") from None
        raise SealError(f"the run directory cannot be opened ({_why(exc)})") from None
    try:
        st = os.fstat(dfd)
        names: list[str] = []
        newest = st.st_mtime
        total = 0
        with os.scandir(dfd) as it:
            for entry in it:
                if entry.is_symlink():
                    raise SealError(f"refused: the run holds a symlink ({_show(entry.name)})")
                if not entry.is_file(follow_symlinks=False):
                    raise SealError("refused: the run holds something that is not a regular "
                                    f"file ({_show(entry.name)})")
                names.append(entry.name)
                est = entry.stat(follow_symlinks=False)
                newest = max(newest, est.st_mtime)
                total += est.st_size
        return OpenRun(dfd, sorted(names), int(st.st_mtime), newest, total)
    except BaseException:
        os.close(dfd)
        raise


def count_db_files(names: list[str]) -> int:
    return sum(1 for n in names if n.endswith(".db") or n.endswith(".db.gz"))


def ready_to_seal(opened: OpenRun, *, named_by_report: bool, when: datetime,
                  now: datetime) -> tuple[bool, str]:
    """(finished?, how we know). A run neither marked finished nor named by
    the report is sealed as found only once it is old and quiet."""
    if opened.finished:
        return True, ""
    if named_by_report:
        return True, ""
    age = now.timestamp() - opened.newest_mtime
    quiet = QUIET_PERIOD.total_seconds()
    changing = -quiet <= age < quiet
    if now - when >= UNFINISHED_GRACE and not changing:
        return True, "as found: the backup never marked it finished"
    return False, ""


def estimate_bytes(opened: OpenRun, extras: list[Extra]) -> int:
    """About what the ciphertext of this run will take: the plaintext, tar
    headers (pax: up to 3 blocks a member), age's 16 bytes per 64 KiB."""
    plain = opened.total_bytes + sum(len(e.data) for e in extras)
    members = len(opened.names) + len(extras) + 1
    return plain + members * 3 * BLOCK + plain // (64 * 1024) * 16 + 2 * RECORD + 64 * 1024


def free_bytes(path: Path) -> int:
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


# ---------------------------------------------------------------------------
# The tar stream (never on disk) and the ciphertext sink
# ---------------------------------------------------------------------------

def _header(name: str, *, size: int = 0, mtime: float = 0, directory: bool = False) -> bytes:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = 0o700 if directory else 0o600
    info.size = 0 if directory else size
    info.mtime = int(mtime)
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info.tobuf(tarfile.PAX_FORMAT, "utf-8", "surrogateescape")


def _pad(size: int) -> bytes:
    return b"\0" * ((-size) % BLOCK)


def tar_chunks(run: OpenRun, stamp: str, extras: list[Extra]) -> Iterator[bytes]:
    """The uncompressed tar of one run, chunk by chunk: `<stamp>/` + its
    files, then the extras (report, bundle config). Each run file is opened
    O_NOFOLLOW relative to the run's directory fd and must stay the size it
    had when its header was written."""
    total = 0

    def emit(chunk: bytes) -> bytes:
        nonlocal total
        total += len(chunk)
        return chunk

    yield emit(_header(f"{stamp}/", mtime=run.dir_mtime, directory=True))
    for name in run.names:
        try:
            fd = os.open(name, _READ_FLAGS, dir_fd=run.dfd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise SealError(f"refused: {_show(name)} became a symlink") from None
            raise SealError(f"{_show(name)} cannot be read ({_why(exc)})") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise SealError(f"refused: {_show(name)} is not a regular file")
            yield emit(_header(f"{stamp}/{name}", size=st.st_size, mtime=st.st_mtime))
            left = st.st_size
            while left:
                chunk = os.read(fd, min(CHUNK, left))
                if not chunk:
                    raise SealError(f"{_show(name)} shrank while it was being sealed")
                left -= len(chunk)
                yield emit(chunk)
            if os.read(fd, 1):
                raise SealError(f"{_show(name)} grew while it was being sealed")
            yield emit(_pad(st.st_size))
        finally:
            os.close(fd)
    for extra in extras:
        yield emit(_header(extra.arcname, size=len(extra.data), mtime=extra.mtime))
        yield emit(extra.data)
        yield emit(_pad(len(extra.data)))
    end = 2 * BLOCK                                   # end-of-archive marker
    end += (-(total + end)) % RECORD                  # pad to a whole record
    yield emit(b"\0" * end)


class TarStream(io.RawIOBase):
    """A readable stream over `tar_chunks`; counts the plaintext bytes and
    keeps the first exception (the encryptor wraps it otherwise)."""

    def __init__(self, chunks: Iterator[bytes]) -> None:
        super().__init__()
        self._chunks = chunks
        self._buf = memoryview(b"")
        self.size = 0
        self.error: Optional[BaseException] = None

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        try:
            while not len(self._buf):
                chunk = next(self._chunks, None)
                if chunk is None:
                    return 0
                self._buf = memoryview(chunk)
            n = min(len(buffer), len(self._buf))
            buffer[:n] = self._buf[:n]
            self._buf = self._buf[n:]
            self.size += n
            return n
        except BaseException as exc:
            if self.error is None:
                self.error = exc
            raise


class CipherSink:
    """Where the encryptor writes: straight to the `.tmp` fd, hashing and
    counting the ciphertext on the way."""

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self.sha = hashlib.sha256()
        self.size = 0
        self.error: Optional[BaseException] = None

    def write(self, data: Any) -> int:
        try:
            view = memoryview(data)
            n = len(view)
            while len(view):
                view = view[os.write(self._fd, view):]
            self.sha.update(data)
            self.size += n
            return n
        except BaseException as exc:
            if self.error is None:
                self.error = exc
            raise

    def flush(self) -> None:
        return None


def _raise_cause(cause: Optional[BaseException], fallback: str) -> NoReturn:
    """Re-raise what really stopped the encryptor (pyrage wraps a callback's
    exception into its own error). KeyboardInterrupt / SystemExit stop the
    WHOLE tool, never just this run; a full disk stops the loop."""
    if cause is None:
        raise SealError(fallback)
    if not isinstance(cause, Exception):
        raise cause
    if _is_disk_full(cause):
        raise DiskFull(_why(cause)) from None
    raise SealError(_why(cause)) from None


# ---------------------------------------------------------------------------
# Output files
# ---------------------------------------------------------------------------

def _unlink_quiet(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in _DIR_FSYNC_UNSUPPORTED:
            raise
    finally:
        os.close(fd)


def _write_atomic(directory: Path, name: str, text: str) -> None:
    tmp = directory / f"{name}{TMP}"
    _unlink_quiet(tmp)
    fd = os.open(tmp, _NEW_FILE_FLAGS, 0o600)
    try:
        view = memoryview(text.encode("utf-8"))
        while len(view):
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, directory / name)


def sealed_groups(sealed_root: Path) -> dict[str, list[str]]:
    """stamp → the names this tool writes for it (outputs and their .tmp),
    as found in the sealed root. Directories and other names are ignored."""
    groups: dict[str, list[str]] = {}
    with os.scandir(sealed_root) as it:
        for entry in it:
            if entry.is_dir(follow_symlinks=False):
                continue
            name = entry.name
            base = name[:-len(TMP)] if name.endswith(TMP) else name
            for suffix in OUTPUT_SUFFIXES:
                if base.endswith(suffix):
                    stamp = base[:-len(suffix)]
                    if parse_stamp(stamp) is not None and stamp + suffix == base:
                        groups.setdefault(stamp, []).append(name)
                    break
    return groups


SHA_LINE = re.compile(r"[0-9a-f]{64}  (\S+)\n")


def _read_small(path: Path, limit: int = 4096) -> bytes:
    fd = os.open(path, _READ_FLAGS)
    try:
        return os.read(fd, limit)
    finally:
        os.close(fd)


def is_sealed(sealed_root: Path, stamp: str) -> bool:
    """All four outputs are regular files and `.complete` holds exactly the
    `.sha256` line for `<stamp>.tar.age`. A lone (stray, planted) .complete,
    or one whose .tar.age was deleted, is NOT sealed: the run is sealed again."""
    try:
        for suffix in OUTPUT_SUFFIXES:
            if not stat.S_ISREG(os.lstat(sealed_root / f"{stamp}{suffix}").st_mode):
                return False
        complete = _read_small(sealed_root / f"{stamp}{SUFFIX_COMPLETE}")
        sha = _read_small(sealed_root / f"{stamp}{SUFFIX_SHA}")
    except OSError:
        return False
    try:
        m = SHA_LINE.fullmatch(complete.decode("ascii"))
    except UnicodeDecodeError:
        return False
    return complete == sha and m is not None and m.group(1) == f"{stamp}{SUFFIX_AGE}"


def _remove_leftovers(sealed_root: Path, stamp: str) -> list[str]:
    """Everything an interrupted seal of `stamp` left (it is not sealed):
    the temp files and any output written before the interruption,
    `.complete` FIRST (a puller never sees it without its .tar.age)."""
    removed = []
    for suffix in (SUFFIX_COMPLETE, SUFFIX_AGE, SUFFIX_SHA, SUFFIX_META):
        for name in (f"{stamp}{suffix}", f"{stamp}{suffix}{TMP}"):
            path = sealed_root / name
            if os.path.lexists(path):
                os.unlink(path)
                removed.append(name)
    return removed


@dataclass
class Sealed:
    stamp: str
    meta: dict[str, Any]
    sha256: str
    leftovers: list[str]


def seal_run(*, backups_root: Path, sealed_root: Path, run: Run, kind: str,
             backup_rc: RC, chain_rc: RC, extras: list[Extra],
             encryption: archive_crypto.ArchiveEncryption,
             clock: Callable[[], datetime]) -> Sealed:
    """Seal one run (it is not sealed). SealError = the one-line reason
    (DiskFull: the sealed root is full). A failure never leaves a .complete:
    the `.tmp` is removed, and anything written before the failure is removed
    by the next seal of the run. KeyboardInterrupt / SystemExit propagate."""
    stamp = run.stamp
    opened = open_run(backups_root, stamp)
    final = sealed_root / f"{stamp}{SUFFIX_AGE}"
    tmp = sealed_root / f"{stamp}{SUFFIX_AGE}{TMP}"
    try:
        if not opened.names:
            raise SealError("the run directory is empty")
        leftovers = _remove_leftovers(sealed_root, stamp)
        fd = os.open(tmp, _NEW_FILE_FLAGS, 0o600)
        try:
            chunks = tar_chunks(opened, stamp, extras)
            source = TarStream(chunks)
            sink = CipherSink(fd)
            try:
                encryption.encrypt_stream(io.BufferedReader(source, CHUNK), sink)
            except archive_crypto.EncryptionConfigError as exc:
                _raise_cause(source.error or sink.error, str(exc))
            finally:
                chunks.close()
            if source.error is not None or sink.error is not None:
                # the encryptor said "done" although a callback failed
                _raise_cause(source.error or sink.error, "")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, final)
    except BaseException:
        _unlink_quiet(tmp)
        raise
    finally:
        opened.close()

    digest = sink.sha.hexdigest()
    sha_line = f"{digest}  {final.name}\n"
    meta = {
        "run_stamp": stamp,
        "kind": kind,
        "backup_rc": backup_rc,
        "chain_rc": chain_rc,
        "db_files": count_db_files(opened.names),
        "plaintext_bytes": source.size,
        "ciphertext_bytes": sink.size,
        "recipients_count": len(encryption.recipients),
        "sealed_at_utc": clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool_version": TOOL_VERSION,
    }
    _write_atomic(sealed_root, f"{stamp}{SUFFIX_SHA}", sha_line)
    _write_atomic(sealed_root, f"{stamp}{SUFFIX_META}",
                  json.dumps(meta, indent=2, sort_keys=True) + "\n")
    _fsync_dir(sealed_root)
    _write_atomic(sealed_root, f"{stamp}{SUFFIX_COMPLETE}", sha_line)    # LAST
    _fsync_dir(sealed_root)
    return Sealed(stamp, meta, digest, leftovers)


def prune(sealed_root: Path, cutoff: datetime, *, dry_run: bool) -> tuple[list[str], list[str]]:
    """Delete the sealed outputs of every run stamped before `cutoff`,
    `.complete` first (a puller never sees half a run). (stamps, errors)."""
    pruned, errors = [], []
    for stamp, names in sorted(sealed_groups(sealed_root).items()):
        when = parse_stamp(stamp)
        if when is None or when >= cutoff:
            continue
        if dry_run:
            pruned.append(stamp)
            continue
        complete = f"{stamp}{SUFFIX_COMPLETE}"
        try:
            for name in sorted(names, key=lambda n: (n != complete, n)):
                os.unlink(sealed_root / name)
            pruned.append(stamp)
        except OSError as exc:
            errors.append(f"{stamp}: prune failed ({_why(exc)})")
    return pruned, errors


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _say(msg: str) -> None:
    print(f"seal: {msg}", flush=True)


def _warn(msg: str) -> None:
    print(f"seal: warning: {msg}", file=sys.stderr, flush=True)


def _error(msg: str) -> None:
    print(f"seal: error: {msg}", file=sys.stderr, flush=True)


def _rc(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer exit code") from None
    if not 0 <= n <= 255:
        raise argparse.ArgumentTypeError("must be an exit code 0..255")
    return n


def _days(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number of days") from None
    if n < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return n


def _since(value: str) -> datetime:
    when = parse_stamp(value)
    if when is None:
        raise argparse.ArgumentTypeError(
            "must be a UTC time like 20261012T060000Z (date -u +%Y%m%dT%H%M%SZ)")
    return when


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="seal_backup_runs.py",
                                 description=__doc__.splitlines()[0])
    ap.add_argument("--backups-root", type=Path, required=True,
                    help="the backup runs (backup_databases.py --backups-root); read only")
    ap.add_argument("--sealed-root", type=Path, required=True,
                    help="the sealed outbox the vault pulls from (must exist, mode 0700)")
    ap.add_argument("--recipients", type=Path, required=True,
                    help="age recipients file: public keys (age1...), one per line")
    ap.add_argument("--backup-rc", type=_rc, default=None,
                    help="backup_databases.py's exit code, for the run being sealed now")
    ap.add_argument("--chain-rc", type=_rc, default=None,
                    help="verify_audit_chain.py's exit code, for the run being sealed now")
    ap.add_argument("--current-since", type=_since, default=None,
                    help="UTC time (YYYYMMDDTHHMMSSZ) taken just before the backup started: "
                         "the run the report names gets the codes only if stamped at or after it")
    ap.add_argument("--kind", choices=KINDS, default="auto",
                    help="kind of the run being sealed now (auto: by its start time)")
    ap.add_argument("--retention-days", type=_days, default=14,
                    help="prune sealed outputs of runs stamped more than N days ago (default 14)")
    ap.add_argument("--backfill", action="store_true",
                    help="seal every existing run not yet sealed, return codes 'unknown'")
    ap.add_argument("--config-file", type=Path, action="append", default=[],
                    help="a bundle file to include under bundle/ (repeatable)")
    ap.add_argument("--report", type=Path, default=None,
                    help=f"the backup report (default <backups-root>/{DEFAULT_REPORT_NAME})")
    ap.add_argument("--dry-run", action="store_true", help="say what would happen; write nothing")
    return ap


def _check_roots(backups_root: Path, sealed_root: Path) -> tuple[Path, Path]:
    for what, path in (("backups root", backups_root), ("sealed root", sealed_root)):
        if not path.is_dir():
            raise SetupError(f"the {what} {path} is not an existing directory")
    b, s = backups_root.resolve(strict=True), sealed_root.resolve(strict=True)
    if b == s or s.is_relative_to(b) or b.is_relative_to(s):
        raise SetupError("the sealed root and the backups root must be separate trees "
                         "(neither inside the other)")
    mode = os.stat(s).st_mode & 0o777
    if mode & 0o022:
        raise SetupError(f"group or other users can write the sealed root {s} (mode "
                         f"{mode:04o}): they could plant a run or a .complete for the vault to "
                         "pull. chmod 700 it")
    return b, s


def _take_lock(sealed_root: Path) -> int:
    """The seal lock, waiting up to LOCK_WAIT_SECONDS for another seal.
    Locked after the wait; SetupError when the filesystem cannot flock."""
    fd = os.open(sealed_root / LOCK_NAME,
                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        deadline = _monotonic() + LOCK_WAIT_SECONDS
        said = False
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except BlockingIOError:
                if _monotonic() >= deadline:
                    raise Locked() from None
                if not said:
                    _say(f"another seal holds the lock: waiting for it (up to "
                         f"{LOCK_WAIT_SECONDS // 60} min)")
                    said = True
                _sleep(LOCK_POLL_SECONDS)
            except OSError as exc:
                raise SetupError(
                    f"the seal lock cannot be taken in {sealed_root} ({_why(exc)}): this "
                    "filesystem does not support flock, and two seals at once could destroy "
                    "each other's output") from None
    except BaseException:
        os.close(fd)
        raise


def main(argv: Optional[list[str]] = None, *, now: Optional[datetime] = None) -> int:
    args = _parser().parse_args(argv)
    if args.backfill:
        if (args.backup_rc is not None or args.chain_rc is not None
                or args.current_since is not None):
            _error("--backfill records the return codes as 'unknown': do not pass "
                   "--backup-rc / --chain-rc / --current-since")
            return EXIT_SETUP
        if args.kind != "auto":
            _error("--backfill classifies each run by its own stamp: --kind must be auto")
            return EXIT_SETUP
    elif args.backup_rc is None or args.chain_rc is None or args.current_since is None:
        _error("--backup-rc, --chain-rc and --current-since are required (or --backfill)")
        return EXIT_SETUP

    started = now or datetime.now(timezone.utc)
    clock: Callable[[], datetime] = (lambda: now) if now else (lambda: datetime.now(timezone.utc))
    dry = args.dry_run
    if args.current_since is not None and args.current_since > started + CLOCK_SKEW:
        _error("--current-since is in the future: it must be the time just before the "
               "backup started")
        return EXIT_SETUP

    try:
        nightly_zone()
        backups_root, sealed_root = _check_roots(args.backups_root, args.sealed_root)
        try:
            recipients = archive_crypto.load_recipients(args.recipients)
            encryption = archive_crypto.with_recipients(recipients, source="file",
                                                        path=args.recipients)
        except archive_crypto.EncryptionConfigError as exc:
            raise SetupError(str(exc)) from None
        extras = load_config_files(args.config_file)
    except SetupError as exc:
        _error(str(exc))
        return EXIT_SETUP

    _say(f"recipients: {len(recipients)} ("
         + ", ".join(archive_crypto.recipient_short(r) for r in recipients) + ")")

    lock_fd: Optional[int] = None
    if not dry:
        if not os.access(sealed_root, os.W_OK | os.X_OK):
            _error(f"the sealed root {sealed_root} is not writable by this user "
                   f"(uid {os.getuid()}): chown it to this uid, mode 0700")
            return EXIT_SETUP
        try:
            lock_fd = _take_lock(sealed_root)
        except Locked:
            _error(f"another seal run held the lock for {LOCK_WAIT_SECONDS // 60} minutes; "
                   "nothing was sealed")
            return EXIT_LOCKED
        except SetupError as exc:
            _error(str(exc))
            return EXIT_SETUP
        except OSError as exc:
            _error(f"the seal lock cannot be created in {sealed_root} ({_why(exc)})")
            return EXIT_SETUP

    try:
        return _run(args, backups_root, sealed_root, encryption, extras, started, clock, dry)
    finally:
        if lock_fd is not None:
            os.close(lock_fd)


def _current_run(args: argparse.Namespace, scan: BackupsScan, sealed_root: Path,
                 report_stamp: Optional[str]) -> Optional[str]:
    """The run the codes belong to: the one the report names, made since
    --current-since, sealable and not sealed yet. Else None (said why)."""
    since = args.current_since
    since_text = since.strftime(RUN_STAMP_FORMAT)
    nowhere = "--backup-rc / --chain-rc / --kind are not recorded for any run"
    named_when = parse_stamp(report_stamp) if report_stamp else None
    if named_when is None or named_when < since:
        _say(f"the backup report names no run made since {since_text} (the backup "
             f"stopped before writing one?): {nowhere}")
        return None
    if report_stamp not in {r.stamp for r in scan.runs}:
        _say(f"the run the backup report names ({report_stamp}) is refused or missing: {nowhere}")
        return None
    if is_sealed(sealed_root, report_stamp):
        _say(f"{report_stamp}: already sealed; its codes and kind are not recorded again")
        return None
    return report_stamp


def _run(args: argparse.Namespace, backups_root: Path, sealed_root: Path,
         encryption: archive_crypto.ArchiveEncryption, extras: list[Extra],
         now: datetime, clock: Callable[[], datetime], dry: bool) -> int:
    failures = 0
    report_path = args.report or (backups_root / DEFAULT_REPORT_NAME)
    report_stamp, report_extra, report_warning = load_report(report_path)
    if report_warning:
        _warn(report_warning)

    scan = scan_backups(backups_root)
    for name, reason in scan.skipped:
        _warn(f"skipped {_show(name)}: {reason}")
    for stamp, reason in scan.refused:
        _error(f"{stamp}: {reason}")
        failures += 1

    # Prune FIRST: expired outputs free their space before anything is written.
    cutoff = now - timedelta(days=args.retention_days)
    pruned, prune_errors = prune(sealed_root, cutoff, dry_run=dry)
    for stamp in pruned:
        _say(f"{stamp}: {'would prune' if dry else 'pruned'} (older than "
             f"{args.retention_days} days)")
    for msg in prune_errors:
        _error(msg)
        failures += 1

    current = None if args.backfill else _current_run(args, scan, sealed_root, report_stamp)

    # The run made just now first, then the others newest first: when space
    # runs out, the runs that matter most are already sealed.
    order = sorted(scan.runs, key=lambda r: r.stamp, reverse=True)
    order.sort(key=lambda r: r.stamp != current)

    sealed_count = already = deferred = stale = empty = 0
    planned = 0
    for index, run in enumerate(order):
        if is_sealed(sealed_root, run.stamp):
            already += 1
            continue
        if run.when < cutoff:
            stale += 1
            _say(f"{run.stamp}: older than {args.retention_days} days, past the sealed "
                 "retention: not sealed")
            continue
        if run.stamp == current:
            backup_rc, chain_rc = args.backup_rc, args.chain_rc
            kind = classify_kind(run.when) if args.kind == "auto" else args.kind
            role = "this run"
        else:
            backup_rc = chain_rc = UNKNOWN
            kind = classify_kind(run.when)
            role = "backfill" if args.backfill else "catch-up"
        extra = list(extras)
        named = report_stamp == run.stamp
        if report_extra is not None and named:
            extra.insert(0, report_extra)
        label = f"{kind}, {role}, backup_rc={backup_rc}, chain_rc={chain_rc}"

        try:
            probe = open_run(backups_root, run.stamp)       # validates it, dry run too
            try:
                files = len(probe.names)
                ready, how = ready_to_seal(probe, named_by_report=named, when=run.when, now=now)
                need = estimate_bytes(probe, extra)
            finally:
                probe.close()
            if not files:
                empty += 1
                _warn(f"{run.stamp}: the run directory holds no files (a backup that is "
                      "starting, or one that stopped early): not sealed")
                continue
            if not ready:
                deferred += 1
                _say(f"{run.stamp}: not marked finished ({RUN_REPORT_NAME}) and not named by "
                     "the report (still being written?): deferred to a later seal")
                continue
            if how:
                label += f"; {how}"
            if dry:
                _say(f"{run.stamp}: would seal ({label}; {files} files"
                     + (", with its backup report" if named else "") + ")")
                sealed_count += 1
                planned += need
                continue
            free = free_bytes(sealed_root)
            if free < need + FREE_SPACE_RESERVE:
                raise DiskFull(f"not enough free space in the sealed root (the run needs "
                               f"about {_gib(need)} plus a {_gib(FREE_SPACE_RESERVE)} "
                               f"reserve; {_gib(free)} free)")
            result = seal_run(backups_root=backups_root, sealed_root=sealed_root, run=run,
                              kind=kind, backup_rc=backup_rc, chain_rc=chain_rc,
                              extras=extra, encryption=encryption, clock=clock)
        except (SealError, OSError) as exc:
            failures += 1
            if _is_disk_full(exc):
                left = sum(1 for r in order[index + 1:]
                           if r.when >= cutoff and not is_sealed(sealed_root, r.stamp))
                _error(f"{run.stamp}: {_why(exc)}: sealing stops here"
                       + (f" ({left} more run(s) left for a later seal)" if left else ""))
                break
            _error(f"{run.stamp}: {_why(exc)}")
            continue
        except Exception as exc:  # noqa: BLE001 — one line per run, then the next run
            failures += 1
            _error(f"{run.stamp}: unexpected {type(exc).__name__}")
            continue
        sealed_count += 1
        meta = result.meta
        redo = "; redone after an interrupted seal" if result.leftovers else ""
        _say(f"{run.stamp}: sealed ({label}; {meta['db_files']} db files, "
             f"{meta['plaintext_bytes']} -> {meta['ciphertext_bytes']} bytes, "
             f"sha256 {result.sha256[:16]}…{redo})")

    if dry:
        free = free_bytes(sealed_root)
        _say(f"dry run: the runs to seal take about {planned} bytes ({_gib(planned)}); "
             f"{free} bytes ({_gib(free)}) free in the sealed root, "
             f"{_gib(FREE_SPACE_RESERVE)} of it kept in reserve")
        if planned + FREE_SPACE_RESERVE > free:
            _warn("they do not all fit: sealing would stop when the space runs out "
                  "(the newest runs go first)")

    verb = "would seal" if dry else "sealed"
    _say(f"{'dry run — nothing was written; ' if dry else ''}{verb} {sealed_count}, "
         f"already sealed {already}, deferred {deferred}, empty {empty}, past retention "
         f"{stale}, skipped {len(scan.skipped)}, failed {failures}, "
         f"{'would prune' if dry else 'pruned'} {len(pruned)}")
    return EXIT_FAILED if failures else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
