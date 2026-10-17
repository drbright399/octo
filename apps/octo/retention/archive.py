"""Cold archive for raw telemetry — written BEFORE a raw row is pruned.

Layout under the archive root (`OCTO_ARCHIVE_ROOT`, bulk storage — an
array share, never the SSD the SQLite state lives on):

    telemetry/<slug>/<YYYY>/<slug>-telemetry-<YYYY-MM-DD>.jsonl.gz            plaintext
    telemetry/<slug>/<YYYY>/<slug>-telemetry-<YYYY-MM-DD>.jsonl.gz.sha256
    telemetry/<slug>/<YYYY>/<slug>-telemetry-<YYYY-MM-DD>.p001.jsonl.gz.age   encrypted part
    telemetry/<slug>/<YYYY>/<slug>-telemetry-<YYYY-MM-DD>.p001.jsonl.gz.age.sha256
    telemetry/<slug>/<YYYY>/<slug>-telemetry-<YYYY-MM-DD>.jsonl.gz.age        converted day file
    telemetry/<slug>/<YYYY>/<slug>-telemetry-<YYYY-MM-DD>.ids                 row-id ledger
    telemetry/<slug>/manifest.json

One day = one tenant's rows of one UTC day of ARRIVAL (the day of
`ingested_at` — the retention's clock, owner decision 2026-09-29: a day holds
what reached Athena that day and is pruned from telemetry.db as one unit).
Each line is one `telemetry_raw` row, exactly as stored (payload text
verbatim, identity fields untouched, `received_at` = the sensor's own time)
plus `tenant`. For a live feed the two days agree except for lookups within
seconds of midnight UTC; a sensor with a wrong clock or a forwarded backlog
files by when it arrived — to find a sensor-time day, load its neighbours
too. A row id is never archived twice for a day.

PLAINTEXT (`OCTO_ARCHIVE_ENCRYPTION=off`, and everything written before
2026-10-07): one gzip JSONL file per day. A later run that finds more rows
for a day already archived (a row that arrived late, the one-off move from
events.db) APPENDS a gzip member — a multi-member gzip is one valid gzip
stream — and dedupes by reading the row ids back out of the file.

ENCRYPTED (`archive_crypto`: age v1, X25519, to the operator's PUBLIC keys —
Athena holds no private key and cannot read these back): the rows a run
archives for a day go to a new PART, `<day>.pNNN.jsonl.gz.age` — the gzip
JSONL above, encrypted after compression; one part per run per day (a
further part each `PART_MAX_BYTES` of compressed rows, so memory stays
bounded). The sidecar covers the CIPHERTEXT. Because the parts cannot be
read, the dedupe source for them is the day's plaintext ROW-ID LEDGER
(`<day>.ids`: per encrypted file its row ids as ranges — ids only, no
payload). It is written BEFORE the part (a crash in between leaves an entry
for a file that does not exist: never counted, dropped by the next write), so
a part on disk always has its ids recorded; a part the ledger does not name
fails the day closed. A day may hold a plaintext file AND encrypted files
(the ids of both count); restore reads them as one day.
`scripts/encrypt_archive.py` converts existing plaintext day files
(`<day>.jsonl.gz.age`, recorded with the plaintext's sha256 in the manifest
and the ledger) and deletes a plaintext only after a recorded decrypt
round-trip with the operator's identity.

The first encrypted file also writes a marker, `telemetry/.archive-encrypted`:
from then on the archive counts as encrypted, so with
`OCTO_ARCHIVE_ENCRYPTION` unset a recipients file that goes missing fails it
closed (`archive_crypto.load_policy(in_use=…)`) — plaintext again only by
`OCTO_ARCHIVE_ENCRYPTION=off`, said explicitly.

`manifest.json` (version 2) records per FILE: day, encrypted yes/no, scheme
`age-x25519`, the recipients' public keys, part number, row count, sha256,
bytes (and for converted files the plaintext's sha256, and a verify record);
`days` keeps a per-day summary (the 2026-10-07 format's file / rows / sha256
/ bytes for the plaintext day file, plus every file of the day).

Every write is atomic: the new file is written beside the old one, fsync'd,
renamed over it, and the directory fsync'd; the `.sha256` sidecar
(`sha256sum -c` format), the ledger and the tenant manifest follow the same
way. A write that fails raises `ArchiveError` and the caller does NOT prune
those rows. The archive itself is never pruned by Athena.

A write KILLED between its temp file and the rename (SIGKILL on a container
recreate, the OOM killer, power loss) leaves `.<file>.tmp-<hex>` behind —
for a plaintext day file, a full PLAINTEXT copy of the day plus the chunk
being added. Its rows are never counted as archived (that happens only after
the rename), so they are in the committed archive or still in telemetry.db:
the temp is what `_atomic_write` itself unlinks after any failure it lives
through. `file_counts` counts such plaintext temps as plaintext (Settings →
System says so), `leftover_temps` lists them, and `encrypt_archive.py
--delete-plaintext` removes them under the run lock.

Permissions: the archive holds UNMASKED raw DNS with device names for every
tenant (the dashboard masks it and the search puts it behind step-up), so
every folder Athena creates under the root is 0700 and every file 0600,
whatever the process umask — never readable by other users or containers
on the host. The root itself is the operator's mount; `permission_warning`
says when it is group- or world-accessible (Settings → System, the scripts).
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import uuid
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from apps.octo import paths
from apps.octo.retention import archive_crypto as crypto
from apps.octo.retention.archive_crypto import (
    AgeIdentities,
    ArchiveEncryption,
    DecryptionError,
    EncryptionConfigError,
)

KIND = "telemetry"
MANIFEST_VERSION = 2
_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PLAIN_SUFFIX = ".jsonl.gz"
AGE_SUFFIX = ".jsonl.gz.age"
LEDGER_SUFFIX = ".ids"
# Compressed rows a run holds in memory for one encrypted part before it
# writes it and starts the next (plaintext appends per chunk instead).
PART_MAX_BYTES = 64 * 1024 * 1024
_PART_RE = re.compile(r"\.p(\d{3,})" + re.escape(AGE_SUFFIX) + r"$")
# Under `<root>/telemetry/`: written before the first encrypted file — the
# archive has held encrypted files (see the module docstring).
ENCRYPTED_MARKER = ".archive-encrypted"
# `.<target file name>.tmp-<hex>` — `_atomic_write`'s temp file.
_TEMP_RE = re.compile(r"^\.(?P<target>.+)\.tmp-[0-9a-f]+$")
_LEDGER_HEADER = (
    "# Athena cold-archive row-id ledger: row ids only, no payload.\n"
    "# One line per encrypted file of the day: <file name> <id ranges>\n"
)
# The file-count walk for Settings → System stops here (a status line, not
# an inventory).
COUNT_LIMIT = 500_000


class ArchiveError(Exception):
    """The archive could not be written or read as expected."""


@dataclass(frozen=True)
class ArchiveWrite:
    day: str
    file: str
    rows_added: int
    rows_already: int
    rows_total: int
    sha256: str
    bytes: int
    encrypted: bool = False
    files: tuple[str, ...] = ()        # every file this write created / changed


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


DIR_MODE = 0o700
FILE_MODE = 0o600


def _mkdirs(root: Path, target: Path) -> None:
    """Create `target` (under `root`) and every missing folder between them
    at DIR_MODE — `Path.mkdir(parents=True)` gives parents the umask's
    default (0755 under umask 022). The root itself must exist."""
    rel = target.relative_to(root)
    current = root
    for part in rel.parts:
        current = current / part
        try:
            current.mkdir(mode=DIR_MODE)
        except FileExistsError:
            continue
        os.chmod(current, DIR_MODE)      # umask may have taken bits off


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex[:8]}")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), FILE_MODE)   # whatever the umask
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
    _fsync_dir(path.parent)


def _jsonl(rows: Iterable[dict[str, Any]]) -> bytes:
    return b"".join(
        (json.dumps(r, separators=(",", ":"), sort_keys=True, ensure_ascii=False) + "\n")
        .encode("utf-8")
        for r in rows
    )


def _parse(data: bytes, where: str) -> list[dict[str, Any]]:
    try:
        text = gzip.decompress(data).decode("utf-8")
    except (OSError, EOFError, zlib.error, UnicodeDecodeError) as exc:
        raise ArchiveError(f"{where}: not a readable gzip JSONL file ({type(exc).__name__})")
    out: list[dict[str, Any]] = []
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            raise ArchiveError(f"{where}: line {n} is not JSON")
        if not isinstance(row, dict) or not isinstance(row.get("id"), int):
            raise ArchiveError(f"{where}: line {n} has no row id")
        out.append(row)
    return out


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ranges(ids: Iterable[int]) -> str:
    """Sorted ids as `a-b` runs (`1-500,502,504-900`)."""
    s = sorted(set(ids))
    out, i = [], 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and s[j + 1] == s[j] + 1:
            j += 1
        out.append(str(s[i]) if i == j else f"{s[i]}-{s[j]}")
        i = j + 1
    return ",".join(out)


# One id range in a ledger never spans more rows than a tenant-day could
# hold: a damaged ledger fails its day closed instead of exhausting memory.
MAX_LEDGER_RANGE = 10_000_000


def _parse_ranges(text: str, where: str) -> set[int]:
    out: set[int] = set()
    if not text:
        return out
    for tok in text.split(","):
        try:
            if "-" in tok:
                a, b = (int(x) for x in tok.split("-", 1))
                if a < 1 or b < a or b - a > MAX_LEDGER_RANGE:
                    raise ValueError
                out.update(range(a, b + 1))
            else:
                v = int(tok)
                if v < 1:
                    raise ValueError
                out.add(v)
        except ValueError:
            raise ArchiveError(f"{where}: not a row-id ledger (bad id range)") from None
    return out


def is_encrypted_name(name: str) -> bool:
    return name.endswith(AGE_SUFFIX)


def temp_target(name: str) -> Optional[str]:
    """The file a leftover `_atomic_write` temp was to become, or None."""
    m = _TEMP_RE.match(name)
    return m.group("target") if m else None


def is_plaintext_temp(name: str) -> bool:
    """A leftover temp of a PLAINTEXT day file (plaintext rows inside)."""
    target = temp_target(name)
    return bool(target and target.endswith(PLAIN_SUFFIX) and f"-{KIND}-" in target)


def part_number(name: str) -> Optional[int]:
    m = _PART_RE.search(name)
    return int(m.group(1)) if m else None


@dataclass
class _DayState:
    """What one day holds, read once by a writer (the run lock makes it the
    only writer)."""
    plain_ids: set[int] = field(default_factory=set)
    plain_sha: Optional[str] = None                            # the plaintext file's
    ledger: dict[str, set[int]] = field(default_factory=dict)  # file name → ids
    present: set[str] = field(default_factory=set)             # encrypted names on disk
    stale: set[str] = field(default_factory=set)               # ledger names not on disk
    known: set[int] = field(default_factory=set)
    next_part: int = 1


class ColdArchive:
    def __init__(
        self, root: Path, encryption: Optional[ArchiveEncryption] = None, *,
        part_max_bytes: int = PART_MAX_BYTES,
    ) -> None:
        """`encryption`: what NEW files get (default: plaintext — the
        environment's policy comes with `from_env`)."""
        self.root = Path(root)
        self.encryption = encryption if encryption is not None else ArchiveEncryption()
        self.part_max_bytes = max(1, int(part_max_bytes))

    @classmethod
    def from_env(cls, root: Optional[Path] = None) -> Optional["ColdArchive"]:
        """The archive the environment configures (`OCTO_ARCHIVE_ROOT`, or
        `root`) with its encryption policy (`OCTO_ARCHIVE_ENCRYPTION`,
        `OCTO_ARCHIVE_RECIPIENTS_PATH`); None = archive disabled."""
        root = root if root is not None else paths.archive_root()
        if root is None:
            return None
        archive = cls(root)
        # An archive that already holds encrypted files stays encrypted
        # (fail closed) unless OCTO_ARCHIVE_ENCRYPTION=off says otherwise.
        archive.encryption = crypto.load_policy(in_use=archive.encryption_in_use())
        return archive

    # ----- layout -----

    def tenant_dir(self, slug: str) -> Path:
        paths.validate_slug(slug)
        return self.root / KIND / slug

    def _prefix(self, slug: str, day: str) -> str:
        if not _DAY_RE.match(day or ""):
            raise ArchiveError(f"invalid archive day {day!r}")
        return f"{slug}-{KIND}-{day}"

    def day_file(self, slug: str, day: str) -> Path:
        """The day's PLAINTEXT file."""
        prefix = self._prefix(slug, day)
        return self.tenant_dir(slug) / day[:4] / f"{prefix}{PLAIN_SUFFIX}"

    def converted_file(self, slug: str, day: str) -> Path:
        """The plaintext day file as `encrypt_archive.py` encrypted it."""
        p = self.day_file(slug, day)
        return p.with_name(p.name + ".age")

    def part_file(self, slug: str, day: str, n: int) -> Path:
        prefix = self._prefix(slug, day)
        return self.tenant_dir(slug) / day[:4] / f"{prefix}.p{n:03d}{AGE_SUFFIX}"

    def ledger_file(self, slug: str, day: str) -> Path:
        prefix = self._prefix(slug, day)
        return self.tenant_dir(slug) / day[:4] / f"{prefix}{LEDGER_SUFFIX}"

    @staticmethod
    def sidecar(path: Path) -> Path:
        return path.with_name(path.name + ".sha256")

    def _rel(self, slug: str, path: Path) -> str:
        return str(path.relative_to(self.tenant_dir(slug)))

    def encrypted_files(self, slug: str, day: str) -> list[Path]:
        """The day's encrypted files on disk: the converted day file first,
        then the parts by number."""
        conv = self.converted_file(slug, day)
        prefix = self._prefix(slug, day)
        folder = conv.parent
        if not folder.is_dir():
            return []
        parts = sorted(
            (p for p in folder.glob(f"{prefix}.p*{AGE_SUFFIX}") if part_number(p.name)),
            key=lambda p: part_number(p.name) or 0,
        )
        return ([conv] if conv.exists() else []) + parts

    def day_files(self, slug: str, day: str) -> list[Path]:
        """Every data file of the day: plaintext, converted, parts."""
        plain = self.day_file(slug, day)
        return ([plain] if plain.exists() else []) + self.encrypted_files(slug, day)

    def days(self, slug: str) -> list[str]:
        """Every day the tenant's folder holds a data file for."""
        out: set[str] = set()
        base = self.tenant_dir(slug)
        if not base.is_dir():
            return []
        pat = re.compile(rf"^{re.escape(slug)}-{KIND}-(\d{{4}}-\d{{2}}-\d{{2}})(\.p\d{{3,}})?"
                         rf"{re.escape(PLAIN_SUFFIX)}(\.age)?$")
        for year in base.iterdir():
            if not year.is_dir():
                continue
            for f in year.iterdir():
                m = pat.match(f.name)
                if m:
                    out.add(m.group(1))
        return sorted(out)

    def leftover_temps(self, slug: str) -> dict[str, list[Path]]:
        """day → the temp files interrupted writes left in the tenant's
        folders for that day (data files, sidecars, ledger). Leftovers only
        while no writer runs (the run lock)."""
        base = self.tenant_dir(slug)
        pat = re.compile(rf"^{re.escape(slug)}-{KIND}-(\d{{4}}-\d{{2}}-\d{{2}})\.")
        out: dict[str, list[Path]] = {}
        if not base.is_dir():
            return out
        for year in sorted(base.iterdir()):
            if not year.is_dir():
                continue
            for f in sorted(year.iterdir()):
                target = temp_target(f.name)
                m = pat.match(target) if target else None
                if m and f.is_file():
                    out.setdefault(m.group(1), []).append(f)
        return out

    def remove_leftover_temps(self, slug: str, day: str) -> list[dict[str, Any]]:
        """Unlink the day's leftover temp files (`leftover_temps`). Their
        rows were never counted as archived: they are in the committed files
        or still in telemetry.db (a temp is what `_atomic_write` unlinks
        after any failure it lives through). NOT a secure erase. Caller
        holds the run lock."""
        out: list[dict[str, Any]] = []
        for f in self.leftover_temps(slug).get(day, []):
            try:
                f.unlink()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ArchiveError(f"{f}: {type(exc).__name__}: {exc}") from None
            out.append({"day": day, "file": str(f), "plaintext": is_plaintext_temp(f.name)})
        if out:
            _fsync_dir(Path(out[0]["file"]).parent)
        return out

    def tenants(self) -> list[str]:
        base = self.root / KIND
        if not base.is_dir():
            return []
        out = []
        for d in sorted(base.iterdir()):
            try:
                paths.validate_slug(d.name)
            except ValueError:
                continue
            if d.is_dir():
                out.append(d.name)
        return out

    # ----- state -----

    def permission_warning(self) -> Optional[str]:
        """Why the ROOT is too open (group or others can enter or read it —
        the files below are 0600 in 0700 folders, but a root that others
        can list is a misconfigured share), or None. Informational: it does
        not block pruning."""
        try:
            mode = self.root.stat().st_mode & 0o777
        except OSError:
            return None
        if mode & 0o077:
            return (f"archive root {self.root} is accessible to other users "
                    f"(mode {mode:04o}) — it holds unmasked DNS history for every "
                    "tenant: chmod 700 it (owner uid 1000)")
        return None

    def unusable_reason(self) -> Optional[str]:
        """None when the root exists and is writable and — encryption
        required — the recipients are usable; otherwise why not. A configured
        root that is unusable BLOCKS pruning (a missing mount must never turn
        into silently unarchived deletes; nor may a required encryption whose
        keys are missing turn into plaintext)."""
        if not self.root.is_dir():
            return f"archive root {self.root} does not exist (mount missing?)"
        if not os.access(self.root, os.W_OK | os.X_OK):
            return f"archive root {self.root} is not writable"
        enc = self.encryption
        if enc.required and not enc.active:
            return ("archive encryption is required but unusable — "
                    + (enc.error or "no recipients"))
        return None

    def file_counts(self, *, limit: int = COUNT_LIMIT) -> dict[str, Any]:
        """{plaintext, encrypted, plaintext_temp, complete}: data files under
        the root (sidecars, ledgers not counted). A temp file an interrupted
        write left of a PLAINTEXT day file holds plaintext rows: counted in
        `plaintext` and in `plaintext_temp` (`encrypt_archive.py
        --delete-plaintext` removes them). `complete` False = the walk
        stopped at `limit` or could not read a folder."""
        def subdirs(path) -> list[str]:
            with os.scandir(path) as it:
                return [e.path for e in it if e.is_dir()]

        plain = enc = temps = 0

        def counts(complete: bool) -> dict[str, Any]:
            return {"plaintext": plain, "encrypted": enc, "plaintext_temp": temps,
                    "complete": complete}

        complete = True
        try:
            tenant_dirs = subdirs(self.root / KIND)
        except FileNotFoundError:
            return counts(True)
        except OSError:
            return counts(False)
        for t in tenant_dirs:
            try:
                for y in subdirs(t):
                    with os.scandir(y) as it:
                        names = [e.name for e in it]
                    for name in names:
                        if name.startswith("."):
                            if is_plaintext_temp(name):
                                plain += 1
                                temps += 1
                            continue
                        if name.endswith(AGE_SUFFIX):
                            enc += 1
                        elif name.endswith(PLAIN_SUFFIX):
                            plain += 1
                    if plain + enc >= limit:
                        return counts(False)
            except OSError:
                complete = False
        return counts(complete)

    # ----- the "has held encrypted files" marker -----

    def encryption_marker(self) -> Path:
        return self.root / KIND / ENCRYPTED_MARKER

    def encryption_in_use(self) -> bool:
        """The archive has held encrypted files (its marker exists)."""
        try:
            return self.encryption_marker().is_file()
        except OSError:
            return False

    def _mark_encrypted(self) -> None:
        """Write the marker before the first encrypted file (OSError to the
        caller, which fails the write)."""
        marker = self.encryption_marker()
        if marker.exists():
            return
        _mkdirs(self.root, marker.parent)
        _atomic_write(marker, (json.dumps({
            "scheme": crypto.SCHEME, "since": _now(),
            "note": ("this archive holds encrypted files: with OCTO_ARCHIVE_ENCRYPTION "
                     "unset, a missing recipients file fails it closed; plaintext "
                     "again only with OCTO_ARCHIVE_ENCRYPTION=off"),
        }, indent=2, sort_keys=True) + "\n").encode())

    # ----- the ledger -----

    def _read_ledger(self, slug: str, day: str) -> dict[str, set[int]]:
        path = self.ledger_file(slug, day)
        try:
            text = path.read_text() if path.exists() else ""
        except (OSError, UnicodeDecodeError) as exc:
            raise ArchiveError(f"{path}: {type(exc).__name__}")
        prefix = self._prefix(slug, day)
        out: dict[str, set[int]] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, _, ranges = line.partition(" ")
            if not (name.startswith(prefix + ".") and is_encrypted_name(name)):
                raise ArchiveError(f"{path}: not a row-id ledger of {slug} on {day}")
            out.setdefault(name, set()).update(_parse_ranges(ranges.strip(), str(path)))
        return out

    def _write_ledger(self, slug: str, day: str, ledger: dict[str, set[int]]) -> None:
        body = "".join(f"{name} {_ranges(ids)}\n" for name, ids in sorted(ledger.items()))
        _atomic_write(self.ledger_file(slug, day), (_LEDGER_HEADER + body).encode())

    def _day_state(self, slug: str, day: str, plain_data: Optional[bytes] = None) -> _DayState:
        """Read the day once: plaintext ids, the ledger, the encrypted files
        on disk. ArchiveError for a file that cannot be read or parsed, and
        for an encrypted file the ledger does not name (its rows cannot be
        told without the private key: fail closed). `plain_data`: the
        plaintext file's bytes, when the caller has just read them."""
        plain = self.day_file(slug, day)
        st = _DayState()
        try:
            if plain_data is not None:
                data = plain_data
            else:
                data = plain.read_bytes() if plain.exists() else b""
        except OSError as exc:
            raise ArchiveError(f"{plain}: {type(exc).__name__}: {exc}")
        if data:
            st.plain_ids = {r["id"] for r in _parse(data, str(plain))}
            st.plain_sha = _sha(data)
        st.ledger = self._read_ledger(slug, day)
        try:
            st.present = {p.name for p in self.encrypted_files(slug, day)}
        except OSError as exc:
            raise ArchiveError(f"{plain.parent}: {type(exc).__name__}: {exc}")
        unledgered = sorted(st.present - set(st.ledger))
        if unledgered:
            raise ArchiveError(
                f"{plain.parent}: {', '.join(unledgered)} not in the day's row-id ledger "
                f"({self.ledger_file(slug, day).name}) — which rows it holds cannot be told "
                "without the private key, so nothing more is archived for this day until "
                "the ledger is restored")
        st.stale = set(st.ledger) - st.present
        st.known = set(st.plain_ids)
        for name in st.present:
            st.known |= st.ledger[name]
        numbers = [n for n in (part_number(x) for x in set(st.ledger) | st.present) if n]
        st.next_part = max(numbers, default=0) + 1
        return st

    def known_ids(self, slug: str, day: str) -> set[int]:
        """Row ids already archived for the day — in its plaintext file and
        (by the ledger) its encrypted files. Raises ArchiveError for a file
        that cannot be read or parsed."""
        return self._day_state(slug, day).known

    def _repair_sidecars(self, slug: str, day: str, st: _DayState) -> None:
        """An encrypted file whose sidecar is missing (a crash between the
        two renames): rewritten when the file matches the manifest's sha256,
        else the day fails closed."""
        files = self.manifest(slug).get("files") or {}
        for name in sorted(st.present):
            path = self.day_file(slug, day).with_name(name)
            side = self.sidecar(path)
            if side.exists():
                continue
            sha = _sha(path.read_bytes())
            want = (files.get(self._rel(slug, path)) or {}).get("sha256")
            if sha != want:
                raise ArchiveError(f"{path}: no .sha256 sidecar, and it does not match the "
                                   "manifest — check it before archiving more of this day")
            _atomic_write(side, f"{sha}  {name}\n".encode())

    # ----- write -----

    def day_writer(self, slug: str, day: str) -> "DayWriter":
        return DayWriter(self, slug, day)

    def append(self, slug: str, day: str, rows: Sequence[dict[str, Any]]) -> ArchiveWrite:
        """Archive `rows` (telemetry_raw rows of one UTC day) for `slug` in
        one go. Rows already archived for the day (by id) are not written
        again. Raises ArchiveError when anything could not be written
        durably. (A caller archiving a large day in chunks uses
        `day_writer`: one read of the day, one encrypted part.)"""
        w = self.day_writer(slug, day)
        w.add(rows)
        return w.finish()

    def _manifest_for_write(self, slug: str) -> dict[str, Any]:
        """The manifest, upgraded to version 2 (the 2026-10-07 format had
        `days` only: each day's plaintext file becomes a `files` entry)."""
        m = self.manifest(slug)
        m.setdefault("tenant", slug)
        m.setdefault("kind", KIND)
        files = m.setdefault("files", {})
        for day, entry in (m.get("days") or {}).items():
            rel = entry.get("file") if isinstance(entry, dict) else None
            if rel and rel not in files and not is_encrypted_name(rel):
                files[rel] = {
                    "day": day, "encrypted": False, "scheme": None, "recipients": [],
                    "part": None, "rows": entry.get("rows"), "sha256": entry.get("sha256"),
                    "bytes": entry.get("bytes"), "updated_at": entry.get("updated_at"),
                }
        m["version"] = MANIFEST_VERSION
        return m

    def _update_manifest(
        self, slug: str, day: str, updates: dict[str, dict[str, Any]], *,
        drop: Iterable[str] = (), day_rows: Optional[int] = None,
        merge: bool = False,
    ) -> None:
        m = self._manifest_for_write(slug)
        files = m["files"]
        now = _now()
        for rel in drop:
            files.pop(rel, None)
        for rel, entry in updates.items():
            base = dict(files.get(rel) or {}) if merge else {}
            base.update(entry)
            base["day"] = day
            base.setdefault("updated_at", now)
            if not merge:
                base["updated_at"] = now
            files[rel] = base
        live = sorted(rel for rel, e in files.items()
                      if e.get("day") == day and not e.get("deleted_at"))
        previous = (m.get("days") or {}).get(day) or {}
        summary: dict[str, Any] = {
            "rows": day_rows if day_rows is not None else previous.get("rows"),
            "files": live,
            "encrypted_files": [rel for rel in live if files[rel].get("encrypted")],
            "updated_at": now,
        }
        plain = next((rel for rel in live if not files[rel].get("encrypted")), None)
        if plain:
            # The 2026-10-07 format's keys: the plaintext day file.
            summary.update(file=plain, sha256=files[plain].get("sha256"),
                           bytes=files[plain].get("bytes"))
        if live:
            m.setdefault("days", {})[day] = summary
        else:
            (m.get("days") or {}).pop(day, None)
        _atomic_write(
            self.tenant_dir(slug) / "manifest.json",
            (json.dumps(m, indent=2, sort_keys=True) + "\n").encode(),
        )

    def _encrypted_entry(self, enc: ArchiveEncryption, *, part: Optional[int], rows: int,
                         sha: str, size: int, **extra: Any) -> dict[str, Any]:
        return {"encrypted": True, "scheme": crypto.SCHEME,
                "recipients": list(enc.recipients), "part": part, "rows": rows,
                "sha256": sha, "bytes": size, **extra}

    # ----- read -----

    def manifest(self, slug: str) -> dict[str, Any]:
        p = self.tenant_dir(slug) / "manifest.json"
        if not p.exists():
            return {}
        try:
            data = json.loads(p.read_text())
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def verify_file(self, path: Path) -> bool:
        """`path` matches its `.sha256` sidecar."""
        side = self.sidecar(path)
        if not path.exists() or not side.exists():
            return False
        fields = side.read_text().split()
        want = fields[0] if fields else ""
        return _sha(path.read_bytes()) == want

    def verify_day(self, slug: str, day: str) -> bool:
        """Every file of the day matches its `.sha256` sidecar (and there is
        at least one)."""
        files = self.day_files(slug, day)
        return bool(files) and all(self.verify_file(f) for f in files)

    def read_day(
        self, slug: str, day: str, *, verify: bool = True,
        identities: Optional[AgeIdentities] = None,
    ) -> list[dict[str, Any]]:
        """Every archived row of one day — plaintext and encrypted files as
        one day, each id once, in file order. With `verify` each file must
        match its checksum BEFORE it is read or decrypted (ArchiveError
        otherwise). Encrypted files need the operator's `identities`."""
        files = self.day_files(slug, day)
        if not files:
            raise ArchiveError(f"no archive for {slug} on {day} ({self.day_file(slug, day)})")
        covered = self.covered_by_plaintext(slug, day)
        files = [f for f in files if f != covered]
        encrypted = [f for f in files if is_encrypted_name(f.name)]
        if encrypted and identities is None:
            raise ArchiveError(
                f"{slug} on {day}: {len(encrypted)} encrypted file(s) — reading them needs "
                "the operator's age identity file (--identity)")
        rows: list[dict[str, Any]] = []
        seen: set[int] = set()
        for f in files:
            if verify and not self.verify_file(f):
                raise ArchiveError(f"{f}: checksum does not match its .sha256 sidecar")
            data = f.read_bytes()
            if is_encrypted_name(f.name):
                try:
                    data = identities.decrypt(data, str(f))   # type: ignore[union-attr]
                except DecryptionError as exc:
                    raise ArchiveError(str(exc)) from None
            for r in _parse(data, str(f)):
                if r["id"] not in seen:
                    seen.add(r["id"])
                    rows.append(r)
        return rows

    # ----- conversion of plaintext day files (scripts/encrypt_archive.py) -----

    def copies_of_plaintext(self, slug: str, day: str) -> list[Path]:
        """Encrypted files `encrypt_archive.py` made from the day's plaintext
        file (whatever it held then — the manifest names it)."""
        rel_plain = self._rel(slug, self.day_file(slug, day))
        files = self.manifest(slug).get("files") or {}
        return [f for f in self.encrypted_files(slug, day)
                if (files.get(self._rel(slug, f)) or {}).get("converted_from") == rel_plain]

    def current_copy(self, slug: str, day: str) -> Optional[Path]:
        """The encrypted copy of the day's plaintext file AS IT IS NOW (its
        manifest entry records the plaintext's sha256), or None — none made
        yet, or the plaintext changed since (a later plaintext append)."""
        plain = self.day_file(slug, day)
        if not plain.exists():
            return None
        copies = self.copies_of_plaintext(slug, day)
        if not copies:
            return None
        psha = _sha(plain.read_bytes())
        files = self.manifest(slug).get("files") or {}
        for f in copies:
            if (files.get(self._rel(slug, f)) or {}).get("plaintext_sha256") == psha:
                return f
        return None

    def covered_by_plaintext(self, slug: str, day: str) -> Optional[Path]:
        """The encrypted copy whose rows the plaintext day file holds as it
        is (reading the plaintext reads them — no identity needed)."""
        return self.current_copy(slug, day)

    def convert_day(self, slug: str, day: str, enc: ArchiveEncryption) -> dict[str, Any]:
        """Encrypt the day's plaintext file to `enc`'s recipients (+ sidecar,
        ledger, manifest entry recording the plaintext's sha256). The
        plaintext is KEPT. Caller holds the run lock.

        Target: `<day>.jsonl.gz.age` — replaced only while everything it
        holds is still in the plaintext (the plaintext grew by appends);
        otherwise (its plaintext was deleted after a verify and a later
        plaintext appeared) a new part, so no encrypted copy is ever
        overwritten by fewer rows.
        {status: encrypted | re-encrypted | already | no-plaintext}."""
        plain = self.day_file(slug, day)
        conv = self.converted_file(slug, day)
        if not plain.exists():
            return {"day": day, "status": "no-plaintext"}
        if not self.verify_file(plain):
            raise ArchiveError(f"{plain}: does not match its .sha256 sidecar — not converted "
                               "(check the file first)")
        data = plain.read_bytes()
        psha = _sha(data)
        files = self.manifest(slug).get("files") or {}
        current = self.current_copy(slug, day)
        if current is not None and self.verify_file(current) and (
                (files.get(self._rel(slug, current)) or {}).get("sha256")
                == _sha(current.read_bytes())):
            return {"day": day, "status": "already", "file": str(current)}
        st = self._day_state(slug, day, plain_data=data)
        ids = set(st.plain_ids)
        if not conv.exists() or st.ledger.get(conv.name, set()) <= ids:
            target, part = conv, None
        else:
            target, part = self.part_file(slug, day, st.next_part), st.next_part
        try:
            ct = enc.encrypt(data)
        except EncryptionConfigError as exc:
            raise ArchiveError(f"{target}: {exc}") from None
        sha = _sha(ct)
        status = "re-encrypted" if target.exists() else "encrypted"
        try:
            self._mark_encrypted()
            # Ledger and manifest name the file before it exists (as for a part).
            ledger = {k: v for k, v in st.ledger.items() if k not in st.stale}
            ledger[target.name] = ids
            self._write_ledger(slug, day, ledger)
            self._update_manifest(
                slug, day,
                {self._rel(slug, target): self._encrypted_entry(
                    enc, part=part, rows=len(ids), sha=sha, size=len(ct),
                    converted_from=self._rel(slug, plain), plaintext_sha256=psha)},
                drop=[self._rel(slug, plain.with_name(s)) for s in st.stale],
                day_rows=len(st.known | ids),
            )
            _atomic_write(target, ct)
            _atomic_write(self.sidecar(target), f"{sha}  {target.name}\n".encode())
        except OSError as exc:
            raise ArchiveError(f"{target}: {type(exc).__name__}: {exc}") from None
        return {"day": day, "status": status, "file": str(target), "rows": len(ids),
                "sha256": sha}

    def verify_encrypted(self, slug: str, day: str, identities: AgeIdentities
                         ) -> list[dict[str, Any]]:
        """Decrypt every encrypted file of the day with the operator's
        identities and check it: sidecar first, then the rows' ids against
        the ledger, and (converted) the decrypted bytes against the
        plaintext's recorded sha256. A file that passes gets a verify record
        in the manifest (what `--delete-plaintext` requires). Caller holds
        the run lock."""
        out: list[dict[str, Any]] = []
        files = self.manifest(slug).get("files") or {}
        ledger = self._read_ledger(slug, day)
        for f in self.encrypted_files(slug, day):
            rel = self._rel(slug, f)
            entry = files.get(rel) or {}
            res: dict[str, Any] = {"day": day, "file": str(f), "ok": False}
            out.append(res)
            if not self.verify_file(f):
                res["error"] = "checksum does not match its .sha256 sidecar"
                continue
            ct = f.read_bytes()
            try:
                pt = identities.decrypt(ct)
                rows = _parse(pt, str(f))
            except (DecryptionError, ArchiveError) as exc:
                res["error"] = str(exc)
                continue
            ids = {r["id"] for r in rows}
            if ids != ledger.get(f.name, set()):
                res["error"] = "its row ids differ from the day's row-id ledger"
                continue
            psha = _sha(pt)
            if entry.get("plaintext_sha256") and entry["plaintext_sha256"] != psha:
                res["error"] = "decrypted, but not the plaintext it was made from (sha256 differs)"
                continue
            record = {
                "at": _now(), "ciphertext_sha256": _sha(ct), "plaintext_sha256": psha,
                "rows": len(ids),
                "identities": [d["fingerprint"] for d in identities.describe()],
            }
            self._update_manifest(slug, day, {rel: {"verified": record}}, merge=True)
            res.update(ok=True, rows=len(ids))
        return out

    def delete_plaintext(self, slug: str, day: str) -> dict[str, Any]:
        """Unlink the day's plaintext file (+ sidecar) — ONLY when the
        encrypted copy of the plaintext AS IT IS NOW has a verify record that
        matches both files, and the ledger holds the copy's ids. NOT a secure
        erase. Caller holds the run lock. {status: deleted | refused |
        no-plaintext, reason}."""
        plain = self.day_file(slug, day)
        if not plain.exists():
            return {"day": day, "status": "no-plaintext"}

        def refused(reason: str) -> dict[str, Any]:
            return {"day": day, "status": "refused", "file": str(plain), "reason": reason}

        copy = self.current_copy(slug, day)
        if copy is None:
            if self.copies_of_plaintext(slug, day):
                return refused("the plaintext changed since its copy was made (run --apply, "
                               "then --verify again)")
            return refused("no encrypted copy (run --apply first)")
        files = self.manifest(slug).get("files") or {}
        entry = files.get(self._rel(slug, copy)) or {}
        record = entry.get("verified") or {}
        if not record:
            return refused("its encrypted copy has never been verified (run --verify "
                           "--identity <path> first)")
        if not self.verify_file(copy):
            return refused("the encrypted copy does not match its .sha256 sidecar")
        csha = _sha(copy.read_bytes())
        if record.get("ciphertext_sha256") != csha or entry.get("sha256") != csha:
            return refused("the encrypted copy changed since it was verified (verify again)")
        psha = _sha(plain.read_bytes())
        if not (record.get("plaintext_sha256") == entry.get("plaintext_sha256") == psha):
            return refused("the plaintext changed since its copy was made (run --apply, "
                           "then --verify again)")
        if copy.name not in self._read_ledger(slug, day):
            return refused("the row-id ledger does not name the encrypted copy")
        conv = copy
        try:
            plain.unlink()
            side = self.sidecar(plain)
            if side.exists():
                side.unlink()
            _fsync_dir(plain.parent)
            self._update_manifest(
                slug, day,
                {self._rel(slug, plain): {
                    "deleted_at": _now(),
                    "deleted_note": (f"unlinked after a verified decrypt of {conv.name} "
                                     "(not a secure erase)"),
                }},
                merge=True,
            )
        except OSError as exc:
            raise ArchiveError(f"{plain}: {type(exc).__name__}: {exc}") from None
        return {"day": day, "status": "deleted", "file": str(plain)}


class DayWriter:
    """Writes one tenant-day: reads what the day holds ONCE, then
    `add()` per chunk and `finish()`.

    Plaintext: each `add` appends a gzip member to the day file (atomic, as
    before). Encrypted: rows are compressed into a buffer and `finish` writes
    them as ONE new part (or a further part each `part_max_bytes`).
    Only valid while the caller is the day's only writer (the run lock)."""

    def __init__(self, archive: ColdArchive, slug: str, day: str) -> None:
        self.archive = archive
        self.slug = slug
        self.day = day
        self.path = archive.day_file(slug, day)
        enc = archive.encryption
        if enc.required and not enc.active:
            raise ArchiveError(archive.unusable_reason() or "archive encryption unusable")
        self.encrypt = enc.active
        try:
            _mkdirs(archive.root, self.path.parent)
            self.state = archive._day_state(slug, day)
            if self.encrypt:
                archive._repair_sidecars(slug, day, self.state)
        except OSError as exc:
            raise ArchiveError(f"{self.path}: {type(exc).__name__}: {exc}") from None
        self.known = self.state.known
        self.added = 0
        self.already = 0
        self._buf = bytearray()
        self._buf_ids: list[int] = []
        self._pending: set[int] = set()
        self._last: tuple[str, str, int] = ("", "", 0)    # file, sha256, bytes
        self._written: list[str] = []

    def add(self, rows: Sequence[dict[str, Any]]) -> int:
        fresh = [dict(r, tenant=self.slug) for r in rows
                 if r["id"] not in self.known and r["id"] not in self._pending]
        self.already += len(rows) - len(fresh)
        if not fresh:
            return 0
        if self.encrypt:
            self._buf += gzip.compress(_jsonl(fresh), mtime=0)
            self._buf_ids.extend(r["id"] for r in fresh)
            self._pending.update(r["id"] for r in fresh)
            if len(self._buf) >= self.archive.part_max_bytes:
                self._flush_part()
        else:
            self._append_plain(fresh)
        self.added += len(fresh)
        return len(fresh)

    def finish(self) -> ArchiveWrite:
        if self.encrypt:
            self._settle_plain_sidecar()
            self._flush_part()
        elif self.added == 0:
            self._settle_plain()
        file, sha, size = self._last
        return ArchiveWrite(
            day=self.day, file=file or str(self.path), rows_added=self.added,
            rows_already=self.already, rows_total=len(self.known), sha256=sha, bytes=size,
            encrypted=self.encrypt, files=tuple(self._written),
        )

    # ----- plaintext -----

    def _write_plain(self, data: bytes, fresh_ids: Sequence[int]) -> None:
        a, slug, path = self.archive, self.slug, self.path
        sha = _sha(data)
        line = f"{sha}  {path.name}\n"
        side = a.sidecar(path)
        # Rewritten whenever it does not describe the file — including after
        # a crash between the data rename and the sidecar's (the file just
        # parsed whole, so it is the one to describe).
        if not side.exists() or side.read_text() != line:
            _atomic_write(side, line.encode())
        plain_rows = len(self.state.plain_ids | set(fresh_ids))
        a._update_manifest(
            slug, self.day,
            {a._rel(slug, path): {"encrypted": False, "scheme": None, "recipients": [],
                                  "part": None, "rows": plain_rows, "sha256": sha,
                                  "bytes": len(data)}},
            day_rows=len(self.known | set(fresh_ids)),
        )
        self._last = (str(path), sha, len(data))

    def _append_plain(self, fresh: list[dict[str, Any]]) -> None:
        ids = [r["id"] for r in fresh]
        try:
            existing = self.path.read_bytes() if self.path.exists() else b""
            data = existing + gzip.compress(_jsonl(fresh), mtime=0)
            _atomic_write(self.path, data)
            self._write_plain(data, ids)
        except OSError as exc:
            raise ArchiveError(f"{self.path}: {type(exc).__name__}: {exc}") from None
        # Only once everything above is durable: the ids are now archived.
        self.state.plain_ids.update(ids)
        self.known.update(ids)
        self._written.append(str(self.path))

    def _settle_plain(self) -> None:
        """Nothing new: the sidecar / manifest still describe the file."""
        if not self.path.exists():
            return
        try:
            data = self.path.read_bytes()
            if data:
                self._write_plain(data, [])
        except OSError as exc:
            raise ArchiveError(f"{self.path}: {type(exc).__name__}: {exc}") from None

    # ----- encrypted -----

    def _settle_plain_sidecar(self) -> None:
        """A plaintext day file next to the encrypted parts (written before
        encryption, or while it was off) whose sidecar does not describe it
        — a crash between its two renames — gets the sidecar (and its
        manifest entry) rewritten: the plaintext path's rule, the file just
        parsed whole in `_day_state` so it is the one to describe. Without
        it restore and `encrypt_archive.py` would refuse the day for good."""
        sha = self.state.plain_sha
        if not sha:
            return
        side = self.archive.sidecar(self.path)
        try:
            if side.exists() and side.read_text() == f"{sha}  {self.path.name}\n":
                return
            data = self.path.read_bytes()
        except (OSError, UnicodeDecodeError) as exc:
            raise ArchiveError(f"{self.path}: {type(exc).__name__}") from None
        if _sha(data) != sha:
            raise ArchiveError(f"{self.path}: changed while its day was being archived")
        last = self._last
        try:
            self._write_plain(data, [])
        except OSError as exc:
            raise ArchiveError(f"{self.path}: {type(exc).__name__}: {exc}") from None
        self._last = last

    def _flush_part(self) -> None:
        if not self._buf_ids:
            return
        a, slug, day, st = self.archive, self.slug, self.day, self.state
        n = st.next_part
        path = a.part_file(slug, day, n)
        ids = set(self._buf_ids)
        try:
            ct = a.encryption.encrypt(bytes(self._buf))
        except EncryptionConfigError as exc:
            raise ArchiveError(f"{path}: {exc}") from None
        sha = _sha(ct)
        try:
            # 1. The ledger names the part's ids BEFORE the part exists: a
            #    crash in between leaves an entry for a missing file (never
            #    counted; dropped here next time), never a part whose rows
            #    the next run cannot tell.
            a._mark_encrypted()
            for name in st.stale:
                st.ledger.pop(name, None)
            st.ledger[path.name] = ids
            a._write_ledger(slug, day, st.ledger)
            # 2. The manifest describes it.
            a._update_manifest(
                slug, day,
                {a._rel(slug, path): a._encrypted_entry(
                    a.encryption, part=n, rows=len(ids), sha=sha, size=len(ct))},
                drop=[a._rel(slug, path.with_name(s)) for s in st.stale],
                day_rows=len(self.known | ids),
            )
            st.stale = set()
            # 3. The part — its rename is the commit point. 4. Its sidecar.
            _atomic_write(path, ct)
            _atomic_write(a.sidecar(path), f"{sha}  {path.name}\n".encode())
        except OSError as exc:
            raise ArchiveError(f"{path}: {type(exc).__name__}: {exc}") from None
        st.present.add(path.name)
        st.next_part = n + 1
        self.known.update(ids)
        self._buf = bytearray()
        self._buf_ids = []
        self._pending = set()
        self._last = (str(path), sha, len(ct))
        self._written.append(str(path))
