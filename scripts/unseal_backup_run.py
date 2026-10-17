#!/usr/bin/env python3
"""unseal_backup_run.py — open ONE sealed backup run safely (operator workstation only).

Counterpart of `seal_backup_runs.py` for drills and restores (the backup vault
design 2026-10-12, section 7). The private key never goes to the bundle host
or the backup vault, so this runs on the operator workstation, with the
operator's identity file and the output on RAM (`/dev/shm`). A sealed run
may be a well-formed FORGERY made by a compromised bundle host (design
section 11), so it is never given to `tar -x`:

  1. the ciphertext is checked against its `<stamp>.tar.age.sha256` sidecar
     (next to it, or --sha256) BEFORE it is decrypted (--no-verify skips it);
  2. it is decrypted (age, the identity file) as a stream into a temporary
     tar INSIDE --out, never anywhere else;
  3. every member is listed and the WHOLE run is refused unless each one is
     exactly one of:
         <stamp>                 the run directory (once)
         <stamp>/<name>          a regular file, flat
         report/<name>           a regular file, flat
         bundle/<name>           a regular file, flat
     with <stamp> = the stamp in the file's name: no symlink, hard link,
     device, sparse file, nested directory, absolute or `..` path, other top
     directory or duplicate name;
  4. only then it is extracted, with tarfile's 'data' filter as well, and the
     temporary tar is deleted (also on any failure).

Then: `restore_databases.py --backup-run <out>/<stamp> --data-root <EMPTY dir>`.
When done, delete --out and the identity file's RAM copy.

Usage (the operator workstation):
    python scripts/unseal_backup_run.py --sealed /dev/shm/drill/20261012T060001Z.tar.age \\
        --identity /dev/shm/drill/identity.txt --out /dev/shm/drill/unsealed

RAM needed in --out: about twice the run (the temporary tar + the files).
Exit codes: 0 unsealed · 1 refused (checksum, decryption, a member outside the
layout, extraction) · 2 setup error (arguments, files, identity, space).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import tarfile
from pathlib import Path
from typing import Any, Optional

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
if _REPO_ROOT.is_dir() and str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_HERE) not in sys.path:
    sys.path.append(str(_HERE))      # appended: never shadows anything else

from seal_backup_runs import SHA_LINE, SUFFIX_AGE, parse_stamp  # noqa: E402 — one layout
from apps.octo.retention import archive_crypto  # noqa: E402

EXIT_OK, EXIT_REFUSED, EXIT_SETUP = 0, 1, 2
OTHER_TOPS = ("report", "bundle")
CHUNK = 1024 * 1024
SPACE_MARGIN = 64 * 1024 * 1024
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


class Refused(Exception):
    """The sealed run is refused; the message is the one-line reason."""


class Setup(Exception):
    """The invocation is refused before anything is decrypted."""


def _show(name: str) -> str:
    text = repr(name)
    return text if len(text) <= 80 else text[:77] + "..."


class _FdWriter:
    """write(bytes) straight to an fd (the temporary tar); keeps the first
    exception (the decryptor wraps it otherwise)."""

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self.error: Optional[BaseException] = None

    def write(self, data: Any) -> int:
        try:
            view = memoryview(data)
            n = len(view)
            while len(view):
                view = view[os.write(self._fd, view):]
            return n
        except BaseException as exc:
            if self.error is None:
                self.error = exc
            raise

    def flush(self) -> None:
        return None


def check_members(tar: tarfile.TarFile, stamp: str) -> list[tarfile.TarInfo]:
    """Every member, when ALL of them fit the sealed layout; else Refused."""
    seen: set[str] = set()
    members: list[tarfile.TarInfo] = []
    run_dir = False
    run_files = 0
    for m in tar.getmembers():
        name = m.name
        if name in seen:
            raise Refused(f"member {_show(name)} appears twice")
        seen.add(name)
        if name == stamp:
            if not m.isdir() or run_dir:
                raise Refused(f"member {_show(name)} is not the run directory")
            run_dir = True
            members.append(m)
            continue
        top, sep, leaf = name.partition("/")
        if (not sep or top not in (stamp, *OTHER_TOPS) or not leaf or "/" in leaf
                or leaf in (".", "..") or "\0" in leaf):
            raise Refused(f"member {_show(name)} is outside the sealed layout")
        if m.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or m.sparse is not None:
            raise Refused(f"member {_show(name)} is not a regular file")
        members.append(m)
        if top == stamp:
            run_files += 1
    if not run_dir:
        raise Refused(f"no run directory {stamp} in it")
    if not run_files:
        raise Refused("the run holds no files")
    return members


def _expected_digest(sidecar: Path, sealed_name: str) -> str:
    try:
        fd = os.open(sidecar, _READ_FLAGS)
    except FileNotFoundError:
        raise Setup(f"no checksum file {sidecar} (give --sha256, or --no-verify)") from None
    except OSError as exc:
        raise Setup(f"the checksum file {sidecar} cannot be read ({exc.strerror})") from None
    try:
        raw = os.read(fd, 4096)
    finally:
        os.close(fd)
    try:
        m = SHA_LINE.fullmatch(raw.decode("ascii"))
    except UnicodeDecodeError:
        m = None
    if m is None or m.group(1) != sealed_name:
        raise Setup(f"the checksum file {sidecar} is not the sha256 line of {sealed_name}")
    return raw[:64].decode("ascii")


def _sha256_of(path: Path) -> str:
    sha = hashlib.sha256()
    fd = os.open(path, _READ_FLAGS)
    try:
        while chunk := os.read(fd, CHUNK):
            sha.update(chunk)
    finally:
        os.close(fd)
    return sha.hexdigest()


def _prepare_out(out: Path) -> None:
    if out.is_symlink():
        raise Setup(f"--out {out} is a symlink: give a new directory")
    if out.exists():
        if not out.is_dir() or any(out.iterdir()):
            raise Setup(f"--out {out} must be a new or EMPTY directory")
        return
    try:
        out.mkdir(mode=0o700, parents=False)
    except OSError as exc:
        raise Setup(f"--out {out} cannot be created ({exc.strerror})") from None


def unseal(sealed: Path, identities: archive_crypto.AgeIdentities, out: Path,
           stamp: str) -> list[tarfile.TarInfo]:
    """Decrypt `sealed` into a temporary tar inside `out`, check its members,
    extract them. Refused on any problem; the temporary tar never stays."""
    tmp = out / f".{stamp}.tar.partial"
    try:
        src = os.open(sealed, _READ_FLAGS)
        try:
            dst = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                          | os.O_CLOEXEC, 0o600)
            writer = _FdWriter(dst)
            try:
                with os.fdopen(os.dup(src), "rb", buffering=CHUNK) as reader:
                    identities.decrypt_stream(reader, writer, where=sealed.name)
            except archive_crypto.DecryptionError as exc:
                cause = writer.error
                if cause is not None and not isinstance(cause, Exception):
                    raise cause from None                 # Ctrl-C: stop, the finally cleans up
                if isinstance(cause, OSError):
                    raise Refused(f"writing the decrypted tar into --out failed "
                                  f"({cause.strerror or type(cause).__name__})") from None
                raise Refused(str(exc)) from None
            finally:
                os.close(dst)
        finally:
            os.close(src)
        try:
            with tarfile.open(tmp, mode="r:") as tar:
                members = check_members(tar, stamp)
                tar.extractall(out, members=members, filter="data")
        except tarfile.TarError as exc:
            raise Refused(f"not a readable tar, or a member was refused on extraction "
                          f"({type(exc).__name__})") from None
        return members
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="unseal_backup_run.py",
                                 description=__doc__.splitlines()[0])
    ap.add_argument("--sealed", type=Path, required=True,
                    help="one <stamp>.tar.age written by seal_backup_runs.py")
    ap.add_argument("--identity", type=Path, required=True,
                    help="the operator's age identity file (0600; on RAM, e.g. /dev/shm)")
    ap.add_argument("--out", type=Path, required=True,
                    help="a NEW or empty directory on RAM (/dev/shm) for the run")
    ap.add_argument("--sha256", type=Path, default=None,
                    help="its checksum file (default <sealed>.sha256)")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip the checksum check (salvage only)")
    args = ap.parse_args(argv)

    sealed: Path = args.sealed
    try:
        name = sealed.name
        stamp = name[:-len(SUFFIX_AGE)] if name.endswith(SUFFIX_AGE) else ""
        if not stamp or parse_stamp(stamp) is None:
            raise Setup(f"{sealed} is not named <stamp>{SUFFIX_AGE} (e.g. 20261012T060001Z"
                        f"{SUFFIX_AGE})")
        try:
            st = os.lstat(sealed)
        except FileNotFoundError:
            raise Setup(f"{sealed} does not exist") from None
        if not stat.S_ISREG(st.st_mode):
            raise Setup(f"{sealed} is not a regular file")
        expected = None
        if not args.no_verify:
            expected = _expected_digest(args.sha256 or Path(f"{sealed}.sha256"), name)
        try:
            identities = archive_crypto.load_identities(args.identity)
        except archive_crypto.EncryptionConfigError as exc:
            raise Setup(str(exc)) from None
        _prepare_out(args.out)
        vfs = os.statvfs(args.out)
        free = vfs.f_bavail * vfs.f_frsize
        need = 2 * st.st_size + SPACE_MARGIN
        if free < need:
            raise Setup(f"--out has {free} bytes free; unsealing this run needs about {need}")
    except Setup as exc:
        print(f"unseal: setup error: {exc}", file=sys.stderr)
        return EXIT_SETUP

    print("unseal: identities: " + ", ".join(
        archive_crypto.recipient_short(k) for k in identities.public_keys))
    try:
        if expected is not None:
            got = _sha256_of(sealed)
            if got != expected:
                raise Refused(f"checksum mismatch: {got[:16]}… is not the sidecar's "
                              f"{expected[:16]}…; not decrypted")
            print(f"unseal: {name}: checksum OK ({got[:16]}…)")
        else:
            print(f"unseal: {name}: checksum NOT checked (--no-verify)")
        members = unseal(sealed, identities, args.out, stamp)
    except Refused as exc:
        print(f"unseal: refused: {name}: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except OSError as exc:
        print(f"unseal: refused: {name}: {exc.strerror or type(exc).__name__}", file=sys.stderr)
        return EXIT_REFUSED

    run_files = sum(1 for m in members if m.name.startswith(f"{stamp}/"))
    report = [m.name for m in members if m.name.startswith("report/")]
    bundle = sum(1 for m in members if m.name.startswith("bundle/"))
    print(f"unseal: {name}: {run_files} run file(s) in {args.out / stamp}, "
          f"report: {'yes' if report else 'no'}, bundle files: {bundle}")
    print(f"unseal: next: restore_databases.py --backup-run {args.out / stamp} "
          "--data-root <an EMPTY directory>")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
