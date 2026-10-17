"""Dev-only tooling writes only into a dev data root (apps.octo.dev.dev_root).

The synthetic-traffic generator, scripts/dev_seed.py and
scripts/dev_reset_triage.py used to accept any data root whose path merely
CONTAINED "octo-dev"; scripts/provision_setup_preview.py kept its own copy
of the strict rule. All four now use the one shared check: the resolved
root must sit under ~/.octo-dev or strictly under the fixed /tmp or /var/tmp
bases, and never inside a production data-root location (/var/lib/octo,
~/octo). These tests pin the refusals, including the substring and symlink
cases the old check let through, and that each tool refuses before touching
anything. scripts/start-dev-backend.sh runs the same check on OCTO_DEV_ROOT
(and its secrets/ and data/) before it creates a directory (the last section).

HOME is pointed at a pytest tmp dir in every test, so ~/.octo-dev and ~/octo
are throwaway directories; paths outside /tmp are only ever resolved, never
created.
"""
from __future__ import annotations

import functools
import importlib.util
import os
import random
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from apps.octo.dev import dev_root
from apps.octo.dev import synthetic_traffic

REPO_ROOT = Path(__file__).resolve().parents[3]

# Never created: these only have to resolve. Both carry the word "octo-dev",
# which is all the old substring check asked for.
LOOKALIKE_ROOTS = ("/srv/octo-dev/data", "/opt/acme/.octo-dev/data")

# An existing directory outside ~/.octo-dev, /tmp and /var/tmp on any POSIX
# host (only resolved, never written).
NON_DEV_DIR = next(Path(d) for d in ("/usr", "/etc", "/") if Path(d).is_dir())


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(
        f"_{name}_under_test", REPO_ROOT / "scripts" / f"{name}.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    assert Path.home() == h
    return h


def _requires_tmp_under_system_tmp(path: Path) -> None:
    resolved = path.resolve()
    if not any(Path(d).resolve() in resolved.parents for d in dev_root.SYSTEM_TMP_DIRS):
        pytest.skip("pytest's tmp dir is not under /tmp or /var/tmp here")


# ---------------------------------------------------------------------------
# The check itself
# ---------------------------------------------------------------------------


def test_dev_home_and_its_subdirs_are_dev_roots(home):
    assert dev_root.dev_root_problem(home / ".octo-dev") is None
    assert dev_root.dev_root_problem(home / ".octo-dev" / "data") is None
    assert dev_root.dev_root_problem("~/.octo-dev/data") is None


def test_the_dev_home_rule_holds_outside_tmp_too(monkeypatch):
    # A home that is not under /tmp (only resolved, never created), so the
    # acceptance below can only come from the ~/.octo-dev rule.
    monkeypatch.setenv("HOME", "/nonexistent-octo-test-home/alice")
    assert dev_root.dev_root_problem("~/.octo-dev/data") is None
    assert dev_root.dev_root_problem("~/.octo-devx/data") is not None
    assert dev_root.dev_root_problem("~/octo/data") is not None


def test_a_directory_strictly_under_system_tmp_is_a_dev_root(home, tmp_path):
    _requires_tmp_under_system_tmp(tmp_path)
    assert dev_root.dev_root_problem(tmp_path / "data") is None


@pytest.mark.parametrize("tmp", dev_root.SYSTEM_TMP_DIRS)
def test_the_system_tmp_dir_itself_is_not(home, tmp):
    assert "not under" in dev_root.dev_root_problem(tmp)


@pytest.mark.parametrize("root", LOOKALIKE_ROOTS)
def test_a_path_that_merely_contains_octo_dev_is_refused(home, root):
    problem = dev_root.dev_root_problem(root)
    assert problem is not None and "not under" in problem
    assert not dev_root.is_dev_data_root(root)


def test_production_locations_are_refused(home):
    assert not dev_root.is_dev_data_root("/var/lib/octo/data")
    (home / "octo" / "data").mkdir(parents=True)
    # ~/octo/data sits under /tmp here (HOME is a tmp dir), so this is the
    # production-location rule firing, not the allow-list.
    problem = dev_root.dev_root_problem(home / "octo" / "data")
    assert problem is not None and "production data-root location" in problem


def test_dotdot_out_of_the_dev_home_is_refused(home):
    (home / "octo" / "data").mkdir(parents=True)
    (home / ".octo-dev").mkdir()
    problem = dev_root.dev_root_problem(f"{home}/.octo-dev/../octo/data")
    assert problem is not None and "production data-root location" in problem


def test_dev_home_symlinked_to_a_production_root_is_refused(home):
    (home / "octo" / "data").mkdir(parents=True)
    (home / ".octo-dev").symlink_to(home / "octo")
    problem = dev_root.dev_root_problem(home / ".octo-dev" / "data")
    assert problem is not None and "production data-root location" in problem


def test_a_tmp_symlink_into_a_non_dev_directory_is_refused(home, tmp_path):
    _requires_tmp_under_system_tmp(tmp_path)
    link = tmp_path / "octo-dev"
    # An existing system directory, never the repo: a clone under /tmp is
    # itself inside the allowed area, wherever the tests run from.
    link.symlink_to(NON_DEV_DIR)
    problem = dev_root.dev_root_problem(link)
    assert problem is not None and "not under" in problem


def test_a_symlink_loop_is_refused_not_raised(home):
    loop = home / ".octo-dev"
    loop.symlink_to(loop)
    assert dev_root.dev_root_problem(loop / "data") is not None


def test_the_temp_bases_are_fixed_not_tmpdir(home, monkeypatch):
    # $TMPDIR (what tempfile.gettempdir() follows) must not widen the rule:
    # TMPDIR=/var/lib/octo would otherwise let the production root pass.
    for tmpdir in ("/srv/scratch", "/var/lib/octo"):
        monkeypatch.setenv("TMPDIR", tmpdir)
        monkeypatch.setattr(tempfile, "tempdir", None)
        assert dev_root.dev_root_problem(f"{tmpdir}/data") is not None


# ---------------------------------------------------------------------------
# synthetic_traffic: both gates hold (opt-in AND strict dev root)
# ---------------------------------------------------------------------------


def test_synthetic_needs_the_opt_in_even_on_a_dev_root(home, monkeypatch):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(home / ".octo-dev" / "data"))
    monkeypatch.delenv("OCTO_DEV_SYNTHETIC", raising=False)
    assert synthetic_traffic.synthetic_allowed() is False
    monkeypatch.setenv("OCTO_DEV_SYNTHETIC", "0")
    assert synthetic_traffic.synthetic_allowed() is False


def test_synthetic_allowed_on_a_dev_root_with_the_opt_in(home, monkeypatch):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(home / ".octo-dev" / "data"))
    monkeypatch.setenv("OCTO_DEV_SYNTHETIC", "1")
    assert synthetic_traffic.synthetic_allowed() is True


@pytest.mark.parametrize("root", LOOKALIKE_ROOTS)
def test_synthetic_refuses_a_lookalike_root_despite_the_opt_in(home, monkeypatch, root):
    monkeypatch.setenv("OCTO_DATA_ROOT", root)
    monkeypatch.setenv("OCTO_DEV_SYNTHETIC", "1")
    assert synthetic_traffic.synthetic_allowed() is False
    with pytest.raises(RuntimeError, match="non-dev data root"):
        synthetic_traffic.emit_batch(random.Random(0))


def test_synthetic_refuses_the_default_production_root(home, monkeypatch):
    # OCTO_DATA_ROOT unset: data_root() is ~/octo/data, a production layout.
    monkeypatch.delenv("OCTO_DATA_ROOT", raising=False)
    monkeypatch.setenv("OCTO_DEV_SYNTHETIC", "1")
    assert synthetic_traffic.synthetic_allowed() is False
    with pytest.raises(RuntimeError, match="non-dev data root"):
        synthetic_traffic.emit_batch(random.Random(0))


def test_synthetic_refuses_a_dev_home_symlinked_to_production(home, monkeypatch):
    (home / "octo" / "data").mkdir(parents=True)
    (home / ".octo-dev").symlink_to(home / "octo")
    monkeypatch.setenv("OCTO_DATA_ROOT", str(home / ".octo-dev" / "data"))
    monkeypatch.setenv("OCTO_DEV_SYNTHETIC", "1")
    assert synthetic_traffic.synthetic_allowed() is False
    with pytest.raises(RuntimeError, match="non-dev data root"):
        synthetic_traffic.emit_batch(random.Random(0))


def test_emit_batch_on_an_empty_dev_root_emits_nothing(home, monkeypatch):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(home / ".octo-dev" / "data"))
    assert synthetic_traffic.emit_batch(random.Random(0)) == 0


# ---------------------------------------------------------------------------
# scripts/dev_seed.py: refuses (exit 3) before touching the data root
# ---------------------------------------------------------------------------


def _run_dev_seed(monkeypatch, *args: str) -> int:
    monkeypatch.setattr(sys, "argv", ["dev_seed.py", *args])
    monkeypatch.delenv("OCTO_DATA_ROOT", raising=False)
    return _load_script("dev_seed").main()


@pytest.mark.parametrize("root", LOOKALIKE_ROOTS)
def test_dev_seed_refuses_a_lookalike_root(home, monkeypatch, capsys, root):
    assert _run_dev_seed(monkeypatch, "--data-root", root) == 3
    assert "REFUSING" in capsys.readouterr().err
    assert not os.path.lexists(root)


def test_dev_seed_refuses_a_production_root_with_a_registry(home, monkeypatch, capsys):
    prod = home / "octo" / "data"
    prod.mkdir(parents=True)
    (prod / "registry.db").write_bytes(b"")
    before = sorted(p.name for p in prod.iterdir())
    assert _run_dev_seed(monkeypatch, "--data-root", str(prod)) == 3
    assert "production data-root location" in capsys.readouterr().err
    assert sorted(p.name for p in prod.iterdir()) == before


def test_dev_seed_refuses_a_dev_home_symlinked_to_production(home, monkeypatch, capsys):
    (home / "octo" / "data").mkdir(parents=True)
    (home / "octo" / "data" / "registry.db").write_bytes(b"")
    (home / ".octo-dev").symlink_to(home / "octo")
    assert _run_dev_seed(monkeypatch, "--data-root", "~/.octo-dev/data") == 3
    assert "REFUSING" in capsys.readouterr().err


def test_dev_seed_passes_the_gate_on_a_dev_root(home, monkeypatch, capsys):
    # Past the gate, a dev root with no registry yet is the "start the dev
    # backend first" error (2), not the refusal (3).
    (home / ".octo-dev" / "data").mkdir(parents=True)
    assert _run_dev_seed(monkeypatch, "--data-root", "~/.octo-dev/data") == 2
    err = capsys.readouterr().err
    assert "registry.db not found" in err and "REFUSING" not in err


# ---------------------------------------------------------------------------
# scripts/provision_setup_preview.py: the shared check, same behaviour
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=None)
def _provision():
    # Loaded once: the script puts the repo root on sys.path at import.
    return _load_script("provision_setup_preview")


def _expect_dev_root(monkeypatch, root) -> Path:
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    return _provision()._expect_dev_root()


def test_provision_has_no_private_copy_of_the_rule():
    module = _provision()
    assert module.dev_root_problem is dev_root.dev_root_problem
    for private in ("_SYSTEM_TMP_DIRS", "_production_roots", "_is_under"):
        assert not hasattr(module, private)


def test_provision_accepts_dev_roots_and_returns_the_resolved_root(home, monkeypatch, tmp_path):
    dev = home / ".octo-dev" / "data"
    assert _expect_dev_root(monkeypatch, dev) == dev.resolve()
    assert _expect_dev_root(monkeypatch, home / ".octo-dev") == (home / ".octo-dev").resolve()
    _requires_tmp_under_system_tmp(tmp_path)
    assert _expect_dev_root(monkeypatch, tmp_path / "data") == (tmp_path / "data").resolve()


def test_provision_refuses_an_unset_data_root(home, monkeypatch, capsys):
    monkeypatch.delenv("OCTO_DATA_ROOT", raising=False)
    with pytest.raises(SystemExit) as exc:
        _provision()._expect_dev_root()
    assert exc.value.code == 2
    assert "OCTO_DATA_ROOT is not set" in capsys.readouterr().err


def test_provision_refuses_what_the_shared_check_refuses(home, monkeypatch, capsys):
    (home / "octo" / "data").mkdir(parents=True)
    # ~/.octo-dev itself symlinked into the production ~/octo.
    (home / ".octo-dev").symlink_to(home / "octo")
    loop = home / "loop"
    loop.symlink_to(loop)
    refused = [
        *((root, "not under") for root in LOOKALIKE_ROOTS),
        *((tmp, "not under") for tmp in dev_root.SYSTEM_TMP_DIRS),
        ("/var/lib/octo/data", ""),
        (str(home / "octo" / "data"), "production data-root location"),
        (str(home / ".octo-dev" / "data"), "production data-root location"),
        (f"{home}/.octo-dev/../octo/data", "production data-root location"),
        (str(loop / "data"), "cannot be resolved"),
    ]
    for root, reason in refused:
        assert not dev_root.is_dev_data_root(root), root
        with pytest.raises(SystemExit) as exc:
            _expect_dev_root(monkeypatch, root)
        assert exc.value.code == 2, root
        err = capsys.readouterr().err
        assert err.startswith("refuse: ") and reason in err, (root, err)


def test_provision_ignores_tmpdir(home, monkeypatch):
    monkeypatch.setenv("TMPDIR", "/srv/scratch")
    monkeypatch.setattr(tempfile, "tempdir", None)
    with pytest.raises(SystemExit):
        _expect_dev_root(monkeypatch, "/srv/scratch/data")


def _run_provision(monkeypatch, root, *args: str) -> None:
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    monkeypatch.setattr(sys, "argv", ["provision_setup_preview.py", *args])
    _provision().main()


@pytest.mark.parametrize("args", [(), ("--delete",)])
def test_provision_main_refuses_before_touching_a_production_root(
    home, monkeypatch, capsys, args,
):
    prod = home / "octo" / "data"
    prod.mkdir(parents=True)
    (prod / "registry.db").write_bytes(b"")
    creds = prod / _provision().PREVIEW_CREDENTIALS_FILENAME
    creds.write_text("synthetic placeholder\n")
    before = {p.name: p.read_bytes() for p in prod.iterdir()}
    with pytest.raises(SystemExit) as exc:
        _run_provision(monkeypatch, prod, *args)
    assert exc.value.code == 2
    assert "production data-root location" in capsys.readouterr().err
    assert {p.name: p.read_bytes() for p in prod.iterdir()} == before


@pytest.mark.parametrize("root", LOOKALIKE_ROOTS)
def test_provision_main_refuses_a_lookalike_root(home, monkeypatch, capsys, root):
    with pytest.raises(SystemExit) as exc:
        _run_provision(monkeypatch, root)
    assert exc.value.code == 2
    assert "not under" in capsys.readouterr().err
    assert not os.path.lexists(root)


# ---------------------------------------------------------------------------
# scripts/dev_reset_triage.py: refuses (exit 2) before resetting anything
# ---------------------------------------------------------------------------


def _tenant_db(clients: Path, slug: str) -> Path:
    """A tenant events.db holding one agent note."""
    tenant = clients / slug
    tenant.mkdir(parents=True)
    edb = tenant / "events.db"
    conn = sqlite3.connect(edb)
    conn.executescript(
        "CREATE TABLE agent_notes (id INTEGER PRIMARY KEY, note_text TEXT);"
        "INSERT INTO agent_notes (note_text) VALUES ('synthetic');"
    )
    conn.commit()
    conn.close()
    return edb


def _notes(edb: Path) -> int:
    conn = sqlite3.connect(edb)
    try:
        return conn.execute("SELECT COUNT(*) FROM agent_notes").fetchone()[0]
    finally:
        conn.close()


def _run_reset(*args: str) -> int:
    return _load_script("dev_reset_triage").main(list(args))


@pytest.fixture
def prod_tenant(home) -> Path:
    """A production-layout tenant (~/octo/data/clients/dev-prod) with a note."""
    return _tenant_db(home / "octo" / "data" / "clients", "dev-prod")


def test_reset_triage_uses_the_shared_check():
    assert _load_script("dev_reset_triage").dev_root_problem is dev_root.dev_root_problem


@pytest.mark.parametrize("root", LOOKALIKE_ROOTS)
def test_reset_triage_refuses_a_lookalike_root(home, monkeypatch, capsys, root):
    assert _run_reset("--data-root", root) == 2
    err = capsys.readouterr().err
    assert "refusing to reset" in err and "not under" in err
    assert not os.path.lexists(root)


def test_reset_triage_refuses_a_production_root(home, monkeypatch, capsys, prod_tenant):
    prod = home / "octo" / "data"
    assert _run_reset("--data-root", str(prod)) == 2
    assert "production data-root location" in capsys.readouterr().err
    # Also when the root comes from OCTO_DATA_ROOT (the default).
    monkeypatch.setenv("OCTO_DATA_ROOT", str(prod))
    assert _run_reset() == 2
    assert "production data-root location" in capsys.readouterr().err
    assert _notes(prod_tenant) == 1


def test_reset_triage_refuses_a_dev_home_symlinked_to_production(
    home, monkeypatch, capsys, prod_tenant,
):
    (home / ".octo-dev").symlink_to(home / "octo")
    assert _run_reset("--data-root", "~/.octo-dev/data") == 2
    assert "production data-root location" in capsys.readouterr().err
    assert _notes(prod_tenant) == 1


@pytest.mark.parametrize("link", ["clients", "tenant", "events.db"])
def test_reset_triage_refuses_a_symlink_out_of_the_dev_root(
    home, monkeypatch, capsys, prod_tenant, link,
):
    dev = home / ".octo-dev" / "data"
    if link == "clients":
        dev.mkdir(parents=True)
        (dev / "clients").symlink_to(prod_tenant.parent.parent)
        dev_db = None
    else:
        # A genuine dev tenant sorted BEFORE the bad one: it must not be
        # reset either, because the refusal comes before any reset.
        dev_db = _tenant_db(dev / "clients", "dev-aaa")
        if link == "tenant":
            (dev / "clients" / "dev-zzz").symlink_to(prod_tenant.parent)
        else:
            (dev / "clients" / "dev-zzz").mkdir()
            (dev / "clients" / "dev-zzz" / "events.db").symlink_to(prod_tenant)
    assert _run_reset("--data-root", str(dev)) == 2
    err = capsys.readouterr().err
    assert "fails the dev-root check" in err and "production data-root location" in err
    assert _notes(prod_tenant) == 1
    if dev_db is not None:
        assert _notes(dev_db) == 1


@pytest.mark.parametrize("slug", ["..", ".", "", "../../../octo/data/clients/dev-prod",
                                  "dev-prod/", "a/b"])
def test_reset_triage_refuses_a_slug_that_is_not_a_plain_name(
    home, monkeypatch, capsys, prod_tenant, slug,
):
    dev = home / ".octo-dev" / "data"
    dev.mkdir(parents=True)
    assert _run_reset("--data-root", str(dev), "--slug", slug) == 2
    assert "--slug must be a single tenant directory name" in capsys.readouterr().err
    assert _notes(prod_tenant) == 1


def test_reset_triage_resets_dev_tenants_on_the_default_dev_root(home, monkeypatch, capsys):
    # OCTO_DATA_ROOT unset: the default is ~/.octo-dev/data, a dev root.
    monkeypatch.delenv("OCTO_DATA_ROOT", raising=False)
    clients = home / ".octo-dev" / "data" / "clients"
    first, second = _tenant_db(clients, "dev-aaa"), _tenant_db(clients, "dev-bbb")
    assert _run_reset() == 0
    assert _notes(first) == 0 and _notes(second) == 0
    assert "refusing" not in capsys.readouterr().err


def test_reset_triage_resets_one_tenant_by_slug(home, monkeypatch):
    dev = home / ".octo-dev" / "data"
    keep, reset = _tenant_db(dev / "clients", "dev-aaa"), _tenant_db(dev / "clients", "dev-bbb")
    assert _run_reset("--data-root", "~/.octo-dev/data", "--slug", "dev-bbb") == 0
    assert _notes(keep) == 1 and _notes(reset) == 0


# ---------------------------------------------------------------------------
# scripts/start-dev-backend.sh: refuses (exit 3) before creating anything
# ---------------------------------------------------------------------------

START_DEV_BACKEND = REPO_ROOT / "scripts" / "start-dev-backend.sh"
needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def _start_dev_backend(script: Path, home: Path, dev_root_env, cwd: Path, first_on_path=()):
    """`start-dev-backend.sh provision` with HOME at the throwaway home."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("OCTO_")}
    env.update(HOME=str(home), PYTHONDONTWRITEBYTECODE="1",
               PATH=os.pathsep.join([*map(str, first_on_path), str(Path(sys.executable).parent),
                                     env.get("PATH", "")]))
    if dev_root_env is not None:
        env["OCTO_DEV_ROOT"] = str(dev_root_env)
    return subprocess.run(["bash", str(script), "provision"], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=120)


def _tree(path: Path) -> list[str]:
    return sorted(str(p.relative_to(path)) for p in path.rglob("*"))


@needs_bash
@pytest.mark.parametrize("case", ["production", "dev-home-to-production", "data-to-production",
                                  "system-dir", "relative-outside", *LOOKALIKE_ROOTS])
def test_start_dev_backend_refuses_a_non_dev_root_before_creating_anything(home, tmp_path, case):
    # A mkdir that only records and fails: should the gate ever let one of
    # these through, the script stops at its first mkdir instead of creating
    # /usr/secrets or /srv/octo-dev/... (as root, it could).
    trip = tmp_path / "tripwire"
    trip.mkdir()
    (trip / "mkdir").write_text(f'#!/bin/sh\necho "mkdir $*" >> "{tmp_path}/tripped"\nexit 97\n')
    (trip / "mkdir").chmod(0o755)
    (home / "octo" / "data").mkdir(parents=True)
    cwd, reason = home, "production data-root location"
    if case == "production":
        root = home / "octo"
    elif case == "dev-home-to-production":
        (home / ".octo-dev").symlink_to(home / "octo")
        root = None  # the default, ~/.octo-dev
    elif case == "data-to-production":
        (home / ".octo-dev").mkdir()
        (home / ".octo-dev" / "data").symlink_to(home / "octo" / "data")
        root = home / ".octo-dev"
    elif case == "system-dir":
        root, reason = NON_DEV_DIR, "not under"
    elif case == "relative-outside":
        # Relative to where it is run from, outside the dev locations.
        root, cwd, reason = "octo-dev", NON_DEV_DIR, "not under"
    else:
        root, reason = case, "not under"
    before = _tree(home)
    proc = _start_dev_backend(START_DEV_BACKEND, home, root, cwd, first_on_path=[trip])
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "REFUSING" in proc.stderr and reason in proc.stderr
    assert not (tmp_path / "tripped").exists()
    assert _tree(home) == before
    if isinstance(root, str):
        assert not os.path.lexists(Path(cwd) / root)


@pytest.fixture
def venvless_repo(tmp_path) -> Path:
    """The script and the shared check alone, no packages/.venv: past the
    gate the script stops at the missing venv (exit 1), provisioning nothing."""
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    shutil.copy2(START_DEV_BACKEND, repo / "scripts" / START_DEV_BACKEND.name)
    pkg = repo / "apps" / "octo" / "dev"
    pkg.mkdir(parents=True)
    for init in (repo / "apps", repo / "apps" / "octo", pkg):
        (init / "__init__.py").write_text("")
    shutil.copy2(Path(dev_root.__file__), pkg / "dev_root.py")
    return repo


@needs_bash
@pytest.mark.parametrize("root", [None, "~/.octo-dev", "relative"])
def test_start_dev_backend_passes_the_gate_on_a_dev_root(home, tmp_path, venvless_repo, root):
    cwd, expected = home, home / ".octo-dev"
    if root == "relative":
        _requires_tmp_under_system_tmp(tmp_path)
        cwd = tmp_path / "work"
        cwd.mkdir()
        expected = cwd / root
    proc = _start_dev_backend(venvless_repo / "scripts" / START_DEV_BACKEND.name, home, root, cwd)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "REFUSING" not in proc.stderr and "python venv not found" in proc.stderr
    # The root the check resolved is the one used: no literal "~" directory.
    assert (expected / "secrets").is_dir() and (expected / "data").is_dir()
    assert not (cwd / "~").exists()
