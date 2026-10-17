#!/usr/bin/env bash
# Local dev backend for Athena Console v3 + OCTO admin API.
#
# Boots the auth-side FastAPI app (apps.octo.api) with a sandbox data root
# under ~/.octo-dev/ — completely isolated from any live deployment.
# OCTO_DEV_ROOT moves it, but only to another dev root (the shared check in
# apps/octo/dev/dev_root.py): anything else is refused (exit 3) before a
# directory or a secret is created.
#
# First run provisions:
#   - pepper.env, mfa-key.env, adapter-credentials-key.env (mode 600)
#   - registry.db with migrations 1..7 applied
#   - a dev super_admin operator (username: dev-admin). No static password:
#     it is $OCTO_DEV_PASSWORD (>= 12 chars) if set, otherwise a random one
#     (secrets.token_urlsafe(16)) generated for this provisioning only.
#   - a TOTP secret (otpauth URI)
#
# The password and the TOTP enrollment are shown ONCE, never logged:
#   - stdout is an interactive terminal: printed there.
#   - stdout is captured (piped by scripts/dev.sh, nohup'd into a log by
#     scripts/dev_up.sh, run by an agent): written to
#     ${OCTO_DEV_ROOT:-~/.octo-dev}/secrets/dev-admin.initial-credentials
#     (mode 600) and only that path is printed. Read it, enroll the TOTP,
#     then delete the file.
# To choose the password yourself without it landing in shell history:
#   read -rs OCTO_DEV_PASSWORD && export OCTO_DEV_PASSWORD
# (this script drops it before starting the server; `unset` it in your
# own shell once the operator exists, later runs ignore it anyway).
#
# Subsequent runs reuse the persisted state and skip provisioning.
#
# Usage:
#   ./scripts/start-dev-backend.sh           # boot uvicorn on :8001
#   ./scripts/start-dev-backend.sh provision # provision only, don't start

set -euo pipefail

# Everything provisioned below (the dev root and secrets dirs, pepper and
# MFA keys, registry.db, the first-run credentials file) is private to
# this user from the moment it exists: no window in which a fresh secret
# is group/world-readable before a chmod. Restored before uvicorn starts.
ORIG_UMASK="$(umask)"
umask 077

# Resolve repo root from this script's location so the command works from
# any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Refuse anything but a dev root before a single directory or secret exists,
# with the strict check every dev tool shares (apps/octo/dev/dev_root.py):
# the root and its secrets/ and data/, after resolving ~, symlinks and `..`,
# must sit under ~/.octo-dev or strictly under /tmp or /var/tmp, and never
# inside a production data-root location. The rest of this script uses the
# resolved root the check returns (a relative OCTO_DEV_ROOT would otherwise
# name one directory here and another after `cd "${REPO_ROOT}"`).
GUARD_PY="${REPO_ROOT}/packages/.venv/bin/python"
[[ -x "${GUARD_PY}" ]] || GUARD_PY="$(command -v python3 || true)"
if [[ -z "${GUARD_PY}" ]]; then
    echo "[start-dev-backend] no python found for the dev-root check" >&2
    exit 2
fi
if ! DEV_ROOT="$(PYTHONPATH="${REPO_ROOT}" "${GUARD_PY}" -B -c 'import sys
from pathlib import Path
from apps.octo.dev.dev_root import dev_root_problem
problem = dev_root_problem(sys.argv[1])
if not problem:
    root = Path(sys.argv[1]).expanduser().resolve()
    problem = dev_root_problem(root / "secrets") or dev_root_problem(root / "data")
print(problem or root)
sys.exit(1 if problem else 0)' "${OCTO_DEV_ROOT:-$HOME/.octo-dev}")"; then
    echo "[start-dev-backend] REFUSING: ${DEV_ROOT:-dev-root check failed}." \
         "The dev backend only provisions a dev root (OCTO_DEV_ROOT)." >&2
    exit 3
fi
SECRETS_DIR="${DEV_ROOT}/secrets"
DATA_DIR="${DEV_ROOT}/data"
DEV_OPERATOR_USERNAME="dev-admin"
# Where the first-run credentials go when stdout is not a terminal (see the
# header). The password itself never lives in a shell variable here: it is
# read from $OCTO_DEV_PASSWORD or generated inside the provisioning step.
DEV_CREDENTIALS_FILE="${SECRETS_DIR}/${DEV_OPERATOR_USERNAME}.initial-credentials"

mkdir -p "${SECRETS_DIR}" "${DATA_DIR}"

export OCTO_DATA_ROOT="${DATA_DIR}"
export OCTO_PEPPER_PATH="${SECRETS_DIR}/pepper.env"
export OCTO_MFA_KEY_PATH="${SECRETS_DIR}/mfa-key.env"
export OCTO_ADAPTER_CREDENTIALS_KEY_PATH="${SECRETS_DIR}/adapter-credentials-key.env"
# LLM-related defaults — always set in dev so the bridge endpoint
# probes the LOCAL sibling on :8101 (vs the production docker DNS
# hostname http://octo-llm:8101 which doesn't resolve here) and the
# Settings → System model selector scans the dev models directory
# instead of /var/lib/octo-llm/models. Setting these in this script
# (vs in dev.sh) guarantees they reach the uvicorn process regardless
# of how the backend is launched.
export OCTO_LLM_URL="${OCTO_LLM_URL:-http://127.0.0.1:8101}"
export OCTO_LLM_MODELS_DIR="${OCTO_LLM_MODELS_DIR:-${DATA_DIR}/octo-llm-models}"
# Autonomous Triage L1 worker (Task #119). Default ON for dev so the
# triage feed populates from real heuristic decisions; set =0 to silence.
# Heuristic L1 is deterministic + LLM-free; the LLM-on-uncertain step
# (119c) is independently gated by the bundle LLM flag + tenant consent.
export OCTO_TRIAGE_WORKER="${OCTO_TRIAGE_WORKER:-1}"
export OCTO_TRIAGE_INTERVAL_SECONDS="${OCTO_TRIAGE_INTERVAL_SECONDS:-15}"
# Dev synthetic-traffic generator (Task #119f) — gates the topbar toggle.
# DEV-ONLY: the backend also requires a dev data-root, and the toggle is
# hidden outside Vite's dev build. Never set this in any real deployment.
export OCTO_DEV_SYNTHETIC="${OCTO_DEV_SYNTHETIC:-1}"
# Browser origin lives at the Vite dev server; OCTO API is proxied
# through Vite, so cookies pin to localhost:5173.
export ATHENA_RP_ID="localhost"
export ATHENA_ORIGIN="http://localhost:5173"
# Dev runs over plain HTTP; browsers refuse to store Secure cookies on
# http://localhost so we disable the flag for local-only operation.
# NEVER set this in any deployment that handles real credentials.
export OCTO_COOKIE_SECURE="0"
# This script intentionally does NOT enable any auth-bypass shortcuts.
# Log in via the real /login flow — the bootstrap provisions a
# dev-admin operator and hands over its password and the TOTP
# enrollment URI once on first run. There is no dev auth bypass.

PYTHON="${REPO_ROOT}/packages/.venv/bin/python"
if [[ ! -x "${PYTHON}" ]]; then
    echo "[start-dev-backend] python venv not found at ${PYTHON}" >&2
    echo "  Expected the project's existing packages/.venv to be present." >&2
    exit 1
fi

# Provision the pepper if missing (32 random hex bytes; same shape as prod).
if [[ ! -f "${OCTO_PEPPER_PATH}" ]]; then
    echo "[start-dev-backend] provisioning pepper.env"
    PEPPER_HEX="$("${PYTHON}" -c 'import secrets; print(secrets.token_hex(32))')"
    cat > "${OCTO_PEPPER_PATH}" <<EOF
PEPPER_VERSION=pepper_v1
PEPPER_HEX=${PEPPER_HEX}
EOF
    chmod 600 "${OCTO_PEPPER_PATH}"
fi

# Provision the MFA key if missing.
if [[ ! -f "${OCTO_MFA_KEY_PATH}" ]]; then
    echo "[start-dev-backend] provisioning mfa-key.env"
    MFA_KEY="$("${PYTHON}" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
    cat > "${OCTO_MFA_KEY_PATH}" <<EOF
MFA_KEY_VERSION=v1
MFA_KEY_BASE64=${MFA_KEY}
EOF
    chmod 600 "${OCTO_MFA_KEY_PATH}"
fi

# Init data root (idempotent — re-running applies new migrations).
echo "[start-dev-backend] running init_data_root()"
( cd "${REPO_ROOT}" && PYTHONPATH=. "${PYTHON}" -c "from apps.octo.auth import bootstrap; bootstrap.init_data_root()" )

# Provision the credentials vault key (idempotent).
( cd "${REPO_ROOT}" && PYTHONPATH=. "${PYTHON}" -c "from apps.octo import credentials; credentials.ensure_key_file()" )

# Provision the dev super_admin operator if missing. Hands over the
# password + TOTP enrollment exactly once (terminal, or a mode-600 file
# when stdout is captured; see the header). The heredoc is quoted: values
# reach Python through the environment, never by splicing into its source.
( cd "${REPO_ROOT}" \
    && DEV_OPERATOR_USERNAME="${DEV_OPERATOR_USERNAME}" \
       DEV_CREDENTIALS_FILE="${DEV_CREDENTIALS_FILE}" \
       PYTHONPATH=. "${PYTHON}" - <<'PY'
import os
import secrets
import sys

from apps.octo import paths
from apps.octo.auth import core as core_auth, crypto, operators
from apps.octo.db import connect, transaction

USERNAME = os.environ["DEV_OPERATOR_USERNAME"]
CREDENTIALS_FILE = os.environ["DEV_CREDENTIALS_FILE"]
SUPPLIED_PASSWORD = os.environ.get("OCTO_DEV_PASSWORD", "")
MIN_PASSWORD_LENGTH = 12


def remove_credentials_file() -> None:
    try:
        os.unlink(CREDENTIALS_FILE)
    except FileNotFoundError:
        pass


def write_credentials_file(content: str) -> None:
    # Fresh file, mode 600, created with O_EXCL so it never follows a
    # planted symlink or inherits looser permissions.
    remove_credentials_file()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(CREDENTIALS_FILE, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)


reg = connect(paths.registry_db_path())
try:
    row = reg.execute("SELECT id FROM operators WHERE username = ?", (USERNAME,)).fetchone()
finally:
    reg.close()

if row is None:
    import pyotp
    if SUPPLIED_PASSWORD and len(SUPPLIED_PASSWORD) < MIN_PASSWORD_LENGTH:
        sys.exit(
            f"[start-dev-backend] OCTO_DEV_PASSWORD is shorter than "
            f"{MIN_PASSWORD_LENGTH} characters; unset it to get a random "
            "password, or choose a longer one."
        )
    password = SUPPLIED_PASSWORD or secrets.token_urlsafe(16)
    totp_secret = pyotp.random_base32()
    uri = pyotp.TOTP(totp_secret).provisioning_uri(
        name=USERNAME, issuer_name="Athena (dev)",
    )
    credentials = [
        f"  username: {USERNAME}",
        "  password: (the value of $OCTO_DEV_PASSWORD)" if SUPPLIED_PASSWORD
        else f"  password: {password}",
        f"  TOTP secret (base32): {totp_secret}",
        f"  otpauth URI: {uri}",
    ]
    to_terminal = sys.stdout.isatty()
    if to_terminal:
        remove_credentials_file()  # stale file from an earlier dev root, if any
    else:
        # stdout is a pipe or a log file: the credentials go to a private
        # file first, so they are not lost if provisioning dies midway.
        write_credentials_file(
            "Athena dev operator — first-run credentials. Enroll the TOTP, "
            "sign in once, then delete this file.\n" + "\n".join(credentials) + "\n"
        )

    op = operators.create_operator(
        username=USERNAME,
        email=f"{USERNAME}@localhost",
        role="super_admin",
        scope_slugs=["*"],
        actor="system",
        reason="dev backend bootstrap",
    )
    pw_hash = core_auth.hash_token(password)
    totp_secret_enc = crypto.encrypt_at_rest(totp_secret.encode())
    op_id = op["operator_id"]
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                "UPDATE operators SET password_hash = ?, mfa_enabled = 1, "
                "mfa_secret_enc = ? WHERE id = ?",
                (pw_hash, totp_secret_enc, op_id),
            )
    finally:
        reg.close()

    print("=" * 70)
    print("DEV SUPER_ADMIN OPERATOR PROVISIONED")
    if to_terminal:
        print("\n".join(credentials))
        print("Enroll this in your authenticator app NOW — it won't be shown again.")
    else:
        print(f"  username: {USERNAME}")
        print(f"  password + TOTP enrollment: in {CREDENTIALS_FILE} (mode 600)")
        print("  (not printed: this output is not a terminal and may be logged)")
        print("Read that file once, enroll the TOTP, then delete it.")
    print("=" * 70)
else:
    print(f"[start-dev-backend] dev operator '{USERNAME}' already provisioned")
    if SUPPLIED_PASSWORD:
        print("[start-dev-backend] OCTO_DEV_PASSWORD ignored: it only applies "
              "when the operator is first provisioned")
    if os.path.exists(CREDENTIALS_FILE):
        print(f"[start-dev-backend] reminder: {CREDENTIALS_FILE} still holds the "
              "first-run credentials; delete it once you have enrolled the TOTP")
PY
)
# The dev password is only needed for provisioning: keep it out of the
# backend process environment.
unset OCTO_DEV_PASSWORD

if [[ "${1:-}" == "provision" ]]; then
    echo "[start-dev-backend] provision-only mode — done"
    exit 0
fi

echo "[start-dev-backend] starting uvicorn on http://127.0.0.1:8001"
echo "  proxy from frontend: http://localhost:5173/api/v1/*"
echo "  data root: ${DATA_DIR}"
umask "${ORIG_UMASK}"
cd "${REPO_ROOT}"
PYTHONPATH=. exec "${REPO_ROOT}/packages/.venv/bin/uvicorn" \
    apps.octo.api:create_app \
    --factory \
    --host 127.0.0.1 \
    --port 8001 \
    --reload \
    --reload-dir apps/octo
