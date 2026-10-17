#!/usr/bin/env bash
# Install the secret-scan hooks (pre-commit, commit-msg, pre-push) for EVERY
# worktree and EVERY branch of this clone. Run once per clone, by every
# collaborator and every agent, and again when a branch says its scanner is
# newer than the installed one:
#
#   scripts/install_hooks.sh            # --force: allow installing an older scanner
#
# The hooks and the scanner are copied ("pinned") into the clone's shared git
# directory and core.hooksPath points there, so a checkout of a branch that
# predates the guardrails (no .githooks/pre-push of its own) is still guarded
# on commit and on push.
#
# Layout (since scanner v5): each install is a fresh versioned directory,
# <git-common-dir>/athena-guardrails.v<N>.<random>/, and
# <git-common-dir>/athena-guardrails is a symlink to the live one, swapped with
# one rename(2). core.hooksPath (<git-common-dir>/athena-guardrails/hooks) never
# names a missing directory, not even for a moment: git would then run no hooks
# at all, silently, for every worktree that commits meanwhile. An older install
# (a plain directory) is migrated the same way: core.hooksPath points at the new
# copy first, then the old directory moves aside.
#
# Parallel agents each run this script, so runs are serialized: staging, the
# swap and the cleanup happen under a lock directory,
# <git-common-dir>/athena-guardrails.lock (mkdir is atomic everywhere; flock is
# not on macOS). A run waits for it (ATHENA_GUARDRAILS_LOCK_WAIT seconds,
# default 120) and breaks it only when it is stale: its owner process (on this
# host) is gone, or it is older than ATHENA_GUARDRAILS_LOCK_STALE seconds
# (default 300). Under
# the lock the live link target is read again right before the cleanup and is
# never removed. At the end core.hooksPath must name a directory holding every
# hook and the scanner, or the script fails loudly (exit 1).
#
# Since scanner v4 (2026-10-15) every hook runs the strict --publish checks:
# the private repo meets the public standard too. A clone pinned at an older
# version says so on each commit until this script runs again.
set -euo pipefail

force=0
[[ "${1:-}" == "--force" ]] && force=1

top="$(git rev-parse --show-toplevel)"
common="$(git rev-parse --path-format=absolute --git-common-dir)"
dest="$common/athena-guardrails"
lock="$common/athena-guardrails.lock"
lock_wait="${ATHENA_GUARDRAILS_LOCK_WAIT:-120}"
lock_stale="${ATHENA_GUARDRAILS_LOCK_STALE:-300}"
py="$(command -v python3 || command -v python || true)"
if [[ -z "$py" ]]; then
  echo "install_hooks: python3 not found; the hooks need it too" >&2
  exit 1
fi
hooks=(pre-commit commit-msg pre-push)
files=(
  .githooks/pre-commit .githooks/commit-msg .githooks/pre-push .githooks/lib-scan.sh
  scripts/scan_sensitive.py
  apps/__init__.py apps/octo/__init__.py apps/octo/security/__init__.py
  apps/octo/security/secret_patterns.py
)
for rel in "${files[@]}"; do
  if [[ ! -f "$top/$rel" ]]; then
    echo "install_hooks: $rel is missing in $top; run this from a branch that has the guardrails" >&2
    exit 1
  fi
done

# --- the lock ---------------------------------------------------------------
held=0
stage=""
live_stage=0
on_exit() {
  if [[ -n "$stage" ]] && (( ! live_stage )); then rm -rf "$stage"; fi
  # Release only a lock this run still owns (a stale-lock breaker may have taken it).
  if (( held )) && [[ "$(cat "$lock/owner" 2>/dev/null || true)" == "$$ "* ]]; then
    rm -rf "$lock"
  fi
  return 0
}
trap on_exit EXIT

age_of() {  # seconds since the lock directory was made (0 if it is gone)
  "$py" -c 'import os, sys, time
try:
    print(max(0, int(time.time() - os.stat(sys.argv[1]).st_mtime)))
except OSError:
    print(0)' "$1"
}

pid_alive() {
  kill -0 "$1" 2>/dev/null && return 0
  # "Operation not permitted": alive, another user's process.
  [[ "$(LC_ALL=C kill -0 "$1" 2>&1)" == *"not permitted"* ]]
}

host="$(hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown)"

lock_is_stale() {
  # owner: "<pid> <epoch> <host>". A process id means something only on the
  # host (and in the pid namespace) that wrote it: a lock from elsewhere (a
  # container, another machine on a shared disk) goes stale by age alone.
  local owner pid rest owner_host
  owner="$(cat "$lock/owner" 2>/dev/null || true)"
  read -r pid _ owner_host rest <<<"$owner" || true
  if [[ "${pid:-}" =~ ^[0-9]+$ && "${owner_host:-}" == "$host" ]] && ! pid_alive "$pid"; then
    return 0  # its owner is gone (killed, crashed)
  fi
  (( $(age_of "$lock") > lock_stale ))
}

break_stale_lock() {
  # One breaker at a time ("$lock.break", held for milliseconds): the lock is
  # judged again under it, so a run never removes a lock another run has
  # just taken in place of the stale one.
  if ! mkdir "$lock.break" 2>/dev/null; then
    if (( $(age_of "$lock.break") > 30 )); then rmdir "$lock.break" 2>/dev/null || true; fi
    return 0
  fi
  if [[ -d "$lock" ]] && lock_is_stale; then
    echo "install_hooks: removing a stale lock (owner: $(cat "$lock/owner" 2>/dev/null || echo none))" >&2
    rm -rf "$lock"
  fi
  rmdir "$lock.break" 2>/dev/null || true
}

acquire_lock() {
  local start now
  if [[ ! -w "$common" ]]; then
    echo "install_hooks: ERROR: $common is not writable; nothing was changed" >&2
    exit 1
  fi
  start="$(date +%s)"
  while ! mkdir "$lock" 2>/dev/null; do
    if [[ -d "$lock" ]] && lock_is_stale; then
      break_stale_lock
      [[ -d "$lock" ]] || continue
    fi
    now="$(date +%s)"
    if (( now - start >= lock_wait )); then
      echo "install_hooks: ERROR: another install holds $lock (owner: $(cat "$lock/owner" 2>/dev/null || echo unknown)) and did not finish within ${lock_wait}s; nothing was changed. If no install is running, remove that directory and run this again." >&2
      exit 1
    fi
    sleep 0.2 2>/dev/null || sleep 1
  done
  held=1
  printf '%s %s %s\n' "$$" "$(date +%s)" "$host" >"$lock/owner"
}

# git config writes through its own lock file: another git command holding it
# for a moment is retried, never silently skipped.
set_hooks_path() {
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    git config core.hooksPath "$1" 2>/dev/null && return 0
    sleep 0.2 2>/dev/null || sleep 1
  done
  git config core.hooksPath "$1"
}

acquire_lock

# --- under the lock: version check, stage, swap, cleanup ---------------------
version() { sed -n 's/^GUARDRAILS_VERSION = \([0-9][0-9]*\).*/\1/p' "$1" 2>/dev/null | head -n 1; }
new="$(version "$top/scripts/scan_sensitive.py")"
if [[ -f "$dest/scripts/scan_sensitive.py" ]] && (( ! force )); then
  old="$(version "$dest/scripts/scan_sensitive.py")"
  if [[ -n "$old" && "$old" -gt "${new:-0}" ]]; then
    echo "install_hooks: the installed scanner (v$old) is newer than this branch's (v${new:-?}); not downgrading (--force to override)" >&2
    exit 1
  fi
fi

stage="$(mktemp -d "$common/athena-guardrails.v${new:-0}.XXXXXX")"
for rel in "${files[@]}"; do
  case "$rel" in
    .githooks/*) target="hooks/${rel#.githooks/}" ;;
    *) target="$rel" ;;
  esac
  mkdir -p "$stage/$(dirname "$target")"
  cp "$top/$rel" "$stage/$target"
done
for hook in "${hooks[@]}"; do chmod 0755 "$stage/hooks/$hook"; done

previous=""
if [[ -L "$dest" ]]; then
  previous="$(readlink "$dest")"
elif [[ -e "$dest" ]]; then
  # A pre-v5 install: a plain directory. Point git at the new copy (git config
  # writes through a lock file and a rename), then move the old one aside.
  live_stage=1  # from here on git may run the hooks from $stage
  set_hooks_path "$stage/hooks"
  retired="$(mktemp -d "$common/athena-guardrails.retired.XXXXXX")"
  mv "$dest" "$retired/"
fi
link="$common/athena-guardrails.link.$$"
rm -f "$link"
ln -s "$(basename "$stage")" "$link"
# rename(2) over the old symlink: the path is never missing.
"$py" -c 'import os, sys; os.replace(sys.argv[1], sys.argv[2])' "$link" "$dest"
live_stage=1
set_hooks_path "$dest/hooks"

# Older copies: keep the live one (read again here, under the lock) and the
# one it replaced (a hook may still be running from it); remove the rest.
# Only names this script creates are touched.
live="$(readlink "$dest" 2>/dev/null || true)"
for old in "$common"/athena-guardrails.v[0-9]*.* "$common"/athena-guardrails.new.* \
           "$common"/athena-guardrails.retired.* "$common"/athena-guardrails.link.*; do
  [[ -e "$old" || -L "$old" ]] || continue
  name="$(basename "$old")"
  if [[ -L "$old" ]]; then
    [[ "$name" == athena-guardrails.link.* ]] && rm -f -- "$old"  # a crashed run's spare link
    continue
  fi
  [[ -d "$old" ]] || continue
  [[ "$name" == "$live" || "$name" == "$(basename "$stage")" || "$name" == "$previous" ]] && continue
  rm -rf -- "$old"
done

# --- verify: git must find every hook where core.hooksPath points ------------
hooks_path="$(git config --path core.hooksPath 2>/dev/null || true)"
[[ -n "$hooks_path" && "$hooks_path" != /* ]] && hooks_path="$top/$hooks_path"
problem=""
if [[ -z "$hooks_path" || ! -d "$hooks_path" ]]; then
  problem="core.hooksPath (${hooks_path:-unset}) is not a directory"
else
  for hook in "${hooks[@]}"; do
    [[ -f "$hooks_path/$hook" && -x "$hooks_path/$hook" ]] || problem="$problem $hook is missing or not executable;"
  done
  [[ -f "$hooks_path/lib-scan.sh" ]] || problem="$problem lib-scan.sh is missing;"
  [[ -f "$hooks_path/../scripts/scan_sensitive.py" ]] || problem="$problem the scanner is missing;"
fi
if [[ -n "$problem" ]]; then
  echo "install_hooks: ERROR: the hooks are NOT active: $problem" >&2
  echo "install_hooks: git runs no hooks from a missing directory, silently. Fix the cause (an environment or global core.hooksPath override, a damaged $common) and run this script again." >&2
  exit 1
fi

echo "hooks: scanner v${new:-?} pinned in $stage; $dest -> $(basename "$stage"); core.hooksPath=$dest/hooks"
echo "hooks: pre-commit, commit-msg and pre-push now run for every worktree and branch of this clone"
