#!/usr/bin/env bash
# scripts/publish_public.sh: THE ONLY supported way to make a public copy.
#
#   1. Export the files committed at REF that match ops/public/allowlist.txt.
#      Anything not listed stays out (internal docs, runbooks, session
#      notes); a fixed hard-exclude list applies whatever the allowlist says
#      (scripts/publish_export.py): working notes and agent state, all of
#      ops/ (host trees, deploy files, the allowlist itself), host access
#      and infrastructure state, key / vault / database / backup files.
#   2. Apply the local, gitignored replacement map .githooks/.publish-map
#      ("real => neutral" per line) to contents and path names.
#   3. Scan the result with scripts/scan_sensitive.py --publish: secrets,
#      never-commit files, LAN / tailnet / public IPs, home and /mnt paths,
#      memory links, *.ts.net names, e-mail addresses and every term in
#      .githooks/.local-block. ANY hit: refuse, delete the export, commit nothing.
#   4. Commit it, authored by a noreply identity, with no trailers and no
#      signature, then re-scan that commit (what it adds, and its message):
#      - the first public copy (--out): ONE orphan commit in a fresh
#        repository outside this one;
#      - every later copy (--onto DIR): ONE commit on top of main in DIR, a
#        local clone of the public repository, whose tree is exactly the
#        export. Files the public main holds and the export does not are
#        removed (expected: a file left the allowlist or the tree) and listed.
#        The commit is built and checked in a scratch repository that only
#        reads DIR's objects; DIR changes only after every check passed
#        (main fast-forwards to the commit), so a refusal leaves DIR as it was.
#
# It never pushes. It prints the push command for a human to run after review.
#
# Usage:
#   scripts/publish_public.sh [--dry-run] [--ref REF] [--out DIR | --onto DIR]
#                             [--remote-url URL] [--allowlist FILE] [--map FILE]
#                             [--local-block FILE] [--repo DIR]
#
#   --dry-run      list what would be published and whether the scan would pass
#                  (exit 1 if it would refuse); with --onto also what the commit
#                  would add, change and remove; writes nothing outside a temp dir
#   --ref          what to publish (default HEAD; committed content only)
#   --out          new directory for the public repository
#                  (default: <repo>-public-<timestamp> next to the repo)
#   --onto         a local clone of the public repository to add the commit to.
#                  It must be outside this repository, clean (no modified or
#                  untracked files), on main, with main at its upstream (fetch
#                  first: this script never contacts a remote), a full clone (not
#                  shallow or partial), and every commit in its history one this
#                  script made (noreply author = committer, UTC dates, one parent
#                  at most, "Public snapshot YYYY-MM-DD" and no body): never
#                  edited, merged or patched by hand or on the hosting site
#   --remote-url   only used in the printed push command
#
# The next re-publish, from a fresh clone of the public repository:
#   git clone <public-repo-url> ../public-clone
#   scripts/publish_public.sh --dry-run --onto ../public-clone
#   scripts/publish_public.sh --onto ../public-clone
#   git -C ../public-clone show --stat HEAD     # review, then push it yourself
#
# Identity: PUBLISH_AUTHOR_NAME (default "Athena-OCTO"; letters, digits, space,
# . _ -; never the operator's git user.name; no local-block term) and
# PUBLISH_AUTHOR_EMAIL (default "noreply@users.noreply.github.com"; must be
# <name>@users.noreply.github.com, no local-block term). The commit is dated in
# UTC (+0000) so it does not carry the operator's time zone.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scanner="$here/scan_sensitive.py"
exporter="$here/publish_export.py"

dry_run=0
ref="HEAD"
out=""
onto=""
remote_url=""
allowlist=""
map=""
local_block=""
repo=""

die() { echo "publish_public: $*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    --ref) ref="${2:?--ref needs a value}"; shift 2 ;;
    --out) out="${2:?--out needs a value}"; shift 2 ;;
    --onto) onto="${2:?--onto needs a value}"; shift 2 ;;
    --remote-url) remote_url="${2:?--remote-url needs a value}"; shift 2 ;;
    --allowlist) allowlist="${2:?--allowlist needs a value}"; shift 2 ;;
    --map) map="${2:?--map needs a value}"; shift 2 ;;
    --local-block) local_block="${2:?--local-block needs a value}"; shift 2 ;;
    --repo) repo="${2:?--repo needs a value}"; shift 2 ;;
    -h|--help) awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ -z "$out" || -z "$onto" ]] || \
  die "--out (a new repository) and --onto (a commit on top of the public main) are alternatives"

py="$(command -v python3 || true)"
[[ -n "$py" ]] || die "python3 not found"

repo="$(cd "${repo:-$here/..}" && git rev-parse --show-toplevel)" || die "not a git repository"
allowlist="${allowlist:-$repo/ops/public/allowlist.txt}"
[[ -f "$allowlist" ]] || \
  die "allowlist not found: $allowlist (a public copy carries none; pass --allowlist FILE)"
map="${map:-$repo/.githooks/.publish-map}"
commit_sha="$(git -C "$repo" rev-parse --verify --quiet "${ref}^{commit}")" || die "unknown ref: $ref"

# The local-block terms (client names, host names, tailnet ids) are the check
# a generic scanner cannot make. No terms file, no public copy.
if [[ -z "$local_block" ]]; then
  for candidate in "$repo/.githooks/.local-block" \
                   "$(dirname "$(git -C "$repo" rev-parse --path-format=absolute --git-common-dir)")/.githooks/.local-block"; do
    if [[ -f "$candidate" ]]; then local_block="$candidate"; break; fi
  done
fi
[[ -n "$local_block" && -f "$local_block" ]] || \
  die "no .githooks/.local-block (client / host / tailnet terms): create it, or pass --local-block FILE"
[[ -f "$map" ]] || echo "publish_public: no replacement map at $map; publishing without replacements" >&2

if [[ -n "$(git -C "$repo" status --porcelain --untracked-files=no)" ]]; then
  echo "publish_public: note: uncommitted changes are NOT published (exporting $ref = ${commit_sha:0:12})" >&2
fi

author_name="${PUBLISH_AUTHOR_NAME:-Athena-OCTO}"
author_email="${PUBLISH_AUTHOR_EMAIL:-noreply@users.noreply.github.com}"
[[ "$author_email" =~ ^[A-Za-z0-9._+-]+@users\.noreply\.github\.com$ ]] || \
  die "PUBLISH_AUTHOR_EMAIL must be a GitHub noreply address (<name>@users.noreply.github.com)"
[[ "$author_name" =~ ^[A-Za-z0-9._\ -]{1,64}$ ]] || \
  die "PUBLISH_AUTHOR_NAME may only use letters, digits, space, '.', '_' and '-'"
operator_name="$(git -C "$repo" config user.name || true)"
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
if [[ -n "$operator_name" ]] && [[ "$(lower "$author_name")" == "$(lower "$operator_name")" ]]; then
  die "PUBLISH_AUTHOR_NAME is the operator's own git user.name; use a project identity"
fi
# No local-block term (a person, a client, a host, a handle) in the identity.
"$py" - "$here" "$local_block" "$author_name" "$author_email" <<'PY' || \
  die "the publish identity contains a local-block term; use a neutral project identity"
import sys
sys.path.insert(0, sys.argv[1])
import scan_sensitive as ss
rx = ss.load_local_block(ss.Path(sys.argv[2]))
sys.exit(1 if rx is not None and any(rx.search(v) for v in sys.argv[3:]) else 0)
PY

scan() {  # scan <dir>: strictest scan of an export directory
  (cd "$repo" && "$py" "$scanner" --publish --root "$1" --local-block "$local_block")
}

# --------------------------------------------------------------------------- #
# --onto DIR: one commit on top of the public main in a clone of it
# --------------------------------------------------------------------------- #
if [[ -n "$onto" ]]; then
  [[ -d "$onto" ]] || die "--onto: no such directory: $onto"
  onto="$(cd "$onto" && pwd -P)"
  repo_real="$(cd "$repo" && pwd -P)"
  case "$onto/" in
    "$repo_real/"*) die "--onto must be outside the repository ($repo)" ;;
  esac
  case "$repo_real/" in
    "$onto/"*) die "--onto must not contain the repository ($repo)" ;;
  esac
  onto_top="$(git -C "$onto" rev-parse --show-toplevel 2>/dev/null)" || \
    die "--onto: $onto is not a git clone"
  [[ "$(cd "$onto_top" && pwd -P)" == "$onto" ]] || die "--onto: $onto is not the top of a clone"
  [[ "$(git -C "$onto" rev-parse --path-format=absolute --git-common-dir)" != \
     "$(git -C "$repo" rev-parse --path-format=absolute --git-common-dir)" ]] || \
    die "--onto: $onto is a worktree of this repository, not a clone of the public one"
  branch="$(git -C "$onto" symbolic-ref -q --short HEAD || true)"
  [[ "$branch" == "main" ]] || die "--onto: $onto is not on main (${branch:-detached HEAD})"
  parent="$(git -C "$onto" rev-parse -q --verify 'HEAD^{commit}')" || \
    die "--onto: main in $onto has no commit; make the first public copy with --out"
  [[ -z "$(git --no-optional-locks -C "$onto" status --porcelain --untracked-files=all)" ]] || \
    die "--onto: $onto has modified or untracked files; it must be a clean clone"
  upstream="$(git -C "$onto" rev-parse -q --verify 'main@{upstream}' 2>/dev/null)" || \
    die "--onto: main in $onto has no upstream; use a clone of the public repository"
  [[ "$upstream" == "$parent" ]] || \
    die "--onto: main in $onto is not at its upstream (ahead or behind): fetch, and bring main to the public main first"
  # A clone of THIS repository (or one that ever fetched from it) is never a target.
  if git -C "$onto" cat-file -e "${commit_sha}^{commit}" 2>/dev/null; then
    die "--onto: $onto holds commits of this repository; it must be a clone of the public repository"
  fi
  # Every public commit is one this script made: author = committer, a GitHub
  # noreply address, UTC dates, one parent at most, the snapshot subject and
  # nothing else in the message. Anything else means the public repository was
  # changed in place (edited, merged or patched on the hosting site). The
  # history checked is that of the commit built on ($parent, main's commit),
  # never a name a tag called "main" could shadow.
  foreign="$(git -C "$onto" log --no-show-signature --date=raw \
      --format='%h%x09%an <%ae>%x09%cn <%ce>%x09%ae%x09%p%x09%ad%x09%cd%x09%s%x09%b' "$parent" | awk -F'\t' '
    /^[0-9a-f]+\t/ {
      ours = NF == 9 && $2 == $3 && $4 ~ /^[A-Za-z0-9._+-]+@users\.noreply\.github\.com$/ &&
             $5 !~ / / && $6 ~ / \+0000$/ && $7 ~ / \+0000$/ && $9 == "" &&
             $8 ~ /^Public snapshot [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/
      if (!ours && !found) { print $1; found = 1 }
      last = $1
      next
    }
    /./ && !found { print last; found = 1 }')"
  [[ -z "$foreign" ]] || \
    die "--onto: the public history holds a commit this script did not make (${foreign}): the public repository was changed in place. Do not publish on top of it; see docs/NON-NEGOTIABLES.md rule 13"
  [[ "$(git -C "$onto" rev-parse --is-shallow-repository)" == "false" && \
     -z "$(git -C "$onto" config --get extensions.partialClone || true)" ]] || \
    die "--onto: $onto is a shallow or partial clone; use a full clone of the public repository"

  work="$(mktemp -d "${TMPDIR:-/tmp}/publish-onto.XXXXXX")"
  trap 'rm -rf "$work"' EXIT
  refuse_onto() {
    rm -rf "$work"
    echo "publish_public: REFUSED: $*. Nothing was committed; $onto is as it was." >&2
    exit 1
  }
  export_dir="$work/export"
  if (( dry_run )); then
    echo "Would publish from $ref (${commit_sha:0:12}) onto $onto (main at ${parent:0:12}), allowlist $allowlist:"
    "$py" "$exporter" --repo "$repo" --ref "$commit_sha" --allowlist "$allowlist" --map "$map" \
      --out "$export_dir" | sed 's/^/  /'
    if ! scan "$export_dir"; then
      echo "Scan: would REFUSE (findings above). Fix the source, the map or the allowlist." >&2
      exit 1
    fi
  else
    "$py" "$exporter" --repo "$repo" --ref "$commit_sha" --allowlist "$allowlist" --map "$map" \
      --out "$export_dir" >/dev/null || refuse_onto "the export failed"
    scan "$export_dir" || refuse_onto "the scan found something (see above)"
  fi
  [[ -n "$(find "$export_dir" -type f -print -quit)" ]] || refuse_onto "the export is empty"

  # A scratch repository with no global / system config (no hooks, templates,
  # signing key or identity but the noreply one) that borrows DIR's objects
  # read-only: everything new is written here, nothing in DIR.
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
  export GIT_AUTHOR_NAME="$author_name" GIT_AUTHOR_EMAIL="$author_email"
  export GIT_COMMITTER_NAME="$author_name" GIT_COMMITTER_EMAIL="$author_email"
  scratch="$work/scratch.git"
  git init -q --bare "$scratch"
  git -C "$onto" rev-parse --path-format=absolute --git-path objects > "$scratch/objects/info/alternates"
  sgit() { git --git-dir="$scratch" "$@"; }
  # The tree is exactly the export: every file, .gitignore'd names included.
  GIT_INDEX_FILE="$work/index" git --git-dir="$scratch" --work-tree="$export_dir" add -A --force
  tree="$(GIT_INDEX_FILE="$work/index" sgit write-tree)"
  diff -q <(sgit ls-tree -r -z --name-only "$tree" | tr '\0' '\n' | LC_ALL=C sort) \
          <(cd "$export_dir" && find . -type f | cut -c3- | LC_ALL=C sort) >/dev/null || \
    refuse_onto "the commit tree is not exactly the export"

  summary() {  # summary <tree-ish>: what the commit adds, changes and removes on the public main
    local added changed removed
    added="$(sgit diff-tree -r --no-renames --diff-filter=A --name-only "$parent" "$1" | wc -l | tr -d ' ')"
    changed="$(sgit diff-tree -r --no-renames --diff-filter=MT --name-only "$parent" "$1" | wc -l | tr -d ' ')"
    removed="$(sgit diff-tree -r --no-renames --diff-filter=D --name-only "$parent" "$1" | wc -l | tr -d ' ')"
    echo "  $added added, $changed changed, $removed removed"
    if (( removed > 0 )); then
      echo "  removed (on the public main, not in this export; expected when a file left the tree or the allowlist):"
      sgit diff-tree -r --no-renames --diff-filter=D --name-only "$parent" "$1" | sed 's/^/    /'
    fi
  }
  if [[ "$tree" == "$(sgit rev-parse "${parent}^{tree}")" ]]; then
    echo "Nothing to publish: main in $onto (${parent:0:12}) already matches this export. Nothing was changed."
    exit 0
  fi
  if (( dry_run )); then
    echo "Scan: clean. A real run would add one commit on top of main in $onto (nothing is pushed):"
    summary "$tree"
    exit 0
  fi

  # UTC, so the commit does not record the operator's time-zone offset.
  now="$(date -u +%s)"
  export TZ=UTC GIT_AUTHOR_DATE="@$now +0000" GIT_COMMITTER_DATE="@$now +0000"
  new="$(sgit commit-tree --no-gpg-sign -p "$parent" -m "Public snapshot $(date -u +%Y-%m-%d)" "$tree")" || \
    refuse_onto "the commit failed"

  [[ "$(sgit rev-list --parents -n 1 "$new")" == "$new $parent" ]] || \
    refuse_onto "the commit's only parent is not the public main"
  trailers="$(sgit log -1 --format=%B "$new" | git interpret-trailers --parse)"
  [[ -z "$trailers" ]] || refuse_onto "the commit message carries trailers"
  ident="$(sgit log -1 --format='%an <%ae>|%cn <%ce>' "$new")"
  [[ "$ident" == "$author_name <$author_email>|$author_name <$author_email>" ]] || \
    refuse_onto "unexpected identity: $ident"
  dates="$(sgit log -1 --format='%ad|%cd' --date=raw "$new")"
  [[ "$dates" == "$now +0000|$now +0000" ]] || refuse_onto "the commit is not dated in UTC: $dates"
  # What the commit adds and its message, as the pre-push hook would see them.
  (cd "$repo" && "$py" "$scanner" --range "$parent..$new" --publish --repo "$scratch" \
      --local-block "$local_block") || refuse_onto "the commit did not re-scan clean"

  # Every check passed: bring the commit into DIR and fast-forward main to it.
  [[ "$(git -C "$onto" rev-parse -q --verify HEAD)" == "$parent" && \
     -z "$(git --no-optional-locks -C "$onto" status --porcelain --untracked-files=all)" ]] || \
    refuse_onto "$onto changed while publishing"
  sgit update-ref refs/heads/publish "$new"
  git -C "$onto" -c core.hooksPath=/dev/null fetch -q --no-tags --no-write-fetch-head \
    --no-recurse-submodules "$scratch" refs/heads/publish || refuse_onto "could not copy the commit into $onto"
  if ! git -C "$onto" -c core.hooksPath=/dev/null -c merge.verifySignatures=false \
         merge -q --ff-only --no-stat "$new" \
     || [[ "$(git -C "$onto" rev-parse HEAD)" != "$new" ]] \
     || [[ -n "$(git --no-optional-locks -C "$onto" status --porcelain --untracked-files=all)" ]]; then
    if [[ "$(git -C "$onto" rev-parse -q --verify HEAD)" == "$new" ]]; then
      git -C "$onto" -c core.hooksPath=/dev/null reset -q --hard "$parent" || true
    fi
    refuse_onto "main in $onto did not fast-forward cleanly to the commit (put back at ${parent:0:12})"
  fi

  files="$(git -C "$onto" ls-files | wc -l | tr -d ' ')"
  push_to="${remote_url:-$(git -C "$onto" config "branch.main.remote" || echo origin)}"
  cat <<EOF

Public commit ready on top of the public main, NOT pushed: $onto
  commit $(git -C "$onto" rev-parse --short HEAD) (parent ${parent:0:12}) by $author_name <$author_email>, $files files, no trailers
  source: $ref (${commit_sha:0:12}); allowlist: $allowlist
EOF
  summary "$new"
  cat <<EOF

Review it (git -C "$onto" show --stat HEAD; read the diff), then push it yourself:
  git -C "$onto" push $push_to main
EOF
  exit 0
fi

if (( dry_run )); then
  stage="$(mktemp -d "${TMPDIR:-/tmp}/publish-dry-run.XXXXXX")"
  trap 'rm -rf "$stage"' EXIT
  echo "Would publish from $ref (${commit_sha:0:12}), allowlist $allowlist:"
  "$py" "$exporter" --repo "$repo" --ref "$commit_sha" --allowlist "$allowlist" --map "$map" \
    --out "$stage/export" | sed 's/^/  /'
  if scan "$stage/export"; then
    echo "Scan: clean. A real run would commit this as one orphan commit (nothing is pushed)."
    exit 0
  fi
  echo "Scan: would REFUSE (findings above). Fix the source, the map or the allowlist." >&2
  exit 1
fi

if [[ -z "$out" ]]; then
  out="$(dirname "$repo")/$(basename "$repo")-public-$(date -u +%Y%m%d-%H%M%S)"
fi
mkdir -p "$(dirname "$out")"
out="$(cd "$(dirname "$out")" && pwd)/$(basename "$out")"
case "$out/" in
  "$repo/"*) die "--out must be outside the repository ($repo)" ;;
esac
if [[ -e "$out" ]] && [[ -n "$(ls -A "$out" 2>/dev/null)" ]]; then
  die "$out exists and is not empty"
fi

refuse() {
  rm -rf "$out"
  echo "publish_public: REFUSED: $*. Nothing was committed; the export was deleted." >&2
  exit 1
}

"$py" "$exporter" --repo "$repo" --ref "$commit_sha" --allowlist "$allowlist" --map "$map" \
  --out "$out" >/dev/null || refuse "the export failed"
scan "$out" || refuse "the scan found something (see above)"

# A fresh repository with no global / system config: no hooks, no templates,
# no signing key, no identity but the noreply one.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME="$author_name" GIT_AUTHOR_EMAIL="$author_email"
export GIT_COMMITTER_NAME="$author_name" GIT_COMMITTER_EMAIL="$author_email"
# UTC, so the snapshot does not record the operator's time-zone offset.
now="$(date -u +%s)"
export TZ=UTC GIT_AUTHOR_DATE="@$now +0000" GIT_COMMITTER_DATE="@$now +0000"
git -C "$out" init -q -b main
git -C "$out" add -A
git -C "$out" -c core.hooksPath=/dev/null -c commit.gpgsign=false \
  commit -q --no-verify --cleanup=strip -m "Public snapshot $(date -u +%Y-%m-%d)"

[[ "$(git -C "$out" rev-list --count HEAD)" == "1" ]] || refuse "the snapshot is not a single commit"
trailers="$(git -C "$out" log -1 --format=%B | git interpret-trailers --parse)"
[[ -z "$trailers" ]] || refuse "the commit message carries trailers"
ident="$(git -C "$out" log -1 --format='%an <%ae>|%cn <%ce>')"
[[ "$ident" == "$author_name <$author_email>|$author_name <$author_email>" ]] || refuse "unexpected identity: $ident"
dates="$(git -C "$out" log -1 --format='%ad|%cd' --date=raw)"
[[ "$dates" == "$now +0000|$now +0000" ]] || refuse "the commit is not dated in UTC: $dates"
(cd "$repo" && "$py" "$scanner" --range HEAD --publish --repo "$out" --local-block "$local_block") \
  || refuse "the committed snapshot did not re-scan clean"

files="$(git -C "$out" ls-files | wc -l | tr -d ' ')"
cat <<EOF

Public snapshot ready, NOT pushed: $out
  one orphan commit $(git -C "$out" rev-parse --short HEAD) by $author_name <$author_email>, $files files, no trailers
  source: $ref (${commit_sha:0:12}); allowlist: $allowlist

Review it (git -C "$out" show --stat; read the files), then push it yourself:
  git -C "$out" push ${remote_url:-<public-repo-url>} main
EOF
