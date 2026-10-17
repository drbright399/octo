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
#   4. Commit it as ONE orphan commit in a fresh repository outside this one,
#      authored by a noreply identity, with no trailers and no signature, then
#      re-scan that commit.
#
# It never pushes. It prints the push command for a human to run after review.
#
# Usage:
#   scripts/publish_public.sh [--dry-run] [--ref REF] [--out DIR] [--remote-url URL]
#                             [--allowlist FILE] [--map FILE] [--local-block FILE] [--repo DIR]
#
#   --dry-run      list what would be published and whether the scan would pass
#                  (exit 1 if it would refuse); writes nothing outside a temp dir
#   --ref          what to publish (default HEAD; committed content only)
#   --out          new directory for the public repository
#                  (default: <repo>-public-<timestamp> next to the repo)
#   --remote-url   only used in the printed push command
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
    --remote-url) remote_url="${2:?--remote-url needs a value}"; shift 2 ;;
    --allowlist) allowlist="${2:?--allowlist needs a value}"; shift 2 ;;
    --map) map="${2:?--map needs a value}"; shift 2 ;;
    --local-block) local_block="${2:?--local-block needs a value}"; shift 2 ;;
    --repo) repo="${2:?--repo needs a value}"; shift 2 ;;
    -h|--help) sed -n '2,37p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

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
