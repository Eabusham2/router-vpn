#!/usr/bin/env bash
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

# Only these exact obsolete publisher/trigger refs may be removed automatically.
# If any branch name exists at a different SHA, fail closed for manual review.
declare -A STALE=(
  [publish-android-auto-badges]=7c4949a7c4a7f151786e56546e9f23f9f6192ccc
  [publish-auto-summary-ui]=d03e82e7938256d2cd2a5c273fdf8843a5125e36
  [publish-desktop-auto-badges]=fba7b457fa33067b154ba6a45b53655c098d9ffb
  [publish-native-ui-v2]=e53bd5664495a55cf0affdcd9eb2b602a98fd41a
  [publish-profile-ui-truth]=39840d14143d489d52a9207551631737918d9b72
  [trigger-cross-platform-ui-remaining]=e33765d96c46d41c84350c67aec790cc72ee4261
)

for branch in "${!STALE[@]}"; do
  expected="${STALE[$branch]}"
  current="$(gh api "repos/$GITHUB_REPOSITORY/branches/$branch" --jq '.commit.sha' 2>/dev/null || true)"
  [[ -n "$current" ]] || continue
  if [[ "$current" != "$expected" ]]; then
    echo "Refusing to delete changed stale-branch candidate: $branch is $current, expected $expected" >&2
    exit 1
  fi
  gh api -X DELETE "repos/$GITHUB_REPOSITORY/git/refs/heads/$branch"
  echo "Removed verified obsolete branch $branch at $expected"
done

mapfile -t extra < <(gh api --paginate "repos/$GITHUB_REPOSITORY/branches?per_page=100" --jq '.[].name' | grep -vx main || true)
if (("${#extra[@]}")); then
  printf 'Unexpected non-main branch(es):\n' >&2
  printf '  %s\n' "${extra[@]}" >&2
  exit 1
fi

echo 'Branch policy OK: main is the only branch.'
