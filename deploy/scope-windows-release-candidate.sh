#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT="$ROOT/dist/packages"

required=(
  RouterVPN-Windows-amd64.zip
  RouterVPN-Windows-arm64.zip
  RouterVPN-Portable-Windows-amd64.zip
  RouterVPN-Portable-Windows-arm64.zip
)

for name in "${required[@]}"; do
  test -s "$OUT/$name" || { echo "missing required release package: $name" >&2; exit 1; }
done

# The reusable one-SHA release candidate has dedicated native macOS/Linux
# producers. Keep the generic producer authoritative only for Windows and
# Portable so aggregate provenance sees exactly one package per platform.
find "$OUT" -maxdepth 1 -type f -print0 | while IFS= read -r -d '' path; do
  base=$(basename "$path")
  keep=false
  for name in "${required[@]}"; do
    if [[ "$base" == "$name" ]]; then keep=true; break; fi
  done
  $keep || rm -f -- "$path"
done

(
  cd "$OUT"
  sha256sum "${required[@]}" > SHA256SUMS
  sha256sum -c SHA256SUMS
)

# Fail if any unexpected regular file survived the scoping step.
mapfile -t files < <(find "$OUT" -maxdepth 1 -type f -printf '%f\n' | sort)
expected=(
  RouterVPN-Portable-Windows-amd64.zip
  RouterVPN-Portable-Windows-arm64.zip
  RouterVPN-Windows-amd64.zip
  RouterVPN-Windows-arm64.zip
  SHA256SUMS
)
[[ "${files[*]}" == "${expected[*]}" ]] || {
  printf 'unexpected scoped release files: %s\n' "${files[*]}" >&2
  exit 1
}

printf 'Scoped generic release candidate to Windows/Portable with verified SHA256SUMS.\n'
