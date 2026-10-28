#!/usr/bin/env bash
# Check/install host tools before promoting any application or private state.
set -euo pipefail
ACTION=${1:-}
APP=${2:-}
[[ "$ACTION" == --check || "$ACTION" == --install ]] && [[ -f "$APP" && ! -L "$APP" && -x "$APP" ]] || {
  echo 'usage: install-linux-system-tools.sh --check|--install /path/to/router-vpn-app' >&2
  exit 2
}

missing=()
check_tools() {
  missing=()
  local tool linkage
  for tool in python3 ip getent ldd; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  # The privileged socket guardian uses these exact system-owned paths.
  for tool in /usr/sbin/nft /usr/sbin/useradd /usr/sbin/userdel /usr/sbin/nologin; do
    [[ -f "$tool" && -x "$tool" ]] || missing+=("$tool")
  done
  if command -v ldd >/dev/null 2>&1; then
    if ! linkage=$(ldd "$APP" 2>&1) || [[ "$linkage" == *'not found'* ]]; then
      missing+=('compatible GTK3/libcurl/json-glib and linked system libraries')
      printf '%s\n' "$linkage" >&2
    fi
  fi
}

check_tools
if (( ${#missing[@]} == 0 )); then
  echo 'Linux runtime system tools and native GUI libraries are available.'
  exit 0
fi
printf 'Missing Linux runtime dependency: %s\n' "${missing[@]}" >&2
if [[ "$ACTION" != --install ]]; then exit 1; fi
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run the installer with sudo to install system dependencies.' >&2; exit 1; }
if ! command -v apt-get >/dev/null 2>&1 || ! command -v apt-cache >/dev/null 2>&1; then
  echo 'Install Python 3, nftables, iproute2, shadow account tools, nologin, GTK3, libcurl and json-glib with your distribution package manager, then run this installer again.' >&2
  exit 1
fi

# Debian/Ubuntu package names changed with the time64 transition. Select only
# a package actually provided by this machine's configured repositories.
# This installs distribution tools, not a second set of VPN engines.
apt-get update
select_package() {
  local candidate metadata
  for candidate in "$@"; do
    if metadata=$(apt-cache show "$candidate" 2>/dev/null) && [[ $'\n'"$metadata" == *$'\n'"Package: $candidate"$'\n'* || $'\n'"$metadata" == *$'\n'"Package: $candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  echo "No compatible runtime package is available: $*" >&2
  return 1
}
gtk=$(select_package libgtk-3-0t64 libgtk-3-0)
curl=$(select_package libcurl4t64 libcurl4)
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  python3 nftables iproute2 passwd util-linux libc-bin "$gtk" "$curl" libjson-glib-1.0-0
check_tools
if (( ${#missing[@]} != 0 )); then
  printf 'Linux runtime dependency remains unavailable: %s\n' "${missing[@]}" >&2
  echo 'Application files and linked node state have not been replaced.' >&2
  exit 1
fi
echo 'Linux runtime system tools and native GUI libraries are available.'
