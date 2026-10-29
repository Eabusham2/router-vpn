#!/bin/bash
set -euo pipefail

# Discovery never grants privileged authority. The native utility validates
# the selected executable and its complete installation before root execution.
routervpn_discover_install_python() {
  local candidate
  for candidate in "$@"; do
    [[ -x "$candidate" ]] || continue
    if "$candidate" -EsS -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  echo 'Install Python 3.9 or newer using the signed macOS installer from https://www.python.org/downloads/macos/ (or an existing Apple Command Line Tools installation), then run this installer again.' >&2
  return 1
}

[[ ${EUID:-$(/usr/bin/id -u)} -ne 0 ]] || { echo 'Run this installer from your normal Mac account; it requests administrator permission itself.' >&2; exit 1; }
[[ $(/usr/bin/uname -s) == Darwin ]] || { echo 'This installer requires macOS.' >&2; exit 1; }
PYTHON_CANDIDATES=(/Library/Developer/CommandLineTools/usr/bin/python3 /Library/Frameworks/Python.framework/Versions/3.*/bin/python3)
if [[ $# -eq 1 && $1 == --discover-python ]]; then
  routervpn_discover_install_python "${PYTHON_CANDIDATES[@]}"
  exit
fi
SOURCE=$(cd "${1:-.}" && pwd -P)
[[ -x "$SOURCE/router-vpn-client" && -d "$SOURCE/RouterVPN.app" && -f "$SOURCE/client/install-macos-native.py" ]] || { echo 'Use the complete extracted native macOS package.' >&2; exit 1; }

# Discovery is unprivileged. The native utility independently verifies the
# complete interpreter installation before executing it as root. A Homebrew
# path is never elevated merely because it was first on the user's PATH.
INSTALL_PYTHON=$(routervpn_discover_install_python "${PYTHON_CANDIDATES[@]}")
/usr/bin/sudo -- "$SOURCE/router-vpn-client" --install-macos-native "$SOURCE" "$INSTALL_PYTHON"

# The application alias is created as the desktop user, never through a root
# write into a user-controlled home directory. Privileged execution always
# resolves to the fixed protected controller, independently of this alias.
mkdir -p "$HOME/Applications"
APP_ALIAS="$HOME/Applications/RouterVPN.app"
if [[ ! -e "$APP_ALIAS" && ! -L "$APP_ALIAS" ]]; then
  ln -s /opt/router-vpn-client/RouterVPN.app "$APP_ALIAS"
elif [[ -L "$APP_ALIAS" && $(/usr/bin/readlink "$APP_ALIAS") == /opt/router-vpn-client/RouterVPN.app ]]; then
  :
else
  echo 'An existing application was preserved. Open /opt/router-vpn-client/RouterVPN.app for this installation.'
fi
echo 'Open RouterVPN.app in your Applications folder. Linked private nodes and settings remain in the protected installation.'
