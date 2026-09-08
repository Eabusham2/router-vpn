#!/usr/bin/env bash
set -euo pipefail
ARCHIVE=$(realpath "${1:?usage: test-linux-rendered-layout.sh NATIVE_PACKAGE.tar.gz}")
for tool in python3 xvfb-run timeout curl; do
  command -v "$tool" >/dev/null || { echo "Rendered Linux layout test needs $tool (install xvfb and xauth)." >&2; exit 2; }
done
# A test must not attach to or stop an unrelated local Router VPN controller.
if curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:8788/api/status >/dev/null 2>&1; then
  echo 'Rendered layout test requires an isolated runner with port 8788 unused.' >&2
  exit 2
fi
WORK=$(mktemp -d "${TMPDIR:-/tmp}/router-vpn-layout.XXXXXX")
trap 'rm -rf -- "$WORK"' EXIT
PACKAGE=$(python3 - "$ARCHIVE" "$WORK" <<'PY'
import json, sys, tarfile
from pathlib import Path, PurePosixPath
archive, work = Path(sys.argv[1]), Path(sys.argv[2])
with tarfile.open(archive, 'r:gz') as stream:
    members = stream.getmembers()
    if len(members) > 6000 or sum(m.size for m in members) > 512 * 1024 * 1024:
        raise SystemExit('native package exceeds test extraction bounds')
    roots = set()
    for member in members:
        name = PurePosixPath(member.name)
        if name.is_absolute() or '..' in name.parts or not name.parts or not (member.isfile() or member.isdir()):
            raise SystemExit('unsafe native package member')
        roots.add(name.parts[0])
    if len(roots) != 1 or not roots.issubset({'RouterVPN-linux-amd64', 'RouterVPN-linux-arm64'}):
        raise SystemExit('unexpected native package root')
    stream.extractall(work, members=members, filter='data')
root = work / roots.pop()
if json.loads((root / 'routers.json').read_text()).get('profiles') != []:
    raise SystemExit('rendered layout test refuses a package with linked private nodes')
print(root)
PY
)
mkdir -m 700 "$WORK/home"
env HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home/config" XDG_CACHE_HOME="$WORK/home/cache" \
  HOMEVPN_ROOT="$PACKAGE" GSETTINGS_BACKEND=memory NO_AT_BRIDGE=1 \
  timeout 60s xvfb-run -a --server-args='-screen 0 1440x1050x24 -nolisten tcp' \
  "$PACKAGE/router-vpn-app" --layout-self-test
if curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:8788/api/status >/dev/null 2>&1; then
  echo 'Rendered layout test left its controller running.' >&2
  exit 1
fi
echo 'Linux shipping GTK rendered layout acceptance: PASS'
