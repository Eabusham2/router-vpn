#!/usr/bin/env bash
set -euo pipefail
TARGET=${1:?runner name}
shift
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
case "$TARGET" in
  run-mode.sh|run-combined.sh|run-max.sh|run-xhttp.sh|run-all.sh) ;;
  *) echo "refusing unapproved platform runner: $TARGET" >&2; exit 2 ;;
esac
SOURCE="$SCRIPT_DIR/$TARGET"
[[ -f "$SOURCE" && ! -L "$SOURCE" ]] || { echo "platform runner source is missing or unsafe: $TARGET" >&2; exit 2; }

if [[ $(uname -s) != Darwin ]]; then
  exec bash "$SOURCE" "$@"
fi

RUN="$ROOT/run"
mkdir -p "$RUN"
TMP=$(mktemp "$RUN/platform-runner.XXXXXX")
chmod 700 "$TMP"
cleanup(){ rm -f "$TMP"; }
trap cleanup EXIT INT TERM
python3 - "$SOURCE" "$TMP" "$SCRIPT_DIR" <<'PY'
from pathlib import Path
import sys
src=Path(sys.argv[1]);dst=Path(sys.argv[2]);script_dir=sys.argv[3]
text=src.read_text(encoding='utf-8')
lines=[]
replaced_dir=False
for line in text.splitlines():
    if not replaced_dir and line.startswith('SCRIPT_DIR='):
        lines.append("SCRIPT_DIR="+repr(script_dir));replaced_dir=True
    elif not replaced_dir and ';SCRIPT_DIR=' in line:
        before=line.split(';SCRIPT_DIR=',1)[0];rest=line.split(';SCRIPT_DIR=',1)[1];after=''
        if ';' in rest:
            _assignment,after=rest.split(';',1)
        lines.append(before+";SCRIPT_DIR="+repr(script_dir)+((';'+after) if after else ''));replaced_dir=True
    else:
        lines.append(line)
text='\n'.join(lines)+'\n'
if not replaced_dir:
    raise SystemExit('platform runner could not anchor SCRIPT_DIR safely')
old='python3 "$SCRIPT_DIR/mtu-policy.py"'
new='python3 "$SCRIPT_DIR/mtu-policy-platform.py"'
if old in text:
    text=text.replace(old,new)
elif src.name!='run-all.sh':
    raise SystemExit('approved runner no longer contains expected MTU policy call')
# Nested mode launches on Darwin must return through the allowlisted platform
# transformer so no branch can accidentally call the Linux-only kill switch.
text=text.replace('exec bash "$SCRIPT_DIR/run-xhttp.sh"','exec bash "$SCRIPT_DIR/run-platform.sh" run-xhttp.sh')
text=text.replace('exec bash "$SCRIPT_DIR/run-max.sh" "$MODE"','exec bash "$SCRIPT_DIR/run-platform.sh" run-max.sh "$MODE"')
text=text.replace('bash "$SCRIPT_DIR/run-max.sh" "$candidate"','bash "$SCRIPT_DIR/run-platform.sh" run-max.sh "$candidate"')
text=text.replace('bash "$SCRIPT_DIR/stop-mode.sh"','bash "$SCRIPT_DIR/stop-mode-platform.sh"')
dst.write_text(text,encoding='utf-8')
PY
exec bash "$TMP" "$@"
