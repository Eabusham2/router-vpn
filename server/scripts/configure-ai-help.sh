#!/bin/sh
set -eu

CONFIG_DIR=${ROUTER_VPN_CONFIG_DIR:-/opt/router-vpn/config}
PROVIDER_FILE="$CONFIG_DIR/ai-provider"
MODEL_FILE="$CONFIG_DIR/ai-model"
KEY_FILE="$CONFIG_DIR/ai-api.key"
BASE_FILE="$CONFIG_DIR/ai-base-url"
WEB_FILE="$CONFIG_DIR/ai-web-access"
LEGACY_MODEL_FILE="$CONFIG_DIR/openai-model"
LEGACY_KEY_FILE="$CONFIG_DIR/openai-api.key"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PRIVATE_BATCH="$SCRIPT_DIR/atomic-private-batch.py"
VERIFIED_READ="$SCRIPT_DIR/verified-regular-read.py"

[ -f "$PRIVATE_BATCH" ] && [ ! -L "$PRIVATE_BATCH" ] || { echo 'Private state publisher is missing or unsafe.' >&2; exit 1; }
[ -f "$VERIFIED_READ" ] && [ ! -L "$VERIFIED_READ" ] || { echo 'Verified private-state reader is missing or unsafe.' >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo 'python3 is required.' >&2; exit 1; }

PROVIDER_TMP=''
MODEL_TMP=''
WEB_TMP=''
BASE_TMP=''
KEY_TMP=''
TTY_ECHO_OFF=0
OLD_STTY=''
KEY=''

cleanup() {
  if [ "$TTY_ECHO_OFF" -eq 1 ]; then
    stty "$OLD_STTY" 2>/dev/null || stty echo 2>/dev/null || true
    TTY_ECHO_OFF=0
  fi
  for tmp in "$PROVIDER_TMP" "$MODEL_TMP" "$WEB_TMP" "$BASE_TMP" "$KEY_TMP"; do
    [ -z "$tmp" ] || rm -f -- "$tmp"
  done
  unset KEY REPLY 2>/dev/null || true
}
signal_exit() {
  trap - HUP INT TERM
  cleanup
  exit 1
}
trap cleanup EXIT
trap signal_exit HUP INT TERM

usage() {
  cat <<'EOF'
Usage:
  configure-ai-help.sh configure [PROVIDER] [MODEL]
  configure-ai-help.sh web on|off
  configure-ai-help.sh status
  configure-ai-help.sh disable

PROVIDER: openai | gemini | anthropic | deepseek | xai | moonshot | local
Aliases accepted: claude, grok, kimi, google, aiboard.

Run this locally on the Router VPN host. API keys are read with terminal echo
disabled and committed as private mode-0600 state; keys are never printed or
passed as command-line arguments. Provider/model/web/base/key changes commit as
one transaction, including removal of stale credentials. The local provider
points at a loopback/private OpenAI-compatible endpoint and may use no API key.
EOF
}

ensure_private_dir() {
  python3 - "$PRIVATE_BATCH" "$PROVIDER_FILE" <<'PY'
from pathlib import Path
import os
import runpy
import sys
helper = runpy.run_path(sys.argv[1])
target = Path(sys.argv[2])
helper["ensure_private_parent"](target)
os.chmod(target.parent, 0o700)
PY
}

canonical_provider() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    openai) echo openai ;;
    gemini|google) echo gemini ;;
    anthropic|claude) echo anthropic ;;
    deepseek) echo deepseek ;;
    xai|grok) echo xai ;;
    moonshot|kimi) echo moonshot ;;
    local|aiboard|ai-board) echo local ;;
    *) return 1 ;;
  esac
}

read_hidden() {
  prompt=$1
  printf '%s' "$prompt" >&2
  OLD_STTY=$(stty -g)
  stty -echo
  TTY_ECHO_OFF=1
  if ! IFS= read -r REPLY; then
    stty "$OLD_STTY" 2>/dev/null || stty echo 2>/dev/null || true
    TTY_ECHO_OFF=0
    return 1
  fi
  stty "$OLD_STTY"
  TTY_ECHO_OFF=0
  printf '\n' >&2
}

read_private_line() {
  path=$1
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then
    return 0
  fi
  python3 - "$VERIFIED_READ" "$path" <<'PY'
from pathlib import Path
import runpy
import sys
helper = runpy.run_path(sys.argv[1])
body = helper["read_verified_regular"](Path(sys.argv[2]), 8192)
line = body.decode("utf-8", errors="strict").splitlines()[0]
if len(line) > 2048 or "\x00" in line:
    raise SystemExit("private configuration line is invalid/oversized")
print(line)
PY
}

private_present() {
  path=$1
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then
    return 1
  fi
  python3 "$VERIFIED_READ" "$path" >/dev/null
}

stage_value() {
  # The value is a shell-function argument only; external mktemp/chmod never see
  # the secret. Callers assign the returned random path to a cleanup variable.
  label=$1
  value=$2
  tmp=$(mktemp "$CONFIG_DIR/.$label.input.XXXXXX")
  printf '%s\n' "$value" >"$tmp"
  chmod 600 "$tmp"
  printf '%s' "$tmp"
}

commit_configuration() {
  # Provider/model/web are always present. Base/key are explicit upsert-or-delete
  # members of the same transaction, and legacy OpenAI state is retired in that
  # transaction as well so no crash can leave mixed generations.
  if [ -n "$BASE_TMP" ] && [ -n "$KEY_TMP" ]; then
    python3 "$PRIVATE_BATCH" \
      "$PROVIDER_FILE=$PROVIDER_TMP" "$MODEL_FILE=$MODEL_TMP" "$WEB_FILE=$WEB_TMP" \
      "$BASE_FILE=$BASE_TMP" "$KEY_FILE=$KEY_TMP" \
      --delete "$LEGACY_MODEL_FILE" --delete "$LEGACY_KEY_FILE"
  elif [ -n "$BASE_TMP" ]; then
    python3 "$PRIVATE_BATCH" \
      "$PROVIDER_FILE=$PROVIDER_TMP" "$MODEL_FILE=$MODEL_TMP" "$WEB_FILE=$WEB_TMP" \
      "$BASE_FILE=$BASE_TMP" \
      --delete "$KEY_FILE" --delete "$LEGACY_MODEL_FILE" --delete "$LEGACY_KEY_FILE"
  elif [ -n "$KEY_TMP" ]; then
    python3 "$PRIVATE_BATCH" \
      "$PROVIDER_FILE=$PROVIDER_TMP" "$MODEL_FILE=$MODEL_TMP" "$WEB_FILE=$WEB_TMP" \
      "$KEY_FILE=$KEY_TMP" \
      --delete "$BASE_FILE" --delete "$LEGACY_MODEL_FILE" --delete "$LEGACY_KEY_FILE"
  else
    python3 "$PRIVATE_BATCH" \
      "$PROVIDER_FILE=$PROVIDER_TMP" "$MODEL_FILE=$MODEL_TMP" "$WEB_FILE=$WEB_TMP" \
      --delete "$BASE_FILE" --delete "$KEY_FILE" \
      --delete "$LEGACY_MODEL_FILE" --delete "$LEGACY_KEY_FILE"
  fi
}

case "${1:-}" in
  configure)
    ensure_private_dir
    RAW_PROVIDER=${2:-}
    if [ -z "$RAW_PROVIDER" ]; then
      printf 'Provider (openai/gemini/anthropic/deepseek/xai/moonshot/local): ' >&2
      IFS= read -r RAW_PROVIDER
    fi
    PROVIDER=$(canonical_provider "$RAW_PROVIDER") || { echo 'Unsupported AI provider.' >&2; exit 2; }

    MODEL=${3:-}
    if [ -z "$MODEL" ]; then
      printf 'Model name: ' >&2
      IFS= read -r MODEL
    fi
    case "$MODEL" in
      ''|*[!A-Za-z0-9._:/-]*) echo 'Invalid model name.' >&2; exit 2 ;;
    esac
    if [ "${#MODEL}" -gt 192 ]; then echo 'Model name is too long.' >&2; exit 2; fi

    BASE=''
    if [ "$PROVIDER" = local ]; then
      printf 'Local AI base URL (example http://127.0.0.1:8000/v1): ' >&2
      IFS= read -r BASE
      case "$BASE" in
        http://*|https://*) ;;
        *) echo 'Local AI base URL must start with http:// or https://.' >&2; exit 2 ;;
      esac
    fi

    if [ ! -t 0 ]; then
      echo 'Refusing to read an API key from non-interactive stdin.' >&2
      exit 2
    fi
    if [ "$PROVIDER" = local ]; then
      read_hidden 'Optional local AI API key (hidden; Enter for none): '
    else
      read_hidden 'Provider API key (hidden): '
    fi
    KEY=$REPLY
    unset REPLY
    case "$KEY" in
      *[[:space:]]*) echo 'Invalid API key.' >&2; unset KEY; exit 2 ;;
    esac
    if [ "$PROVIDER" != local ] && { [ "${#KEY}" -lt 12 ] || [ "${#KEY}" -gt 1024 ]; }; then
      echo 'API key length is invalid.' >&2
      unset KEY
      exit 2
    fi
    if [ "$PROVIDER" = local ] && [ -n "$KEY" ] && { [ "${#KEY}" -lt 12 ] || [ "${#KEY}" -gt 1024 ]; }; then
      echo 'Optional local API key length is invalid.' >&2
      unset KEY
      exit 2
    fi

    case "$PROVIDER" in
      openai|gemini|anthropic|xai) WEB=on ;;
      *) WEB=off ;;
    esac

    umask 077
    PROVIDER_TMP=$(stage_value ai-provider "$PROVIDER")
    MODEL_TMP=$(stage_value ai-model "$MODEL")
    WEB_TMP=$(stage_value ai-web "$WEB")
    if [ -n "$BASE" ]; then BASE_TMP=$(stage_value ai-base-url "$BASE"); fi
    if [ -n "$KEY" ]; then KEY_TMP=$(stage_value ai-key "$KEY"); fi
    commit_configuration
    unset KEY

    echo "AI Help configured: provider=$PROVIDER model=$MODEL web=$WEB"
    [ -z "$BASE" ] || echo 'Local endpoint: configured (private file)'
    echo 'Restart/recreate only the Setup Center container/process if it is already running.'
    ;;
  web)
    ensure_private_dir
    case "${2:-}" in
      on|off)
        umask 077
        WEB_TMP=$(stage_value ai-web "$2")
        python3 "$PRIVATE_BATCH" "$WEB_FILE=$WEB_TMP"
        echo "AI Help web access: $2"
        ;;
      *) echo 'Use: configure-ai-help.sh web on|off' >&2; exit 2 ;;
    esac
    ;;
  status)
    provider=$(read_private_line "$PROVIDER_FILE")
    model=$(read_private_line "$MODEL_FILE")
    if [ -z "$provider" ] && { [ -e "$LEGACY_MODEL_FILE" ] || [ -L "$LEGACY_MODEL_FILE" ]; }; then
      provider=openai
      model=$(read_private_line "$LEGACY_MODEL_FILE")
    fi
    if [ -n "$provider" ] && [ -n "$model" ]; then
      echo "AI Help provider: $provider"
      echo "Model: $model"
      if [ "$provider" = local ]; then
        if private_present "$BASE_FILE"; then echo 'Local base URL: present (not displayed)'; else echo 'Local base URL: missing'; fi
        if private_present "$KEY_FILE"; then echo 'API key: present (not displayed)'; else echo 'API key: not set (allowed for local)'; fi
      else
        if private_present "$KEY_FILE" || { [ "$provider" = openai ] && private_present "$LEGACY_KEY_FILE"; }; then
          echo 'API key: present (not displayed)'
        else
          echo 'API key: missing'
        fi
      fi
      web=$(read_private_line "$WEB_FILE")
      echo "Web access: ${web:-provider default}"
    else
      echo 'AI Help is not configured.'
      exit 1
    fi
    ;;
  disable)
    ensure_private_dir
    python3 "$PRIVATE_BATCH" \
      --delete "$PROVIDER_FILE" --delete "$MODEL_FILE" --delete "$KEY_FILE" \
      --delete "$BASE_FILE" --delete "$WEB_FILE" \
      --delete "$LEGACY_MODEL_FILE" --delete "$LEGACY_KEY_FILE"
    echo 'AI Help disabled; private provider configuration removed transactionally.'
    ;;
  *) usage; exit 2 ;;
esac
