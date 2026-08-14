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
disabled and written mode 0600; keys are never printed or passed as command-line
arguments. The local provider points at a loopback/private OpenAI-compatible
endpoint and may use an empty API key.
EOF
}

ensure_private_dir() {
  mkdir -p "$CONFIG_DIR"
  chmod 700 "$CONFIG_DIR" 2>/dev/null || true
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

write_private() {
  target=$1
  value=$2
  label=$3
  umask 077
  tmp=$(mktemp "$CONFIG_DIR/.${label}.XXXXXX")
  trap 'rm -f "$tmp"' EXIT HUP INT TERM
  printf '%s\n' "$value" >"$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$target"
  trap - EXIT HUP INT TERM
}

read_hidden() {
  prompt=$1
  printf '%s' "$prompt" >&2
  old_stty=$(stty -g)
  trap 'stty "$old_stty" 2>/dev/null || true' EXIT HUP INT TERM
  stty -echo
  IFS= read -r REPLY
  stty "$old_stty"
  trap - EXIT HUP INT TERM
  printf '\n' >&2
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
    write_private "$PROVIDER_FILE" "$PROVIDER" ai-provider
    write_private "$MODEL_FILE" "$MODEL" ai-model
    write_private "$WEB_FILE" "$WEB" ai-web
    if [ -n "$BASE" ]; then write_private "$BASE_FILE" "$BASE" ai-base-url; else rm -f "$BASE_FILE"; fi
    if [ -n "$KEY" ]; then write_private "$KEY_FILE" "$KEY" ai-key; else rm -f "$KEY_FILE"; fi
    unset KEY
    # Once provider-neutral files are committed, stale legacy OpenAI credentials
    # must not silently override the selected provider.
    rm -f "$LEGACY_MODEL_FILE" "$LEGACY_KEY_FILE"
    echo "AI Help configured: provider=$PROVIDER model=$MODEL web=$WEB"
    [ -z "$BASE" ] || echo 'Local endpoint: configured (private file)'
    echo 'Restart/recreate only the Setup Center container/process if it is already running.'
    ;;
  web)
    ensure_private_dir
    case "${2:-}" in on|off) write_private "$WEB_FILE" "$2" ai-web; echo "AI Help web access: $2" ;; *) echo 'Use: configure-ai-help.sh web on|off' >&2; exit 2 ;; esac
    ;;
  status)
    provider=$(sed -n '1p' "$PROVIDER_FILE" 2>/dev/null || true)
    model=$(sed -n '1p' "$MODEL_FILE" 2>/dev/null || true)
    if [ -z "$provider" ] && [ -r "$LEGACY_MODEL_FILE" ]; then provider=openai; model=$(sed -n '1p' "$LEGACY_MODEL_FILE" 2>/dev/null || true); fi
    if [ -n "$provider" ] && [ -n "$model" ]; then
      echo "AI Help provider: $provider"
      echo "Model: $model"
      if [ "$provider" = local ]; then
        [ -r "$BASE_FILE" ] && echo 'Local base URL: present (not displayed)' || echo 'Local base URL: missing'
        [ -r "$KEY_FILE" ] && echo 'API key: present (not displayed)' || echo 'API key: not set (allowed for local)'
      else
        if [ -r "$KEY_FILE" ] || { [ "$provider" = openai ] && [ -r "$LEGACY_KEY_FILE" ]; }; then echo 'API key: present (not displayed)'; else echo 'API key: missing'; fi
      fi
      web=$(sed -n '1p' "$WEB_FILE" 2>/dev/null || true)
      echo "Web access: ${web:-provider default}"
    else
      echo 'AI Help is not configured.'
      exit 1
    fi
    ;;
  disable)
    rm -f "$PROVIDER_FILE" "$MODEL_FILE" "$KEY_FILE" "$BASE_FILE" "$WEB_FILE" "$LEGACY_MODEL_FILE" "$LEGACY_KEY_FILE"
    echo 'AI Help disabled; private provider configuration removed.'
    ;;
  *) usage; exit 2 ;;
esac
