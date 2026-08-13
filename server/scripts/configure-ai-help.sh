#!/bin/sh
set -eu

CONFIG_DIR=${ROUTER_VPN_CONFIG_DIR:-/opt/router-vpn/config}
MODEL_FILE="$CONFIG_DIR/openai-model"
KEY_FILE="$CONFIG_DIR/openai-api.key"

usage() {
  cat <<'EOF'
Usage:
  configure-ai-help.sh configure [MODEL]
  configure-ai-help.sh status
  configure-ai-help.sh disable

Run this locally on the Router VPN host. The API key is read with terminal echo
disabled and written mode 0600; it is never printed or passed as a command-line
argument. Setup Center only reports whether AI Help is configured.
EOF
}

ensure_private_dir() {
  mkdir -p "$CONFIG_DIR"
  chmod 700 "$CONFIG_DIR" 2>/dev/null || true
}

case "${1:-}" in
  configure)
    ensure_private_dir
    MODEL=${2:-}
    if [ -z "$MODEL" ]; then
      printf 'OpenAI model name: ' >&2
      IFS= read -r MODEL
    fi
    case "$MODEL" in
      ''|*[!A-Za-z0-9._:-]*) echo 'Invalid model name.' >&2; exit 2 ;;
    esac
    if [ "${#MODEL}" -gt 128 ]; then echo 'Model name is too long.' >&2; exit 2; fi

    if [ ! -t 0 ]; then
      echo 'Refusing to read an API key from non-interactive stdin.' >&2
      exit 2
    fi
    printf 'OpenAI API key (hidden): ' >&2
    old_stty=$(stty -g)
    trap 'stty "$old_stty" 2>/dev/null || true' EXIT HUP INT TERM
    stty -echo
    IFS= read -r KEY
    stty "$old_stty"
    trap - EXIT HUP INT TERM
    printf '\n' >&2
    case "$KEY" in
      ''|*[[:space:]]*) echo 'Invalid API key.' >&2; unset KEY; exit 2 ;;
    esac
    if [ "${#KEY}" -lt 20 ] || [ "${#KEY}" -gt 512 ]; then
      echo 'API key length is invalid.' >&2
      unset KEY
      exit 2
    fi

    umask 077
    model_tmp=$(mktemp "$CONFIG_DIR/.openai-model.XXXXXX")
    key_tmp=$(mktemp "$CONFIG_DIR/.openai-key.XXXXXX")
    trap 'rm -f "$model_tmp" "$key_tmp"' EXIT HUP INT TERM
    printf '%s\n' "$MODEL" >"$model_tmp"
    printf '%s\n' "$KEY" >"$key_tmp"
    unset KEY
    chmod 600 "$model_tmp" "$key_tmp"
    mv -f "$model_tmp" "$MODEL_FILE"
    mv -f "$key_tmp" "$KEY_FILE"
    trap - EXIT HUP INT TERM
    echo "AI Help configured for model: $MODEL"
    echo 'Restart/recreate only the Setup Center container/process if it is already running.'
    ;;
  status)
    if [ -r "$MODEL_FILE" ] && [ -r "$KEY_FILE" ]; then
      model=$(sed -n '1p' "$MODEL_FILE" 2>/dev/null || true)
      echo "AI Help configuration files present. Model: ${model:-unknown}"
      echo 'API key: present (not displayed)'
    else
      echo 'AI Help is not configured.'
      exit 1
    fi
    ;;
  disable)
    rm -f "$MODEL_FILE" "$KEY_FILE"
    echo 'AI Help disabled; private provider configuration removed.'
    ;;
  *) usage; exit 2 ;;
esac
