#!/usr/bin/env bash
# Shared functions for Blindfold scripts.
# Source this file: source "$(dirname "$0")/lib.sh"

REGISTRY="${BLINDFOLD_REGISTRY:-$HOME/.claude/secrets-registry.json}"
SERVICE="claude-secrets"
ACCOUNT_PREFIX="claude-secret"
MIN_REDACT_LENGTH=4
# Default to login keychain. Set BLINDFOLD_KEYCHAIN to use a dedicated keychain.
BLINDFOLD_KEYCHAIN="${BLINDFOLD_KEYCHAIN:-}"
# Set BLINDFOLD_EGRESS=proxy to let sandboxed commands reach the network only
# through the local proxy (macOS only, experimental).
BLINDFOLD_EGRESS="${BLINDFOLD_EGRESS:-}"

# Callers that already know this directory can set _SV_LIB_DIR first and skip the lookup
_SV_LIB_DIR="${_SV_LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
INSTALL_DIR="${_SV_LIB_DIR%/scripts}"
PROXY_BIN="${BLINDFOLD_PROXY_BIN:-${_SV_LIB_DIR}/../bin/blindfold-proxy}"
# Config the agent must not change: the policy and the proxy's run files
CONFIG_DIR="${BLINDFOLD_CONFIG_DIR:-$HOME/.config/blindfold}"
POLICY_FILE="${BLINDFOLD_POLICY:-${CONFIG_DIR}/policy.toml}"
PROXY_PORT_FILE="${BLINDFOLD_PROXY_PORT_FILE:-${CONFIG_DIR}/run/proxy.port}"
CA_BUNDLE="${PROXY_PORT_FILE%/*}/ca-bundle.pem"
EGRESS_LOG="${BLINDFOLD_EGRESS_LOG:-$HOME/.local/state/blindfold/egress.jsonl}"

# Cached values (computed once per script execution)
_SV_BACKEND=""
_SV_PROJECT_PATH=""
_SV_PLATFORM=""

# Returns the keychain path arg for security commands, or empty if using login keychain.
_keychain_arg() {
  [[ -n "$BLINDFOLD_KEYCHAIN" ]] && echo "$BLINDFOLD_KEYCHAIN" || true
}

ensure_keychain() {
  # If using a dedicated keychain, create it if needed (macOS only).
  # If BLINDFOLD_KEYCHAIN is unset, the login keychain is used and no setup is needed.
  [[ "$(get_platform)" == "Darwin" ]] || return 0
  [[ -n "$BLINDFOLD_KEYCHAIN" ]] || return 0
  if [[ ! -f "$BLINDFOLD_KEYCHAIN" ]]; then
    security create-keychain -p "" "$BLINDFOLD_KEYCHAIN" 2>/dev/null
    # No auto-lock timeout
    security set-keychain-settings "$BLINDFOLD_KEYCHAIN" 2>/dev/null
  fi
  # Ensure unlocked (idempotent)
  security unlock-keychain -p "" "$BLINDFOLD_KEYCHAIN" 2>/dev/null
}

get_platform() {
  if [[ -z "$_SV_PLATFORM" ]]; then
    _SV_PLATFORM="$(uname -s)"
  fi
  echo "$_SV_PLATFORM"
}

has_sandbox() {
  case "$(get_platform)" in
    Darwin) command -v sandbox-exec &>/dev/null ;;
    Linux) command -v bwrap &>/dev/null ;;
    *) return 1 ;;
  esac
}

egress_enabled() {
  [[ "$BLINDFOLD_EGRESS" == "proxy" && "$OSTYPE" == darwin* ]]
}

# Sets PROXY_PORT to a running proxy, starting one first if needed. A running
# proxy is reused only if it wrote its CA bundle and the binary hasn't been
# rebuilt since it started, so an upgrade never leaves an old proxy serving.
# The wait is capped at 2s so a slow start fails cleanly inside the hook's 5s
# timeout.
ensure_proxy() {
  local i pid_file="${PROXY_PORT_FILE%.port}.pid" old_pid=""
  PROXY_PORT=""
  read -r PROXY_PORT <"$PROXY_PORT_FILE" 2>/dev/null
  if [[ -n "$PROXY_PORT" && -f "$CA_BUNDLE" && ! "$PROXY_BIN" -nt "$PROXY_PORT_FILE" ]] &&
    { true <>"/dev/tcp/127.0.0.1/${PROXY_PORT}"; } 2>/dev/null; then
    return 0
  fi
  [[ -x "$PROXY_BIN" ]] || return 1

  read -r old_pid <"$pid_file" 2>/dev/null
  [[ "$old_pid" =~ ^[0-9]+$ ]] && kill "$old_pid" 2>/dev/null
  mkdir -p -m 700 "$(dirname "$PROXY_PORT_FILE")"
  rm -f "$PROXY_PORT_FILE"
  local args=(--port-file "$PROXY_PORT_FILE" --log "$EGRESS_LOG" --policy "$POLICY_FILE" --ca-bundle "$CA_BUNDLE")
  [[ -n "$BLINDFOLD_KEYCHAIN" ]] && args+=(--keychain "$BLINDFOLD_KEYCHAIN")
  nohup "$PROXY_BIN" "${args[@]}" </dev/null >/dev/null 2>&1 &
  echo "$!" >"$pid_file"
  for ((i = 0; i < 100; i++)); do
    if [[ -s "$PROXY_PORT_FILE" ]]; then
      read -r PROXY_PORT <"$PROXY_PORT_FILE"
      return 0
    fi
    sleep 0.02
  done
  return 1
}

# Sets SANDBOX_ARGV to the words that run a command sandboxed, or to nothing
# where there is no sandbox. The guard and run_sandboxed both use it, so the
# choice of profile and proxy lives in one place. Fails when egress lockdown is
# on but can't be set up, so callers refuse rather than run unprotected.
build_sandbox_argv() {
  SANDBOX_ARGV=()
  [[ "$OSTYPE" == darwin* ]] && command -v sandbox-exec &>/dev/null || return 0

  if egress_enabled; then
    local profile="${_SV_LIB_DIR}/sandbox-egress.sb" names name var
    [[ -f "$profile" && -x "$PROXY_BIN" ]] || return 1
    if ! names=$("$PROXY_BIN" -print-secrets -policy "$POLICY_FILE" 2>&1); then
      EGRESS_SETUP_ERROR="The Blindfold policy is not valid. ${names}"
      EGRESS_SETUP_HINT="Fix it in your own editor, outside the agent."
      return 1
    fi
    ensure_proxy || return 1

    local url="http://127.0.0.1:${PROXY_PORT}" local_hosts="localhost,127.0.0.1,::1"
    SANDBOX_ARGV=(env "HTTPS_PROXY=$url" "https_proxy=$url" "HTTP_PROXY=$url" "http_proxy=$url"
      "ALL_PROXY=$url" "all_proxy=$url" "NO_PROXY=$local_hosts" "no_proxy=$local_hosts")
    if [[ -n "$names" ]]; then
      # Trust the local CA, inside the sandbox only, so the proxy can open
      # TLS to policy hosts
      for var in SSL_CERT_FILE CURL_CA_BUNDLE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO PIP_CERT; do
        SANDBOX_ARGV+=("${var}=${CA_BUNDLE}")
      done
      # Tools that read their token from the environment send the
      # placeholder, and the proxy fills it in for the right host
      while IFS= read -r name; do
        SANDBOX_ARGV+=("${name}={{${name}}}")
      done <<<"$names"
    fi
    SANDBOX_ARGV+=(sandbox-exec -D "CONFIG_DIR=$(real_dir "$CONFIG_DIR")" -D "INSTALL_DIR=$(real_dir "$INSTALL_DIR")"
      -f "$profile")
  elif [[ -f "${_SV_LIB_DIR}/sandbox.sb" ]]; then
    SANDBOX_ARGV=(sandbox-exec -f "${_SV_LIB_DIR}/sandbox.sb")
  fi
}

# Prints the real path of a directory, creating it first, since Seatbelt
# matches resolved paths and the profile needs one that exists
real_dir() {
  mkdir -p "$1" 2>/dev/null
  (cd "$1" 2>/dev/null && pwd -P)
}

# True when path, once symlinks and .. are resolved, is inside CONFIG_DIR or
# INSTALL_DIR. The agent's file tools go through this, since they run outside
# the sandbox.
is_protected_path() {
  local path="$1" rest="" dir hops
  # Follow a symlink at the end, a few hops at most
  for ((hops = 0; hops < 8; hops++)); do
    [[ -L "$path" ]] || break
    local target
    target=$(readlink "$path")
    [[ "$target" == /* ]] && path="$target" || path="$(dirname "$path")/${target}"
  done
  # Resolve the deepest part that exists. A .. in the part that doesn't exist
  # yet can't be resolved here, so treat it as protected rather than guess.
  dir="$path"
  while [[ -n "$dir" && ! -d "$dir" ]]; do
    rest="/$(basename "$dir")${rest}"
    dir=$(dirname "$dir")
  done
  [[ "$rest" == */../* || "$rest" == */.. ]] && return 0
  # A hard link made from inside the sandbox would let a file tool write a
  # protected file under another name, so refuse files with more than one
  if [[ -f "$path" ]]; then
    local links
    links=$(stat -f %l "$path" 2>/dev/null || stat -c %h "$path" 2>/dev/null)
    [[ "${links:-1}" -gt 1 ]] && return 0
  fi
  local real
  real="$(cd "$dir" 2>/dev/null && pwd -P)${rest}"
  local protected
  for protected in "$(real_dir "$CONFIG_DIR")" "$(real_dir "$INSTALL_DIR")"; do
    [[ "$real" == "$protected" || "$real" == "$protected"/* ]] && return 0
  done
  return 1
}

EGRESS_SETUP_ERROR="Egress lockdown is on, but the proxy did not start."
EGRESS_SETUP_HINT="Build it with scripts/build-proxy.sh in your own terminal, or unset BLINDFOLD_EGRESS."

run_sandboxed() {
  build_sandbox_argv || { echo "ERROR: ${EGRESS_SETUP_ERROR} ${EGRESS_SETUP_HINT}" >&2; return 1; }
  # The +-form keeps an empty array from tripping set -u on bash 3.2
  ${SANDBOX_ARGV[@]+"${SANDBOX_ARGV[@]}"} "$@"
}

check_dependencies() {
  if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required but not installed." >&2
    echo "  macOS: brew install jq" >&2
    echo "  Linux: sudo apt install jq / sudo yum install jq" >&2
    exit 1
  fi
}

detect_backend() {
  if [[ -n "$_SV_BACKEND" ]]; then
    echo "$_SV_BACKEND"
    return
  fi
  case "$(uname -s)" in
    Darwin) _SV_BACKEND="keychain" ;;
    Linux)
      if command -v secret-tool &>/dev/null; then _SV_BACKEND="secret-tool"
      elif command -v gpg &>/dev/null; then _SV_BACKEND="gpg"
      else _SV_BACKEND="none"; fi ;;
    MINGW*|MSYS*|CYGWIN*) _SV_BACKEND="wincred" ;;
    *) _SV_BACKEND="none" ;;
  esac
  echo "$_SV_BACKEND"
}

get_project_path() {
  if [[ -n "$_SV_PROJECT_PATH" ]]; then
    echo "$_SV_PROJECT_PATH"
    return
  fi
  _SV_PROJECT_PATH=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
  echo "$_SV_PROJECT_PATH"
}

make_account_key() {
  local scope="$1" name="$2"
  echo "${ACCOUNT_PREFIX}:${scope}:${name}"
}

resolve_scope() {
  local scope_arg="${1:-global}"
  if [[ "$scope_arg" == "project" ]]; then
    get_project_path
  else
    echo "global"
  fi
}


get_secret() {
  local account="$1"
  local backend
  backend=$(detect_backend)

  case "$backend" in
    keychain)
      ensure_keychain
      security find-generic-password -a "$account" -s "$SERVICE" -w $(_keychain_arg) 2>/dev/null
      ;;
    secret-tool)
      secret-tool lookup service "$SERVICE" account "$account" 2>/dev/null
      ;;
    gpg)
      local gpg_file="$HOME/.claude/vault/$(echo "$account" | tr '/:' '__').gpg"
      [[ -f "$gpg_file" ]] && gpg --batch --yes -d "$gpg_file" 2>/dev/null
      ;;
    wincred)
      powershell.exe -NoProfile -Command "
        \$cred = Get-StoredCredential -Target '${account}' 2>\$null
        if (\$cred) { \$cred.GetNetworkCredential().Password }
      " 2>/dev/null | tr -d '\r'
      ;;
    none)
      echo "ERROR: No secret backend available. Install one of: secret-tool, gpg" >&2
      return 1
      ;;
    *) echo "" ;;
  esac
}

store_secret() {
  local account="$1" value="$2"
  local backend
  backend=$(detect_backend)

  case "$backend" in
    keychain)
      ensure_keychain
      # Note: -w passes the value as a CLI arg, briefly visible in ps. macOS security
      # command does not support stdin for -w. The exposure window is very short.
      security add-generic-password -a "$account" -s "$SERVICE" -U -w "$value" $(_keychain_arg) 2>/dev/null ||
      security add-generic-password -a "$account" -s "$SERVICE" -w "$value" $(_keychain_arg) 2>/dev/null
      ;;
    secret-tool)
      echo -n "$value" | secret-tool store --label="$account" service "$SERVICE" account "$account" 2>/dev/null
      ;;
    gpg)
      local vault_dir="$HOME/.claude/vault"
      mkdir -p "$vault_dir" && chmod 700 "$vault_dir"
      echo -n "$value" | gpg --batch --yes --symmetric --cipher-algo AES256 \
        -o "$vault_dir/$(echo "$account" | tr '/:' '__').gpg" 2>/dev/null
      ;;
    wincred)
      cmdkey "/add:${account}" "/user:${SERVICE}" "/pass:${value}" >/dev/null 2>&1
      ;;
    none)
      echo "ERROR: No secret backend available. Cannot store secret." >&2
      echo "Install one of: secret-tool (Linux), gpg" >&2
      return 1
      ;;
  esac
}

delete_secret() {
  local account="$1"
  local backend
  backend=$(detect_backend)

  case "$backend" in
    keychain) ensure_keychain; security delete-generic-password -a "$account" -s "$SERVICE" $(_keychain_arg) >/dev/null 2>&1 || true ;;
    secret-tool) secret-tool clear service "$SERVICE" account "$account" 2>/dev/null || true ;;
    gpg) rm -f "$HOME/.claude/vault/$(echo "$account" | tr '/:' '__').gpg" 2>/dev/null || true ;;
    wincred) cmdkey "/delete:${account}" >/dev/null 2>&1 || true ;;
  esac
}

secret_exists() {
  local account="$1"
  local backend
  backend=$(detect_backend)

  case "$backend" in
    keychain) ensure_keychain; security find-generic-password -a "$account" -s "$SERVICE" $(_keychain_arg) >/dev/null 2>&1 ;;
    secret-tool) secret-tool lookup service "$SERVICE" account "$account" >/dev/null 2>&1 ;;
    gpg) [[ -f "$HOME/.claude/vault/$(echo "$account" | tr '/:' '__').gpg" ]] ;;
    wincred) cmdkey "/list:${account}" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

has_gui() {
  case "$(uname -s)" in
    Darwin) [[ -n "${DISPLAY:-}" ]] || system_profiler SPDisplaysDataType &>/dev/null ;;
    Linux) [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]] ;;
    *) return 1 ;;
  esac
}

prompt_terminal() {
  local safe_name="$1"
  if [[ -t 0 ]] || [[ -e /dev/tty ]]; then
    read -rsp "Enter value for ${safe_name}: " value </dev/tty
    echo >&2
    echo "$value"
  else
    echo "ERROR: No GUI or terminal available for secure input." >&2
    echo "Store the secret manually. Run:" >&2
    echo "  bash ${CLAUDE_SKILL_DIR:-~/.claude/skills/blindfold}/scripts/secret-store.sh --scope global ${safe_name}" >&2
    return 1
  fi
}

prompt_secret_dialog() {
  local name="$1"
  local backend
  backend=$(detect_backend)

  local safe_name="${name//[^A-Za-z0-9_]/}"

  # If no GUI is available (SSH, Remote Control, headless), always use terminal prompt
  if ! has_gui; then
    prompt_terminal "$safe_name"
    return
  fi

  case "$backend" in
    keychain)
      osascript -e "
        set dialogResult to display dialog \"Enter value for ${safe_name}:\" default answer \"\" with hidden answer with title \"Blindfold\" with icon caution buttons {\"Cancel\", \"Store\"} default button \"Store\"
        return text returned of dialogResult
      " 2>/dev/null || prompt_terminal "$safe_name"
      ;;
    secret-tool)
      if command -v zenity &>/dev/null; then
        zenity --password --title="Blindfold" --text="Enter value for ${safe_name}:" 2>/dev/null || prompt_terminal "$safe_name"
      elif command -v kdialog &>/dev/null; then
        kdialog --password "Enter value for ${safe_name}:" --title "Blindfold" 2>/dev/null || prompt_terminal "$safe_name"
      else
        prompt_terminal "$safe_name"
      fi
      ;;
    gpg|none)
      prompt_terminal "$safe_name"
      ;;
    wincred)
      powershell.exe -Command "
        \$cred = Get-Credential -Message 'Enter value for ${safe_name}' -UserName '${safe_name}'
        \$cred.GetNetworkCredential().Password
      " 2>/dev/null | tr -d '\r' || prompt_terminal "$safe_name"
      ;;
  esac
}

ensure_registry() {
  if [[ ! -f "$REGISTRY" ]]; then
    echo '{"version":3,"global":{"secrets":[]},"projects":{}}' > "$REGISTRY"
    chmod 600 "$REGISTRY"
  fi
}

# Atomic registry update: write to temp, validate, then mv
update_registry() {
  local jq_filter="$1"
  local tmp
  tmp=$(mktemp "${REGISTRY}.XXXXXX")
  if jq "$jq_filter" "$REGISTRY" > "$tmp" 2>/dev/null && jq empty "$tmp" 2>/dev/null; then
    mv "$tmp" "$REGISTRY"
  else
    rm -f "$tmp"
    echo "ERROR: Registry update failed. File unchanged." >&2
    return 1
  fi
}

add_to_registry() {
  local scope="$1" name="$2"
  ensure_registry

  if [[ "$scope" == "global" ]]; then
    update_registry "$(printf '.global.secrets |= if index("%s") then . else . + ["%s"] end' "$name" "$name")"
  else
    update_registry "$(printf 'if .projects["%s"] == null then .projects["%s"] = {"secrets": ["%s"]} elif (.projects["%s"].secrets | index("%s")) then . else .projects["%s"].secrets += ["%s"] end' "$scope" "$scope" "$name" "$scope" "$name" "$scope" "$name")"
  fi
}

# Every registered secret name, global and project, once each
registered_secret_names() {
  [[ -f "$REGISTRY" ]] || return 0
  jq -r '[.global.secrets[]?] + [.projects | to_entries[]? | .value.secrets[]?] | unique | .[]' "$REGISTRY" 2>/dev/null
}

# "scope<TAB>name" for each secret this project can resolve: its own, then global
registered_secret_scopes() {
  [[ -f "$REGISTRY" ]] || return 0
  jq -r --arg p "$(get_project_path)" \
    '(.projects[$p].secrets[]? | "\($p)\t\(.)"), (.global.secrets[]? | "global\t\(.)")' \
    "$REGISTRY" 2>/dev/null
}

parse_scope_arg() {
  local arg="${1:-global}"
  if [[ "$arg" == "project" ]]; then
    get_project_path
  else
    echo "global"
  fi
}

# Create a temp file with secure permissions
secure_mktemp() {
  local tmp
  tmp=$(mktemp)
  chmod 600 "$tmp"
  echo "$tmp"
}

