#!/usr/bin/env bash
# Shared functions for Blindfold scripts.
# Source this file: source "$(dirname "$0")/lib.sh"

REGISTRY="${BLINDFOLD_REGISTRY:-$HOME/.claude/secrets-registry.json}"
SERVICE="claude-secrets"
ACCOUNT_PREFIX="claude-secret"
MIN_REDACT_LENGTH=4
# Default to login keychain. Set BLINDFOLD_KEYCHAIN to use a dedicated keychain.
BLINDFOLD_KEYCHAIN="${BLINDFOLD_KEYCHAIN:-}"

# Cached values (computed once per script execution)
_SV_BACKEND=""
_SV_PROJECT_PATH=""
_SV_SANDBOX_PROFILE=""
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

get_sandbox_profile() {
  if [[ -n "$_SV_SANDBOX_PROFILE" ]]; then
    echo "$_SV_SANDBOX_PROFILE"
    return
  fi
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  _SV_SANDBOX_PROFILE="${script_dir}/sandbox.sb"
  echo "$_SV_SANDBOX_PROFILE"
}

run_sandboxed() {
  local profile
  profile=$(get_sandbox_profile)
  if [[ "$(get_platform)" == "Darwin" && -f "$profile" ]] && command -v sandbox-exec &>/dev/null; then
    sandbox-exec -f "$profile" "$@"
  else
    "$@"
  fi
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

