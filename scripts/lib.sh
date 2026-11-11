#!/usr/bin/env bash
# Shared functions for Blindfold scripts.
# Source this file: source "$(dirname "$0")/lib.sh"

REGISTRY="${BLINDFOLD_REGISTRY:-$HOME/.claude/secrets-registry.json}"
SERVICE="claude-secrets"
ACCOUNT_PREFIX="claude-secret"
MIN_REDACT_LENGTH=4
# Default to login keychain. Set BLINDFOLD_KEYCHAIN to use a dedicated keychain.
BLINDFOLD_KEYCHAIN="${BLINDFOLD_KEYCHAIN:-}"
# BLINDFOLD_EGRESS=proxy lets sandboxed commands reach the network only
# through the local proxy (macOS only, experimental). The settings file can
# turn it on too, and the environment can't turn off what the file turned on.
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
# What the running proxy loaded: "ok" or "error", the global secret names,
# then "@id NAME..." for each approved project in effect
POLICY_STATE="${PROXY_PORT_FILE%/*}/policy.state"
PROXY_PID_FILE="${PROXY_PORT_FILE%.port}.pid"
# Project tokens and approved project policies. Sandboxed commands can neither
# read nor write it.
PRIVATE_DIR="${CONFIG_DIR}/private"
PROJECT_POLICY_FILE=".blindfold.toml"
EGRESS_LOG="${BLINDFOLD_EGRESS_LOG:-$HOME/.local/state/blindfold/egress.jsonl}"
# One line per secret filled in, echoed back or refused
AUDIT_LOG="${BLINDFOLD_AUDIT_LOG:-${EGRESS_LOG%/*}/audit.jsonl}"
# Blindfold's own switches, as NAME=value lines. It sits in CONFIG_DIR, which
# the agent can't write under lockdown, so the agent can't turn them off.
SETTINGS_FILE="${CONFIG_DIR}/settings"
# Claude Code's config folder
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"

# Cached values (computed once per script execution)
_SV_BACKEND=""
_SV_PROJECT_PATH=""
_SV_PLATFORM=""
PROTECTED_DIRS=()
KEPT_FILES=()

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

# Sets PROXY_PORT to a running proxy, starting one first if needed. The proxy
# exits by itself when its binary is rebuilt, so a dead port means "start it".
# A proxy without a state file predates policies and is replaced too. The wait
# is capped at 2s so a slow start fails cleanly inside the hook's 5s timeout;
# build-proxy.sh launches a new binary once so its first start isn't slow.
ensure_proxy() {
  local i
  PROXY_PORT=""
  read -r PROXY_PORT 2>/dev/null <"$PROXY_PORT_FILE"
  if [[ -n "$PROXY_PORT" && -f "$POLICY_STATE" ]] &&
    { true <>"/dev/tcp/127.0.0.1/${PROXY_PORT}"; } 2>/dev/null; then
    return 0
  fi
  [[ -x "$PROXY_BIN" ]] || return 1

  mkdir -p -m 700 "$(dirname "$PROXY_PORT_FILE")"
  rm -f "$PROXY_PORT_FILE" "$POLICY_STATE"
  local args=(--port-file "$PROXY_PORT_FILE" --log "$EGRESS_LOG" --audit "$AUDIT_LOG" --policy "$POLICY_FILE"
    --state "$POLICY_STATE" --private "$PRIVATE_DIR" --ca-bundle "$CA_BUNDLE"
    --service "$SERVICE" --account-prefix "$ACCOUNT_PREFIX")
  [[ -n "$BLINDFOLD_KEYCHAIN" ]] && args+=(--keychain "$BLINDFOLD_KEYCHAIN")
  nohup "$PROXY_BIN" "${args[@]}" </dev/null >/dev/null 2>&1 &
  echo "$!" >"$PROXY_PID_FILE"
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
# where there is no sandbox, and POLICY_NAMES to the secrets the proxy fills
# in for this command. The guard and secret-exec.sh both use it, so the
# choice of profile and proxy lives in one place. Fails when egress lockdown is
# on but can't be set up, so callers refuse rather than run unprotected.
build_sandbox_argv() {
  SANDBOX_ARGV=() POLICY_NAMES=()
  if [[ -n "$SETTINGS_ERROR" ]]; then
    EGRESS_SETUP_ERROR="$SETTINGS_ERROR"
    EGRESS_SETUP_HINT="Fix it in your own editor, outside the agent. Each line is BLINDFOLD_EGRESS=proxy or BLINDFOLD_EXEC_ANY_SECRET=1."
    return 1
  fi
  [[ "$OSTYPE" == darwin* ]] && command -v sandbox-exec &>/dev/null || return 0

  if egress_enabled; then
    local profile="${_SV_LIB_DIR}/sandbox-egress.sb" name var
    [[ -f "$profile" ]] && ensure_proxy || return 1
    read_policy_state
    if [[ "$STATE_STATUS" == error ]]; then
      EGRESS_SETUP_ERROR="The Blindfold policy is not valid. ${STATE_DETAIL}"
      EGRESS_SETUP_HINT="Fix it in your own editor, outside the agent."
      return 1
    fi
    # Fill get_project_path's cache here, not in a $(...) subshell where it
    # would be lost, so git runs once per command
    get_project_path >/dev/null
    PROJECT_DIR=$(cd "$_SV_PROJECT_PATH" 2>/dev/null && pwd -P)
    check_project_policy || return 1
    POLICY_NAMES=(${STATE_NAMES[@]+"${STATE_NAMES[@]}"})
    for name in ${PROJECT_NAMES[@]+"${PROJECT_NAMES[@]}"}; do
      [[ " ${POLICY_NAMES[*]-} " == *" ${name} "* ]] || POLICY_NAMES+=("$name")
    done

    # A project's token, as the proxy password, tells the proxy which approved
    # project policy applies
    local url="http://127.0.0.1:${PROXY_PORT}" local_hosts="localhost,127.0.0.1,::1"
    [[ -n "$PROJECT_TOKEN" ]] && url="http://blindfold:${PROJECT_TOKEN}@127.0.0.1:${PROXY_PORT}"
    SANDBOX_ARGV=(env "HTTPS_PROXY=$url" "https_proxy=$url" "HTTP_PROXY=$url" "http_proxy=$url"
      "ALL_PROXY=$url" "all_proxy=$url" "NO_PROXY=$local_hosts" "no_proxy=$local_hosts")
    if [[ ${#POLICY_NAMES[@]} -gt 0 ]]; then
      # Trust the local CA, inside the sandbox only, so the proxy can open
      # TLS to policy hosts. proxy/policy.go reserves these names.
      for var in SSL_CERT_FILE CURL_CA_BUNDLE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO PIP_CERT; do
        SANDBOX_ARGV+=("${var}=${CA_BUNDLE}")
      done
      # Tools that read their token from the environment send the
      # placeholder, and the proxy fills it in for the right host
      for name in "${POLICY_NAMES[@]}"; do
        SANDBOX_ARGV+=("${name}={{${name}}}")
      done
    fi
    protected_dirs
    kept_files
    regex_of "${KEPT_FILES[@]}"
    KEPT_REGEX="$REGEX"
    # The project's .claude is only kept once it exists, so commands can still make it
    PARENTS=()
    parents_of "${PROTECTED_DIRS[@]}" "${KEPT_FILES[@]}"
    [[ -d "${PROJECT_DIR}/.claude" ]] && parents_of "${PROJECT_DIR}/.claude/settings.json"
    regex_of "${PARENTS[@]}"
    PARENTS_REGEX="$REGEX"
    SANDBOX_ARGV+=(sandbox-exec -D "CONFIG_DIR=${PROTECTED_DIRS[0]}" -D "INSTALL_DIR=${PROTECTED_DIRS[1]}"
      -D "PRIVATE_DIR=${PRIVATE_REAL}" -D "PROJECT_POLICY=${PROJECT_DIR}/${PROJECT_POLICY_FILE}"
      -D "CLAUDE_SETTINGS=^(${KEPT_REGEX})(/.*)?\$" -D "PARENT_DIRS=^(${PARENTS_REGEX})\$"
      -f "$profile")
  elif [[ -f "${_SV_LIB_DIR}/sandbox.sb" ]]; then
    SANDBOX_ARGV=(sandbox-exec -f "${_SV_LIB_DIR}/sandbox.sb")
  fi
}

# Reads what the running proxy loaded into STATE_STATUS ("ok" or "error"),
# STATE_DETAIL (the error), STATE_NAMES (global secrets) and STATE_PROJECTS
# ("id NAME..." for each approved project in effect)
read_policy_state() {
  local line
  STATE_STATUS="" STATE_DETAIL="" STATE_NAMES=() STATE_PROJECTS=()
  {
    read -r STATE_STATUS
    [[ "$STATE_STATUS" == error ]] && read -r STATE_DETAIL
    while IFS= read -r line; do
      case "$line" in
        @*) STATE_PROJECTS+=("${line#@}") ;;
        ?*) STATE_NAMES+=("$line") ;;
      esac
    done
  } <"$POLICY_STATE"
}

# Sets PROJECT_NAMES to the secrets of the approved project with id $1, if
# the running proxy has it loaded
loaded_project_names() {
  local entry
  PROJECT_NAMES=()
  for entry in ${STATE_PROJECTS[@]+"${STATE_PROJECTS[@]}"}; do
    if [[ "${entry%% *}" == "$1" ]]; then
      read -ra PROJECT_NAMES <<<"${entry#"$1"}"
      return 0
    fi
  done
  return 1
}

random_hex() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }

# Sets PROJECT_TOKEN and PROJECT_ID for the project at real path $1, if it has
# them. The token is the project's proxy password and stays secret; the id
# only names the project's files in PRIVATE_DIR.
find_project_token() {
  local token id path
  PROJECT_TOKEN="" PROJECT_ID=""
  [[ -f "${PRIVATE_DIR}/tokens.tsv" ]] || return 1
  while IFS=$'\t' read -r token id path; do
    if [[ "$path" == "$1" ]]; then
      PROJECT_TOKEN="$token" PROJECT_ID="$id"
      return 0
    fi
  done <"${PRIVATE_DIR}/tokens.tsv"
  return 1
}

# Like find_project_token, but makes them the first time
project_token() {
  find_project_token "$1" && return 0
  mkdir -p -m 700 "$PRIVATE_DIR"
  PROJECT_TOKEN=$(random_hex 16) PROJECT_ID=$(random_hex 6)
  [[ ${#PROJECT_TOKEN} -eq 32 && ${#PROJECT_ID} -eq 12 ]] || return 1
  (umask 077 && printf '%s\t%s\t%s\n' "$PROJECT_TOKEN" "$PROJECT_ID" "$1" >>"${PRIVATE_DIR}/tokens.tsv")
}

# Checks PROJECT_DIR's .blindfold.toml against what the user decided. Once
# it's approved, sets PROJECT_TOKEN and PROJECT_NAMES from what the proxy
# loaded. A denied policy is ignored. A new or changed one gets the approval
# dialog, and commands are refused (with EGRESS_SETUP_ERROR set) until the
# user answers, so the agent can't run ahead without the secrets it expects.
# A project without a policy gets no token at all.
check_project_policy() {
  local file="${PROJECT_DIR}/${PROJECT_POLICY_FILE}" i err
  PROJECT_TOKEN="" PROJECT_ID="" PROJECT_NAMES=()
  [[ -f "$file" ]] || return 0
  project_token "$PROJECT_DIR" || return 1
  local pending="${PRIVATE_DIR}/pending/${PROJECT_ID}.toml"

  if cmp -s "$file" "${PRIVATE_DIR}/trusted/${PROJECT_ID}.toml"; then
    # The approval script signals the proxy to reload, so this is normally
    # there on the first look, and the proxy's own check each second catches
    # it otherwise. Until it's loaded, the project's placeholders aren't
    # exported, since the proxy wouldn't fill them in anyway.
    for ((i = 0; i < 24; i++)); do
      loaded_project_names "$PROJECT_ID" && return 0
      sleep 0.05
      read_policy_state
    done
    return 0
  fi
  cmp -s "$file" "${PRIVATE_DIR}/denied/${PROJECT_ID}.toml" && return 0

  if ! cmp -s "$file" "$pending"; then
    if ! err=$("$PROXY_BIN" -check "$file" 2>&1 >/dev/null); then
      EGRESS_SETUP_ERROR="This project's ${PROJECT_POLICY_FILE} is not valid: ${err}"
      EGRESS_SETUP_HINT="Fix it in your own editor, outside the agent."
      return 1
    fi
    mkdir -p -m 700 "${PRIVATE_DIR}/pending"
    cp "$file" "$pending" || return 1
    nohup bash "${_SV_LIB_DIR}/secret-approve.sh" "$PROJECT_DIR" </dev/null >/dev/null 2>&1 &
  fi
  EGRESS_SETUP_ERROR="This project's ${PROJECT_POLICY_FILE} is waiting for your approval in a Blindfold dialog."
  EGRESS_SETUP_HINT="Approve or deny it there, then run the command again. Without a dialog, run: bash ${_SV_LIB_DIR}/secret-approve.sh ${PROJECT_DIR}"
  return 1
}

# Sets PROTECTED_DIRS to the real paths of CONFIG_DIR and INSTALL_DIR, and
# PRIVATE_REAL to PRIVATE_DIR's, once per run. They're created first, since
# Seatbelt matches resolved paths and the profile needs ones that exist.
protected_dirs() {
  [[ ${#PROTECTED_DIRS[@]} -gt 0 ]] && return 0
  local d
  for d in "$CONFIG_DIR" "$INSTALL_DIR"; do
    [[ -d "$d" ]] || mkdir -p "$d" 2>/dev/null
    PROTECTED_DIRS+=("$(cd "$d" 2>/dev/null && pwd -P)")
  done
  PRIVATE_REAL="${PROTECTED_DIRS[0]}${PRIVATE_DIR#"$CONFIG_DIR"}"
}

# Sets RESOLVED_PATH to path with symlinks and .. resolved, following a
# symlink at the end a few hops at most. Fails when a .. sits in a part that
# doesn't exist yet, which can't be resolved here.
resolve_path() {
  local path="$1" rest="" dir target hops
  for ((hops = 0; hops < 8; hops++)); do
    [[ -L "$path" ]] || break
    target=$(readlink "$path")
    [[ "$target" == /* ]] && path="$target" || path="${path%/*}/${target}"
  done
  dir="$path"
  while [[ -n "$dir" && ! -d "$dir" ]]; do
    rest="/${dir##*/}${rest}"
    [[ "$dir" == */* ]] && dir="${dir%/*}" || dir="."
  done
  [[ "$rest" == */../* || "$rest" == */.. ]] && return 1
  RESOLVED_PATH="$(cd "${dir:-/}" 2>/dev/null && pwd -P)${rest}"
}

# True when path resolves into one of the given dirs, or is a hard link to a
# file in one. A path that can't be resolved counts as inside, rather than
# guessing.
path_is_inside() {
  local path="$1" dir links inode
  shift
  resolve_path "$path" || return 0
  for dir in "$@"; do
    [[ "$RESOLVED_PATH" == "$dir" || "$RESOLVED_PATH" == "$dir"/* ]] && return 0
  done
  # A hard link made inside the sandbox could give a file a second name. Only
  # multiply-linked files need the (slower) inode search.
  [[ -f "$RESOLVED_PATH" ]] || return 1
  # GNU stat first: on Linux `stat -f` means file system status and succeeds
  # with unrelated output, while BSD stat simply rejects -c
  read -r links inode < <(stat -c '%h %i' "$RESOLVED_PATH" 2>/dev/null || stat -f '%l %i' "$RESOLVED_PATH" 2>/dev/null)
  [[ "$links" =~ ^[0-9]+$ && "$inode" =~ ^[0-9]+$ && "$links" -gt 1 ]] || return 1
  [[ -n "$(find "$@" -xdev -inum "$inode" -print -quit 2>/dev/null)" ]]
}

# True for Blindfold's config and code, and for any project's .blindfold.toml.
# The agent's file tools go through this, since they run outside the sandbox.
is_protected_path() {
  protected_dirs
  [[ "${1##*/}" == "$PROJECT_POLICY_FILE" ]] && return 0
  path_is_inside "$1" "${PROTECTED_DIRS[@]}" && return 0
  [[ "${RESOLVED_PATH##*/}" == "$PROJECT_POLICY_FILE" ]]
}

# Adds to KEPT_FILES the real path of each name in folder $1, and for a
# symlink, the real path of what it points to as well
add_kept() {
  local dir="$1" name
  shift
  [[ -L "$dir" ]] && KEPT_FILES+=("$dir")
  resolve_path "$dir" || return 0
  dir="$RESOLVED_PATH"
  for name in "$@"; do
    KEPT_FILES+=("${dir}/${name}")
    [[ -L "${dir}/${name}" ]] && resolve_path "${dir}/${name}" && KEPT_FILES+=("$RESOLVED_PATH")
  done
}

# Sets KEPT_FILES to Claude Code's user settings, its plugins folder (which
# says what's installed and where it came from) and the shell profiles, once
# per run
kept_files() {
  [[ ${#KEPT_FILES[@]} -gt 0 ]] && return 0
  local zsh=(.zshenv .zprofile .zshrc .zlogin)
  add_kept "$CLAUDE_DIR" settings.json settings.local.json plugins
  add_kept "$HOME" "${zsh[@]}" .bash_profile .bash_login .bashrc .profile
  add_kept "$HOME/.config/fish" config.fish
  [[ -n "${ZDOTDIR:-}" ]] && add_kept "$ZDOTDIR" "${zsh[@]}"
}

# True for a file named like a project's Claude Code settings, anywhere
is_project_settings() {
  [[ "$1" == */.claude/settings.json || "$1" == */.claude/settings.local.json ]]
}

# True for Claude Code's settings, its plugins folder and the shell profiles.
# The guard only refuses these under lockdown: without it, Bash can write them
# anyway.
is_claude_settings_path() {
  is_project_settings "$1" && return 0
  kept_files
  path_is_inside "$1" "${KEPT_FILES[@]}" && return 0
  is_project_settings "$RESOLVED_PATH"
}

# Adds to PARENTS every folder above the given paths, once each, so the
# sandbox can keep them from being renamed or removed with what's inside.
# Plain bash, since this runs on every command.
parents_of() {
  local p seen
  for p in "$@"; do
    while p="${p%/*}"; [[ -n "$p" ]]; do
      # A folder seen before has had its own parents added already
      for seen in ${PARENTS[@]+"${PARENTS[@]}"}; do
        [[ "$seen" == "$p" ]] && continue 3
      done
      PARENTS+=("$p")
    done
  done
}

# Sets REGEX to one alternation that matches each given path literally
regex_of() {
  local p c
  REGEX=""
  for p in "$@"; do
    for c in '\' . '[' ']' '*' '^' '$' + '?' '(' ')' '{' '}' '|'; do
      p="${p//"$c"/\\$c}"
    done
    REGEX+="${REGEX:+|}${p}"
  done
}

# True for the private folder, where reading a project token would let the
# agent pass for that project
is_private_path() {
  protected_dirs
  path_is_inside "$1" "$PRIVATE_REAL"
}

# Reads SETTINGS_FILE. Sets BLINDFOLD_EGRESS=proxy when it turns lockdown on,
# and EXEC_ANY_SECRET when it turns secret-exec.sh's refusal off. A file it
# can't make sense of turns lockdown on and sets SETTINGS_ERROR, so commands
# are refused until it's fixed rather than run with a guess.
read_settings() {
  local line
  EXEC_ANY_SECRET="" SETTINGS_ERROR=""
  [[ -f "$SETTINGS_FILE" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    case "$line" in
      BLINDFOLD_EGRESS=proxy) BLINDFOLD_EGRESS=proxy ;;
      BLINDFOLD_EGRESS=) ;;
      BLINDFOLD_EXEC_ANY_SECRET=1) EXEC_ANY_SECRET=1 ;;
      BLINDFOLD_EXEC_ANY_SECRET=0 | BLINDFOLD_EXEC_ANY_SECRET=) ;;
      *) SETTINGS_ERROR="Line '${line}' in ${SETTINGS_FILE} is not a setting Blindfold knows." ;;
    esac
  done <"$SETTINGS_FILE"
  [[ -z "$SETTINGS_ERROR" ]] || BLINDFOLD_EGRESS=proxy
}
read_settings

EGRESS_SETUP_ERROR="Egress lockdown is on, but the proxy did not start."
EGRESS_SETUP_HINT="Build it with scripts/build-proxy.sh in your own terminal, or turn lockdown off."

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

