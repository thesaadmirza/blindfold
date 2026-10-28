#!/usr/bin/env bash
# PreToolUse hook: enforces kernel-level sandbox on Bash commands (macOS Seatbelt)
# and keeps Read away from files that hold a stored secret value.
# Exit 0 with JSON = allow (possibly with modified command)
# Exit 2 = deny
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_PROFILE="${SCRIPT_DIR}/sandbox.sb"

INPUT=$(</dev/stdin)

# Read each field on its own: @tsv would turn real newlines into a literal \n
TOOL_NAME=$(jq -r '.tool_name // ""' <<< "$INPUT" 2>/dev/null)
COMMAND=$(jq -r '.tool_input.command // ""' <<< "$INPUT" 2>/dev/null)

deny() {
  echo "DENIED by Blindfold: $1" >&2
  echo "Use secret-exec.sh to run commands that need secrets." >&2
  exit 2
}

# Read: refuse a file that contains any stored value, e.g. one a command wrote
# a secret into. Checked before the read, since output can't be redacted after.
if [[ "$TOOL_NAME" == "Read" ]]; then
  FILE_PATH=$(jq -r '.tool_input.file_path // ""' <<< "$INPUT" 2>/dev/null)
  [[ -f "$FILE_PATH" && -r "$FILE_PATH" ]] || exit 0
  source "${SCRIPT_DIR}/lib.sh"
  [[ -f "$REGISTRY" ]] || exit 0

  CONTENT=$(<"$FILE_PATH")
  PROJECT_PATH=$(get_project_path)
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    for scope in "$PROJECT_PATH" "global"; do
      value=$(get_secret "$(make_account_key "$scope" "$name")")
      [[ -n "$value" && ${#value} -ge $MIN_REDACT_LENGTH ]] || continue
      [[ "$CONTENT" == *"$value"* ]] && deny "${FILE_PATH} contains the value of ${name}."
    done
  done < <(registered_secret_names)
  exit 0
fi

[[ "$TOOL_NAME" == "Bash" ]] || exit 0
[[ -n "$COMMAND" ]] || exit 0

# Wrap a string in single quotes. Uses sed because bash 3.2, the macOS
# default, keeps the backslashes in a ${var//\'/...} replacement.
single_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# Exempt Blindfold's own scripts -- must match at start, followed by space or end-of-string
is_exempt() {
  local cmd="$1" path="$2"
  [[ "$cmd" == "bash ${path}" || "$cmd" == "bash ${path} "* ]] && return 0
  [[ "$cmd" == "${path}" || "$cmd" == "${path} "* ]] && return 0
  return 1
}

# True when the command is one plain invocation. Exempt scripts run outside
# the sandbox, so nothing may ride along after them: no ; & | < > ( ) or
# newline outside quotes, and no $( or backtick anywhere the shell would run it.
is_single_command() {
  local cmd="$1" quote="" c next i
  for ((i = 0; i < ${#cmd}; i++)); do
    c="${cmd:i:1}"
    next="${cmd:i+1:1}"
    if [[ "$quote" == "'" ]]; then
      [[ "$c" == "'" ]] && quote=""
      continue
    fi
    if [[ "$c" == "\\" ]]; then
      i=$((i + 1))
      continue
    fi
    if [[ "$quote" == '"' ]]; then
      case "$c" in
        '"') quote="" ;;
        '`') return 1 ;;
        '$') [[ "$next" == "(" ]] && return 1 ;;
      esac
      continue
    fi
    case "$c" in
      "'" | '"') quote="$c" ;;
      ';' | '&' | '|' | '<' | '>' | '(' | ')' | '`' | $'\n' | $'\r') return 1 ;;
      '$') [[ "$next" == "(" || "$next" == "'" ]] && return 1 ;;
    esac
  done
  [[ -z "$quote" ]]
}

for script in secret-exec.sh secret-store.sh secret-list.sh secret-delete.sh; do
  if is_exempt "$COMMAND" "${SCRIPT_DIR}/${script}"; then
    is_single_command "$COMMAND" || deny "Run ${script} on its own, not chained with other commands."
    exit 0
  fi
done

# On macOS with Seatbelt: wrap the command in sandbox-exec
if [[ "$OSTYPE" == darwin* && -f "$SANDBOX_PROFILE" ]] && command -v sandbox-exec &>/dev/null; then
  WRAPPED="sandbox-exec -f $(single_quote "$SANDBOX_PROFILE") bash -c $(single_quote "$COMMAND")"

  jq -n --arg cmd "$WRAPPED" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
      updatedInput: {
        command: $cmd
      }
    }
  }'
  exit 0
fi

# Fallback: string matching for platforms without sandbox
if [[ "$OSTYPE" == darwin* ]]; then
  [[ "$COMMAND" == *"find-generic-password"*"-w"* ]] && deny "Keychain password read blocked."
  [[ "$COMMAND" == *"find-generic-password"*"claude-secret"* ]] && deny "Keychain read of managed secret blocked."
  [[ "$COMMAND" == *"dump-keychain"* ]] && deny "Keychain dump blocked."
  [[ "$COMMAND" == *"claude-secrets"*"-w"* ]] && deny "Keychain read blocked."
elif [[ "$OSTYPE" == linux* ]]; then
  [[ "$COMMAND" == *"secret-tool"*"lookup"*"claude-secrets"* ]] && deny "secret-tool lookup blocked."
  [[ "$COMMAND" == *".claude/vault/"*".gpg"* ]] && deny "GPG vault access blocked."
fi

exit 0
