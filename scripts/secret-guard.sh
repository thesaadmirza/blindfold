#!/usr/bin/env bash
# PreToolUse hook: enforces kernel-level sandbox on Bash commands (macOS Seatbelt).
# Exit 0 with JSON = allow (possibly with modified command)
# Exit 2 = deny
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_PROFILE="${SCRIPT_DIR}/sandbox.sb"

INPUT=$(</dev/stdin)

# Read each field on its own: @tsv would turn real newlines into a literal \n
TOOL_NAME=$(jq -r '.tool_name // ""' <<< "$INPUT" 2>/dev/null)
COMMAND=$(jq -r '.tool_input.command // ""' <<< "$INPUT" 2>/dev/null)

[[ "$TOOL_NAME" == "Bash" ]] || exit 0
[[ -n "$COMMAND" ]] || exit 0

deny() {
  echo "DENIED by Blindfold: $1" >&2
  echo "Use secret-exec.sh to run commands that need secrets." >&2
  exit 2
}

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

for script in secret-exec.sh secret-store.sh secret-list.sh secret-delete.sh; do
  is_exempt "$COMMAND" "${SCRIPT_DIR}/${script}" && exit 0
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
