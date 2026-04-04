#!/usr/bin/env bash
# PreToolUse hook: blocks commands that would expose secret values.
# Exit 0 = allow, Exit 2 = deny
set -uo pipefail

REGISTRY="$HOME/.claude/secrets-registry.json"

INPUT=$(cat)

PARSED=$(echo "$INPUT" | jq -r '[.tool_name // "", .tool_input.command // .tool_input.file_path // ""] | @tsv' 2>/dev/null)
TOOL_NAME="${PARSED%%	*}"
COMMAND="${PARSED#*	}"

[[ "$TOOL_NAME" == "Bash" || "$TOOL_NAME" == "Read" ]] || exit 0
[[ -n "$COMMAND" ]] || exit 0

deny() {
  echo "DENIED by Blindfold: $1" >&2
  echo "Use secret-exec.sh to run commands that need secrets." >&2
  exit 2
}

# Check for secret store keywords ANYWHERE in the command string.
# This catches direct calls, subprocess calls from Python/Ruby/Node,
# backtick expansion, xargs, eval, and other nesting tricks.
case "$(uname -s)" in
  Darwin)
    [[ "$COMMAND" == *"find-generic-password"*"-w"* ]] && deny "Keychain password read blocked."
    [[ "$COMMAND" == *"find-generic-password"*"claude-secret"* ]] && deny "Keychain read of managed secret blocked."
    [[ "$COMMAND" == *"dump-keychain"* ]] && deny "Keychain dump blocked."
    [[ "$COMMAND" == *"security"*"export"*"keychain"* ]] && deny "Keychain export blocked."
    # Block any command referencing the claude-secrets service with password retrieval
    [[ "$COMMAND" == *"claude-secrets"*"-w"* ]] && deny "Keychain read of Blindfold secrets blocked."
    [[ "$COMMAND" == *"claude-secrets"*"password"* ]] && deny "Keychain password access blocked."
    ;;
  Linux)
    [[ "$COMMAND" == *"secret-tool"*"lookup"*"claude-secrets"* ]] && deny "secret-tool lookup blocked."
    [[ "$COMMAND" == *".claude/vault/"*".gpg"* ]] && deny "GPG vault access blocked."
    ;;
esac

# Block reading registered .env files
if [[ -f "$REGISTRY" ]]; then
  ENV_PATHS=$(jq -r '
    [.global.envProfiles | values // empty] +
    [.projects | to_entries[]? | .value.envProfiles | values // empty]
    | unique | .[]
  ' "$REGISTRY" 2>/dev/null)

  while IFS= read -r env_path; do
    [[ -n "$env_path" ]] || continue

    if [[ "$TOOL_NAME" == "Read" && "$COMMAND" == "$env_path" ]]; then
      deny "Direct reading of registered .env file blocked."
    fi

    if [[ "$TOOL_NAME" == "Bash" && "$COMMAND" == *"$env_path"* ]]; then
      deny "Access to registered .env file blocked."
    fi
  done <<< "$ENV_PATHS"
fi

exit 0
