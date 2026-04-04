#!/usr/bin/env bash
# PreToolUse hook: enforces kernel-level sandbox on Bash commands (macOS Seatbelt)
# and blocks direct reads of registered .env files.
# Exit 0 with JSON = allow (possibly with modified command)
# Exit 2 = deny
set -uo pipefail

REGISTRY="$HOME/.claude/secrets-registry.json"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_PROFILE="${SCRIPT_DIR}/sandbox.sb"

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

# --- .env file blocking (applies to both Bash and Read) ---
if [[ -f "$REGISTRY" ]]; then
  ENV_PATHS=$(jq -r '
    [.global.envProfiles | values // empty] +
    [.projects | to_entries[]? | .value.envProfiles | values // empty]
    | unique | .[]
  ' "$REGISTRY" 2>/dev/null)

  while IFS= read -r env_path; do
    [[ -n "$env_path" ]] || continue
    [[ "$TOOL_NAME" == "Read" && "$COMMAND" == "$env_path" ]] && deny "Direct reading of registered .env file blocked."
    [[ "$TOOL_NAME" == "Bash" && "$COMMAND" == *"$env_path"* ]] && deny "Access to registered .env file blocked."
  done <<< "$ENV_PATHS"
fi

# --- Sandbox wrapping (Bash only, macOS only) ---
[[ "$TOOL_NAME" == "Bash" ]] || exit 0

# Exempt secret-exec.sh -- it needs unsandboxed keychain access
[[ "$COMMAND" == *"secret-exec.sh"* ]] && exit 0
# Exempt secret-store.sh -- it needs unsandboxed keychain access for storing
[[ "$COMMAND" == *"secret-store.sh"* ]] && exit 0

# On macOS with Seatbelt: wrap the command in sandbox-exec
if [[ "$(uname -s)" == "Darwin" && -f "$SANDBOX_PROFILE" ]]; then
  # Escape the command for embedding in bash -c
  ESCAPED_CMD=$(printf '%s' "$COMMAND" | sed "s/'/'\\\\''/g")
  WRAPPED="sandbox-exec -f '${SANDBOX_PROFILE}' bash -c '${ESCAPED_CMD}'"

  # Output updatedInput to replace the command with the sandboxed version
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

# --- Fallback: string matching for platforms without sandbox ---
case "$(uname -s)" in
  Darwin)
    # Sandbox should have handled this, but just in case
    [[ "$COMMAND" == *"find-generic-password"*"-w"* ]] && deny "Keychain password read blocked."
    [[ "$COMMAND" == *"find-generic-password"*"claude-secret"* ]] && deny "Keychain read of managed secret blocked."
    [[ "$COMMAND" == *"dump-keychain"* ]] && deny "Keychain dump blocked."
    [[ "$COMMAND" == *"claude-secrets"*"-w"* ]] && deny "Keychain read blocked."
    ;;
  Linux)
    [[ "$COMMAND" == *"secret-tool"*"lookup"*"claude-secrets"* ]] && deny "secret-tool lookup blocked."
    [[ "$COMMAND" == *".claude/vault/"*".gpg"* ]] && deny "GPG vault access blocked."
    ;;
esac

exit 0
