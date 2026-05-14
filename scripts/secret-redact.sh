#!/usr/bin/env bash
# PostToolUse hook: scans Bash output for leaked secret values and
# warns Claude via systemMessage to disregard them.
# Note: Claude Code does not support output replacement for built-in tools.
# The tool_response emission is silently ignored, so we rely on systemMessage.
set -uo pipefail

SCRIPT_DIR="$(dirname "$0")"
[[ -f "$SCRIPT_DIR/lib.sh" ]] && source "$SCRIPT_DIR/lib.sh" || exit 0

INPUT=$(</dev/stdin)

PARSED=$(jq -r '[.tool_name // "", .tool_response.stdout // .tool_response // ""] | @tsv' <<< "$INPUT" 2>/dev/null)
TOOL_NAME="${PARSED%%	*}"
TOOL_RESULT="${PARSED#*	}"

[[ "$TOOL_NAME" == "Bash" && -n "$TOOL_RESULT" && -f "$REGISTRY" ]] || exit 0
[[ ${#TOOL_RESULT} -ge 4 ]] || exit 0

SECRET_COUNT=$(jq '(.global.secrets | length) + ([.projects | to_entries[]? | .value.secrets | length] | add // 0)' "$REGISTRY" 2>/dev/null || echo "0")
[[ "$SECRET_COUNT" -gt 0 ]] || exit 0

# Skip if output came from secret-exec.sh (already redacted)
[[ "$TOOL_RESULT" != *"[REDACTED:"* ]] || exit 0

check_dependencies

REDACTED_RESULT="$TOOL_RESULT"
LEAKED_NAMES=()
PROJECT_PATH=$(get_project_path)

ALL_SECRETS=$(jq -r '
  [.global.secrets[]?] + [.projects | to_entries[]? | .value.secrets[]?]
  | unique | .[]
' "$REGISTRY" 2>/dev/null)

while IFS= read -r name; do
  [[ -n "$name" ]] || continue
  for scope in "$PROJECT_PATH" "global"; do
    value=$(get_secret "$(make_account_key "$scope" "$name")")
    if [[ -n "$value" && ${#value} -ge $MIN_REDACT_LENGTH ]]; then
      if [[ "$REDACTED_RESULT" == *"$value"* ]]; then
        LEAKED_NAMES+=("$name")
        # Replace all occurrences of the secret value
        repl="[REDACTED:${name}]"
        REDACTED_RESULT="${REDACTED_RESULT//"$value"/$repl}"
      fi
      break
    fi
  done
done <<< "$ALL_SECRETS"

if [[ ${#LEAKED_NAMES[@]} -gt 0 ]]; then
  NAMES_STR=$(IFS=', '; echo "${LEAKED_NAMES[*]}")

  # Warn Claude not to reference the leaked values.
  # This is the only effective output channel — Claude Code ignores
  # tool_response stdout from PostToolUse hooks for built-in tools.
  jq -n --arg msg "WARNING: Secret values for [${NAMES_STR}] were detected in command output. The raw values may appear in context. Do not store, repeat, or reference them." \
    '{"systemMessage": $msg}' >&2
fi

exit 0
