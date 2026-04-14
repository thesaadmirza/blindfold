#!/usr/bin/env bash
# PostToolUse hook: scans Bash output for leaked secret values.
set -uo pipefail

REGISTRY="$HOME/.claude/secrets-registry.json"

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

SCRIPT_DIR="$(dirname "$0")"
[[ -f "$SCRIPT_DIR/lib.sh" ]] && source "$SCRIPT_DIR/lib.sh" || exit 0

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
      [[ "$TOOL_RESULT" == *"$value"* ]] && LEAKED_NAMES+=("$name")
      break
    fi
  done
done <<< "$ALL_SECRETS"

if [[ ${#LEAKED_NAMES[@]} -gt 0 ]]; then
  NAMES_STR=$(IFS=', '; echo "${LEAKED_NAMES[*]}")
  jq -n --arg msg "WARNING: Secret values detected in output for: ${NAMES_STR}. DO NOT reference or repeat these values." \
    '{"systemMessage": $msg}' >&2
fi

exit 0
