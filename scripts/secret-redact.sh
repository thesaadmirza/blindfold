#!/usr/bin/env bash
# PostToolUse hook: scans Bash output for leaked secret values and
# replaces them with [REDACTED:NAME] before Claude sees the result.
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
        REDACTED_RESULT="${REDACTED_RESULT//"$value"/"[REDACTED:${name}]"}"
      fi
      break
    fi
  done
done <<< "$ALL_SECRETS"

if [[ ${#LEAKED_NAMES[@]} -gt 0 ]]; then
  NAMES_STR=$(IFS=', '; echo "${LEAKED_NAMES[*]}")

  # Emit the scrubbed result so Claude sees redacted output
  jq -n --arg result "$REDACTED_RESULT" \
    '{"tool_response": {"stdout": $result}}'

  # Also warn Claude not to reference the values
  jq -n --arg msg "WARNING: Secret values for [${NAMES_STR}] were redacted from output. Do not attempt to recover or reference the original values." \
    '{"systemMessage": $msg}' >&2
fi

exit 0
