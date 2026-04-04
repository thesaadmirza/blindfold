#!/usr/bin/env bash
set -uo pipefail
source "$(dirname "$0")/lib.sh"
check_dependencies

ENV_PROFILE=""
COMMAND=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) [[ $# -ge 2 ]] || { echo "ERROR: --env requires a profile name" >&2; exit 1; }
           ENV_PROFILE="$2"; shift 2 ;;
    -h|--help) echo "Usage: secret-exec.sh [--env <profile>] '<command>'"; exit 1 ;;
    *) COMMAND="$1"; shift ;;
  esac
done

[[ -n "$COMMAND" ]] || { echo "ERROR: Command is required." >&2; exit 1; }
[[ -f "$REGISTRY" ]] || { echo "ERROR: Registry not found." >&2; exit 1; }

PROJECT_PATH=$(get_project_path)

# Secure temp files (600 permissions, cleaned up on exit)
OLD_UMASK=$(umask)
umask 077
REDACT_FILE=$(mktemp)
EXEC_SCRIPT=$(mktemp)
STDOUT_TMP=$(mktemp)
STDERR_TMP=$(mktemp)
umask "$OLD_UMASK"
trap 'rm -f "$REDACT_FILE" "$EXEC_SCRIPT" "$STDOUT_TMP" "$STDERR_TMP" 2>/dev/null' EXIT

echo '#!/usr/bin/env bash' > "$EXEC_SCRIPT"

# Resolve {{PLACEHOLDER}} secrets
PLACEHOLDERS=$(echo "$COMMAND" | grep -oE '\{\{[A-Za-z_][A-Za-z0-9_]*\}\}' | sort -u || true)
RESOLVED_CMD="$COMMAND"

while IFS= read -r placeholder; do
  [[ -n "$placeholder" ]] || continue
  name="${placeholder#\{\{}"
  name="${name%\}\}}"

  value=$(get_secret "$(make_account_key "$PROJECT_PATH" "$name")")
  [[ -n "$value" ]] || value=$(get_secret "$(make_account_key global "$name")")
  [[ -n "$value" ]] || { echo "ERROR: Secret '${name}' not found." >&2; exit 1; }

  printf '%s\t%s\n' "$name" "$value" >> "$REDACT_FILE"
  printf 'export __SV_%s=%q\n' "$name" "$value" >> "$EXEC_SCRIPT"
  RESOLVED_CMD="${RESOLVED_CMD//"{{${name}}}"/"\${__SV_${name}}"}"
done <<< "$PLACEHOLDERS"

# Load env profile
if [[ -n "$ENV_PROFILE" ]]; then
  ENV_PATH=$(resolve_env_profile "$ENV_PROFILE")
  [[ -n "$ENV_PATH" ]] || { echo "ERROR: Env profile '${ENV_PROFILE}' not found." >&2; exit 1; }
  [[ -f "$ENV_PATH" ]] || { echo "ERROR: Env file missing: ${ENV_PATH}" >&2; exit 1; }

  grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$ENV_PATH" 2>/dev/null | while IFS= read -r line; do
    key="${line%%=*}"
    val="${line#*=}"
    val="${val#\"}" ; val="${val%\"}"
    val="${val#\'}" ; val="${val%\'}"
    printf 'ENV:%s\t%s\n' "$key" "$val" >> "$REDACT_FILE"
    printf 'export %s=%q\n' "$key" "$val" >> "$EXEC_SCRIPT"
  done
fi

echo "$RESOLVED_CMD" >> "$EXEC_SCRIPT"

# Execute (sandboxed on macOS to prevent the inner command from reaching the keychain)
run_sandboxed bash "$EXEC_SCRIPT" > "$STDOUT_TMP" 2> "$STDERR_TMP"
CMD_EXIT=$?
rm -f "$EXEC_SCRIPT"

# Build single-pass redaction: export secrets as env vars, awk reads them via ENVIRON
REDACT_COUNT=0
while IFS=$'\t' read -r label value; do
  [[ -n "$value" && ${#value} -ge $MIN_REDACT_LENGTH ]] || continue
  export "__REDACT_F_${REDACT_COUNT}=${value}"
  export "__REDACT_R_${REDACT_COUNT}=[REDACTED:${label}]"
  REDACT_COUNT=$((REDACT_COUNT + 1))
done < "$REDACT_FILE"

if [[ $REDACT_COUNT -gt 0 ]]; then
  AWK_SCRIPT='{ for (i = 0; i < n; i++) { f = ENVIRON["__REDACT_F_" i]; r = ENVIRON["__REDACT_R_" i]; while (idx = index($0, f)) { $0 = substr($0, 1, idx-1) r substr($0, idx + length(f)) } } print }'
  for f in "$STDOUT_TMP" "$STDERR_TMP"; do
    awk -v n="$REDACT_COUNT" "$AWK_SCRIPT" "$f" > "${f}.redacted" && mv "${f}.redacted" "$f"
  done
  # Clean up env vars
  for ((i=0; i<REDACT_COUNT; i++)); do unset "__REDACT_F_${i}" "__REDACT_R_${i}"; done
fi

STDOUT_CONTENT=$(cat "$STDOUT_TMP")
STDERR_CONTENT=$(cat "$STDERR_TMP")

[[ -z "$STDOUT_CONTENT" ]] || echo "$STDOUT_CONTENT"
[[ -z "$STDERR_CONTENT" ]] || echo "$STDERR_CONTENT" >&2

exit "$CMD_EXIT"
