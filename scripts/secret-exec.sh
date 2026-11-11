#!/usr/bin/env bash
set -uo pipefail
source "$(dirname "$0")/lib.sh"
check_dependencies

COMMAND=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) echo "Usage: secret-exec.sh '<command with {{PLACEHOLDERS}}>'"; exit 1 ;;
    *) COMMAND="$1"; shift ;;
  esac
done

[[ -n "$COMMAND" ]] || { echo "ERROR: Command is required." >&2; exit 1; }
[[ -f "$REGISTRY" ]] || { echo "ERROR: Registry not found." >&2; exit 1; }

# Fill get_project_path's cache in this shell, so build_sandbox_argv reuses it
get_project_path >/dev/null
PROJECT_PATH="$_SV_PROJECT_PATH"

# Secure temp files (600 permissions, cleaned up on exit and signals)
# Note: SIGKILL (kill -9) cannot be trapped — temp files may persist.
# Mitigations: restrictive permissions (600) and umask 077 limit exposure.
OLD_UMASK=$(umask)
umask 077
REDACT_FILE=$(mktemp)
EXEC_SCRIPT=$(mktemp)
STDOUT_TMP=$(mktemp)
STDERR_TMP=$(mktemp)
umask "$OLD_UMASK"
chmod 600 "$REDACT_FILE" "$EXEC_SCRIPT" "$STDOUT_TMP" "$STDERR_TMP"

CHILD_PID=""
cleanup_temp_files() {
  [[ -n "$CHILD_PID" ]] && kill "$CHILD_PID" 2>/dev/null
  rm -f "$REDACT_FILE" "$EXEC_SCRIPT" "$STDOUT_TMP" "$STDERR_TMP" 2>/dev/null
}
trap cleanup_temp_files EXIT
trap 'cleanup_temp_files; exit 143' SIGTERM
trap 'cleanup_temp_files; exit 130' SIGINT
trap 'cleanup_temp_files; exit 129' SIGHUP

echo '#!/usr/bin/env bash' > "$EXEC_SCRIPT"

# The secret names the command's {{PLACEHOLDERS}} refer to, once each
NAMES=$(echo "$COMMAND" | grep -oE '\{\{[A-Za-z_][A-Za-z0-9_]*\}\}' | tr -d '{}' | sort -u || true)

# Set up the sandbox before reading any value. Under egress lockdown this also
# says which secrets have a policy: those go through the proxy, which only
# sends them to their own hosts, so they're never put into a command here.
# BLINDFOLD_EXEC_ANY_SECRET=1 in Blindfold's settings file turns this off
# while migrating. It's read from the file only, never the environment, so the
# agent can't set it: under lockdown it can't write the file.
build_sandbox_argv || { echo "ERROR: ${EGRESS_SETUP_ERROR} ${EGRESS_SETUP_HINT}" >&2; exit 1; }
while IFS= read -r name; do
  [[ -n "$name" && -z "$EXEC_ANY_SECRET" && " ${POLICY_NAMES[*]-} " == *" ${name} "* ]] || continue
  echo "ERROR: ${name} has a policy, so secret-exec.sh won't put its value into a command." >&2
  echo "Run the command directly instead, with {{${name}}} or \$${name} where the value goes." >&2
  echo "The proxy fills it in on the way to the hosts its policy allows." >&2
  exit 1
done <<< "$NAMES"

# Resolve {{PLACEHOLDER}} secrets. A separate pass from the check above, so a
# refused secret stops the command before any value is read.
RESOLVED_CMD="$COMMAND"

while IFS= read -r name; do
  [[ -n "$name" ]] || continue

  value=$(get_secret "$(make_account_key "$PROJECT_PATH" "$name")")
  [[ -n "$value" ]] || value=$(get_secret "$(make_account_key global "$name")")
  [[ -n "$value" ]] || { echo "ERROR: Secret '${name}' not found." >&2; exit 1; }

  printf '%s\t%s\n' "$name" "$value" >> "$REDACT_FILE"
  printf 'export __SV_%s=%q\n' "$name" "$value" >> "$EXEC_SCRIPT"
  RESOLVED_CMD="${RESOLVED_CMD//"{{${name}}}"/"\${__SV_${name}}"}"
done <<< "$NAMES"

echo "$RESOLVED_CMD" >> "$EXEC_SCRIPT"

# Execute (sandboxed on macOS to prevent the inner command from reaching the
# keychain). The +-form keeps an empty array from tripping set -u on bash 3.2.
${SANDBOX_ARGV[@]+"${SANDBOX_ARGV[@]}"} bash "$EXEC_SCRIPT" > "$STDOUT_TMP" 2> "$STDERR_TMP" &
CHILD_PID=$!
wait "$CHILD_PID"
CMD_EXIT=$?
CHILD_PID=""
rm -f "$EXEC_SCRIPT"

# Single-pass redaction via ENVIRON
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
  for ((i=0; i<REDACT_COUNT; i++)); do unset "__REDACT_F_${i}" "__REDACT_R_${i}"; done
fi

STDOUT_CONTENT=$(cat "$STDOUT_TMP")
STDERR_CONTENT=$(cat "$STDERR_TMP")

[[ -z "$STDOUT_CONTENT" ]] || echo "$STDOUT_CONTENT"
[[ -z "$STDERR_CONTENT" ]] || echo "$STDERR_CONTENT" >&2

exit "$CMD_EXIT"
