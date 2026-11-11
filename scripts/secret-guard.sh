#!/usr/bin/env bash
# PreToolUse hook: enforces kernel-level sandbox on Bash commands (macOS Seatbelt),
# keeps Read away from files that hold a stored secret value, and keeps the
# file-editing tools away from Blindfold's config and code.
# Exit 0 with JSON = allow (possibly with modified command)
# Exit 2 = deny
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

INPUT=$(</dev/stdin)

# Read each field on its own: @tsv would turn real newlines into a literal \n
TOOL_NAME=$(jq -r '.tool_name // ""' <<< "$INPUT" 2>/dev/null)
case "$TOOL_NAME" in
  Bash | Read | Grep | Write | Edit | MultiEdit | NotebookEdit) ;;
  *) exit 0 ;;
esac

_SV_LIB_DIR="$SCRIPT_DIR"
source "${SCRIPT_DIR}/lib.sh"

# deny REASON [HINT]
deny() {
  echo "DENIED by Blindfold: $1" >&2
  echo "${2:-Use secret-exec.sh to run commands that need secrets.}" >&2
  exit 2
}

# Read and Grep must stay out of the private folder: a project token read
# there would let the agent pass for that project
if [[ "$TOOL_NAME" == "Read" || "$TOOL_NAME" == "Grep" ]]; then
  FILE_PATH=$(jq -r '.tool_input.file_path // .tool_input.path // ""' <<< "$INPUT" 2>/dev/null)
  [[ -n "$FILE_PATH" ]] && is_private_path "$FILE_PATH" &&
    deny "${FILE_PATH} holds Blindfold's private project tokens." "Nothing in it is meant for the agent."
  [[ "$TOOL_NAME" == "Grep" ]] && exit 0
fi

# File tools run outside the sandbox, so the sandbox's write rules don't cover
# them. Refuse edits to Blindfold's config and scripts and to project policies.
if [[ "$TOOL_NAME" != "Bash" && "$TOOL_NAME" != "Read" ]]; then
  FILE_PATH=$(jq -r '.tool_input.file_path // .tool_input.notebook_path // ""' <<< "$INPUT" 2>/dev/null)
  [[ -n "$FILE_PATH" ]] || exit 0
  is_protected_path "$FILE_PATH" &&
    deny "${FILE_PATH} is Blindfold's own config or code, or a project policy." "Edit it yourself, outside the agent."
  exit 0
fi

# Read: refuse a file that contains any stored value, e.g. one a command wrote
# a secret into. Checked before the read, since output can't be redacted after.
if [[ "$TOOL_NAME" == "Read" ]]; then
  FILE_PATH=$(jq -r '.tool_input.file_path // ""' <<< "$INPUT" 2>/dev/null)
  [[ -f "$FILE_PATH" && -r "$FILE_PATH" ]] || exit 0

  CONTENT=$(<"$FILE_PATH")
  while IFS=$'\t' read -r scope name; do
    value=$(get_secret "$(make_account_key "$scope" "$name")")
    [[ ${#value} -ge $MIN_REDACT_LENGTH ]] || continue
    [[ "$CONTENT" == *"$value"* ]] && deny "${FILE_PATH} contains the value of ${name}."
  done < <(registered_secret_scopes)
  exit 0
fi

COMMAND=$(jq -r '.tool_input.command // ""' <<< "$INPUT" 2>/dev/null)
[[ -n "$COMMAND" ]] || exit 0

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

# Wrap the command in the sandbox lib.sh picks (Seatbelt on macOS, with egress
# lockdown when it's on). Each word is single-quoted; the replacement sits in a
# variable because bash 3.2, the macOS default, keeps the backslashes of an
# inline '\'' there.
build_sandbox_argv || deny "$EGRESS_SETUP_ERROR" "$EGRESS_SETUP_HINT"
if [[ ${#SANDBOX_ARGV[@]} -gt 0 ]]; then
  q="'\\''"
  WRAPPED=""
  for word in "${SANDBOX_ARGV[@]}" bash -c "$COMMAND"; do
    WRAPPED+="'${word//\'/$q}' "
  done
  WRAPPED="${WRAPPED% }"

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
