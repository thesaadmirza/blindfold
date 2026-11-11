#!/usr/bin/env bash
# Asks you to approve a project's .blindfold.toml before the proxy uses it.
# The guard starts this in the background, where it shows a dialog. Run it in
# a terminal to answer there instead:
#   bash secret-approve.sh /path/to/project
#
# Run from inside the sandbox it can't read the private folder, so the agent
# can't approve a policy for itself.
set -uo pipefail

_SV_LIB_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${_SV_LIB_DIR}/lib.sh"

given="${1:?usage: secret-approve.sh PROJECT_DIR}"
PROJECT=$(cd "$given" 2>/dev/null && pwd -P) || { echo "No such folder: $given" >&2; exit 1; }
find_project_token "$PROJECT" || { echo "Blindfold hasn't seen ${PROJECT} yet. Run a command there first." >&2; exit 1; }
id="$PROJECT_ID"

pending="${PRIVATE_DIR}/pending/${id}.toml"
[[ -f "$pending" ]] || { echo "Nothing in ${PROJECT} is waiting for approval."; exit 0; }

# Decide on a snapshot, so what gets approved is exactly what was shown
snapshot=$(mktemp "${pending}.XXXXXX") || exit 1
cp "$pending" "$snapshot"
names=$("$PROXY_BIN" -check "$snapshot" | tr '\n' ' ') || { rm -f "$snapshot"; exit 1; }

message="A project wants Blindfold to send secrets for it.

Project: ${PROJECT}
Secrets: ${names}"
[[ -f "${PRIVATE_DIR}/trusted/${id}.toml" ]] &&
  message+="
This replaces a policy you approved earlier for this project."
policy=$(<"$snapshot")
((${#policy} > 1500)) && policy="${policy:0:1500}
[... shortened, see ${PROJECT}/${PROJECT_POLICY_FILE}]"
message+="

Approve only if you wrote this file or trust whoever did.

${policy}"

decision=""
if [[ -t 0 ]]; then
  printf '%s\n\n' "$message"
  read -rp "Trust this policy? [y/N] " answer
  [[ "$answer" == [yY]* ]] && decision=trust || decision=deny
else
  # Deny is the default and the cancel button, so Return or Escape never trusts
  reply=$(osascript -e 'on run argv' \
    -e 'display dialog (item 1 of argv) with title "Blindfold" buttons {"Deny", "Trust"} default button "Deny" cancel button "Deny" giving up after 300 with icon caution' \
    -e 'end run' "$message" 2>&1)
  # Deny is the cancel button, which osascript reports as error -128. Any
  # other failure, such as no GUI, is no answer, never a decision.
  case "$reply" in
    *"button returned:Trust"*"gave up:false"*) decision=trust ;;
    *"(-128)"*) decision=deny ;;
  esac
fi

case "$decision" in
  trust)
    mkdir -p -m 700 "${PRIVATE_DIR}/trusted"
    mv "$snapshot" "${PRIVATE_DIR}/trusted/${id}.toml"
    rm -f "${PRIVATE_DIR}/denied/${id}.toml"
    # Reload now, so the agent's next try already has the project
    # (only if that pid is still the proxy, since SIGHUP ends most programs)
    read -r pid <"$PROXY_PID_FILE" 2>/dev/null
    [[ "${pid:-}" =~ ^[0-9]+$ && "$(ps -p "$pid" -o comm= 2>/dev/null)" == *blindfold-proxy* ]] &&
      kill -HUP "$pid" 2>/dev/null
    ;;
  deny)
    mkdir -p -m 700 "${PRIVATE_DIR}/denied"
    mv "$snapshot" "${PRIVATE_DIR}/denied/${id}.toml"
    ;;
  *)
    # No answer: ask again on the next command
    rm -f "$snapshot"
    ;;
esac
rm -f "$pending"
[[ -t 0 ]] && echo "Done: ${decision:-no decision}."
exit 0
