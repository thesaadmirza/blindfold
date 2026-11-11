#!/usr/bin/env bash
# Builds the egress proxy into bin/blindfold-proxy. Needs Go 1.24 or newer.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v go &>/dev/null || { echo "ERROR: Go is required to build the proxy (brew install go)." >&2; exit 1; }

mkdir -p "${ROOT}/bin"
(cd "${ROOT}/proxy" && go build -trimpath -o "${ROOT}/bin/blindfold-proxy" .)
# Run it once now: macOS checks a new binary on its first launch, which can
# take seconds, and that should happen here rather than inside a hook
"${ROOT}/bin/blindfold-proxy" -check /dev/null >/dev/null
echo "Built ${ROOT}/bin/blindfold-proxy"
