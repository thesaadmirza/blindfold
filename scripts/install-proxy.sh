#!/usr/bin/env bash
# Downloads a prebuilt egress proxy into bin/blindfold-proxy, so you don't need
# Go. The binary is checked against the release's SHA-256 checksums before it's
# used. If gh is installed and logged in, GitHub's build provenance is checked
# too: that proves the binary was built from the tag by the release workflow.
#
# Usage: install-proxy.sh [vX.Y.Z]   (defaults to the version in plugin.json)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="thesaadmirza/blindfold"
BUILD_HINT="Build it from source with scripts/build-proxy.sh instead."

[[ "$(uname -s)" == Darwin ]] || { echo "ERROR: prebuilt proxies are only made for macOS. ${BUILD_HINT}" >&2; exit 1; }
command -v jq &>/dev/null || { echo "ERROR: jq is required (brew install jq)." >&2; exit 1; }

version="${1:-v$(jq -r .version "${ROOT}/.claude-plugin/plugin.json")}"
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "ERROR: '${version}' isn't a version like v1.2.3." >&2; exit 1; }

arch=$(uname -m)
case "$arch" in
  arm64) ;;
  # A shell running under Rosetta reports x86_64 on Apple Silicon
  x86_64) [[ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" == 1 ]] && arch=arm64 || arch=amd64 ;;
  *) echo "ERROR: there's no prebuilt proxy for ${arch}. ${BUILD_HINT}" >&2; exit 1 ;;
esac

asset="blindfold-proxy-darwin-${arch}"
base="https://github.com/${REPO}/releases/download/${version}"

mkdir -p "${ROOT}/bin"
tmp=$(mktemp -d "${ROOT}/bin/.install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

for file in SHA256SUMS "$asset"; do
  curl -fsSL --proto-redir =https -o "${tmp}/${file}" "${base}/${file}" \
    || { echo "ERROR: couldn't download ${file} for ${version}." >&2; exit 1; }
done

want=$(awk -v f="$asset" '$2 == f { print $1 }' "${tmp}/SHA256SUMS")
[[ "$want" =~ ^[0-9a-f]{64}$ ]] || { echo "ERROR: SHA256SUMS has no single checksum for ${asset}." >&2; exit 1; }
got=$(shasum -a 256 "${tmp}/${asset}" | awk '{ print $1 }')
[[ "$got" == "$want" ]] || { echo "ERROR: ${asset} doesn't match its checksum, so it wasn't installed." >&2; exit 1; }

if command -v gh &>/dev/null && gh auth status &>/dev/null; then
  gh attestation verify "${tmp}/${asset}" -R "$REPO" \
    --signer-workflow "${REPO}/.github/workflows/release.yml" \
    --source-ref "refs/tags/${version}" --deny-self-hosted-runners >/dev/null \
    || { echo "ERROR: GitHub couldn't confirm ${asset} was built from ${version} by the release workflow, so it wasn't installed." >&2; exit 1; }
  checked="its checksum and build provenance"
else
  checked="its checksum"
  tip="To check its build provenance too, install gh, log in, and run this again."
fi

chmod +x "${tmp}/${asset}"
# Run it once now: macOS checks a new binary on its first launch, which can
# take seconds, and that should happen here rather than inside a hook
"${tmp}/${asset}" -check /dev/null >/dev/null
mv -f "${tmp}/${asset}" "${ROOT}/bin/blindfold-proxy"

echo "Installed ${version} (${arch}) to ${ROOT}/bin/blindfold-proxy, after checking ${checked}."
[[ -z "${tip:-}" ]] || echo "$tip"
