"""Tests for install-proxy.sh.

curl, uname, sysctl and gh are stubbed on PATH, and the stub curl serves the
release URLs from a local folder. So these run on any OS and never touch the
network or the keychain.
"""

import hashlib
import json
import os
import shutil
import subprocess

import pytest

from conftest import SCRIPTS_DIR

REPO = "thesaadmirza/blindfold"
RELEASES_URL = f"https://github.com/{REPO}/releases/download/"

FAKE_COMMANDS = {
    "curl": f"""#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--proto-redir) [ "$1" = -o ] && out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "$url" >> "$FAKE_CURL_LOG"
case "$url" in {RELEASES_URL}*) ;; *) exit 1 ;; esac
cp "$FAKE_RELEASES/${{url#{RELEASES_URL}}}" "$out" 2>/dev/null || exit 22
""",
    "uname": """#!/bin/sh
case "$1" in
  -s) echo "${FAKE_OS:-Darwin}" ;;
  -m) echo "${FAKE_ARCH:-arm64}" ;;
esac
""",
    "sysctl": """#!/bin/sh
[ -n "$FAKE_TRANSLATED" ] || exit 1
echo "$FAKE_TRANSLATED"
""",
    "gh": """#!/bin/sh
case "$1" in
  auth) exit "${FAKE_GH_AUTH:-1}" ;;
  attestation) echo "$@" >> "$FAKE_GH_LOG"; exit "${FAKE_GH_VERIFY:-0}" ;;
esac
exit 1
""",
}

# A stand-in proxy: it only has to survive the `-check /dev/null` run. The
# arch comment after the exit lets a test tell which binary was installed.
FAKE_PROXY = """#!/bin/sh
[ "$1" = -check ] || exit 1
exit "${FAKE_PROXY_EXIT:-0}"
"""


def _publish(releases, version, archs=("arm64", "amd64")):
    """Write a fake release, returning its folder."""
    folder = releases / version
    folder.mkdir(parents=True)
    lines = []
    for arch in archs:
        asset = folder / f"blindfold-proxy-darwin-{arch}"
        asset.write_text(FAKE_PROXY + f"# {arch}\n")
        lines.append(f"{hashlib.sha256(asset.read_bytes()).hexdigest()}  {asset.name}\n")
    (folder / "SHA256SUMS").write_text("".join(lines))
    return folder


@pytest.fixture(scope="session")
def fake_commands(tmp_path_factory):
    """Write the stubs once: macOS checks every new executable on its first
    run, which costs a few hundred ms per test if they're made per test."""
    fakes = tmp_path_factory.mktemp("fakes")
    for name, body in FAKE_COMMANDS.items():
        (fakes / name).write_text(body)
        (fakes / name).chmod(0o755)
    return fakes


@pytest.fixture()
def install(tmp_path, fake_commands):
    """Copy the script into a fake checkout and return a runner for it."""
    root = tmp_path / "blindfold"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPTS_DIR / "install-proxy.sh", root / "scripts")
    (root / ".claude-plugin").mkdir()
    (root / ".claude-plugin" / "plugin.json").write_text(json.dumps({"version": "1.0.0"}))

    releases = tmp_path / "releases"
    releases.mkdir()
    gh_log = tmp_path / "gh.log"
    curl_log = tmp_path / "curl.log"

    env = {
        **os.environ,
        "PATH": f"{fake_commands}:{os.environ['PATH']}",
        "FAKE_RELEASES": str(releases),
        "FAKE_GH_LOG": str(gh_log),
        "FAKE_CURL_LOG": str(curl_log),
    }

    def run(*args, **overrides):
        return subprocess.run(
            ["bash", str(root / "scripts" / "install-proxy.sh"), *args],
            env={**env, **overrides},
            capture_output=True,
            text=True,
            timeout=30,
        )

    run.releases = releases
    run.gh_log = gh_log
    run.curl_log = curl_log
    run.installed = root / "bin" / "blindfold-proxy"
    return run


def _assert_refused(result, install, message):
    assert result.returncode != 0
    assert message in result.stderr
    assert not install.installed.exists()
    assert not list(install.installed.parent.glob(".install.*"))


class TestInstall:
    def test_installs_the_version_in_plugin_json(self, install):
        release = _publish(install.releases, "v1.0.0")

        result = install()

        assert result.returncode == 0, result.stderr
        assert install.installed.read_bytes() == (release / "blindfold-proxy-darwin-arm64").read_bytes()
        assert os.access(install.installed, os.X_OK)
        assert install.curl_log.read_text().split() == [
            f"{RELEASES_URL}v1.0.0/SHA256SUMS",
            f"{RELEASES_URL}v1.0.0/blindfold-proxy-darwin-arm64",
        ]
        assert "after checking its checksum." in result.stdout
        assert "install gh, log in" in result.stdout
        assert not list(install.installed.parent.glob(".install.*"))

    def test_installs_a_named_version(self, install):
        _publish(install.releases, "v2.1.0")

        result = install("v2.1.0")

        assert result.returncode == 0, result.stderr
        assert "Installed v2.1.0" in result.stdout

    @pytest.mark.parametrize("version", ["latest", "1.0.0", "v1.0", "v1.0.0/../x"])
    def test_refuses_something_that_isnt_a_version(self, install, version):
        _assert_refused(install(version), install, "isn't a version")

    @pytest.mark.parametrize(
        "arch, translated, expected",
        [("arm64", "", "arm64"), ("x86_64", "", "amd64"), ("x86_64", "1", "arm64")],
    )
    def test_picks_the_binary_for_the_machine(self, install, arch, translated, expected):
        _publish(install.releases, "v1.0.0")

        result = install(FAKE_ARCH=arch, FAKE_TRANSLATED=translated)

        assert result.returncode == 0, result.stderr
        assert f"# {expected}" in install.installed.read_text()

    def test_refuses_other_systems(self, install):
        _publish(install.releases, "v1.0.0")

        result = install(FAKE_OS="Linux")

        _assert_refused(result, install, "only made for macOS")
        assert "build-proxy.sh" in result.stderr

    def test_refuses_an_unknown_architecture(self, install):
        _assert_refused(install(FAKE_ARCH="riscv64"), install, "no prebuilt proxy for riscv64")

    def test_reports_a_missing_release(self, install):
        _assert_refused(install(), install, "couldn't download SHA256SUMS for v1.0.0")


class TestChecksums:
    def test_refuses_a_binary_that_doesnt_match(self, install):
        release = _publish(install.releases, "v1.0.0")
        (release / "blindfold-proxy-darwin-arm64").write_text("#!/bin/sh\nexit 0\n")

        _assert_refused(install(), install, "doesn't match its checksum")

    def test_refuses_when_the_binary_has_no_checksum(self, install):
        release = _publish(install.releases, "v1.0.0", archs=("amd64",))
        (release / "blindfold-proxy-darwin-arm64").write_text("#!/bin/sh\nexit 0\n")

        _assert_refused(install(), install, "no single checksum")

    def test_refuses_two_checksums_for_one_binary(self, install):
        release = _publish(install.releases, "v1.0.0")
        sums = release / "SHA256SUMS"
        sums.write_text(sums.read_text() + f"{'0' * 64}  blindfold-proxy-darwin-arm64\n")

        _assert_refused(install(), install, "no single checksum")

    def test_keeps_the_old_binary_when_the_new_one_wont_run(self, install):
        _publish(install.releases, "v1.0.0")
        install.installed.parent.mkdir()
        install.installed.write_text("old")

        result = install(FAKE_PROXY_EXIT="1")

        assert result.returncode != 0
        assert install.installed.read_text() == "old"
        assert not list(install.installed.parent.glob(".install.*"))


class TestProvenance:
    def test_checks_provenance_when_gh_is_logged_in(self, install):
        _publish(install.releases, "v1.0.0")

        result = install(FAKE_GH_AUTH="0")

        assert result.returncode == 0, result.stderr
        assert "checksum and build provenance" in result.stdout
        assert "install gh" not in result.stdout
        call = install.gh_log.read_text().split()
        assert call[:2] == ["attestation", "verify"]
        assert call[call.index("-R") + 1] == REPO
        assert call[call.index("--signer-workflow") + 1] == f"{REPO}/.github/workflows/release.yml"
        assert call[call.index("--source-ref") + 1] == "refs/tags/v1.0.0"
        assert "--deny-self-hosted-runners" in call

    def test_refuses_when_provenance_fails(self, install):
        _publish(install.releases, "v1.0.0")

        _assert_refused(install(FAKE_GH_AUTH="0", FAKE_GH_VERIFY="1"), install, "couldn't confirm")

    def test_skips_provenance_when_gh_isnt_logged_in(self, install):
        _publish(install.releases, "v1.0.0")

        result = install(FAKE_GH_AUTH="1")

        assert result.returncode == 0, result.stderr
        assert not install.gh_log.exists()
