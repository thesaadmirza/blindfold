"""Tests for egress lockdown (BLINDFOLD_EGRESS=proxy).

The wiring tests only inspect what the guard emits, so they run anywhere on
macOS. The runtime tests apply the egress sandbox for real and skip where
macOS refuses it, which happens inside another sandbox (for example a shell
that is itself sandboxed).
"""

import http.server
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from conftest import (
    SCRIPTS_DIR,
    build_guard_input,
    execute_wrapped,
    macos_only,
    run_guard,
    run_script,
    wrap_through_guard,
)

REPO_PROXY = SCRIPTS_DIR.parent / "bin" / "blindfold-proxy"
BASE_PROFILE = SCRIPTS_DIR / "sandbox.sb"
EGRESS_PROFILE = SCRIPTS_DIR / "sandbox-egress.sb"
PY = "python3 -I -c"
DIRECT_CONNECT = f"{PY} \"import socket; socket.create_connection(('1.1.1.1', 443), 3)\""
DNS_LOOKUP = f"{PY} \"import socket; socket.gethostbyname('example.com')\""
CURL_EXAMPLE = "curl -s -o /dev/null -w %{{http_code}} --max-time 15 {extra} https://example.com/"
# example.com answers any request, so it stands in for an API here
POLICY = '[secrets.BFTEST_TOKEN]\nhosts = ["example.com"]\nheader = "X-Test-Token"\n'

pytestmark = macos_only


@pytest.fixture(scope="session")
def proxy_bin(tmp_path_factory):
    if REPO_PROXY.exists():
        return REPO_PROXY
    if shutil.which("go") is None:
        pytest.skip("Go is not installed and bin/blindfold-proxy is not built")
    out = tmp_path_factory.mktemp("proxy") / "blindfold-proxy"
    subprocess.run(["go", "build", "-o", str(out), "."],
                   cwd=SCRIPTS_DIR.parent / "proxy", check=True, timeout=300)
    return out


# Where lib.sh puts things under BLINDFOLD_CONFIG_DIR
def _config_dir(env) -> Path:
    return Path(env["BLINDFOLD_CONFIG_DIR"])


def _port_file(env) -> Path:
    return _config_dir(env) / "run" / "proxy.port"


def _pid_file(env) -> Path:
    return _port_file(env).with_suffix(".pid")


def _ca_bundle(env) -> Path:
    return _port_file(env).parent / "ca-bundle.pem"


def _write_policy(env, body):
    path = _config_dir(env) / "policy.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)


def _env_words(wrapped):
    """NAME=value words the guard sets before sandbox-exec"""
    words = shlex.split(wrapped)
    return [w for w in words[1:words.index("sandbox-exec")] if "=" in w]


@pytest.fixture()
def egress_env(tmp_path, temp_registry, proxy_bin):
    env = os.environ.copy()
    env.pop("BLINDFOLD_KEYCHAIN", None)
    env.update({
        "BLINDFOLD_EGRESS": "proxy",
        "BLINDFOLD_PROXY_BIN": str(proxy_bin),
        "BLINDFOLD_CONFIG_DIR": str(tmp_path / "config"),
        "BLINDFOLD_EGRESS_LOG": str(tmp_path / "egress.jsonl"),
        "BLINDFOLD_REGISTRY": str(temp_registry),
    })
    yield env
    try:
        os.kill(int(_pid_file(env).read_text()), signal.SIGTERM)
    except (FileNotFoundError, ProcessLookupError, ValueError):
        pass


class TestEgressWiring:

    def test_guard_starts_the_proxy_and_uses_the_egress_profile(self, egress_env):
        wrapped = wrap_through_guard("echo hi", egress_env)

        port = _port_file(egress_env).read_text().strip()
        assert str(EGRESS_PROFILE) in wrapped
        assert re.search(rf"HTTPS_PROXY=http://blindfold:[0-9a-f]{{32}}@127\.0\.0\.1:{port}'", wrapped)
        assert "NO_PROXY=localhost,127.0.0.1,::1" in wrapped

    def test_a_running_proxy_is_reused(self, egress_env):
        wrap_through_guard("echo one", egress_env)
        first_port = _port_file(egress_env).read_text()
        first_pid = _pid_file(egress_env).read_text()

        wrap_through_guard("echo two", egress_env)

        assert _port_file(egress_env).read_text() == first_port
        assert _pid_file(egress_env).read_text() == first_pid

    def test_missing_proxy_binary_is_denied(self, egress_env):
        egress_env["BLINDFOLD_PROXY_BIN"] = "/nonexistent/blindfold-proxy"

        result = run_guard(build_guard_input("echo hi"), egress_env)

        assert result.returncode == 2
        assert "build-proxy.sh" in result.stderr

    def test_egress_is_off_by_default(self, egress_env):
        egress_env.pop("BLINDFOLD_EGRESS")

        wrapped = wrap_through_guard("echo hi", egress_env)

        assert str(BASE_PROFILE) in wrapped
        assert "HTTPS_PROXY" not in wrapped

    def test_sandbox_is_told_which_folders_to_protect(self, egress_env):
        wrapped = wrap_through_guard("echo hi", egress_env)

        assert f"CONFIG_DIR={_config_dir(egress_env).resolve()}" in wrapped
        assert f"INSTALL_DIR={SCRIPTS_DIR.parent.resolve()}" in wrapped

    def test_egress_profile_keeps_every_base_rule(self):
        egress_rules = set(EGRESS_PROFILE.read_text().splitlines())
        missing = [line for line in BASE_PROFILE.read_text().splitlines() if line not in egress_rules]

        assert not missing, f"sandbox-egress.sb is missing rules from sandbox.sb: {missing}"

    def test_no_policy_means_no_local_ca(self, egress_env):
        wrapped = wrap_through_guard("echo hi", egress_env)

        assert "SSL_CERT_FILE" not in wrapped
        assert "{{" not in wrapped

    def test_policy_secrets_get_placeholders_and_the_ca(self, egress_env):
        _write_policy(egress_env, POLICY)

        wrapped = wrap_through_guard("echo hi", egress_env)

        bundle = _ca_bundle(egress_env)
        for var in ["SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"]:
            assert f"{var}={bundle}" in wrapped
        assert "BFTEST_TOKEN={{BFTEST_TOKEN}}" in wrapped
        assert bundle.read_text().count("BEGIN CERTIFICATE") >= 2, "bundle is missing the roots or the CA"

    def test_a_policy_secret_cannot_shadow_what_the_guard_sets(self, egress_env):
        # The guard sets these itself, so proxy/policy.go must refuse them as names
        _write_policy(egress_env, POLICY)
        own = {w.split("=", 1)[0].upper() for w in _env_words(wrap_through_guard("echo hi", egress_env))
               if not w.endswith("}}")}
        go = (SCRIPTS_DIR.parent / "proxy" / "policy.go").read_text()
        reserved = set(re.findall(r'"([A-Z_]+)"', go[go.index("var reservedNames"):go.index("var reservedPrefixes")]))

        assert own <= reserved, f"missing from reservedNames in policy.go: {sorted(own - reserved)}"

    def test_invalid_policy_is_denied_with_the_reason(self, egress_env):
        _write_policy(egress_env, '[secrets.X]\nhosts = ["*.example.com"]\nheader = "X"\n')

        result = run_guard(build_guard_input("echo hi"), egress_env)

        assert result.returncode == 2
        assert "wildcards are not allowed" in result.stderr

    def test_rebuilt_proxy_replaces_the_running_one(self, egress_env, proxy_bin, tmp_path):
        copy = tmp_path / "blindfold-proxy"
        shutil.copy2(proxy_bin, copy)
        egress_env["BLINDFOLD_PROXY_BIN"] = str(copy)
        wrap_through_guard("echo one", egress_env)
        old_pid = int(_pid_file(egress_env).read_text())
        future = time.time() + 60
        os.utime(copy, (future, future))

        # The proxy notices its binary changed and exits within a second or so
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(old_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            pytest.fail("the old proxy kept running after its binary changed")
        wrap_through_guard("echo two", egress_env)

        assert int(_pid_file(egress_env).read_text()) != old_pid




@pytest.fixture()
def project(tmp_path, egress_env):
    """A project folder, with the approval dialog swapped for a stub that
    records the folder it was asked about"""
    folder = tmp_path / "proj"
    folder.mkdir()
    stub = tmp_path / "approve-stub.sh"
    stub.write_text(f'#!/bin/bash\necho "$1" > {tmp_path / "asked"}\n')
    egress_env["BLINDFOLD_APPROVE_CMD"] = str(stub)
    return folder


def _private(env) -> Path:
    return _config_dir(env) / "private"


def _token_line(env):
    """token, id and path of the only project the guard has seen"""
    lines = (_private(env) / "tokens.tsv").read_text().splitlines()
    assert len(lines) == 1, lines
    return lines[0].split("\t")


class TestProjectPolicies:


    def test_each_project_gets_its_own_proxy_password(self, egress_env, project):
        first = wrap_through_guard("echo hi", egress_env, cwd=project)
        again = wrap_through_guard("echo hi", egress_env, cwd=project)

        token, project_id, path = _token_line(egress_env)
        assert re.fullmatch(r"[0-9a-f]{32}", token) and re.fullmatch(r"[0-9a-f]{12}", project_id)
        assert Path(path).resolve() == project.resolve()
        assert f"HTTPS_PROXY=http://blindfold:{token}@127.0.0.1:" in first
        assert first == again
        assert oct((_private(egress_env) / "tokens.tsv").stat().st_mode & 0o777) == "0o600"

    def test_sandbox_is_told_about_the_private_folder(self, egress_env, project):
        wrapped = wrap_through_guard("echo hi", egress_env, cwd=project)

        assert f"PRIVATE_DIR={_config_dir(egress_env).resolve()}/private" in wrapped


def _egress_sandbox_applies() -> bool:
    # Evaluated at collection time on every platform, so check first
    if shutil.which("sandbox-exec") is None:
        return False
    params = [f"{p}=/nonexistent" for p in ("CONFIG_DIR", "INSTALL_DIR", "PRIVATE_DIR", "PROJECT_POLICY")]
    r = subprocess.run(["sandbox-exec", *[w for p in params for w in ("-D", p)],
                        "-f", str(EGRESS_PROFILE), "/usr/bin/true"],
                       capture_output=True, text=True)
    return r.returncode == 0


def _online() -> bool:
    try:
        socket.create_connection(("example.com", 443), timeout=3).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _egress_sandbox_applies(),
                    reason="macOS refuses a network sandbox inside another sandbox")
class TestEgressRuntime:

    @pytest.mark.parametrize("command", [DIRECT_CONNECT, DNS_LOOKUP], ids=["direct-connect", "dns"])
    def test_traffic_that_skips_the_proxy_is_refused(self, egress_env, command):
        result = execute_wrapped(wrap_through_guard(command, egress_env))

        assert result.returncode != 0, "traffic got out of the sandbox without the proxy"

    def test_loopback_still_works(self, egress_env):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/"
            cmd = f"curl -s -o /dev/null -w %{{http_code}} {url}"
            result = execute_wrapped(wrap_through_guard(cmd, egress_env))
        finally:
            srv.shutdown()

        assert result.stdout == "200", f"stdout={result.stdout!r} stderr={result.stderr!r}"

    def test_secret_exec_is_locked_down_too(self, egress_env):
        result = run_script("secret-exec.sh", [DIRECT_CONNECT], env=egress_env)

        assert result.returncode != 0, "secret-exec let a direct connection out"

    def test_commands_cannot_write_blindfold_files(self, egress_env, tmp_path):
        policy = _config_dir(egress_env) / "policy.toml"
        script = SCRIPTS_DIR / ".write-probe"
        fine = tmp_path / "fine.txt"
        cmd = f"echo x > {policy}; echo x > {script}; echo x > {fine}"
        try:
            result = execute_wrapped(wrap_through_guard(cmd, egress_env))
            assert not policy.exists(), "a sandboxed command wrote the policy"
            assert not script.exists(), "a sandboxed command wrote into Blindfold's scripts"
            assert fine.exists(), f"ordinary writes broke: stderr={result.stderr!r}"
        finally:
            script.unlink(missing_ok=True)

    def test_commands_cannot_read_project_tokens(self, egress_env, project):
        wrap_through_guard("echo hi", egress_env, cwd=project)
        tokens = _private(egress_env) / "tokens.tsv"

        result = execute_wrapped(wrap_through_guard(f"cat {tokens}", egress_env, cwd=project))

        assert result.returncode != 0 and _token_line(egress_env)[0] not in result.stdout

    @pytest.mark.skipif(not _online(), reason="needs internet access")
    def test_https_goes_through_the_proxy_and_is_logged(self, egress_env):
        result = execute_wrapped(wrap_through_guard(CURL_EXAMPLE.format(extra=""), egress_env))

        assert result.stdout == "200", f"stdout={result.stdout!r} stderr={result.stderr!r}"
        _wait_for_entry(egress_env, lambda e: e["kind"] == "connect" and e["host"] == "example.com:443")

    @pytest.mark.skipif(not _online(), reason="needs internet access")
    def test_policy_host_is_intercepted_and_trusted(self, egress_env):
        _write_policy(egress_env, POLICY)

        result = execute_wrapped(wrap_through_guard(CURL_EXAMPLE.format(extra=""), egress_env))

        assert result.stdout == "200", f"curl did not trust the local CA: stderr={result.stderr!r}"
        _wait_for_entry(egress_env, lambda e: e["kind"] == "https" and e["host"] == "example.com")

    @pytest.mark.skipif(not _online(), reason="needs internet access")
    @pytest.mark.parametrize("header", ["{{BFTEST_TOKEN}}", "$BFTEST_TOKEN"], ids=["placeholder", "env-var"])
    def test_placeholder_is_filled_from_the_keychain(self, egress_env, temp_keychain, header):
        subprocess.run(["security", "add-generic-password", "-a", "claude-secret:global:BFTEST_TOKEN",
                        "-s", "claude-secrets", "-w", "bftest-real-value", str(temp_keychain)], check=True)
        egress_env["BLINDFOLD_KEYCHAIN"] = str(temp_keychain)
        _write_policy(egress_env, POLICY)
        cmd = CURL_EXAMPLE.format(extra=f'-H "X-Test-Token: {header}"')

        result = execute_wrapped(wrap_through_guard(cmd, egress_env))

        assert result.stdout == "200", f"stdout={result.stdout!r} stderr={result.stderr!r}"
        _wait_for_entry(egress_env, lambda e: e["kind"] == "https" and e.get("secrets") == ["BFTEST_TOKEN"])



def _wait_for_entry(env, match):
    """The proxy writes a line as each request or tunnel finishes, which can be
    just after the command exits, so poll for a moment."""
    log = Path(env["BLINDFOLD_EGRESS_LOG"])
    deadline = time.monotonic() + 5
    entries = []
    while time.monotonic() < deadline:
        entries = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        if any(match(e) for e in entries):
            return
        time.sleep(0.1)
    pytest.fail(f"no matching entry in the egress log: {entries}")
