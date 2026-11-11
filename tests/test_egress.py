"""Tests for egress lockdown (BLINDFOLD_EGRESS=proxy).

The wiring tests only inspect what the guard emits, so they run anywhere on
macOS. The runtime tests apply the egress sandbox for real and skip where
macOS refuses it, which happens inside another sandbox (for example a shell
that is itself sandboxed).
"""

import http.server
import json
import os
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


def _port_file(env) -> Path:
    return Path(env["BLINDFOLD_PROXY_PORT_FILE"])


def _pid_file(env) -> Path:
    return _port_file(env).with_suffix(".pid")


@pytest.fixture()
def egress_env(tmp_path, temp_registry, proxy_bin):
    env = os.environ.copy()
    env.pop("BLINDFOLD_KEYCHAIN", None)
    env.update({
        "BLINDFOLD_EGRESS": "proxy",
        "BLINDFOLD_PROXY_BIN": str(proxy_bin),
        "BLINDFOLD_PROXY_PORT_FILE": str(tmp_path / "run" / "proxy.port"),
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
        assert f"HTTPS_PROXY=http://127.0.0.1:{port}" in wrapped
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

    def test_egress_profile_keeps_every_base_rule(self):
        egress_rules = set(EGRESS_PROFILE.read_text().splitlines())
        missing = [line for line in BASE_PROFILE.read_text().splitlines() if line not in egress_rules]

        assert not missing, f"sandbox-egress.sb is missing rules from sandbox.sb: {missing}"


def _egress_sandbox_applies() -> bool:
    # Evaluated at collection time on every platform, so check first
    if shutil.which("sandbox-exec") is None:
        return False
    r = subprocess.run(["sandbox-exec", "-f", str(EGRESS_PROFILE), "/usr/bin/true"],
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

    @pytest.mark.skipif(not _online(), reason="needs internet access")
    def test_https_goes_through_the_proxy_and_is_logged(self, egress_env):
        cmd = "curl -s -o /dev/null -w %{http_code} --max-time 15 https://example.com/"

        result = execute_wrapped(wrap_through_guard(cmd, egress_env))

        assert result.stdout == "200", f"stdout={result.stdout!r} stderr={result.stderr!r}"
        # The proxy writes the line as the tunnel closes, just after curl exits
        log = Path(egress_env["BLINDFOLD_EGRESS_LOG"])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            entries = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            if any(e["kind"] == "connect" and e["host"] == "example.com:443" for e in entries):
                return
            time.sleep(0.1)
        pytest.fail(f"no connect entry for example.com:443 in {entries}")
