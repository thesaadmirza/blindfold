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

import pytest

from conftest import (
    SCRIPTS_DIR,
    build_guard_input,
    execute_wrapped,
    macos_only,
    run_guard,
    run_script,
    wrapped_command,
)

REPO_PROXY = SCRIPTS_DIR.parent / "bin" / "blindfold-proxy"
EGRESS_PROFILE = SCRIPTS_DIR / "sandbox-egress.sb"

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


@pytest.fixture()
def egress_env(tmp_path, temp_registry, proxy_bin):
    run_dir = tmp_path / "run"
    env = os.environ.copy()
    env.update({
        "BLINDFOLD_EGRESS": "proxy",
        "BLINDFOLD_PROXY_BIN": str(proxy_bin),
        "BLINDFOLD_PROXY_PORT_FILE": str(run_dir / "proxy.port"),
        "BLINDFOLD_EGRESS_LOG": str(tmp_path / "egress.jsonl"),
        "BLINDFOLD_REGISTRY": str(temp_registry),
    })
    yield env
    pid_file = run_dir / "proxy.pid"
    if pid_file.exists():
        try:
            os.kill(int(pid_file.read_text()), signal.SIGTERM)
        except (ProcessLookupError, ValueError):
            pass


def _port(env) -> str:
    with open(env["BLINDFOLD_PROXY_PORT_FILE"]) as f:
        return f.read().strip()


def _wrap(command: str, env) -> str:
    result = run_guard(build_guard_input(command), env)
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    wrapped = wrapped_command(result.stdout)
    assert wrapped is not None, f"Guard did not wrap: {result.stdout!r}"
    return wrapped


class TestEgressWiring:

    def test_guard_starts_the_proxy_and_uses_the_egress_profile(self, egress_env):
        wrapped = _wrap("echo hi", egress_env)

        port = _port(egress_env)
        assert str(EGRESS_PROFILE) in wrapped
        assert f"HTTPS_PROXY=http://127.0.0.1:{port}" in wrapped
        assert "NO_PROXY=localhost,127.0.0.1,::1" in wrapped

    def test_a_running_proxy_is_reused(self, egress_env):
        _wrap("echo one", egress_env)
        pid_file = egress_env["BLINDFOLD_PROXY_PORT_FILE"].replace(".port", ".pid")
        first_port, first_pid = _port(egress_env), open(pid_file).read()

        _wrap("echo two", egress_env)

        assert _port(egress_env) == first_port
        assert open(pid_file).read() == first_pid

    def test_missing_proxy_binary_is_denied(self, egress_env):
        egress_env["BLINDFOLD_PROXY_BIN"] = "/nonexistent/blindfold-proxy"

        result = run_guard(build_guard_input("echo hi"), egress_env)

        assert result.returncode == 2
        assert "build-proxy.sh" in result.stderr

    def test_egress_is_off_by_default(self, egress_env):
        egress_env.pop("BLINDFOLD_EGRESS")

        wrapped = _wrap("echo hi", egress_env)

        assert str(SCRIPTS_DIR / "sandbox.sb") in wrapped
        assert "HTTPS_PROXY" not in wrapped


def _egress_sandbox_applies() -> bool:
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

    PY = "python3 -I -c"

    def test_direct_connection_out_is_refused(self, egress_env):
        cmd = f"{self.PY} \"import socket; socket.create_connection(('1.1.1.1', 443), 3)\""

        result = execute_wrapped(_wrap(cmd, egress_env))

        assert result.returncode != 0, "a direct connection got out of the sandbox"

    def test_dns_lookup_is_refused(self, egress_env):
        cmd = f"{self.PY} \"import socket; socket.gethostbyname('example.com')\""

        result = execute_wrapped(_wrap(cmd, egress_env))

        assert result.returncode != 0, "a DNS lookup worked inside the sandbox"

    def test_loopback_still_works(self, egress_env):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/"
            result = execute_wrapped(_wrap(f"curl -s -o /dev/null -w %{{http_code}} {url}", egress_env))
        finally:
            srv.shutdown()

        assert result.stdout == "200", f"stdout={result.stdout!r} stderr={result.stderr!r}"

    def test_secret_exec_is_locked_down_too(self, egress_env):
        cmd = f"{self.PY} \"import socket; socket.create_connection(('1.1.1.1', 443), 3)\""

        result = run_script("secret-exec.sh", [cmd], env=egress_env)

        assert result.returncode != 0, "secret-exec let a direct connection out"

    @pytest.mark.skipif(not _online(), reason="needs internet access")
    def test_https_goes_through_the_proxy_and_is_logged(self, egress_env):
        cmd = "curl -s -o /dev/null -w %{http_code} --max-time 15 https://example.com/"

        result = execute_wrapped(_wrap(cmd, egress_env))

        assert result.stdout == "200", f"stdout={result.stdout!r} stderr={result.stderr!r}"
        with open(egress_env["BLINDFOLD_EGRESS_LOG"]) as f:
            entries = [json.loads(line) for line in f]
        assert any(e["kind"] == "connect" and e["host"] == "example.com:443" for e in entries)
