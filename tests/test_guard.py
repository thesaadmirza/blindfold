"""Tests for secret-guard.sh (PreToolUse hook).

None of these touch a keychain, so they run inside a sandboxed shell too.
"""

import json
import os

import pytest

from conftest import (
    SCRIPTS_DIR,
    build_guard_input,
    execute_wrapped,
    macos_only,
    run_guard,
    wrapped_command,
)

EXEC = SCRIPTS_DIR / "secret-exec.sh"
LIST = SCRIPTS_DIR / "secret-list.sh"


class TestExemptScriptsCannotCarryOtherCommands:
    """Blindfold's own scripts skip the sandbox, so the guard must refuse
    anything chained onto them. Runs on every platform: the check comes
    before the platform branch."""

    @pytest.mark.parametrize("command", [
        f"bash {EXEC} 'true'; security find-generic-password -s claude-secrets -w",
        f"bash {EXEC} 'true' && security dump-keychain",
        f"{LIST} || cat ~/.ssh/id_rsa",
        f"bash {EXEC} 'true' | sh",
        f"bash {EXEC} 'true' & security dump-keychain",
        f"bash {EXEC} 'true'\nsecurity dump-keychain",
        f"bash {EXEC} \"$(security dump-keychain)\"",
        f"bash {EXEC} \"`security dump-keychain`\"",
        f"bash {EXEC} $(security dump-keychain)",
        f"bash {EXEC} 'true' > /tmp/out",
        f"bash {EXEC} 'unterminated",
    ])
    def test_chained_command_is_denied(self, command):
        result = run_guard(build_guard_input(command))
        assert result.returncode == 2, (
            f"Expected deny for {command!r}, got exit {result.returncode}, "
            f"stdout={result.stdout!r}"
        )
        assert "DENIED by Blindfold" in result.stderr

    @pytest.mark.parametrize("command", [
        f"bash {EXEC} 'curl -s https://api.example.com | jq .name; echo done'",
        f"bash {EXEC} 'echo \"$(date)\" > /tmp/out'",
        f"bash {EXEC} \"curl -H 'X-Token: {{{{API_KEY}}}}' $BASE_URL\"",
        f"bash {EXEC} 'echo one\necho two'",
        f"bash {EXEC} echo \\; still one argument",
        f"bash {LIST}",
        f"{LIST}",
    ])
    def test_plain_invocation_stays_exempt(self, command):
        result = run_guard(build_guard_input(command))
        assert result.returncode == 0, f"stderr={result.stderr!r}"
        assert result.stdout.strip() == "", (
            f"Exempt commands should produce no output, got: {result.stdout!r}"
        )


@macos_only
class TestWrappedCommandRunsAsWritten:
    """The sandbox wrapper must not change what the command does."""

    def _run_through_guard(self, command: str) -> str:
        result = run_guard(build_guard_input(command))
        assert result.returncode == 0, f"stderr={result.stderr!r}"
        wrapped = wrapped_command(result.stdout)
        assert wrapped is not None, f"Guard did not wrap: {result.stdout!r}"
        executed = execute_wrapped(wrapped)
        assert executed.returncode == 0, f"stderr={executed.stderr!r}"
        return executed.stdout

    def test_single_quotes(self):
        assert self._run_through_guard("echo 'hello world'") == "hello world\n"

    def test_quote_inside_double_quotes(self):
        assert self._run_through_guard('echo "it\'s here"') == "it's here\n"

    def test_multi_line_command(self):
        assert self._run_through_guard("echo one\necho two") == "one\ntwo\n"

    def test_backslash_is_kept(self):
        assert self._run_through_guard(r"printf '%s\n' 'a\b'") == "a\\b\n"


@macos_only
class TestReadGuard:
    """Read is refused when the file holds a stored secret value.

    A stub `security` on PATH stands in for the keychain, so these run
    without one and never open a keychain dialog."""

    SECRET_NAME = "BFTEST_READ"
    SECRET_VALUE = "read-guard-value-98765"

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, temp_registry):
        temp_registry.write_text(json.dumps({
            "version": 3,
            "global": {"secrets": [self.SECRET_NAME]},
            "projects": {},
        }))
        stub_dir = tmp_path / "bin"
        stub_dir.mkdir()
        stub = stub_dir / "security"
        stub.write_text(
            "#!/bin/sh\n"
            f'case "$*" in *"global:{self.SECRET_NAME}"*-w*) '
            f"printf '%s' '{self.SECRET_VALUE}' ;; *) exit 44 ;; esac\n"
        )
        stub.chmod(0o755)

        self.env = os.environ.copy()
        self.env.pop("BLINDFOLD_KEYCHAIN", None)
        self.env["BLINDFOLD_REGISTRY"] = str(temp_registry)
        self.env["PATH"] = f"{stub_dir}:{self.env['PATH']}"
        self.dir = tmp_path

    def _read(self, path):
        hook_input = json.dumps({
            "tool_name": "Read",
            "tool_input": {"file_path": str(path)},
        })
        return run_guard(hook_input, self.env)

    def test_file_holding_a_secret_is_denied(self):
        leaked = self.dir / "out.txt"
        leaked.write_text(f"token={self.SECRET_VALUE}\n")

        result = self._read(leaked)

        assert result.returncode == 2, f"stderr={result.stderr!r}"
        assert self.SECRET_NAME in result.stderr
        assert self.SECRET_VALUE not in result.stderr

    def test_ordinary_file_is_allowed(self):
        clean = self.dir / "notes.txt"
        clean.write_text("nothing to see here\n")

        result = self._read(clean)

        assert result.returncode == 0, f"stderr={result.stderr!r}"
        assert result.stdout.strip() == ""

    def test_missing_file_is_left_to_read(self):
        result = self._read(self.dir / "does-not-exist")

        assert result.returncode == 0
        assert result.stdout.strip() == ""
