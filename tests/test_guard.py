"""Tests for secret-guard.sh (PreToolUse hook).

None of these touch a keychain, so they run inside a sandboxed shell too.
"""

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
