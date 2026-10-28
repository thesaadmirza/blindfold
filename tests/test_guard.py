"""Tests for secret-guard.sh (PreToolUse hook).

None of these touch a keychain, so they run inside a sandboxed shell too.
"""

from conftest import (
    build_guard_input,
    execute_wrapped,
    macos_only,
    run_guard,
    wrapped_command,
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
