"""Phase 2 integration tests — automated from the TESTING.md manual suite.

These tests exercise the full script pipeline (guard hook, secret-exec,
redact hook) against the real macOS Keychain and Seatbelt sandbox.

Mapping to TESTING.md Phase 2 manual tests:
    2.1 Hook loads                           -> TestGuardHookBasics
    2.2 Guard blocks find-generic-password   -> TestSandboxBlocksKeychainRead
    2.3 Guard blocks dump-keychain           -> TestSandboxBlocksKeychainDump
    2.4 Guard allows safe security command   -> TestSandboxAllowsSafeCommand
    2.6 secret-exec placeholder + redaction  -> TestSecretExecPlaceholder
    2.7 Redact hook fires on leaked output   -> TestRedactHookFiresOnLeak

Skipped (obsolete — env-profile feature removed in upstream 94a7a83):
    2.5 secret-list envProfiles
    2.8 Guard blocks cat .env
    2.9 Guard blocks Read on .env
TODO: reintroduce these tests if env-profile support is ever added back.

All tests are macOS-only (they exercise Seatbelt sandbox and macOS Keychain).
They skip on Linux/Windows via the @macos_only marker.
"""

import json
import subprocess
from pathlib import Path

import pytest

from conftest import (
    build_guard_input,
    build_redact_input,
    macos_only,
    run_script,
    SCRIPTS_DIR,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_guard(hook_input: str, env: dict) -> subprocess.CompletedProcess:
    """Run secret-guard.sh with the given hook input on stdin."""
    return subprocess.run(
        ["bash", str(SCRIPTS_DIR / "secret-guard.sh")],
        input=hook_input,
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )


def _run_redact(hook_input: str, env: dict) -> subprocess.CompletedProcess:
    """Run secret-redact.sh with the given hook input on stdin."""
    return subprocess.run(
        ["bash", str(SCRIPTS_DIR / "secret-redact.sh")],
        input=hook_input,
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )


def _extract_wrapped_command(guard_stdout: str) -> str | None:
    """Parse guard stdout and extract the sandboxed command.

    On macOS with sandbox-exec available, the guard emits a
    hookSpecificOutput JSON with `updatedInput.command` set to the
    wrapped command. Returns None if the guard didn't emit JSON
    (e.g., exempt command, or non-macOS fallback path).
    """
    try:
        payload = json.loads(guard_stdout)
        return payload["hookSpecificOutput"]["updatedInput"]["command"]
    except (json.JSONDecodeError, KeyError):
        return None


def _execute_wrapped(wrapped_cmd: str) -> subprocess.CompletedProcess:
    """Execute a sandbox-wrapped command string."""
    return subprocess.run(
        ["bash", "-c", wrapped_cmd],
        capture_output=True,
        text=True,
        timeout=10,
    )


# ---------------------------------------------------------------------------
# 2.1 — Hook loads and wraps benign commands
# ---------------------------------------------------------------------------

@macos_only
class TestGuardHookBasics:
    """2.1 — Guard hook accepts benign input and wraps commands in sandbox."""

    def test_guard_wraps_benign_command(self, env_with_registry):
        """Guard emits hookSpecificOutput JSON with command wrapped in sandbox-exec."""
        hook_input = build_guard_input("echo hook test")
        result = _run_guard(hook_input, env_with_registry)

        assert result.returncode == 0, (
            f"Guard should exit 0 on benign command, got {result.returncode}. "
            f"stderr={result.stderr}"
        )
        assert result.stdout.strip(), "Guard should emit JSON on stdout"

        wrapped = _extract_wrapped_command(result.stdout)
        assert wrapped is not None, (
            f"Guard output missing hookSpecificOutput: {result.stdout}"
        )
        assert "sandbox-exec" in wrapped, (
            "Guard should wrap command in sandbox-exec"
        )
        assert "echo hook test" in wrapped, (
            "Wrapped command should contain the original command"
        )

    def test_guard_ignores_non_bash_tools(self, env_with_registry):
        """Guard should exit 0 silently for non-Bash tools."""
        hook_input = json.dumps({
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/foo"},
        })
        result = _run_guard(hook_input, env_with_registry)

        assert result.returncode == 0
        assert result.stdout.strip() == "", (
            "Non-Bash tools should produce no guard output"
        )

    def test_guard_exempts_blindfold_scripts(self, env_with_registry):
        """Commands invoking blindfold's own scripts should pass through without wrapping."""
        exec_path = str(SCRIPTS_DIR / "secret-exec.sh")
        hook_input = build_guard_input(f"bash {exec_path} 'echo hi'")
        result = _run_guard(hook_input, env_with_registry)

        assert result.returncode == 0
        # Exempt commands exit 0 with no JSON output
        assert result.stdout.strip() == "", (
            f"Exempt commands should produce no output, got: {result.stdout}"
        )


# ---------------------------------------------------------------------------
# 2.2 / 2.3 — Sandbox blocks keychain access at runtime
# ---------------------------------------------------------------------------

@macos_only
class TestSandboxBlocksKeychainRead:
    """2.2 — Sandbox blocks `security find-generic-password` when wrapped via guard."""

    def test_wrapped_find_generic_password_is_blocked(self, env_with_registry):
        """The sandbox must prevent keychain Mach IPC from inside a wrapped command."""
        # Build a guard request for a keychain read
        hook_input = build_guard_input(
            "security find-generic-password -a claude-secret:global:BFTEST_BLOCK "
            "-s claude-secrets -w"
        )
        guard_result = _run_guard(hook_input, env_with_registry)
        assert guard_result.returncode == 0, "Guard wraps, doesn't deny directly"

        wrapped = _extract_wrapped_command(guard_result.stdout)
        assert wrapped is not None, "Guard should emit wrapped command"
        assert "sandbox-exec" in wrapped

        # Execute the sandbox-wrapped command
        exec_result = _execute_wrapped(wrapped)

        # Sandbox blocks the SecurityServer Mach IPC → security command fails.
        # Exact exit code varies, but the combined output should mention the
        # sandbox denial or the command should fail nonzero.
        assert exec_result.returncode != 0, (
            f"Sandbox should block keychain read, but wrapped command succeeded. "
            f"stdout={exec_result.stdout!r} stderr={exec_result.stderr!r}"
        )


@macos_only
class TestSandboxBlocksKeychainDump:
    """2.3 — Sandbox blocks `security dump-keychain` when wrapped via guard."""

    def test_wrapped_dump_keychain_is_blocked(self, env_with_registry):
        """dump-keychain must fail inside the sandbox."""
        hook_input = build_guard_input("security dump-keychain")
        guard_result = _run_guard(hook_input, env_with_registry)
        assert guard_result.returncode == 0

        wrapped = _extract_wrapped_command(guard_result.stdout)
        assert wrapped is not None

        exec_result = _execute_wrapped(wrapped)
        assert exec_result.returncode != 0, (
            f"Sandbox should block dump-keychain, but wrapped command succeeded. "
            f"stdout={exec_result.stdout!r} stderr={exec_result.stderr!r}"
        )


# ---------------------------------------------------------------------------
# 2.4 — Sandbox allows non-keychain commands
# ---------------------------------------------------------------------------

@macos_only
class TestSandboxAllowsSafeCommand:
    """2.4 — Harmless commands should run successfully inside the sandbox."""

    def test_wrapped_echo_succeeds(self, env_with_registry):
        """A plain `echo` must succeed inside the sandbox wrapper."""
        hook_input = build_guard_input("echo safe output")
        guard_result = _run_guard(hook_input, env_with_registry)
        assert guard_result.returncode == 0

        wrapped = _extract_wrapped_command(guard_result.stdout)
        assert wrapped is not None

        exec_result = _execute_wrapped(wrapped)
        assert exec_result.returncode == 0, (
            f"Sandbox should allow harmless echo, but it failed. "
            f"stderr={exec_result.stderr!r}"
        )
        assert "safe output" in exec_result.stdout


# ---------------------------------------------------------------------------
# 2.6 — secret-exec.sh placeholder substitution + output redaction
# ---------------------------------------------------------------------------

@macos_only
class TestSecretExecPlaceholder:
    """2.6 — secret-exec.sh resolves {{PLACEHOLDER}} and redacts values in output."""

    @pytest.fixture(autouse=True)
    def _setup(self, env_with_registry, temp_registry, temp_keychain):
        """Register a test secret and store it in the isolated keychain."""
        self.env = env_with_registry
        self.keychain = str(temp_keychain)
        self.secret_name = "BFTEST_PHASE2"
        self.secret_value = "phase2-test-value-12345"

        # Register in temp registry
        run_script(
            "secret-store.sh",
            ["--register-only", self.secret_name],
            env=self.env,
        )

        # Store directly in temp keychain
        account = f"claude-secret:global:{self.secret_name}"
        subprocess.run(
            ["security", "add-generic-password",
             "-a", account, "-s", "claude-secrets", "-w", self.secret_value,
             self.keychain],
            capture_output=True,
        )

        yield

        subprocess.run(
            ["security", "delete-generic-password",
             "-a", account, "-s", "claude-secrets", self.keychain],
            capture_output=True,
        )

    def test_placeholder_is_substituted_and_redacted(self):
        """Output of `echo "val={{BFTEST_PHASE2}}"` must show redacted placeholder."""
        result = run_script(
            "secret-exec.sh",
            [f'echo "val={{{{{self.secret_name}}}}}"'],
            env=self.env,
        )

        assert result.returncode == 0, (
            f"secret-exec.sh failed: stderr={result.stderr!r}"
        )
        # The raw value must NOT appear in output
        assert self.secret_value not in result.stdout, (
            f"Secret value leaked into stdout: {result.stdout!r}"
        )
        # The redacted placeholder MUST appear
        assert f"[REDACTED:{self.secret_name}]" in result.stdout, (
            f"Expected [REDACTED:{self.secret_name}] in stdout, got: {result.stdout!r}"
        )


# ---------------------------------------------------------------------------
# 2.7 — Redact hook fires when a secret value appears in Bash output
# ---------------------------------------------------------------------------

@macos_only
class TestRedactHookFiresOnLeak:
    """2.7 — PostToolUse hook redacts leaked values from Bash output.

    This complements test_redaction.py by exercising the full scenario
    from the manual test (a Bash command echoes a stored secret value
    verbatim, and the hook scrubs it before Claude sees the result).
    """

    @pytest.fixture(autouse=True)
    def _setup(self, env_with_registry, temp_registry, temp_keychain):
        self.env = env_with_registry
        self.keychain = str(temp_keychain)
        self.secret_name = "BFTEST_LEAK"
        self.secret_value = "leak-value-abc123xyz"

        run_script(
            "secret-store.sh",
            ["--register-only", self.secret_name],
            env=self.env,
        )
        account = f"claude-secret:global:{self.secret_name}"
        subprocess.run(
            ["security", "add-generic-password",
             "-a", account, "-s", "claude-secrets", "-w", self.secret_value,
             self.keychain],
            capture_output=True,
        )

        yield

        subprocess.run(
            ["security", "delete-generic-password",
             "-a", account, "-s", "claude-secrets", self.keychain],
            capture_output=True,
        )

    def test_leaked_value_is_redacted_from_output(self):
        """If Bash output contains a stored secret, the hook must scrub it."""
        # Simulate the manual test scenario: `echo <secret>` produced the raw value
        hook_input = build_redact_input(self.secret_value)
        result = _run_redact(hook_input, self.env)

        assert result.returncode == 0

        # Hook should have emitted a tool_response with the value redacted
        payload = json.loads(result.stdout)
        assert "tool_response" in payload, (
            "Hook must emit tool_response (regression guard for issue #2)"
        )
        redacted_stdout = payload["tool_response"]["stdout"]
        assert self.secret_value not in redacted_stdout, (
            "Secret value must not appear in redacted output"
        )
        assert f"[REDACTED:{self.secret_name}]" in redacted_stdout, (
            "Redacted output must contain the placeholder marker"
        )
