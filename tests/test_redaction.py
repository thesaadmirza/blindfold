"""Tests for output redaction in the PostToolUse hook.

The PostToolUse hook (secret-redact.sh) runs after every Bash command
and replaces any leaked secret values with [REDACTED:NAME] in the
output before Claude sees it.

These tests verify that redaction actually replaces the values and
that the emitted JSON uses the correct `tool_response` key (regression
for issue #2, where the hook was silently reading the wrong field).
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from conftest import build_redact_input, macos_only, run_script, SCRIPTS_DIR


def _run_redact_hook(hook_input: str, env: dict) -> subprocess.CompletedProcess:
    """Run secret-redact.sh with the given hook input on stdin."""
    script_path = SCRIPTS_DIR / "secret-redact.sh"
    return subprocess.run(
        ["bash", str(script_path)],
        input=hook_input,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


@macos_only
class TestRedactionActuallyRedacts:
    """Verify that the PostToolUse hook replaces leaked values, not just warns."""

    @pytest.fixture(autouse=True)
    def _setup(self, env_with_registry, temp_registry, temp_keychain):
        """Store a real secret in isolated test Keychain for redaction tests."""
        self.env = env_with_registry
        self.temp_registry = temp_registry
        self.keychain = str(temp_keychain)
        self.secret_name = "BFTEST_REDACT"
        self.secret_value = "super-secret-value-xyz789"

        # Register in registry
        run_script(
            "secret-store.sh",
            ["--register-only", self.secret_name],
            env=self.env,
        )

        # Store in test Keychain directly
        account = f"claude-secret:global:{self.secret_name}"
        subprocess.run(
            ["security", "add-generic-password",
             "-a", account, "-s", "claude-secrets", "-w", self.secret_value,
             self.keychain],
            capture_output=True,
        )

        yield

        # Cleanup handled by temp_keychain fixture
        subprocess.run(
            ["security", "delete-generic-password",
             "-a", account, "-s", "claude-secrets", self.keychain],
            capture_output=True,
        )

    def test_leaked_secret_is_replaced_in_output(self):
        """If a secret value appears in Bash output, it must be replaced."""
        hook_input = build_redact_input(
            f"Response from API: token={self.secret_value} status=200"
        )
        result = _run_redact_hook(hook_input, self.env)

        # The hook emits a modified tool_response with the value replaced
        assert self.secret_value not in result.stdout, (
            "Secret value was NOT redacted from stdout"
        )

    def test_hook_emits_tool_response_not_tool_result(self):
        """Regression for #2: emitted JSON must use tool_response key.

        The field name must match Claude Code's hook schema (tool_response).
        If a future change reverts to tool_result, the hook will silently
        fail because the stdout will never flow back to Claude Code.
        """
        hook_input = build_redact_input(f"leak={self.secret_value}")
        result = _run_redact_hook(hook_input, self.env)

        # Parse stdout as JSON — hook should emit a tool_response object
        payload = json.loads(result.stdout)
        assert "tool_response" in payload, (
            "Hook output must use tool_response key to match Claude Code schema"
        )
        assert "tool_result" not in payload, (
            "tool_result is the wrong field name (regression for #2)"
        )

    def test_redacted_output_contains_placeholder(self):
        """Redacted output should show [REDACTED:NAME] instead of the value."""
        hook_input = build_redact_input(
            f"key={self.secret_value}"
        )
        result = _run_redact_hook(hook_input, self.env)

        # Should contain the redaction marker
        combined = result.stdout + result.stderr
        assert f"[REDACTED:{self.secret_name}]" in combined, (
            "Expected [REDACTED:BFTEST_REDACT] in output but not found"
        )

    def test_multiple_occurrences_all_redacted(self):
        """Every occurrence of the secret in output should be replaced."""
        hook_input = build_redact_input(
            f"first={self.secret_value} middle=ok last={self.secret_value}"
        )
        result = _run_redact_hook(hook_input, self.env)

        combined = result.stdout + result.stderr
        assert self.secret_value not in combined, (
            "Secret value still present after redaction"
        )

    def test_non_bash_tool_is_ignored(self):
        """Redaction hook should only process Bash tool output."""
        hook_input = build_redact_input(
            f"value={self.secret_value}",
            tool_name="Read",
        )
        result = _run_redact_hook(hook_input, self.env)
        # Should exit cleanly without processing
        assert result.returncode == 0

    def test_output_without_secrets_passes_through(self):
        """Output that doesn't contain secrets should not be modified."""
        hook_input = build_redact_input("normal output with no secrets")
        result = _run_redact_hook(hook_input, self.env)
        assert result.returncode == 0
        # No warning should be emitted
        assert "WARNING" not in result.stderr
