"""Tests for leak detection in the PostToolUse hook.

The PostToolUse hook (secret-redact.sh) runs after every Bash command
and warns Claude via systemMessage if any secret values appear in the
output. Claude Code does not support output replacement for built-in
tools, so the hook detects and warns rather than scrubs.
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
class TestLeakDetection:
    """Verify that the PostToolUse hook detects leaked values and warns Claude."""

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

    def test_leaked_secret_triggers_warning(self):
        """If a secret value appears in Bash output, a systemMessage warning must be emitted."""
        hook_input = build_redact_input(
            f"Response from API: token={self.secret_value} status=200"
        )
        result = _run_redact_hook(hook_input, self.env)

        # The hook emits a systemMessage on stderr warning Claude
        assert "WARNING" in result.stderr, (
            "Hook must emit a systemMessage warning when a secret is detected"
        )
        assert self.secret_name in result.stderr, (
            f"Warning must name the leaked secret ({self.secret_name})"
        )

    def test_hook_emits_system_message_not_tool_response(self):
        """Hook must emit systemMessage on stderr, not tool_response on stdout.

        Claude Code ignores tool_response stdout from PostToolUse hooks
        for built-in tools. The only effective channel is systemMessage.
        """
        hook_input = build_redact_input(f"leak={self.secret_value}")
        result = _run_redact_hook(hook_input, self.env)

        # stderr should contain a valid systemMessage JSON
        payload = json.loads(result.stderr)
        assert "systemMessage" in payload, (
            "Hook must emit systemMessage on stderr"
        )
        # stdout should be empty (no tool_response emission)
        assert result.stdout.strip() == "", (
            "Hook should not emit tool_response on stdout (ignored by Claude Code)"
        )

    def test_warning_names_leaked_secret(self):
        """Warning message should identify which secret was detected."""
        hook_input = build_redact_input(
            f"key={self.secret_value}"
        )
        result = _run_redact_hook(hook_input, self.env)

        assert self.secret_name in result.stderr, (
            f"Expected secret name {self.secret_name} in warning but not found"
        )

    def test_multiple_occurrences_detected(self):
        """Multiple occurrences of a secret should still trigger the warning."""
        hook_input = build_redact_input(
            f"first={self.secret_value} middle=ok last={self.secret_value}"
        )
        result = _run_redact_hook(hook_input, self.env)

        assert "WARNING" in result.stderr, (
            "Hook must warn even with multiple occurrences"
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
        """Output that doesn't contain secrets should not trigger a warning."""
        hook_input = build_redact_input("normal output with no secrets")
        result = _run_redact_hook(hook_input, self.env)
        assert result.returncode == 0
        # No warning should be emitted
        assert "WARNING" not in result.stderr
