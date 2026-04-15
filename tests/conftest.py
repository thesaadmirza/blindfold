"""Shared fixtures for Blindfold tests.

Tests call bash scripts via subprocess to validate the full pipeline.
Two tiers:
  - Unit tests: run anywhere, test argument parsing, registry logic, etc.
  - Integration tests: macOS only, test Keychain store/retrieve/delete cycle.

Hook input builders (`build_guard_input`, `build_redact_input`) produce
JSON that matches the real Claude Code hook schema. Tests should use
these rather than rolling their own dicts — this is how issue #2 hid
(the original test mock used the wrong field name, perpetuating the bug).
See issue #12 for the test hygiene audit.
"""

import json
import os
import platform
import subprocess
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"

# Custom marker for macOS-only integration tests
macos_only = pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="Requires macOS Keychain",
)


@pytest.fixture()
def scripts_dir():
    """Path to the blindfold scripts directory."""
    return SCRIPTS_DIR


@pytest.fixture()
def temp_registry(tmp_path):
    """Create a temporary secrets registry and set it via env var.

    Yields the path to the temp registry file. The file is cleaned up
    automatically by pytest's tmp_path fixture.
    """
    registry = tmp_path / "secrets-registry.json"
    registry.write_text('{"version":3,"global":{"secrets":[]},"projects":{}}')
    registry.chmod(0o600)
    yield registry


@pytest.fixture()
def temp_keychain(tmp_path):
    """Create a temporary macOS Keychain for test isolation.

    Only created on macOS. On other platforms, yields None.
    Cleaned up after the test.
    """
    if platform.system() != "Darwin":
        yield None
        return

    keychain_path = tmp_path / "blindfold-test.keychain-db"
    subprocess.run(
        ["security", "create-keychain", "-p", "", str(keychain_path)],
        capture_output=True,
    )
    # Unlock the keychain (required for add/find operations)
    subprocess.run(
        ["security", "unlock-keychain", "-p", "", str(keychain_path)],
        capture_output=True,
    )
    # No auto-lock timeout
    subprocess.run(
        ["security", "set-keychain-settings", str(keychain_path)],
        capture_output=True,
    )

    yield keychain_path

    # Cleanup: delete the test keychain
    subprocess.run(
        ["security", "delete-keychain", str(keychain_path)],
        capture_output=True,
    )


@pytest.fixture()
def env_with_registry(temp_registry, temp_keychain):
    """Environment dict with BLINDFOLD_REGISTRY and BLINDFOLD_KEYCHAIN
    pointing to temp files.

    This keeps tests isolated from the user's real registry and keychain.
    """
    env = os.environ.copy()
    env["BLINDFOLD_REGISTRY"] = str(temp_registry)
    if temp_keychain is not None:
        env["BLINDFOLD_KEYCHAIN"] = str(temp_keychain)
    return env


@pytest.fixture()
def test_secret_name():
    """A unique secret name for test isolation."""
    return "BLINDFOLD_TEST_SECRET"


@pytest.fixture()
def test_secret_value():
    """A known value for test assertions."""
    return "test-value-s3cr3t-12345"


def run_script(script_name: str, args: list[str] | None = None,
               env: dict | None = None, input_text: str | None = None) -> subprocess.CompletedProcess:
    """Run a blindfold bash script and return the result.

    Args:
        script_name: Name of the script in scripts/ (e.g., "secret-store.sh")
        args: Command-line arguments to pass
        env: Environment variables (use env_with_registry fixture for isolation)
        input_text: Text to pipe to stdin
    """
    script_path = SCRIPTS_DIR / script_name
    cmd = ["bash", str(script_path)] + (args or [])
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        input=input_text,
        timeout=30,
    )


# ---------------------------------------------------------------------------
# Canonical hook input builders — keep in sync with Claude Code hook schema.
# ---------------------------------------------------------------------------

def build_guard_input(command: str, tool_name: str = "Bash") -> str:
    """Build PreToolUse hook input JSON (for secret-guard.sh).

    Schema verified against `scripts/secret-guard.sh:12`:
        jq -r '[.tool_name // "", .tool_input.command // ""] | @tsv'
    """
    return json.dumps({
        "tool_name": tool_name,
        "tool_input": {
            "command": command,
        },
    })


def build_redact_input(stdout: str, tool_name: str = "Bash") -> str:
    """Build PostToolUse hook input JSON (for secret-redact.sh).

    Schema verified via debug capture of real Claude Code hook input
    (TESTING.md line 84). The field is `tool_response`, NOT `tool_result`
    — see issue #2 for the bug where this was wrong.
    """
    return json.dumps({
        "tool_name": tool_name,
        "tool_response": {
            "stdout": stdout,
        },
    })
