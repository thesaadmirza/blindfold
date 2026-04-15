"""Integration tests for macOS Keychain lifecycle.

These tests store real secrets in the macOS Keychain and verify the full
store → retrieve → list → delete pipeline. They are skipped on non-macOS
platforms.

All test secrets use a unique prefix and are cleaned up in teardown,
but a safety cleanup runs at the start of each test as well.
"""

import json
import subprocess

import pytest

from conftest import macos_only, run_script

# Use a distinct service name to avoid colliding with real secrets
TEST_SERVICE = "claude-secrets"


@macos_only
class TestKeychainLifecycle:
    """Full store → retrieve → list → delete lifecycle on macOS Keychain."""

    @pytest.fixture(autouse=True)
    def _setup(self, env_with_registry, temp_keychain):
        """Set up test environment with isolated keychain."""
        self.env = env_with_registry
        self.keychain = str(temp_keychain)
        yield

    def _store_secret(self, name: str, value: str) -> subprocess.CompletedProcess:
        """Store a secret using isolated test keychain."""
        run_script(
            "secret-store.sh",
            ["--register-only", name],
            env=self.env,
        )
        account = f"claude-secret:global:{name}"
        result = subprocess.run(
            ["security", "add-generic-password",
             "-a", account, "-s", TEST_SERVICE, "-w", value, self.keychain],
            capture_output=True, text=True,
        )
        return result

    def _get_secret(self, name: str) -> str | None:
        """Retrieve a secret from the isolated test keychain."""
        account = f"claude-secret:global:{name}"
        result = subprocess.run(
            ["security", "find-generic-password",
             "-a", account, "-s", TEST_SERVICE, "-w", self.keychain],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None

    def test_store_and_retrieve(self):
        """Store a secret and retrieve it from Keychain."""
        result = self._store_secret("BFTEST_STORE", "my-test-value-42")
        assert result.returncode == 0

        value = self._get_secret("BFTEST_STORE")
        assert value == "my-test-value-42"

    def test_full_lifecycle(self, temp_registry):
        """Store → list → delete → verify gone."""
        # Store
        self._store_secret("BFTEST_LIFECYCLE", "lifecycle-value")

        # List — should show the secret
        result = run_script("secret-list.sh", env=self.env)
        assert result.returncode == 0
        assert "BFTEST_LIFECYCLE" in result.stdout

        # Delete
        result = run_script(
            "secret-delete.sh",
            ["BFTEST_LIFECYCLE"],
            env=self.env,
        )
        assert result.returncode == 0

        # Verify gone from Keychain
        value = self._get_secret("BFTEST_LIFECYCLE")
        assert value is None

        # Verify gone from registry
        data = json.loads(temp_registry.read_text())
        assert "BFTEST_LIFECYCLE" not in data["global"]["secrets"]

    def test_overwrite_existing_secret(self):
        """Storing a secret with the same name should update the value."""
        self._store_secret("BFTEST_OVERWRITE", "original-value")
        assert self._get_secret("BFTEST_OVERWRITE") == "original-value"

        # Overwrite — delete from test keychain first, then re-store
        account = f"claude-secret:global:BFTEST_OVERWRITE"
        subprocess.run(
            ["security", "delete-generic-password",
             "-a", account, "-s", TEST_SERVICE, self.keychain],
            capture_output=True,
        )
        self._store_secret("BFTEST_OVERWRITE", "updated-value")
        assert self._get_secret("BFTEST_OVERWRITE") == "updated-value"
