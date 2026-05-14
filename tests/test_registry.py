"""Unit tests for secrets registry operations.

These tests run on any platform — they only exercise the JSON registry
file, not the OS keychain backend.
"""

import json

from conftest import run_script


class TestRegistryCreation:
    """Verify the registry file is created and structured correctly."""

    def test_list_creates_registry_if_missing(self, scripts_dir, tmp_path):
        """secret-list.sh should handle missing registry gracefully."""
        import os
        env = os.environ.copy()
        env["BLINDFOLD_REGISTRY"] = str(tmp_path / "nonexistent.json")
        result = run_script("secret-list.sh", env=env)
        assert result.returncode == 0
        assert "No secrets registered" in result.stdout

    def test_store_creates_registry(self, env_with_registry, temp_registry):
        """secret-store.sh --register-only should create registry entries."""
        result = run_script(
            "secret-store.sh",
            ["--register-only", "TEST_KEY"],
            env=env_with_registry,
        )
        assert result.returncode == 0
        assert "registered" in result.stdout

        data = json.loads(temp_registry.read_text())
        assert "TEST_KEY" in data["global"]["secrets"]


class TestRegistryOperations:
    """Test adding, listing, and removing entries from the registry."""

    def test_register_global_secret(self, env_with_registry, temp_registry):
        """Register a global secret and verify it appears in the registry."""
        run_script(
            "secret-store.sh",
            ["--register-only", "API_KEY"],
            env=env_with_registry,
        )
        data = json.loads(temp_registry.read_text())
        assert "API_KEY" in data["global"]["secrets"]

    def test_register_multiple_secrets(self, env_with_registry, temp_registry):
        """Register multiple secrets and verify all appear."""
        for name in ["KEY_A", "KEY_B", "KEY_C"]:
            run_script(
                "secret-store.sh",
                ["--register-only", name],
                env=env_with_registry,
            )
        data = json.loads(temp_registry.read_text())
        assert set(data["global"]["secrets"]) == {"KEY_A", "KEY_B", "KEY_C"}

    def test_register_duplicate_is_idempotent(self, env_with_registry, temp_registry):
        """Registering the same secret twice should not create duplicates."""
        for _ in range(3):
            run_script(
                "secret-store.sh",
                ["--register-only", "DUP_KEY"],
                env=env_with_registry,
            )
        data = json.loads(temp_registry.read_text())
        assert data["global"]["secrets"].count("DUP_KEY") == 1

    def test_delete_removes_from_registry(self, env_with_registry, temp_registry):
        """Deleting a secret should remove it from the registry."""
        run_script(
            "secret-store.sh",
            ["--register-only", "TO_DELETE"],
            env=env_with_registry,
        )
        run_script(
            "secret-delete.sh",
            ["TO_DELETE"],
            env=env_with_registry,
        )
        data = json.loads(temp_registry.read_text())
        assert "TO_DELETE" not in data["global"]["secrets"]

    def test_delete_nonexistent_secret_succeeds(self, env_with_registry):
        """Deleting a secret that doesn't exist should not fail."""
        result = run_script(
            "secret-delete.sh",
            ["GHOST_KEY"],
            env=env_with_registry,
        )
        assert result.returncode == 0
        assert "deleted" in result.stdout.lower()


class TestArgumentValidation:
    """Test that scripts validate inputs correctly."""

    def test_store_rejects_empty_name(self, env_with_registry):
        """secret-store.sh should reject calls with no name."""
        result = run_script("secret-store.sh", env=env_with_registry)
        assert result.returncode != 0
        assert "required" in result.stderr.lower() or "usage" in result.stderr.lower()

    def test_store_rejects_invalid_name(self, env_with_registry):
        """secret-store.sh should reject names with special characters."""
        result = run_script(
            "secret-store.sh",
            ["--register-only", "invalid-name!"],
            env=env_with_registry,
        )
        assert result.returncode != 0
        assert "alphanumeric" in result.stderr.lower()

    def test_store_accepts_underscored_name(self, env_with_registry):
        """secret-store.sh should accept names with underscores."""
        result = run_script(
            "secret-store.sh",
            ["--register-only", "MY_API_KEY_V2"],
            env=env_with_registry,
        )
        assert result.returncode == 0
