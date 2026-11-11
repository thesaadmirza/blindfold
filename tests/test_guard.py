"""Tests for secret-guard.sh (PreToolUse hook).

None of these touch a keychain, so they run inside a sandboxed shell too.
"""

import json
import os

import pytest

from conftest import (
    SCRIPTS_DIR,
    build_file_tool_input,
    build_guard_input,
    build_read_input,
    execute_wrapped,
    macos_only,
    run_guard,
    wrap_through_guard,
)

REPO_ROOT = SCRIPTS_DIR.parent
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

    @pytest.mark.parametrize("command,expected", [
        ("echo 'hello world'", "hello world\n"),
        ('echo "it\'s here"', "it's here\n"),
        ("echo one\necho two", "one\ntwo\n"),
        (r"printf '%s\n' 'a\b'", "a\\b\n"),
    ])
    def test_output_matches_unwrapped(self, command, expected):
        executed = execute_wrapped(wrap_through_guard(command))
        assert executed.returncode == 0, f"stderr={executed.stderr!r}"
        assert executed.stdout == expected


@macos_only
class TestReadGuard:
    """Read is refused when the file holds a stored secret value.

    A stub `security` on PATH stands in for the keychain, so these run
    without one and never open a keychain dialog."""

    SECRET_NAME = "BFTEST_READ"
    SECRET_VALUE = "read-guard-value-98765"

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, temp_registry):
        self.registry = temp_registry
        self._register(global_secrets=[self.SECRET_NAME])
        stub_dir = tmp_path / "bin"
        stub_dir.mkdir()
        stub = stub_dir / "security"
        stub.write_text(
            "#!/bin/sh\n"
            f'case "$*" in *":{self.SECRET_NAME} "*-w*) '
            f"printf '%s' '{self.SECRET_VALUE}' ;; *) exit 44 ;; esac\n"
        )
        stub.chmod(0o755)

        self.env = os.environ.copy()
        self.env.pop("BLINDFOLD_KEYCHAIN", None)
        self.env["BLINDFOLD_REGISTRY"] = str(temp_registry)
        self.env["PATH"] = f"{stub_dir}:{self.env['PATH']}"
        self.dir = tmp_path

    def _register(self, global_secrets=(), projects=None):
        self.registry.write_text(json.dumps({
            "version": 3,
            "global": {"secrets": list(global_secrets)},
            "projects": projects or {},
        }))

    def _read(self, path):
        return run_guard(build_read_input(str(path)), self.env)

    def _write_leak(self):
        leaked = self.dir / "out.txt"
        leaked.write_text(f"token={self.SECRET_VALUE}\n")
        return leaked

    def test_file_holding_a_secret_is_denied(self):
        result = self._read(self._write_leak())

        assert result.returncode == 2, f"stderr={result.stderr!r}"
        assert self.SECRET_NAME in result.stderr
        assert self.SECRET_VALUE not in result.stderr

    def test_file_holding_a_project_secret_is_denied(self):
        # The guard runs from tests/, so the project is the repo root
        project = str(REPO_ROOT)
        self._register(projects={project: {"secrets": [self.SECRET_NAME]}})

        result = self._read(self._write_leak())

        assert result.returncode == 2, f"stderr={result.stderr!r}"
        assert self.SECRET_NAME in result.stderr

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


class TestBlindfoldFilesAreProtected:
    """The agent's file tools run outside the sandbox, so the guard has to
    keep them off the policy, the proxy's files and Blindfold's own code."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        self.config = tmp_path / "config"
        self.config.mkdir()
        self.env = os.environ.copy()
        self.env["BLINDFOLD_CONFIG_DIR"] = str(self.config)
        self.dir = tmp_path

    def _edit(self, path, tool="Write"):
        return run_guard(build_file_tool_input(tool, str(path)), self.env)

    @pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit", "NotebookEdit"])
    def test_policy_file_is_refused(self, tool):
        result = self._edit(self.config / "policy.toml", tool)

        assert result.returncode == 2, f"stderr={result.stderr!r}"
        assert "DENIED by Blindfold" in result.stderr

    def test_blindfold_scripts_are_refused(self):
        assert self._edit(SCRIPTS_DIR / "lib.sh", "Edit").returncode == 2

    def test_new_file_in_a_missing_config_subfolder_is_refused(self):
        assert self._edit(self.config / "run" / "new" / "proxy.port").returncode == 2

    def test_path_through_a_symlinked_folder_is_refused(self):
        link = self.dir / "innocent"
        link.symlink_to(self.config)

        assert self._edit(link / "policy.toml").returncode == 2

    def test_symlinked_file_is_refused(self):
        (self.config / "policy.toml").write_text("")
        link = self.dir / "notes.toml"
        link.symlink_to(self.config / "policy.toml")

        assert self._edit(link, "Edit").returncode == 2

    def test_dotdot_through_a_missing_folder_is_refused(self):
        sneaky = f"{self.dir}/nope/../config/policy.toml"

        assert self._edit(sneaky).returncode == 2

    def test_hard_linked_file_is_refused(self):
        (self.config / "policy.toml").write_text("")
        alias = self.dir / "alias.toml"
        os.link(self.config / "policy.toml", alias)

        assert self._edit(alias, "Edit").returncode == 2

    def test_hard_linked_file_elsewhere_is_allowed(self):
        # pnpm and similar tools hard-link files; only links into Blindfold count
        (self.dir / "store.js").write_text("")
        os.link(self.dir / "store.js", self.dir / "linked.js")

        assert self._edit(self.dir / "linked.js", "Edit").returncode == 0

    def test_any_project_policy_is_refused(self):
        assert self._edit(self.dir / "some-project" / ".blindfold.toml").returncode == 2

    def test_symlink_to_a_project_policy_is_refused(self):
        project = self.dir / "proj"
        project.mkdir()
        (project / ".blindfold.toml").write_text("")
        (self.dir / "notes.toml").symlink_to(project / ".blindfold.toml")

        assert self._edit(self.dir / "notes.toml", "Edit").returncode == 2

    @pytest.mark.parametrize("tool,key", [("Read", "file_path"), ("Grep", "path")])
    def test_private_folder_cannot_be_read_or_searched(self, tool, key):
        private = self.config / "private"
        private.mkdir()
        (private / "tokens.tsv").write_text("secret-token\tid\t/x\n")
        target = private / "tokens.tsv" if tool == "Read" else private

        result = run_guard(json.dumps({"tool_name": tool, "tool_input": {key: str(target)}}), self.env)

        assert result.returncode == 2, f"stderr={result.stderr!r}"
        assert "secret-token" not in result.stderr

    def test_grep_elsewhere_is_allowed(self):
        result = run_guard(json.dumps({"tool_name": "Grep", "tool_input": {"path": str(self.dir)}}), self.env)

        assert result.returncode == 0, f"stderr={result.stderr!r}"

    @pytest.mark.parametrize("name", ["notes.md", "sub/new.py"])
    def test_ordinary_files_are_allowed(self, name):
        result = self._edit(self.dir / "project" / name)

        assert result.returncode == 0, f"stderr={result.stderr!r}"
        assert result.stdout.strip() == ""
