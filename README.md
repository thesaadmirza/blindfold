# Blindfold

A Claude Code plugin that keeps your secrets out of the LLM's context window. API keys, tokens, and passwords live in your OS keychain. The LLM works with placeholders like `{{API_KEY}}` and never sees the actual values.

## How it works

You store a secret in your keychain. Claude references it by name. A wrapper script resolves the real value in a sandboxed subprocess and redacts it from output before Claude reads it back.

On macOS, every bash command Claude runs is wrapped in a Seatbelt sandbox that blocks `com.apple.SecurityServer` at the kernel level. The sandbox denies the Mach IPC call that all keychain access goes through. Doesn't matter how the command is constructed.

## Installation

Inside Claude Code:

```
/plugin marketplace add thesaadmirza/blindfold
/plugin install blindfold@blindfold
```

`jq` is required (`brew install jq` / `apt install jq`).

For manual install or other environments, see the [install guide](#manual-install) below.

## Usage

```
> store my gitlab token
# Native password dialog opens. You type the value. Claude sees "OK: stored."

> curl the gitlab API with my token
# Claude runs: secret-exec.sh 'curl -H "PRIVATE-TOKEN: {{GITLAB_TOKEN}}" ...'
# Output: PRIVATE-TOKEN: [REDACTED:GITLAB_TOKEN]

> what secrets do I have?
# Lists all secrets by scope, never shows values

> delete my gitlab token
# Removes from keychain and registry
```

## Platforms

| Platform | Secret store | Input dialog |
|----------|-------------|--------------|
| macOS | Keychain | osascript / terminal |
| Linux (GUI) | GNOME Keyring / KWallet | zenity / kdialog |
| Linux (headless) | GPG encrypted files | terminal prompt |
| Windows (WSL) | Credential Manager | PowerShell |

Detected automatically. Falls back to terminal prompt when no GUI is available.

## Scoping

Secrets can be global (shared across projects) or project-scoped (tied to a specific directory). A `DATABASE_URL` in your API project is separate from `DATABASE_URL` in your frontend project. Project scope is checked first, global is the fallback.

## Security model

On macOS, a PreToolUse hook wraps every bash command in a Seatbelt sandbox before execution. The sandbox blocks `com.apple.SecurityServer` at the kernel level, which cuts off all keychain access from any process inside it. Python subprocesses, base64-decoded scripts, temp file execution, doesn't matter. The block is below the shell.

`secret-exec.sh` is the only path to secrets. It runs outside the sandbox, reads from the keychain, injects values as prefixed env vars (`__SV_NAME`), then runs the user command inside the sandbox. Output is redacted before Claude sees it. Claude never knows what the prefixed env vars contain because it doesn't know the `__SV_` prefix exists.

Storing a secret goes through a native OS dialog. The value goes from your keyboard to the keychain. Claude sees "OK: stored."

The same hook also covers the Read tool. If a file contains the value of any stored secret, the read is denied before Claude sees the contents.

On Linux, the guard hook falls back to string matching since Seatbelt is macOS only.

## Files

```
blindfold/
├── .claude-plugin/
│   ├── plugin.json
│   └── marketplace.json
├── skills/
│   └── blindfold/
│       └── SKILL.md
├── hooks/
│   └── hooks.json
├── scripts/
│   ├── lib.sh
│   ├── sandbox.sb
│   ├── secret-store.sh
│   ├── secret-list.sh
│   ├── secret-delete.sh
│   ├── secret-exec.sh
│   ├── secret-guard.sh
│   └── secret-redact.sh
├── LICENSE
└── README.md
```

## Manual install

If `/plugin` isn't available:

```bash
git clone https://github.com/thesaadmirza/blindfold.git ~/.claude/skills/blindfold
chmod 700 ~/.claude/skills/blindfold/scripts/*.sh
```

Add hooks to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "bash ~/.claude/skills/blindfold/scripts/secret-guard.sh", "timeout": 5}]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "bash ~/.claude/skills/blindfold/scripts/secret-redact.sh", "timeout": 10}]
      }
    ]
  }
}
```

## Limitations

- On macOS, enforcement is kernel-level via Seatbelt. On Linux, it falls back to string matching which can be bypassed by obfuscating commands.
- `security add-generic-password` on macOS passes the value as a CLI argument, briefly visible in `ps`. Short exposure window.
- The GPG fallback on Linux uses symmetric encryption with a passphrase prompt. `secret-tool` with GNOME Keyring is more secure if available.
- Output redaction is string-based. Secrets shorter than 4 characters won't be redacted.
- If the process is killed with SIGKILL, temp files with secrets may persist in `/tmp/`. Normal termination cleans them up.

## License

MIT
