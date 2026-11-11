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

## Egress lockdown (experimental, macOS)

By default a sandboxed command can still connect anywhere. Egress lockdown changes that. Sandboxed commands can only reach loopback, so the rest of their traffic has to go through a small local proxy, which logs every destination to `~/.local/state/blindfold/egress.jsonl`. DNS is blocked inside the sandbox, and tools that ignore `HTTPS_PROXY` will fail to connect.

To try it, build the proxy (needs Go 1.24+):

```bash
bash ~/.claude/skills/blindfold/scripts/build-proxy.sh
```

Then set `BLINDFOLD_EGRESS=proxy` for Claude Code, for example in the `env` block of `~/.claude/settings.json`. The guard starts the proxy on first use, and restarts it after you rebuild it. If the proxy can't start, commands are refused rather than run without the lockdown.

macOS won't apply this profile inside another sandbox. If Claude Code's own sandbox is on, commands under egress lockdown fail to start.

Under lockdown, sandboxed commands can't write to `~/.config/blindfold/` or to Blindfold's own folder, and the guard stops Claude's Write and Edit tools from changing them too.

### Binding a secret to its host

With lockdown on, you can say where each secret may go, and then the command never holds the real value at all. It sends a placeholder. The proxy swaps in the value on the way to the host you named, in the header or parameter you named, and nowhere else.

Write `~/.config/blindfold/policy.toml` yourself (the agent can't):

```toml
[secrets.GITLAB_TOKEN]
hosts  = ["gitlab.com"]
header = "PRIVATE-TOKEN"

[secrets.REGISTRY_PASSWORD]
hosts      = ["registry.example.com"]
basic_auth = { username = "deploy-bot" }

[secrets.MAPS_KEY]
hosts = ["maps.googleapis.com"]
query = "key"
```

Each secret gets exactly one of `header`, `basic_auth` or `query`. Hosts are exact names: no wildcards, IP addresses or ports. The secret has to be stored globally (`secret-store.sh --scope global`).

Then a plain command works, and the agent never sees the value:

```bash
curl -H "PRIVATE-TOKEN: {{GITLAB_TOKEN}}" https://gitlab.com/api/v4/user
curl -H "PRIVATE-TOKEN: $GITLAB_TOKEN" https://gitlab.com/api/v4/user   # same thing
```

Every policy secret is set in the sandbox's environment as its own placeholder, so tools that read a token from the environment pick it up too. If the agent sends `{{GITLAB_TOKEN}}` anywhere else, such as another host, a request body, another header, or plain HTTP, it goes out as that literal text.

Under the hood, for a policy host the proxy terminates TLS with a certificate from a local CA it makes in memory at startup. The CA is limited by name constraints to your policy hosts. Sandboxed commands trust it through `SSL_CERT_FILE` and similar variables, and it's never added to your system trust store. Traffic to every other host is tunnelled as before, untouched. The proxy picks up changes to the policy file within a second. An invalid policy turns injection off and the guard refuses commands until it's fixed, telling you what's wrong.

### Asking before a secret is used

A policy can ask you first. Add `approve` to a secret:

```toml
[secrets.GITLAB_TOKEN]
hosts   = ["gitlab.com"]
header  = "PRIVATE-TOKEN"
approve = "writes"      # never (the default), writes, or always
```

`writes` asks before any request that isn't a GET or HEAD, and `always` asks before every one. The request waits, before the value is sent anywhere, while a Blindfold dialog shows you the secret, method, host and path. Choose Deny, Allow once, or Allow 30 min, which covers that secret, method and host for half an hour so routine work doesn't turn into a stream of prompts. Deny is the default button, and no answer within 60 seconds counts as Deny. When the agent repeats a request while you're still deciding, those copies wait for the same answer instead of opening more dialogs.

The path in the dialog comes from the agent, so it's shortened and shown on a line marked as the request path. If that line reads like advice about which button to press, that's the agent talking, not Blindfold.

### Project policies

A project can carry its own `.blindfold.toml` in its root, in the same format, for secrets only that project uses. Since anyone can ship one in a repo, and the agent could write one, the proxy ignores it until you approve it.

The first time a sandboxed command runs in a project with a new or changed `.blindfold.toml`, the command is refused and a Blindfold dialog shows you the file. Trust it and the agent's next try works. Deny it and the file is ignored until it changes. With no screen to show a dialog on, approve it from a terminal instead:

```bash
bash ~/.claude/skills/blindfold/scripts/secret-approve.sh /path/to/project
```

What you approve is an exact copy. Change one byte and it needs approving again.

A project policy can't change the rule for a secret the global policy already names, so an approved project can't send your global token somewhere new. For its own secrets, the project's stored value is used first (`secret-store.sh --scope project`), then the global one.

Projects are kept apart by a secret token for each project with a policy, which the guard puts in the proxy URL as a password. The tokens live in `~/.config/blindfold/private/`, which sandboxed commands can't read and Claude's file tools are kept out of, so a command in one project can't pass for another.

### What comes back, and what gets recorded

Responses from a policy host are checked on the way back. Any copy of a secret's value, in a header or the body, is swapped for its placeholder before the command sees it. That covers APIs that echo a token, and ones that store a token and return it on some later call. To read the body, the proxy asks for an uncompressed response, and if a server sends gzip anyway it unpacks it. A response in an encoding the proxy can't read, like brotli, is refused rather than passed through unchecked.

Every use of a secret goes in `~/.local/state/blindfold/audit.jsonl`, one line each:

```json
{"ts":"2026-11-11T14:02:09Z","decision":"filled","secret":"GITLAB_TOKEN","method":"POST","host":"gitlab.com","path":"/api/v4/projects/42/issues","status":201}
```

The decisions are `filled`, `echoed` (the response held the value and it was scrubbed), and the refusals: `refused-host`, `refused-username`, `refused-missing`, `refused-encoding`, `refused-approval`, `outside-slot` (a placeholder sent in a header or parameter its rule doesn't name) and `plain-http`. Query strings are never logged. If something looks off, read the refusals first. Most will be a tool misconfigured, but a refusal is also what it looks like when something tries to send a secret where it isn't allowed.

Not done yet:

- `secret-exec.sh` still puts real values into commands. Use the placeholder pattern above for HTTP APIs.

Known limits:

- Go programs on macOS, including `gh`, ignore `SSL_CERT_FILE`, so they won't trust the local CA and requests to policy hosts fail. Nothing leaks, but they don't work. curl and Python trust the CA fine. The guard also sets the variables Node, git and pip read, though I haven't tried those against a policy host yet.
- For policy hosts the proxy only speaks HTTP/1.1 to the client.
- Tools that pin certificates won't accept the local CA.
- A project's token is in the environment of the commands that run there, so another process of yours that can read process environments could see it. Inside the sandbox that would let a command pass for a project it's running next to.
- Without lockdown, Bash commands aren't kept out of Blindfold's config. Turn lockdown on before relying on any policy.
- Scrubbing catches the value as it was stored. A response holding it transformed, say base64-encoded, gets through, though an API doing that would be odd.
- A placeholder in a request body isn't looked for, so `outside-slot` only covers headers and the URL. It's never filled in either way.
- An approval needs a screen to show the dialog on. Without one, over SSH say, every gated request is denied.
- An allowed host can still be misused. The proxy keeps a secret from going anywhere else, but it won't stop an unwanted call to the right host. Narrowly scoped tokens help.

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
├── proxy/              # egress proxy and policy injection (Go)
├── scripts/
│   ├── build-proxy.sh
│   ├── lib.sh
│   ├── sandbox.sb
│   ├── sandbox-egress.sb
│   ├── secret-store.sh
│   ├── secret-list.sh
│   ├── secret-delete.sh
│   ├── secret-approve.sh
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
      },
      {
        "matcher": "Read|Grep",
        "hooks": [{"type": "command", "command": "bash ~/.claude/skills/blindfold/scripts/secret-guard.sh", "timeout": 10}]
      },
      {
        "matcher": "Write|Edit|MultiEdit|NotebookEdit",
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
