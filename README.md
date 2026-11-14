# Blindfold

A Claude Code plugin that keeps your secrets out of the LLM's context window. API keys, tokens, and passwords live in your OS keychain. The LLM works with placeholders like `{{API_KEY}}` and never sees the actual values. With egress lockdown on, it goes further: a secret can only ever reach the host you bound it to.

## How it works

You store a secret in your keychain. Claude refers to it by name. On macOS, every bash command Claude runs is wrapped in a Seatbelt sandbox that blocks `com.apple.SecurityServer` at the kernel level, which cuts off every way to the keychain from inside the command, however it's written.

From there, Blindfold works at one of two levels.

**Basic.** `secret-exec.sh` reads the value, runs the command in the sandbox with the value filled in, and redacts the value from the output before Claude reads it. This keeps the value out of the conversation when things go as intended. It can't stop a command from sending the value somewhere else, because the command holds it.

**Egress lockdown** (macOS, opt in). Sandboxed commands can only reach a local proxy. You write a policy saying which host each secret is for, and in which header or parameter. The command only ever holds the placeholder. The proxy swaps in the real value on the way to that host, scrubs it out of what comes back, can ask you first, and logs every use. A command can do whatever it likes with `{{GITLAB_TOKEN}}`: anywhere other than gitlab.com, it's just text. See [Egress lockdown](#egress-lockdown-experimental-macos).

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
# Basic: Claude runs secret-exec.sh 'curl -H "PRIVATE-TOKEN: {{GITLAB_TOKEN}}" ...'
#        and any echoed value comes back as [REDACTED:GITLAB_TOKEN]
# Lockdown, with a policy for GITLAB_TOKEN: Claude runs the curl directly,
#        and the proxy fills in the token on the way to gitlab.com

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

There are two ways a value leaves the keychain. `secret-exec.sh` runs outside the sandbox, reads the value, passes it to the command in a prefixed variable (`__SV_NAME`), runs the command inside the sandbox and redacts the output. Under egress lockdown, the proxy reads it instead, and only to put it into a request to a host its policy names. With lockdown on, `secret-exec.sh` refuses any secret that has a policy, so for those the proxy is the only way. While you migrate, add `BLINDFOLD_EXEC_ANY_SECRET=1` to `~/.config/blindfold/settings` to turn that refusal off. Blindfold only reads it from that file, which the agent can't write under lockdown, so setting it in a command or in Claude Code's environment does nothing.

Storing a secret goes through a native OS dialog. The value goes from your keyboard to the keychain. Claude sees "OK: stored."

The same hook also covers Claude's file tools. Read is refused for a file that holds a stored value, so a value a command wrote to disk can't be read back. Write and Edit are refused for Blindfold's own scripts and config and for any `.blindfold.toml`, so the agent can't change where secrets may go. Under lockdown, Write and Edit are also refused for Claude Code's settings files (`~/.claude/settings.json` and `settings.local.json`, and any project's `.claude/settings.json` and `.claude/settings.local.json`), for `~/.claude/plugins/`, and for your shell profiles. That's where Blindfold's hooks and lockdown get switched on, so an agent that could edit them could switch Blindfold off for the next session.

[SECURITY.md](SECURITY.md) has the full threat model, including what Blindfold doesn't protect against.

On Linux, the guard hook falls back to string matching since Seatbelt is macOS only.

## Egress lockdown (experimental, macOS)

By default a sandboxed command can still connect anywhere. Egress lockdown changes that. Sandboxed commands can only reach loopback, so the rest of their traffic has to go through a small local proxy, which logs every destination to `~/.local/state/blindfold/egress.jsonl`. DNS is blocked inside the sandbox, and tools that ignore `HTTPS_PROXY` will fail to connect. Anything that isn't HTTP, like git over ssh or a remote database, can only reach this machine.

To try it, install the proxy. This downloads the prebuilt binary for your Mac from the release that matches your copy of Blindfold, and checks it against the release's SHA-256 checksums before using it:

```bash
bash ~/.claude/skills/blindfold/scripts/install-proxy.sh
```

If [gh](https://cli.github.com) is installed and logged in, the script also checks GitHub's build provenance attestation, which shows the binary was built from that release's tag by this repo's release workflow. Without gh, only the checksums are checked, and those come from the same release as the binary. You can check it yourself later with `gh attestation verify bin/blindfold-proxy -R thesaadmirza/blindfold`.

Or build it from source (needs Go 1.24+):

```bash
bash ~/.claude/skills/blindfold/scripts/build-proxy.sh
```

Then turn it on in Blindfold's settings file:

```bash
mkdir -p ~/.config/blindfold && echo BLINDFOLD_EGRESS=proxy >> ~/.config/blindfold/settings
```

Setting `BLINDFOLD_EGRESS=proxy` in Claude Code's environment works too, but the file is the better place. The agent can't write it under lockdown, and no `BLINDFOLD_EGRESS` value in the environment can turn off what it turned on. The file takes one `NAME=value` per line. If Blindfold finds a line it doesn't know, it refuses commands until you fix it rather than guess. The guard starts the proxy on first use, and restarts it after you reinstall or rebuild it. If the proxy can't start, commands are refused rather than run without the lockdown.

macOS won't apply this profile inside another sandbox. If Claude Code's own sandbox is on, commands under egress lockdown fail to start.

Under lockdown, sandboxed commands can't write to `~/.config/blindfold/`, Blindfold's own folder, Claude Code's settings files, `~/.claude/plugins/` or your shell profiles, and they can't rename or remove a folder that holds any of those. The guard stops Claude's Write and Edit tools from changing them too. The catch is that Claude can't edit its own settings while lockdown is on. It'll tell you what to change, and you make the edit.

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

`writes` asks before any request that isn't a GET or HEAD, and `always` asks before every one. The request waits, before the value is sent anywhere, while a Blindfold dialog shows you the secret, method, host and path. Choose Allow 30 min, Allow once, or Deny (the rightmost button), which covers that secret, method and host for half an hour so routine work doesn't turn into a stream of prompts. Deny is the default button, and no answer within 60 seconds counts as Deny. When the agent repeats a request while you're still deciding, those copies wait for the same answer instead of opening more dialogs.

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
│   ├── install-proxy.sh
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
