# Security Model

This document describes Blindfold's security architecture, threat model, known limitations, and platform-specific properties. The design behind egress lockdown is in [docs/design/destination-binding.md](docs/design/destination-binding.md).

## Two levels

Blindfold protects secrets at one of two levels.

**Basic.** Secrets live in the OS keychain. Every command Claude runs is sandboxed so it can't reach the keychain itself. `secret-exec.sh` fills a value into a command, runs it in the sandbox, and redacts the value from the output. This keeps a value out of the conversation when the agent behaves. It doesn't hold up against an agent that's been turned against you, for example by prompt injection, because the command holds the real value and can send it anywhere.

**Egress lockdown** (macOS, `BLINDFOLD_EGRESS=proxy`). Sandboxed commands can't reach the network except through a local proxy. A policy binds each secret to its hosts and to one slot in the request. The command only ever holds a placeholder, and the proxy puts the value in on the way to an allowed host. The agent can copy, encode or post the placeholder anywhere; outside its one slot on its own host, it's just text.

## Architecture

```
                              Claude Code session
                                      │
       ┌──────────────────────────────┼─────────────────────────────┐
       ▼                              ▼                             ▼
 secret-store.sh              PreToolUse hook                PostToolUse hook
 (native dialog,              (secret-guard.sh)              (secret-redact.sh)
  value → keychain)           wraps Bash in Seatbelt;        warns when output
       │                      refuses Read of files with     holds a stored value
       ▼                      values, edits to Blindfold's
  OS keychain ◄──┐            config and policies
                 │                    │
                 │                    ▼
                 │        ┌─────────── sandbox ────────────┐
                 │        │ the command Claude wrote        │
                 │        │ no keychain                     │
                 │        │ lockdown: no network but the    │
                 │        │ proxy; can't read tokens or     │
                 │        │ write Blindfold's files         │
                 │        └───────────────┬─────────────────┘
                 │                        │ HTTPS_PROXY (lockdown)
                 │                        ▼
                 │        blindfold-proxy (outside the sandbox)
                 └─────── 1. policy host? if not, plain tunnel
                          2. ask first, if the policy says so
                          3. read the value, fill its one slot
                          4. scrub it from the response
                          5. audit log
```

Under the basic level, `secret-exec.sh` sits where the proxy is: it reads the keychain outside the sandbox and fills the value into the command before running it inside.

### Components

| Component | File | Role |
|-----------|------|------|
| **Store** | `secret-store.sh` | Asks for the value in a native OS dialog, stores it in the keychain, registers the name |
| **Guard** | `secret-guard.sh` | PreToolUse hook. Wraps every Bash command in Seatbelt; with lockdown, points it at the proxy with placeholders and the local CA. Refuses Read of files holding a stored value, Read and Grep of the private folder, and Write or Edit of Blindfold's files and any `.blindfold.toml` |
| **Execute** | `secret-exec.sh` | Basic level: fills `{{PLACEHOLDER}}` values into a command, runs it sandboxed, redacts the output. Under lockdown it refuses secrets that have a policy |
| **Redact** | `secret-redact.sh` | PostToolUse hook. Warns Claude when Bash output holds a stored value |
| **Proxy** | `proxy/` (`blindfold-proxy`) | Lockdown: tunnels traffic, intercepts policy hosts with a local CA, fills placeholders, scrubs responses, asks for approval, writes the egress and audit logs |
| **Approve** | `secret-approve.sh` | Asks you to trust a project's `.blindfold.toml`, in the proxy's dialog or a terminal |
| **Sandbox** | `sandbox.sb`, `sandbox-egress.sb` | Seatbelt profiles. Both block the keychain. The egress one also blocks the network except loopback, writes to Blindfold's config and code, and reads of the private folder |
| **Library** | `lib.sh` | Backends, registry, sandbox setup, project tokens, path checks |

## Threat model

The attacker is content the agent reads: a README, an issue, a web page, a tool result. It can get the agent to run any command the sandbox allows. Trusted: you, the OS, the keychain, and Blindfold's own code running outside the sandbox.

### What Blindfold protects against

| Threat | Level | How |
|--------|-------|-----|
| The LLM seeing a raw value | Both | Values live in the keychain; the LLM works with `{{PLACEHOLDER}}` names |
| A command reaching the keychain itself | Both | Seatbelt blocks the keychain's Mach service, below the shell, however the command is written |
| A value in command output | Both | `secret-exec.sh` redacts it; under lockdown the proxy scrubs it from responses before the command sees them, gzip included |
| Reading back a file a value was written to | Both | The guard refuses Read of any file holding a stored value |
| Chaining commands onto Blindfold's own scripts | Both | Those run outside the sandbox, so the guard refuses a call that carries `;`, `&`, `\|`, redirects, a newline, `$(...)` or backticks |
| Sending a secret to an attacker's server | Lockdown | Commands only hold the placeholder; the proxy fills it in only for the policy's hosts |
| Encoding a secret to slip past redaction | Lockdown | There's no value in the command to encode |
| Planting a secret on an allowed host, e.g. in an issue body | Lockdown | The value only goes in the one header, basic-auth password or query parameter the policy names, never a body |
| Redirects, or a different `Host` inside a tunnel | Lockdown | A redirect is a new request, checked from scratch; a mismatched `Host` is refused |
| Widening a policy | Lockdown | The sandbox can't write the policy or Blindfold's files, the guard refuses Write and Edit on them, and a project policy only counts while it matches the exact copy you approved |
| One project using another's secrets | Lockdown | Each project has a token the sandbox can't read; a request without the right token gets the global policy only |
| A secret used for something you didn't expect | Lockdown | `approve = "writes"` or `"always"` asks in a dialog first. Deny is the default and is drawn on the right |
| Not knowing what happened | Lockdown | The audit log records every value filled in, echoed back, or refused |

### What Blindfold does not protect against

| Threat | Why | Mitigation |
|--------|-----|------------|
| **Exfiltration at the basic level** | The command holds the real value and can send it anywhere it can reach. | Turn on lockdown and write a policy for any secret used over HTTP. |
| **Misusing an allowed host** | The proxy keeps a secret from going anywhere else, but an agent can still make an unwanted call to the right host, like deleting a project. | Narrowly scoped tokens, and `approve = "writes"`. |
| **Tools that don't trust the local CA** | Go programs on macOS, `gh` among them, ignore `SSL_CERT_FILE`; certificate-pinning tools reject the CA. | They fail rather than leak. Use curl or an SDK for those hosts. |
| **Non-HTTP secrets under lockdown** | Only HTTP goes through the proxy. A database password used with `secret-exec.sh` is held by the command, and non-HTTP traffic can only reach this machine. | Fine for local services; remote ones need lockdown off for that work. |
| **Transformed echoes** | Scrubbing matches the stored value. A response holding it base64-encoded gets through. | Rare for real APIs. |
| **Placeholders in request bodies** | They're never filled in, but `outside-slot` audit lines only cover headers and URLs. | None needed for safety; it's a gap in the audit log only. |
| **Project tokens in process environments** | A project's token is in its commands' environment. Another process of yours that can read environments could see it and pass for that project. | Keep untrusted processes off the machine. |
| **No screen for a dialog** | Approvals and project trust need a GUI. Without one, gated requests are denied. | `secret-approve.sh` works from a terminal for project policies. |
| **Lockdown off** | Without lockdown, Bash commands aren't kept out of Blindfold's config, and the network is open. | Turn lockdown on before relying on a policy. |
| **Lockdown inside another sandbox** | macOS won't apply a network or file-rule profile inside another sandbox, such as Claude Code's own. | Use one sandbox or the other. |
| **SIGKILL temp files** | `kill -9` can't be trapped. `secret-exec.sh` temp files may persist. | Created with mode 600 and umask 077. |
| **`ps` during store** | `security add-generic-password -w VALUE` puts the value on the command line for a moment. | Short window; `security` has no stdin option for `-w`. |
| **Secrets under 4 characters** | Redaction and scrubbing skip them to avoid mangling output. | Real secrets are longer. |
| **Linux** | No Seatbelt: the guard falls back to string matching, and lockdown is macOS only. | Use macOS for security-critical work. |
| **Grep of project files** | Only Read is checked for stored values; Grep can show matching lines. | Keep secrets out of project files. |
| **Other malware running as you** | It can ask the keychain or the proxy directly. | Out of scope. |

## Platform security properties

| Property | macOS | Linux (GUI) | Linux (Headless) | Windows (WSL) |
|----------|-------|-------------|------------------|---------------|
| **Secret backend** | Keychain | GNOME Keyring / KWallet | GPG encrypted files | Credential Manager |
| **Sandbox enforcement** | Seatbelt (kernel-level) | String matching (bypassable) | String matching (bypassable) | None |
| **Egress lockdown** | Yes | No | No | No |
| **Input method** | osascript dialog | zenity / kdialog | Terminal prompt | PowerShell dialog |
| **Keychain isolation** | Per-keychain file | Per-user keyring | Per-directory GPG files | Per-user credential store |
| **Process isolation** | `sandbox-exec` | `bwrap` (if available) | None | None |

### macOS Seatbelt details

Both profiles deny `com.apple.SecurityServer` at the Mach IPC level. All keychain access goes through that service, regardless of how the command is constructed: Python subprocesses, base64-decoded scripts, temp file execution are all blocked, because the block is below the shell layer. The egress profile adds a network rule that only allows loopback, a write rule for Blindfold's config and code and the project's `.blindfold.toml`, and a read rule for the private folder.

## Known limitations

### macOS keychain state

If the login keychain is renamed, moved, or the keychain database is corrupted, `security` commands fail with "One or more parameters passed to a function were not valid."

**Symptoms:**
- `security list-keychains` returns an error
- `security create-keychain` fails
- `security add-generic-password` prompts to "reset to defaults"

**Fix:**
```bash
# Point macOS at the existing keychain file (find it in ~/Library/Keychains/)
security default-keychain -s ~/Library/Keychains/<your-keychain-file>.keychain-db
security list-keychains -s ~/Library/Keychains/<your-keychain-file>.keychain-db
```

**WARNING:** Do NOT choose "Reset to Defaults" when prompted. This deletes all existing keychain entries (saved passwords, certificates, keys). Fix the path instead. The same dialog appears when something sandboxed tries to write to the keychain; cancel it.

### Dedicated keychain for automation

For automated tools (CI, background agents), consider a dedicated Blindfold keychain instead of the login keychain:

```bash
security create-keychain -p "" ~/Library/Keychains/blindfold.keychain-db
security unlock-keychain -p "" ~/Library/Keychains/blindfold.keychain-db
security set-keychain-settings ~/Library/Keychains/blindfold.keychain-db
```

Then set `BLINDFOLD_KEYCHAIN` to point to it. The proxy reads from the same keychain.

### Hook performance

The hooks run on every Bash, Read, Grep, Write and Edit call. With lockdown on, a Bash call also reads the proxy's state file and, in a project with a policy, compares it with the approved copy; the proxy itself is started once and reused. The redact hook reads each registered secret from the keychain, so its cost grows with the number of secrets.

## Comparison to alternatives

| Feature | `.env` files | Blindfold | HashiCorp Vault | 1Password CLI |
|---------|-------------|-----------|-----------------|---------------|
| **Cost** | Free | Free | Free (dev) / Paid (enterprise) | $2.99+/mo |
| **LLM-aware** | No, the LLM reads `.env` directly | Yes, the LLM sees `{{PLACEHOLDER}}` only | No | No |
| **Output redaction** | No | Yes (`secret-exec.sh`, and proxy scrubbing under lockdown) | No | No |
| **Sandbox isolation** | No | Yes (macOS Seatbelt) | N/A (server-side) | No |
| **Secret backend** | Plaintext file | OS keychain | Encrypted server | Encrypted vault |
| **Setup complexity** | Trivial | Low (plugin install; lockdown needs Go to build the proxy) | High (server + auth) | Medium (CLI + account) |
| **Rotation support** | Manual | Manual | Automatic | Automatic |
| **Audit logging** | None | Local log under lockdown | Full | Full |
| **Multi-user** | No (file sharing) | No (per-user keychain) | Yes | Yes (family/team) |

What Blindfold is for is the agent in the middle. Secrets never enter its context window, and under lockdown a value can't go anywhere but its own host, even when the agent is working against you. The tools in this table are good at keeping secrets safe at rest and in transit; they weren't built with an agent between you and the secret in mind.

## Responsible disclosure

If you discover a security vulnerability in Blindfold:

1. **Do not** open a public issue.
2. Email the maintainer with a description of the vulnerability, steps to reproduce, and potential impact.
3. Allow 90 days for a fix before public disclosure.

Contact [thesaadmirza](https://github.com/thesaadmirza) via GitHub.
