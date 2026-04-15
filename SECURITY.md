# Security Model

This document describes Blindfold's security architecture, threat model, known limitations, and platform-specific properties.

## Architecture

```
                          Claude Code Session
                                 |
     ┌───────────────────────────┼───────────────────────────┐
     │                           │                           │
     ▼                           ▼                           ▼
 secret-store.sh          PreToolUse Hook             PostToolUse Hook
     │                    (secret-guard.sh)           (secret-redact.sh)
     │                           │                           │
     │                           ▼                           ▼
     │                    Blocks keychain              Scans output for
     │                    access from inside           leaked secret values.
     │                    sandboxed commands.           Replaces with
     │                    macOS: Seatbelt              [REDACTED:NAME]
     │                    Linux: string match          before Claude sees it.
     │                           │
     ▼                           ▼
 OS Keychain              secret-exec.sh
 (macOS Keychain,         ┌─────────────────┐
  GNOME Keyring,          │ 1. Read secrets  │
  GPG, WinCred)           │    from keychain │
     ▲                    │ 2. Inject as     │
     │                    │    __SV_ env vars│
     │                    │ 3. Run command   │
     └────────────────────│    in sandbox    │
                          │ 4. Redact output │
                          │ 5. Clean up      │
                          │    temp files    │
                          └─────────────────┘
```

### Component Responsibilities

| Component | File | Role |
|-----------|------|------|
| **Store** | `secret-store.sh` | Prompts for value via native OS dialog, stores in keychain, registers in JSON registry |
| **Guard** | `secret-guard.sh` | PreToolUse hook. On macOS, wraps every Bash command in Seatbelt sandbox blocking keychain access |
| **Execute** | `secret-exec.sh` | Resolves `{{PLACEHOLDER}}` syntax, injects secrets as env vars, runs command in sandbox, redacts output |
| **Redact** | `secret-redact.sh` | PostToolUse hook. Scans Bash output for leaked secret values, replaces with `[REDACTED:NAME]` |
| **List** | `secret-list.sh` | Shows registered secrets with backend status (never shows values) |
| **Delete** | `secret-delete.sh` | Removes from keychain and registry |
| **Library** | `lib.sh` | Shared functions: backend detection, keychain operations, registry management, sandboxing |
| **Sandbox** | `sandbox.sb` | macOS Seatbelt profile blocking `com.apple.SecurityServer` Mach IPC |

## Threat Model

### What Blindfold Protects Against

| Threat | Protection | Mechanism |
|--------|-----------|-----------|
| LLM seeing raw secret values | Secrets stored in OS keychain, LLM works with `{{PLACEHOLDER}}` references | `secret-store.sh`, `secret-exec.sh` |
| Sandboxed commands accessing keychain | Seatbelt sandbox blocks keychain Mach IPC at kernel level | `sandbox.sb`, `secret-guard.sh` |
| Secret values in command output | PostToolUse hook replaces values with `[REDACTED:NAME]` | `secret-redact.sh` |
| Obfuscated keychain access attempts | Seatbelt operates at Mach IPC level, not string matching (macOS) | `sandbox.sb` |
| Secret registry tampering | Atomic updates via temp file + `jq` validation + `mv` | `lib.sh:update_registry()` |

### What Blindfold Does NOT Protect Against

| Threat | Reason | Mitigation |
|--------|--------|------------|
| **SIGKILL temp file persistence** | `kill -9` cannot be trapped by any process. Temp files containing secrets may persist in `/tmp/`. | Files created with 600 permissions and umask 077. Trap handlers cover SIGTERM, SIGINT, SIGHUP. |
| **`ps` visibility during store** | `security add-generic-password -w VALUE` passes the value as a CLI argument, briefly visible in process listing. | Exposure window is very short (milliseconds). macOS `security` command does not support stdin for `-w`. |
| **Secrets shorter than 4 characters** | `MIN_REDACT_LENGTH=4` prevents false positive redaction of short strings. | Configure `MIN_REDACT_LENGTH` in `lib.sh` if needed. Secrets should be long by nature. |
| **Linux guard bypass via obfuscation** | Linux falls back to string matching (no Seatbelt equivalent). Commands can be obfuscated to bypass pattern matching. | Use macOS for security-critical workloads. Linux bubblewrap (`bwrap`) support is partial. |
| **`env` command dumping `__SV_` vars** | If a sandboxed command runs `env`, the `__SV_`-prefixed vars containing secrets would be visible. | The LLM doesn't know the `__SV_` prefix exists. The sandbox blocks keychain but not env inspection. |
| **Registry file readable by user** | `secrets-registry.json` lists secret names (not values) with 600 permissions. | Names are not sensitive. Values are in the OS keychain only. |

## Platform Security Properties

| Property | macOS | Linux (GUI) | Linux (Headless) | Windows (WSL) |
|----------|-------|-------------|------------------|---------------|
| **Secret backend** | Keychain | GNOME Keyring / KWallet | GPG encrypted files | Credential Manager |
| **Sandbox enforcement** | Seatbelt (kernel-level) | String matching (bypassable) | String matching (bypassable) | None |
| **Input method** | osascript dialog | zenity / kdialog | Terminal prompt | PowerShell dialog |
| **Keychain isolation** | Per-keychain file | Per-user keyring | Per-directory GPG files | Per-user credential store |
| **Process isolation** | `sandbox-exec -f sandbox.sb` | `bwrap` (if available) | None | None |

### macOS Seatbelt Details

The sandbox profile (`sandbox.sb`) denies `com.apple.SecurityServer` at the Mach IPC level. This is the service that all keychain access goes through, regardless of how the command is constructed. Python subprocesses, base64-decoded scripts, temp file execution, dynamically generated commands -- all blocked because the block is below the shell layer.

## Known Limitations

### macOS Keychain State

If the login keychain is renamed, moved, or the keychain database is corrupted, `security` commands will fail with "One or more parameters passed to a function were not valid."

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

**WARNING:** Do NOT choose "Reset to Defaults" when prompted. This deletes all existing keychain entries (saved passwords, certificates, keys). Fix the path instead.

### Dedicated Keychain for Automation

For automated tools (CI, background agents), consider creating a dedicated Blindfold keychain instead of sharing the login keychain:

```bash
security create-keychain -p "" ~/Library/Keychains/blindfold.keychain-db
security unlock-keychain -p "" ~/Library/Keychains/blindfold.keychain-db
security set-keychain-settings ~/Library/Keychains/blindfold.keychain-db
```

Then set `BLINDFOLD_KEYCHAIN` environment variable to point to it. This isolates Blindfold secrets from the login keychain and avoids authorization prompts in automated contexts.

### Hook Performance

PreToolUse and PostToolUse hooks run on every Bash command. Each hook invocation:
- Reads the registry file (JSON parse via `jq`)
- On redact: retrieves each registered secret from the keychain for comparison

With zero secrets registered, the hooks exit quickly. With many secrets, there is a per-command overhead proportional to the number of registered secrets.

## Comparison to Alternatives

| Feature | `.env` files | Blindfold | HashiCorp Vault | 1Password CLI |
|---------|-------------|-----------|-----------------|---------------|
| **Cost** | Free | Free | Free (dev) / Paid (enterprise) | $2.99+/mo |
| **LLM-aware** | No -- LLM reads `.env` directly | Yes -- LLM sees `{{PLACEHOLDER}}` only | No | No |
| **Output redaction** | No | Yes (PostToolUse hook) | No | No |
| **Sandbox isolation** | No | Yes (macOS Seatbelt) | N/A (server-side) | No |
| **Secret backend** | Plaintext file | OS keychain | Encrypted server | Encrypted vault |
| **Setup complexity** | Trivial | Low (plugin install) | High (server + auth) | Medium (CLI + account) |
| **Rotation support** | Manual | Manual | Automatic | Automatic |
| **Audit logging** | None | None | Full | Full |
| **Multi-user** | No (file sharing) | No (per-user keychain) | Yes | Yes (family/team) |
| **CI/CD integration** | Via env injection | Via keychain + hooks | Native | Via CLI |

Blindfold's unique value is **LLM context isolation**: secrets never enter the AI's context window. Other tools secure secrets at rest and in transit but don't address the LLM-specific attack surface.

## Responsible Disclosure

If you discover a security vulnerability in Blindfold:

1. **Do not** open a public issue.
2. Email the maintainer with a description of the vulnerability, steps to reproduce, and potential impact.
3. Allow 90 days for a fix before public disclosure.

Contact [thesaadmirza](https://github.com/thesaadmirza) via GitHub.
