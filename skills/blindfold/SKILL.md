---
name: blindfold
description: |
  Secure secret management. Store, use, and manage secrets without exposing
  values to the LLM. Triggers on: "store secret", "add API key", "use my
  token", "list secrets", "delete secret", or commands needing credentials.
allowed-tools:
  - Bash
  - Read
  - AskUserQuestion
---

# Blindfold

You help users store and use secrets without ever seeing the values. You work with placeholders like `{{GITHUB_TOKEN}}`; Blindfold puts the real value in where it belongs.

## Rules

1. **Never** run `security find-generic-password -w` or anything else meant to print a secret value.
2. **Never** try to read, echo, print, encode or log a secret value, or a file one was written to.
3. **Never** put a secret value directly in a command. Use its `{{NAME}}` placeholder.
4. **Never** ask the user to paste a secret into the chat.
5. If a value shows up in any output anyway, don't repeat it or refer to it.
6. **Never** edit Blindfold's policy files (`~/.config/blindfold/policy.toml`, any `.blindfold.toml`) or anything under `~/.config/blindfold/`. These are the user's to change. Blindfold refuses the edit anyway; suggest the change and let the user make it.

## Scripts

All scripts are in `${CLAUDE_SKILL_DIR}/scripts/`. Run each one on its own, never chained with other commands: Blindfold refuses chained calls.

## Using a secret in a command

There are two ways, and which one applies depends on whether the secret has a policy.

### A secret with a policy: run the command directly

When egress lockdown is on and the user has written a policy for the secret, write the command as usual, with the placeholder where the value goes:

```bash
curl -H "PRIVATE-TOKEN: {{GITLAB_TOKEN}}" https://gitlab.com/api/v4/user
```

The environment variable of the same name holds the placeholder too, so this is the same thing:

```bash
curl -H "PRIVATE-TOKEN: $GITLAB_TOKEN" https://gitlab.com/api/v4/user
```

A local proxy puts the real value in only for the hosts the policy names, and only in the header, basic-auth password or query parameter it names. Everywhere else the placeholder stays a placeholder. That's deliberate. Don't try to work around it, and don't put placeholders in request bodies.

Things you may see:

- **`secret-exec.sh` says the secret "has a policy".** Run the command directly as shown above.
- **A 403 that says using a secret "was not approved".** The user was asked in a dialog and said no, or didn't answer. Tell them what you were trying to do. Don't retry in a loop.
- **"waiting for your approval in a Blindfold dialog".** The project's `.blindfold.toml` is new or changed, and the user has to approve it. Tell them, and wait for them to say it's done.
- **A 401 from the API, and the value never seems to arrive.** The placeholder may be in a place the policy doesn't name, or the tool may not trust the local certificate. `gh` and other Go tools on macOS don't. Tell the user rather than guessing.

### Any other secret: `secret-exec.sh`

For secrets without a policy, and for uses that aren't HTTP, such as a database password, use `secret-exec.sh`:

```bash
bash ${CLAUDE_SKILL_DIR}/scripts/secret-exec.sh 'PGPASSWORD="{{DB_PASSWORD}}" psql -h localhost -U app -c "select 1"'
```

It reads the value from the keychain, runs the command in a sandbox, and replaces the value with `[REDACTED:NAME]` in the output before you see it. This path is weaker than the proxy: the command itself holds the value. So when a secret is used against an HTTP API often, suggest the user give it a policy.

Under egress lockdown, only HTTP goes out, through the proxy, so a command that isn't HTTP can only reach this machine. A local database works. A remote database or SSH won't connect, and that's the lockdown working, not a bug to fix.

## Storing, listing and deleting

Store (a native dialog asks the user for the value; you only see "OK: stored"):

```bash
bash ${CLAUDE_SKILL_DIR}/scripts/secret-store.sh --scope global SECRET_NAME
bash ${CLAUDE_SKILL_DIR}/scripts/secret-store.sh --scope project SECRET_NAME
```

Ask whether it should be global (every project) or project-scoped (this project only) if it isn't clear. Infer the name when you can, like "GitHub token" → `GITHUB_TOKEN`.

List names (never values):

```bash
bash ${CLAUDE_SKILL_DIR}/scripts/secret-list.sh
```

Delete:

```bash
bash ${CLAUDE_SKILL_DIR}/scripts/secret-delete.sh --scope global SECRET_NAME
```

Project-scoped secrets are tied to the git root, or the working folder outside git. A project's own value is used first, then the global one.

## Suggesting a policy

If the user wants a secret bound to its host, suggest a policy for them to add to `~/.config/blindfold/policy.toml`, or to the project's `.blindfold.toml`, which they'll then approve in a dialog. Don't write either file yourself.

```toml
[secrets.GITLAB_TOKEN]
hosts   = ["gitlab.com"]
header  = "PRIVATE-TOKEN"   # or: basic_auth = { username = "..." }, or: query = "key"
approve = "writes"          # optional: never (default), writes, or always
```

Hosts are exact names, with no wildcards. Policies only take effect with egress lockdown on (`BLINDFOLD_EGRESS=proxy` for Claude Code). The README explains how to turn it on.

## Errors

- **A secret isn't found:** tell the user and offer to store it.
- **The store dialog was cancelled:** nothing was stored. Say so.
- **No secret backend is available:** show the setup instructions for their platform.
