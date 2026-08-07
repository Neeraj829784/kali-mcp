# Security Model

kali-mcp exposes real command-execution tooling, so it's built defensively. This
page explains the protections in place — useful both for trusting the tool and
for running it responsibly.

## Transport: stdio only, no network

The server speaks MCP over **stdio** — the client launches it as a child
process. There is no network socket and no authentication layer, because none
is needed: access is bounded by who can run the process locally.

The HTTP/SSE transports are **refused** unless you explicitly override them,
because they would expose every tool (nmap, sqlmap, metasploit, `ssh_exec`, ...)
to any client that can reach the port — completely unauthenticated. If you ever
set `KALI_MCP_TRANSPORT` to something else, the server demands
`KALI_MCP_INSECURE_ALLOW_NETWORK=yes` and warns loudly. Don't do this outside an
isolated lab behind an authenticating proxy.

## Scope enforcement

Every tool call validates its target before doing anything.

```
scope empty      = lab mode — all targets allowed
scope populated  = restricted — only listed targets allowed

Supported entries:
  10.0.0.1          exact IP
  192.168.1.0/24    CIDR range
  example.com       exact domain
  *.example.com     wildcard subdomain (matches subdomains and the apex)
```

An **out-of-scope denylist** (set by an active [program](program-scope.md)) is
checked *first* and overrides everything — a denied target is refused even in
lab mode. The scope cache is guarded by a lock, so it's safe under the parallel
tool execution that workflows trigger.

## Input validation (argument-injection defense)

Everything runs via an argv list (never a shell), so classic shell injection is
impossible. The remaining risk is *argument injection* — a value like
`-oN/tmp/x` being read as a flag. Two defenses:

- **Global guard:** any target beginning with `-` is rejected (`check_scope`
  runs this for every tool, even in lab mode).
- **nmap allowlist regex:** nmap targets must match IP/CIDR/hostname/range/
  wildcard patterns. `--script=evil`, `/etc/passwd`, and `10.0.0.1;id` are all
  rejected before a subprocess runs.

## Credential vault

Discovered credentials are encrypted at rest.

```
Encryption:  Fernet (AES-128-CBC + HMAC)
Key source:  KALI_MCP_VAULT_KEY env var, or an auto-generated vault.key (0600)
Storage:     vault.db (git-ignored)
Thread safe: double-checked locking on key initialization
```

Prefer supplying `KALI_MCP_VAULT_KEY` from a secret manager. Losing the key makes
stored ciphertext unrecoverable, so back it up with the engagement.

## SSH host-key pinning (TOFU)

`ssh_exec` / `ssh_enum_privesc` use trust-on-first-use pinning: the first
connection to a host pins its key; a later key change is rejected as a possible
man-in-the-middle attack, instead of being silently accepted.

## File access

- File reads are restricted to an allowlist of directories (artifacts, `/tmp`,
  `/var/tmp`, wordlist dirs) and refuse sensitive filenames (SSH keys, `.env`,
  shell history, `.aws/`, ...).
- Report/output save paths are validated by `safe_save_path()` — writes are
  confined to the artifacts dir, `/tmp`, or `/var/tmp`, blocking `../` traversal.

## Process isolation

Each tool runs in its own session (`setsid`), so on timeout or cancel the whole
process group is killed — no orphaned scanners. A global semaphore caps how many
tool subprocesses run at once.

## Secrets in git

These are always git-ignored and must never be committed:

```
vault.key   vault.db   jobs.db   engagements.db   programs.db
known_hosts   audit.log   scope.txt   artifacts/
```

If you set `KALI_MCP_DATA_DIR`, all of these live in that one directory — easy to
lock down and keep out of the repo.

## Audit trail

Every tool call is appended to `audit.log`:

```
2026-06-15 14:32:10 scope_add target=10.10.10.0/24
2026-06-15 14:32:15 get_job_status job_id=a1b2c3d4
```

## Your responsibility

These controls reduce risk; they don't replace authorization. Only test systems
you own or are explicitly permitted to test. Use [programs](program-scope.md) to
encode that authorization and keep yourself inside it.

## Next steps

- [Program Scope & Policy](program-scope.md) — encode authorization boundaries
- [Configuration](configuration.md) — the environment variables referenced here
