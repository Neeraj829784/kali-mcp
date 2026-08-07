# Program Scope & Policy

A **program** is a named authorization boundary. Where basic [scope](security.md)
is a simple allowlist, a program adds **out-of-scope rules**, rules of
engagement, and persistence — the things you need for real bug-bounty or
contracted work where "what am I allowed to touch?" has a precise answer.

## Why programs exist

Bug-bounty and pentest scopes are rarely "everything in this CIDR". They're
"this CIDR **except** these hosts", plus rate limits, plus allowed hours, plus a
record of who approved it. A program captures all of that under one name and
enforces the in/out-of-scope part on every tool call.

The key capability over a plain allowlist: **out-of-scope always wins**. A
denied target is refused even if it falls inside an in-scope range — and even in
lab mode. That protects you from accidentally scanning the one box the client
told you to leave alone.

## Core concepts

- **in_scope** — targets you're authorized to test (IPs, CIDRs, domains, `*.wildcards`).
- **out_of_scope** — targets that must never be touched. Overrides in-scope.
- **rules** — a free-form dict for rules of engagement (e.g. `max_findings`,
  `duration_hours`, `reporting_format`).
- **approvers** — who authorized/​can modify the program.

Programs persist in a database, and the active program is restored across
restarts, so scope stays enforced.

## Quick start

```
# Create and activate a program — sets the allowlist AND the denylist
program_scope_start(
    name="ACME-BugBounty-2026",
    in_scope=["10.10.10.0/24", "*.acme.com"],
    out_of_scope=["10.10.10.254", "admin.acme.com"],
    client="ACME Ltd",
    rules={"max_findings": 100, "duration_hours": 48}
)

# From here, every tool checks this scope.
# 10.10.10.50      → allowed (in the CIDR)
# admin.acme.com   → BLOCKED (explicitly out of scope, even though *.acme.com is in scope)
# 8.8.8.8          → BLOCKED (not in scope)
```

## Managing a program

```
program_scope_status()                          # what's active right now
program_scope_list()                            # every program on record

program_scope_add_targets(["dev.acme.com"])     # widen in-scope
program_scope_remove_targets(["10.10.10.0/24"]) # narrow in-scope

program_scope_out_of_scope(["backup.acme.com"]) # add a deny rule
program_scope_allow("api.acme.com")             # explicitly allow one target
program_scope_deny("legacy.acme.com")           # explicitly deny one target

program_scope_end()                             # close it and clear scope
```

## How enforcement works

Under the hood, activating a program sets two lists that `check_scope()`
consults before any tool touches a target:

1. **Denylist** (out-of-scope) is checked first — a match raises an error
   immediately, even in lab mode.
2. **Allowlist** (in-scope) is checked next — if it's non-empty and the target
   isn't in it, the target is refused.

This is the same enforcement path every tool already uses, so no tool can bypass it.

## Programs vs Engagements

- A **program** answers *"what am I allowed to touch?"* and can span many sessions.
- An **[engagement](engagements.md)** answers *"what did I find this session, and what's the report?"*

You'll often run several engagements under one long-lived program.

## Next steps

- [Asset Inventory](asset-inventory.md) — track everything the program's scans discover
- [Security Model](security.md) — the scope-enforcement internals
