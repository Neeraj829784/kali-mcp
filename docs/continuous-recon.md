# Continuous Recon

Attack surface changes constantly — new subdomains appear, new ports open, apps
get redeployed. A one-time scan is a snapshot of a moving target. Continuous
recon answers the more valuable question: **"what changed since last time?"**

For bug-bounty work especially, being *first* on newly-exposed surface is where
the wins are. A freshly-deployed staging box with debug mode on is far more
likely to be vulnerable — and far less likely to have been tested by everyone else.

## How it works

Continuous recon builds on the [asset inventory](asset-inventory.md)'s **scan
runs**. Each run records exactly which assets it observed. Comparing two runs
tells you precisely what's new, what disappeared, and what changed.

```
recon_sweep(domain="acme.com", program="ACME-BugBounty-2026")
```

A sweep:

1. Opens a new scan run.
2. Runs **passive** recon tools (subfinder, `amass -passive`, theHarvester)
   within the active program's scope.
3. Ingests every result into the asset inventory under that run's id.
4. Closes the run and diffs it against the previous run for the same program.
5. Returns the changes, with newly-appeared assets flagged as high priority.

It's **passive by design** — safe to run repeatedly and unattended without
tripping WAFs or straying outside rules of engagement.

## What a sweep reports

- **New subdomains** (surfaced as new hosts, so they stand out)
- **New IPs and open ports**
- **New services / web applications**
- **New vulnerabilities**
- **Disappeared assets** — things present last time but gone now
- **priority_new_assets** — the freshly-appeared hosts/services, called out
  first because new surface is often less tested

The first sweep for a program has nothing to compare against, so it establishes
a **baseline** and reports no diff. Every sweep after that reports changes.

## Controlling a sweep

```
recon_sweep(domain="acme.com")                          # all passive tools
recon_sweep(domain="acme.com", tools=["subfinder"])     # just one
recon_sweep(domain="acme.com", tool_budget=1)           # cap tools per sweep
recon_sweep(domain="acme.com", program="ACME-2026")     # group under a program
```

`tool_budget` supports per-program scan budgets — handy when you want a light,
cheap sweep on a frequent schedule.

## Inspecting runs and diffs directly

```
asset_list_runs(program="ACME-2026")            # every recorded run
asset_diff_runs(prev_run_id=7, curr_run_id=9)   # compare any two runs
asset_latest_changes(program="ACME-2026")       # diff the two most recent runs
```

## Scheduling

kali-mcp intentionally does **not** run a background scheduler daemon — it's a
stdio server with no long-running process (a deliberate security choice, see
[Security Model](security.md)). To run sweeps on a schedule, drive `recon_sweep`
from outside: a `cron` job or `systemd` timer that invokes it periodically. This
keeps the "continuous" benefit without weakening the server's security posture.

## Next steps

- [Asset Inventory](asset-inventory.md) — where runs and results are stored
- [Program Scope & Policy](program-scope.md) — scope + budgets a sweep respects
