# Asset Inventory

The asset inventory is a **persistent, project-wide database of everything you
discover** — hosts, services, and vulnerabilities — that outlives any single
engagement. It answers questions like *"what do we already know about
10.10.10.5?"* even across different test sessions.

## Why it's separate from engagements

An [engagement](engagements.md) is a session — it comes and goes. The asset
inventory is the long-term memory. Findings from every scan flow into it
automatically, building a living map of the target environment over time. This
is also what makes [continuous recon](continuous-recon.md) and change detection
possible.

## What it stores

Three linked record types:

- **Hosts** — IPs/hostnames, when first and last seen, how many times scanned, and a status.
- **Services** — per host: port, protocol, service name, version, state, banner.
- **Vulnerabilities** — per host/service: title, CVE (if any), severity, confidence, remediation, and a status.

Records are de-duplicated on ingest: re-scanning a host updates its `last_seen`
and bumps its `scan_count` rather than creating duplicates.

## Statuses

Both hosts and vulnerabilities carry a workflow status you can set as you triage:

- Hosts: `new` · `scanned` · `confirmed` · `remediated` · `false_positive`
- Vulnerabilities: `unconfirmed` · `confirmed` · `false_positive` · `remediated`

## Exploring the inventory

```
asset_list_hosts()                              # every known host
asset_list_hosts(status="confirmed")            # filter by status

asset_get_host("10.10.10.5")                    # full detail: services + vulns

asset_list_services(service_name="http")        # every HTTP service found
asset_list_services(host_ip="10.10.10.5")       # services on one host

asset_list_vulnerabilities(min_severity="high") # the serious stuff
asset_list_vulnerabilities(host_ip="10.10.10.5")

asset_search("CVE-2021-44228")                  # search by CVE
asset_search("10.10.10")                        # ...or IP / hostname / service
```

## Triage actions

```
asset_mark_host("10.10.10.5", "confirmed")
asset_mark_vuln(42, "false_positive")
```

## Where the data comes from

You rarely populate it by hand. Any scan whose findings pass through the
[finding pipeline](finding-pipeline.md) is ingested automatically — including a
CVE extracted from the finding's title/evidence, and a best-effort remediation
hint based on the finding type.

## Scan runs

The inventory also records **scan runs** — each recon cycle is timestamped and
remembers exactly which assets it observed. That's the foundation for diffing
one run against another. See [Continuous Recon](continuous-recon.md) for
`asset_list_runs`, `asset_diff_runs`, and `asset_latest_changes`.

## Next steps

- [Continuous Recon](continuous-recon.md) — schedule recon and detect changes over time
- [The Finding Pipeline](finding-pipeline.md) — how findings get here
