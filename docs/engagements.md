# Engagements

An **engagement** is a named test session. It's the professional wrapper around
your work: it sets scope, tags every finding to the session, tracks validation
status, and produces the final report. If you're doing a real assessment, start
here.

## Why use an engagement?

Without one, kali-mcp still works (findings are extracted and stored), but an
engagement gives you:

- **Automatic scope** — the targets you pass become the allowlist for every tool.
- **Automatic tagging** — every finding is linked to this engagement.
- **A validation workflow** — mark findings confirmed or false-positive.
- **A one-command report** — scoped to this engagement's findings.
- **Persistence** — the active engagement survives a server restart.

## The full lifecycle

```
# 1. Start — this sets scope on every tool automatically
engagement_start(name="ACME-WebApp-2026", scope=["10.10.10.0/24"], client="ACME Ltd")

# 2. Scan — run any workflow or tool; findings auto-tag to the engagement
scan_host(target="10.10.10.5")

# 3. Triage — reads straight from the engagement's database (fast)
analyze_findings(min_severity="medium")
analyze_attack_chains()

# 4. Validate (optional, for a zero-false-positive report)
list_unconfirmed_findings()
update_finding_status(finding_id=42, status="confirmed")
update_finding_status(finding_id=43, status="false_positive")

# 5. Report
generate_pentest_report(
    format="html",
    confirmed_only=True,
    save_to="artifacts/ACME-report.html"
)

# 6. Close — clears scope back to lab mode
engagement_end()
```

## Finding statuses

Every tagged finding starts as `unconfirmed`. During validation you move it to:

- `confirmed` — verified real and exploitable
- `false_positive` — not real; excluded from a `confirmed_only` report
- `unconfirmed` — reset back to pending

`list_unconfirmed_findings()` lets a human — or a dedicated validation agent —
work through them one at a time. See
[False-Positive Reduction](false-positive-reduction.md).

## What the report includes

`generate_pentest_report()` produces a client-ready document (Markdown or a
self-contained HTML file):

- Executive summary with host/finding counts and an overall risk rating
- **Attack chains** section with compound-impact narratives
- Findings grouped by severity (critical → info)
- Per finding: host, contributing tool(s), evidence, and CVE-specific remediation
- A scan-coverage appendix (tools used, job count, timestamp)

Set `confirmed_only=True` to include only findings you've validated — the
recommended mode for client delivery.

## Engagements vs Programs

They're complementary:

- An **engagement** is a *session* — it groups findings and produces a report.
- A **[program](program-scope.md)** is an *authorization boundary* — named
  in/out-of-scope rules and rules of engagement that can outlive a single session.

Use an engagement for "this week's test of ACME"; use a program for "the ACME
bug-bounty scope that applies across many sessions".

## Next steps

- [Program Scope & Policy](program-scope.md) — richer scope with out-of-scope rules
- [Asset Inventory](asset-inventory.md) — the persistent, cross-engagement view
