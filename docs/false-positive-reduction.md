# False-Positive Reduction

A scanner-wrapping tool is only as useful as it is *trustworthy*. Because
kali-mcp is driven by an AI, it faces two sources of false positives:

1. **Tool noise** — scanners like nikto and gobuster emit a lot of low-value or
   spurious results.
2. **AI over-claiming** — a language model can misread output, inflate severity,
   or report an unconfirmed guess as fact.

kali-mcp fights both with layered defenses. This page explains each one so you
understand *why* the findings you see can be trusted.

## Layer 1 — Evidence-anchored confidence floor

**Rule: a finding may only claim medium/high confidence if it is backed by
concrete evidence.**

Every finding carries an `evidence` field. If that field is empty or trivial
(and the finding wasn't corroborated by multiple tools), the pipeline caps its
confidence at `low` and marks it `confidence_capped: true`.

Why it matters: neither a noisy tool nor the AI can present an unsubstantiated
claim as high-confidence. Confidence becomes *server-authoritative* — earned
from real output, not asserted.

```
Finding with real evidence  → keeps its confidence
Finding with no evidence     → forced to LOW, flagged as capped
Finding seen by 2+ tools     → exempt (agreement is itself evidence)
```

## Layer 2 — Active web verification

For web-path findings (from gobuster/ffuf), the server **re-requests the path
itself** and decides its fate from the actual HTTP response — not from what the
scanner claimed.

### Soft-404 / wildcard baseline

Many servers return `200 OK` for *everything*, including nonsense paths. The
pipeline first requests a random path that shouldn't exist to fingerprint that
"not found" response. Any discovered path matching the baseline (same status,
near-identical length) is dropped as a false positive.

### Catch-all clustering

Some apps (single-page apps, catch-all routers) return the *same* response for
many different paths. If a large group of distinct paths all share the same
`(status, length)` signature, the whole cluster is treated as a wildcard
responder and dropped — something the pairwise baseline alone can miss.

### Content-aware proof

Certain high-value findings are verified by their *content*, not just status:

| Finding | How it's proven |
|---|---|
| Exposed `.git` | Fetch `/.git/HEAD` and confirm it's a real git ref (`ref: refs/...` or a commit hash) |
| Exposed `.env` | Confirm the body actually contains `KEY=value` lines |

A "`.git` exposure" that returns a styled 404 page is **disproven and dropped**.
A genuinely exposed repo is **promoted to HIGH confidence**. Only findings the
server itself verified earn high confidence.

> This layer never loses data on error: if a request fails (network issue,
> timeout), the finding is passed through unchanged rather than dropped.

## Layer 3 — Cross-tool corroboration

During deduplication, when two or more *distinct* tools independently report the
same finding, its confidence is boosted one level. Agreement between
independent tools is strong evidence — and it exempts a finding from the
evidence floor, since the corroboration itself is the evidence.

## Layer 4 — Reporting rules for the AI

The `reporting_rules()` prompt gives the AI explicit, non-negotiable instructions
when it writes up findings:

1. Only report findings present in the structured data — never invent CVEs,
   versions, or hosts a tool didn't return.
2. Use the server-assigned `severity` and `confidence` **verbatim** — never
   upgrade a `low` to `high`.
3. Treat `confidence_capped` / low-confidence findings as tentative, not fact.
4. Cite the `evidence` field for every finding presented.
5. Prefer `confirmed_only=True` reports for client delivery.
6. Never claim exploitation succeeded unless a tool result explicitly shows it.

## Layer 5 — Human/agent validation (optional, strongest)

For a zero-false-positive deliverable, run a validation pass before reporting:

```
list_unconfirmed_findings()                      # findings awaiting review
update_finding_status(finding_id=42, "confirmed")
update_finding_status(finding_id=43, "false_positive")

generate_pentest_report(confirmed_only=True)     # only confirmed findings included
```

This is ideal for a dedicated verification agent whose only job is to confirm or
deny each finding — an independent reviewer that reduces confirmation bias.

## The net effect

By the time a finding reaches your report, it has survived evidence anchoring,
active re-verification, clustering, and (optionally) explicit confirmation. The
result is a report you can hand to a client with far fewer "that's not real"
moments.

## Next steps

- [The Finding Pipeline](finding-pipeline.md) — where these layers sit
- [Engagements](engagements.md) — the validation + reporting workflow
