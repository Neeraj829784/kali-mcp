# Testing

kali-mcp ships with a large test suite (~370 tests across 32 files). Most are
fast and offline; a subset that drives real tools against live targets is marked
so it's skipped by default.

## Running tests

```bash
# Fast suite — the default (slow/live tests are excluded automatically)
pytest

# Verbose
pytest -v

# A specific area
pytest tests/test_findings.py
pytest tests/test_chains.py

# Include the slow / live-target integration tests
pytest -m "slow or live"
```

The default configuration (`pyproject.toml`) runs with `-m 'not slow'`, so a
plain `pytest` stays quick. `slow` tests are long-running; `live` tests need a
reachable target.

## What's covered

### Core & pipeline
| File | Covers |
|---|---|
| `test_core.py` | JobManager, ToolExecutor, scope |
| `test_findings.py` | Extractors, dedup, soft-404 verification |
| `test_evidence_floor.py` | Evidence-anchored confidence capping |
| `test_web_verification.py` | `.git`/`.env` content proof, catch-all clustering |
| `test_chains.py` | Attack-chain templates and confidence-weighted signals |
| `test_suggest.py` | Auto-suggest logic for every tool branch |

### Features
| File | Covers |
|---|---|
| `test_program_scope.py` | Program create/activate, in/out-of-scope enforcement |
| `test_asset_inventory.py` | Host/service/vuln ingest, dedup, search, statuses |
| `test_continuous_recon.py` | Scan-run diffing, disappeared detection, `recon_sweep` |
| `test_data_dir.py` | `KALI_MCP_DATA_DIR` relocation + backward compatibility |
| `test_finding_status.py` | Validation workflow (confirmed/false-positive) |
| `test_report.py`, `test_report_polish.py` | Report generation, HTML output, chains in reports |

### Regression & coverage
| File | Covers |
|---|---|
| `test_fixes_hp/mp/lp.py` | Security-hardening and correctness regression tests |
| `test_fixes_missing.py` | OS/MSF extractors, masscan rate, input validation |
| `test_coverage_gaps.py` | Parsers, vault, engagement lifecycle |
| `test_tier1/2/3.py` | Tiered feature regression tests |
| `test_tools_*.py` | Per-tool wrapper tests (some hit the network — see below) |

## A note on live-network tests

The `test_tools_*` files exercise real tools (gobuster, nikto, etc.), some
against `example.com`. They're slower and depend on network access. If you're
iterating on core logic, stick to the offline files above — they don't need a
network and finish in seconds.

## Continuous integration

`.github/workflows/test.yml` runs the non-integration suite on every pull
request, so regressions are caught automatically.

## Next steps

- [The Finding Pipeline](finding-pipeline.md) — the logic most of these tests protect
- [False-Positive Reduction](false-positive-reduction.md) — what the verification tests guard
