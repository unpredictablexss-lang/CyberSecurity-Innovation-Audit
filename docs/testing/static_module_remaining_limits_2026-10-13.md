# Teammate A remaining-limit integration — 2026-10-13

## Scope

This run integrates the teammate A static module with the latest locally
fetched Core, interface and workbench branches. External scanners remain
research-only. The shared_ptr race PoC is maintained by
`feat/interface-ipc-detector`; this branch only consumes its ownership and
artifact boundary.

## Catalog and ownership

- `ohscanner.cpp.lifetime` and `ohscanner.cpp.shared_ptr_race` are registered
  as `research_candidate`, not production vulnerability detectors.
- `ohscanner.interface.ipc` is also a `research_candidate`.
- The example detector remains explicitly non-security.
- The shared_ptr PoC is imported from the interface line and is not maintained
  as an A-line duplicate.

## Real component compilation and tool runs

Pinned target:

- repository: `openharmony/commonlibrary_c_utils`
- commit: `b807d3dadb7dbb7639fe85b3a5f72da18d318da2`
- snapshot tree: `52b42d41ed091f7dcae37c4ce3a0d95b6fb1f16d`
- source scope used for host tools: 21 GN-listed utilsbase C++ translation
  units, 6,978 LOC
- dependency: `openharmony/third_party_bounds_checking_function`
- dependency commit: `61baa7a3eb9347efca58397d1d0504faa96d79f0`

| Tool | Version | Result | Coverage / limitations |
|---|---|---|---|
| Clang SA | Ubuntu clang 14.0.0 | 21/21 TUs analyzed; summary warning 1; normalized adapter count 31 | Reconstructed Linux host profile, not product GN export |
| CodeQL | 2.27.2, cpp-queries 1.9.0 | Full 183-query security-and-quality suite completed; 11 diagnostics; no coverage issues | Manual build trace over the same 21 host TUs; not a product build |
| Infer/Pulse | 1.2.0 | Completed; 7 issues: 4 lock-consistency, 2 dead-store, 1 unnecessary-copy | Isolated worktree and generated Makefile; no vulnerability promotion |
| Joern | 4.0.654 | `nothrow` and `lifetime-reset-stale-alias` queries executed; 0 findings | Blocked/unknown overall: 62/123 C/C++ files had parsed/CPG rows |

The CodeQL runner was fixed to pass a space-free manual-build argv string and
allow up to 1,200 seconds per database/query step. Infer v1.3.0 was rejected
by Ubuntu 22.04 glibc; v1.2.0 was used and recorded.

## Historical CVE binding

The following samples are now exact-bound and included in historical
benchmark metadata:

- CVE-2025-0587 — `arkcompiler_ets_runtime-atomic-index-overflow-2025-03`
- CVE-2025-27536 — `arkcompiler_ets_runtime-typedarray-filter-confusion-2025-09`
- CVE-2025-21098 — `kernel_liteos_a-os-copy-user-param-bypass-2025-03`

For every pair, `benchmarks/historical/source_bindings/` records the merged fix
commit, vulnerable parent, affected file, vulnerable/fixed Git blob SHA-1,
source SHA-256, symbol and PR patch SHA-256. Reproduction:

```text
python -m scripts.verify_historical_source_bindings
```

The verifier returned `verified` for all three pairs. These are historical
evidence records, not new vulnerability discoveries. Their patch-obligation
sidecars were created after reading the fixes and are therefore not independent
holdouts.

## Workbench integration

`scripts.verify_workbench.py` was run against the pinned c_utils repository:

```text
status: completed_with_limitations
indexed_files: 123
parse: complete=93, partial=30
candidate_count: 0
validated_vulnerability: 0
cli_parity: true
scan_seconds: 24.480740467000032
```

The workbench owns repository registration, persistent jobs, Worker execution,
source evidence and report export. A-line code does not implement a competing
Web or task platform.

## Verification

```text
.venv-web/bin/python -m unittest discover -s tests -q
Ran 640 tests in 103.547s
OK (skipped=11)
```

- `python -m compileall -q src scripts tests`: passed.
- `git diff --check`: passed.
- Node 22.23.3 `npm ci`: 77 packages, 0 vulnerabilities.
- Node 22.23.3 `npm run build`: TypeScript check and production bundle passed.
- Historical source-binding verifier: 3/3 pairs `verified`.
- Workbench verification: `cli_parity=true`, `completed_with_limitations`.

## Remaining boundaries

- `research_candidate` registration is complete; promotion to a production
  catalog remains an owner review decision.
- Host bootstrap compilation is not an OpenHarmony product build or complete
  macro/template profile.
- Joern coverage remains partial and therefore unknown outside the parsed rows.
- New CVE samples have exact source bindings but no independent safe/unrelated
  holdout execution or Precision/Recall claim.
- Agent loop is intentionally not implemented by teammate A; only read-only
  fact interfaces are available.
- No candidate is promoted to `confirmed/reportable` by these experiments.
