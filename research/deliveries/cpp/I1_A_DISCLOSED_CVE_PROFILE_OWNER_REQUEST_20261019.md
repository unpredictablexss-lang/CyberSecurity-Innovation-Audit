# I1 owner request: publish an A-line disclosed-CVE scan profile — 2026-10-19

## Request

Expose a named `A disclosed CVE` scan profile in the shared scanner selection flow. The profile should explicitly select the current A memory and lifetime detector set plus `ohscanner.known_disclosed_cves`; it should not silently enable the CVE rule pack in every unrelated default scan until the independent holdout gate is satisfied.

## Why this is needed

Fetched scanner baseline: `db77164fdc2af0da02e4d3efc056d84694fd68e8`. The catalog already imports and registers `ohscanner.known_disclosed_cves` 0.16.0. Its metadata currently sets `default_enabled: false`, with explicit-selection reason that the public-CVE rule corpus is not an independent holdout and product reachability/impact remain unverified.

The A-line integrated disclosure report includes three current cases not reached by ordinary default selection: CVE-2026-46675 (libpng), CVE-2026-67216 (cJSON), and CVE-2026-67215 (cJSON). Production M2 CLI has now exercised all three rules as candidates on source-shaped input and returned zero diagnostics on a safe/fixed-shape control. The vulnerable snapshot has one partial parse and correctly remains blocked. This validates the CLI candidate path, not exact vulnerable product source or an upstream fixed build.

## Proposed selection

Core profile:

- `ohscanner.cpp.bounds`
- `ohscanner.cpp.integer_bounds`
- `ohscanner.cpp.resource_lifetime`
- `ohscanner.known_disclosed_cves`

The ordinary default detector set should remain otherwise intact. Keep `ohscanner.cpp.null_dereference` separate and opt-in pending current source-bound CVE-2025-26690 vulnerable/fixed replay and unrelated-control review; a five-detector broad replay produced generic candidates on the fixed controls.

## Acceptance

1. The profile is selectable through the supported CLI and workbench planning paths without changing detector contracts or defaulting every scanner run to the CVE rule pack.
2. The selected detector IDs and versions are recorded in normalized run reports.
3. Current A-line exact source pairs remain: libtiff CVE-2025-9900, curl CVE-2026-92391, libpng CVE-2026-33416; add explicit known-CVE shape controls for CVE-2026-46675/67216/67215. Require vulnerable candidate, fixed/safe/unrelated quiet for same root, and partial coverage blocked with retained candidates.
4. Preserve source/profile hashes, parser status, candidate obligations and `validated_vulnerability=0` for fixture/component-only evidence.
5. Keep product applicability and impact unknown where the integrated review says unknown. Do not emit CVE counts as product vulnerability counts.

## Scope boundary

Catalog, CLI profile plumbing, planning/workbench selection and shared metadata are owner-only under `config/collaboration/ownership.json`. A-line has not changed those files. Implement this request in the owner worktree; A-line detector code, tests and source evidence remain in the D2 worktree.

Evidence:

- A-line profile and CVE coverage matrix: `research/deliveries/cpp/A_DISCLOSED_CVE_SCAN_PROFILE_20261019.md`
- Source-shaped production CLI reports and reproducible tiny source bundles: `research/evidence/cpp/disclosed_cve_m2_cli_replay_20261019/`
- Exact component-source detector replays: `research/evidence/cpp/d2-disclosed-vulnerability-regression.md`
- Current shared-catalog setting: `src/ohscanner/detectors/catalog.py`, `ohscanner.known_disclosed_cves.default_enabled=false`
