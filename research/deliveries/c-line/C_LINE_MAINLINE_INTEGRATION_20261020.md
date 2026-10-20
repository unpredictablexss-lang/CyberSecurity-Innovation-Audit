# C-line Ark Runtime mainline integration

Date: 2026-10-20

## Snapshot and integration

- Mainline base: `4b0e16576a45a111b4fad7e8f82819a47ed472f5`.
- Source C integration: `e798fa77fda843ff00f3b0ac7367f4eea02eb5ac`.
- Integrated commit before this report: `eb43f462769b315e87f7716f237c58b66f058acd`.
- Branch: `codex/c-mainline-dev-closeout-20261020`.
- The C delta was cherry-picked. The only merge conflict was the Ark Runtime Catalog description/admission text. The D104 C1 source-profile restriction was retained and combined with the added exact repository/commit/blob/source-hash profile language. No D104 source identity or parser files were modified. The Runner applicability hook was merged with the latest mainline Runner.
- Ark Runtime stays `0.6.3` / model `0.8.14`, `default_enabled: false`, explicit-selection only, and exact-source bound. The Float32Array and conditional `TypedArray.set` candidates remain unpromoted.

The mainline baseline test expected the existing `research_only_explicit_selection` Catalog marker. The C integration commit's changed Catalog test no longer asserted it. This integration restores that assertion and retains the marker alongside `explicit_selection_required` and the exact source-profile restrictions. This is a compatibility fix to the C Catalog text; it does not change D104 admission semantics or enable the detector by default.

## Verification

All commands ran against the integration worktree and source snapshot `eb43f462769b315e87f7716f237c58b66f058acd`, with Python 3.12.15 and the repository requirements installed in `/tmp/ohscanner-c-mainline-test-venv`.

1. Ark Runtime suite:

   `python -m unittest discover -s tests/detectors/ark_runtime -t .`

   Result: 212 tests, 209 passed, 3 skipped, 0 failed.

2. Runner, Catalog, source-binding, contract, audit-plan and D104-adjacent parser/data regressions:

   `python -m unittest tests.test_contract_v2_source_binding tests.test_ohscanner_contract tests.test_audit_plan tests.detectors.ark_runtime.test_catalog tests.detectors.ark_runtime.test_parser_owner tests.detectors.data.test_sensitive_exposure tests.detectors.data.test_t101_assignment_comma_parser`

   Result: 143 tests, 142 passed, 1 skipped, 0 failed.

3. `git diff --check` passed for the integration patch before adding this report.

The integration tester separately reported the mainline-baseline Catalog marker assertion failure (1 failure in the 149-test Ark run and 1 in the 43-test focused run). The failure was confirmed by reading the test at the stated base SHA and is addressed by the marker/assertion restoration above. The reported baseline run's test counts are not added to the integration counts.

## Runtime status

Runtime validation remains **not_run** for this mainline integration. No Ark VM execution or component test was performed here. The earlier stage report's WSL NTFS/P9 build stall is a separate environment record and is not represented as a successful runtime test.

## Scope

This commit integrates the existing C detector package and its controls with the D104 mainline baseline. It does not modify Ark Runtime upstream source, merge a C9/C11/C12/C13 branch wholesale, or claim a confirmed product vulnerability. Changes are limited to the existing selective integration delta, its Catalog compatibility correction, and this report.
