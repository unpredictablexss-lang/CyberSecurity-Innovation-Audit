# C12 Ark deep semantics slice

This slice closes four bounded semantic gaps in the Ark Runtime detector: effectful helper source contracts, numeric cast/sign-width loss, generated CFG loop backedges and cross-function identity summaries. All outcomes remain source-bound candidates/unknown; no finding was upgraded to confirmed/reportable.

## Files

Production changes are limited to `src/ohscanner/detectors/ark_runtime/{analysis,cross_helper,runtime_ir,size_overflow,type_origin}.py`. The new controls are `tests/detectors/ark_runtime/test_c12_deep_semantics.py` and `tests/detectors/ark_runtime/fixtures/c12_deep_semantics/*.cpp`.

## Baseline and source identity

Baseline commit: `ddd8556768d679fcc09f1fcb37d10730f49b2c6c`. Baseline tree: `7d102eb9d2f0c2149fe978bb350129b7cf2fac71`. The worktree is intentionally dirty. File SHA-256 values are in `source-hashes.json`; the tracked production diff is `minimal.patch`.

## Mechanisms

1. `cross_helper.build_helper_contracts` records complete local helper source hashes and effect tokens. Only exact same-typed parameter returns and bounded forwarding chains become identity helpers. `OriginEvaluator.unsupported_cpp_effect` emits explicit effectful-helper unknown observations.
2. `size_overflow` now carries source/target signedness and width through C++ casts. Signed narrowing or sign-changing casts feeding allocation/copy loops are candidates; unknown conversion operators produce a partial limitation.
3. `runtime_ir.LoopBackedge` records only exact generated `LoopEnd` backedges to a matching `LoopBegin`; mismatch or unresolved labels are limitations.
4. `build_helper_contracts` resolves exact one-hop forwarding through proven identity helpers as a bounded fixed point. Effectful/unknown wrappers remain non-identity.

## Validation

See `logs-final/`. Ark full: 193 tests, 3 historical skips. C12 focused: 20 tests. Known regression: 5 tests. `compileall` and `git diff --check` exit 0. Nine C11 known-case parent/fixed controls remain unchanged by the C12 regression suite; exact before/after rows are in `known-case-regression.json`. This is not a product replay or proof of coverage.

## Controls

`control-matrix.json` records positive/fixed/safe/unrelated/unknown for every mechanism. Safe controls are explicitly non-security conclusions. Unknown controls are partial/unknown and never safe.
