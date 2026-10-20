# C-line next-slice scout — 2026-10-20

## Finding

**Layer:** runner applicability / source-context mapping, not a confirmed Ark Runtime detector defect.

At `src/ohscanner/runner.py:217`, `run_all_with_coverage()` chooses every context unit whose language is supported. It does not call the Ark Runtime adapter's `select_applicable_units()` (`src/ohscanner/detectors/ark_runtime/detector.py:22`). That hook restricts detector targets to exact model-bound source paths, while the adapter also needs `new_object_stub_builder.cpp` present in the full `ScanContext` to validate its version-bound dependency.

## Reproduction and exact evidence

Source repository: `openharmony/arkcompiler_ets_runtime`; pinned commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`; target `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`.

Target exact identity in the registered type-safety model: Git blob `68fb3b0adc4f9062889a861be51b7be90362e37a`; SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`. Creator dependency exact identity: Git blob `991ac5ac034a1a027e3200787ec25c55b3f15b69`; SHA-256 `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0`.

Using the registered CLI and local pinned Git store `D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`:

| Scope | Result |
|---|---|
| Target + exact creator dependency (`c1_registered.json`) | `applicable_files=2`; target partial/partially inspected; creator dependency `not_analyzed` because it is not a model target. Detector status `blocked`, 0 diagnostics. |
| Target only (`c1_target_only.json`) | `applicable_files=1`; target `not_analyzed`; detector blocked because exact creator dependency is outside scanned source scope. |

Both reports have `completed_with_limitations` at experiment level; neither constitutes a safety result. With the dependency present, target source identity matches exactly, but parser status is `partial` with 13 issues (lines 148, 151, 154, 155, 166, 2862, 2873, 2952, 2953, 3041, 3286, 3611, 3629). Internal analysis is partial/limited and zero CLI diagnostics does not establish safety. An in-process research-partial observation at `Map` line 2747 is `unknown` (`type_fact_invalidated_by_call`), which is a model/effect limitation, not a confirmed detector defect.

The two saved CLI reports are `c1_registered.json/.md` and `c1_target_only.json/.md` in this directory. Both runs used detector `ohscanner.ark.runtime.type_safety` 0.6.2 and profile `light-ast`.

## Proposed next slice

Separate the full source context required for exact dependency verification from the set of files counted as detector-applicable. In the runner, honor an optional detector applicability selector while keeping all supplied units available in `ScanContext`; define coverage and skipped-file semantics explicitly. Do not relax source binding, promote partial parse, or reinterpret unknown as safe.

### Development prompt

Implement runner applicability selection through the existing optional `select_applicable_units(context, units)` hook (with language filtering/fallback for detectors that lack it). Keep dependency units in context for the Ark adapter's exact blob/SHA check, but exclude non-target dependencies from detector applicable-file counts and target outcomes. Add tests for the exact target+dependency pair, target-only missing-dependency block, and an unrelated same-language unit. Preserve the C1 target's partial/blocked status.

### Independent test prompt

Re-run the registered CLI on pinned C1 with target plus exact creator dependency and target-only. Assert exact source identity, dependency verification, applicable count reflects only model targets, target+dependency remains partial/blocked with 0 validated vulnerabilities, target-only remains blocked for missing dependency, and an unrelated same-language file does not become a target. Confirm partial/unknown limitations remain visible. Do not interpret empty diagnostics as safety.

## Boundaries / unresolved

- No production code was edited in this scout; this is a reproducible runner mapping/coverage issue suitable for a narrow follow-on.
- C1 remains parser-partial and semantically limited; this proposal does not repair those issues.
- No formal precision/recall or product-impact claim is supported.
- At scout start the branch was at `2d79560cad45db75bb1b0c6d0677200294e17d10`; the worktree already contained untracked prior scout CLI outputs under this directory. They were retained, not overwritten except for the newly named target-only replay and this report.
