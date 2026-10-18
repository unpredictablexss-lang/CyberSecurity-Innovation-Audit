# C3 current Ark Runtime snapshot binding and Runner replay

Date: 2026-10-18 (Asia/Shanghai)

## Decision

The local source identity is verified, so the exact target snapshot was added to the Ark Runtime research detector model, version `0.6.2` (the prior C4 experiments used `0.6.1`). The catalog entry remains `kind=research_candidate`, `default_enabled=false`, and requires explicit selection of `ohscanner.ark.runtime.type_safety`.

This is a research-only applicability entry. It does not make the result production-ready: the current source parses as partial, the detector cannot recover the exact namespace/class owner after Tree-sitter error recovery, and 18 of 19 model-supporting source blobs differ from the reviewed historical model inputs. No current-version candidate was emitted.

## Verified source identity

| Field | Value |
|---|---|
| Repository | `openharmony/arkcompiler_ets_runtime` |
| Checkout | `D:\openHarmonyScanner\openharmony\arkcompiler\ets_runtime` |
| Commit | `a65a2853ccae13da167d9aa4720ab8b11ec16656` |
| Tree | `8781f036a3e7e04d8e0b34970d5f623b42875016` |
| Path | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` |
| Index mode | `100644` |
| Git blob | `68fb3b0adc4f9062889a861be51b7be90362e37a` |
| File SHA-256 | `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c` |
| Parser | `partial` |
| Component checkout status | clean |

The commit, tree, index entry, Git blob, and SHA-256 were read from the local Git object store through WSL. The CLI independently loaded the pinned Git commit and reported the same commit/tree and target-source SHA. No network fetch was used.

`git rev-parse HEAD:<path>`, the index entry, and `git hash-object <path>` all returned blob `68fb3b0…`; `git cat-file -s HEAD:<path>` returned 150,610 bytes. The checked-out working tree was clean.

## Run results

The explicit current-version CLI run selected one file. It returned `blocked`, zero diagnostics, `not_analyzed=1`, `complete=0`, `partial=0`, and `validated_vulnerability=0`. The file's parser status remains `partial`; the detector limitations include `runtime_owner_not_resolved` and `target_not_resolved_in_partial_ast`. Since the analyzer did not resolve the target function, zero candidates here means unknown coverage, not a fixed or safe result.

The unbound parent commit `6518536b40ae58ef959a0572d82ddfece862eda0` contains the same target-file blob but has a different tree and is not an admitted commit. Explicit Runner execution returned `blocked`, zero diagnostics, and `not_analyzed=1`. This checks the exact commit gate even when file bytes happen to match.

The existing C4 historical evidence supplied for this work reports type-origin parent/fix candidate counts `1/0` and exception-guard parent/fix `2/0`, all partial/blocked. The current component Git object store lacks those historical commits, so that parent/fix result could not be replayed from this checkout. The old commit tests are explicitly skipped when their Git objects are absent; no source bytes were relabeled as `git_object` provenance.

The Runner contract controls passed: a fixed/safe control does not produce a rule candidate; a bound partial positive control remains blocked; and a valid local candidate plus evidence obligations survive aggregate blocked status. These controls are synthetic fixtures, separate from the current exact-source result and the unavailable historical Git replay.

## Model context drift

The runtime model references 19 supporting source blobs (effect summaries and allocation/type dependencies). At the current commit, 1 blob is unchanged and 18 differ. These supporting files have not been semantically re-reviewed for this snapshot. The exact target file binding therefore authorizes only a bounded research attempt; it does not validate the old model assumptions against the current product build. The full expected/observed list is in `model_dependency_comparison.json`.

## Source drift review record

`source_drift_review.json` and `source_drift_review.md` bind each changed model reference to the historical and current Git commit/tree/blob and raw-source SHA-256, and retain per-item textual diff and changed identifier cues. The effect/type rows use the model's pinned effect-summary revision `a0e30483ab3e4aead67ecfb5c708489915e447f9`; the two exception-guard rows use their separate pinned revisions `c758818dbfd0b146a908d43d21f6ca1706c33783` and `81ca57487d04ea30cd11c271e86494a4e130f43e` respectively. The recorded historical blob OIDs equal the model's expected OIDs.

This pass completes the provenance binding and per-item textual change inventory. Semantic meaning and rule-applicability impact remain `unknown` for all 18 changed references: exact preprocessing, declaration/call context, and product build configuration were not established. No changed dependency is treated as unaffected. The unchanged `profiler_operation.h` reference is also recorded. The exact-source and partial gates remain unchanged. The parent/fix, safe/fixed, and unrelated controls retain the outcomes documented above and in the historical replay record; they are not recast as semantic validation of all dependency drift.

Recompute the source binding and inventory from the pinned Git objects:

```bash
cd /mnt/d/openHarmonyScanner
python3 CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c3_20261018/generate_source_drift_review.py
```

This script verifies the model-recorded old/current blob OIDs and hashes the raw bytes returned by `git show`. It does not parse or normalize source bytes.

## Exact commands

Metadata checks (read-only; the `.git/config` link in the component checkout is a repo-tooling symlink that Windows Git cannot read, so Git metadata commands use WSL):

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime && git rev-parse HEAD && git rev-parse HEAD^{tree} && git status --short && git ls-files --stage -- ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp && git hash-object -- ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp && sha256sum ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp'
```

Current exact-source CLI replay (C4 Runner/CLI path; detector explicitly selected):

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c4 && PYTHONPATH=$PWD /tmp/ohscanner-c4-py312/bin/python -m src.cli ohscan-run --repo-dir /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime --repository openharmony/arkcompiler_ets_runtime --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out research/experiments/ark_runtime/c3_20261018/current-run.json --md-out research/experiments/ark_runtime/c3_20261018/current-run.md'
```

Unbound same-blob parent negative control:

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c4 && PYTHONPATH=$PWD /tmp/ohscanner-c4-py312/bin/python -m src.cli ohscan-run --repo-dir /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime --repository openharmony/arkcompiler_ets_runtime --commit 6518536b40ae58ef959a0572d82ddfece862eda0 --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out research/experiments/ark_runtime/c3_20261018/unbound-parent-run.json --md-out research/experiments/ark_runtime/c3_20261018/unbound-parent-run.md'
```

Regression command and result:

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c4 && export PYTHONPATH=$PWD OHSCANNER_ARK_REPO=/mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime && /tmp/ohscanner-c4-py312/bin/python -m unittest tests.detectors.ark_runtime.test_type_origin tests.detectors.ark_runtime.test_parser_owner tests.detectors.ark_runtime.test_ir_path tests.detectors.ark_runtime.test_c3_mechanisms tests.detectors.ark_runtime.test_detector_cases tests.detectors.ark_runtime.test_exception_guard tests.detectors.ark_runtime.test_historical tests.test_runner_applicability -v'
```

Result: **95 tests passed, 2 skipped**. Both skips are historical Git pair suites whose exact bound commits are absent from the supplied local component store. An initial `unittest discover -s tests/detectors/ark_runtime` attempt failed because it imported package tests without their package context; the explicit module invocation above is the successful rerun.

The explicitly run safe/fixed fixture controls and blocked-candidate retention controls were:

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c4 && PYTHONPATH=$PWD /tmp/ohscanner-c4-py312/bin/python -m unittest tests.detectors.ark_runtime.test_type_origin.TypeOriginTests.test_C04_target_type_has_same_identity tests.detectors.ark_runtime.test_type_origin.TypeOriginTests.test_C05_local_object_alias_preserves_identity tests.detectors.ark_runtime.test_type_origin.TypeOriginTests.test_C06_token_copy_preserves_origin tests.detectors.ark_runtime.test_exception_guard.ExceptionGuardSyntheticTests.test_exception_return_before_use_suppresses_candidate tests.detectors.ark_runtime.test_detector_cases.ContractAdapterTests.test_aggregate_limited_does_not_discard_valid_local_candidate tests.detectors.ark_runtime.test_detector_cases.ContractAdapterTests.test_exactly_bound_partial_fixture_preserves_candidate_and_unknown_scope -v'
```

Result: **6 passed**. The four safe/fixed synthetic controls emitted no candidate; the two positive fixture controls kept a candidate and its obligations when aggregate status was blocked. They are synthetic parser/model controls, not substitutes for the historical upstream fixed commits that are absent locally.

## Files and limitations

- `current-run.json` / `current-run.md`: exact current-source CLI report.
- `unbound-parent-run.json` / `unbound-parent-run.md`: exact-commit mismatch report.
- `model_dependency_comparison.json`: expected and current blobs for all 19 model dependencies.
- No component source was changed. No push or merge was performed. The A-line checkout was not edited/reset/cleaned/stashed.
- This is one file of one commit, one `light-ast` profile, and a bounded syntax/IR model. Build flags, product packaging, runtime reachability, trigger conditions, security impact, and the changed model dependencies remain unverified.
- `validated_vulnerability` remains zero. Neither zero candidates nor blocked/not-analyzed coverage is a security verdict.
