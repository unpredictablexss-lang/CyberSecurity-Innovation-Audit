# Independent runner applicability replay — 2026-10-20

## Reproduction setup

Worktree: `D:\openHarmonyScanner\worktrees\worktrees\c-static-replay-test-20261020`.
The checkout was clean before replay at `fbc54b5a19e722cee0606d3983de6aaccf47e8f7`. Cherry-picked requested source commit `85a1f1e6f91247e5fbad39fb6bd03f64201700bb` (`fix runner detector applicability scope`), whose source tree is `35987c5207e7466a57996cc0756216a313ec3899`; replay HEAD is `a8035945b4412a440cfe7306e51fb95aa2fc6f78`. The cherry-pick changes only `src/ohscanner/runner.py` and `tests/detectors/ark_runtime/test_detector_cases.py`; no production model or detector rule was edited. Stable patch IDs match for the original commit and cherry-pick (`384d3e34555c03f4d5dcbb40f25389c4e591aca8`), and a path-scoped diff between those commits is empty. Their full tree IDs differ because the replay commit has a different parent history; the runner/test patch itself is identical. The report file was added afterward and is not part of the code cherry-pick.

CLI invocations (PowerShell; same repo, commit, detector, and output directory for each):

```powershell
$repo = 'D:\openHarmonyScanner	mp\c-line-ark-history-full-snapshots-20261018.git'
$commit = 'a65a2853ccae13da167d9aa4720ab8b11ec16656'
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit $commit --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out D:\openHarmonyScanner	mp\c-static-replay-after-85a1-20261020	arget-only.json
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit $commit --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --include ecmascript/compiler/new_object_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out D:\openHarmonyScanner	mp\c-static-replay-after-85a1-20261020	arget-creator.json
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit $commit --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --include ecmascript/compiler/new_object_stub_builder.cpp --include ecmascript/compiler/builtins/builtins_array_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out D:\openHarmonyScanner	mp\c-static-replay-after-85a1-20261020	arget-creator-unrelated.json
```

The source store, repository, commit, and detector are thus pinned identically for all three runs.

## Results

All three runs identify source commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`, target blob `68fb3b0adc4f9062889a861be51b7be90362e37a`, and target SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`.

- Target only: one selected file and one applicable file; detector is `blocked`, coverage has `not_analyzed=1`, and diagnostics are 0. The report explicitly says the required creator dependency is outside scanned source scope.
- Target plus creator: two selected source files but `applicable_files=1`; the creator stays in the report's full source context and validates as parse-complete. Its blob is `991ac5ac034a1a027e3200787ec25c55b3f15b69`, SHA-256 `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0`. Target analysis is still partial and blocked, with 0 diagnostics.
- Target, creator, and unrelated same-language file: three selected source files but `applicable_files=1`; only the exact target SHA appears in detector coverage and no finding is emitted from the unrelated file. Target remains partial/blocked, 0 diagnostics.

Across all reports the target has the same 13 parser issues (lines 148, 151, 154, 155, 166, 2862, 2873, 2952, 2953, 3041, 3286, 3611, 3629). Thus the zero-diagnostic result is incomplete/blocked evidence, not a safety result.

Selector behavior was also checked by committed tests: model target selection narrows applicability while its creator remains in context; unrelated same-language units are excluded; an out-of-context selector unit yields `failed` with 0 diagnostics; missing creator remains `blocked`. A direct no-hook harness confirmed language fallback: a detector with `supported_languages=("cpp",)` and no `select_applicable_units` received `applicable_files=1` from one C++ plus one JS unit, completed with coverage `complete=1`. The runner constrains selector input to supported-language units.

## Verification

- All Ark Runtime tests: unittest reported `Ran 159 tests`, `OK (skipped=3)` (`OHSCANNER_ARK_REPO` unset; 156 passed, 3 skipped). This checkout’s observed count is 159 total. A development-side count of 162 was mentioned, but the differing test inventory/revision was not supplied, so the three-test discrepancy is unresolved; no equivalence is claimed.
- Runner/source-binding core suites `tests.test_ohscanner_m2` and `tests.test_contract_v2_source_binding`: 34 passed.
- Broader `tests.test_ohscanner_m1`, `tests.test_ohscanner_m2`, `tests.test_contract_v2_source_binding`, `tests.test_source_planning_manifest`: `Ran 54 tests`, 2 failures and 2 errors. The 34 tests in M2/source-binding passed. Exact failures: `GitObjectIndexTests.test_symlink_not_followed_and_non_utf8_not_disguised` and `SourcePlanningManifestTests.setUpClass` error at `symlink_to` with `OSError: [WinError 1314]` (the current Windows user lacks symlink privilege); `GitObjectIndexTests.test_git_blobs_are_read_in_one_bounded_batch` expected LF bytes but the temp checkout contained CRLF (`b"...\n" != b"...\r\n"`); `GitObjectIndexTests.test_index_real_commit_objects_and_language_parse_state` expected ETS `complete` but observed `not_run`. The first three errors are supported as environment/input-specific by their output; the ETS/parser mismatch is recorded without attributing a root cause. None exercise the changed runner applicability path.
- CLI reports all returned `completed_with_limitations`; each had parser partial status and detector blocked status as above.
