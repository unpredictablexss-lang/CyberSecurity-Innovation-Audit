# Independent runner applicability replay — 2026-10-20

## Reproduction setup

Worktree: `D:\openHarmonyScanner\worktrees\worktrees\c-static-replay-test-20261020`.
The checkout was clean before replay at `fbc54b5a19e722cee0606d3983de6aaccf47e8f7`. Cherry-picked requested source commit `85a1f1e6f91247e5fbad39fb6bd03f64201700bb` (`fix runner detector applicability scope`), whose source tree is `35987c5207e7466a57996cc0756216a313ec3899`; replay HEAD is `a8035945b4412a440cfe7306e51fb95aa2fc6f78`. The cherry-pick changes only `src/ohscanner/runner.py` and `tests/detectors/ark_runtime/test_detector_cases.py`; no production model or detector rule was edited.

CLI used the fixed bare Git store `D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`, repository `openharmony/arkcompiler_ets_runtime`, commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, and explicit detector `ohscanner.ark.runtime.type_safety`. Commands differed only in repeated `--include` arguments: target only; target plus `ecmascript/compiler/new_object_stub_builder.cpp`; then those two plus unrelated `ecmascript/compiler/builtins/builtins_array_stub_builder.cpp`. JSON outputs are in `D:\openHarmonyScanner\tmp\c-static-replay-after-85a1-20261020\`.

## Results

All three runs identify source commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`, target blob `68fb3b0adc4f9062889a861be51b7be90362e37a`, and target SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`.

- Target only: one selected file and one applicable file; detector is `blocked`, coverage has `not_analyzed=1`, and diagnostics are 0. The report explicitly says the required creator dependency is outside scanned source scope.
- Target plus creator: two selected source files but `applicable_files=1`; the creator stays in the report's full source context and validates as parse-complete. Its blob is `991ac5ac034a1a027e3200787ec25c55b3f15b69`, SHA-256 `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0`. Target analysis is still partial and blocked, with 0 diagnostics.
- Target, creator, and unrelated same-language file: three selected source files but `applicable_files=1`; only the exact target SHA appears in detector coverage and no finding is emitted from the unrelated file. Target remains partial/blocked, 0 diagnostics.

Across all reports the target has the same 13 parser issues (lines 148, 151, 154, 155, 166, 2862, 2873, 2952, 2953, 3041, 3286, 3611, 3629). Thus the zero-diagnostic result is incomplete/blocked evidence, not a safety result.

Selector behavior was also checked by the committed tests: model target selection narrows detector applicability while its creator remains available in context; unrelated same-language units are excluded; an out-of-context selector unit yields `failed` with 0 diagnostics; missing creator remains `blocked`. The runner retains language-only fallback for detectors without `select_applicable_units` and constrains selector candidates to supported languages.

## Verification

- All Ark Runtime tests: 159 passed, 3 skipped (`OHSCANNER_ARK_REPO` unset).
- Runner/source-binding core suites `tests.test_ohscanner_m2` and `tests.test_contract_v2_source_binding`: 34 passed.
- Broader `tests.test_ohscanner_m1`, `tests.test_ohscanner_m2`, `tests.test_contract_v2_source_binding`, `tests.test_source_planning_manifest`: 54 tests; M2 and source-binding passed, while M1/source-planning had 2 failures and 2 errors attributable to this Windows environment: symlink creation denied (2 cases), a CRLF checkout byte expectation, and one ETS parser expected `complete` but returned `not_run`. These are unrelated to the runner applicability change.
- CLI reports all returned `completed_with_limitations`; each had parser partial status and detector blocked status as above.
