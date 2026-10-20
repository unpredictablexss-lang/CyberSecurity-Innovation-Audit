# C9 Type-Origin Acceptance 20261019

## Final e4e result

The corrected patch defines `callee = call.child_by_field_name("function")` before `member_call` computation. The earlier `UnboundLocalError` patch is excluded and is not acceptance evidence.

Six named e4e counterexamples pass with the corrected patch:

| Counterexample | Required local semantics | Final result |
|---|---|---|
| `test_fresh_read_does_not_revalidate_an_old_copy` | fresh read does not revive `old` | `["matched", "unknown"]` |
| `test_host_builder_write_does_not_mutate_runtime_type` | exact builder write preserves type; foreign receiver is unknown | `matched` / `unknown` |
| `test_mechanism_matrix(G07)` | `UnknownGlobalEffect()` cannot prove type stability | `unknown` |
| `test_readonly_summary_requires_exact_builder_receiver` | exact `BuiltinsArrayStubBuilder` receiver only | `matched` / `unknown` |
| `test_two_stale_snapshots_cannot_prove_current_destination_type` | stale guard cannot prove current destination type | `candidate` |
| `test_verified_by_value_call_does_not_refresh_old_token` | old copy stays stale; later fresh read is matched | `["unknown", "matched"]` |

Retained run: `e4e-six-callee-fixed-final/`: 6 tests, 6 passed, 0 failed, 0 errors, 0 skipped.

The transferable minimal patch is `e4e-minimal-type-origin.patch`. The e4e tests already exist at `e4e0761501a83ac25cc67d04c527eefe9f4a1b50:tests/detectors/ark_runtime/test_c3_mechanisms.py`; no e4e test patch is required. The current-worktree equivalent controls were added only to `tests/detectors/ark_runtime/test_type_origin.py` and are captured in `current-type-origin-tests.patch`.

## Full focused result

`e4e-full-focused-callee-fixed-final-shortpath/` ran 156 tests: 144 passed, 11 skipped, 1 error. Skips and the error are not counted as passes.

The single error is an external input binding failure: `test_every_declared_file_byte_is_in_digest` could not read `WORKSPACE_ROOT/openharmony/arkcompiler/ets_runtime/ecmascript/compiler/BUILD.gn`. The 11 skips require pinned Ark Git stores or `OHSCANNER_ARK_REPO`; no implicit fetch was performed. Therefore this is not a full-green claim.

## Current worktree and source-bound controls

`current-type-origin-final/`: 30 tests passed, including the six equivalent acceptance controls. `source-bound-regression.json` records positive candidate, fixed matched, safe/local-control matched, unrelated not_analyzed, and all six c8 effects as unknown with fixture SHA-256 values and model digest. All 10 source-bound assertions passed.

`current-c3-control-final/` is retained as a non-acceptance divergence: the older in-tree `test_c3_mechanisms.py` expects `two_stale...` and G11 as `unknown`, while the newer e4e expectations require `candidate` and candidate respectively. Per task scope, that older test file was not edited.

## Source review and comparison

The source audit original is not missing. Read-only object identity:

- ref: `origin/codex/c-line-ark-runtime-20261018`
- commit: `e4e0761501a83ac25cc67d04c527eefe9f4a1b50`
- tree: `307ac8237263db793028e0bf34a82a85f60821a5`
- review blob: `dbedea677c8dc70c1b0066c7bc52df27bcff06ea`
- path: `research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`

The TypeOrigin entry IBS5YG remains a source-level candidate with product reachability/impact unconfirmed. The same ref contains `unseen_detector.py` and `unseen_model.py`; this worktree HEAD does not. They were compared read-only and not modified. The patch does not create a second scanner or rely on `unseen_*` verdicts.

## Limitations and next slice

No product vulnerability, CVE, Precision/Recall, zero FP/FN, exploitability, or safety claim is made. Static local evidence does not prove attacker control, reachability, ownership, concurrency, or CIA impact. The missing external `BUILD.gn` prevents one dependency-manifest assertion; 11 provenance tests remain skipped without pinned Ark stores. `scripts/check_docs_context_budget.py` is absent from this pinned worktree/ref, so that validation is recorded as blocked rather than passed.

Next minimal slice: supply the exact external snapshot input and pinned Ark Git stores in an authorized checkout, rerun the full focused suite without implicit fetch, apply `e4e-minimal-type-origin.patch` to e4e, and update `docs/项目现状与下一步.md` only after integration.