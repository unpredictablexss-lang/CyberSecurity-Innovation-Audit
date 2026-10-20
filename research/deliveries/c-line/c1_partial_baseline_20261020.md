# Independent C1 partial baseline — 2026-10-20

## Setup and reproduction

Test worktree began clean at runner replay report commit `84e73672bc95fde70070e8f5369f712911a923dd` (branch `codex/c-static-replay-test-20261020`). No production code or model was changed.

Source came from local bare store `D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`; no source fetch was needed. Exact-bound target:

- repository `openharmony/arkcompiler_ets_runtime`
- commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`
- tree `8781f036a3e7e04d8e0b34970d5f623b42875016`
- target `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`
- blob `68fb3b0adc4f9062889a861be51b7be90362e37a`
- SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`

Exact CLI replay with creator dependency in scope:

```powershell
$repo = 'D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git'
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --include ecmascript/compiler/new_object_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out D:\openHarmonyScanner\tmp\c1-partial-baseline-20261020\c1-with-creator.json
```

## Observed result

Aggregate status is `completed_with_limitations`; the detector is `blocked`, diagnostic count is 0, and detector coverage is `partial` with `applicable_files=1`, `partial=1`, and no complete files. The target parser is `partial`; analysis is `partial` with reason `detector_model_incomplete`. The creator stays in source context, has blob `991ac5ac034a1a027e3200787ec25c55b3f15b69`, SHA-256 `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0`, and parse status `complete`.

The 13 target parser issues are at lines **148, 151, 154, 155, 166, 2862, 2873, 2952, 2953, 3041, 3286, 3611, 3629**. Types in order: missing, missing, error, missing, error, missing, error, error, missing, error, missing, missing, error.

The detector reports these target limitations: `experimental_partial_function_scope`, `parse_dependency_contamination_unknown`, `partial_scope_routed_through_semantic_selector`, and `unresolved_local_observations`. The run also explicitly reports `INCOMPLETE COVERAGE` and `Coverage incomplete or unsupported; do not infer safety`. Empty findings are therefore not evidence of safety or a rule-level miss.

As a local related control, the same registered CLI and exact target-plus-creator scope were run on fixed exception-guard revision `81ca57487d04ea30cd11c271e86494a4e130f43e` (tree `f0ddee8ee7f74b3f22e45b174ce96a269b2e57a`; target blob `3b9de9d915d767d7a67316145451da2446162884`, SHA-256 `4684a1587519e7d141f181b595317db489991a3908e1f1b4ef67513c25d9efd0`). It also returned `blocked`, partial target coverage, and zero diagnostics, with two parser missing-node issues at lines 3391 and 3704. This is a fixed control for the historical exception-guard profile, not a complete/safe verdict and not a clean result for the C1 parser limitation.

A target-only rerun is preserved at `D:\openHarmonyScanner\tmp\c1-partial-baseline-20261020\c1.json`: the same target identity is recognized, but analysis is `not_analyzed` and blocked because `new_object_stub_builder.cpp` is outside source scope. The full-context replay above is the relevant parser/model baseline.

JSON artifacts are outside the worktree under `D:\openHarmonyScanner\tmp\c1-partial-baseline-20261020\`.
