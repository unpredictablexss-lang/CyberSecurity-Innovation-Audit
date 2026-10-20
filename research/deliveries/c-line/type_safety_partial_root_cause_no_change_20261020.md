# Ark Runtime `type_safety` partial/blocked root cause — no-change report (2026-10-20)

## Scope and identity

- Development baseline requested: `0f53af62283dbd0f249280805e8286a04b2d43b9` (`docs(ipc): bind closeout evidence to main SHA`).
- Replayed checkout: `cfdbd21eac05f6b515d123a29640f5011733ab03` (`codex/c-line-parallel-plan-20261020`), which contains the registered C-line adapter and prior runner fix.
- Source: `openharmony/arkcompiler_ets_runtime@a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`.
- Target: `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`, blob `68fb3b0adc4f9062889a861be51b7be90362e37a`, SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`.
- Required creator: `ecmascript/compiler/new_object_stub_builder.cpp`, blob `991ac5ac034a1a027e3200787ec25c55b3f15b69`, SHA-256 `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0`.

## Reproduction

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git `
  --repository openharmony/arkcompiler_ets_runtime `
  --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 `
  --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp `
  --include ecmascript/compiler/new_object_stub_builder.cpp `
  --detector ohscanner.ark.runtime.type_safety `
  --json-out D:\openHarmonyScanner\tmp\c-type-safety-replay-20261020\replay.json `
  --md-out D:\openHarmonyScanner\tmp\c-type-safety-replay-20261020\replay.md
```

Observed result: aggregate `completed_with_limitations`; detector `blocked`; target `partial`, analysis `partial` with reason `detector_model_incomplete`; 13 parser issues at lines 148, 151, 154, 155, 166, 2862, 2873, 2952, 2953, 3041, 3286, 3611 and 3629; zero diagnostics. The saved artifact is `D:\openHarmonyScanner\tmp\c-type-safety-replay-20261020\replay.json`.

## Stage diagnosis

1. **Model binding/source mapping: passes.** Exact repository, commit, path, Git blob and SHA-256 match the registered C1 target. No identity mismatch or source mapping failure was observed.
2. **Creator dependency: present, but not a target finding.** The exact creator object is available and identity checked. Its presence removes the target-only missing-dependency condition; it does not make the target complete or cause the creator to be analyzed as a target.
3. **Parser/internal coverage: blocking cause.** The target is parsed as raw C++ without Ark macro expansion. The 13 locations are cascades around `IR_IF`/`IR_ELSE`, `BRANCH`, and typed-array case-list macros. Pinned header definitions show these tokens expand to valid C++ control flow/case blocks. The separate Map callback observation remains an effect/type fact unknown, not a parser defect.
4. **Detector/rule behavior: not reached conclusively.** Because target analysis is partial and the detector is blocked, zero diagnostics cannot distinguish rule miss from unavailable facts. No minimal rule defect with a positive and negative control is established.

## Decision

**No production code change.** A parser/model change would require an exact pinned macro-aware preprocessing profile with compiler defines, include closure, and source-location mapping. Those build facts are unavailable; textual macro rewriting would risk false completeness. Preserve `partial`, `unknown`, and `blocked` semantics.

## Verification and limits

- Registered CLI replay: completed successfully with limitations; 0 unverified diagnostics.
- Existing C-line Ark Runtime focused suite on the recorded baseline: 162 passed, 3 skipped (from the prior independent replay record).
- `git diff --check`: required after adding this report.
- This is source/component evidence only. Runtime execution, compiled IR, product build/profile, reachability, exploitability, and security impact remain `unknown`/`not_run`; zero diagnostics is not a safety result.
