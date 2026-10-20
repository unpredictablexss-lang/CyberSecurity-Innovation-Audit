# C-line Float32Array negative-TDouble source-bound static candidate rule

Date: 2026-10-20
Implementation status: committed and independently replayed on the same implementation commit `46fdb5887c49a552b249fb20805025ba6316d8d0`.

## Result

The C1 Ark Runtime model now contains a narrow candidate-only rule, `ark.runtime.float32array-negative-double-length` (rule version `1.0.0`). It is applicable only to the exact repository `openharmony/arkcompiler_ets_runtime`, commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, `light-ast` Git-object profile, and exact source bindings below. It emits at most one candidate, on `common_stubs.cpp:228`, only when the CommonStub and TypedHCR double branches both have the exact round-trip and upper-bound checks without a nonnegative lower bound, their tagged-int branches retain `isGEZero`, and the pinned allocation helper carries the expected size to `NewByteArray`.

The rule does not label runtime behavior or memory safety. Its finding is `unassessed`, its coverage remains partial/blocked when the CommonStub translation unit is partial, and obligations keep compiled dispatch, allocation, metadata and access behavior unknown. The second-layer 32-bit conditional later indexed-read concern is mentioned only as an outstanding review obligation, not as evidence that the detector proves an out-of-bounds read. The empty initialization interval is not treated as a write. The implementation hardening commit pins the complete ordered model binding rows to immutable expected commit/blob/SHA values, so a self-consistent but altered model profile fails closed.

## Exact source bindings

All three paths are required in the scanned Git-object context; absence, wrong commit/repository, stale/mutated SHA or blob, or incomplete parser facts yields no candidate and `not_analyzed`/blocked coverage.

| Path | Commit | Git blob | SHA-256 |
|---|---|---|---|
| `ecmascript/compiler/common_stubs.cpp` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `6267f2f27a98a298b1190e327abbfa2bd58203f8` | `5a401580e666596fcf2ea89a8dc0321009b53ef5320b20edc59d37781d852212` |
| `ecmascript/compiler/typed_hcr_lowering.cpp` | same | `1ad4e329a226fc9941db30fa7a10a6562f58f68d` | `acd4ed88bb4ba5d327d5628dc45b7b89685a9c425c5849891cbf2544e8534a0c` |
| `ecmascript/compiler/new_object_stub_builder.cpp` | same | `991ac5ac034a1a027e3200787ec25c55b3f15b69` | `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0` |

Full-file parsing is complete for TypedHCR and the allocation helper. CommonStub is partial (13 parser issues), but its exact target `GenerateCircuit` source slice (lines 186–267) reparses completely and has no translation-unit parser errors within that scope. The rule also requires clean focused parsing for TypedHCR conversion (2333–2373), its fast-path caller (2375–2428), and both allocation helper functions (3042–3077 and 3119–3142). Any parser error overlapping these source scopes blocks the candidate.

## Controls and current verification

- Exact a65 three-file M2 replay: **one** unassessed candidate at `common_stubs.cpp:228`; run status `blocked`, coverage `partial=1`; this preserves the existing CommonStub translation-unit parser limitation.
- Tagged-int `-1`: the source predicate must contain `isGEZero`; this alone does not trigger the TDouble candidate.
- Positive integral TDouble: passes the same source guard; the rule is about the missing lower bound permitting a negative integral representation, not a runtime test of a particular value.
- Direct fixed-guard branch fixture: an added `DoubleGreaterThanOrEqual(doubleLength, Double(0))` rejects candidate matching.
- Wrong commit, altered exact source bytes, missing/mutated helper, or missing/mismatched AST facts: the pinned-profile verifier returns no candidate and `not_analyzed`/blocked. This is unknown evidence, not a safe/fixed verdict.
- Independent same-commit CLI replay on implementation commit `46fdb5887c49a552b249fb20805025ba6316d8d0`: exact a65 positive produced one candidate at `common_stubs.cpp:228` with partial/blocked coverage; wrong commit and missing helper each produced zero candidates and blocked/`not_analyzed` outcomes. Replay report: commit `6d41c4746b41c21af9139d2853acc1d0c9189ffa`.
- Model-row tampering is covered by a unit test and fails closed. CLI replay of mutated helper bytes/blob, fixed-source commit, and runtime behavior were not run.
- Unrelated source blocks do not match the exact source profile or both branch structures.

Commands run:

```text
python -m pytest tests/detectors/ark_runtime/test_negative_double_length.py -q
5 passed

python -m pytest tests/detectors/ark_runtime -q
198 passed, 3 skipped

git diff --check
passed

python -m src.cli.main ohscan-run --repo-dir D:\OpenHarmony807\repos\arkcompiler_ets_runtime --repository openharmony/arkcompiler_ets_runtime --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 --include ecmascript/compiler/common_stubs.cpp --include ecmascript/compiler/typed_hcr_lowering.cpp --include ecmascript/compiler/new_object_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out D:\Temp\c-line-float32-static-candidate.json --md-out D:\Temp\c-line-float32-static-candidate.md
[OK] one unverified diagnostic; run completed_with_limitations; normalized detector run blocked; partial=1
```

The independent tester replay used the same implementation SHA and independently confirmed the positive, wrong-commit, and missing-helper cases. The detector result remains a source-bound candidate only; it does not establish compiled-runtime behavior or product impact. The exact runtime PoC remains not run.
