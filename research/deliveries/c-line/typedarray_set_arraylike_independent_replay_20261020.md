# TypedArray `set(arrayLike, offset)` independent replay

Date: 2026-10-20. Implementation under test: `f0ecebbe2d8b7b5318e3258b39088e03943a32ac` (detached clean worktree, exact HEAD verified). No detector, model, test, or Ark Runtime production source was edited. The separate baseline report is `typedarray_set_arraylike_independent_baseline_20261020.md`.

## Exact source identity and arithmetic

Ark Runtime source checkout: `D:\OpenHarmony807\repos\arkcompiler_ets_runtime`, HEAD `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`, repository declared `openharmony/arkcompiler_ets_runtime`. Verified candidate/dependency pins:

| Path | Blob OID | SHA-256 | Parse |
|---|---|---|---|
| `ecmascript/builtins/builtins_typedarray.cpp` | `0fc27c213e1ea80d93e1e3807eec11baf2634832` | `14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c` | complete |
| `ecmascript/builtins/builtins_arraybuffer.cpp` | `2aa22c58803df690a5a2b326451e02297dc5e2f6` | `4d388d997313cf7c900f1f0d54fbe826266845665424e32cc9dd4cdbaa62dcc9` | complete |
| `ecmascript/builtins/builtins_typedarray.h` | `b291181c949c7038b7030a216f5bdc0e7474a1c2` | `651d426c00c1d8bc6503c1d717decf42b28c61c57336e9418ad422604a6a1be7` | partial, 33 issues |

The source scout had the `.cpp` and `.h` identities swapped; these corrected pins match the independent baseline and the implementation's candidate report. Independently recomputed modulo arithmetic for offset `2^64-2048`, `srcLen=2049`, byte offset 4096 and one-byte elements: the uint64 range sum is 1; the uint32 start/end are 2048/4097. This is a source-derived cross-view write hypothesis; all indices remain below the 6145-byte backing length. No Ark Runtime execution or build was performed.

## Reproduction

All M2 invocations used `python -m src.cli ohscan-run` from the exact detached scanner checkout above, explicit detector `ohscanner.ark.runtime.type_safety`, and source commit above. Commands used:

```powershell
python -m src.cli ohscan-run --repo-dir D:\OpenHarmony807\repos\arkcompiler_ets_runtime --repository openharmony/arkcompiler_ets_runtime --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 --include ecmascript/builtins/builtins_typedarray.cpp --include ecmascript/builtins/builtins_arraybuffer.cpp --include ecmascript/builtins/builtins_typedarray.h --detector ohscanner.ark.runtime.type_safety --json-out D:\OpenHarmonyScanner\tmp\typedarray-set-f0-positive.json --md-out D:\OpenHarmonyScanner\tmp\typedarray-set-f0-positive.md
python -m src.cli ohscan-run --repo-dir D:\OpenHarmony807\repos\arkcompiler_ets_runtime --repository openharmony/arkcompiler_ets_runtime --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 --include ecmascript/builtins/builtins_typedarray.cpp --include ecmascript/builtins/builtins_typedarray.h --detector ohscanner.ark.runtime.type_safety --json-out D:\OpenHarmonyScanner\tmp\typedarray-set-f0-missing-helper.json --md-out D:\OpenHarmonyScanner\tmp\typedarray-set-f0-missing-helper.md
python -m src.cli ohscan-run --repo-dir D:\OpenHarmony807\repos\arkcompiler_ets_runtime --repository wrong/repository --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 --include ecmascript/builtins/builtins_typedarray.cpp --include ecmascript/builtins/builtins_arraybuffer.cpp --include ecmascript/builtins/builtins_typedarray.h --detector ohscanner.ark.runtime.type_safety --json-out D:\OpenHarmonyScanner\tmp\typedarray-set-f0-wrong-repo.json --md-out D:\OpenHarmonyScanner\tmp\typedarray-set-f0-wrong-repo.md
```

Results, taken from the JSON reports:

| Case | Result |
|---|---|
| Exact three-file source | Aggregate `completed_with_limitations`; detector `blocked`; one unassessed candidate at `builtins_typedarray.cpp:1227`; parse 2 complete / 1 partial; `validated_vulnerability=0`. Candidate message preserves partial header, unexecuted dispatch, cross-view-only hypothesis, and runtime/build/product unknowns. |
| Sink helper omitted from selected scope | `completed_with_limitations`; detector `blocked`; zero diagnostics; target limitation `arraylike_set_bounds_missing_sink_helper`; parse 1 complete / 1 partial. This is unknown/blocked, not safe. |
| Exact bytes under wrong declared repository | `completed_with_limitations`; detector `blocked`; zero diagnostics; target limitation says pinned upstream Git provenance and light-ast profile are required; parse 2 complete / 1 partial. |

The source checkout has only one commit object (`git rev-list --all --count` = 1); the proposed alternate historical commit `830e85b40240677039719fcbf14f721ad3b19050` is absent. Thus no wrong-commit M2 source replay was possible. The focused unit suite does exercise wrong-commit provenance via an all-zero SHA and expects `not_analyzed`, zero observations. It also exercises wrong repository, missing target, missing helper, mutated helper bytes, incomplete binding profile, fixed subtraction guard, stable-array-only path, unrelated sink/loop, small in-range/one-past arithmetic, and the wrap arithmetic.

Focused replay command/result on the same exact implementation checkout:

```powershell
python -m pytest -q tests/detectors/ark_runtime/test_arraylike_set_bounds.py tests/detectors/ark_runtime/test_catalog.py
# 12 passed in 0.14s
```

The fixed/in-range and mutated-helper cases above are unit fixture/static controls, not separate source commits or M2 executions. No dynamic runtime, build, ASan, architecture-specific runtime test, product-profile check, or impact evaluation was run; these remain `not_run`/`unknown`. I found no mismatch in the exercised exact-positive and fail-closed cases. No result here establishes a runtime vulnerability or allocation-boundary out-of-bounds access.
