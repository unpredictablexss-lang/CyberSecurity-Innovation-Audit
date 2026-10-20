# Float32Array negative-TDouble candidate: independent CLI baseline

Date: 2026-10-20. Tester slice `C-TEST-FLOAT32-STATIC-CANDIDATE`. This report records the pre-implementation registered CLI/adapter baseline and replay matrix. No detector, model, task-tree, or production source was edited.

## Exact Ark Runtime source and parser baseline

Repository checkout used: `D:\OpenHarmony807\repos\arkcompiler_ets_runtime`, clean source identity at commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016` (`openharmony/arkcompiler_ets_runtime`). The three selected source files were independently checked with `git ls-tree` and the scanner's pinned Git index:

| Path | Git blob | SHA-256 | light-ast status |
|---|---|---|---|
| `ecmascript/compiler/common_stubs.cpp` | `6267f2f27a98a298b1190e327abbfa2bd58203f8` | `5a401580e666596fcf2ea89a8dc0321009b53ef5320b20edc59d37781d852212` | `partial`, 13 parse issues |
| `ecmascript/compiler/typed_hcr_lowering.cpp` | `1ad4e329a226fc9941db30fa7a10a6562f58f68d` | `acd4ed88bb4ba5d327d5628dc45b7b89685a9c425c5849891cbf2544e8534a0c` | `complete`, 0 issues |
| `ecmascript/compiler/new_object_stub_builder.cpp` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` | `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0` | `complete`, 0 issues |

Index summary: 3 C++ files, 2 complete and 1 partial. The `common_stubs.cpp` status remains partial; this baseline does not infer full-file or product-build coverage from a locally resolvable function.

## Reproducible command and current registered result

Environment: `D:\OpenHarmonyScanner\.venv-c-line\Scripts\python.exe`, OHScanner checkout at current planning branch HEAD `3b537b2aedafc1ab14b6751965551c0bbee50bf3` when the baseline ran. Commands:

```powershell
D:\OpenHarmonyScanner\.venv-c-line\Scripts\python.exe -m src.cli ohscan-index --repo-dir D:\OpenHarmony807\repos\arkcompiler_ets_runtime --repository openharmony/arkcompiler_ets_runtime --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 --include ecmascript/compiler/common_stubs.cpp --include ecmascript/compiler/typed_hcr_lowering.cpp --include ecmascript/compiler/new_object_stub_builder.cpp --json-out D:\openHarmonyScanner\tmp\float32-candidate-index-baseline.json --md-out D:\openHarmonyScanner\tmp\float32-candidate-index-baseline.md
D:\OpenHarmonyScanner\.venv-c-line\Scripts\python.exe -m src.cli ohscan-run --repo-dir D:\OpenHarmony807\repos\arkcompiler_ets_runtime --repository openharmony/arkcompiler_ets_runtime --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 --include ecmascript/compiler/common_stubs.cpp --include ecmascript/compiler/typed_hcr_lowering.cpp --include ecmascript/compiler/new_object_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out D:\openHarmonyScanner\tmp\float32-candidate-run-baseline.json --md-out D:\openHarmonyScanner\tmp\float32-candidate-run-baseline.md
```

Observed M2 result: command completed with limitations; one explicitly selected detector; zero diagnostics; detector coverage `blocked`; 3 applicable files, 0 analyzed, 0 partially inspected, and 3 not analyzed. Each file reports `exact upstream repository/commit/path is not in the reviewed model`. This is an unsupported/unbound baseline, not evidence that the candidate is absent or safe.

Registration architecture independently checked:

- `src/ohscanner/detectors/catalog.py` registers `ohscanner.ark.runtime.type_safety` as a first-party research-candidate detector, `default_enabled=False`; explicit `--detector` is required.
- `c_line_static_model()` currently binds its a65 `target_bindings` and species-read-width profile to `builtins_typedarray_stub_builder.cpp`; its `source_dependencies` contains the exact `new_object_stub_builder.cpp` creator blob, but it has no target binding for `common_stubs.cpp` or `typed_hcr_lowering.cpp` and no rule for this constructor check.
- The strict adapter selects exact modeled paths, then requires exact repository, commit, path, Git blob, SHA-256, `git_object` provenance, and `light-ast` profile. A matching path without an exact binding is `not_analyzed`; a changed source OID/hash or commit must not be reported as an analyzed clean/fixed result.
- M1 indexing reads immutable local Git objects and provides parser/source identity facts; it does not run a vulnerability rule. M2's zero-diagnostic output and blocked sidecar retain unknown coverage.

## Independent source-derived control matrix for developer SHA replay

None of these semantic cases below was executed in Ark Runtime. They are source-derived expectations; only the M1/M2 CLI baseline above was executed.

| Case | Required identity/input | Expected result and interpretation |
|---|---|---|
| Exact parent candidate | Exact a65 repo/commit and the three pinned files above; include creator helper. Both double-tag paths have equality round-trip plus upper `MAX_GAP`, no `>=0`; tagged-int path has `>=0`. | A sparse candidate only on the applicable negative-TDouble conversion guard path(s). Do not emit candidates from allocator/helper functions or unrelated byte arithmetic. Keep CommonStub partial and any incomplete analysis explicit. |
| Fixed-byte control | Change the double predicate to include `doubleLength >= 0` in both CommonStub and TypedHCR source, changing file blob/SHA; run with the exact fixed source identity if it is registered. | The fixed predicate should reject negative doubles when evaluated. If submitted under a65 binding or an unregistered fixed commit, adapter must fail closed as unknown/not_analyzed; zero diagnostics on a mismatched hash is not a safe/miss result. A direct synthetic analyzer unit may separately verify that the fixed source condition removes the candidate, labeled as fixture/source-level only. |
| TaggedInt `-1` | Exact parent path; distinguish `TaggedIsInt` / `intLen >= 0` branch from TDouble branch. | Source-predicted reject/slow path; must not itself cause a TDouble candidate. Not runtime-executed. |
| Positive integral TDouble | Exact parent path; e.g. `1.0` in the double branch. | Source-predicted accepted positive fast path/control; must not produce a negative-length candidate. Not runtime-executed. |
| Unrelated function/path | Exact source commit but a function without the Float32Array constructor predicate, or unrelated file. | No candidate; if not a modeled target, retain `not_analyzed`/`not_applicable`, not a global-safe claim. |
| Wrong commit/repository/blob/SHA | Alter one provenance identity at a time. | Zero candidate and fail-closed `not_analyzed`/blocked. Never treat the mismatch as an analyzed safe control. |
| Missing or mutated creator helper | Omit `new_object_stub_builder.cpp`, or include bytes that do not match the expected OID/SHA. | Dependency unknown/blocked; do not claim candidate-to-allocation trace complete and do not downgrade to safe. |
| Partial / insufficient function evidence | Keep `common_stubs.cpp` at its existing partial/13 parse issues; or remove required function/AST evidence. | Preserve partial/unknown or blocked. Do not upgrade whole-file parse status, fabricate test pass, or broaden findings based on partial-file neighbors. |

The only allowed claim for the source input is a conditional static candidate. Neither the candidate nor its control matrix establishes JavaScript representation reachability, successful construction, an out-of-bounds access, or product impact.

## Baseline artifact locations

Generated reports are retained outside the repo at:

- `D:\OpenHarmonyScanner\tmp\float32-candidate-index-baseline.json`
- `D:\OpenHarmonyScanner\tmp\float32-candidate-index-baseline.md`
- `D:\OpenHarmonyScanner\tmp\float32-candidate-run-baseline.json`
- `D:\OpenHarmonyScanner\tmp\float32-candidate-run-baseline.md`

