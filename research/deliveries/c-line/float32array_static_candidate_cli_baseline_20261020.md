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

## Developer working-tree replay (pre-commit)

After the developer added the source-bound rule in the shared working tree, I independently reran M2 using the same exact a65 source checkout, repository, three-file scope, and explicit detector as the baseline. This is a **pre-commit working-tree replay**, not yet a result bound to a developer commit SHA:

| Case | CLI outcome | Meaning |
|---|---|---|
| Exact a65 commit, all three exact files and helper present | 1 diagnostic at `common_stubs.cpp:228`; run `completed_with_limitations`; detector `blocked`; coverage 1 partial, 0 complete, 0 not analyzed; obligations unknown | One sparse candidate; CommonStub retains partial status. This is not runtime validation. |
| Exact a65 target + HCR files, creator helper omitted | 0 diagnostics; detector `blocked`; target not analyzed with `negative_double_length_missing_source:...new_object_stub_builder.cpp` | Dependency gate fails closed. |
| Exact a65 source commit but declared repository `example/wrong-repository` | 0 diagnostics; detector `blocked`; files not analyzed | Repository identity gate fails closed. |
| Wrong but locally available source commit `830e85b40240677039719fcbf14f721ad3b19050`, same paths | 0 diagnostics; detector `blocked`; CommonStub not analyzed with `exact upstream repository/commit/path is not in the reviewed model` | Exact-commit gate fails closed. This commit was available in the local full-history object store; the clean `D:\OpenHarmony807` checkout itself is shallow/grafted and lacks the a65 parent. |

Run artifacts are in `D:\OpenHarmonyScanner\tmp\float32-candidate-run-dev-working.{json,md}`, `float32-candidate-run-missing-helper.{json,md}`, `float32-candidate-run-wrong-repo.{json,md}`, and `float32-candidate-run-wrong-commit.{json,md}`. The exact positive CLI produced one finding only; the helper and identity negative controls produced zero findings without reporting an analyzed safe result.

Still pending at this point: developer commit-SHA-bound replay; fixed-guard source fixture; altered target blob/hash; mutated helper bytes/hash; explicit wrong-blob control; TaggedInt and positive TDouble are source-semantic controls, not Ark Runtime executions. The developer's unit tests cover predicate fixtures for fixed lower bound, tagged-int distinction, and unrelated/incorrect upper-bound blocks, but those unit tests were not run independently in this tester slice yet. No control in this section establishes an OOB vulnerability or product impact.

## Same-commit independent replay

The implementation was committed as OHScanner SHA `929904ab522d855be32c6c58a0704f8d21faed58`. Before replay I verified `git rev-parse HEAD` returned this exact SHA and the worktree was clean. I then reran the same three-file exact a65 positive scope and the key wrong-commit and missing-helper negative cases; commands were the same as above with output paths under `D:\OpenHarmonyScanner\tmp\float32-candidate-run-929904ab-*`.

| Case | Result on implementation SHA `929904ab522d855be32c6c58a0704f8d21faed58` |
|---|---|
| Exact a65 source + all three exact source files | 1 candidate at `common_stubs.cpp:228`; detector `blocked`; coverage partial 1, no complete or not-analyzed files; exact C++ file stays partial. |
| Wrong commit `830e85b40240677039719fcbf14f721ad3b19050` | 0 candidate; detector `blocked`; common stub `not_analyzed` with exact repository/commit/path absent from reviewed model. |
| Exact a65 source with creator helper omitted | 0 candidate; detector `blocked`; common stub `not_analyzed` with `negative_double_length_missing_source:...new_object_stub_builder.cpp`. |

The output tree for the positive and missing-helper cases is the exact Ark Runtime tree `8781f036a3e7e04d8e0b34970d5f623b42875016`. The wrong-commit control uses local source commit/tree `830e85b40240677039719fcbf14f721ad3b19050` / `579712c1ebbb703d17cea422b1572023bed5d8a4`. The implementation's candidate remains one diagnostic, at the same single location, and its exact bound target retains partial coverage; no runtime or vulnerability conclusion is added.

The post-commit replay did not execute a fixed-byte mutated target, a mutated-helper Git object, or a separate helper-SHA mismatch case. The pre-commit unit tests' fixed-predicate fixture is developer-authored and has not been independently rerun here. Those controls remain pending rather than passed.

## Hardened profile same-commit replay

The developer subsequently added an immutable exact three-row source-pin whitelist and a model-pin tamper assertion in implementation commit `46fdb5887c49a552b249fb20805025ba6316d8d0`. I verified this exact SHA was `HEAD` and the worktree was clean before running the cases below. This hardening commit is the latest implementation SHA covered by this report.

| Case | Result on `46fdb5887c49a552b249fb20805025ba6316d8d0` |
|---|---|
| Exact a65 source + all three exact files | 1 candidate at `common_stubs.cpp:228`; detector blocked; coverage partial 1, no complete or not-analyzed files. |
| Wrong source commit `830e85b40240677039719fcbf14f721ad3b19050` | 0 candidate; detector blocked; common stub not analyzed because the exact repository/commit/path is not in the reviewed model. |
| Exact a65 with creator helper omitted | 0 candidate; detector blocked; common stub not analyzed with `negative_double_length_missing_source:...new_object_stub_builder.cpp`. |

These three runs were independent CLI executions with output files `D:\OpenHarmonyScanner\tmp\float32-candidate-run-46fdb588-{positive,wrong-commit,missing-helper}.{json,md}`. The exact source tree remained `8781f036a3e7e04d8e0b34970d5f623b42875016` for positive and missing-helper cases. Candidate count stayed at one and did not spread to helper files.

I also independently reran the detector-specific tests and complete Ark Runtime detector test directory against this implementation SHA. `D:\anaconda3\python.exe -m pytest -q tests/detectors/ark_runtime/test_negative_double_length.py` passed (5 passed); `D:\anaconda3\python.exe -m pytest -q tests/detectors/ark_runtime` passed (198 passed, 3 skipped). The `D:\OpenHarmonyScanner\.venv-c-line` environment does not contain pytest, so the test command was run using the already available Anaconda pytest installation. These tests do not execute Ark Runtime or prove runtime impact.

Still not executed independently: fixed-byte target under a separately bound fixed commit, mutated-helper Git blob/hash, wrong helper SHA with the exact profile, wrong target blob/SHA, TaggedInt runtime behavior, positive TDouble runtime behavior, or Ark Runtime/ASan. The code has a predicate-level fixed guard unit fixture, but that does not replace an exact-source fixed CLI control. Keep these statuses as not run.
