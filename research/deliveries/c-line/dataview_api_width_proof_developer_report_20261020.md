# DataView API index-width candidate refinement — 2026-10-20

## Finding and bounded change

The registered index-width rule emitted candidates at parent `GetViewValue:394` and `SetViewValue:455`. The exact source does not support those as signed-32-bit wraparound paths: both APIs reject negative indices; the non-integer conversion helper returns within `INT32_MIN..INT32_MAX`; the integer fast path supplies an `int32_t` value; and `JSDataView::GetElementSize` returns only 1, 2, 4, or 8. Consequently, the checked `index + elementSize` cannot wrap `uint32_t` (`INT32_MAX + 8 < UINT32_MAX`). A passing view-length check also bounds the subsequent address sum for a constructed view, though this change does not claim to prove all backing-buffer mutation semantics.

The rule now suppresses only these two API candidates when both exact helper sources are present and match commit, Git blob, SHA-256, and complete parse: `JSDataView::GetElementSize` in `ecmascript/js_dataview.cpp`, and `NumberHelper::DoubleInRangeInt32` in `ecmascript/base/number_helper.cpp`. It leaves an explicit partial/unknown limitation for each suppressed API. If either dependency is absent or mismatched, the original candidates remain. Other detector paths, including the `SetTypedValue` candidate, are unaffected. The fixed API continues to report its existing constructor/get/set unknowns; no safe verdict is inferred.

The runner now honors an optional detector `select_applicable_units(context, units)` hook after language filtering. It rejects returned objects outside the supplied context, duplicates, and unsupported languages. This lets helper files stay in the full context for exact dependency checks while only target files count as applicable. Detectors without the hook retain language-based scope.

## Exact source pins

Target identities were independently checked against the local Git object store:

| Revision | Commit | Tree | Target blob | Target SHA-256 |
|---|---|---|---|---|
| Parent | `d62f6de64daa7e11a7936a6153748a7c5fae9e41` | `a26f18bc7b1cd97fb926ae61b3655ddbf2caf8d1` | `e6bac984354292405ae62f7728170d7be5e3760e` | `bc01e0f8b8a2a5ab30d1478587b45a14aa8130d3d53dfb32b9513ff4d73bc38c` |
| Fixed | `48fcec3686e45175f95b4600b579026a65149966` | `6ff7f405071d29fc3ecf9bac1abd9d59a485909f` | `a2376e822e995333b2400520ca5b882de9578b5e` | `39b1ed79451980ad85e1176805deaf6c6315bca09d7676ea5c63f5ff1c4bd65b` |

The two evidence dependencies are identical at both commits: `js_dataview.cpp` blob `5057a103a88096b5db0e39be0feca2864a2ff8eb`, SHA-256 `3782d04ee5c44504bf453b3b45f96d7431ff902fb575257c425c707890b83243`; `number_helper.cpp` blob `a648bf6cf36715d57c6466f0ab4bfdc00bdc8f35`, SHA-256 `94db5ecc8ff7ea79d656950abacd9c24756ccf6aa0e3b2b895d7dc9961dbc91f`.

## Controls and replay

The independent boundary matrix covered widths 1/2/4/8; index 0 and exact-fit; exact end; first-past-end and end; negative index; `INT32_MAX` with too-small and arithmetic-fit view lengths; maximum offset with half-open end `UINT32_MAX`; and out-of-range conversion as a separate unknown. The developer tests verify missing/widened helper evidence retains candidates, exact helper evidence suppresses only the API wrap candidates and remains partial, unrelated candidates remain unaffected, and runner target/dependency accounting is bounded.

Command:

```powershell
python research/deliveries/c-line/dataview_api_width_proof_replay_20261020.py --git-dir D:/openHarmonyScanner/tmp/arkruntime-gitee-audit-20261023.git
```

The registered replay produced:

- Parent with no dependencies: two candidates at lines 394/455; detector blocked and coverage partial.
- Parent with both exact dependencies: zero diagnostics; explicit API wrap-excluded unknowns plus constructor unknown; detector blocked and coverage partial.
- Fixed with or without dependencies: zero diagnostics; existing constructor/get/set unknowns; detector blocked and coverage partial.
- In all four runs, only the target `builtins_dataview.cpp` counted as applicable; helper files remained available in context but were not counted as target files.

Validation passed: `python -m pytest tests/detectors/ark_runtime tests/test_runner_applicable_units.py -q` (195 passed, 3 skipped); `git diff --check` passed. The exact replay JSON is saved beside the replay script. Repository-wide `python -m pytest -q` could not collect seven unrelated test modules because this Windows environment lacks `fastapi` and POSIX `fcntl`. A broader runner-focused set also had three pre-existing environment failures in M1 Git tests (CRLF expectation, ArkTS parser not_run, and symlink privilege); its other 53 tests passed.

## Limits

This is a source-level narrowing of one arithmetic mechanism. It does not prove all resizable/growable/shared backing-store or concurrent mutation behavior, full ECMAScript conversion compatibility, generated IR behavior, runtime reachability, product impact, or overall detector accuracy. The exact registered outcomes remain blocked/partial because the broader model is incomplete. No product or runtime conclusion is made.
