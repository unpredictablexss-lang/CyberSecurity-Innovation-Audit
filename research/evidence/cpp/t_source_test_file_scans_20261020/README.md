# Source-bound upstream test-file scans (2026-10-20)

These are supplementary observations from scanning two unmodified upstream test files at the exact vulnerable-source commits used by the historical matrix replay. They are **not safe or unrelated controls** and do not upgrade CVE-2025-0587 or CVE-2025-23420 from `PARTIAL`:

- `atomic_helper_test.cpp` exercises legal indices 0, 1 and 2 for `ValidateAtomicAccess`; it does not test negative, overflowed, or out-of-range requests.
- `js_array_test.cpp` does not establish safe behavior for the `SortElementsByObject` mutation/bounds root cause.
- A zero finding on a test file is not evidence that the corresponding vulnerable implementation is safe.

The evidence files preserve raw CLI JSON. Both executions used independent checkout `5f8b0ce0c587b023eef3d871c012caba755cee79` (PR #35 head at execution) and source repository objects in `D:\openHarmonyScanner\arkruntime-holdout-history`.

## Reproduce

From the repository root, with the historical source object repository available:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit cae11f121c030a90ba41d8e4d866f91292f25892 --include ecmascript/base/tests/atomic_helper_test.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/t_source_test_file_scans_20261020/cve2025-0587-atomic-helper-test.json --md-out $env:TEMP\t0587-atomic-helper-test.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit aeee3fd12c03193545edea4b8e0fdfa3d9a03d11 --include ecmascript/tests/js_array_test.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/t_source_test_file_scans_20261020/cve2025-23420-js-array-test.json --md-out $env:TEMP\t23420-js-array-test.md
python research/evidence/cpp/t_source_test_file_scans_20261020/verify.py --source-git-dir D:\openHarmonyScanner\arkruntime-holdout-history
```

## Results

| Related case | Source test file | Source commit | Tree | Blob | SHA-256 | Parse / detector | Result |
|---|---|---|---|---|---|---|---|
| CVE-2025-0587 | `ecmascript/base/tests/atomic_helper_test.cpp` | `cae11f121c030a90ba41d8e4d866f91292f25892` | `61ff01d9a06b4186125a04e2b790e07640f57198` | `ca2806418b4189d0ccc4a7b55f7b8cc9291abb1f` | `a15f57aa48e3d2256713fdd0db959dbe7fd79538d83b4ed4686949b219ddb630` | complete; `integer_bounds` 0.2.0 | completed, 0 diagnostics |
| CVE-2025-23420 | `ecmascript/tests/js_array_test.cpp` | `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` | `0eea26c9eb6846f4d19926be83092c06f0d98692` | `a9a35d082d05b8dbd5ed1b40c8154394fefa2567` | `cf4c6eb657953e5c25ac2ec3d75d89ae521e40935e7f542d65f9e4e8fce56241` | complete; `bounds` 0.3.0 | completed, 0 diagnostics |

## Remaining evidence gap: root-specific controls and fixed evidence are missing

The two production-source observations below are retained as narrowly interpreted adjacent controls; they do not satisfy root-specific control or fixed-source evidence:

- CVE-2025-0587 still lacks a source-bound negative/large-index control exercising the same `ValidateAtomicAccess` typed-array atomic path, plus a trusted fixed source for that function.
- CVE-2025-23420 still lacks a source-bound control that exercises comparator-driven mutation against the dynamic `JSObject` access path, plus a trusted fixed source for `SortElementsByObject`.
- The CVE-2025-23420 `SortElementsByInsertionSort` observation remains method-local because the CLI scans whole files; its parent file correctly reports five candidates in the vulnerable method.

Neither adjacent control supplies a vulnerable/fixed root-cause differential. Product reachability and impact are also unproven. Keep both matrix rows `PARTIAL` until the missing root-specific and product evidence is resolved.

## Production-source control review

Two additional source-bound production-code observations were scanned:

- **CVE-2025-0587 — DataView range guard.** `BuiltinsDataView::GetViewValue` in `ecmascript/builtins/builtins_dataview.cpp` converts an index to `int32_t`, rejects a negative result, then checks the resulting index plus element size against the view byte length before reading. Oversized values saturate at `INT32_MAX` through `DoubleInRangeInt32` and fail the range check for ordinary valid view sizes. This is an analogous guarded index-to-memory-access path, not the vulnerable TypedArray atomic operation. The current `integer_bounds` detector produced zero candidates and parsed the file completely. Treat this as a relevant adjacent safe control for conversion/range-check behavior, not proof that every TypedArray case is safe.
- **CVE-2025-23420 — fixed-size sort buffer.** In the exact vulnerable `js_array.cpp`, `JSArray::SortElements` takes `len` from `elements->GetLength()` and passes the same fixed `TaggedArray` plus that length to `SortElementsByInsertionSort`. Its indexed reads/writes are derived from `i`, `beginIndex`, `endIndex`, and `j`, each bounded by that fixed length; unlike `SortElementsByObject`, it does not re-read a potentially mutated JSObject's backing elements after invoking the comparator. The whole-file `bounds` scan parsed completely and reported five candidates only at lines 650, 653, 665, 666 and 668 in `SortElementsByObject`; no candidate was located in `SortElementsByInsertionSort` (lines 603–636). This is a same-file, method-local control observation, not a quiet whole-file control.

These controls are real upstream source, bound to the same exact vulnerable commits/tree and file identities. Their interpretation is limited to the code reviewed above. They do not supply fixed-source safety evidence, and neither establishes product reachability or impact; retain both matrix rows as `PARTIAL`.

Production-control CLI commands:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit cae11f121c030a90ba41d8e4d866f91292f25892 --include ecmascript/builtins/builtins_dataview.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/t_source_test_file_scans_20261020/cve2025-0587-dataview-adjacent.json --md-out $env:TEMP\t0587-dataview-adjacent.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit aeee3fd12c03193545edea4b8e0fdfa3d9a03d11 --include ecmascript/js_array.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/t_source_test_file_scans_20261020/cve2025-23420-js-array-root-control-review.json --md-out $env:TEMP\t23420-js-array-root-control-review.md
```

| Related case | Production control source | Source commit | Tree | Blob | SHA-256 | Parse / detector | Result |
|---|---|---|---|---|---|---|---|
| CVE-2025-0587 | `ecmascript/builtins/builtins_dataview.cpp` (`BuiltinsDataView::GetViewValue`) | `cae11f121c030a90ba41d8e4d866f91292f25892` | `61ff01d9a06b4186125a04e2b790e07640f57198` | `103b6f850280c39168a1f4d71d385cb2c281e650` | `e26279b7c341ded1962aad40341976c5175c2256e6c885c6eea423aa1099af06` | complete; `integer_bounds` 0.2.0 | completed, 0 diagnostics |
| CVE-2025-23420 | `ecmascript/js_array.cpp` (`SortElementsByInsertionSort`, lines 603–636) | `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` | `0eea26c9eb6846f4d19926be83092c06f0d98692` | `2c58914ad27b6b3c5f570dbd2fe0ed02d1d9e471` | `b7f28be2f63850ba1cb57a35d518930986855784d2081124e555f2a57d673e9b` | complete; `bounds` 0.3.0 | whole file: 5 candidates, all in `SortElementsByObject`; none in control method |
