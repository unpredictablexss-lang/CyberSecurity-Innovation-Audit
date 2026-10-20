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

## Remaining evidence gap

For both cases, a directly relevant, source-bound safe/unrelated behavior control still needs to be identified and independently scanned with its semantic basis reviewed. The reports also do not establish product reachability or impact. Keep both matrix rows `PARTIAL` until those obligations have evidence.
