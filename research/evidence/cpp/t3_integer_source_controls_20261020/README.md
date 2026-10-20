# T3 historical integer/bounds source-control closeout (2026-10-20)

## Scope and result

This is an independent source-control review on scanner baseline `81dd4aea9bb51522ac912b33504ef0d2ddb79089`. It does not change detector code, tests, fixtures, A0, or owner status. It checks whether the two historical rows have production controls that exercise the same root-cause semantics, not merely zero-result files.

| Case | Control result | Current disposition |
|---|---|---|
| CVE-2025-0587 | No source-bound production safe/unrelated control matching the vulnerable TypedArray Atomics `ToIndex` → signed narrowing → array-length comparison → atomic buffer access path was found in the exact vulnerable source. Existing DataView is only adjacent and is not reclassified. | `PARTIAL/BLOCK`; retain the vulnerable/fixed 1/0 replay, but missing matching control, product reachability/impact, and runtime/build context remain. |
| CVE-2025-23420 | Found a same-semantic snapshot control in exact vulnerable commit: `ArrayHelper::SortIndexedProperties` in `ecmascript/base/array_helper.cpp` reads the source object into a separate `TaggedArray` before invoking comparator callbacks, so the comparator loop does not use the mutable source object as its backing storage. Current `bounds` CLI parsed the whole file completely and emitted 0 candidates. | `PARTIAL/BLOCK`; this is a root-related safe control for comparator reentrancy versus dynamic backing-store access. It does not supply a trusted fixed implementation for `SortElementsByObject`, prove runtime/product behavior, or establish product reachability/impact. Existing InsertionSort evidence remains method-local and is not used as this control. |

The 0587 search was bounded to the exact vulnerable `atomic_helper.cpp` and adjacent TypedArray/DataView helper implementation in the pinned source. The only matching conversion/range-access observations outside the target were the already-recorded DataView path and typed-array constructor offset/length conversions; the latter narrow values before range validation and cannot responsibly be labeled safe. `AtomicHelper::ValidateAtomicAccess` is shared by the atomic operations, so a second operation routed through the same helper is not an independent safe control.

Search commands (against source Git objects, no fetch):

```powershell
git grep -n 'ToIndex(thread' cae11f121c030a90ba41d8e4d866f91292f25892 -- ecmascript/base ecmascript/builtins
git grep -n -E 'GetArrayLength|GetByteLength|DoubleInRangeInt32|DoubleToUInt64|ToIndex' cae11f121c030a90ba41d8e4d866f91292f25892 -- ecmascript/base/typed_array_helper.cpp ecmascript/builtins/builtins_typedarray.cpp ecmascript/builtins/builtins_dataview.cpp ecmascript/base/atomic_helper.cpp
git diff cae11f121c030a90ba41d8e4d866f91292f25892 5aa9c035e98911ec7ed28065a2138c2709792a42 -- ecmascript/base/atomic_helper.cpp
```

The first search found the vulnerable atomic path and TypedArray constructor uses; the second narrowed review to exact nearby conversions and guards. Constructor `byteOffset` narrowing occurs before its range comparison, so it is not a reviewed safe control. The source identities and diff were manually checked; no additional 0587 CLI was run because no eligible control candidate was found.

## Source identities

The vulnerable/fixed pairs below are the exact historical matrix bindings, not newly asserted product-version claims:

| Case / role | Commit | Tree | File | Blob | SHA-256 |
|---|---|---|---|---|---|
| CVE-2025-0587 vulnerable | `cae11f121c030a90ba41d8e4d866f91292f25892` | `61ff01d9a06b4186125a04e2b790e07640f57198` | `ecmascript/base/atomic_helper.cpp` | `7fd67717571c6d8fe7b10bf294998e952dc61e36` | `f4890391896239c845bbcaee489d83c85eb5a64e37d563b91ed6e3908c62a541` |
| CVE-2025-0587 fixed | `5aa9c035e98911ec7ed28065a2138c2709792a42` | `05ac3902979e37ae08efa2d1e3ed32472a69d0cc` | `ecmascript/base/atomic_helper.cpp` | `80d7ad14e70825ef2daf7b3f2fc956a891bf8b2c` | `39521f4c6fa6b4b65d8b3daacd80f6e051b5a01c5aa814c9ac2ffc432529b36b` |
| CVE-2025-23420 vulnerable | `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` | `0eea26c9eb6846f4d19926be83092c06f0d98692` | `ecmascript/js_array.cpp` | `2c58914ad27b6b3c5f570dbd2fe0ed02d1d9e471` | `b7f28be2f63850ba1cb57a35d518930986855784d2081124e555f2a57d673e9b` |
| CVE-2025-23420 source control | `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` | `0eea26c9eb6846f4d19926be83092c06f0d98692` | `ecmascript/base/array_helper.cpp` | `ce74b02e5a2df9f434d982ea09440ce9f33f1dd9` | `861f37ecc33fa5a890279606e4a740ba26216c60158b802f537199b74a8d578f` |

For CVE-2025-0587, exact vulnerable-to-fixed diff confirms that `length` changes from `int32_t(static_cast<int32_t>(GetArrayLength()))` to `uint32_t`, and `index` from `DoubleInRangeInt32(ToIndex(...))` to `DoubleToUInt64(ToIndex(...))` before the `index >= length` check. This pins the relevant signedness/narrowing semantics. It does not by itself prove exploitability.

For CVE-2025-23420, the control is specific to comparator reentrancy and mutable backing-store access: the control copies object properties into `TaggedArray` before sorting; `SortElementsByObject` instead repeatedly calls `ElementAccessor::Get/Set` on the potentially mutated `JSObject` after `SortCompare`. This is a reviewed code-path distinction, not a scanner-confirmed safe verdict.

## Scanner replay

The 23420 control replay used the isolated scanner checkout at baseline `81dd4aea9bb51522ac912b33504ef0d2ddb79089` and the exact vulnerable source commit:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit aeee3fd12c03193545edea4b8e0fdfa3d9a03d11 --include ecmascript/base/array_helper.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/t3_integer_source_controls_20261020/cve2025-23420-sort-indexed-properties.json --md-out $env:TEMP\t3-cve2025-23420-sort-indexed-properties.md
```

Result: completed; `ohscanner.cpp.bounds` 0.3.0; one selected source file; parse complete; 0 diagnostics; file SHA-256 and blob OID are in the raw JSON. This scanner result is corroborating evidence only; semantic safety attribution is manual and remains bounded to the copied-input comparator path.

The existing T2 source pair scans remain the current vulnerable/fixed differentials: 0587 integer_bounds 1/0 and 23420 bounds 5/0. Existing T2 DataView and InsertionSort controls are referenced only as adjacent/method-local observations. They are not repeated as root-specific controls here.

## Reproduction and verification

```powershell
python research/evidence/cpp/t3_integer_source_controls_20261020/verify.py --source-git-dir D:\openHarmonyScanner\arkruntime-holdout-history --scanner-git-dir .
python -m scripts.check_change_scope --base 81dd4aea9bb51522ac912b33504ef0d2ddb79089 --lane cpp
git diff --check
```

The verifier recomputes the vulnerable/fixed/control commit trees and file blob SHA-256 values from local Git objects, then checks the raw scanner report's scanner baseline, target commit, declared one-file scope, detector/version, complete parse status, zero findings, and source SHA/blob binding. No fixed source for the 23420 method, product build identity, runtime reachability or impact evidence was added; both matrix rows remain `PARTIAL/BLOCK`.
