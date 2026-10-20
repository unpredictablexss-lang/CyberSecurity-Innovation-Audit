# D23 integer/bounds historical detector gap review

Status: **NO DETECTOR CHANGE; both historical rows remain PARTIAL.**

Scanner baseline: `81dd4aea9bb51522ac912b33504ef0d2ddb79089` (detached independent worktree). The current CLI was rerun against all four exact vulnerable/fixed source commits using the existing 0.2.0 `integer_bounds` and 0.3.0 `bounds` rules. Raw JSON is beside this report. `verify.py` rechecks Git tree/blob/source SHA-256 identities and the fresh report scope, complete parse status, detector result count, and finding locations.

## Reproduced pairs

| Case | Exact source pair | Current CLI | Interpretation |
|---|---|---|---|
| OpenHarmony CVE-2025-0587 | `cae11f121c030a90ba41d8e4d866f91292f25892` / `5aa9c035e98911ec7ed28065a2138c2709792a42`; `ecmascript/base/atomic_helper.cpp` | `integer_bounds@0.2.0`: 1 / 0; complete parse on both | Vulnerable candidate at `ValidateAtomicAccess`, line 71, for `int32_t index = DoubleInRangeInt32(ToIndex(...))`; fix changes length to `uint32_t` and index to `uint64_t` before comparison and offset arithmetic. This is an existing root-positive/fixed differential, not a detector miss. |
| OpenHarmony CVE-2025-23420 | `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` / `1b23531531e768398682582969c2a9f17e72cafe`; `ecmascript/js_array.cpp` | `bounds@0.3.0`: 5 / 0; complete parse on both | All five vulnerable candidates are `ElementAccessor` accesses inside `SortElementsByObject` (lines 650, 653, 665, 666, 668); the fixed source reports zero. The current detector's bounded lexical rule deliberately reports these direct accesses when it cannot model the comparator-mutated backing store. This is existing root-positive/fixed differential, not a detector miss. |

Exact tree/blob/file SHA-256 values match the source-bound identities in `a_matrix_13row_current_replay_inventory_20261020.md` and `a_matrix_history_20261020/matrix_history_replay_20261020.json`. The pre-existing verifier was rerun and returned `PASS_SOURCE_BOUND_STATIC_DIFFERENTIAL`, `errors: []`.

## Detector gap assessment

No generalizable change is justified by the available evidence:

- CVE-2025-0587 already has the vulnerable narrowed-index candidate and a trusted fixed-source differential. Its known same-function control gap remains specific: no source-bound safe/unrelated control exercises `ValidateAtomicAccess` with a negative/overflowed/out-of-range request. The previously reviewed DataView guard is adjacent only; upstream `atomic_helper_test.cpp` covers legal indices only. The existing 0587 finding therefore supports candidate coverage, but cannot establish that a proposed relaxation or refinement preserves root-specific safe behavior.
- CVE-2025-23420 already has candidates at each unguarded dynamic `ElementAccessor` operation in `SortElementsByObject` and a trusted fixed-source differential. The same-source `SortElementsByInsertionSort` observation is a method-local adjacent control using a fixed `TaggedArray`, not the same comparator-driven dynamic `JSObject` access path. Upstream `js_array_test.cpp` does not establish safe behavior for the root. There is no source-bound safe/unrelated control for that dynamic mutation path.
- Existing detector unit controls cover renamed, unrelated, safe, and partial fixtures, but those fixtures do not supply the missing root-specific upstream controls. Widening or narrowing either rule without those controls would be unsupported. No diagnostic schema, parser threshold, API, catalog, detector, tests, or fixtures were changed.

Keep both matrix rows **PARTIAL**: root candidates and fixed differentials are reproduced, but root-specific safe/unrelated controls, product reachability and impact evidence remain missing. No static finding is asserted as a validated product vulnerability. Minimum next inputs: (1) a source-bound negative/large-index `ValidateAtomicAccess` safe/rejection control at a trusted source identity; (2) a source-bound safe comparator/dynamic-array control for `SortElementsByObject` at a trusted identity; and for either row, product build/reachability/impact evidence if the status is to advance beyond bounded static regression.

## Reproduction

Run from the scanner repository root (the historical source Git object repository must be available):

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit cae11f121c030a90ba41d8e4d866f91292f25892 --include ecmascript/base/atomic_helper.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/d23_integer_bounds_gap_20261030/0587-vuln.json --md-out $env:TEMP\d23-0587-vuln.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit 5aa9c035e98911ec7ed28065a2138c2709792a42 --include ecmascript/base/atomic_helper.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/d23_integer_bounds_gap_20261030/0587-fixed.json --md-out $env:TEMP\d23-0587-fixed.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit aeee3fd12c03193545edea4b8e0fdfa3d9a03d11 --include ecmascript/js_array.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d23_integer_bounds_gap_20261030/23420-vuln.json --md-out $env:TEMP\d23-23420-vuln.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit 1b23531531e768398682582969c2a9f17e72cafe --include ecmascript/js_array.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d23_integer_bounds_gap_20261030/23420-fixed.json --md-out $env:TEMP\d23-23420-fixed.md
python research/evidence/cpp/d23_integer_bounds_gap_20261030/verify.py --source-git-dir D:\openHarmonyScanner\arkruntime-holdout-history
```
