# C4 historical upstream fix: TypedArray allocation exception path

Classification: **confirmed upstream-fixed source-level missing exception guard in the local generator path; product impact and exploitability unknown**. This confirms the source correction in the reviewed upstream history. It does not confirm a deployed product vulnerability, CVE, affected release range, or security impact.

Repository: [openharmony/arkcompiler_ets_runtime](https://github.com/openharmony/arkcompiler_ets_runtime). The exact upstream fix is [commit 81ca5748](https://github.com/openharmony/arkcompiler_ets_runtime/commit/81ca57487d04ea30cd11c271e86494a4e130f43e), parent c758818dbfd0b146a908d43d21f6ca1706c33783. The commit message is [bufix]: fix typedArray map (issue IC7B8Q).

The parent source creates a TypedArray result with NewTypedArray, then reads its HClass in the generated Filter and Map paths without first returning when an exception is pending. The fix moves the Filter HClass read behind HasPendingException and adds the corresponding pending-exception return after Map allocation. The same upstream change includes related ordering guards in ToReversed; this C4 rule deliberately does not cover NewTypedArraySameType or claim coverage of that third method.


### Allocation-callsite census for this exact source pair

A source-only census found six relevant allocation sites in the pinned target translation unit. Only Filter and Map are currently analyzed by this rule; the other rows are manual source-order review, not detector verdicts.

| Caller | Parent sequence | Fixed sequence | Review boundary |
|---|---|---|---|
| Filter | `NewTypedArray` → `LoadHClass(newArray)` → pending-exception branch | pending-exception branch → `LoadHClass(newArray)` | Candidate in parent; exact analyzer replay finds the use before the guard. |
| Slice | `NewTypedArray` → pending-exception branch → `CopyTypedArrayBuffer` | same | Guard order is visible; rule does not model this copy sink. |
| With | `NewTypedArraySameType` → pending-exception branch → copy/store | same | Guard order is visible; same-type semantics and later store are outside this exception rule. |
| ToSorted | `NewTypedArraySameType` → pending-exception branch → `CopyTypedArrayBuffer` | same | Guard order is visible; sorting/copy semantics are outside this exception rule. |
| Map | `NewTypedArray` → `LoadHClass(newArray)` | pending-exception branch → `LoadHClass(newArray)` | Candidate in parent; exact analyzer replay finds the use before the guard. |
| ToReversed | `NewTypedArraySameType` → input read → pending-exception branch → destination store | pending-exception branch → loop | Unknown: pending-state effects of the input read and empty-loop result handling are unverified. |

The source census does not establish runtime reachability or product impact. It is useful as regression scope only; unmodeled allocation sites remain outside detector coverage.

The helper implementation is byte-identical at the parent and fix revisions. Its NewTypedArray helper can take the species-creation runtime path; the caller must check pending exception before using a result that can be absent on the exceptional path. This is source-level evidence for the guard obligation, not evidence that the condition is attacker-reachable or security-sensitive in a product.

The analyzer is limited to the exact Filter and Map names/signatures; it reports a missing expected caller, conditional definition, parse error, or signature drift as partial/unknown. Reassignment of the allocated GateRef and LoadHClass parameter/arity mismatch also prevent a candidate or suppression. The exact parent/fix target blobs and SHA-256 values are recorded in C4_SOURCE_BINDINGS.json and bound into model version 0.6.1 (digest 3069f778c0869e00b8a8a67429811c62444aa5e5025a3ffe41e792280072147c). The registered Runner replay emits two candidates in the parent (Filter, Map) and none in the fixed source. Both runs remain blocked because parsing is partial. Synthetic controls cover: unguarded use => candidate; exception branch writes Exception() and exits before use => matched/suppressed; unsupported call or exhausted path budget => unknown/no candidate.


### ToReversed exclusion review

The same fix adds a pending-exception branch after `NewTypedArraySameType` in `ToReversed`. In the parent source, the first visible destination write (`FastSetPropertyByIndex(..., newArray, ...)`) follows a `FastGetPropertyByIndex` and a `HasPendingException` branch that exits on pending state. However, the exact effect summary for `FastGetPropertyByIndex` on an already-pending exception is not established, and the zero-length loop path returns `newArray` without the new explicit branch. Whether callers ignore that result while the exception is pending is also unreviewed. This path is therefore **unknown**, not a confirmed missing-guard vulnerability or a safe match; the detector intentionally excludes it until those semantics are source-bound and tested.

The upstream change adds test/moduletest/typedarraymapoverflow/typedarraymapoverflow.js, which recursively calls TypedArray map until stack overflow and catches the exception. This review verified the committed test source and patch only; it did not build or execute the Ark runtime or this regression test. GitHub returned no workflow runs and no commit status checks for fix commit 81ca57487d04ea30cd11c271e86494a4e130f43e, so upstream execution/pass status is unknown.

### Backport recommendation

When applying this upstream correction to an affected fork, branch on `HasPendingException(glue)` immediately after each potentially throwing TypedArray allocation and before reading the result HClass or using the result as a destination. On the exception branch, write `Exception()` to the result and exit. Keep a regression test that asserts exception propagation and normal output; add a separate zero-length `ToReversed` case before extending this detector rule. This is source-level repair guidance only; the affected product versions and runtime behavior remain unverified.

The finding classification remains candidate for a possible product issue. Runtime behavior, crash/corruption/security impact, realistic input control, exact shipped build and release scope remain unknown. No dynamic validation was performed, and validated_vulnerability remains zero.
