# C8: callback exception before result conversion

Updated 2026-10-19. Root cause: a callback may complete abruptly, and code must propagate the pending exception before converting or consuming its result. The disclosed TypedArray Filter case is linked to [OpenHarmony issue I7E0FM](https://gitee.com/openharmony/arkcompiler_ets_runtime/issues/I7E0FM) and [merged PR !4255](https://gitee.com/openharmony/arkcompiler_ets_runtime/pulls/4255). No CVE association was verified.

## Prior capability audit

- `ohscanner.ark.runtime.type_safety` is a first-party detector executed through production M2 CLI, explicitly selected; Catalog keeps it disabled as `research_candidate`.
- The TypedArray type-origin rule is production detector code, but its profile and prior real-source evidence were light AST, without full macro/preprocessor, product build, or independent validation. The pending-exception probe from earlier compiler work was a research rule and did not cover runtime `BuiltinsTypedArray::Filter`.
- C7 exact-source replay is a research script; it does not replace M2. The current C8 reports use exact upstream Git objects, not hand-cut source snippets.
- C++ source parses completely with light AST; `ecma_macros.h` is partial. There is no exact product build, complete dependency/configuration binding, runtime reproduction, or product vulnerability confirmation.

## Disclosed TypedArray Filter pair

Upstream issue I7E0FM and merged PR !4255 pair vulnerable first parent `d6d18548750373cd4e93e9af24eda3e84f6f1b8e` with fixed merge `30571a40879bb2092dcb9ae994d6970c1dfd5fc1`. The vulnerable `BuiltinsTypedArray::Filter` calls the callback and then calls `ToBoolean()` before checking abrupt completion; the fix inserts `RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread)` between them.

Same `light-ast` scope, scanned via the first-party M2 CLI at v0.8.3:

- Vulnerable parent: 1 candidate at Filter line 613; complete run.
- Fixed merge: 0; complete run.
- Current a65 source: 0; complete run, source-state observation only.

Replay commands, using the local pinned object database after explicit source synchronization:

```powershell
$scanner = 'D:\openHarmonyScanner\CyberSecurity-Innovation-Audit-c4'
$objects = 'D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git'
$out = 'D:\openHarmonyScanner\tmp\c8-prod-replay-v083-20261019'
$scope = @('--include','ecmascript/builtins/builtins_typedarray.cpp','--include','ecmascript/ecma_macros.h','--detector','ohscanner.ark.runtime.type_safety')
Push-Location $scanner
python -m src.cli.main ohscan-run --repo-dir $objects --repository openharmony/arkcompiler_ets_runtime --commit d6d18548750373cd4e93e9af24eda3e84f6f1b8e @scope --json-out (Join-Path $out 'typedarray-parent.json') --md-out (Join-Path $out 'typedarray-parent.md')
python -m src.cli.main ohscan-run --repo-dir $objects --repository openharmony/arkcompiler_ets_runtime --commit 30571a40879bb2092dcb9ae994d6970c1dfd5fc1 @scope --json-out (Join-Path $out 'typedarray-fixed.json') --md-out (Join-Path $out 'typedarray-fixed.md')
Pop-Location
```

## Direct-call variant development data

v0.8.1 added assignment provenance after v0.8.0 missed `callResult = JSFunction::Call(info)`. v0.8.2 raised the AST budget from 4096 to 16384. v0.8.3 avoids attributing an earlier use to a later definition and leaves same-loop backward paths unknown. Current exact history replays use complete detector coverage:

- b487 parent: four candidates in Array Filter, Find, FindIndex and Some. b487 fix removes Filter, Find and FindIndex, while Some remains.
- f536 parent/fix: Some candidate 1→0.
- current a65 Array source: zero diagnostics.

The b487/f536 cases were used during development and are not an independent holdout. Their object identities and M2 reports are recorded in `source_identity_manifest.json` and `reports/`.

## Post-freeze wrapper probe and gap

After freezing v0.8.3, I fetched the official Gitee master history into a separate shallow object database and selected the 2022 `BuiltinsArray::Every` wrapper change. Commit `7fb7ec3107e5117c8c00c66fca64d02eea087d38` adds an exception guard after `JSStableArray::HandleEveryOfStable` and before the caller's `callResult.ToBoolean()`. Its parent is `493a73ba63c4a74ce1c67122e55e2a4f1e0d383b`; the diff also changes the helper implementation. The commit message references issue I5XZRO and describes an uncaught-exception crash; no CVE or regression test was verified.

The v0.8.3 M2 replay on both commits emitted five diagnostics in other direct-callback functions, no finding for the Every wrapper path, and partial/blocked coverage for `JSStableArray::HandleEveryOfStable`. This is inconclusive and exposes a missing interprocedural effect summary. The Every source overlaps the development-era Array family, so this sample does not count as an independent holdout without leakage adjudication. Reports and full file identities are preserved.

Replay (separate official history object database, populated before these scan commands):

```powershell
$scanner = 'D:\openHarmonyScanner\CyberSecurity-Innovation-Audit-c4'
$objects = 'D:\openHarmonyScanner\tmp\c-line-callback-holdout-history-20261019.git'
$out = 'D:\openHarmonyScanner\tmp\c8-holdout-every-wrapper-v083-20261019'
$scope = @('--include','ecmascript/builtins/builtins_array.cpp','--include','ecmascript/js_stable_array.cpp','--include','ecmascript/js_stable_array.h','--include','ecmascript/ecma_macros.h','--detector','ohscanner.ark.runtime.type_safety')
Push-Location $scanner
python -m src.cli.main ohscan-run --repo-dir $objects --repository openharmony/arkcompiler_ets_runtime --commit 493a73ba63c4a74ce1c67122e55e2a4f1e0d383b @scope --json-out (Join-Path $out 'parent.json') --md-out (Join-Path $out 'parent.md')
python -m src.cli.main ohscan-run --repo-dir $objects --repository openharmony/arkcompiler_ets_runtime --commit 7fb7ec3107e5117c8c00c66fca64d02eea087d38 @scope --json-out (Join-Path $out 'fixed.json') --md-out (Join-Path $out 'fixed.md')
Pop-Location
```

## Tests, controls and limits

- Focused runtime-exception/unseen detector tests: 19 passed, 2 skipped.
- Full Ark Runtime detector suite on isolated pinned checkout: 124 passed, 1 skipped in 58.40s.
- Exact fixed TypedArray source is a complete fix control. `builtins_number.cpp` returned zero but was not applicable (zero applicable files), so it is not counted as a control. No source-disjoint, complete-coverage same-mechanism safe control or successful independent holdout is established.
- Static findings remain candidates. Component runtime reproduction, product build binding, affected product versions, attacker reachability and product impact are unknown. No precision/recall or zero-error claim is made.

## Historical next operation (before v0.8.5)

Freeze v0.8.4 and select a different Ark Runtime callback API/source family absent from prior tuning. Verify its official issue/PR and regression tests, pin vulnerable/fixed commits and helper dependencies, then run the production M2 pair before changing the detector. Require a parent-only root-cause result with complete relevant coverage, or preserve the miss as evidence. See [checkpoint.json](checkpoint.json) and [coverage_ledger.json](coverage_ledger.json).

## v0.8.4 source-derived helper summary replay

v0.8.4 derives a bounded `may propagate exception` effect from selected C++ helper bodies. It requires a parsed `JSTaggedValue` helper that invokes a configured callback source and then uses a configured macro whose source definition checks `HasPendingException()` and returns the helper result/exception value. The summary is tied to parsed call sites and helper source included in the M2 scope; absent helper definitions produce partial coverage. This is not general interprocedural dataflow or CFG/dominance analysis.

Production-entry results, all at the pinned `light-ast` profile:

- TypedArray exact parent/fix remains 1 candidate -> 0, both complete.
- I5XZRO parent/fix now produces an Every candidate only on the parent (line 719); fixed has no Every diagnostic. Total diagnostics are 6 -> 5, but both M2 runs remain blocked because other Array callback paths cross unsupported compounds. This is a partial root-cause signal, not whole-file validation.
- Direct Array f536 pair produces 2 -> 1 diagnostics; a FindIndex finding remains and both runs are blocked. Do not interpret this as a clean fix result.
- The remaining FindIndex finding maps to the stable-array wrapper call and `ToBoolean()` with no intervening pending-exception check in both source revisions. It is a plausible same-mechanism candidate outside the Some fix scope; its own disclosure/fix relationship has not been established.
- Focused tests: 21 passed, 2 skipped. Full Ark Runtime detector suite on pinned a65 checkout: 126 passed, 1 skipped in 49.38 seconds.

The I5XZRO sample remains non-independent because it shares the Array::Every surface with development-era samples. No complete-coverage real safe control or untouched source-disjoint holdout is established. No product build or dynamic reproduction was run. Exact JSON output is in `reports/v084-*.json`; `checkpoint.json` names the next operation.

Replay commands from the scanner root (source synchronization completed earlier; these commands only read local pinned objects):

```powershell
$out = 'D:\openHarmonyScanner\tmp\c8-prod-replay-v084-20261019'
$scope = @('--include','ecmascript/builtins/builtins_array.cpp','--include','ecmascript/js_stable_array.cpp','--include','ecmascript/js_stable_array.h','--include','ecmascript/ecma_macros.h','--detector','ohscanner.ark.runtime.type_safety')
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\tmp\c-line-callback-holdout-history-20261019.git --repository openharmony/arkcompiler_ets_runtime --commit 493a73ba63c4a74ce1c67122e55e2a4f1e0d383b @scope --json-out (Join-Path $out 'wrapper-parent.json') --md-out (Join-Path $out 'wrapper-parent.md')
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\tmp\c-line-callback-holdout-history-20261019.git --repository openharmony/arkcompiler_ets_runtime --commit 7fb7ec3107e5117c8c00c66fca64d02eea087d38 @scope --json-out (Join-Path $out 'wrapper-fixed.json') --md-out (Join-Path $out 'wrapper-fixed.md')
```

## v0.8.4 FindIndex exact source correction

The pinned Gitee history identifies commit `c333bfc148f0ecc2e0db8c84c821a7560f904906` (2023-09-09), whose parent is `9824afc4c09441f4e504b679c70d9876ba90607c`. Its `builtins_array.cpp` diff adds exactly one relevant line after `JSStableArray::HandleFindIndexOfStable(...)` and before `callResult.ToBoolean()`: `RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread)`. The helper body can return the callback result when the thread has a pending exception.

Production M2 v0.8.4 replay used the same declared four-path `light-ast` scope on both commits. The vulnerable parent produced a FindIndex candidate at line 1030 (two total diagnostics); the fixed revision removed that FindIndex candidate and retained a separate FindLastIndex candidate at line 3314 (one total). Both runs remain blocked with two applicable C++ files partial because other callback paths cross unsupported compounds. The relevant FindIndex path delta is supported; the whole-file family is not passed.

Disclosure status is deliberately separate: c333's commit message is “bugfix of jsproxy” and references issue I7ZZHM. The issue page could not be opened, and neither the commit title nor accessible source proves that I7ZZHM disclosed the FindIndex path. No CVE or product version mapping is verified. This is a real-source regression result, not an independent holdout: FindIndex was already used in earlier Array development scans. No test specifically for the inserted guard was found in the commit diff.

The JSON M2 reports and full tree/blob/source SHA-256 identities are in `reports/v084-findindex-c333-{parent,fixed}.json` and `source_identity_manifest.json`. Earlier candidate pairs `3280366f... -> d2934063...` and `5a8303ac... -> d0dc4354...` both produced zero diagnostics with blocked coverage; they are retained as inconclusive history probes, not passes.

Reproduction from the scanner checkout, using the already-populated local history object database (no fetch during scans):

```powershell
$out = 'D:\openHarmonyScanner\tmp\c8-findindex-c333-v084-20261019'
$scope = @('--include','ecmascript/builtins/builtins_array.cpp','--include','ecmascript/js_stable_array.cpp','--include','ecmascript/js_stable_array.h','--include','ecmascript/ecma_macros.h','--detector','ohscanner.ark.runtime.type_safety')
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\tmp\c-line-callback-holdout-history-20261019.git --repository openharmony/arkcompiler_ets_runtime --commit 9824afc4c09441f4e504b679c70d9876ba90607c @scope --json-out (Join-Path $out 'findindex-parent.json') --md-out (Join-Path $out 'findindex-parent.md')
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\tmp\c-line-callback-holdout-history-20261019.git --repository openharmony/arkcompiler_ets_runtime --commit c333bfc148f0ecc2e0db8c84c821a7560f904906 @scope --json-out (Join-Path $out 'findindex-fixed.json') --md-out (Join-Path $out 'findindex-fixed.md')
```


## v0.8.5 NewRuntimeCallInfo exception guard

The selected source family is the exact upstream pair `11c5ad59240da5603504821d674c499e3cbff75a` → `f596e410db3ab90a4706a248cf935b135a62490a`. In the parent, `NewRuntimeCallInfo` can return null after `DoStackOverflowCheck` sets a pending RangeError. Two `JSIterator::IteratorNext` paths then call `info->SetCallArg(...)`. The fix inserts `RETURN_VALUE_IF_ABRUPT_COMPLETION(thread, undefined)` before both pointer uses. The fix commit references I7K7L6, but the issue contents, security classification, CVE, and product release mapping remain unverified. Full tree and blob identities and SHA-256 values are in `callinfo_source_identity.json`.

The production M2 `light-ast` replay on the exact same two-path scope reports two candidates at `js_iterator.cpp:142,163` on the parent and zero on the fix. Both runs complete and fully analyze the applicable C++ translation unit (about 0.066 seconds each). `ecma_macros.h` is in scope but partial parsing/no macro expansion remains a limitation. At v0.8.4, the same pair produced 0→0, complete for the C++ file, showing the earlier semantic coverage gap.

An untouched source-disjoint `builtins_string.cpp` variant in the same f596 remediation batch produces 2→0 candidates (about 0.371/0.388 seconds); this was not used to tune the rule, but it is a correlated variant rather than an independent historical disclosure. The v0.8.5 TypedArray regression remains 1→0 complete. The Every regression has limitations and total findings 6→7, so it is not passed. Focused tests: 25 passed, 2 skipped. Full Ark Runtime detector suite: 130 passed, 1 skipped in 45.61 seconds.

The detector is bounded to a parsed direct `EcmaRuntimeCallInfo*` initializer from `NewRuntimeCallInfo`, a same-function binding to configured `SetCallArg`, and a verified same-thread exception guard. It does not prove arbitrary alias or reassignment flows, general CFG dominance, preprocessor behavior, or product impact. No separate-commit historical sample, complete real safe control, dynamic component reproduction, or product build association exists. Findings are candidates; the rule remains research-candidate/disabled by default.

Replay commands (history objects were fetched explicitly before scans; these commands do not fetch):

```powershell
$out = 'D:\openHarmonyScanner\tmp\c8-newruntime-callinfo-replay-v085-20261019'
$scope = @('--include','ecmascript/js_iterator.cpp','--include','ecmascript/ecma_macros.h','--detector','ohscanner.ark.runtime.type_safety')
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\tmp\c-line-callback-holdout-history-20261019.git --repository openharmony/arkcompiler_ets_runtime --commit 11c5ad59240da5603504821d674c499e3cbff75a @scope --json-out (Join-Path $out 'iterator-parent.json') --md-out (Join-Path $out 'iterator-parent.md')
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\tmp\c-line-callback-holdout-history-20261019.git --repository openharmony/arkcompiler_ets_runtime --commit f596e410db3ab90a4706a248cf935b135a62490a @scope --json-out (Join-Path $out 'iterator-fixed.json') --md-out (Join-Path $out 'iterator-fixed.md')
```

## v0.8.5 follow-up (completed and superseded in v0.8.6)

Inspect the pinned Ark Runtime history for a source-disjoint, separate-commit `NewRuntimeCallInfo`/pending-exception fix with a linked regression test. Record its exact parent/fix before changing the detector, then run production M2 on an untouched scope. Require complete applicable coverage, a vulnerable-only root-cause candidate, a clean fixed revision, and a real safe control; otherwise preserve the miss. Current checkpoint and case ledger: [checkpoint.json](checkpoint.json), [coverage_ledger.json](coverage_ledger.json).


## v0.8.6 source-validated macro guard contract

The v0.8.5 `RETURN_REJECT_PROMISE_IF_ABRUPT` path showed that two unchanged AsyncFromSyncIterator pointer uses were already protected by a macro, but the model did not recognize its contract. The macro handles `HasPendingException()` on the same thread, clears that state for promise rejection, and returns the promise from inside the pending-exception branch. v0.8.6 only accepts this guard when the scoped macro source has that branch and return together; a negative test with the return outside the branch stays partial. The detector is now v0.8.6 / semantic-contract-v8.

The exact separate upstream commit pair `811daec3dc48a2ba4426b9c6eea7bcc1ee7ab315` → `3bf1a3cee91252507d02ebcd0ef332d61bbad342` references issue IB40SU. On the untouched `builtins_async_from_sync_iterator.cpp` scope, final M2 produces four call-info findings on the parent at lines 93, 122, 170, 200, and zero on the fix. Both runs complete with full applicable C++ file coverage, about 0.056 seconds each. The source diff inserts guards at all four sites. This pair was used to refine the guard contract and is development evidence, not a holdout. IB40SU details, security classification, CVE and product version mapping remain unverified.

The exact I7K7L6 pair remains 2→0 with complete applicable C++ coverage. TypedArray Filter remains 1→0 complete. A separate RuntimeInstanceofByHandler patch (I7SDBG) changes pending-exception returns from false to the Exception sentinel, but its production M2 scope is partial due an unrelated cross-compound pointer path in `RuntimeOptSuperCall`; its 0→0 result is unknown, not a pass. A SharedArray FindIndex probe is also partial in both revisions and produces no interpretable result. A same-batch AsyncGeneratorResolve guard uses `StackCheck::NO`; it produces 0→0 and is not a positive call-info-construction case. These reports and source identities are retained.

Focused tests after macro integration: 27 passed, 2 skipped; full Ark Runtime suite: 123 passed, 10 skipped in 46.83 seconds. The earlier intermediate 6→2 report exposed the two macro-protected residuals; final v0.8.6 output is 4→0. Reports are `reports/v086-*.json`; exact Git tree/blob and file SHA-256 identities are in `exception_history_source_identity.json`. No separate-commit untouched complete holdout or complete real safe control has passed. Dynamic component reproduction and product binding remain unexecuted/unknown.

Reproduce the exact development pair from the scanner checkout using the already-synced local object database (no scan-time fetch):

```powershell
$out = 'D:\openHarmonyScanner\tmp\c8-final-v086-20261019'
$scope = @('--include','ecmascript/builtins/builtins_async_from_sync_iterator.cpp','--include','ecmascript/ecma_macros.h','--detector','ohscanner.ark.runtime.type_safety')
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\tmp\c-line-callback-holdout-history-20261019.git --repository openharmony/arkcompiler_ets_runtime --commit 811daec3dc48a2ba4426b9c6eea7bcc1ee7ab315 @scope --json-out (Join-Path $out 'asyncfromsync-parent.json') --md-out (Join-Path $out 'asyncfromsync-parent.md')
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\tmp\c-line-callback-holdout-history-20261019.git --repository openharmony/arkcompiler_ets_runtime --commit 3bf1a3cee91252507d02ebcd0ef332d61bbad342 @scope --json-out (Join-Path $out 'asyncfromsync-fixed.json') --md-out (Join-Path $out 'asyncfromsync-fixed.md')
```

## Next operation

Freeze v0.8.6. Inspect the exact I7SDBG `RuntimeOptSuperCall` pointer-flow boundary to identify why whole-header analysis is partial; add bounded CFG support only if its control flow can be represented without upgrading unknown paths. Then select a new separate-commit, source-disjoint exception-propagation pair before tuning, and run the production M2 parent/fix with complete applicable coverage. Current machine-readable handoff: [checkpoint.json](checkpoint.json), [coverage_ledger.json](coverage_ledger.json), [exception_history_source_identity.json](exception_history_source_identity.json).


## v0.8.7 bounded ancestor guard dominance

I7SDBG M2 in v0.8.6 was partial because `RuntimeOptSuperCall` creates `EcmaRuntimeCallInfo` in the function compound, checks the same thread immediately after construction, then dereferences the pointer inside a later loop body. v0.8.7 adds a bounded ancestor-compound order check for this call-info rule: a verified sequential guard in the common outer compound may protect a nested sink. It does not claim arbitrary CFG, labels/gotos, general exception effects, or whole-program dominance. New controls check both a guarded and unguarded pointer use inside a loop.

Production M2 on exact I7SDBG parent/fix (`905f840797ff27839d9d984aee36c0f8a773adb2` → `c73261dd8452524fa707c0b3c768e899786d22f2`) now completes with 0→0 call-info findings and complete applicable header coverage. This result only validates the pointer-dereference rule: the source patch changes `RETURN_VALUE_IF_ABRUPT_COMPLETION(thread, JSTaggedValue(false))` to `RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread)`, and v0.8.7 does not detect that separate normal-value versus exception-sentinel semantic bug. Keep it tracked as unmodeled, not passed.

Regression: I7K7L6 remains 2→0 complete; IB40SU remains 4→0 complete but is development data; TypedArray Filter remains 1→0 complete. Focused tests: 29 passed, 2 skipped; full Ark Runtime suite: 125 passed, 10 skipped in 39.15 seconds. Exact M2 reports: `reports/v087-*.json`.

## Next operation

Freeze v0.8.7. Select an untouched source-disjoint upstream exception-sentinel or call-info parent/fix pair before tuning that family. Then build a source-derived return/effect contract, use I7SDBG as development data, and validate on a separate untouched pair plus real fixed/safe controls with complete M2 coverage. Current checkpoint and coverage ledger describe the evidence boundary.


## IAO7GO compiler exception lowering baseline (v0.8.7)

Official Gitee issue [IAO7GO](https://gitee.com/openharmony/arkcompiler_ets_runtime/issues/IAO7GO) is marked Bug/Done and supplies an AOT `Reflect.apply` reproducer plus compiler/run flags. It does not establish a CVE or security classification. The exact !9061 mainline pair is first parent `3fc1d0b960e0b1bb5bfe1aad8066bb8c9aa99724` → merge `18d8532a200d0c9aa64a6dfe2b146dc841b52bf8`; the merge's second parent is patch `f253b45f59d7a8444fed2e7f271e894f106f8117`. The patch replaces a comparison of the returned Gate value with `ExceptionConstant()` by a `HasPendingException(glue_)` check. It adds an AOT throw regression in `test/aottest/throw/throw.ts`. Full tree/blob/source SHA-256 identity is in `iao7go_source_identity.json`.

Production M2 v0.8.7 with `light-ast`, scoped to `ecmascript/compiler/native_inline_lowering.cpp`, reports 0 diagnostics on both parent and fix, but the detector is blocked with `not_applicable`, zero applicable files. The C++ translation unit parses completely. This is a selector/model coverage miss, not a 0→0 pass. Reports: `reports/v087-iao7go-reflect-apply-mainline-parent.json` and `reports/v087-iao7go-reflect-apply-mainline-fixed.json`. The issue's AOT test was not built or run; no product build or runtime evidence is available.

Replay from scanner checkout (objects were already present in the pinned local Git store; the command does not fetch):

```powershell
$repo = 'D:\\openHarmonyScanner\\tmp\\c-line-callback-holdout-history-20261019.git'
$scope = @('--include','ecmascript/compiler/native_inline_lowering.cpp','--detector','ohscanner.ark.runtime.type_safety')
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit 3fc1d0b960e0b1bb5bfe1aad8066bb8c9aa99724 @scope --json-out research/experiments/ark_runtime/c8_20261018/reports/v087-iao7go-reflect-apply-mainline-parent.json --md-out research/experiments/ark_runtime/c8_20261018/reports/v087-iao7go-reflect-apply-mainline-parent.md
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit 18d8532a200d0c9aa64a6dfe2b146dc841b52bf8 @scope --json-out research/experiments/ark_runtime/c8_20261018/reports/v087-iao7go-reflect-apply-mainline-fixed.json --md-out research/experiments/ark_runtime/c8_20261018/reports/v087-iao7go-reflect-apply-mainline-fixed.md
```


## v0.8.8 TypedArray Map store-type origin (not admitted)

The source candidate is Ark Runtime `BuiltinsTypedArrayStubBuilder::Map`: the vulnerable source constructs `newArray` with `jsType`, then supplies `jsType` as the `FastSetPropertyByIndex` type token. The !11130 fix samples `GetObjectType(LoadHClass(newArray))` and supplies `newArrayType`. The new semantic selector admits functions containing typed-array creation plus indexed property store; the sink model resolves destination and type-token argument positions and accepts renamed locals.

The exact local-object parent/fix pair is `c4623e514d5648aa0f7fe33631c8379b31cba7c4` → `6627179cbf6f8d40d1adfcf5c3c686b902f42419`. Official April 2025 OpenHarmony disclosure confirms CVE-2025-24304 as an Ark Runtime out-of-bounds write affecting v4.1 and 5.0.2 release lines. The bulletin links maintenance cherry-pick batches; it does not prove a one-to-one CVE mapping to mainline !11130. !11130's source change is mechanism-consistent and adds a TypedArray Map regression, while !11279 calls two changes vulnerability fixes. Keep CVE-to-!11130 as unverified association.

Production CLI v0.8.7 missed the Map flow on both pair members; its only finding was the separate Filter candidate under the same generic TypeOrigin rule. v0.8.8 selects the generic creation-to-indexed-store flow and models the target and token argument origins. Source inspection shows `NewTypedArray` can take a runtime species slow path, and its fast path sets a typed-array HClass using the source type token. `FastSetPropertyByIndex` consumes the type token to choose the write interpretation. In `Map`, result allocation precedes user callback dispatch; the callback receives the source `thisValue`, while the fresh result is not included in the call arguments. The analyzer now retains a fresh result's creation relationship across unknown calls only while the result is not passed directly/nested to an unknown call and not placed in the recognized `JSCallArgs.callThisArg3WithReturnArgs` list. Source type snapshots and guards are still invalidated. Escaped results remain unknown.

The exact production CLI pair now reports a Map candidate at line 2665 on the vulnerable parent and no Map candidate on the fixed revision; the separate Filter candidate under the same generic TypeOrigin rule remains on both. Runs are 0.599s and 0.585s, but both are blocked because the full selected TU parses partial outside Map. This is an exact-source root-cause distinction, not a full-file coverage pass. An earlier broader attempt lacked escape tracking and was withdrawn after three safety-control regressions; the current narrow model passes those controls and a new `JSCallArgs` escape control. Focused tests: 51 passed, 2 skipped; full Ark Runtime suite: 128 passed, 10 skipped.

The fixing commit directly references upstream issue IBP5J6. Official 5.0.3 PR !11279 describes !11130 and !10809 as two vulnerability fixes, strengthening the security relevance of !11130. The exact mapping from CVE-2025-24304 to this individual mainline fix is still unverified because the bulletin points to maintenance-branch aggregate PRs. Synthetic renamed/safe/escape controls are development data; no independent historical holdout has passed. No dynamic reproduction or product build/impact evidence exists. Rule remains candidate-only and disabled by default.

Replay commands (official source objects were explicitly synced to a local bare Git database; these scans do not fetch):

```powershell
$out = 'D:\openHarmonyScanner\tmp\c8-cve-2025-24304-replay-v088-20261019'
$repo = 'D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git'
$scope = @('--include','ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp','--detector','ohscanner.ark.runtime.type_safety')
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit c4623e514d5648aa0f7fe33631c8379b31cba7c4 @scope --json-out (Join-Path $out 'map-parent.json') --md-out (Join-Path $out 'map-parent.md')
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit 6627179cbf6f8d40d1adfcf5c3c686b902f42419 @scope --json-out (Join-Path $out 'map-fixed.json') --md-out (Join-Path $out 'map-fixed.md')
```

Exact tree/blob identities: `cve_2025_24304_map_source_identity.json`; case dimensions and unresolved evidence: `coverage_ledger.json`; checkpoint gives exact next action.

### Independent exception-propagation history (not a CVE claim)

Pinned issue IC7B8Q and PR !11684 add a pending-exception branch after `NewTypedArray` in `Map` before reading the result HClass. The same change adds a recursive stack-exhaustion regression. Production CLI v0.8.8 reports the allocation-exception rule on the parent Map path at line 2656 (and a separate Filter path at 1487), then zero findings on the fix. Both full-file runs are blocked by partial parse outside these functions; the upstream runtime test was not built/run. No CVE or product association was verified. This is an independent historical candidate for the exception-propagation detector. The same parent/fix pair is reserved as a safe variant holdout for the type-origin rule: both revisions preserve `newArrayType` derived from the result object and neither reports a Map type-origin candidate. It is a safe sample, not an independent vulnerable positive. Full-file parsing remains blocked. !10809 was inspected and excluded: it fixes NewTaggedSubArray HClass/prototype selection and a species fallback, a distinct mechanism. Exact pair and file identities: `typedarray_map_exception_holdout_identity.json`; reports: `reports/v088-ic7b8q-map-*.json`. Replay from the scanner checkout without fetching:

```powershell
$out = 'D:\openHarmonyScanner	mp\c8-independent-typedarraymap-overflow-20261019'
$repo = 'D:\openHarmonyScanner	mp\c-line-callback-holdout-history-20261019.git'
$scope = @('--include','ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp','--detector','ohscanner.ark.runtime.type_safety')
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit bcf67a5df41bcf37b94d848812e54884f6bedb95 @scope --json-out (Join-Path $out 'map-overflow-parent.json') --md-out (Join-Path $out 'map-overflow-parent.md')
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit b362fab4f80c7466b1a33d882fa65b828d952712 @scope --json-out (Join-Path $out 'map-overflow-fixed.json') --md-out (Join-Path $out 'map-overflow-fixed.md')
```

## v0.8.9 TypedArray Map replay and current gate

The v0.8.9 semantic wording now describes the modeled operation as a creation that may change runtime type, including species/fallback behavior, instead of implying that species is the only type-changing route. Production CLI replay on the exact !11130 parent/fix remains Map TypeOrigin 1→0 (vulnerable parent line 2665; no fixed Map finding). A Filter TypeOrigin candidate under the same generic rule remains on both revisions, so total diagnostics are 2→1; its species-changing path is unresolved and it is not an unrelated clean finding. The independent !11684 pair is TypeOrigin 0→0; it is a real safe variant control, while its parent still has two exception-guard candidates. All four whole-file scans remain `blocked` with partial parsing, at about 0.58–0.59 seconds each.

Reports are in `reports/v089-*.json` and `.md`. The full Ark Runtime test run after the wording/version update produced 127 passed, 1 failed, 10 skipped. The failure is in the existing C4 dependency-manifest test: it expects `unresolved_dependency:ACTUAL_INCLUDE_CLOSURE`, while the current C4 manifest reports four other unresolved items (`C1_PRODUCT_BUILD_PROFILE`, `C2_CASE_MATRIX`, `GENERATED_BUILD_INPUTS`, `PARSER_BINARY_IDENTITY`). No C8 test failed; the C4-owned test was left untouched. Focused C8-related regression was 74 passed, 2 skipped.

Production admission remains blocked by partial whole-TU parse, no independent vulnerable positive for the type-origin family, and missing product build/runtime evidence. The independent safe variant does not fill the positive holdout requirement. Parser findings and a narrowly scoped integration request are recorded in `parser-integration-request.md`. Next executable action: search the pinned local Ark history for a separate vulnerable indexed-storage/type-origin patch outside !11130 and the previously used Filter history; preserve the positive holdout gap if none is found.

### v0.8.9 replay commands

Run from `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit-c4` with the local Python environment. These commands read pinned objects only and do not fetch:

```powershell
$out = 'D:\openHarmonyScanner\tmp\c8-typedarray-type-origin-v089-20261019'
$scope = @('--include','ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp','--detector','ohscanner.ark.runtime.type_safety')
$repo = 'D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git'
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit c4623e514d5648aa0f7fe33631c8379b31cba7c4 @scope --json-out (Join-Path $out 'cve-map-parent.json') --md-out (Join-Path $out 'cve-map-parent.md')
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit 6627179cbf6f8d40d1adfcf5c3c686b902f42419 @scope --json-out (Join-Path $out 'cve-map-fixed.json') --md-out (Join-Path $out 'cve-map-fixed.md')
$repo = 'D:\openHarmonyScanner\tmp\c-line-callback-holdout-history-20261019.git'
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit bcf67a5df41bcf37b94d848812e54884f6bedb95 @scope --json-out (Join-Path $out 'holdout-safe-parent.json') --md-out (Join-Path $out 'holdout-safe-parent.md')
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit b362fab4f80c7466b1a33d882fa65b828d952712 @scope --json-out (Join-Path $out 'holdout-safe-fixed.json') --md-out (Join-Path $out 'holdout-safe-fixed.md')
```

## I7KZJ7 typed-array byte-length overflow prototype

The local patch pair `087449d3d657d081611cf1bf4c731ff048748812` → `1b0ac0aa076b91d92b5d5aba91e92bc6c2a06c50` changes the `CreateFromTypedArray` allocation-size product from 32-bit to 64-bit arithmetic. The v0.8.10 candidate rule tracks a typed product into an allocator and a copy loop bounded by an operand. Its implementation uses a lexically bounded function-body scan after the production source index confirms complete C++ AST parsing; the rule deliberately reports partial coverage because it cannot prove C++ range semantics, macro expansion, branch dominance, or all call/alias paths. Unit controls cover variable renaming, widening before multiplication, widening only the destination, and unrelated products.

Matched `ohscan-run` v0.8.10 replays now produce one candidate on the exact parent (line 237; allocation line 255; factor-bounded write loop line 275) and zero on the exact fixed merge. Both have complete source AST parsing but `blocked` detector status and partial file analysis. The parent candidate and fixed-side zero are therefore a root-specific signal, not a complete coverage or safety pass. A separate real !4688 constructor-length pair produces zero diagnostics on both sides; this is an unrelated integer-conversion control, not an independent vulnerable positive. Its exact tree/blob/source hashes are in `i4688_unrelated_control_identity.json`. Unit controls are development samples. No independent vulnerable same-mechanism holdout has been validated. No dynamic test, security bulletin, release mapping, or product build was verified; the I7KZJ7 issue page remains inaccessible in this pass.

The same source history contains a safe `CreateSharedFromTypedArray` variant in !8451: its product widens before multiplying and flows into `AllocateSendableArrayBuffer` followed by an `elementLength`-bounded copy loop. The production CLI reports zero diagnostics, and the local flow model records the product as non-overflowing. This sample prompted adding the sendable allocator to the modeled sinks, so it is a development control rather than an independent holdout. Exact identity and report: `sendable_safe_variant_identity.json` and `reports/sendable-safe-variant-v0.8.10.json`.

Regression after this addition: the focused C8 detector suites report 38 passed, 2 skipped. The full Ark Runtime suite reports 133 passed, 1 failed, 10 skipped in 69.37 seconds. The sole failure is the C4-owned dependency-manifest assertion: it expected `ACTUAL_INCLUDE_CLOSURE`, while the current manifest verifier reports `C1_PRODUCT_BUILD_PROFILE`, `C2_CASE_MATRIX`, and `PARSER_BINARY_IDENTITY`. The C4-owned test and manifest were left unchanged.

The first parent CLI attempts exposed a Windows access violation in the original Tree-sitter child-node walk. The rule was changed to scan source text inside AST-complete function boundaries and to snapshot diagnostic offsets as plain values. Subsequent parent and fixed CLI runs completed. Preserved crash and successful run logs are in `reports/i7kzj7-parent-parser-crash-initial.log` and `reports/i7kzj7-parent-final-cli.log`. Exact reports are `reports/i7kzj7-production-parent-v0.8.10.json` and `reports/i7kzj7-production-fixed-v0.8.10.json`.

Replay from the scanner checkout; source access is local-only and scanning does not fetch:

```powershell
$out = 'D:\openHarmonyScanner\tmp\c8-typedarray-byte-length-overflow-I7KZJ7-v010-20261019'
$repo = 'D:\openHarmonyScanner\tmp\c-line-callback-holdout-history-20261019.git'
$scope = @('--include','ecmascript/base/typed_array_helper.cpp','--detector','ohscanner.ark.runtime.type_safety')
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit 087449d3d657d081611cf1bf4c731ff048748812 @scope --json-out (Join-Path $out 'typedarray-byte-length-parent.json') --md-out (Join-Path $out 'typedarray-byte-length-parent.md')
python -m src.cli.main ohscan-run --repo-dir $repo --repository openharmony/arkcompiler_ets_runtime --commit 1b0ac0aa076b91d92b5d5aba91e92bc6c2a06c50 @scope --json-out (Join-Path $out 'typedarray-byte-length-fixed.json') --md-out (Join-Path $out 'typedarray-byte-length-fixed.md')
```

The !4245 follow-up is now verified through official Gitee `refs/pull/4245/head` (commit `3be786861f4f90092ce88741882ce8549de4dd43`). Its diff adjusts `CreateFromArrayBuffer` length underflow and signed/unsigned handling, a distinct mechanism. Both parent and fix scans still report the unchanged `CreateFromTypedArray` I7KZJ7 candidate at line 230; this is explicitly excluded as a !4245 detection result. Reports and rationale are in `pr4245_control_audit_identity.json` and `reports/pr4245-*-source-replay-v0.8.10.json`.


An unseen !7532 `CreateSharedFromTypedArray` refactor was replayed after rule logic was frozen. Source inspection confirms a widened `uint64_t` product, buffer allocation, and element-count bounded copy flow. Production CLI produced 0 findings on both refactor parent and refactor commit, with AST parse complete but detector analysis blocked/partial on both. Preserve this as a safe structural holdout, not a complete safety pass. Identity: `i7kzj7_refactor_safe_variant_identity.json`; reports: `reports/i7kzj7-refactor-*.json`. The remaining concrete operation is to inspect pinned Ark history for a distinct vulnerable product→allocation→copy fix outside `CreateFromTypedArray`, then run its exact parent/fix and a new unseen safe control through `ohscan-run` without changing the rule first.


### Adjacent historical cases screened (2026-10-19)

!4688 changes TypedArray constructor length conversion from `int32_t` to `uint32_t`; its added oversized-length test expects RangeError. It does not establish memory corruption and is not the byte-product overflow root. !10468 widens DataView/Atomics index handling and adds a large-index RangeError test; source/test review has not established an out-of-bounds access. Production v0.8.10 baselines returned 0 diagnostics on both sides for each pair, but analysis was blocked/partial and these are not safety passes. Both cases and exact source identities are in `typedarray_adjacent_history_screen_20261019.json` and the coverage ledger. Next work returns to the higher-priority Map type-origin pair for a v0.8.10 matched replay.


### TypeOrigin replay on v0.8.10 (2026-10-19)

Current production CLI replay confirms !11130 Map TypeOrigin 1→0: the vulnerable parent has a Map candidate at line 2665 and a separate Filter candidate at line 1491; the fixed merge retains only Filter. The independent !11684 pair has no TypeOrigin findings on either side. Its parent does have two separate exception-guard candidates (Filter and Map), removed by the exception patch; these are not TypeOrigin findings. Earlier turn commentary that called them Map type-origin findings was incorrect. All four scans are blocked because the full translation unit parses partial. The fixed !11130 commit was not present in the callback-history DB; it was verified and scanned from the separate local pinned `cve-2025-arkruntime-official.git` DB, with no scan-time fetch. Reports and summarized identities are in `typeorigin_v0810_replay_20261019.json`. Focused tests: 40 passed, 3 skipped.


The v0.8.10 parent report records light-parser missing nodes at lines 3354 and 3667. Source review bound line 3354 to the `BRANCH` macro defined in `ecmascript/compiler/circuit_builder.h`, and line 3667 to `BUILTIN_COMPILER_TYPED_ARRAY_TYPES` defined in `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.h`; both sites are outside Map and Filter. This explains the parser limitation, but macro definitions alone do not prove the exact product preprocessing context. Header blob/source identities are stored in `typeorigin_v0810_replay_20261019.json`.


### Official OpenHarmony 5.0.2 Map lineage replay (2026-10-19)

The official `OpenHarmony-v5.0.2-Release` manifest tag pins Ark Runtime at `8b615647dc4af6f4b572fca50bfbd4d1b91ecad4`. This exact source revision is an ancestor of release-branch commit `2654cd98e39479b343ee11abf3a65b74e8e9d957`, whose parent is `5817985af4207505309793a5c95468053b876f80` and whose change derives the indexed access type token from the newly allocated Map result. PR !11279 source diff matches this repair; upstream PR subject and issue key refer to TypedArray Map/IBP5J6. The April bulletin confirms CVE-2025-24304 affects Ark Runtime 5.0.2 and classifies an out-of-bounds write, but does not give a patch URL; exact CVE-to-this-root attribution remains unproven. Identities: `v502_map_source_identity.json`.

Production v0.8.10 CLI replay on the exact official manifest pin emitted four TypeOrigin candidates, including Map; the release fix emitted three candidates, with Map removed. Remaining candidates are Filter, With and ToReversed. The root-specific signal is 1→0, while aggregate findings are 4→3. The release pin report says complete parsing; the fix report is blocked/partial. No matching product compile profile or macro-expanded TU, dynamic test, or shipped product build was verified. This is real-source static evidence at candidate status; production admission remains blocked pending compile/profile binding, review of fixed-side candidates, and an independent vulnerable positive holdout. Exact reports: `reports/typeorigin-v0810-v502-release-pin.json` and `reports/typeorigin-v0810-v502-map-fix.json`.

Next executable operation: bind the exact product compile action and transitive include closure for both commits, preprocess the TU and verify macro expansion, then rerun the same production scope. If those build artifacts are unavailable, record the missing artifact identities and review the three fixed-side candidates against source-grounded controls.


### Fixed-side TypeOrigin residual review (2026-10-19)

The official 5.0.2 fixed source retains TypeOrigin candidates in Filter, With and ToReversed. Source review found that all pass a source-derived type token to an indexed operation on a newly created TypedArray, while `NewTypedArray` can call `TypedArraySpeciesCreate` on fallback. Filter allocates after callback execution; With has no HasConstructor fast-path guard; ToReversed checks HasConstructor but that alone does not prove every helper fast-path condition. These are unresolved same-family candidates, not unrelated findings and not confirmed vulnerabilities. The Map-specific patch removes the Map candidate, but the generalized root-family fixed-version gate fails until the three residuals are resolved. Details: `v502_residual_candidates_triage.json`.

The available C1 profile is not an exact-source match: it pins Ark Runtime `a65a2853...` with a different target-file SHA-256. No preprocessing/build claim is made for the 5.0.2 pair. Next operation: bind a compile profile to both exact commits, then run upstream species behavior controls on an exact-source runtime and resolve each residual candidate without method-name suppression.

Current-checkout regression after this candidate triage: `python -m pytest tests/detectors/ark_runtime/test_type_origin.py tests/detectors/ark_runtime/test_unseen_detector.py -q` returned 29 passed, 2 skipped (0.16s). This validates the existing unit/control suite only; the detector implementation was unchanged and no exact-source dynamic scenario was run.


### Official 5.0.3 backport replay (2026-10-19)

The production CLI replayed official PR !11279 parent `1eea202527c76b4ee171efe7597ebccecb1ee027` and merge `acb7197ca9ce52248f3842012cb8c483158655a8` on the same single-file scope. Map TypeOrigin is 1→0 (parent line 2698); total candidates are 4→3, with Filter/With/ToReversed remaining. Parent scan status is completed; fixed scan is completed_with_limitations and detector-blocked/partial. The parent/fixed target-file blobs are identical to the 5.0.2 pair, so this is a branch-backport provenance check, not an independent holdout. Reports are `reports/typeorigin-v0810-v503-pr11279-parent.json` and `reports/typeorigin-v0810-v503-pr11279-fixed.json`.

Official PR !11279 says two vulnerability fixes were cherry-picked to 5.0.3 and names !11130 Map and !10809. The April bulletin lists Ark Runtime out-of-bounds-write CVE-2025-24304 and affected 5.0.2. This makes CVE-2025-24304 ↔ !11130 a strong inference, but no direct source gives a one-to-one CVE mapping; the ledger retains that uncertainty.


C-line delivery copy of the machine-readable ledger and checkpoint: `research/deliveries/c-line/`. Keep that directory synchronized at each handoff; detailed scan evidence remains in this experiment directory.

### Official TypedArray Filter direct parent/fix replay (2026-10-19)

Verified PR !11196 (`IBS5YG`) and corrected an earlier pairing mistake: commit `857ff17` was not the fix's direct parent. The fix commit `919e4fbb011f610427e788889083fa8e28d2f951` has direct parent `2ea501258ab4155826b64f01b499b43d1911e0e2`. The parent source creates Filter's result with `NewTypedArray(..., thisValue, arrayType, ...)` and writes through `StoreTypedArrayElement(..., arrayType)`; the fix reads the result HClass and passes the result-derived type token. Production `ohscan-run` v0.8.10 on the exact pair reports 1 candidate → 0, under the same one-file light-AST scope. Both reports are blocked/partial due incomplete parsing and missing product compile/dependency binding. This supports a real source-level root-cause signal; it does not establish runtime or product impact.

The upstream PR adds a species/prototype regression case, but this workspace did not build or execute it. !11130 Map remains a known same-mechanism development case, not a blind holdout. !11684 is a separate historical control whose TypeOrigin scan had zero findings on both commits, but that file scan was partial/blocked, so it is not a clean safe pass. No complete independent unrelated control or untouched positive holdout exists for this family.

The official current master head `d1a58d59166777e16574ceed64c15f0b2f44a76c` produced 0 findings with blocked/partial coverage. The active Catalog factory is the source-identity-independent semantic detector, which does analyze the file; TypeOrigin observations remain unresolved under the partial AST. An older limitation string incorrectly named an exact-binding adapter and has since been corrected. This result is not evidence of safety and must not be generalized to current Ark Runtime.

Next executable operation: bind exact compile actions and transitive include/macro closure for `2ea501...` and `919e4f...`, preprocess both target translation units, then build an isolated runtime and execute the upstream Filter regression plus a safe species control. Preserve the rule as research candidate until parsing, controls, and an untouched same-mechanism positive are adequately supported.

### TypeOrigin API scope follow-up (2026-10-19)

The production rule/model now accepts the reviewed `LoadHClass(glue, object)` graph-read form, two-argument `NewObjectStubBuilder`/`BuiltinsArrayStubBuilder` constructors, and the `GetCurrentGlobalEnv()` accessor. Five declaration/header identities from C1 commit `a65a285...` are bound in `RuntimeTypeModel.api_overload_evidence`; they support the modeled API semantics and do not select a vulnerability finding. Positive mismatch and correct-result-origin regressions cover the overloads. The direct !11196 pair remains 1→0. Current a65 and official master still produce 0 diagnostics with partial/blocked analysis and unresolved TypeOrigin observations.

A prior limitation label referred to an exact-binding adapter, but the active Catalog factory is the source-identity-independent semantic detector. The stale label is corrected to `partial_scope_routed_through_semantic_selector`, and a unit test protects that wording. This correction also changes the interpretation of the master replay: the semantic analyzer reaches the source, but cannot resolve some target/type-origin facts. The zero count is unknown, not a safety pass. The focused suite (TypeOrigin, exception, unseen, and parser-owner controls) reports 72 passed, 4 skipped.

Next operation: inspect TypeOrigin graph states for the result object at a65 Filter lines 1542–1563 and master Filter lines 1498–1507. Determine where identity is lost across the exception branch, label binding, loop header and backedge; add only source-supported graph/dataflow semantics and retest the exact parent/fix, a65, and master.


### Glue-aware 图查询语义复核（2026-10-19）

针对 a65 Filter 的 `IsEcmaObject(glue, thisValue)` 会清除来源事实的问题，核对了 a65 的头文件、内联转发和 `CircuitBuilder`/`StubBuilder` 实现，加入七个二参数 graph-read overload 的精确签名与 source identity。它们只保留 GateRef 参数来源，不代表对象类型跨 JS callback 稳定。错误 arity 单测继续产出 unknown。

生产 `ohscan-run` 在同一 light-AST 单文件 scope 重放 !11196 直接 parent/fix、产品快照 a65 和官方 master：parent 1 candidate（Filter:1498）→ fix 0；a65 0；master 0。四份报告均 completed-with-limitations，目标 TU 均 partial，运行均 blocked。a65/master 的 0 不是安全结果；仍有 unresolved TypeOrigin，a65 还有 unsupported host expression effects。聚焦回归 74 passed、4 skipped。未构建/运行上游 species 回归，未验证产品影响。

报告：`reports/typeorigin-v0810-reviewed-glue-i11196-parent.json`、`...-fix.json`、`typeorigin-v0810-reviewed-glue-a65.json`、`...-master.json`。精确下一操作见 `checkpoint.json`：定位 a65/master Filter 中使来源变 unknown 的剩余调用/分支，仅补 source-verified signature，再复放四提交并 triage fixed-side candidates。


### a65 Filter host-constructor 阻断定位（2026-10-19）

在固定 a65 `a65a2853ccae13da167d9aa4720ab8b11ec16656` 的 Filter 函数上逐条运行 host-effect 检查，唯一阻断点是第 1511 行 `CallStubBuilder callBuilder(this, glue, callbackFnHandle, ..., callArgs)`。a65 `call_stub_builder.h` 的对应构造函数签名允许该 7 参数形式，构造体只赋值 builder 成员。将精确头文件 blob/hash 纳入语义证据并支持 arity 7；没有把实际 JS callback 调用视作纯函数。

重新执行生产 `ohscan-run`，同一单文件 light-AST scope 下 !11196 parent/fix 为 1→0 candidate，a65/master 为 0/0。四个 CLI 结果都是 completed-with-limitations、detector blocked，TU partial。另以直接 analyzer sidecar 保留 `matched` 观察：Filter parent 为 candidate，fix/a65/master 为 matched。a65 与 master 的生产 0 不能作为安全结论；其他函数仍有 unknown，特别是 Map 的 `type_fact_invalidated_by_call`。同轮聚焦套件 75 passed、4 skipped。

可重放：`python research/experiments/ark_runtime/c8_20261018/replay_type_origin_semantic_observations.py --official-git-dir D:/openHarmonyScanner/tmp/cve-2025-arkruntime-official.git --history-git-dir D:/openHarmonyScanner/tmp/c-line-ark-history-full-snapshots-20261018.git --output research/experiments/ark_runtime/c8_20261018/typeorigin_v0810_semantic_observations_20261019.json`。该脚本只读取已固定本地 Git 对象，不 fetch。生产入口报告以 `reports/typeorigin-v0810-call-builder-` 为前缀。下一步按 checkpoint 跟踪 Map 的 callback、类型 token 采样与结果创建顺序；在路径证据充分前保持 unknown。


### 结果类型事实跨 callback 与 glue 查询（2026-10-19）

真实源码追踪发现 a65 `CopyWithin` 的 `IsFastTypedArray(jsType)` 是一参数图谓词，`With` 使用 `IsTypedArray(glue, thisValue)` 和 `IsJsCOWArray(glue, thisValue)`；a65 `circuit_builder.cpp`/`stub_builder-inl.h` 显示这些调用仅组合 HClass/字段读取或比较。补齐精确签名后，这些路径不再因 gate 参数而丢失来源。对用户 callback 的影响按对象逃逸区分：新 TypedArray 尚未逃逸时，它自己的 HClass/type token 可继续描述该对象；源对象旧 token 仍失效；把新对象传给 callback 后该 token 降为 unknown。合成两向控制均通过。

在官方 !11196 parent/fix、a65 产品源码和官方 master 上经生产 CLI 重放为 1→0/0/0 TypeOrigin candidate，均仍因 TU partial 而 blocked。直接语义 sidecar 的 Filter 为 candidate→matched/matched/matched；Map、With、CopyWithin、Set 在本轮所列路径均 matched。独立历史 !11684 safe parent/fix 的 TypeOrigin 路径均 matched；生产 parent 报告的两条是独立 `ark.runtime.typedarray-allocation-exception-guard` 候选，fix 无该诊断。!11684 已被先前复核，不作为 untouched blind holdout。

最终当轮聚焦套件 77 passed、4 skipped。报告以 `reports/typeorigin-v0810-type-origin-preservation-` 开头，六提交直接分析记录为 `typeorigin_v0810_semantic_observations_20261019.json`。当前规则仍未完成盲留出验收；下一步寻找独立且未用于调参的官方 vulnerable/fixed TypeOrigin 历史样本，固定对象后先跑生产入口，再决定是否继续扩展机制。


### !9063 TypedArray Filter receiver guard (2026-10-19)

Exact first parent `c4c52fb57b6e204128e1520340c8e66c8e708981` and fix/merge `2a70904be0e21a37a666eb00cab49d02068260ea` were replayed through production `ohscan-run` v0.8.10 using pinned local upstream Git objects, `light-ast`, and the same one-file scope. Rule `ark.runtime.typedarray-receiver-type-guard` reports Filter line 1413 on the parent and no same-root diagnostic on the fix (1→0). Aggregate diagnostics 4→3 because three existing TypeOrigin findings persist on both sides. Both runs are `completed_with_limitations`, detector `blocked`, file outcome `partial`.

The rule binds `GetObjectType(LoadHClass(receiver))` through `IsFastTypeArray` to the same receiver and proves successful-branch dominance over `GetViewedArrayBuffer(receiver)` in the generated graph. Five unit/history controls passed, including renamed bindings and sibling `LastIndexOf` safe-variant control guarded by `IsTypedArray(receiver)` on both source revisions. This control is not a blind holdout. The upstream PR page was not accessible through the browser; local Git objects verify the exact diff and regression source. No CVE was established.

Build profile, macro expansion, transitive dependency closure, upstream runtime regression, product mapping and security impact remain unverified. See `typeguard_ia7e8_source_identity_20261019.json`, `reports/typeguard-v0810-ia7e8-parent.json`, `reports/typeguard-v0810-ia7e8-fix.json`, and the C-line coverage ledger.

### Runtime exception-result guard polarity hardening (2026-10-19)

Review of `runtime_exception.py` found its `IsException()` fast path treated any `if` containing that call plus any nested `return` as a guard. That could incorrectly mark `if (!result.IsException()) return ...`, a conditional-only nested return, or a return of a normal value as safe. It now accepts only a positive test of the same resolved result binding with an unconditional return of `JSTaggedValue::Exception()` or that result itself. Other forms keep the candidate.

Focused controls: 27 tests passed, including the four new inversion/conditional-exit/normal-return/positive-exit cases. The exact !4255/I7E0FM official source pair was rescanned through production M2 `ohscan-run` v0.8.10 at `light-ast`, same two-file scope: vulnerable first parent `d6d18548750373cd4e93e9af24eda3e84f6f1b8e` has one callback-exception candidate; fixed merge `30571a40879bb2092dcb9ae994d6970c1dfd5fc1` has zero; both files are complete. Reports: `reports/runtime-exception-guard-v0810-i7e0fm-parent-20261019.json` and `...-fixed-20261019.json`.

The historical !4255 patch uses a verified pending-exception macro, so this replay is a production regression check for the family, not a direct historical exercise of the newly hardened `IsException()` branch predicate. The branch-polarity controls are unit inputs. No independent historical case for this exact branch form, product build, runtime reproduction or product impact is established; static diagnostics remain candidates. Next: search the pinned official Ark history for a real `IsException()` branch pair and production-replay it without further model changes; if none is found, keep this subcase research-only and return to the exact !9063 build-profile blocker.

### FindIndex generated callback exception path: I9K03B (2026-10-19)

The pinned upstream commit `df668db447d7b19ee38fe7925638feffdd2c9bd6` references I9K03B and adds an `arrayfindindex` regression. Direct issue-page contents and security classification were not retrieved; no CVE is claimed. Exact parent/fix source identities and regression blob identities are in `runtime-exception-i9k03b-source-identity-20261019.json`.

Baseline M2 v0.8.10 on the exact `builtins_array_stub_builder.cpp` parent/fix pair was 0/0 with `completed_with_limitations` and blocked detector status. Source inspection shows `JSCallDispatch` result `retValue` is passed to `FastToBoolean`; in the stable-array path the parent branches on `TaggedIsException(retValue)`, while the fix branches on `HasPendingException(glue)`. The patch test exercises a callback that is not callable and expects `TypeError` to be caught/printed. This establishes a real source change and regression input, not runtime execution or product impact.

Implemented a source-independent CFG/dataflow extension in the existing production exception rule. It ties a callback value derived from `GetCallArg0` to the `JSCallDispatch` result, follows that same binding into `FastToBoolean`, and tracks pending-exception state separately from the result-sentinel branch. Renaming control and the safe `HasPendingException` form are unit-tested. The detector version is now v0.8.11.

On the exact pair with v0.8.11 and the same scope/profile, parent diagnostics are 2 at lines 2234 and 2292; fixed diagnostics are 1 at line 2292. The source file AST is complete, while whole detector runs are `completed_with_limitations` / `blocked`. The changed stable-array path produces the parent-only candidate at 2234. The fixed-source residual at 2292 is in the non-stable path, whose `TaggedIsException(retValue)` check is unchanged by this patch. Its safety is unknown; it remains a candidate. Baseline and updated reports are under `reports/runtime-exception-v0811-i9k03b-*20261019.json`.

Review of the fixed-source line-2292 residual confirms it uses the same `JSCallDispatch` call mode and still tests `TaggedIsException(retValue)` before `FastToBoolean(retValue)`; the patch only changes the stable-array branch. It remains a candidate because no evidence proves that the fallback's exception semantics differ.

The v0.8.11 !4255/I7E0FM production regression remains 1→0 on complete target-file analysis; the !9063 receiver candidate remains 1→0 with three unchanged TypeOrigin candidates. Across runtime-exception, exception-guard and detector suites: 51 passed, 3 skipped. M2 reports show the I9K03B scope runtime rising from a blocked no-analysis baseline (~0.000013s) to ~0.0865s per side with partial findings; peak memory is unavailable, and this is not a like-for-like cost comparison because coverage changed. The I9K03B pair was used to design this graph extension and is a development sample, not an independent holdout. Product build/profile binding, upstream test execution, runtime reproduction, complete safe/unrelated controls, and product impact remain unverified. Local build-profile search found only the a65-bound product profile; its SHA-256 and exact mismatch are recorded in the identity JSON. Next: obtain the official product manifest pinning the I9K03B parent/fix plus matching GN args and FindIndex compile action; do not reuse a65. Keep the line-2292 candidate until matching-profile runtime evidence resolves it.

Full `tests/detectors/ark_runtime` run: 146 passed, 11 skipped, 7 failed. Six failures are in the pre-existing C3 TypeOrigin mechanism tests; the same six reproduce at baseline scanner commit e4e0761 in the isolated baseline worktree. The remaining failure is the existing C4 dependency-manifest expectation mismatch (`ACTUAL_INCLUDE_CLOSURE` vs current unresolved-dependency set), already recorded as a C4 blocker. None of these failures are in the exception propagation changes.


### Source-verified inherited `Branch(...)` CFG for generated callbacks (2026-10-19)

The earlier v0.8.11 exact-source scan of the official 2024-05-21 OpenHarmony 4.1 manifest pin `3ad6d4c17d24fd4e1bb9a42067b36cc498d0979f` selected only `builtins_array_stub_builder.cpp`. It returned zero diagnostics while the generated callback paths were `unknown`: this source spells control flow as `Branch(...)`, whereas the bounded CFG only recognized `BRANCH(...)`. The manifest snapshot independently pins `arkcompiler_ets_runtime` to the 4.1 release branch; this binds a source snapshot, not a built product.

The production graph builder now recognizes the CamelCase alias only when the selected real C++ sources prove the relevant contract: the target owner reaches the `StubBuilder` class through parsed inheritance declarations; the exact three-argument `Branch(GateRef, Label*, Label*)` declaration and parsed method body are present; and the body routes `IfTrue`/`IfFalse` of the same branch gate to the corresponding label arguments. An explicit `Branch` macro definition or a derived-class `Branch` redeclaration disables the alias. Unavailable, ambiguous, or inverted contracts leave `Branch` unmodeled. Fully qualified class identities prevent enabling the alias for an unrelated same-named class. Regression tests cover the verified contract, missing contract, swapped edge mapping, derived override, and namespace collision.

Production M2 `ohscan-run` v0.8.12 on the exact manifest-pinned source and a five-file scope (target `.cpp`, target header, `builtins_stubs.h`, `stub_builder.h`, `stub_builder.cpp`) emits two `ark.runtime.callback-exception-before-result-conversion` candidates in `FindIndex` at lines 1282 and 1340. Target AST parsing is complete; the detector remains blocked/partial because other callback paths in Filter/Find/FindIndex are unresolved. `builtins_stubs.h` itself is parser-partial, although the specific inheritance declaration node is recovered and used only as one source-bound contract fact.

The exact I9K03B pair was rescanned at the same five-file scope: parent `a3bbeab9883c7c22d4bdc0e65b3b516215d39e0d` reports two candidates at 2234/2292; fix `df668db447d7b19ee38fe7925638feffdd2c9bd6` reports one at 2292. These source revisions use uppercase `BRANCH`, so their 2→1 replay is a regression check for the existing generated callback model, not evidence that the new CamelCase alias caused the pair delta. The fixed non-stable-path candidate remains unresolved. An attempted v0.8.10 five-file baseline returned `not_applicable` / “no source with supported language”; it is invalid as a zero-result comparator. The earlier one-file v0.8.11 zero-result report also lacked the source contract needed to model CamelCase `Branch` and remains an incomplete-coverage observation.

The manifest pin was used to implement the source contract and is development data, not a blind holdout. No independent safe/unrelated real control or untouched same-mechanism holdout is established. No exact compile profile, macro expansion, runtime build/test, dynamic reproduction, product mapping, or impact evidence exists. The exception rule remains a research candidate and all findings remain unassessed candidates. See `branch_control_contract_i9k03b_20261019.json`, `reports/runtime-exception-v0812-i9k03b-{parent-expanded-scope,fixed-expanded-scope}-20261019.json`, `reports/runtime-exception-v0812-i9k03b-manifest-tag-20240521-20261019.json`, and `runtime-exception-i9k03b-source-identity-20261019.json`.

Focused runtime-exception/unseen-detector tests after the final change: 44 passed, 2 skipped. The full Ark Runtime suite: 150 passed, 11 skipped, 7 failed. All seven failures are the previously observed six C3 TypeOrigin expectation failures and one C4 dependency-manifest expectation mismatch; the C8 exception-path tests pass. The exact focused command is `python -m pytest tests/detectors/ark_runtime/test_runtime_exception.py tests/detectors/ark_runtime/test_unseen_detector.py -q`; the full command is `python -m pytest tests/detectors/ark_runtime -q -rs`.

Next operation: use the pinned local Ark history to identify one source-disjoint generated-callback case whose owning class inherits the verified `Branch` contract and whose source contains a matching safe pending-exception guard; freeze its complete source identities before scanning, then run production M2 at the same five-file support scope. If no such case exists in the pinned history, record the searched ref/commit boundary and keep the independent-control gate open.


### Tagged-exception guard candidate from pinned history (2026-10-19)

Commit `0aab2028c1f8b90d60064210d2a0ab94876528ba` (message references I943QV; issue classification not independently verified) was scanned through production M2 v0.8.12 using the same five-file scope. It yielded two FindIndex callback-exception candidates at lines 1431 and 1489 even though both source paths branch on `TaggedIsException(retValue)`, return the exception result, and exit before `FastToBoolean(retValue)`. The scan is `completed_with_limitations`; parsing is 4 complete / 1 partial, with no build profile or macro expansion.

This is a plausible earlier same-mechanism source candidate, not a confirmed vulnerable version or safe sample: the old snapshot's `JSCallDispatch` exception contract has not been bound. The later exact I9K03B fix changes the same FindIndex guard from `TaggedIsException(retValue)` to `HasPendingException(glue)`, which supports same-family relevance but does not establish an I943QV disclosure association or an exact fix pair. Do not suppress these candidates or use the snapshot as a holdout. Next, trace the exact FindIndex guard blob through intervening commits to the I9K03B parent/fix and bind its regression test; then determine whether this older snapshot is an earlier vulnerable variant. Evidence: `reports/runtime-exception-v0812-i943qv-safe-pattern-development-20261019.{json,md}`.
