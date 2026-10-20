# TypedArray allocation exception guard: second-layer review (2026-10-20)

## Scope and evidence identity

This is an independent source review of the registered-adapter historical control for `ark.runtime.typedarray-allocation-exception-guard`. It does not treat the detector label or its test expectation as proof of a vulnerability.

The historical test ran against the supplied bare Git object store `D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git` and passed:

```text
OHSCANNER_ARK_REPO=<store> python -m unittest tests.detectors.ark_runtime.test_exception_guard.ExceptionGuardHistoricalTests.test_exact_parent_and_fixed_source_through_registered_adapter -v
Ran 1 test ... OK
```

The test independently recomputes and checks source identity before invoking the registered detector adapter:

| Revision | Target blob | Target SHA-256 | Adapter result for this rule |
|---|---|---|---|
| parent `c758818dbfd0b146a908d43d21f6ca1706c33783` | `857ad416bc102fcd5d462e9702d2ba7c51f29b6d` | `984e45f2b6ea652c412437be03dda4189549afe4cf77c95713cf0d0c5d361db9` | two `candidate` findings |
| fixed `81ca57487d04ea30cd11c271e86494a4e130f43e` | `3b9de9d915d767d7a67316145451da2446162884` | `4684a1587519e7d141f181b595317db489991a3908e1f1b4ef67513c25d9efd0` | no finding for this rule |

The historical helper `ecmascript/compiler/new_object_stub_builder.cpp` is present in both exact commit trees and has the same blob. The `TypedArraySpeciesCreate` implementation is likewise present in both trees at `ecmascript/base/typed_array_helper.cpp` (blob `f69feb7923fcfe002ed5aca79dc162daaba07976`). This binds helper source to those trees, but does not bind either revision to a shipped product/build profile.

## Parent findings

Both observations are in the sensitive sequence `NewTypedArray(...)` then `GetObjectType(LoadHClass(glue, newArray))`:

| Function | Parent lines | Flow and assessment |
|---|---:|---|
| `BuiltinsTypedArrayStubBuilder::Filter` | 1380, 1486–1488 | After callback iteration, `NewTypedArray` at 1486 returns `newArray`; line 1487 immediately loads its HClass; the pending-exception branch is only at 1488. The HClass read therefore dominates the caller's exception exit. Fixed moves the HClass read to line 1494, after the branch at 1487–1492 and exception return at 1490. |
| `BuiltinsTypedArrayStubBuilder::Map` | 2606, 2655–2656 | `NewTypedArray` at 2655 is immediately followed by the HClass load at 2656; no pending-exception check intervenes. Fixed adds the branch at 2658 and writes/returns `Exception()` at 2659–2662; the HClass read moves after the no-exception bind at 2664–2665. |

The `Map` path is especially clear at source level: the missing check is directly between a potentially throwing builder call and a type/header read. `Filter` has the same ordering defect, and its call occurs after user callback execution, which can change the receiver's constructor/species-related state before allocation.

### Can `NewTypedArray` actually return an exception value?

The exact `NewTypedArray` helper in both revisions is at lines 2290–2361. Its fast path creates an object and assigns it to `result` (2320–2321). It can leave that path for `slowPath` when constructor/protector/prototype/accessor checks or the on-heap size/object-size checks fail (2303, 2307–2313, 2328, 2336). The slow path calls `CallRuntime(...TypedArraySpeciesCreate...)` and assigns that return directly to `result` (2351–2355), then returns it (2358–2361).

The exact same-tree `TypedArraySpeciesCreate` helper (lines 971 onward) returns `JSTaggedValue::Exception()` after abrupt completion in both the default allocation arm and species construction/validation arm (1001 and later abrupt-completion checks). Its `TypedArrayCreate` helper also returns the Exception sentinel after abrupt construction/validation. Thus an exception-valued result is supported by concrete source evidence for the helper slow path; this is not inferred from the detector's label.

There is an important nuance: the `NewTypedArray` fast path calls `NewByteArray`, whose `AllocateInYoung` error edge can leave the pending exception set while the outer `NewTypedArray` result remains the previously allocated `obj`. That path alone does **not** establish that `newArray` is the Exception sentinel. The stronger exception-valued-result evidence is the explicit `TypedArraySpeciesCreate` slow path. In `Filter`, callback side effects make such a slow path credible. In `Map`, the caller checks some preconditions and invokes the helper before any callback; the helper's additional size/protector/species checks still permit its fallback in source, but this review does not establish which such path is reachable in a particular runtime/build or whether there is an intervening invariant outside the inspected source.

## Fixed source and residual uncertainty

The fix changes control flow rather than changing the allocation helper: both callers test `HasPendingException(glue)` immediately after `NewTypedArray` and return `Exception()` before reading the result HClass. This closes the source-level use-before-exception-check ordering in both functions.

The rule-level `matched`/no-finding result on the fixed blob only means its bounded local check found the sensitive read dominated by the modeled exception check. It is not a proof of full program safety or a product fix.

## Partial / blocked status

The adapter test asserts that the parent and fixed runs both have aggregate detector status `blocked` and one partially covered file. The local exception-guard observations remain present in the parent despite that aggregate state. The runner and adapter deliberately preserve partial observations while refusing to infer complete coverage; the aggregate status reflects incomplete analysis/coverage in the translation unit and/or other modeled rule analysis, not a negation of these local control-flow observations. The test does not isolate every source of the aggregate `partial` state, so this report does not attribute it exclusively to a parser defect or to this rule.

Partial parsing limits negative conclusions about unseen macros, declarations, and paths. It does not erase the visible ordering in the two parsed function bodies or the same-tree helper implementation. Conversely, AST ordering plus helper source does not demonstrate runtime execution in a product build.

## Review disposition

- **Source-level missing exception protection:** supported in both parent functions; fixed source places a same-glue pending-exception exit before each HClass read.
- **Exception-valued result possibility:** supported for `NewTypedArray`'s species/runtime slow path by exact same-tree helper source. The direct fast-path `NewByteArray` failure edge instead establishes a pending exception while the result may remain an allocated object; do not conflate the two.
- **Specific vulnerability:** the two candidates are concrete code-path candidates, not confirmed vulnerabilities. `Filter` has the clearest runtime-relevant route because callbacks precede allocation; for `Map`, the helper fallback exists, but exact reachability through its additional guards needs runtime/build or fuller semantic proof.
- **Runtime / product impact:** unknown. No exact product binding, target build configuration, runtime reproduction, crash/corruption evidence, or security impact was supplied or established here. No CWE, exploitability, or accuracy metric is claimed.
- **Status:** historical component-source control review complete; runtime and product validation not run.

## Evidence limits and negative evidence

The review confirms exact target blob/SHA identities and same-tree helper contents. It does not compile either upstream revision or instrument generated machine code, evaluate allocation-failure behavior in a running VM, establish an attacker-controlled entry point, or bind the code to a released product. The fixed commit's exception check is directly visible and the adapter test's no-finding result is corroborating detector behavior, not independent proof by itself.
