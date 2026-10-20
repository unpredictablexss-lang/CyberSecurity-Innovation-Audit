# Scanner gap: type-origin known parent is unknown under 0.7.0

## Fixed input

- repository: `openharmony/arkcompiler_ets_runtime`
- local Git object store: `E:\网安\_oh_targets\arkcompiler_ets_runtime`
- parent commit: `830e85b40240677039719fcbf14f721ad3b19050`
- parent tree: `579712c1ebbb703d17cea422b1572023bed5d8a4`
- path: `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`
- parent blob: `054451b1be4f39254d56a1683cc9d1c1b5e55018`
- parent source SHA-256: `847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422`
- rule: `ark.runtime.typedarray-store-type-origin`
- detector/model version: `0.7.0`

## Minimal reproduction

```text
Given the exact parent blob above,
When ArkRuntimeTypeSafetyDetector 0.7.0 analyzes the bound `Filter` function,
Then no candidate is emitted.
The local result is `unknown`, not `hit`, `miss`, or `not_analyzed`.
```

Existing regression command:

```powershell
python -m unittest tests.detectors.ark_runtime.test_historical.HistoricalPairTests -v
```

Observed:

```text
test_C01_pinned_before_has_origin_candidate ... FAIL
test_C02_pinned_fix_has_no_rule_candidate ... ok
test_exact_parent_and_fix_through_runner_keep_candidate_and_coverage_distinct ... FAIL

FAILED (failures=2)
```

Focused c9 regression records the same gap while passing its assertions:

```text
test_type_origin_known_parent_gap_is_minimized_as_unknown_not_hit ... ok
test_type_origin_fixed_source_is_also_unknown_not_a_clean_miss ... ok
```

## Mechanism

Parent `Filter` stores with receiver `newArray` but uses receiver token `arrayType`:

```cpp
GateRef newArray = newBuilder.NewTypedArray(glue, thisValue, arrayType, ...);
...
GateRef kValue = arrayStubBuilder.GetTaggedValueWithElementsKind(glue, kept, *i);
StoreTypedArrayElement(glue, newArray, ..., kValue, arrayType);
```

The fix reads the destination token after allocation:

```cpp
GateRef newArrayType = GetObjectType(LoadHClass(newArray));
...
StoreTypedArrayElement(glue, newArray, ..., kValue, newArrayType);
```

0.7.0 observes:

```text
reason=type_fact_invalidated_by_call
effect_sites includes GetTaggedValueWithElementsKind
```

`GetTaggedValueWithElementsKind` is recognized syntactically but is not admitted as a bounded by-value/read-only/type-stable operation. The model therefore invalidates the earlier `arrayType` fact before the sink and fails closed to `unknown`.

## Why the Detector was not changed

The exact effect-summary input `ecmascript/compiler/builtins/builtins_array_stub_builder.h` is bound in the model to blob:

`88e131561f756db9bd9e57b3078df22ac3c34c6a`

That blob is absent from the local partial-clone object store. Without the exact dependency it is not auditable whether the call can mutate `thisValue`, `kept`, or type state. Marking it pure/type-stable would weaken invalidation without evidence and could convert C3 unknown controls into false candidates or false matches.

Accordingly, this slice preserves fail-closed semantics and leaves the algorithm change to the next dependency-bound slice.

## Required closure for the next slice

1. Make the exact effect-summary blob locally available through an authorized pinned object source; no implicit fetch.
2. Bind its blob and source SHA-256 at a declared revision.
3. Verify the precise function signature and effects on receiver/type state.
4. Only then add the narrow operation summary.
5. Re-run positive/fixed/safe/unrelated/unknown controls and the exact parent/fix pairs.
6. Require `830e85b -> hit`, `a0e3048 -> miss`, safe -> no candidate, unrelated -> `not_analyzed`, unknown invalidation -> `unknown`.
