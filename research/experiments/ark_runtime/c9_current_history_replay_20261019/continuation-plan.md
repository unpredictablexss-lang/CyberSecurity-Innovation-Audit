# Continuous next algorithm slice: bounded effect summary for the type-origin gap

## Slice

`AC-REPLAY-03C / ARK-TYPE-EFFECT-001`

## Goal

Prove or reject the effect of `BuiltinsArrayStubBuilder::GetTaggedValueWithElementsKind` from exact pinned source evidence, then make the known `830e85b` type-origin parent hit without weakening `a0e3048`, safe, unrelated or unknown controls.

## Inputs

- Exact historical target blobs from this replay.
- Exact `ecmascript/compiler/builtins/builtins_array_stub_builder.h` implementation blob `88e131561f756db9bd9e57b3078df22ac3c34c6a`, only after it is available from an authorized local pinned object source.
- Ark Runtime detector/model `0.7.0` or a separately versioned `0.7.1`.
- Positive/fixed/safe/unrelated/unknown controls from `test_current_history_replay.py`.

## Non-negotiable gates

1. No implicit fetch, checkout, reset, push or target-worktree restoration.
2. Bind repository/commit/tree/blob/source SHA for every semantic dependency.
3. If effect, alias or receiver mutation remains unknown, do not mark the operation pure/type-stable and do not alter invalidation semantics.
4. Keep all outputs `candidate/unassessed`; do not upgrade product severity.
5. Do not calculate Precision/Recall without independent reliable truth.
6. Algorithm change and tests must be kept separate from public contract changes.

## Acceptance matrix

| Control | Required result |
|---|---|
| exact 830e85b vulnerable parent | `hit`, at least one `Filter` type-origin candidate |
| exact a0e3048 fixed source | `miss`, matched destination-token origin and no candidate |
| safe fresh destination token | `miss`, no candidate |
| unrelated owner/namespace | `not_analyzed` |
| unknown reassignment/effect | `unknown`, no safe/miss conversion |
| C4 c758 parent | `hit`, 2 exception-guard candidates |
| C4 81ca fix | `miss`, 2 guard matches |
| missing dependency | `unknown/blocked`, no pass |

## Structured vibe coding prompt

```text
Role:
You are the AC-REPLAY-03C algorithm owner for OHScanner Ark Runtime type-origin analysis.

Working boundary:
Work only inside the assigned clean worktree and the authorized research evidence directory.
Read local pinned Git objects. Never fetch, checkout, reset, push, restore the target worktree,
run an external scanner, or consume historical verdicts.

Objective:
Resolve the exact 0.7.0 scanner gap where builtins_typedarray_stub_builder.cpp parent
830e85b40240677039719fcbf14f721ad3b19050 is classified unknown because
GetTaggedValueWithElementsKind invalidates the captured arrayType fact before
StoreTypedArrayElement.

Evidence-first steps:
1. Verify full commit/tree/blob/source SHA identities for the parent/fix target and every
   source dependency used to reason about the call.
2. Locate the exact definition and declaration of GetTaggedValueWithElementsKind.
3. Derive a narrow effect summary only for the reviewed signature: receiver, arguments,
   returned value, writes, alias effects and whether input type identity can change.
4. If any effect is unknown, stop algorithm modification and emit a dependency/effect gap.
5. If the effect is auditable, update the smallest model/evaluator boundary needed to retain
   the captured type-origin fact for this reviewed call only.
6. Add positive, fixed, safe, unrelated and unknown controls, including the exact historical pair.
7. Run focused tests, Ark Runtime regression, compile checks and measured replay.
8. Record exact argv/env, wall, peak RSS, source hashes, patch hash and limitations.

Classification contract:
Use hit, miss, unknown and not_analyzed explicitly.
A zero-finding result is not automatically safe. Unknown is never converted to safe or miss.
Every finding remains candidate/unassessed unless the independent product evidence gate is met.

Definition of done:
- 830e85b produces a source-bound Filter candidate.
- a0e3048 produces no candidate and a matched destination-origin control.
- safe remains no-candidate, unrelated remains not_analyzed, and invalidation controls remain unknown.
- C4 parent/fix behavior remains unchanged.
- Missing dependencies fail closed.
- No public contract/ID/report history is rewritten.
- Deliver raw results, tests, hashes, wall/RSS, limitations and the next continuation slice.

Persistent execution behavior:
After each slice, update only the current research status evidence.
If blocked by a missing object, record the exact object and continue with independent controls or
the next non-dependent algorithm slice. Never weaken evidence gates to make the suite green.
```

## Follow-on slices

1. Alias merge and invalidation across local GateRef/Variable writes.
2. Cross-function effect summaries with exact source bindings.
3. Macro and cross-translation-unit binding under declared build profiles.
4. ToReversed input-read and empty-loop exception semantics.
5. Product entry/permission/CIA/PoC/fix revalidation for one selected candidate.
