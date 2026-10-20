# Limitations and next cross-function effect-summary slice

## Scope completed

This slice validates the local generated-IR exception-order semantics for
`NewTypedArray` and `NewTypedArraySameType`, including `LoadHClass`,
`CopyTypedArrayBuffer`, and `StoreTypedArrayElement` effects. The result stays
at `candidate/unassessed`: `matched` is only a local guard-order observation,
not a safe or vulnerability verdict.

The source review is located at
`origin/codex/c-line-ark-runtime-20261018:e4e0761501a83ac25cc67d04c527eefe9f4a1b50:research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`
(blob `dbedea677c8dc70c1b0066c7bc52df27bcff06ea`). Its fixed evidence records
IC7B8Q TypedArray Map allocation exception and IAO7GO Reflect.apply exception
propagation. I7E0FM / PR !4255 TypedArray Filter abrupt completion is carried
by the same fixed commit's `ark-runtime-coverage-ledger-20261019.json` and
`research/experiments/ark_runtime/c8_20261018/README.md`, with the exact pair
`d6d18548750373cd4e93e9af24eda3e84f6f1b8e` -> `30571a40879bb2092dcb9ae994d6970c1dfd5fc1`.
No source-audit item is treated as absent.

## Unproved semantics retained as unknown

- A void zero-length/early return can precede later labeled generated-IR
  obligations. A bounded newline-preserving continuation pass keeps those later
  local candidates, while the return path itself remains
  `result_return_before_modeled_effect_order_unknown`. This does not prove
  cross-function effects, aliasing, or exception clearing.
- Nested or adjacent `CopyTypedArrayBuffer` / `StoreTypedArrayElement` calls in
  one IR instruction have no local evaluation/effect-order proof. Both nesting
  orders and both configured model orders stay
  `effect_signature_or_same_instruction_order_unknown`.
- A pending-exception branch remains pending until a terminating return/exit.
  `result->WriteVariable(Exception())` is treated as a reviewed exception-result
  write, not as permission to execute later copy/store effects.
- Unknown calls, unresolved labels, wrong glue/binding, signature mismatches,
  and budget exhaustion remain unknown/partial. None is counted as safe or miss.
- The analysis is bounded AST/CFG evidence. It does not prove ownership,
  dominance over all product paths, concurrency, attacker control, reachable
  sensitive operations, or CIA impact.

## Verification limitations

- Focused synthetic tests execute without skips. The full focused module has one
  historical skip because `OHSCANNER_ARK_REPO` is not configured; that skip is
  not a pass. The Ark suite has eight pinned-source/owner skips; those are not
  passes.
- `scripts/check_docs_context_budget.py` is not present in this worktree and the
  recorded invocation exited 2. This is an error, not a pass.
- No untrusted dynamic PoC was executed. No product CVE/CIA/affected-version or
  Precision/Recall claim is made.

## Next slice: bounded cross-function effect summaries

1. Add a source-bound summary record per selected helper: repository, full
   commit/tree/blob/source hash, function signature, `may_complete_abruptly`,
   same-thread pending-exception predicate, exception return/sentinel, result
   conversion effect, copy/store effect, argument/alias positions, and explicit
   unknown fields.
2. Propagate only reviewed one-hop call edges. Missing bodies, unresolved
   wrappers, macro expansion, thread changes, or conflicting effects must make
   the caller path unknown rather than safe.
3. Replay I7E0FM/PR !4255, IC7B8Q/PR !11684, and IAO7GO/PR !9061 only from
   supplied pinned Git objects with positive/fixed/safe/unrelated/unknown
   controls. Historical skips remain non-passes.
4. Keep the current local rule separate from the cross-function rule and keep
   all outputs at `candidate/unassessed` until the full evidence gate is met.
