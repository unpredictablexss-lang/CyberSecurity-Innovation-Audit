# Ark Runtime C-line frozen history replay recovery

## Disposition

The requested same-scope replay is **blocked**. The task-start 0.7.0 semantic freeze was TypeSafety 0.3.1 (model SHA-256 `ec13c5…c575`). The live freeze file and model have since moved to 0.3.2 (`6f2602…12df`). The 0.3.1 `model.py` bytes named by the freeze (`299b49…f3f3`) are no longer in the working tree or the recorded execution commit, so the frozen model cannot be reconstructed or run without guessing. The snapshot file in this folder records the freeze metadata observed at task start; it is explicitly not a byte-identical recovery of the original JSON.

The preserved TypedArray parent and fix source bytes both recompute to their recorded Git blob OIDs and SHA-256 values. Their commit/tree objects are unavailable in the local history cache, and the source checkout has an empty `.git/config`; this replay did not fetch. The `NewObjectStubBuilder` source dependency named by the freeze is not present in the retained source bundle. These are separate provenance/dependency blockers; they do not erase the byte-level source checks.

## Sample dispositions

| Sample | Status | Explanation |
|---|---|---|
| TypedArray `Filter` parent | `blocked` | Source bytes match the recorded blob; frozen 0.3.1 model and local commit/tree proof unavailable. No detector result emitted. |
| TypedArray `Filter` fix | `blocked` | Same blockers. Expected semantic change is receiver type token to result-array type token; the new type read precedes pending-exception handling, so the expected frozen result is `unknown`, not safe. This is not an observed replay result. |
| `Set` safe control in fix blob | `blocked` | In-scope control, not run because the frozen implementation is incomplete. |
| `Map` unrelated control | `not_analyzed` | Outside the frozen caller profiles. No override was used. |
| `slowpath_lowering.cpp` exception parent/fix | `not_analyzed` | Exact sources and their commit/tree bindings are present in the local history records, but this pair belongs to a separate research-only lexical probe, not the frozen TypeSafety rule. It is not combined with the TypeSafety observations. |

No new `candidate`, `safe`, or `miss` label was produced. Earlier 0.2.0/0.3.0 runs remain in their original evidence folders and are not inputs to this replay. The historical C2 parser/owner work remains partial; parser gaps, unexpanded macros, missing GN compile profile, unresolved dependency closure and no product runtime validation remain blocking conditions. The developer controls are not holdout truth and do not support precision/recall.

## Reproduction and validation

From the `CyberSecurity-Innovation-Audit` repository root:

```powershell
$env:GIT_NO_LAZY_FETCH = '1'
python research/experiments/ark-runtime-history-replay-20261018/replay.py
```

The command recomputes source SHA-1 Git blob IDs and SHA-256 values, inspects only objects already in the local history cache with lazy fetch disabled, compares the current implementation with the task-start frozen hashes, and writes `replay-manifest.json` and `run-summary.json`. It exits successfully when it has reproduced the *blocked disposition*; that is not a successful detector replay.

No detector regression test was run: the test would load the live 0.3.2 model, not the missing frozen 0.3.1 model. Running it would violate the same-config requirement. The prior 0.2.0, 0.3.0 and exception-probe test outputs are preserved as historical records only.

## Reviewed C-line records

- [0.7.0 TypeSafety contract and admission boundary](../../deliveries/cpp/ark-runtime-c-line-contract-20261018.md)
- [C-line algorithm freeze as it existed at task start (metadata snapshot)](frozen-contract-start-snapshot.json)
- [Current live algorithm freeze](../../deliveries/cpp/ark-runtime-c-line-algorithm-freeze-20261018.json)
- [C2 parser/owner profile study](../../deliveries/cpp/typedarray-parser-gap-20261018/README.md)
- [C2 exact-source replay record](../ark-runtime-exact-source-20261018/reproduction-record.json)
- [C2 exception-guard follow-up](../ark-runtime-exception-guard-20261018/README.md)
- [Independent blind holdout packet](../../deliveries/cpp/holdout-arkcompiler-runtime-core-a053abc4/blind_packet.md)

The Runtime Core blind packet omits detector predictions, but it is not an independent holdout: the developer inspected its source before the final freeze. Its 20 label rows remain blank, so it is not counted as a true-positive or true-negative result.

## Read-only source-object revalidation addendum (2026-10-18 to 2026-10-19)

The original recovery command ran through the Windows view of the OpenHarmony Git object store. A later independent check found that this Windows view cannot read its reparse/pack paths, so the old `not_confirmed_local_cache` rows describe a tool-access failure, not proof that the Git objects are absent. Rechecking through the configured WSL object store with lazy fetch disabled confirmed both TypeSafety profile commits, expected trees, target blobs and creator blobs. It also checked all 30 exact model dependency bindings at each commit (60 commit/path/blob and content SHA-256 checks); all matched. See [C-line source binding verification](../../deliveries/cpp/C_LINE_SOURCE_BINDING_VERIFICATION_20261018.json).

This updates source provenance only. The records above still describe a 0.3.1 recovery attempt and are not a 0.3.2 Detector replay. During the independent review, the live 0.3.2 freeze was updated several times; the 2026-10-19 captured freeze now matches current implementation/model bytes and the focused 32-test regression passes. Its older dependency manifest is stale, the freeze does not pin parser/toolchain package or binary identity, and the required `BUILD.gn` input cannot be represented by the strict public `SourceUnit` contract. The current historical Detector result therefore remains `blocked`; no prior candidate/fix/control output is promoted or combined.
