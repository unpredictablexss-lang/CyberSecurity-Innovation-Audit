# C-line ArrayBuffer lifecycle/mutation scout — 2026-10-20

## Result

**No-go: no new high-signal ArrayBuffer lifecycle/mutation candidate selected.** This is a scoped source triage result, not a safety finding. The ArrayBuffer `slice` and internal `CloneArrayBuffer` paths inspected here have bounded source/destination ranges under their visible length and caller invariants. No narrower reachable violation survived the checks. Runtime, product configuration, and full-build behavior remain `unknown` / `not_run`.

## Exact source and workspace identity

- Scanner repository: `D:\openHarmonyScanner\worktrees\c-line-task-tree-20261020`, branch `codex/c-line-parallel-plan-20261020`, clean at start, HEAD `b019f492c6477a8619c7e6635556ec7f86f5a6e0`, tree `2e55bf798c6b63327c7734d5f3d5c1f5d5243d12`.
- Upstream component: `openharmony/arkcompiler_ets_runtime`, checkout `D:\OpenHarmony807\repos\arkcompiler_ets_runtime`, clean `master...origin/master`, exact HEAD `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`.
- Current task tree excludes this slice from closed work and marks `C-SCOUT-ARRAYBUFFER-MUTATION-NEXT` active. Float32 negative-double, TypedArray length, DataView API width/IB8BCA, receiver guards, and C1 Map slices are excluded as directed.

Exact component file pins (Git blob; SHA-256; this scout's Tree-sitter status):

| Path | Git blob | SHA-256 | Parse |
|---|---|---|---|
| `ecmascript/builtins/builtins_arraybuffer.cpp` | `2aa22c58803df690a5a2b326451e02297dc5e2f6` | `4d388d997313cf7c900f1f0d54fbe826266845665424e32cc9dd4cdbaa62dcc9` | complete (38 functions) |
| `ecmascript/builtins/builtins_arraybuffer.h` | `c938b4263bdae62c1418dc8ca159b2ba8bc0a493` | `c2a4fb1a18e785d1f105eee52ac71a38386b93a6ac80b685c438edf48e3fe9e6` | complete (1 function) |
| `ecmascript/js_arraybuffer.cpp` | `3c05650cfffa5ece7a8d00b546fea6a0b6107416` | `e7f0db160d3d58ba31854f30e2a2652b0b4a7daae092288b78f45702cc5aabad` | complete (4 functions) |
| `ecmascript/js_arraybuffer.h` | `a6da193e8a91fe42706aab71ce71d92c00bb8adf` | `fe09165a245f519938012ad9deab67635cc0d52953fb26151771504fb23fe863` | partial (1 function; declaration file) |
| `ecmascript/base/typed_array_helper.cpp` | `bcb422fe67f4e670adcca31fffd4da7e2b3b0b21` | `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d` | complete (27 functions) |
| `ecmascript/builtins/builtins_typedarray.cpp` | `0fc27c213e1ea80d93e1e3807eec11baf2634832` | `14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c` | complete (53 functions) |
| `ecmascript/builtins/builtins_sendable_arraybuffer.cpp` | `f0de07a83e4343dec4b243d0053e532c176f5671` | `8bb024a0504762de5288f6f930b7dbdb9204fc1528e4a23fe51cc1d53adf695c` | complete (9 functions) |
| `ecmascript/serializer/value_serializer.cpp` | `0e4ba12ee11aef24596355c968a795bebdf2ec2b` | `26215acb99dd56a71aae2c405e3bc6c0a5d9b1454f11f3de27197f3e2ece364b` | complete (15 functions) |

Statuses above are direct parse results on pinned bytes, not whole-repository coverage. `js_arraybuffer.h` remains partial. The scanner model/adapter has no ArrayBuffer lifecycle rule or binding; the direct Ark Runtime analyzer is scoped to modeled `BuiltinsTypedArrayStubBuilder` source-to-store flows and does not apply to these functions. For these paths the current registered/direct-analysis baseline is therefore no ArrayBuffer finding/rule execution, not an observed safe result. The adapter's exact dependency profile cannot treat absence of a rule as complete analysis.

## Source triage and counterevidence

1. `BuiltinsArrayBuffer::Slice` reads a `uint32_t` byte length into `int32_t`, calculates `first`, `last`, and `newLen`, constructs a result, verifies the result is an ArrayBuffer with length at least `newLen`, rechecks source detachment after species construction, then copies only when `newLen > 0`. `AllocateArrayBuffer` rejects `byteLength > INT_MAX` before narrowing to `uint32_t`; ordinary constructor-created byte lengths are thus capped at `INT_MAX`, so the signed cast does not wrap for a successfully allocated buffer. `first`/`last` clamp to `[0,len]`, and `newLen=max(last-first,0)`. The custom species callback can mutate/detach the source, but detachment is rechecked before copying; destination identity and minimum length are also checked. No source-supported OOB copy trigger found.
2. `CloneArrayBuffer` takes a `uint32_t srcByteOffset`, uses only an `ASSERT(srcByteOffset <= srcLen)` internally, then subtracts and copies. This initially looked like a possible release-build boundary. The inspected internal callers (`TypedArrayHelper::TypedArraySpeciesCreate` and `%TypedArray%.prototype.set`) derive offset from the source typed array's internal `[[ByteOffset]]`; the latter also checks source length against target capacity, and same-buffer copy clones that validated source region before writing. No untrusted public caller passing an arbitrary offset was found in the source search. For a ByteArray source, clone byte length is computed as `(srcLen-srcByteOffset)*byteLen`; if this exceeds signed `int32_t`, the narrowed `cloneLen` is nonpositive or negative and the copy is skipped or `AllocateArrayBuffer` receives a huge converted unsigned length and rejects it (`>INT_MAX`) before allocation. This arithmetic merits regression coverage if callers evolve, but current evidence does not establish a reachable unsafe copy.
3. `JSArrayBuffer::CopyDataPointBytes` calls `memcpy_s(to, count, from + fromIndex, count)`. Its declared `count`/`fromIndex` are signed `int32_t`; the audited public `slice` path supplies nonnegative bounded values, and the audited clone caller supplies a valid internal offset and positive representable clone length. The helper itself has no independent source/destination extent parameters, but no reachable unsafe input source was demonstrated.
4. Exact tree search found no public resizable/grow implementation in this checkout. `JSArrayBuffer` stores a 32-bit byte length and data pointer; serializer transfer paths detach/attach through `JSArrayBuffer::Detach`/`Attach`, but no concrete lifecycle inconsistency was established from the inspected implementation. Transfer ownership, native allocator accounting, and deserialization interactions were not exhaustively proven.

Relevant declarations and helper relationships: `BuiltinsArrayBuffer::Slice`, `AllocateArrayBuffer`, `CloneArrayBuffer`, `IsDetachedBuffer`, and `GetDataPointFromBuffer` are declared in `builtins_arraybuffer.h`; `JSArrayBuffer::CopyDataPointBytes`, `Attach`, and `Detach` are declared in `js_arraybuffer.h` and defined in `js_arraybuffer.cpp`; typed-array species construction calls `CloneArrayBuffer` from `base/typed_array_helper.cpp` and `builtins_typedarray.cpp`; serializer transfer paths call detach/attach from `serializer/value_serializer.cpp`. `js_arraybuffer.h` parse partial means exact declaration semantics should be checked textually if future work binds it.

## Source-derived controls for any future re-triage

- Safe: slice empty/reversed intervals (`newLen == 0`) performs no copy; ordinary interval fully within a valid source; custom species destination longer than requested is allowed, shorter is rejected; source detached during species callback is rejected before copy.
- Boundary: offsets exactly at `srcLen` produce zero clone length; offset `srcLen+1` must remain unreachable through internal callers. If a public/internal caller is added, test this explicitly in assertion-enabled and release configurations.
- Unrelated: `ByteArray` clone path and sendable/shared ArrayBuffer implementations must not be conflated with ordinary `JSArrayBuffer` semantics; analyze them only with their own exact helper/source contracts.
- Identity: wrong commit, modified target blob, or helper/declaration mismatch must remain unbound/unknown; matching path/name alone is insufficient.
- Missing evidence: partial `js_arraybuffer.h`, missing helper bytes, parser refusal, or absent caller chain must remain partial/unknown, never pass/safe.

## Follow-up prompts and feedback flow

**Developer prompt (conditional only; no implementation is recommended by this no-go):**

```text
ROLE=ArrayBuffer lifecycle source analyst / conditional detector developer.
INPUT=task tree at current planning HEAD; this report; exact Ark source identity a65a2853ccae13da167d9aa4720ab8b11ec16656 and listed blob/SHA pins.
GOAL=independently try to falsify the no-go by finding one reachable, precise unsafe lifecycle/copy path; only if source evidence establishes it, propose a single source-bound candidate.
STEPS=verify clean source identity and all relevant helper/declaration identities; trace callers and release-build behavior for offset, detach, species callbacks, copy extents, and allocation bounds; inspect parser status and registered/direct-analysis baseline; compare safe/boundary/unrelated/wrong-identity/missing-helper controls; send expected matrix to tester before any implementation.
OUTPUT=short evidence report; default to no-go. If a candidate is established, provide one exact trigger/sink and a narrow expected-result matrix for independent replay.
STOP=one evidence-based no-go, or one concrete candidate returned for independent testing.
NEVER=edit Ark Runtime source, duplicate closed C-line cases, claim runtime/product impact or accuracy, or relabel unknown/not_run as pass.
```

**Independent tester prompt:**

```text
ROLE=independent adversarial ArrayBuffer source tester.
INPUT=exact source commit/tree/path/blob/SHA pins in this report; current task tree and detector model; developer matrix only if a candidate is proposed.
GOAL=challenge the no-go independently, or replay one proposed candidate and its fail-closed controls on the same scanner commit.
STEPS=verify source and helper identities; independently trace caller preconditions, integer conversions, allocator limits, detach/reentrancy checks and copy bounds; record parser statuses and current adapter/direct-analysis behavior; exercise safe empty/in-range, exact-boundary, unrelated implementation, wrong commit/blob, and missing/partial helper controls; if proposed candidate survives, replay through focused tests and registered CLI where feasible and return counterexamples to developer before closure.
OUTPUT=separate concise report with commands, exact identities, baseline/replay results, and explicit partial/blocked/unknown/not_run states.
STOP=one independent no-go confirmation or a concrete counterexample returned to developer.
NEVER=edit production detector/model, infer safety from zero findings, claim product impact/accuracy, or report unexecuted runtime checks as passing.
```

Feedback order: developer/source analyst shares a candidate and controls with tester; tester returns any mismatch before closure; developer adjusts only if evidence supports it; tester replays the exact resulting commit. A second-layer source review is useful only if one candidate survives that loop. This scout itself makes no runtime or product claim.
