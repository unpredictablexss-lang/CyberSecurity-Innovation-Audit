# DataView API index-width independent baseline

## Scope and source identity

This report independently traces `BuiltinsDataView::GetViewValue`, `SetViewValue`, and the constructor invariants for the exact parent/fixed pair. It records source-level arithmetic and a registered-detector baseline; it is not runtime execution, a product claim, or a vulnerability verdict.

Sources were read directly from `D:\openHarmonyScanner\tmp\arkruntime-gitee-audit-20261023.git` using `git --git-dir <store> show <commit>:<path>`, with tree/blob IDs obtained by `rev-parse` and SHA-256 computed over the exact source bytes.

| Revision | Commit | Tree | `builtins_dataview.cpp` blob | SHA-256 |
|---|---|---|---|---|
| Parent | `d62f6de64daa7e11a7936a6153748a7c5fae9e41` | `a26f18bc7b1cd97fb926ae61b3655ddbf2caf8d1` | `e6bac984354292405ae62f7728170d7be5e3760e` | `bc01e0f8b8a2a5ab30d1478587b45a14aa8130d3d53dfb32b9513ff4d73bc38c` |
| Fixed | `48fcec3686e45175f95b4600b579026a65149966` | `6ff7f405071d29fc3ecf9bac1abd9d59a485909f` | `a2376e822e995333b2400520ca5b882de9578b5e` | `39b1ed79451980ad85e1176805deaf6c6315bca09d7676ea5c63f5ff1c4bd65b` |

These identities match the execution-tree pins. The developer and I were coordinating the source matrix against planning HEAD `85eb0948515e777d53996caf8f7ecb4b87897c90`. The planning worktree had since advanced to docs-only HEAD `a15faf8927651ee150030f23f543e85645a22071`; I confirmed the model and detector source files were unchanged between those commits, and ran the baseline against that current planning code.

## Conversion, widths, and source invariants

Parent `GetViewValue` (lines 353–368) takes `GetInt()` for tagged integers; otherwise it converts with `ToNumber` and calls `DoubleInRangeInt32`. It rejects a negative resulting `indexInt`, then casts the nonnegative int32 to `uint32_t`. Parent `SetViewValue` (lines 414–428) stores the index in `int64_t`; tagged integers still come from `GetInt()`, while non-integers go through `ToIndex` and then `DoubleInRangeInt32`, followed by a negative check and later `static_cast<uint32_t>(index)`. The pinned `DoubleInRangeInt32` implementation clamps values at/above `INT32_MAX` to `INT32_MAX`, values at/below `INT32_MIN` to `INT32_MIN`, and otherwise calls `DoubleToInt` (truncation toward zero). Thus, after the negative guard, both parent paths have `index <= INT32_MAX`. The getter and setter differ in conversion semantics: the getter uses `ToNumber`, while the setter uses `ToIndex` for the non-integer path. This report does not conflate those API differences with an out-of-bounds finding.

The fixed getter and setter use `uint64_t index`. A tagged integer path explicitly rejects negative values; the other path uses `ToIndex` and converts its result to uint64. The pinned `ToIndex` truncates, rejects results below zero or above `SAFE_NUMBER`, and admits nonnegative values through `SAFE_NUMBER`. Fixed paths retain that wider index through the bounds comparison; they narrow `index + offset` to uint32 only after the comparison passes.

`JSDataView::GetElementSize` maps types to widths 1, 2, 4, or 8 bytes. Parent `GetViewValue` checks `index + elementSize > size` at line 390; parent `SetViewValue` checks `static_cast<uint32_t>(index) + elementSize > size` at line 455. After the parent nonnegative conversion, the largest possible sum is `INT32_MAX + 8 = 2147483655`, below `UINT32_MAX = 4294967295`. Therefore the uint32 addition in either parent bounds check cannot wrap for these inputs. Exact equality to view size is permitted because the check is strict `>`.

The constructor reads the backing byte length into `uint32_t`. It converts byte offset and explicit view length through `ToIndex` into uint64, checks `offset <= bufferByteLength`, then checks `offset + viewByteLength <= bufferByteLength`; omitted view length is `bufferByteLength - offset`. Only after these checks does it store offset and view length as uint32 fields. The sum is formed in uint64. The ordinary `ArrayBuffer` and `SharedArrayBuffer` allocation entry points reject requested byte lengths greater than `INT_MAX`; equality passes that particular comparison, but backing allocation success at that size is not asserted here. `AllocateArrayBuffer` also checks the existing native ArrayBuffer area against a 4 GB limit and can reject before backing allocation. The APIs permit both ArrayBuffer and SharedArrayBuffer in the constructor.

Given those constructor invariants, when `index + elementSize <= viewSize`, the mathematical address interval satisfies `index + offset + elementSize <= bufferByteLength`. With the parent index bound and element sizes, neither the bounds addition nor the subsequent uint32 `index + offset` can wrap on that path. The fixed source establishes the same interval through a uint64 comparison and narrows the buffer index afterward. This is a source-invariant argument; mutation, resizable/external backing-store paths, allocation feasibility, and runtime sink behavior remain outside this report's proof.

## Boundary and control matrix

Let `w` be any supported width in `{1, 2, 4, 8}`, `S` the view length, `O` its byte offset, and `B` the backing buffer length. Rows describe source arithmetic, not allocations or runtime execution.

| Case | Inputs | Parent source behavior | Fixed source behavior |
|---|---|---|---|
| Ordinary valid access | `index=0`, `S=w`, `O=0`, `B>=w` | `0+w == S`; bounds check permits the sink | Same result after uint64 comparison |
| Last valid element | `index=S-w`, with `S>=w` and `O+S<=B` | Sum equals `S`; strict `>` check permits access | Widened sum equals `S`; permits access |
| Exact end control | `index=S-w` | Equality is permitted; `index+O` is within the constructed view | Same |
| First past end | `index=S-w+1` | Sum is `S+1`; with parent index bounded to INT32_MAX and `w<=8`, uint32 arithmetic does not wrap; the check rejects | uint64 sum exceeds `S`; rejects |
| Index at view end | `index=S` | `index+w>S`; rejects | Same |
| Negative integer control | `index=-1` | Negative check rejects before bounds/address arithmetic | Fast tagged-int check rejects, or `ToIndex` rejects negative input |
| Signed-boundary control | `S=INT32_MAX`, `index=INT32_MAX`, each `w` | Sum is `2147483648`, `2147483649`, `2147483651`, or `2147483655` for widths 1/2/4/8 respectively; all exceed `S` and remain below UINT32_MAX | Wide comparison rejects each value against `S` |
| Exact upper arithmetic control | `S=INT32_MAX+w`, `index=INT32_MAX`, `O=0` | Sum equals `S`; arithmetic guard permits it | Wide guard permits equality. Real backing/view feasibility is unknown; standard allocation path rejects sizes greater than INT_MAX |
| `INT_MAX` allocation-guard boundary offset with nonzero access | `B=INT32_MAX`, `O=INT32MAX-w`, `S=w`, `index=0` | Constructor/access bounds are equalities; buffer interval is half-open `[INT32MAX-w, INT32MAX)` | Same source interval; fixed narrowing is representable |
| `INT_MAX` offset, zero-length view | `B=INT32_MAX`, `O=INT32_MAX`, `S=0`, `index=0` | Constructor permits the empty view; every positive width fails the access bounds check | Same |
| Type-width control | `w=1,2,4,8` | Maximum checked sum is at most `INT32_MAX+8`, so below UINT32_MAX | uint64 arithmetic remains within range for admitted ToIndex values |

The boundary table assumes the source-level preconditions shown in each row. It does not claim that tagged-integer endpoints, maximum-size buffers, or views are constructible in a particular product build.

Conversion control: for a non-integer numeric request greater than `INT32_MAX`, the parent helper clamps to `INT32_MAX`; the fixed path retains the ToIndex result. With `S=INT32_MAX` (the largest byte length not rejected by the allocators' `INT_MAX` guard; actual allocation success is unverified), the parent clamp and fixed wide index both fail the bounds check for every positive width. If a wider backing/view exists through an unexamined path, these conversions can differ semantically—for example, for request `2^31` and `S=INT32_MAX+w`, the parent clamp reaches equality while the fixed index is one byte past the view—but the constructor interval invariant still bounds any access that passes the check. That is a conversion/API compatibility difference, not an OOB proof. Parent `GetViewValue` uses `ToNumber`; the setter and fixed paths use `ToIndex` for non-integer requests. No claim is made here about special-value or fractional conversion equivalence.

Malformed receiver control: both functions check that `view` is an ECMAScript object and has the DataView internal slot before index arithmetic; invalid receivers throw before reaching the candidate expressions. This is source control flow only.

## Registered detector baseline

I independently invoked `ArkRuntimeTypeSafetyDetector(model=RuntimeTypeModel())` through `run_all_with_coverage` on exact one-file contexts for each revision. Each source was parsed with `src.parser.ast.parse_source(..., 'cpp')` (`parse_status=complete`, zero parser issues), and each context carried the exact Git blob OID, source SHA-256, repository `openharmony/arkcompiler_ets_runtime`, commit, `provenance='git_object'`, and `profile_id='light-ast'`.

| Revision | Diagnostic output | Report status | Coverage |
|---|---|---|---|
| Parent | 2 candidates: `ark.runtime.dataview-index-width-bounds` at `GetViewValue` line 394 and `SetViewValue` line 455 | `blocked` | 1 applicable/inspected file; 1 partial, 0 analyzed; `detector_model_incomplete` |
| Fixed | 0 diagnostics; limitations name `DataViewConstructor`, `GetViewValue`, and `SetViewValue` as not fully proven | `blocked` | 1 applicable/inspected file; 1 partial, 0 analyzed; `detector_model_incomplete` |

The aggregate report explicitly says coverage is incomplete and safety must not be inferred. The parent findings remain candidates, not confirmed memory-safety defects. The fixed zero-diagnostic result is unknown/partial, not a safe verdict. The developer received the independent source matrix and this pre-change baseline before implementing any model changes. This is the registered detector baseline; no C++ runtime execution was performed.

I also added the same-revision `ecmascript/builtins/builtins_arraybuffer.cpp` as an unrelated-path control in a two-unit context. Parent still returned the two DataView candidates; fixed still returned zero diagnostics. For both revisions, the sidecar reported two applicable files, inspected only `builtins_dataview.cpp`, and marked `builtins_arraybuffer.cpp` not analyzed because that source identity/path is not a reviewed target binding for this detector. This is a scope-exclusion control, not evidence that the unrelated file is safe.

## Limits

The constructor invariant and integer bounds prove a narrow source-level arithmetic property for these code paths. They do not establish all runtime configurations, backing-store mutation behavior, actual allocations at `INT_MAX`, product reachability, or security impact. The detector's own `detector_model_incomplete` result further limits its coverage. No formal precision/recall or product-safety claim is made.
