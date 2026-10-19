# T6 IBS5YG runtime test matrix design

**Status:** design only; no build, PoC, or runtime execution performed.  
**Case:** `ARK-TYPEDARRAY-FILTER-RESULT-TYPE-ORIGIN-IBS5YG`  
**Purpose:** specify an auditable future source-pair test matrix for the existing static candidate. This document does not establish dynamic behavior, product inclusion, exploitability, or security impact.

## Frozen design basis

The source-level candidate is that `Filter` runs the callback before allocating the result, then the parent copy loop supplies the receiver's captured element type while storing into the species result. A callback can install a constructor/species which returns a same-ContentType TypedArray with enough elements but a different element width. In the narrow case, an `Int32Array` produces `n=3` accepted callback results and the species returns `Uint8Array(3)`. Source arithmetic predicts the final store at byte offset 8 with width 4, against 3 logical bytes. The reviewed source layout rounds the ByteArray data extent to 8 bytes, so a logical-bound check alone is insufficient to establish an allocation-boundary crossing. The fixed source selects the destination HClass element type before storing. These are static expectations to test, not runtime findings.

Two trigger sequences must remain separate:

1. **Callback-installed species (candidate sequence):** enter `Filter` with an `Int32Array`; from a callback, install the receiver constructor/species; return truthy for exactly `n` elements; let result construction occur after callbacks. Instrumentation must prove that the intended `Filter` stub is active and show whether callback-side mutation reaches species construction and the copy loop.
2. **Pre-call prototype mutation (published regression sequence):** preserve the official fixed regression input that changes the receiver prototype before calling `Filter`. This sequence may select a slow path and is not evidence that the callback-installed candidate path executed. Replay it as its own regression row and capture dispatch/path evidence.

## Test matrix

Run every applicable row against both frozen parent and fixed source builds with the same harness, flags, architecture, allocator mode, and input. Use fresh processes or fully reset isolates between rows. `n` means the exact number of truthy callback results and therefore the requested result length; record it rather than inferring it from input length.

| ID | Trigger and source pair | Species/result and boundary | Expected semantic observation | Required path / stub evidence | Memory-bound expectation |
|---|---|---|---|---|---|
| T6-01 | Callback-installed species; parent and fixed | `Int32Array`, `n=3`, species returns exact `Uint8Array(3)` | Record returned value/type/length or thrown exception. Parent source predicts the candidate store; fixed source predicts destination-width stores. Do not infer a write solely from a successful return. | Prove callback ran before species construction; record constructor/species calls, `Filter` builtin identity, fast/slow dispatch, `NewTypedArray` / species path, copy-loop entry, and each destination store's resolved type, index, byte offset and width. | Parent: guarded logical backing boundary must flag any store past byte 3; ASan should report only if actual instrumented allocation/redzone is crossed. Fixed: no store may cross logical or allocation boundary. Capture raw sanitizer and guard logs. |
| T6-02 | Callback-installed species; parent and fixed | `Int32Array`, `n=3`, same-type `Int32Array(3)` species | Normal successful result; verify values and type. | Same observations as T6-01; confirm destination element type is Int32. | No logical or allocation-boundary violation in either build. |
| T6-03 | Callback-installed species; parent and fixed | `Int32Array`, `n=3`, same-width cross-type `Float32Array(3)` species | Record values as bytes and elements; this isolates element-type mismatch from width mismatch. | Confirm the destination is Float32 and record the store type and width actually used. | No out-of-bounds write expected in either build because both widths are four bytes; semantic differences remain observable and must not be called a memory finding. |
| T6-04 | Callback-installed species; parent and fixed | `Int32Array`, `n=3`, BigInt-content species (for example `BigInt64Array(3)`) | Expect and record the specified content-type rejection/exception; confirm no result-copy stores occur after rejection. | Prove species constructor was attempted, rejection site/exception was observed, and copy-loop store count is zero. | No result allocation write beyond bounds; any partial result allocation must be tracked and have zero invalid stores. |
| T6-05 | Callback-installed species; parent and fixed | `Int32Array`, exactly `n=3` truthy results, species returns same-content `Uint8Array(2)` | Expect and record the insufficient-length rejection/exception; confirm copy loop does not write into a short destination. | Record requested length 3, returned species length 2, validation outcome and zero copy stores. | No invalid store in either build. If the engine accepts this input, stop and preserve the trace as a semantic discrepancy; do not continue to an uncontrolled write. |
| T6-06 | Callback-installed species; parent and fixed | `Int32Array`, `n=1`, species returns exact `Uint8Array(1)` | Record result and store details. This is a narrow boundary control: source arithmetic predicts a four-byte store at offset 0 while the logical backing length is one byte. | Prove candidate stub/path and capture the single store's type, offset and width. | Guard must report a logical-boundary violation if parent emits the predicted store. ASan may remain silent because allocator rounding can place the write within the physical object; absence of ASan alone is not a pass. Fixed must stay within logical bounds. |
| T6-07 | Callback-installed species; parent and fixed | `Int32Array`, `n=3`, species returns `Uint8Array(8)` | Record result and stores as a width/path control with sufficient logical destination storage. | Confirm exact destination byte length 8 and store sequence. | No logical-boundary violation expected; parent may still use Int32 stores. This row helps distinguish width mismatch from actual bound crossing. |
| T6-08 | Published regression input, before `Filter`; parent and fixed | Replay the exact `test/aottest/typedarrayfilter/typedarrayfilter.ts` input from the pinned fixed commit, unchanged | Record success/exception, returned object, type, length and values. Upgrade the original print-only signal with non-mutating assertions/trace where feasible; retain an unmodified replay too. | Independently record whether invocation enters the same Filter stub, a slow runtime builtin, or another path. Do not count this row as candidate-path coverage unless the exact store path is proven. | No invalid logical or physical write expected on fixed. On parent, report only measured behavior; this legacy sequence is not presumed equivalent to callback-installed species. |

## Guard and sanitizer protocol

- Prefer an instrumented build with ASan and a test-only guarded allocator or explicit redzones around the TypedArray data region. The guard must distinguish the logical data length from allocator-rounded object extent and report the first invalid byte, access width, and call stack.
- Add a store trace at the narrowest stable point that observes actual destination buffer, destination type, computed byte offset, write width, and caller path. Avoid using a source-level predicted offset as proof of an executed store.
- Record allocation identity, logical byte length, physical allocation range, redzone placement, allocation/free events, and whether the tested backing store is on-heap or external. If runtime layout cannot be observed reliably, mark the allocator-boundary result `UNKNOWN`.
- Run each case at least 20 times in fresh processes after the initial smoke replay, then retain every raw log; deterministic reproduction is useful but a single clean run does not establish absence of a conditional write. Keep the same seed and runtime flags across parent/fixed comparisons.
- A sanitizer silence is not a pass unless the tested store is covered by that sanitizer and the redzone encloses the actual backing allocation. A guard finding and ASan finding are separate observations.
- Stop a row immediately on unexpected acceptance of an invalid species, harness corruption, sanitizer abort, or loss of path instrumentation. Preserve the process output and crash artifacts; do not retry by weakening guards.

## Evidence and hash binding

Before any execution, create an immutable run manifest that binds each result to:

1. Case ID and matrix row ID.
2. Parent/fixed repository URL, commit, tree, source path, Git blob OID, raw source SHA-256, and verified ancestry. The current static-review identity is recorded below; revalidate it against the actual build inputs.
3. The exact test source and harness SHA-256, including a separate hash for the unchanged published regression replay.
4. Product identity and locked manifest digest if the run is product-targeted; otherwise explicitly label it a source-validation build and do not represent it as product evidence.
5. GN target, exact `args.gn`, build command, toolchain/compiler/linker/sysroot identities, generated/include closure, preprocessed translation units, macro log, binary SHA-256, and runtime/library hashes.
6. OS/kernel, architecture, allocator and sanitizer versions/options, environment variables, seeds, process/isolate reset strategy, and guard configuration.
7. Raw stdout/stderr, structured path/store trace, sanitizer report, guard report, exit status, and SHA-256 for every output/artifact. Hash the final manifest itself and keep it read-only after execution.

Static-review source identities already recorded (not proof that a future test binary uses these sources):

| Item | Commit | Path | Git blob | Raw SHA-256 |
|---|---|---|---|---|
| Parent Filter source | `2ea501258ab4155826b64f01b499b43d1911e0e2` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `054451b1be4f39254d56a1683cc9d1c1b5e55018` | `847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422` |
| Fixed Filter source | `919e4fbb011f610427e788889083fa8e28d2f951` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `95f54f2875f401afe3167c62f8c1e7799782be8c` | `8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e` |
| Official fixed regression input | `919e4fbb011f610427e788889083fa8e28d2f951` | `test/aottest/typedarrayfilter/typedarrayfilter.ts` | `ef25a446c3d91d3019a7fa09d6a9702fe8e670e6` | `510e8e96f06d585a98db5e6f32568568f5e7f1c6b87f379329032f779ebb3037` |

The review also binds shared helpers, including `new_object_stub_builder.cpp` SHA-256 `3fd7e99e957fb5b7793cb7c36c01b370208c05645aa93551da6abeecaf2e7198`, `js_typed_array.cpp` SHA-256 `e0fa7cb24aae9e3da6ac0bf6ea06972c9419dda83a6647cf3e62d9595997342f`, and `builtins_arraybuffer.cpp` SHA-256 `ccf5281e92af41022b25be409f7e69c5bb269a1ad2e32b4d01f9c73c57d42f08`. The test team must bind the complete helper closure to the actual built artifacts rather than inherit these hashes without verification.

## Execution admission gates

- **PC-1 case gate:** the IBS5YG source-to-target build profile must identify the exact product/build or be explicitly scoped as a non-product source validation. For product claims, require all case identity and build/preprocess fields from the approved profile contract, internally consistent and hash-bound. Portfolio PC-1 remains separate: one IBS5YG pass cannot close the 16-case portfolio.
- **PC-3:** establish the target product component mapping, reachable entry, privilege boundary, attacker-controlled input/trigger, sensitive operation and concrete CIA impact using case-bound evidence. If any remain unknown, product applicability stays blocked and no product result may be claimed.
- **PC-4:** execute against a product only with explicit authorization for the exact isolated target, test cases and containment/recovery conditions, after applicable PC-1 and PC-3 evidence passes. Source-validation testing must also have a controlled, disposable environment and recorded authorization from the project owner.
- **PC-5 follow-up:** only after a valid, authorized parent reproduction, build the fixed source under the same profile and compare the same harness, guards and controls. A source-pair test does not itself close fixed-product revalidation.

## Feedback and limits

Return the path trace, source/build manifest, raw bounds evidence and parent/fixed delta to L2. L2 should review whether the observed path matches the static candidate, whether callback-installed species was genuinely exercised, and whether the guard covers the actual backing allocation. Keep all unobserved behavior `UNKNOWN`; this design does not claim a runtime result or vulnerability finding.
