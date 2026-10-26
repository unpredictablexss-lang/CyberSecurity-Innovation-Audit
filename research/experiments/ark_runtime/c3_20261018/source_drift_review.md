# C3 frozen-rule source drift semantic review

Date: 2026-10-18 (Asia/Shanghai)

## Decision

This review applies the audited C1 profile manifest (blocked; see profile artifact) and covers the 18 changed supporting dependencies in the frozen `ohscanner.ark.runtime.type_safety` model input set. Each is **unknown** for semantic impact. The source review establishes changed Git blobs and identifies changed semantic boundaries, but it cannot establish the full compiled declarations, macros, types, call graph, and control flow under the requested C1 audited build/preprocessing profile.

The reviewed C1 source evidence records exact source commits and blobs. The audited build/preprocessing profile supplied for this review is `research/experiments/ark_runtime/c3_20261018/build_profile.json` (`ark-runtime-build-profile-v1`), SHA-256 `6aea7ff0d37a726cf6d9e369316dac88f7645dd51de5189cf9aaac8c51525a98`. Its recorded status is **blocked**: no exact compile database, GN args, Ninja graph, target command, resolved macro/include set, or successful preprocessed output is available. C3 `light-ast` reports `build_profile=none` and `macro_expansion=false`, so it cannot substitute for that profile. This is the principal blocker; a small textual diff or stable identifier cannot close it.

No rule/model changes or tuning were made. A rule change may be proposed separately after a specific semantic premise is demonstrated; evaluation under a new rule must wait for a new freeze.

## Scope and fixed identity

- Repository: `openharmony/arkcompiler_ets_runtime`.
- Old dependency binding: normally fixed commit `a0e30483ab3e4aead67ecfb5c708489915e447f9`; exception-guard rows retain their own old commits `c758818dbfd0b146a908d43d21f6ca1706c33783` and `81ca57487d04ea30cd11c271e86494a4e130f43e`.
- New dependency binding: commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`.
- Frozen detector/model: `ohscanner.ark.runtime.type_safety`, model `0.6.2`, model SHA-256 `662c74d79b75b2a111f7ec0eca4cb819a8b1f092ea3e9f7e6cff63621a3d8a1a`.
- The review's exact old/new commit, tree, path, blob OID, source byte count and source SHA-256 for every dependency are in `source_drift_review.json` and are recomputed by `verify_source_drift_inputs.py` from the local Git object store.

Rule paths being assessed:

1. Type origin: `StoreTypedArrayElement` / `StoreTypedArrayElementFromStoreIC` → TypedArray type identity and exemplar/token propagation → same-type creator guards.
2. Allocation and exception state: `NewTypedArray` / `NewTypedArraySameType` → allocation result and HClass → exception guard and subsequent HClass load/use.
3. Caller and sink: `Filter` and reviewed builtin/runtime wrappers → typed-array element read/write and caller argument flow.

The primary detector source `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` is a separate input from these 19 supporting dependencies. Its old/new bindings and changed caller/sink context are documented in `dependency-review-20261018.md`; its current parse is partial and does not supply a complete compile or CFG context.

## Per-dependency decisions

`unknown` below is the semantic-impact label. `source identity` is reported separately so a changed blob is not confused with a proven rule-semantic change. Row numbers refer to the exact old/new commit:path/blob table in `dependency-review-20261018.md`; full object and SHA-256 evidence is in the JSON artifact.

| # | Dependency / frozen-rule path | Source difference and semantic boundary | Decision and reason | Limitation |
|---:|---|---|---|---|
| 1 | `compiler/stub_builder.h`; loop/control-flow wrappers → dominance and sink reachability | Loop, break, continue and IR wrapper declarations changed. | **unknown** — control-flow construction can affect type-origin and exception-path dominance. | No profile-resolved declarations or CFG. |
| 2 | `compiler/stub_builder-inl.h`; call/effect wrappers → creator and value identity | `Alloca`, `Return`, `Bind`, `CallRuntime`, `CallStub` and typed predicate implementations differ. | **unknown** — same names do not establish equal purity, aliasing or exception effects. | No macro-selected implementation or effect proof. |
| 3 | `compiler/stub_builder.cpp`; branch/loop/suspend builders → guard dominance | `Jump`, `Branch`, loop and suspend construction contexts changed. | **unknown** — generated edges may alter exception paths and sink reachability. | No compiled graph or CFG. |
| 4 | `compiler/hcr_circuit_builder.h`; HClass predicates → type identity guard | `IsSpecial` / `IsJSHClass` predicate context differs. | **unknown** — input representation and generated predicate semantics are not established. | No build-resolved tagged-value types or macros. |
| 5 | `compiler/mcr_circuit_builder.h`; TypedArray predicate → identity/same-type guard | `TaggedObjectIsTypedArray` and related predicates differ. | **unknown** — directly touches TypedArray classification used by the frozen identity premise. | No exact compiled predicate semantics. |
| 6 | `compiler/lcr_circuit_builder.cpp`; load/store/allocation wrappers → creator result and type reads | `ReadSp`, `Alloca`, `StoreWithoutBarrier`, `Load` contexts differ. | **unknown** — wrapper changes can affect value flow, memory effects and allocation facts. | No preprocessed call path/effect summary. |
| 7 | `compiler/circuit_builder.cpp`; object/HClass operations → constructor/type guards | `Arguments`, `GetObjectType`, `StoreHClass`, `HasConstructorByHClass` and related contexts differ. | **unknown** — object identity and HClass state feed creator and guard assumptions. | No generated graph or complete caller conditions. |
| 8 | `compiler/new_object_stub_builder.h`; creator declarations → return identity/exception state | `NewTypedArray` / `NewTypedArraySameType` declaration surface differs. | **unknown** — declarations and overloads do not establish the returned object's identity or exception behavior. | Full definitions and profile-selected call sites not closed. |
| 9 | `compiler/builtins/builtins_stubs.cpp`; builtin wrappers → caller argument flow | `GetCallArg2`, `ArrayConstructor`, `MapConstructor` and wrappers differ. | **unknown** — caller path into the modeled creator/sink is not fully established. | No whole-program call graph. |
| 10 | `compiler/builtins/builtins_array_stub_builder.h`; builtin signatures → caller/overload selection | Array builtin declarations and wrappers differ. | **unknown** — cannot prove the changed overload surface is unrelated to modeled TypedArray callers. | No compile-resolved overload/call-site inventory. |
| 11 | `compiler/call_stub_builder.h`; call wrappers → call effects and value propagation | `CallCoStubBuilder` / `CallStubBuilder` declarations differ. | **unknown** — wrapper names do not establish selected overload or call effects. | No exact profile-resolved call boundary. |
| 13 | `base/typed_array_helper-inl.h`; type width mapping → allocation layout | `TypedArrayHelper::GetSizeFromType` differs. | **unknown** — type-to-size mapping directly affects allocation/layout premises. | Full profile-conditioned behavior not proved equivalent. |
| 14 | `base/typed_array_helper.cpp`; allocation/copy/validation → creator, type and exception path | `AllocateTypedArrayBuffer`, `CreateFromTypedArray`, `ValidateTypedArray`, `SortCompare` contexts differ. | **unknown** — several frozen semantic boundaries are affected. | No path-sensitive proof under the selected product configuration. |
| 15 | `stubs/runtime_stubs.cpp`; runtime creator → returned identity/effects | `TypedArrayCreateSameType` and runtime wrapper context differ. | **unknown** — runtime entry, return identity and exception behavior are not tied to the profile. | No selected runtime entry or execution evidence. |
| 16 | `js_typed_array.cpp`; property operations → element read/write sink | `DefineOwnProperty`, `OwnPropertyKeys`, fast get/set property paths differ. | **unknown** — surrounding conversions and access paths may affect sink behavior. | Exact caller relation and conditional build context incomplete. |
| 17 | `compiler/new_object_stub_builder.cpp`; creator/layout/guard → HClass and allocation | Existing diff review records glue-wrapper HClass reads, `contentType` `INT32`→`INT8`/`LoadPrimitive`, `StoreHClass`, and SameType fast-guard changes. | **unknown** — these are material to frozen creator, layout and identity premises; impact direction cannot be closed. | No profile-resolved declarations/macros/types/CFG. |
| 18 | `compiler/new_object_stub_builder.cpp`; exception guard → allocation then HClass use (old `c758…`) | SameType/TypedArray allocation and result-HClass path differs from the exact exception-guard parent binding. | **unknown** — guard dominance and exception state require the complete compiled path. | Independent old commit retained; exact build profile absent. |
| 19 | `compiler/new_object_stub_builder.cpp`; exception guard → allocation then HClass use (old `81ca…`) | Same path and new blob as row 18, but a distinct old commit binding. | **unknown** — row 18 evidence is not silently substituted for this old commit's input identity. | Independent old commit retained; exact build profile absent. |

Rows 1–11, 13–19 are the 18 changed source dependencies. Row 12, `compiler/profiler_operation.h`, is the sole unchanged dependency: old and new blob OIDs are identical, so its source identity is **unaffected**. It does not discharge any of the 18 changed dependencies' semantic obligations. The full 19-row inventory intentionally keeps row numbering aligned with the existing comparison manifest.

## Difference classes and coverage

- **Source identity:** 18 changed blob OIDs and source SHA-256 values; row 12 is byte-identical. Exact values are verified in the JSON artifact.
- **Syntax/declarations:** declaration and wrapper surfaces changed in rows 1–2, 8, 10–11. Source-level parsing alone cannot determine the product's selected declarations or overloads.
- **Semantic boundaries:** control flow/effects (1–3, 6–7, 11), type identity (4–5, 7, 13, 17–19), allocation/copy (6–8, 13–15, 17–19), and caller/sink (9–10, 14–16) are identified in the row evidence. These are impact paths, not proof that the frozen rule's result changes.
- **Build conditions:** all changed rows remain unknown because the exact C1 audited build/preprocessing profile is absent. No preprocessed output, macro inventory, build-selected target configuration, or include closure was available.
- **Not covered:** transitive compile dependencies outside the 19-row manifest; product packaging/target selection; runtime reachability and trigger conditions; CIA impact. The primary detector source remains separately reviewed and partial as described above.

## Reproduction and read-only checks

Run from the project root in WSL Ubuntu. The verifier reads pinned Git objects, validates the comparison manifest's expected old/new blob OIDs, computes SHA-256 over the actual blob bytes, captures each old/new commit tree, checks the 18/1 inventory, hashes the C1/C3 input artifacts, and rewrites only `source_drift_review.json`.

```bash
python3 research/experiments/ark_runtime/c3_20261018/verify_source_drift_inputs.py
```

Equivalent object inspection commands used by the verifier are read-only:

```bash
git -C /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime rev-parse '<commit>^{tree}'
git -C /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime rev-parse '<commit>:<path>'
git -C /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime cat-file blob '<blob-oid>'
```

Input artifacts whose SHA-256 values are captured: C1 `source_evidence.json`; C3 `model_dependency_comparison.json`, `dependency-review-20261018.md`, `current-run.json`, `dependency-gated-run-20261018.json`, and this review markdown. Verification output is stored in `source_drift_review.json`.

Read-only verification commands attempted in this session:

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c3-review && python3 research/experiments/ark_runtime/c3_20261018/verify_source_drift_inputs.py'
```

The command could not start WSL (host returned a WSL localhost/network startup error), so this session did not refresh Git object verification. Existing JSON object/hash records remain prior evidence and must be re-run in a working Linux/WSL environment before treating them as freshly verified. No network fetch, push, merge, Draft mutation, component-source mutation, frozen model edit, or rule tuning was performed.
