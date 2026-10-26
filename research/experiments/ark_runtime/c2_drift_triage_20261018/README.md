# C2 Ark Runtime dependency drift handoff

Date: 2026-10-18 (Asia/Shanghai)

## Scope and decision

P2/C2 static comparison preparation for `openharmony/arkcompiler_ets_runtime@a65a2853ccae13da167d9aa4720ab8b11ec16656` (tree `8781f036a3e7e04d8e0b34970d5f623b42875016`). The C-line checkout observed at HEAD `629e30cb8da581e55439a797852b221997154775`; its pre-existing dirty files/untracked evidence were preserved. At observation, existing changes were limited to the shared status/task-tree, C4/C7 research and the previously present C1/C5/C7 untracked paths; none were modified by this handoff. The Ark Runtime source checkout observed at the target commit/tree and clean.

Object evidence was recomputed from the local Git object database: all 19 manifest pairs match commit:path blob OIDs, tree IDs, raw blob byte counts and SHA-256; the exact function-context patch is included and per-diff hashes are indexed. Eighteen source blobs differ; row 12 is same-blob control. See [object_verification.json](object_verification.json), [triage_matrix.json](triage_matrix.json), [source-diffs.patch](source-diffs.patch), [all_old_ark_manifest_pins_20261019.json](all_old_ark_manifest_pins_20261019.json), and [verify_c2_evidence.py](verify_c2_evidence.py).

C1 selected hihope/rk3568. The two exact ARM compile actions pass preprocessing (-E), dependency scanning (-M), and macro dumping (-dM -E), all with return code 0, using generated retry3 outputs. Their preprocessed TUs, dependency lists, macro dumps, generated headers, compiler command hashes, and success observation are hash-bound below. C4 now verifies all 1,196 active dependencies and the recursively declared generated-input closure for these two actions. The full source archive omits 19 nested gitlink commit trees (16 have parent `.gitmodules` URLs; 3 have no declared origin) and one of five linkfile sources (`vendor/ohemu/common/qemu-run`) is missing; the generated graph also emits duplicate-output warnings and a full graph query remains blocked. A new complete-history search covers all three distinct old Ark commits represented by the 18 changed rows (`a0e304…`, `c75881…`, `81ca57…`): none is pinned by any of the 10,315 captured advertised refs or their 10,420 reachable commits. The ref list and commit graph hashes match the original full-history audit snapshot. This confirms that the recorded manifest history cannot supply a matching old product profile; it does not rule out third-party or unadvertised server objects. All 18 semantic statuses remain unknown because a profile-matched old revision and per-dependency semantic path evidence are still missing. No item is called unaffected from path/symbol resemblance. Frozen scanner/model/config were not changed.

## Exact new-revision profile activation map

The C1 retry3 evidence answers whether these exact new-revision files are in the two ARM target translation units. The verifier maps exact Git diff additions to source line markers in each preprocessed TU and separately checks each -M list. Added-line counts below are per action (action 1 / action 2); exact Git file-line and preprocessed-output-line ranges are in object_verification.json dependencies[].profile_context and triage_matrix.json dependencies[].exact_profile_context. A positive mapping proves inclusion/emission of new source lines only; it does not prove that the changed lines alter the frozen rule’s result or are reachable on a modeled path.

| Row | Dependency | In both ARM -M and .ii | New diff-added lines emitted (A1 / A2) | Semantic status |
|---:|---|:---:|---:|---|
| 1 | ecmascript/compiler/stub_builder.h | yes | 676 / 676 | unknown |
| 2 | ecmascript/compiler/stub_builder-inl.h | yes | 1349 / 1349 | unknown |
| 3 | ecmascript/compiler/stub_builder.cpp | no | 0 / 0 | unknown |
| 4 | ecmascript/compiler/hcr_circuit_builder.h | yes | 161 / 161 | unknown |
| 5 | ecmascript/compiler/mcr_circuit_builder.h | yes | 299 / 299 | unknown |
| 6 | ecmascript/compiler/lcr_circuit_builder.cpp | no | 0 / 0 | unknown |
| 7 | ecmascript/compiler/circuit_builder.cpp | no | 0 / 0 | unknown |
| 8 | ecmascript/compiler/new_object_stub_builder.h | yes | 29 / 29 | unknown |
| 9 | ecmascript/compiler/builtins/builtins_stubs.cpp | no | 0 / 0 | unknown |
| 10 | ecmascript/compiler/builtins/builtins_array_stub_builder.h | yes | 15 / 15 | unknown |
| 11 | ecmascript/compiler/call_stub_builder.h | yes | 37 / 37 | unknown |
| 13 | ecmascript/base/typed_array_helper-inl.h | yes | 4 / 4 | unknown |
| 14 | ecmascript/base/typed_array_helper.cpp | no | 0 / 0 | unknown |
| 15 | ecmascript/stubs/runtime_stubs.cpp | no | 0 / 0 | unknown |
| 16 | ecmascript/js_typed_array.cpp | no | 0 / 0 | unknown |
| 17 | ecmascript/compiler/new_object_stub_builder.cpp | no | 0 / 0 | unknown |
| 18 | ecmascript/compiler/new_object_stub_builder.cpp | no | 0 / 0 | unknown |
| 19 | ecmascript/compiler/new_object_stub_builder.cpp | no | 0 / 0 | unknown |

Observed in both target TUs: rows 1, 2, 4, 5, 8, 10, 11, 13. Not present in either of these two target TUs: rows 3, 6, 7, 9, 14, 15, 16, 17, 18, 19. The latter result is scoped to this target source’s two actions; it is not proof that the separate source files are unused by the product or semantically irrelevant to the detector. Rows 17–19 retain their distinct old exception-guard commits even though the new path is the same.

## New-profile product action census for non-target `.cpp` rows

The 3.9 GiB retry3 `compile_commands.json` was streamed in place and its full SHA-256 and byte count matched the C1 profile (`f4ac150e…19cee7e`, 4,103,004,071 bytes; 234,245 source entries). All eight unique changed `.cpp` paths outside the selected target TU have ARM product compile database entries: five actions each for `stub_builder.cpp`, `lcr_circuit_builder.cpp`, `circuit_builder.cpp`, `builtins_stubs.cpp`, and `new_object_stub_builder.cpp`; eight each for `typed_array_helper.cpp`, `runtime_stubs.cpp`, and `js_typed_array.cpp` (49 actions total). Rows 17–19 share the `new_object_stub_builder.cpp` action census but retain distinct old-source identities. Exact command strings, command hashes, output paths, and target triples are in `new_profile_product_action_census_20261019.json`; the capture script is `capture_new_profile_product_action_census.py`.

This establishes that GN exported current-profile ARM source compile actions for those files. It does not establish that those actions ran, which changed lines are active in them, their modeled caller/guard/sink relationship, the matching old-profile actions, or semantic impact. All 18 changed dependencies remain `unknown`; no `unaffected` conclusion is permitted.

## Bounded old-profile manifest search

The old Ark baseline commit is `a0e30483ab3e4aead67ecfb5c708489915e447f9` (2025-03-10, tree `82af11ced4297818410ccf61906b703d25b69165`). A reproducible search checked 12 locally materialized OpenHarmony release and March feature refs, plus the current origin branch inventory. None pins that exact Ark commit. The nearest HiHope candidate, `OpenHarmony-v5.0.3-Release`, uses `tag/manifest_tag_20250320_101213.xml` and pins Ark Runtime to `637821232cb94231ed09c7df528a3a8a811feffa`; that commit is not a descendant of the C2 old baseline. Its HiHope board/vendor pins therefore do not make it a matching old profile. That initial local-ref audit is now supplemented by a complete bare mirror audit of all 10,315 refs advertised by the recorded GitCode manifest remote and all 10,420 reachable commits. No exact pin was found. This result is scoped to advertised refs at capture time; third-party repositories and unadvertised or unreachable objects remain outside scope. Machine-readable evidence and capture script are `full_manifest_history_audit_20261019.json` and `audit_full_manifest_history.py`; the earlier bounded audit remains in the evidence chain for provenance. The matching old product profile is still unresolved.

Accordingly, old-profile actions and semantic IR/CFG comparison remain unavailable; all 18 changed rows remain `unknown`.

For every active row, the per-row minimum chain in `exact_profile_context.minimum_missing_proof` is now: obtain profile-matched old revision context, trace changed definitions to concrete callers/guards/sinks, and compare old/new IR/CFG or equivalent effect evidence. For every inactive row, first locate that path’s actual product compile action in both revisions and trace its caller/registration chain. C4 now binds the selected new-profile dependency closure; these remaining gaps keep every changed dependency unknown.

## Per-dependency static triage

### 1. `ecmascript/compiler/stub_builder.h` — **unknown**

- **Objects:** row 1 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/compiler/stub_builder.h` blob `b784eb0812c27f11c1bfd8673cda4bf884a6a9cd`, source SHA-256 `37757e96a98a20c3598af837d27003912d0f41a6a633e5ec99c04078ef2c8c1d`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/stub_builder.h` blob `9e2fbd3ede1da91133dcd936018285e597944515`, source SHA-256 `a11ca83c0a8bbe16ea4ce9dabb2ab3aca2ee9c680a95433371e79494e2a92cb0`. Diff SHA-256 `bf197a9aff06347c5962d30804b6ec67576c5bc68870d9ab7b9153ad64b784fc` in `source-diffs.patch`.
- **Observed source facts:** Declaration/wrapper surface and loop/control-flow helpers differ; prior review locates function-context changes around new lines 126–1666. Symbols/constructs: `StubBuilder IR wrapper declarations; LoopOptions, IR_WHILE, IR_BREAK, IR_CONTINUE`.
- **Static inference only:** Changed IR construction APIs can alter loop edges, dominance or exception/sink reachability if these wrappers are selected by the target build; this is a hypothesis, not a CFG finding.
- **Requires effective profile:** Which wrapper declarations and macro branches are active in the exact compile, and what call sites construct the modeled paths?
- **Minimum follow-up evidence:** Old/new target compile commands and preprocessing for this header’s consuming translation units; include closure; resolved wrapper declarations/types; CFG or IR dump for relevant creator and sink paths.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 2. `ecmascript/compiler/stub_builder-inl.h` — **unknown**

- **Objects:** row 2 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/compiler/stub_builder-inl.h` blob `8658e6ee729c3b171639772ad3a1ada06442abd0`, source SHA-256 `a41ac4bc896fc56c93176b80590620976f0fedd8105bff61f30d9548b0da2520`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/stub_builder-inl.h` blob `c0521ab7a55cd63850736c2db8a290115965373c`, source SHA-256 `e3e840771be228a2c5e6c15576ecdf3f06175622b5840525520345f1d22d76be`. Diff SHA-256 `71da8cf96278a9323f64e4d8f8214379f42c52313d1e5608c1c136f815dff1e9` in `source-diffs.patch`.
- **Observed source facts:** Inline wrapper implementations/signatures differ across the exact blobs; prior review inspected new hunks 60–1006. Symbols/constructs: `Alloca, Return, Bind, CallRuntime, CallStub, typed predicate wrappers`.
- **Static inference only:** Call effects, alias/value propagation and exception behavior may differ; identical wrapper names do not establish identical effect summaries.
- **Requires effective profile:** Which inline implementation is selected, and what are its resolved argument/result types and call effects at modeled call sites?
- **Minimum follow-up evidence:** Exact preprocessed header for both revisions; active macro/overload definitions; target call sites plus generated IR/effect evidence for the modeled operations.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 3. `ecmascript/compiler/stub_builder.cpp` — **unknown**

- **Objects:** row 3 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/compiler/stub_builder.cpp` blob `8aae4bfa151e8b8dbd58d03a5cd881f3315151c2`, source SHA-256 `6a58a43a3bc1dd018acb57bf54b8c85bda5bbf197eedf7f4fd41dd63941799b8`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/stub_builder.cpp` blob `c630a6200215705843d11c0dd86c565709e8c6c4`, source SHA-256 `978f507daa99982b115f2db4e63ce629c653f011b4b998ac9e20255ab786b25a`. Diff SHA-256 `c3927e93f113fabb63e95c6d725c10a45311cca71f66c474d7d8eace1a954be6` in `source-diffs.patch`.
- **Observed source facts:** Branch/jump/loop/suspend builder bodies differ at reviewed new hunks around 55, 83, 148, 186 and 222. Symbols/constructs: `Jump, Branch, LoopBegin, CheckSuspend, LoopEnd`.
- **Static inference only:** Constructed graph edges or suspend/safepoint placement may affect guard dominance and sink reachability; source diff does not establish the resulting graph.
- **Requires effective profile:** Under the selected profile, what CFG edges and exception/suspend paths are generated at the affected callers?
- **Minimum follow-up evidence:** Old/new exact compile commands, active macros/types and IR/CFG dumps of affected creator/caller functions, including exception and suspend edges.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 4. `ecmascript/compiler/hcr_circuit_builder.h` — **unknown**

- **Objects:** row 4 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/compiler/hcr_circuit_builder.h` blob `176dd0a5ee320f814049c2b671119515c746380d`, source SHA-256 `c43c0a5de7474f763ca1c37e2276e5129e911324c31993c3043d5441f1758c51`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/hcr_circuit_builder.h` blob `e66c414a7a739284b474c234e6f90bae0368cd11`, source SHA-256 `380940bddd7790a8c65e5297ed0646ff2dd5301b2a1197fa78b3766ab8653497`. Diff SHA-256 `2c8617f1776607cfb4d13284e7cee490a8278d9d6fdda4ffb7e7caadec43e6e7` in `source-diffs.patch`.
- **Observed source facts:** Type-predicate implementation/context differs in the exact header blobs (reviewed new lines 25–37). Symbols/constructs: `CircuitBuilder::IsSpecial, CircuitBuilder::IsJSHClass`.
- **Static inference only:** The predicate may classify a different input representation or emit different checks; the symbol name alone cannot establish type equivalence.
- **Requires effective profile:** What are the active parameter/value representations, predicate definitions and macro-selected branches?
- **Minimum follow-up evidence:** Preprocessed declarations/definitions and resolved tagged-value/GateRef types for both revisions, plus the call sites feeding these predicates.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 5. `ecmascript/compiler/mcr_circuit_builder.h` — **unknown**

- **Objects:** row 5 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/compiler/mcr_circuit_builder.h` blob `631911dec663addd62533d6a6808ffe699a6f884`, source SHA-256 `a92932e25ab94f020403bdfd30a5848076bcd444e587461b61d3630805de5ba9`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/mcr_circuit_builder.h` blob `297a46c06349c0ed7e881ee4475291a41361f743`, source SHA-256 `15d10575db365d6f938b1af4832f1afc65ea7bedb52f5685f4e1c411a500ebe0`. Diff SHA-256 `fbface0ec820aaf0153981641ce9acf3d6173e8c450b830c89de81876b2b3b61` in `source-diffs.patch`.
- **Observed source facts:** TypedArray/tagged-type predicate surface differs; prior review places the primary predicate at new line 399 onward. Symbols/constructs: `CircuitBuilder::TaggedObjectIsTypedArray and related tagged predicates`.
- **Static inference only:** This boundary directly participates in TypedArray identity classification, but no target-profile representation or predicate truth conditions are established.
- **Requires effective profile:** Which tag bits, HClass/type checks and target macros define the predicate, and which modeled creator guards consume it?
- **Minimum follow-up evidence:** Exact preprocessed predicate definitions, underlying tag/HClass declarations and layouts, and resolved caller/guard sites for old and new revisions.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 6. `ecmascript/compiler/lcr_circuit_builder.cpp` — **unknown**

- **Objects:** row 6 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/compiler/lcr_circuit_builder.cpp` blob `af4d27bcd46ea0a4a2980a805dd7de77970ffb56`, source SHA-256 `838a127ac98866a44f73ff71b574820b7175b8424a0fbb1fda0dfb3cedfd1739`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/lcr_circuit_builder.cpp` blob `a6df4cba87c9a49f09a292648e7ea7d7cad1b24c`, source SHA-256 `4575cf4b84cef1046cf617d5328bd1c2c61b5a29f4550b4cbfba5b8ba4d289db`. Diff SHA-256 `71f387181b2e3580df3885eafecf1363f8788c9e3df2c2dc17ba29b4730eb6e5` in `source-diffs.patch`.
- **Observed source facts:** IR memory/allocation wrapper contexts differ (reviewed new hunks 63–302). Symbols/constructs: `ReadSp, Alloca, StoreWithoutBarrier, Load`.
- **Static inference only:** Pointer width, memory attributes, barrier behavior or value flow may differ in ways relevant to allocation and type reads; no generated operation is inferred.
- **Requires effective profile:** What active overloads, type widths, memory attributes and barriers are generated under the product toolchain?
- **Minimum follow-up evidence:** Exact profile preprocessing plus old/new resolved API/types and IR for affected creator allocation/load/store call sites; include target ABI and relevant memory-attribute definitions.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 7. `ecmascript/compiler/circuit_builder.cpp` — **unknown**

- **Objects:** row 7 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/compiler/circuit_builder.cpp` blob `b4bf452cac6bdeb820b78334be98cb3dc11330cb`, source SHA-256 `beb2668526a760d30c2fe8ae181a1cd5544a45d4b6bf888d92f96fb10452077c`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/circuit_builder.cpp` blob `225f09385632bfc2a6ff20bbdf2bfd8694fcffb6`, source SHA-256 `33fac8872f897163ec8261674cad91e8722609e005732a30d675628145974a29`. Diff SHA-256 `64f8811d81c53661ab64882b1f0c8bad0f045bb7100b9ccd2ee55be554e8f8d3` in `source-diffs.patch`.
- **Observed source facts:** Object/type/HClass builder implementations and contexts differ (reviewed new hunks 29–715). Symbols/constructs: `Arguments, IsJsCOWArray, GetObjectType, StoreHClass, HasConstructorByHClass`.
- **Static inference only:** Object identity, HClass updates, constructor checks or argument flow could affect modeled guards; source-level names do not prove use or dominance.
- **Requires effective profile:** Which definitions and representation/layout are active, and do affected HClass writes/reads dominate or reach the modeled checks?
- **Minimum follow-up evidence:** Exact preprocessed definitions/types and all target call sites; generated IR/CFG around HClass reads/writes, constructor guard and exception branches.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 8. `ecmascript/compiler/new_object_stub_builder.h` — **unknown**

- **Objects:** row 8 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/compiler/new_object_stub_builder.h` blob `f411d72cbca7915e56b9d851beeb57b788e438ac`, source SHA-256 `4b2d3586c0df13bdc25a2b029cc6a445c6f6bc1b95349968ca2b221df6779bb4`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/new_object_stub_builder.h` blob `ecdf871b20e884e013ce0f26877ef404e4950cb0`, source SHA-256 `d84a72bb1a252fb9ea2b8ff01e702c3a0c952681e211d8f1a850f1880217778b`. Diff SHA-256 `ce57a58821a32fbb1826f454ac3393e9c686c491b9b683a3901993e1ca594874` in `source-diffs.patch`.
- **Observed source facts:** Creator declaration/overload surface differs (reviewed header hunks 32–194). Symbols/constructs: `NewTypedArray, NewTypedArraySameType, allocation helper declarations`.
- **Static inference only:** Arity, overload resolution, return identity and exception contract may differ; declarations do not establish definitions or actual call selection.
- **Requires effective profile:** Which declarations/definitions are active and which overloads are selected by modeled callers?
- **Minimum follow-up evidence:** Generated/preprocessed declaration closure and definitions for both revisions; compile-resolved call sites with argument/result types and exception contract.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 9. `ecmascript/compiler/builtins/builtins_stubs.cpp` — **unknown**

- **Objects:** row 9 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/compiler/builtins/builtins_stubs.cpp` blob `715c5d65164369bc93a82aa4a6cc1d19b7970143`, source SHA-256 `64263f8d75dae7f7f924d9e34fb7a41e2180ae4e6f73e16f1c139e79987e4e76`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/builtins/builtins_stubs.cpp` blob `f9c026f6b732cf090aca9df620c4d79bf7597f3b`, source SHA-256 `58f8c8b2183735dd41ef96ceb47d9cd7de0e9e13b76b4a4338f48493d9502e82`. Diff SHA-256 `a1a3ab8eadad8764bab592f7117779ed13ab3c23e49a11360c8339703b8cc397` in `source-diffs.patch`.
- **Observed source facts:** Builtin wrapper/caller contexts differ (reviewed new hunks 160–646). Symbols/constructs: `GetCallArg2, ArrayConstructor, MapConstructor and builtin wrappers`.
- **Static inference only:** Argument propagation into creator/sink may differ, but whole-program reachability and selected wrapper are not established.
- **Requires effective profile:** Do these wrappers occur on the modeled TypedArray caller chain for the exact product target?
- **Minimum follow-up evidence:** Profile-resolved call graph or compiler call-site evidence from reviewed builtin entry points to creator/sink, with argument types and active declarations.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 10. `ecmascript/compiler/builtins/builtins_array_stub_builder.h` — **unknown**

- **Objects:** row 10 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/compiler/builtins/builtins_array_stub_builder.h` blob `88e131561f756db9bd9e57b3078df22ac3c34c6a`, source SHA-256 `c665d4e13208dc00e809331e13a0135b5ae4c63f9c47f4e99e85dc51eb491ee2`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/builtins/builtins_array_stub_builder.h` blob `c9b5a66c12c657533047286ec79406a639fb8232`, source SHA-256 `1804426bca64803a2a7b70c63004eb5236718daa075c67d74c68fd5f21ef151c`. Diff SHA-256 `b6e105eba9f2553830e4914843b6ab18375c0a63c931f0872761e42eafd048e7` in `source-diffs.patch`.
- **Observed source facts:** Array builtin declaration/signature surface differs (reviewed hunks 27–226). Symbols/constructs: `Array builtin declarations and wrapper signatures`.
- **Static inference only:** The change may alter overload or caller boundary selection; unrelatedness to TypedArray paths is not established.
- **Requires effective profile:** Which changed declarations are included and selected by current callers under the target defines?
- **Minimum follow-up evidence:** Preprocessed declarations and resolved callers/overloads for each changed wrapper; include generated declarations and compile-time conditions.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 11. `ecmascript/compiler/call_stub_builder.h` — **unknown**

- **Objects:** row 11 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/compiler/call_stub_builder.h` blob `f1f44f44679a9a6d648c8dd0182864d4af7c24f7`, source SHA-256 `3bcb06509efea7261bdaef4c108e31281275c8eff4cbbda24632d710edc98d21`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/call_stub_builder.h` blob `d1fb1b9ef28ff8c928a6e8dfdd9aed67e42ef6aa`, source SHA-256 `18af6653e22c36dc1fce30d9b7b7eda9d616084add2b1c6d1faa6d89c6c895ae`. Diff SHA-256 `c1d35cd60ce908eb9536de8759af5246bc27033af5ac8235b0d295dbe3c1cdbc` in `source-diffs.patch`.
- **Observed source facts:** Call-wrapper declarations differ (reviewed hunks 112–273). Symbols/constructs: `CallCoStubBuilder, CallStubBuilder`.
- **Static inference only:** Call boundary, effects and argument/value propagation may change; method-name correspondence cannot establish selected overload/effect.
- **Requires effective profile:** Which overload is instantiated at relevant call sites, with what callee/value and effect behavior?
- **Minimum follow-up evidence:** Exact preprocessed declaration set, concrete old/new call sites and resolved argument/result types; IR/effect summary at the modeled calls.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 13. `ecmascript/base/typed_array_helper-inl.h` — **unknown**

- **Objects:** row 13 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/base/typed_array_helper-inl.h` blob `3adadba4324927a18ff715efa99b2aa9cd15bc41`, source SHA-256 `ed9bc1df7a3c1a4c30046710a9a28c5d74e2fc0e56e21da1de1d752006635fc4`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/base/typed_array_helper-inl.h` blob `172fa188b64ed23d0714c4f4cd0ef66bcbb8e1cf`, source SHA-256 `ecad66a6acb1a19f4eed9b84ce9f86f565348ad0be8c3411643ebace7a8ee559`. Diff SHA-256 `cf7a212774ad98d56d81070cb9b13c7ecdde1497151c2bb195c3811215b31551` in `source-diffs.patch`.
- **Observed source facts:** Type-to-size mapping function differs (prior review places old/new function context around line 482). Symbols/constructs: `TypedArrayHelper::GetSizeFromType`.
- **Static inference only:** Element-width/layout assumptions can be affected; no profile-conditioned mapping equivalence or allocation consequence is proven.
- **Requires effective profile:** Which enum values, element types and macro-selected mapping entries apply to the product ABI?
- **Minimum follow-up evidence:** Exact enum/type definitions, preprocessed mapping body, old/new callers and target element-width/layout definitions under the selected profile.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 14. `ecmascript/base/typed_array_helper.cpp` — **unknown**

- **Objects:** row 14 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/base/typed_array_helper.cpp` blob `17f4b8f50ea126eb646ef011e9b7fa7e461394dc`, source SHA-256 `0704698674d39389525de7ccca0941138fc0bb4a84d3acdf0f14544a119558a3`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/base/typed_array_helper.cpp` blob `bcb422fe67f4e670adcca31fffd4da7e2b3b0b21`, source SHA-256 `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d`. Diff SHA-256 `e558307764f0fb8ef59c89c5cb7dabed353b592bb9b110d47b8d3a863d44c261` in `source-diffs.patch`.
- **Observed source facts:** Allocator/copy/validation/comparison implementations differ across reviewed new hunks 31–1180. Symbols/constructs: `AllocateTypedArrayBuffer, CreateFromTypedArray, ValidateTypedArray, SortCompare`.
- **Static inference only:** Creator identity, source type, allocation and exception flow are plausible impact boundaries; reachability and path effects remain open.
- **Requires effective profile:** Which changed branches are compiled and reached from modeled creator/sink paths, and what types/exception edges result?
- **Minimum follow-up evidence:** Exact preprocessing and definitions/types for these functions; profile-resolved caller chain, CFG/IR for allocation/copy/validation failure and exception paths.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 15. `ecmascript/stubs/runtime_stubs.cpp` — **unknown**

- **Objects:** row 15 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/stubs/runtime_stubs.cpp` blob `c7ce18a76e25289ee7274354fd85950fa9b17af8`, source SHA-256 `0a11c3832d2d4a0b1adf0879a01e1cbde40a62885f2702dff316985838c135a3`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/stubs/runtime_stubs.cpp` blob `14dc06350881b1fa0fdabeeb8465ae9063224d6c`, source SHA-256 `0c390fb329387ff75943089da0e7eecab4bc1df21da1be4f33db969b2bf79a46`. Diff SHA-256 `5d19f9eca48bb82d8dd6b2dd0ecc841fb0f25bb81d68cb85bdd577bf45bd00db` in `source-diffs.patch`.
- **Observed source facts:** Runtime creator and wrapper contexts differ (reviewed new hunk starts around line 306). Symbols/constructs: `TypedArrayCreateSameType and runtime wrappers`.
- **Static inference only:** Returned-object identity, runtime dispatch and exception/effect behavior may differ; selected runtime entry is not known.
- **Requires effective profile:** Which runtime stub is registered/selected by the product and what exact value/type/exception contract does it implement?
- **Minimum follow-up evidence:** Generated runtime-stub registration/declaration closure, exact preprocessed body, callers and resolved return/exception behavior in the selected product.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 16. `ecmascript/js_typed_array.cpp` — **unknown**

- **Objects:** row 16 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/js_typed_array.cpp` blob `892e376de57c08c768831936503a8e4dac4b39bb`, source SHA-256 `e0fa7cb24aae9e3da6ac0bf6ea06972c9419dda83a6647cf3e62d9595997342f`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/js_typed_array.cpp` blob `098c2a22cae3152af3a59063dda25e145f03bbd7`, source SHA-256 `e67c0ce082885efb6fa5894f7a1998a41eb4cddfa2e381c8335497e10e2b9bbe`. Diff SHA-256 `9dc1a6a2a3da7616c5bf5c809a3ad550de642c1e09614642456ed555c90d3683` in `source-diffs.patch`.
- **Observed source facts:** TypedArray property read/write and surrounding conversion/access paths differ (reviewed new hunks 71–847). Symbols/constructs: `DefineOwnProperty, OwnPropertyKeys, FastGetPropertyByIndex, FastSetPropertyByIndex`.
- **Static inference only:** Sink behavior or value conversion may be affected, but relationship to the modeled sink and active conditional branches are not closed.
- **Requires effective profile:** Are changed access paths on the exact modeled caller/sink chain, and which conversion/type branches are active?
- **Minimum follow-up evidence:** Exact preprocessing, resolved caller/callee chain, key/value types and CFG for the changed read/write methods and modeled sink.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 17. `ecmascript/compiler/new_object_stub_builder.cpp` — **unknown**

- **Objects:** row 17 in `object_verification.json`: old `a0e30483ab3e4aead67ecfb5c708489915e447f9 (tree 82af11ced4297818410ccf61906b703d25b69165):ecmascript/compiler/new_object_stub_builder.cpp` blob `757b8d050d306d349822600deacb295c7a54245e`, source SHA-256 `3fd7e99e957fb5b7793cb7c36c01b370208c05645aa93551da6abeecaf2e7198`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/new_object_stub_builder.cpp` blob `991ac5ac034a1a027e3200787ec25c55b3f15b69`, source SHA-256 `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0`. Diff SHA-256 `281db9260a37a6114a300de1c24ddfe4bea9fefd7a6793ac155ad877ebd17fd5` in `source-diffs.patch`.
- **Observed source facts:** Creator bodies differ: HClass reads use glue wrappers; contentType load/store changes from INT32 to INT8/LoadPrimitive; young-space StoreHClass and SameType fast guard change (reviewed hunks 2843–2970, 3092+). Symbols/constructs: `NewTypedArray, NewTypedArraySameType, NewTypedArrayFromCtor`.
- **Static inference only:** These edits intersect type identity, allocation layout and result guard assumptions; width/guard effect depends on actual declarations, ABI and generated control flow.
- **Requires effective profile:** What field type/offset and HClass check are active in hihope/rk3568, and what branches dominate result HClass use?
- **Minimum follow-up evidence:** Exact old/new preprocessing and declarations, generated layout/offset definitions, resolved load types, creator callers, and IR/CFG including allocation exception guards.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 18. `ecmascript/compiler/new_object_stub_builder.cpp` — **unknown**

- **Objects:** row 18 in `object_verification.json`: old `c758818dbfd0b146a908d43d21f6ca1706c33783 (tree 5d7c18a5d5ccbf48617b3c07ae9353f5f427d07a):ecmascript/compiler/new_object_stub_builder.cpp` blob `05dda56de74949f07a241942be6465beaf94b52a`, source SHA-256 `c10e934be1804fe9388d599cba54369eed4ee150b078d04924e0da68a2f43b9e`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/new_object_stub_builder.cpp` blob `991ac5ac034a1a027e3200787ec25c55b3f15b69`, source SHA-256 `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0`. Diff SHA-256 `e080f54e466b74da4de49b9c2cc0b0c72a5fd8b2ee4b861d794c2b40084d1357` in `source-diffs.patch`.
- **Observed source facts:** Exact old binding is c758…; new blob matches row 17 new blob. The creator/allocation/HClass source interval overlaps reviewed new hunks 2843–2970. Symbols/constructs: `NewTypedArray, NewTypedArraySameType; allocation then result-HClass read`.
- **Static inference only:** The modeled NewTypedArray(4) → LoadHClass exception-state premise may be affected; no guard dominance or path equivalence is established for this independent old commit.
- **Requires effective profile:** Under the corresponding old and target product profile, does allocation failure/exception return dominate every HClass read?
- **Minimum follow-up evidence:** Independent c758 old-source preprocessing/type closure and new target profile output; resolved allocation call, exception state and CFG proof around every LoadHClass use.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

### 19. `ecmascript/compiler/new_object_stub_builder.cpp` — **unknown**

- **Objects:** row 19 in `object_verification.json`: old `81ca57487d04ea30cd11c271e86494a4e130f43e (tree f0ddee8ee7f74b3f22e45b174ce96a269b2e57a5):ecmascript/compiler/new_object_stub_builder.cpp` blob `05dda56de74949f07a241942be6465beaf94b52a`, source SHA-256 `c10e934be1804fe9388d599cba54369eed4ee150b078d04924e0da68a2f43b9e`; new `a65a2853ccae13da167d9aa4720ab8b11ec16656 (tree 8781f036a3e7e04d8e0b34970d5f623b42875016):ecmascript/compiler/new_object_stub_builder.cpp` blob `991ac5ac034a1a027e3200787ec25c55b3f15b69`, source SHA-256 `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0`. Diff SHA-256 `e080f54e466b74da4de49b9c2cc0b0c72a5fd8b2ee4b861d794c2b40084d1357` in `source-diffs.patch`.
- **Observed source facts:** Exact old binding is 81ca…; its old blob equals row 18 but commit/tree binding is distinct; new source is the same target blob. Symbols/constructs: `NewTypedArray, NewTypedArraySameType; allocation then result-HClass read`.
- **Static inference only:** Same bytes in old row 18 do not supply the complete commit/profile context for this binding; exception guard/effect remains unknown.
- **Requires effective profile:** Does this exact 81ca commit resolve the same declarations/macros/parents, and does exception guard dominate each HClass use?
- **Minimum follow-up evidence:** Independently bind 81ca tree/include/generated inputs and old/new preprocessed TUs, then provide call and exception CFG context for allocation and HClass reads.
- **Status:** semantic `unknown`; the exact new-profile line activation is indexed in exact_profile_context, but old-profile comparison and the modeled semantic chain remain unproven.

## Carry-forward rules

- The exact new-revision profile context is now mapped for every row against both ARM TUs. Rows 1, 2, 4, 5, 8, 10, 11 and 13 have diff-added lines emitted in both preprocessed outputs; rows 3, 6, 7, 9, 14, 15, 16, 17, 18 and 19 are absent from both target TUs. Use the line ranges and per-row missing-proof records in the machine-readable evidence.
- For active files, obtain matching old-revision preprocessing/build inputs, bind the complete C4 include/generated-input closure, and connect the emitted changed code to actual modeled caller/guard/sink behavior. For absent files, locate their exact product compile actions and call/registration paths before making any claim about product semantics.
- Keep every semantic label unknown until a complete premise chain supports changed or unaffected. Source-line emission is not a semantic verdict. Keep exception-guard old commits 18 and 19 independent. This handoff does not tune the model, compute evaluation metrics, or authorize push/merge.

## Reproduction and input provenance

Historical source origin: C1 source_evidence.json identifies the before/fixed target files as retrieved at exact GitHub commits (its recorded local Git object verification was false then). The C3 dependency review records that exact historical commits were later fetched from the openharmony/arkcompiler_ets_runtime GitHub mirror into the local component object store; configured gitcode fetch failed before transfer, and no source branch was updated. This C2 pass read the existing local objects only and did no fetch. The C3 review row table and its artifact SHA are in object_verification.json input hashes. The verifier also binds the retry3 preprocessing observation and derives exact new-file line activation from both ARM .d/.ii outputs and the recorded Git diffs.

Run from the C-line checkout under Kali WSL: `python3 research/experiments/ark_runtime/c2_drift_triage_20261018/verify_c2_evidence.py`. It reads Git objects and writes only `object_verification.json` and `source-diffs.patch` in this new directory. Input SHA-256 values are in `object_verification.json`; C1 profile status and selected product are documented in `research/experiments/ark_runtime/c1_20261017/profile_recheck_20261018.md`. The upstream C3 row review and original source-drift records remain inputs, not edited here.

## C1 preprocessing handoff (2026-10-19)

The selected hihope/rk3568 GN profile remains bound to exact Ark Runtime commit/tree and the stable profile digest e86461191c065e3e140afb734c9d8c27818851ae51651f9ba004231fa7d52063. The compile database SHA-256 is f4ac150e2af2d2d0eff5da063e5be3beee973c459d998c50ca119530019cee7e (234,245 commands); build.ninja SHA-256 is eb313a6a3f282c71c72186e6f3e2022973e6fa0d07efc18426e7505ce7fc8951. The target ARM action command SHA-256 values remain c6d7959215306a67152ac3c2bf1f5012ba919107e27380691c0f9c32e6a6fa88 and 7471f97a0bfab59e0e350be060391af4f17511aa4c019a861822f5154750e82a.

C1 generated the exact Ninja target inputs under retry3 and reran both ARM actions. For each action, preprocessing (-E), dependency scanning (-M), and macro dumping (-dM -E) returned 0 with empty stderr. C2 binds the success observation at research/experiments/ark_runtime/c1_20261017/preprocessor_success_20261019/results/preprocessor_observation.json (SHA-256 2eb080ec6ae72564647b2f77ba596702525e8db9d9595e51d472db84120355ac). Action 1 outputs: preprocessed TU SHA-256 dab12661579ac32a102c7e121f14359c008f0ff403a2b17b82b99a03ccf9c299 (11,684,931 bytes), dependency list 2e297ea17442dfe27f59179a36670cf1d14d746ebe10da9ef966116ad70438c0 (113,409 bytes), macro dump 8324be27ad6b466787312ca034c9a32e54b2b4beb3410bd132cb7ac6045befba (653,566 bytes). Action 2 outputs: preprocessed TU e82309686e0a056e38e46b24d37645e84fb0bee9cd44c01d59de9b738671123e (11,684,891 bytes), dependency list eaa4aecd560560ff053990e9168b017339be364110fd23a537dc2194d27778b2 (113,608 bytes), macro dump 3ec49a353a85e9295a626b698ceb2831dc9450750de27b29a47a0b2b905ac350 (653,648 bytes).

The captured generated-header files are:
- logger_enum_gen.h — SHA-256 122de5b838fe8bd3fdd9a6c12d77a9acbf3a0476d96e47f210278afb7b7c939b.
- libpandafile/type.h — SHA-256 a71454f8b90d3654487e145c100ada5795bb64f7216715bd0ccc34b0067ccb74.
- file_format_version.h — SHA-256 b5c553cf52753e63d06c12cb2176fb69200bfa49868273f5e78c4a411e9ac371.
- source_lang_enum.h — SHA-256 77f702686b210d18fadaa5a40bce67cf2e342455983a97dde57f706f5f562bec.
- bytecode_instruction_enum_gen.h — SHA-256 9926ab909a82533f7a7dd3406e414c3975af34a6f81d2f0ae092984a728ad395.
- bytecode_instruction-inl_gen.h — SHA-256 c2163a60901c6579427d29f8df6d98cf0cb4f5ff1af80673f9994b24436fc4be.
- Musl features.h is referenced by both dependency outputs and preprocessed TUs at obj/third_party/musl/usr/include/arm-linux-ohos/features.h. C4 binds its generated content SHA-256 `6d228e77b88b69f70f9157548b6ec673ffc6b998ce6035fbbee0caddb8442903` and the recursively declared Musl producer inputs.

The generated Ninja target logs are recorded in object_verification.json. They include duplicate-output warnings from the full product graph; the prior full ninja -t query failure at Contacts_DataAbility.stamp remains relevant to full-graph status. Targeted generation succeeded for the required headers, but a complete product build did not run. The exact manifest source archive remains incomplete: 19 nested gitlink commit trees were not materialized (16 declared origins, 3 with no parent .gitmodules URL), and one of five exact root linkfile sources (`vendor/ohemu/common/qemu-run`) is missing. C4 now binds the active dependency paths/content and declared generated-input provenance for these two actions; this does not establish a full product build or a complete top-level snapshot.

C2 still has semantic_gate_passed=false. All 18 changed dependencies remain unknown: the new-revision preprocessing and C4 content closure are verified, but there is no matching old-revision product profile, nor per-dependency proof of the frozen rule's call/guard/sink effects. The same-blob row 12 is a source control, not one of the 18 semantic conclusions. Do not infer changed or unaffected based solely on the newly available token stream.

Next handoff: reconstruct a product-profile-matched old revision, locate actual compile actions for the ten dependencies outside these two TUs, then compare declarations/types and relevant caller/guard/sink IR/CFG evidence. Preserve the 19 gitlink and linkfile source gaps as snapshot limitations. Until the old-side context and semantic chains are complete, all 18 statuses remain unknown; do not tune the model or compute evaluation metrics.
