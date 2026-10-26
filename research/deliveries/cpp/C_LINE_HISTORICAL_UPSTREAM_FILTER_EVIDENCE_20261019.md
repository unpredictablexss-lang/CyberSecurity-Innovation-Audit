# Historical TypedArray Filter upstream evidence and C1 test preparation (2026-10-19)

## Exact historical fix evidence

The local OpenHarmony `arkcompiler_ets_runtime` Git object database identifies `a0e30483ab3e4aead67ecfb5c708489915e447f9` (authored 2025-03-07, committed 2025-03-10) as `fix: typed array filter cause outbound`; its parent is `830e85b40240677039719fcbf14f721ad3b19050`. The patch changes `BuiltinsTypedArrayStubBuilder::Filter`: after `NewTypedArray`, it reads the result array's HClass type and passes that `newArrayType` to `StoreTypedArrayElement` instead of reusing the source's `arrayType`.

That commit adds an AOT regression at `test/aottest/typedarrayfilter/typedarrayfilter.ts`. It creates a `Float32Array(3924)`, assigns its prototype to a `Uint8ClampedArray(3594)` instance, calls `a.filter(Array, a)`, and expects `success`. The new `BUILD.gn` declares a host AOT test with PGO and the typed path enabled. This is direct evidence that upstream treated a cross-type Filter result/store path as an outbound-write regression and added a repair test. The test's expected output alone does not show the parent failing, quantify corruption, or establish exploitability.

## Current C1 profile cross-check

The independently pinned C1 `a65a2853ccae13da167d9aa4720ab8b11ec16656` target source contains the same key result-type flow: `GetObjectType(LoadHClass(glue, newArray))` and `StoreTypedArrayElement(..., newArrayType)`. The C1 target blob is `68fb3b0adc4f9062889a861be51b7be90362e37a`; its ARM32 VM SHA-256 is `c6b51a8036fc40415da3c02a7bb1e1b732f9e7fe094fca33ce5f29ad19c9c4c5`. The historical fix commit is **not** an ancestor of the C1 commit, so this is a source-semantic match in a separately pinned later profile, not proof that the C1 build is the historical fixed build or that the historical product configuration matches.

The exact regression source was extracted from the historical fix commit; Git blob OID `ef25a446c3d91d3019a7fa09d6a9702fe8e670e6`, SHA-256 `510e8e96f06d585a98db5e6f32568568f5e7f1c6b87f379329032f779ebb3037`. It compiles successfully with the pinned C1 `es2abc` (`84029e93a9b067df86f6bf5a9880f199187beedd7292da42a4c169c48943a474`) using `--target-api-sub-version=beta3`; ABC SHA-256 `af0ef12cc7aa4f37ee86899d1a15985fcfcd170c4341b7791f2a6d9c30245ba3`.

The regression source compiles with the pinned C1 `es2abc` and runs on the pinned C1 ARM32 VM under QEMU 8.2.2. The raw upstream source prints `success` and then aborts during process teardown (SIGABRT); the C1 harness expects an explicit `test_end()` completion hook, so a separately hashed harness copy appends that hook after the unchanged test body. That copy exits 0 and prints `success`. QEMU SHA-256 exactly matches the earlier C1 record (`47a63bcbdf3030cf42230a0521dae38ff9d62ba1268d5cafc7d8ccf7da7c761c`). Machine details, source/ABC/output hashes, and commands are in `research/experiments/ark_runtime/historical_fix_regression_20261019/execution_record.json`; the reproducible driver is `run_regression.py`. This run uses the later C1 fixed-source VM and executes ABC through `ark_js_vm`; it is **not** the upstream AOT/typed-path test configuration, not a historical parent/fix binary comparison, and not an ASan/out-of-bounds detector. It shows only that this input completes on that fixed later VM.

## Scope separation from the older Filter issue

The 2023 public [issue I7E0FM](https://gitee.com/openharmony/arkcompiler_ets_runtime/issues/I7E0FM?skip_mobile=true) and [merged PR !4255](https://gitee.com/openharmony/arkcompiler_ets_runtime/pulls/4255) describe an illegal-address-access issue in `panda::ecmascript::builtins::BuiltinsTypedArray::Filter` while running ABC, resolved by checking whether a result was an exception. That is a different function namespace, different defect mechanism, and different source history from the 2025 compiler-stub type-origin change studied by this C-line detector. It must not be counted as confirmation of the 2025 candidate or as evidence that this detector found the 2023 issue.

The 2025 change references issue IBS5YG in its Git commit message; the issue page was not accessible in this review, so no additional issue details are inferred.

## Disposition

- Historical parent source: `candidate` at the narrow type-origin level, still `partial` because full TU preprocessing/build profile and parent runtime replay are unavailable.
- Historical fix source: source-level repair is verified; historical runtime control remains `partial`.
- C1 source/runtime: its pinned compiled source uses the repaired result-type flow; this says nothing about the parent binary.
- Product security: no parent crash/corruption reproduction, real product entry/attacker-control path, or impact validation was obtained here. Keep product-vulnerability promotion and public Runner admission closed.

Primary upstream reference: [exact 2025 fix commit a0e30483ab3e4aead67ecfb5c708489915e447f9](https://gitee.com/openharmony/arkcompiler_ets_runtime/commit/a0e30483ab3e4aead67ecfb5c708489915e447f9). The older issue/PR pair is linked above only to clarify scope.
