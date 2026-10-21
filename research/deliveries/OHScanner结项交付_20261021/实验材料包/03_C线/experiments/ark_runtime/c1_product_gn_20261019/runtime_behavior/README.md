# C1 TypedArray species behavior (2026-10-19)

This is a current-product-runtime behavior check for the fixed `rk3568@hihope` C1 source snapshot. The classification is a **candidate semantic divergence**, not a product vulnerability conclusion.

## Fixed artifacts

- Runtime: `arkcompiler/ets_runtime` commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`.
- Target and creator blobs, object hash, ARM32 VM hash, host `es2abc` hash, QEMU version, source/ABC hashes, exact arguments and captured output hashes are in `runtime_behavior_record.json`（文件引用：runtime_behavior_record.json）.
- The host `es2abc` and product ARM32 `ark_js_vm` were built from the same C1 source archive. QEMU used the C1 musl sysroot; it has no OpenHarmony logging service, so the VM emits repeated HiLog socket warnings.
- The key species and four-control probes were also rerun with `--asm-interpreter=false --test-assert=true`, matching the repository's VM test-helper execution mode. Their results matched the initial runs; output hashes are included in the machine record.
- `vm_entry_smoke.js` calls `assert_true(true); test_end();` and exits 0 with `--test-assert=true`. The exact pinned VM registers the hook as `test_end`; the earlier `testEnd` attempt was a harness-name error and is not behavior evidence.

## Observed behavior

The probe reads each constructor's `Symbol.species` directly, then calls `filter()` on an `Int8Array` subclass. The C1 VM reports the expected getter values (`DefaultDerived` and `Uint16Species`) but returns `Int8Array` for both `filter()` calls. Node v22.14 returns `DefaultDerived` and `Uint16Species`, respectively. The isolated product probe exits 0 and captures these results. The broader control script's expected cross-type subclass result therefore fails at its second control; controls later in that aggregate script remain partial.

An instance-level `source.constructor = { [Symbol.species]: ... }` control behaves differently in the same VM: `filter()` returns `Uint16Species` or `Uint16Array`, and `-1` converts to `65535`. This narrows the observation to species dispatch through the subclass constructor path.

Four isolated product controls also pass: a Number-to-BigInt species mismatch throws `TypeError`; callbacks finish before the species constructor and its thrown sentinel propagates unchanged; a callback's mutation of `source.constructor` is observed when Filter creates its result; and Set/CopyWithin/With do not read `@@species`, with With returning the intrinsic same-type result. Three new, separately compiled probes now isolate those method-family assertions: Set mutates the receiver with no species read; CopyWithin mutates the receiver with no species read; With returns an intrinsic `Int8Array` with no species read. Each probe passed individually on the same C1 ARM32 VM under QEMU using `--asm-interpreter=false --test-assert=true`. Their JS, ABC, stdout and stderr hashes are in the machine record and checked by `verify_profile_artifacts.py`. These are scoped safe controls, not historical parent/fix behavior. The broader original control script still stops at the subclass mismatch, so its later items remain partial in that aggregate replay.

The exact C1 source review and a new same-process perturbation probe now narrow the cause to the TypedArray species protector guard. In the same VM process, the probe first calls `filter()` on an `Int8Array` subclass and observes `Int8Array`; it then defines a getter for `Symbol.species` on `%TypedArray%` (the intrinsic constructor returned by `Object.getPrototypeOf(Int8Array)`), calls `filter()` again, and observes one getter call and a `Uint16Array` result with value `6`. The pinned `ecmascript/object_operator.cpp` sets `TypedArraySpeciesProtectDetector` when a `Symbol.species` property is defined on the intrinsic TypedArray constructor (lines 392–398; Git blob `d885881517adb4a892ec9968cfd3e457e2bc2afd`, SHA-256 `05f1eed11c34f0dd178b35515ca7b7fbbe737a5468fdb8abb2727d8e1abfe21b`). The pinned `TypedArraySpeciesCreate` guard in `ecmascript/base/typed_array_helper.cpp` skips the fast path once this protector is set (lines 949–975; SHA-256 `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d`). This perturbation links the behavior change to the guard state and slow species lookup. It remains a current C1 VM semantic candidate under QEMU, not a product vulnerability finding.

A callback-mutation control verifies the ordering boundary within one Filter call: an `Int32Array` subclass callback redefines `%TypedArray%[Symbol.species]` on its first invocation. Both callbacks run, the species getter runs once after iteration, and Filter returns `Uint8Array` with values `120` and `121`. This supports that the current C1 result-creation path observes protector invalidation performed by the callback. It does not establish behavior in the historical parent build or security impact.

ECMAScript 2025 specifies that `TypedArray.prototype.filter` calls `TypedArraySpeciesCreate` after callbacks and before storing the kept elements (§23.2.3.10（文件引用：https://tc39.es/ecma262/2025/multipage/indexed-collections.html#sec-%typedarray%.prototype.filter）). This comparison identifies an API behavior mismatch for the current C1 VM. It has not shown memory corruption, a reachable product call site, attacker control, or security impact.

## Classification and next evidence

- **candidate:** subclass `@@species` is observable by direct property access but ignored by `filter()` in this current C1 ARM32 VM under QEMU while the species protector is valid. Defining `%TypedArray%[Symbol.species]` invalidates that protector and makes Filter call the getter and return its selected type.
- **partial:** the original aggregate script stopped at this mismatch. Isolated BigInt, exception/effect, callback-mutation and Set/CopyWithin/With controls passed; the remaining items and full matrix are still incomplete.
- **blocked:** historical parent/fix runtime comparison, full product image/device execution, product entry reachability, attacker control, and security consequence remain unverified. Public Runner admission stays **C / blocked / execution_enabled=false**.

The complete machine record is `runtime_behavior_record.json`（文件引用：runtime_behavior_record.json）. This observation is not an independent blind holdout label and does not satisfy the scanner's admission gate.
