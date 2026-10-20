# C1 TypedArray Map source-effect review

**Disposition:** the current Map-path `unknown` at line 2733 is **candidate-worthy for focused developer/test validation**. The exact source passes the destination TypedArray's sampled JSType as the type argument while reading the source TypedArray. Species construction may return a different element kind with the same Number-vs-BigInt content type. The inline getter checks the source index against its array length, then indexes the source backing store using the passed kind's element width without a visible backing-byte-length check. This gives a concrete source-level out-of-range-read hypothesis. It is not a confirmed runtime or product vulnerability: compiler lowering, memory behavior, and execution remain unverified.

The old line-2747 `type_fact_invalidated_by_call` observation belongs to analyzer HEAD `463f6e3`; on planning HEAD `fbb537a`, both registered and runtime models stop earlier at line 2733 with `effectful_helper_contract:...FastGetPropertyByIndex`. The distinct-kind source read below explains why retaining that current unknown is appropriate and why it should not be reduced to a generic unrelated-helper effect.

## Exact binding

Ark Runtime commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`. Every path below was resolved through `git rev-parse <commit>:<path>` in `D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`; SHA-256 was computed from `git show <commit>:<path>` bytes.

| Same-tree path | Git blob | SHA-256 |
|---|---|---|
| `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `68fb3b0adc4f9062889a861be51b7be90362e37a` | `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c` |
| `ecmascript/compiler/new_object_stub_builder.cpp` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` | `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0` |
| `ecmascript/base/typed_array_helper.cpp` | `bcb422fe67f4e670adcca31fffd4da7e2b3b0b21` | `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d` |
| `ecmascript/object_operator.cpp` | `d885881517adb4a892ec9968cfd3e457e2bc2afd` | `05f1eed11c34f0dd178b35515ca7b7fbbe737a5468fdb8abb2727d8e1abfe21b` |
| `ecmascript/builtins/builtins.cpp` | `f530df69e3081f2a6a0c0d586eb7c5faaa8b1aef` | `184d585c57d343ff18080eadd71e80ac4ef2ea6763dda6b4d5bb6287ee571694` |
| `ecmascript/compiler/builtins/builtins_arraybuffer_stub_builder.cpp` | `21d7f79fa83ffc05e7510a532f39398075aeae16` | `0e41c2def0393275293c3cd1df983bccec42bee7bfa6ed58567a11b00ad745d6` |
| `ecmascript/stubs/runtime_stubs.cpp` | `14dc06350881b1fa0fdabeeb8465ae9063224d6c` | `0c390fb329387ff75943089da0e7eecab4bc1df21da1be4f33db969b2bf79a46` |
| `ecmascript/compiler/stub_builder-inl.h` | `c0521ab7a55cd63850736c2db8a290115965373c` | `e3e840771be228a2c5e6c15576ecdf3f06175622b5840525520345f1d22d76be` |
| `ecmascript/compiler/lcr_circuit_builder.cpp` | `a6df4cba87c9a49f09a292648e7ea7d7cad1b24c` | `4575cf4b84cef1046cf617d5328bd1c2c61b5a29f4550b4cbfba5b8ba4d289db` |
| `ecmascript/compiler/codegen/llvm/llvm_ir_builder.cpp` | `38b7a09cd57349530887b0722e384c33b5af73e4` | `00bc8c41251738b36432dd138b38e0756937d479b399b835b324caa7ea4c98f4` |
| `ecmascript/compiler/codegen/maple/litecg_ir_builder.cpp` | `8e07e416dc11b1e985c2259474af3fd0936a2a06` | `6eb18562eb1ff9964d3d82ad121310e0d93ba2dc65c412159f91687354789581` |
| `ecmascript/js_typed_array.cpp` | `098c2a22cae3152af3a59063dda25e145f03bbd7` | `e67c0ce082885efb6fa5894f7a1998a41eb4cddfa2e381c8335497e10e2b9bbe` |
| `ecmascript/js_hclass.cpp` | `241359029874d0f32ace5bc3ca9685dc3a3e1840` | `b81a9d06a91d3aa20d552738150c6a9e0c622cc2572079ab31ab098c3579d261` |
| `ecmascript/js_hclass.h` | `fca61941b181d1796d485e387054221d6f136337` | `36d38fd0d12b05c21069a663418b569063e96912f6758b9611b832a78477d4e3` |
| `ecmascript/js_object.cpp` | `214ff0f70048c600b9a8a99bbe1ca2318b4affc3` | `ef5610c619966db2122ffd65475d31b5da01f6c8ee5bdb4474d5ea44151dac4c` |

## Current helper unknown and source path

The exact target's `Map` fast body checks that the receiver is a fast TypedArray, has no constructor bit, is not detached, and its prototype accessor-change marker is clear (`builtins_typedarray_stub_builder.cpp:2678–2691`). It does not check the TypedArray species-protector bit in that outer guard. It calls `NewTypedArray` at 2713 and samples `newArrayType = GetObjectType(LoadHClass(newArray))` at 2721. At line 2733 it reads the *source* `thisValue` using `FastGetPropertyByIndex(..., newArrayType)`. The callback is later at 2739; the destination store at 2747 also receives `newArrayType`.

The species route is source-supported. Specific TypedArray constructor function HClasses inherit from the `%TypedArray%` function (`builtins.cpp:2441–2444`), so its species property is consulted through the constructor chain. Defining `Symbol.species` on the `%TypedArray%` function marks `TypedArraySpeciesProtectDetector` (`object_operator.cpp:392–398`). `NewObjectStubBuilder::NewTypedArray` checks the detector and routes to `TypedArraySpeciesCreate` when invalid (`new_object_stub_builder.cpp:2844–2853, 2888–2892`). The helper then performs `SpeciesConstructor` and `TypedArrayCreate` (`typed_array_helper.cpp:964–975`). The construct path validates that the result is a TypedArray and checks its requested length (`typed_array_helper.cpp:987–1018`); `TypedArraySpeciesCreate` checks matching Number-vs-BigInt ContentType (`978–983`), but does not require the same concrete typed-array element kind. A custom species can therefore return a Float64Array for a Uint8Array source, with both containing Number values.


`LoadPrimitive(INT64, block, byteIndex)` is a typed IR load, not an abstract bounds-checking accessor: `StubBuilder::LoadPrimitive` forwards to `LoadWithoutBarrier` (`stub_builder-inl.h:448–454`), and `CircuitBuilder::LoadWithoutBarrier` forms `PtrAdd(base, offset)` and emits a gate typed with the requested machine type (`lcr_circuit_builder.cpp:226–235`). The LLVM backend's load visitor emits `LLVMBuildLoad` (`codegen/llvm/llvm_ir_builder.cpp:1711–1734`); the LiteCG visitor emits an `Iread` (`codegen/maple/litecg_ir_builder.cpp:1222–1231`). These are source-level lowering paths only. Which backend/configuration applies to an actual product build, generated machine code, and runtime memory behavior were not established.

For a Uint8Array source of length 1 and a valid Float64Array species result of length 1, line 2733's call passes `JS_FLOAT64_ARRAY` while its receiver remains the one-byte source. `FastGetPropertyByIndex` checks detachment and `index < GetArrayLength(array)` (`builtins_typedarray_stub_builder.cpp:199–225`), then passes the supplied `jsType` to `GetValueFromBuffer`. The Float64 arm computes `index * 8 + offset` and loads an `INT64` (`296–324, 438–443`); it has no visible check against source buffer byte length. For index zero and zero offset, the source logical backing range is one byte, while the IR load width is eight bytes. The data-pointer helper returns the ByteArray data address or ArrayBuffer external pointer (`builtins_arraybuffer_stub_builder.cpp:316–338`), without adding a byte-length bound. A non-detached source, valid index, and numeric Float64 result all stay on this inline getter path. This is a concrete source-level width/bounds mismatch candidate; whether the generated/runtime access manifests as an exploitable out-of-range read is not established here.

The runtime fallback also receives the same explicit type argument (`runtime_stubs.cpp:3170–3177`), and `JSTypedArray::FastGetPropertyByIndex` uses that argument for `GetElementSize`/`GetType` (`js_typed_array.cpp:640–665`). Its runtime buffer behavior was not executed or adjudicated. The inline source is already sufficient to justify keeping the model unknown and giving the mismatch a focused positive/control test.

## Callback escape and line-2747 type fact

The species constructor can retain an alias to the result it returns, so the map callback can access that result through user state; result non-escape is not a valid assumption. Callback code can also change its prototype and hence HClass identity. Same-tree `JSObject::SetPrototype` transitions the object's HClass (`js_object.cpp:1818–1849`); `JSHClass::TransitionProto` calls `Clone` (`js_hclass.cpp:450–476`), and `Clone` seeds the copy from the old `GetObjectType()` (`227–248`). This proves that this ordinary prototype transition preserves JSType; it does not prove a universal invariant against every conceivable runtime or native effect.

The type sampled at line 2721 is already the species result's actual type. For the destination store at 2747, a prototype/HClass identity change alone therefore does not establish a stale element-kind value: ordinary HClass cloning preserves JSType and the sink uses the captured type for element width/type selection. The historical `type_fact_invalidated_by_call` at 2747 remains a reasonable conservative effect unknown in the older `463f6e3` model, but its specific callback-mutates-prototype hypothesis is reduced by the same-tree clone evidence. The current analyzer does not reach that sink because of the earlier helper-contract unknown; do not describe the historical observation as current HEAD output.

## Findings and boundaries

- **Current line 2733:** retain `unknown` and classify the source mismatch as a source/component candidate for focused validation: a species-selected destination JSType controls an unchecked-width source read. Validate same-kind and different-kind species, both content types, index zero and final index, detached/short backing controls, and exact helper binding before detector/model promotion.
- **Historical line 2747:** the callback can reach an escaped result, but the examined ordinary HClass/prototype change preserves JSType. No source evidence here makes that sink a type-confusion candidate by itself.
- **Scope:** no detector or LLM implementation, compile, runtime test, exploitability adjudication, or product-impact claim was made. The source unit remains parser/model partial. No formal precision/recall claim follows.
