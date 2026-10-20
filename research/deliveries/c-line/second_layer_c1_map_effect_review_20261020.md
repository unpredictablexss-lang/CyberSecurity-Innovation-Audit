# C1 TypedArray Map effect review

**Result:** the line-2747 type/HClass unknown is **reducible** for this specific stale-type concern. Custom species can make the allocated result observable before the map callback, and the callback can change its prototype/HClass. The captured value is a `JSType`, however, and the available source shows ordinary prototype transitions clone the HClass while preserving its object type. The sink uses that captured type for element-width and element-kind selection. I found no source-level evidence that prototype/HClass mutation alone can make the captured type disagree with the result's typed-array element type. This is not a claim about compiled lowering, runtime behavior, or product impact.

## Pinned target and provenance

- Requested Ark Runtime revision: commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`.
- Target: `arkcompiler/ets_runtime/ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`, blob `68fb3b0adc4f9062889a861be51b7be90362e37a`, SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`.
- The byte-for-byte local source file matches the supplied SHA-256 and Git blob ID. The local object store contains the target blob, but does not contain the supplied commit or tree objects; therefore I cannot independently prove tree membership here. Supporting implementation references below come from the local Ark Runtime source export and are individually SHA-256 pinned, but are not represented as verified members of the supplied tree.

## Effect path

At target lines 2680–2691, `Map` takes its in-stub path when the receiver has no constructor bit and the receiver prototype's accessor-change marker remains clear. At 2721 it calls `NewTypedArray`; at 2721–2722 it captures `newArrayType` from the returned object's HClass. The JS map callback executes at 2730–2732, and line 2747 passes the captured `newArrayType` to `FastSetPropertyByIndex`.

Custom species is a real way for the result to escape before the callback. In the supporting local source, `ObjectOperator::UpdateDetectorOnDefineProperty` marks the TypedArray species protector when `Symbol.species` is changed on the TypedArray constructor (`object_operator.cpp:392–398`). `NewObjectStubBuilder::NewTypedArray` checks that protector and takes its runtime slow path when invalid (`new_object_stub_builder.cpp:2844–2860`). `TypedArraySpeciesCreate` then performs `SpeciesConstructor` / `TypedArrayCreate`, accepts a constructed TypedArray of sufficient length, and checks matching ContentType rather than requiring the same concrete TypedArray kind (`base/typed_array_helper.cpp:946–983, 987–1019`). A custom constructor can retain an alias to the object it returns, making it reachable to the later map callback.

Thus an effect-based unknown is warranted: callback code can mutate an escaped result's prototype, causing an HClass transition before line 2747. The question is whether this invalidates the already captured element kind. Supporting source shows `JSObject::SetPrototype` transitions the instance through `JSHClass::TransitionProto` (`js_object.cpp:1818–1847`); that function clones the old HClass (`js_hclass.cpp:450–476`), and `JSHClass::Clone` initializes the clone with the old HClass's `GetObjectType()` (`js_hclass.cpp:227–250`). Ordinary property-shape transitions likewise clone the source HClass (`js_hclass.cpp:322+`). This supports that a prototype transition changes the HClass identity/prototype while retaining the `JSType` used at line 2721.

At the sink, `FastSetPropertyByIndex` first reads the result's current buffer and length, but uses its passed `jsType` to choose `GetElementSize(jsType)` and `GetType(jsType)` (`js_typed_array.cpp:668–704`). The compiler sink checks detachment and current length, then dispatches stores using the passed type (`builtins_typedarray_stub_builder.cpp:2840–2867 and 2870+`). A custom species result can differ in concrete kind from the source, but the kind is captured from the actual returned result after species construction, before the callback. Prototype changes alone do not supply a source-grounded route to a different typed-array element kind.

## Disposition and limits

Reduce the line-2747 unknown to: **custom species construction and result escape are feasible; callback HClass identity changes are feasible; a stale typed-array-kind mismatch from prototype/HClass mutation is unsupported by the reviewed source.** Do not promote this path as a memory-safety candidate on that basis. Preserve separate unknowns for exact-tree membership of supporting files, compiler lowering, runtime execution and product impact. No build or runtime test was performed.

Supporting local-source file SHA-256 values:

- `compiler/new_object_stub_builder.cpp`: `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0`
- `compiler/builtins/builtins_typedarray_stub_builder.cpp`: `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`
- `compiler/hcr_circuit_builder.h`: `380940bddd7790a8c65e5297ed0646ff2dd5301b2a1197fa78b3766ab8653497`
- `object_operator.cpp`: `05f1eed11c34f0dd178b35515ca7b7fbbe737a5468fdb8abb2727d8e1abfe21b`
- `base/typed_array_helper.cpp`: `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d`
- `js_hclass.cpp`: `b81a9d06a91d3aa20d552738150c6a9e0c622cc2572079ab31ab098c3579d261`
- `js_object.cpp`: `ef5610c619966db2122ffd65475d31b5da01f6c8ee5bdb4474d5ea44151dac4c`
- `js_typed_array.cpp`: `e67c0ce082885efb6fa5894f7a1998a41eb4cddfa2e381c8335497e10e2b9bbe`
