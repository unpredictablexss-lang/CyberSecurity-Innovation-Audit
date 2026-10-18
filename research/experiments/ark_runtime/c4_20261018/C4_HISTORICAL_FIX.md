# C4 historical upstream fix: TypedArray Filter destination type

Classification: **confirmed upstream-fixed source-level type-token defect; product exploitability and impact unknown**. This classification describes the source change and attached upstream regression case. It is not a confirmed deployed-product vulnerability, CVE, or affected-release determination.

Repository: [openharmony/arkcompiler_ets_runtime](https://github.com/openharmony/arkcompiler_ets_runtime). The exact fix is [commit a0e30483](https://github.com/openharmony/arkcompiler_ets_runtime/commit/a0e30483ab3e4aead67ecfb5c708489915e447f9), whose direct parent is `830e85b40240677039719fcbf14f721ad3b19050`.

In the parent version, `BuiltinsTypedArrayStubBuilder::Filter` derives `arrayType` from the source receiver and passes it to `StoreTypedArrayElement` for `newArray`. The fix reads `newArrayType` from the allocated destination object's HClass and passes that token to the store. The change is consistent with the possibility that TypedArray species creation yields a destination with a different element type.

The upstream commit adds a regression case at `test/aottest/typedarrayfilter/typedarrayfilter.ts`: a `Float32Array` receiver is given a `Uint8ClampedArray` prototype, then `filter(Array, a)` is called. The source test is linked through the upstream commit; this review did not build or execute the Ark runtime.

Recommended remediation is the upstream change: derive the store type token from the actual allocated destination object, not the source receiver. The static replay is one candidate before the patch and zero after it, with both files marked partial/blocked. No claim is made that the regression case demonstrates memory corruption, attacker reachability, product impact, or a release range. Those remain unknown until reproduced against a matching isolated runtime/product build.
