# C4 source facts, resolved mechanisms, and remaining unknowns

Fixed source commits: parent `830e85b40240677039719fcbf14f721ad3b19050`; fix `a0e30483ab3e4aead67ecfb5c708489915e447f9`. Both target-file Git blobs and SHA-256 values are bound in `C4_SOURCE_BINDINGS.json`.

## C3 unknown mechanisms re-reviewed at the fixed source

The exact target translation unit was run through the bounded local analyzer with the research-only partial path. Results are local function observations; the file stays partial and retains `parse_dependency_contamination_unknown`.

| Function | Parent line / result | Fixed line / result | Source fact supporting local match | Boundary |
|---|---|---|---|---|
| `CopyWithin` | 964 / matched | 964 / matched | The fast path rejects a custom constructor, accepts integer index arguments, samples `thisValue`'s HClass type, then reads and writes elements on that same receiver using the sampled type. | The slow path, build selection, and partial translation-unit dependencies remain unresolved. |
| `Filter` | 1498 / candidate | 1499 / matched | The fixed source derives the destination type from the allocated result before the element store; the parent used the source receiver's type. | Candidate is a source-level discrepancy, not a confirmed product vulnerability. |
| `Set` | 2234 / matched | 2235 / matched | The reviewed fast path uses the destination receiver's type at the store. | Does not cover all slow paths or cross-TU call behavior. |
| `With` | 1762 / matched | 1763 / matched | It samples the exemplar type and creates a same-type destination. The exact helper fast path copies the HClass/type inputs; its slow path calls `TypedArrayCreateSameType`, whose helper selects the intrinsic constructor for the exemplar's TypedArrayName. `CopyTypedArrayBuffer` copies raw bytes only when source and target types match, otherwise it uses typed element reads/writes. | Product build flags, exceptional behavior outside the reviewed branch, and partial-TU dependencies remain unknown. |

The exact source helper `new_object_stub_builder.cpp` has blob `757b8d050d306d349822600deacb295c7a54245e` at the fixed commit. The C4 model's 16 effect-summary blobs also match that fixed commit. For the separate exception-path pair, the parent/fix target bytes fetched by their exact upstream raw commit URLs match the model's Git blob and SHA-256 values; the helper blob is identical at both commits and was checked against each commit tree. No upstream source was modified.

## Still unknown

- The translation unit parses as partial. Declarations, includes, macros, overloads, build flags, and other omitted dependencies may affect local facts; the research route preserves a parse-completeness obligation and blocked/partial coverage.
- A read-only spot-check of the upstream `master` tip `edc5231fdbc81d0d7477d03347c0ea44408f6726` (target blob `68fb3b0adc4f9062889a861be51b7be90362e37a`, SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`) parsed 72 functions with `partial` status. The local function parser drops the namespace on `BuiltinsTypedArrayStubBuilder::Filter` and `::Map`, so the registered exact owner binding did not resolve. An exploratory direct call that supplied those observed unqualified names returned local `matched` observations at lines 1550 and 2721 respectively; this is not a Runner replay and does not extend the model's approved commit bindings. `ToReversed` uses `NewTypedArraySameType`, outside this exception rule's creator binding; its empty result is not a safety result. Keep current-tip generalization and ToReversed semantics unknown.
- The model assumes `NDEBUG=1;ENABLE_ASM_ASSERT=0`; this has not been confirmed for a shipped product build.
- The exact deployed source revision, product configuration, runtime path feasibility, attacker-reachable input, exploitability, and concrete CIA impact have not been established.
- No compatible isolated Ark runtime/build was available for dynamic reproduction.
- The 16 C3 holdout labels have not been independently reviewed. There is no valid Precision/Recall or community-wide coverage claim.

## Evidence boundary

The local observations support a narrow source-level explanation for these four exact function bodies and source revisions. They do not prove the whole file safe, prove all generated/runtime paths, or confirm a product vulnerability. Confirmed product vulnerabilities remain 0.
