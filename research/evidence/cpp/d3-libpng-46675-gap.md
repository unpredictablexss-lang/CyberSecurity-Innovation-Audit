# D3: libpng CVE-2026-46675 replay gap

Status: unresolved parser and semantic-coverage gap. No CVE-specific rule or parser bypass was added.

## Advisory and pinned source pair

- Official advisory: https://github.com/pnggroup/libpng/security/advisories/GHSA-qvg3-h654-xq3j
- Affected range in advisory: libpng 1.6.0 through 1.6.58; fixed 1.6.59 and 1.8.0.
- Vulnerable upstream revision: `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`.
- Vulnerable `pngrutil.c` blob: `a4eda54c8cb3d36cf1651dba159067b65030e3aa`; SHA-256 `b328fb05352226866b1e44c8cddd3e03df35413f1f38f4d81ba51afe4f2333a5e`.
- Scanned transport snapshot: commit `e283ed5d3a74c0112f092ddb1003c97e0e9a4717`, tree `c78da20c3ffe37b09653eaa3b49c5213745ac4bd`, snapshot SHA-256 `192e4c1ac567f539395a92a383b0f55e22baa49467de510efda1198962064098`.
- Exact upstream fix: https://github.com/pnggroup/libpng/commit/aa77ef38c17ab2fc1b41bec09fb973c6a386641d (parent `4eeb825ab26605ed34cd74495d4cce920939fe9f`). The official fix-source `pngrutil.c` SHA-256 is `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e`.
- Independently fetched raw files at the vulnerable tag and fix commit reproduce the above SHA-256 values. The pre-existing `fixed/` file matches the exact fix commit file; it must not be described as a full 1.6.59 release tree.

## Mechanism and scanner result

The advisory describes incomplete chunk decompression leaving an input pointer and nonzero byte count in a shared decompressor stream after its prior owner releases it. A later read-end path sees the count and resumes from the stale pointer. The fix clears input/output pointers and counters on stream acquisition and release. This is a cross-function shared-state/lifetime ordering problem; the current `ohscanner.cpp.resource_lifetime` local allocation/release model does not express that state transition.

The preserved D2 real-source CLI result is `completed_with_limitations`; `ohscanner.cpp.resource_lifetime` v0.3.0 is `blocked`, 0 diagnostics, 0/1 analyzed, and the one selected 153,112-byte C source is `partial` with broad tree-sitter errors/missing nodes. The report is `d2-libpng-46675-vulnerable-unknown.json` and its readable summary is `d2-libpng-46675-vulnerable-unknown.md`. This is unknown, not a safe result or a detector miss. No exact-fixed Runner replay or vulnerable mechanism candidate was produced, so the D3 acceptance condition is unmet.

## Attempt and disposition

Inspected the complete vulnerable-to-fix diff and the detector’s parse gate. Its current complete-AST local UAF analysis returns before processing this source; existing partial-safe rules concern different bounded relations (recursive cleanup and cross-member aliases). Extending them to infer arbitrary shared stream state, ownership release, stale byte counts, and later cross-function consumption from this translation unit would require unmodeled call/control-flow and type semantics. A lexical pattern tied to the CVE’s field names, source path, function names, or hashes would violate the generalization requirement. No such rule was added.

Analysis cost: one source/fix diff review, SHA-256 verification of both upstream raw files, and inspection of the existing pinned Runner result and detector parse gate. No runtime exploit replay was repeated in D3. D2’s separate libpng 1.6.55/1.6.56 cross-struct alias family remains the positive libpng lifetime replay; it does not satisfy this CVE’s stale stream-buffer root cause.

Next valid step is improved C parsing/locally trusted syntax-region analysis plus a general interprocedural field-state model, validated with unrelated decompressor and buffer-owner controls. Until then, leave this CVE unknown/partial and out of positive replay counts. Catalog/Runner changes remain an owner integration task.
