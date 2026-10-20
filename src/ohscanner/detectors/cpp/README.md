# C/C++ detector catalog

`src/ohscanner/detectors/catalog.py` is the executable registry and source of default selection. Every detector below emits research candidates; a zero-result scan is not a safe verdict.

| Detector | Current version | Ordinary default | Scope |
|---|---:|---|---|
| `ohscanner.cpp.bounds` | 0.3.0 | enabled | Bounded copy sizes, element access, unsigned dimension pointer offsets, and `std::vector` indexes |
| `ohscanner.cpp.integer_bounds` | 0.2.1 | enabled | Bounded integer arithmetic, truncation, and narrowing indexes |
| `ohscanner.cpp.lifetime` | 0.4.0 | enabled | `unique_ptr` reset and raw-alias lifetime candidates |
| `ohscanner.cpp.resource_lifetime` | 0.4.2 | enabled | Double-free, use-after-free, recursive cleanup, recursive tree amplification, and recursive compare-cost candidates |
| `ohscanner.cpp.shared_ptr_race` | 0.5.1 | enabled | Narrow conflicting non-atomic `shared_ptr` member access candidates |
| `ohscanner.cpp.unsafe_memory_call` | 0.5.0 | enabled | Unbounded memory and non-literal format-call candidates |
| `ohscanner.cpp.null_dereference` | 0.6.0 | disabled; explicit selection required | Bounded same-function NULL source/sink observations; unknown-return observations remain weak and separate |
| `ohscanner.cpp.path_traversal` | 0.3.0 | disabled; explicit selection required | Bounded lexical source-to-file-sink candidates |

The versions above were read from the detector implementations and confirmed in Catalog metadata. `research_candidate` is a candidate status, not a product acceptance level. Source binding, parser completeness, semantic coverage, candidate signal, and runtime reachability must be reported separately.

## Method cards

- Bounds and integer ranges: `research/methods/cpp/A_MEMORY_BOUNDS_SPEC.md`
- Resource lifetime: `research/methods/cpp/A_RESOURCE_LIFETIME_SPEC.md`
- Unsafe calls: `research/methods/cpp/A_UNSAFE_CALL_SPEC.md`
- NULL dereference: `research/methods/cpp/NULL_DEREFERENCE_METHOD_CARD_V2.md`
- Path traversal: `research/methods/cpp/PATH_TRAVERSAL_METHOD_CARD_20261019.md`
- Shared pointer races and `unique_ptr` lifetime: see the corresponding cards under `research/methods/cpp/`.

## Regression and evidence

Detector fixtures and unit regressions live under `tests/detectors/`. The A-line closeout report and source-bound CLI outputs live under `research/evidence/cpp/a_final_closeout_20261020/` and `research/deliveries/cpp/`. Those reports retain product-level blockers and do not promote source candidates to confirmed vulnerabilities.
