# C/C++ detectors

## A-NULL-01 v0.7.0 / rule 2.0.0

`ohscanner.cpp.null_dereference` v0.7.0 (rule 2.0.0) reports only explicit NULL
assignments to local/member pointers, `new (std::nothrow)` results, and function returns
with an explicit nullable contract. All pointer parameters, smart pointers with
unknown nullability, and unannotated function returns are suppressed. The
detector still uses bounded same-function syntax and guard/error-path analysis; it
does not prove full CFG dominance, cross-function aliases, build context, runtime
reachability or impact. Results remain candidates requiring review. Zero findings
are not a safe verdict. The detector enforces 1 MiB per unit and 32 MiB per run
limits and keeps partial/failed/not-analyzed coverage fail-closed.

Owner approval is recorded in
`research/contracts/a_ccr_04/owner_approval.json`; catalog registration remains a
separate change from this detector implementation.

Current method card: `research/methods/cpp/NULL_DEREFERENCE_METHOD_CARD_V2.md`.

## C/C++ shared_ptr race detector v0.5.0

Detector `ohscanner.cpp.shared_ptr_race`, version `0.5.0`, emits source-bound
`candidate/unassessed` syntax evidence for modeled class/static `std::shared_ptr`
members. It records read/write, atomic/non-atomic, lock identity and function/location
facts, then evaluates every potential conflicting access pair independently.

Mixed atomic/non-atomic paths are not suppressed by a mutex unless a common synchronization
protocol is proven. Uncertain synchronization emits
`EvidenceObligation("synchronization_proof", status="unknown")`; `try_to_lock`,
`defer_lock`, unresolved lock identity and incomplete lexical scope retain blocked/unknown
coverage. Only atomic-only access sets and all-ordinary conflicting pairs covered by
reliable shared lexical mutexes receive narrow suppression.

This is not a whole-program race proof. Cross-function protocols, lock aliases, templates,
macros, CFG/happens-before facts and real product builds remain unknown. Zero findings
under the narrow scope is not a safe verdict. See the
[method card](../../../../research/methods/cpp/SHARED_PTR_RACE_METHOD_CARD.md) for the
pairwise model, regression record and evidence gate.

C/C++ family PoCs:

- DelayedSingleton shared_ptr: `src/ohscanner/poc/cpp_shared_ptr_race.py`
- unique_ptr raw-alias lifetime: `src/ohscanner/poc/cpp_lifetime_uaf.py`

Both record controlled dynamic evidence without upgrading candidates to product
vulnerabilities. The lifetime detector is version `0.4.0` and covers reset, owner
assignment and scope-bounded move transfer invalidations. See
`research/methods/cpp/DETECTOR_POC_MATRIX.md`.

Targeted regression:

```bash
python3 -m unittest tests.detectors.test_cpp_shared_ptr_race_detector -v
python3 -m unittest discover -s tests/detectors -q
```
