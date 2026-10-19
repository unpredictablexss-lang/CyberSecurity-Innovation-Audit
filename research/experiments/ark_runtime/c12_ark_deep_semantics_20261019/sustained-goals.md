# G12-AS sustained goals

1. Bind each helper contract to full commit/tree/blob/source hashes and replay parent/fixed source identities for the nine known cases.
2. Add explicit effect lattice edges for reads/writes, pointer/reference escape, exception and callback behavior; keep every unknown fail-closed.
3. Extend numeric analysis to C++ usual arithmetic conversions, signed overflow, checked casts and allocation-size provenance, with positive/fixed/safe/unrelated/unknown controls per rule.
4. Add minimal structured CFG support for bounded host loops and loop invariants without turning unsupported control into reachability proof.
5. Add cross-function summaries for bounded call graphs, recursion SCCs and pointer alias effects, with source-contract compatibility tests.
6. Freeze an independent blind holdout and report family TP/FP/FN/unknown only after reliable labels; then run authorized isolated product PoC and fix revalidation.
