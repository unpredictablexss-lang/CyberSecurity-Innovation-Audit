# A-line parallel queue addendum — D24

### D24 — DataShare shared_ptr race model assessment (development)

```text
Role: A-line C/C++ concurrency candidate detector developer.
Continuous goal: improve generic shared_ptr race candidate quality only when the production CLI path has a source-backed, reproducible model gap.
Inputs: frozen A0 CR-0005–CR-0012 rows; component commit/tree/blob/SHA; current shared_ptr_race CLI adapter and regression controls.
Steps: verify all source objects; replay the target headers and bounded implementation files; trace shared_ptr member construction, mutation, reads, locks, and wrapper/thread lifetime; distinguish inner detector behavior from the M2 adapter execution path.
Done when: either a generic production-path rule gap is fixed with controls and exact-source replay, or a no-change report preserves parser/model and thread-context limits, exact source identities, CLI coverage/performance, and all original queue states.
Boundaries: no file/symbol/CVE hardcoding; no shared parser/API/Catalog edits; no A0 status edits; no race/safety claim from syntax candidates or zero results.
```

D24 completed with **no detector change**. The source objects and A0 queue rows are independently rechecked by [the D24 verifier](verify_d24_datashare_race.py). The CLI's M2 adapter invokes `shared_ptr_race` per file; it does not join `ResultSetHolder` header declarations to `.cpp` reads/resets. Header-only scope parsed 5/5 files completely and returned 5 candidates in 0.0313 seconds; the 10-file bounded scope parsed 10/10 completely and returned the same 5 candidates in 0.1509 seconds. These candidates do not demonstrate same-object concurrent access. CR-0005–0012 remain `not_testable / paused_pending_evidence`. Full details and raw outputs are in the [D24 report](d24_datashare_race_20261020.md).
