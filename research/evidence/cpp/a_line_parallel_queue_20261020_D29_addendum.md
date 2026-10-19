# A-line parallel queue addendum — D29

### D29 — HUKS CR-0342 shared_ptr race replay (development)

```text
Role: A-line C/C++ shared_ptr race detector developer.
Continuous goal: bind the queued HUKS candidate to exact source objects and improve only source-proven shared_ptr race coverage.
Inputs: frozen A0 CR-0342 row; current shared_ptr_race production M2 CLI; HUKS task header, implementation and task executor at the source commit resolved from the original row prefix.
Steps: verify repo/commit/tree/blob/SHA and preserve the row verbatim; replay the reported scope with the current CLI; cross-reference all accesses, guards/atomics and task/worker lifetime; modify the detector only for a reproduced current-rule gap.
Done when: provide machine-verifiable source identity, CLI version/coverage/findings, access and synchronization review, and either positive/safe/unrelated regressions for a justified rule change or a sourced no-change report with minimum missing evidence.
Boundaries: do not rewrite A0 rows; do not claim a race or safety from syntax candidates/empty findings; no shared API/Catalog/docs changes; preserve PARTIAL/BLOCK and target-build/runtime limitations.
```

D29 completed with no detector change. The production CLI parsed the exact reported header completely and emitted zero findings; source review found a recipient-owned and a task-owned `shared_ptr` copy pointing to one `atomic<bool>`, with an atomic callback store and worker/reply loads. This does not establish a detector miss. The full commit/tree/blob/SHA match the frozen A0 row. Original A0 status stays `not_testable / queued_first_batch`.

See [D29 report](d29_huks_cr0342_sharedptr_replay_20261020.md), [raw CLI JSON](d29_huks_cr0342_cli_20261020.json), and [verifier](verify_d29_huks_cr0342.py).
