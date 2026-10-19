# A-line parallel queue addendum — T28, 2026-10-20

## T28 — independent DataShare IPC candidate audit (test/evidence line)

- Scope: A0 queue CR-0016, CR-0017, CR-0018 only; independent checkout at scanner baseline `a950a2662a4e131b31ca28c0b7f8937b7140a034`.
- Source: `openharmony/distributeddatamgr_data_share` commit `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd`, tree `f731230c116c94d7619f5514c828b33ffac69924`, `datashare_stub.cpp` blob `cb62502d82c0534a6b9466f7a5d0a9e122d85693`, SHA-256 `cc742b1811c6c6ce2c351e27619a74ec1e5f472502a7a712c50d49fbaeed667a`.
- Current M2 CLI replay independently emits the 204/221/243 line candidates. Bounded file parse status is partial (0 complete / 1 partial); source dispatch bindings exist, but product reachability and caller authorization are not independently proven. Permission helper definitions do not prove guard dominance for these operations. No fixed source or runtime impact evidence.
- Disposition: all three remain `not_testable / queued_first_batch`, **PARTIAL/BLOCK**. No detector, tests, fixtures, or frozen queue edits.
- Artifacts: [`T28 report`](a_t28_datashare_ipc_audit_20261020.md), [`structured evidence`](a_t28_datashare_ipc_audit_20261020.json), [`CLI replay`](a_t28_datashare_cr0016_0018_cli_20261020.md), [`verifier`](verify_a_t28_datashare_ipc_audit.py).
- Continuous test-line goal: independently bind each A0 candidate to exact source objects, replay current production CLI, preserve uncertainty and the original queue state, and record the next evidence required to unblock it.
- Next task: obtain the concrete provider implementation and product profile for this target; establish reachability and caller/permission semantics for each transaction, then assess an isolated target-derived runtime harness. Keep the rows blocked until that evidence exists.
