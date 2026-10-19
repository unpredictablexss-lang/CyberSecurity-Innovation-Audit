# A-line parallel queue addendum — T25

## T25: DataShare CR-0013–CR-0015 source and CLI audit

- Lane: independent test/evidence; no detector, tests, fixtures, or A0 queue files modified.
- Base: `c0d59bf2911a358643e7f38a0d93ed2c5cb6e5d8`.
- Queue: three rows read from the frozen full 345-row `a0_triage_20261019/queue.csv`; IDs, source keys, `not_testable` and `paused_pending_evidence` retained.
- Source: `openharmony/distributeddatamgr_data_share`, commit `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd`, tree `f731230c116c94d7619f5514c828b33ffac69924`; CR-0013–0015 bind to header blob `b3cc65d4a39b596cad57477e30e06bc7a673b37c`, SHA-256 `81df12f7bf672ed146509837fc73c7ad857237d08f47cb4af54341311ebc284c`.
- CLI: detector `ohscanner.cpp.shared_ptr_race` 0.5.1 reports two constructor-write candidates at `uvQueue_` lines 35 and 42; no candidate at CR-0014's `extension_` initializer line 40. Scope is four files; parse 3 complete / 1 partial, with `datashare_uv_queue.cpp` unanalyzed by the detector.
- Source result: all observed request-path `uvQueue_` reads in the selected `.cpp` are under `mutex_`; no same-object unordered cross-thread access is evidenced. The two constructor writes are alternative construction paths. Destruction/publication ordering, product thread model, reachability, impact, and runtime remain unverified. Case disposition stays PARTIAL/BLOCK; no safe or confirmed-race verdict.
- Evidence: [audit report](a_t25_datashare_race_source_audit_20261020.md), [per-ID JSON](a_t25_datashare_race_source_audit_20261020.json), [raw CLI JSON](a_t25_datashare_cr0013_0015_cli_20261020.json), [raw CLI Markdown](a_t25_datashare_cr0013_0015_cli_20261020.md), and [read-only verifier](verify_a_t25_datashare_race_source_audit.py).
- Verification: run T25 verifier with frozen queue and local project object DB; run `python -m research.deliveries.cpp.a0_triage_20261019.verify_triage`; run C++ lane scope checker against base `c0d59bf2911a358643e7f38a0d93ed2c5cb6e5d8`; run `git diff --check`.
- Post-freeze D25 cross-check: source identities, queue binding, selected CLI source set and provenance matched; independently ran D25's verifier from commit `930cd889219cf769d6386ae26176332e37472002`, which passed. Finding labels were not used for T25 dispositions; details are in the T25 report.

## Continuous test objective

Keep CR-0013–0015 source identities and original states unchanged while acquiring product build/profile and runtime evidence, a complete queue implementation analysis, and object publication/destruction concurrency contracts. If evidence establishes a feasible same-object conflicting access on distinct threads, bind and run the exact product target under TSan; otherwise retain the source negative without relabeling the original queue rows.
