# T38 — Preferences vector-fuzzer independent audit (CR-0091–CR-0096)

## Result

T38 independently reran the current `ohscan-run` CLI for the exact A0 source object. The one-file, 93-LOC scope parsed completely; `ohscanner.cpp.shared_ptr_race` 0.5.1 emitted six syntax candidates, matching all six queue-bound lines. This reproduces detector observations only. The exact GN target is `ohos_fuzztest("DBPreferencesVectorFuzzTest")`, listed in a `fuzztest` group marked `testonly = true`. The harness entry sequentially sets up, calls Put/Get helpers, and tears down a static `shared_ptr`; this source does not establish a production build, a concurrent interleaving, or product vulnerability.

## Immutable source identity and CLI

- Repository: `openharmony/distributeddatamgr_preferences`
- Commit: `bff9efd79afc0d7d1ed22a63ff355f1600404596`
- Tree: `7761d9e273ae7007046ae115797f255e554523ae`
- Source: `test/native/fuzztest/dbpreferencesvector_fuzzer/dbpreferencesvector_fuzzer.cpp`
- Source blob: `3de64e85dcba575ed35b6bc7f3e5b2fbcf223e2c`
- Source SHA-256: `4b4f6e8e9f7f8e4d06887b93f67352ba9c5e9cf9b697c7814cc713573c0b7dfe`
- BUILD: `test/native/fuzztest/dbpreferencesvector_fuzzer/BUILD.gn`; blob and SHA-256 are recorded in `t38_preferences_vector_replay_20261024.json`.
- CLI: `python -m src.cli.main ohscan-run --repo-dir <pinned-source-checkout> --repository openharmony/distributeddatamgr_preferences --commit bff9efd79afc0d7d1ed22a63ff355f1600404596 --include test/native/fuzztest/dbpreferencesvector_fuzzer/dbpreferencesvector_fuzzer.cpp --detector ohscanner.cpp.shared_ptr_race`
- Result: completed; parse `complete: 1`; detector `ohscanner.cpp.shared_ptr_race` 0.5.1; 6 diagnostics at all six queue locations.

## A0 row mapping

All six rows share the same source identity and detector rule `ohcpp-shared-ptr-race-candidate-001`. Each retains `not_testable / paused_pending_evidence` and is assessed PARTIAL.

| A0 ID | Source line | CLI candidate |
| --- | ---: | --- |
| CR-0091 | 45 | `ohscanner.cpp.shared_ptr_race:07d9e0bcac5b3c28` |
| CR-0092 | 50 | `ohscanner.cpp.shared_ptr_race:99b4bea93cf5d266` |
| CR-0093 | 52 | `ohscanner.cpp.shared_ptr_race:9ff4745d9094a32e` |
| CR-0094 | 68 | `ohscanner.cpp.shared_ptr_race:ae7a984b69ab110b` |
| CR-0095 | 77 | `ohscanner.cpp.shared_ptr_race:653de71495ef3908` |
| CR-0096 | 78 | `ohscanner.cpp.shared_ptr_race:eb9d0be0d85827d7` |

## Evidence limits and next action

The whole target source is syntactically complete, but that does not prove the fuzzer target is included in a product build. The entry function calls setup, Put, Get, and teardown in sequence; no thread creation or parallel dispatch is shown in this translation unit. Product BUILD inclusion, production caller reachability, same-object overlapping accesses, synchronization/ownership protocol, attacker control, and security impact remain unverified. Do not call these confirmed product vulnerabilities or confirmed false positives. Preserve all A0 states. No detector, tests, fixtures, or A0 rows were changed.

**Structured follow-up prompt:** Role: independent A-line Preferences race auditor. Sustained goal: determine whether any CR-0091–CR-0096 candidate corresponds to production-reachable unsynchronized concurrent access to the same Preferences object. Bind the exact product BUILD and caller path; trace object identity, threads/tasks, locks/atomics, teardown and attacker reachability; record missing evidence explicitly. Completion gate: independently sourced product-build and same-object concurrency evidence, or a precise blocker; otherwise preserve PARTIAL/BLOCK and all frozen queue states. Boundary: do not infer product vulnerability from fuzz harness syntax or alter A0 labels.

Artifacts: [machine replay](t38_preferences_vector_replay_20261024.json), [raw CLI output](t38_preferences_vector_cli_20261024.json), [replay/verifier script](t38_preferences_vector_20261024.py), and [independent verifier](verify_t38_preferences_vector_20261024.py).
