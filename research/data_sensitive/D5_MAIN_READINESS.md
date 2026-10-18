# D5 main readiness

| Gate | Status | Evidence / remaining condition |
|---|---|---|
| M0: default-off isolated module | **Not met** | D suite 41/41, full Python suite 870 pass / 0 fail / 5 skip, and frontend tests 16/16 (frontend result is the prior D8 run). Fixed-source dual replay is blocked. Full dependency/license review and a clean latest-main CI result remain. Keep D unregistered. |
| M1: explicit experimental registration | **Not met** | Shared partial-AST admission and UI/report integration are owner work. Public Runner still withholds partial D files. No D registration or shared-path change was made. |
| M2: default one-click scan | **Not met** | One exact historical API model, no two independent shapes, no independent labeled real-source holdout, no measured recall/precision or end-to-end runtime/resource benchmark. |
| M3: confirmed product vulnerability | **Not met** | No product build identity, dynamic synthetic-trigger evidence, unauthorized reader proof, validated remediation build, or product impact/version map. `validated_vulnerability=0`. |

Recommendation: preserve the module as research-only on this branch. Re-run
the frontend build/test in a Node-enabled clean environment and restore the
exact historical source Git objects before reconsidering M0. The shared
platform owner must separately approve partial evidence admission and any
experimental UI path. No automatic Catalog registration or confirmation is
appropriate.


D9 updated the detector to 0.6.0 and added pinned upstream HiLog macro sinks (sink model 0.2.0). D10 verified the exact upstream tree and all 10 DSoftBus manifest files plus 3 HiLog API header blobs. D11 then added bounded tracking for direct fields of explicitly modeled sensitive struct types and raised the detector to 0.7.0. The 9 selected DSoftBus code files parse as 3 complete / 6 partial; the detector remains blocked with 1 unresolved cross-file call candidate. The two local crypto member copies no longer produce unresolved escapes because the reviewed functions do not pass them to a public-log sink. This direct manifest-bound replay is not public Git Runner validation. No independent labeled real-source holdout, product/build binding, runtime validation, or reader-impact evidence exists; shared partial-source admission remains unavailable and validated_vulnerability=0. See D10_REAL_SOURCE_REPLAY.json.
