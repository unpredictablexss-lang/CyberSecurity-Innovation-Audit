# T59 — Independent camera framework shared_ptr_race audit CR-0261–CR-0290

## Result

**PARTIAL/BLOCK.** T59 independently rebound the 30 requested A0 rows to `openharmony/multimedia_camera_framework` commit `35445b57d739a41cb916330935e61f1e83d982ca`, tree `2907d1748b46897c49c8f8c253c49384294a6a7a`, and verified every row's blob OID and source SHA-256 against the pinned Git object database. The A0 CSV and JSON still contain 345 unique IDs, and all 30 target IDs retain `not_testable / paused_pending_evidence`.

Current `ohscanner.cpp.shared_ptr_race` 0.5.1 replay selected the 13 distinct A0 source files. All 13 parsed syntactically complete; the detector run is `blocked` with 13 diagnostics. Exact `(path, line, column, symbol)` mapping reproduces 10/30 A0 locations and leaves 20 unmapped. This is a candidate replay, not a vulnerability verdict. Complete syntax parsing does not establish detector semantic coverage or safety.

## Exact replay

The independent checkout was materialized at the exact A0 commit. Replay command shape:

```text
python -m src.cli.main ohscan-run --repo-dir <pinned-checkout> --repository openharmony/multimedia_camera_framework --commit 35445b57d739a41cb916330935e61f1e83d982ca --include <each of the 13 distinct A0 paths> --detector ohscanner.cpp.shared_ptr_race --json-out research/evidence/cpp/t59_camera_sharedptr_cli_20261030.json --md-out research/evidence/cpp/t59_camera_sharedptr_cli_20261030.md
```

| A0 IDs | Exact line/column/symbol result |
| --- | --- |
| CR-0261 | Hit: `camera_auto_ref_taihe.h:52`, `callbackRef_` |
| CR-0262–0265 | No exact hit |
| CR-0266–0275 | No exact hit |
| CR-0276–0278 | Hit: `buffer_wrapper_base.h:47/122/127`, `encodedBuffer_` |
| CR-0279 | No exact hit |
| CR-0280–0283 | Hit: `unified_pipeline_audio_capture_wrap.h:75/81/86/87`, `audioCapturer_` |
| CR-0284–0285 | No exact hit |
| CR-0286–0287 | Hit: `camera_rotate_strategy_parser.h:40/48`, `curNode_` |
| CR-0288–0290 | No exact hit |

The current run also reports candidates outside these exact A0 keys; T59 does not re-label them. Per-row findings and source identity are in the machine audit JSON.

## Source and build-context observations

- CR-0261's getter reads `AutoRef::callbackRef_`. D47's nearby Taihe review found accesses routed under `CallbackList::listMutex`; the getter's exact call context still requires caller-by-caller validation for this wider row set.
- CR-0262–0264 and CR-0267–0269 reference listener-map lookup/update methods explicitly named `NoLock`. The method names do not prove that every caller holds the same lock; entry points, environment/thread affinity, and callers must be traced before a race claim.
- CR-0276–0278 include destructor reset, setter, and getter access to `encodedBuffer_` without an in-line guard. Same-instance lifetime overlap and external synchronization are unresolved.
- CR-0280–0283 dereference/use `audioCapturer_`; this source slice does not prove conflicting writes or concurrent access. CR-0284–0285 are callback-wrapper constructor initializations and likewise need lifetime/dispatch context.
- CR-0286–0287 are parser construction/destruction writes to `curNode_`; concurrent destruction/use has not been established.
- The pinned tree contains production-capable GN targets in Taihe (`camera_taihe`, `camera_picker_taihe`), JS camera NAPI (`camera_napi`, `camerapicker_napi`), `movie_file`, `camera_service`, and `deferred_processing_service`. However, this pass did not prove direct target ownership, selected product profile, macro expansion, or whether each candidate header is linked into a specific product image. No row is labeled testonly or product-reachable based only on a neighboring BUILD.gn.
- No trustworthy fixed-source counterpart or target-derived concurrency harness/TSan result is bound to these 30 rows.

## Minimum follow-up

1. Trace callers and all reads/writes of each candidate object, resolve aliases and lock identity/guard dominance, and document executor/callback ordering.
2. Bind each source to an exact GN target and enabled product configuration; mark testonly harnesses separately from targets reachable in shipped products.
3. For a demonstrated conflicting same-object access, obtain a target-derived reproducer or race-detector result and a trusted fixed revision. Otherwise leave the row `PARTIAL/BLOCK`.

The verifier checks all 345 queue IDs, the 30 exact repository/commit/tree/blob/SHA bindings, unchanged original and queue states, the exact current CLI mapping, parse counts, and detector version. It does not alter A0 data. See [machine audit](t59_camera_sharedptr_audit_20261030.json), [raw CLI JSON](t59_camera_sharedptr_cli_20261030.json), [CLI report](t59_camera_sharedptr_cli_20261030.md), and [verifier](verify_t59_camera_sharedptr_20261030.py).
