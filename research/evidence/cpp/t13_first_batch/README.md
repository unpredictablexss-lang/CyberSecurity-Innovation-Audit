# T13 A0 first-batch source triage

Date: 2026-10-20 (Asia/Shanghai)

Independent test/evidence checkout: `codex/a-t13-queue-first-batch-20261020`, started at `8e79a238c3689ec6ffc2d98559a801e1620042ed`.

This review covers the five rows currently marked `queued_first_batch`: CR-0016, CR-0017, CR-0018, CR-0336, and CR-0342. It preserves their original `not_testable` labels and queue state. The three DataShare IDs point to the same commit, tree, source blob, and file; they are related observations, not three independent defects.

## Method and result

- Re-read `research/deliveries/cpp/a0_triage_20261019/queue.json` and T12 acceptance JSON from this clean checkout.
- Read the exact OpenHarmony project-object mirrors under `D:/openHarmonyScanner/openharmony/.repo/project-objects`; verified each source commit, commit tree, path-to-blob entry, blob bytes, byte count, and SHA-256. The verifier repeats these checks.
- Inspected only the selected source and directly relevant same-commit functions needed to resolve the queued question. No detector, test, fixture, or queue source was edited.
- Independently reran the original A0 package verifier: 345 unique IDs; 97 manifest files / 4,364,747 bytes match; original status counts remain `not_reproduced=9`, `not_testable=336`; queue counts remain 9 / 5 / 331.

All five remain `PARTIAL/QUEUED`. Source observations provide useful next-step evidence, but none establishes the product security boundary, effective access policy, end-to-end reachability/impact, or target-specific concurrency proof needed to resolve the original queue question.

## Per-ID records

- [CR-0016](CR-0016.md) — DataShare `OpenFile` authorization and URI path.
- [CR-0017](CR-0017.md) — DataShare `CMD_OPEN_FILE` descriptor return.
- [CR-0018](CR-0018.md) — DataShare `CMD_OPEN_FILE_WITH_ERR_CODE` descriptor return.
- [CR-0336](CR-0336.md) — Wi-Fi manager remote-object export.
- [CR-0342](CR-0342.md) — HUKS async task cancellation/shared-state candidate.

JSON records sit beside each Markdown file. Run `python research/evidence/cpp/t13_first_batch/verify_t13_queue.py` to recheck all 345 baseline ID/status pairs, selected rows, T12 queue counts, and source object identities. The verifier expects the local OpenHarmony project-object mirrors at the path above; a missing mirror is reported as verification failure, not treated as an absent source object upstream.

## Next evidence needed

- CR-0016–0018: exact DataShare service/provider publication configuration, caller identity and permission declarations for the target build, path from externally reachable IPC transaction into provider code, and target-derived authorized/unauthorized controls. For the FD rows, also demonstrate which recipient can use the returned descriptor and what data it reaches.
- CR-0336: service publication/SA access-control policy for the target build, caller permissions/token domain, and the receiving `IWifiDevice` interface methods reachable through the exported object.
- CR-0342: exact async executor ownership/join/cancel contract and task lifetime proof across `Run`, `OnDone`, destruction, and death-recipient callbacks, followed by a target-derived concurrency harness only if an unsynchronized object access remains. The reviewed cancellation flag itself is `std::atomic<bool>`; that fact alone does not resolve shared ownership/task lifetime.\n