# T62 independent acceptance — dSoftBus CVE-2025-26690

Date: 2026-10-30

## Result

**PARTIAL/BLOCK; no detector or fixture changes.** In an independent scanner worktree at `dac497e85b55baf9279368469047fc142b325ea6`, the current CLI reproduced D22's exact 5/0 differential. The source syntax parse is complete for both variants. The detector's own semantic analysis remains partial and execution remains blocked for both variants, so this is not a complete detection pass or proof of safety.

## Bound source identity

Repository declared by the source record: `openharmony/communication_dsoftbus`; path: `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp`.

| Variant | Commit | Tree | Path blob | Bytes | SHA-256 |
|---|---|---|---|---:|---|
| Vulnerable | `258662cd9840b55a31546a72d91027f6368cea84` | `366a4ced9400653c9628c0b677e4ae657c0e7bd8` | `a82b71fb5520b02278a4af695bbe918d14c1048e` | 8502 | `5453bd68645a7708f0d9ef9c214451a4735a256b5223729f6808ab34095125a6` |
| Fixed | `192f3e11d74beeaa3d879333471deb8a24a7e1c5` | `1d58ba0ef706a6f69dd372bd496c8058810882aa` | `13ddbe93a7f617784dec0f3761e09f66b5c3217c` | 9387 | `5a093d91efc624147d40bf3f4dbbe3ab7ab6d724b17978298e9d5c30d9e5eb81` |

The available bare Git object store at `D:\openHarmonyScanner\tmp\d22-upstream-dsoftbus-object-store` contains both full commits. Their actual commit/tree/path blob objects match the table, the fixed commit has the vulnerable commit as its parent, and the stored `FETCH_HEAD` records both IDs from `https://gitcode.com/openharmony/communication_dsoftbus`. Thus the inputs are not merely the prior one-file synthetic Git packages: this replay used full fetched commit objects. The fetch record and object graph do not constitute a signed publisher attestation; repository identity is still based on the recorded remote URL.

## Independent scanner replay

Detector `ohscanner.cpp.null_dereference` v0.6.0, rule `ohcpp-null-dereference-candidate-001` v1.4.0, profile `light-ast`, one-file scope. Commands were run from the T62 independent checkout; complete commands and durable outputs are retained in the machine record and linked JSON artifacts.

| Variant | CLI candidates | Candidate lines | Parse | Detector semantic coverage | Execution |
|---|---:|---|---|---|---|
| Vulnerable | 5 | 71, 82, 97, 108, 123 | complete (1/1) | partial (0/1 semantically complete) | blocked |
| Fixed | 0 | — | complete (1/1) | partial (0/1 semantically complete) | blocked |

The patch diff inserts `clientProxy == nullptr` checks before each of the five corresponding method dereferences. This supports the same-rule source differential. It does not resolve detector semantic coverage or establish the real allocation-failure path, production reachability, or impact.

## Controls and A0 reconciliation

The focused detector suite was rerun independently:

```text
python -m unittest tests.detectors.test_cpp_null_dereference_detector tests.detectors.test_cpp_null_dereference_signal_controls -q
Ran 21 tests — OK
```

These tests exercise mechanism-level positive/fixed/safe/unrelated and partial/failed/not-analyzed states. There are no independently source-bound safe or unrelated `communication_dsoftbus` controls in the available case evidence. They therefore do not close case-specific control coverage.

This CVE remains a separate row in the 2026-10-19 historical matrix and is not one of the 345 rows in `research/deliveries/cpp/a0_triage_20261019/queue.csv`. T62 verified 345 unique candidate IDs and the frozen status distribution: 336 `not_testable`, 9 `not_reproduced`; queue states 331 `paused_pending_evidence`, 5 `queued_first_batch`, and 9 `queued_not_reproduced`. No A0 queue row was changed. The dated case overlay remains `PARTIAL`, following the original matrix `BLOCK`.

## Minimum evidence to close

- Trusted product build/configuration and compilation context for the affected component.
- Independently source-bound dSoftBus safe and unrelated controls, with expected outcomes supported by source semantics.
- Detector semantic coverage that can resolve the relevant nullability and guard/dominance questions; rerun against these immutable objects.
- Caller/entry reachability, allocation-failure trigger feasibility, and concrete impact evidence; preferably a target-derived isolated allocation-failure test.
- Preserve `PARTIAL/BLOCK` until all applicable static requirements are independently accepted. Do not interpret the fixed zero-result as a safety verdict.
