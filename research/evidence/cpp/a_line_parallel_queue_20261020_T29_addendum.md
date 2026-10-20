### T29 — CR-0336 Wi-Fi IPC capability export audit (testing/evidence)

```text
Role: Independent A-line IPC audit reviewer.
Continuous goal: independently verify source identity, scanner candidates, access-boundary evidence, and missing-proof queue for A0 IPC cases.
Inputs: integration baseline 2c1535fd8c4fde34eb506725de8a9fbe9cb666b6; frozen A0 CR-0336 row; exact communication_wifi commit/tree/blob/SHA; current IPC detector output.
Steps: verify the source objects; rerun the current CLI on the source-bound stub and service implementation; inspect transaction dispatch, service publication, SA profile, returned interface, and receiver permission checks; record product-policy/runtime unknowns and preserve original queue status.
Done when: the candidate and every reviewed source have a reproducible identity, current parse/finding coverage is recorded, and the evidence verifier plus A0 and change-scope checks pass.
Boundaries: do not change detector/tests/fixtures/API/Catalog or queue status; do not treat export alone as unauthorized use; do not treat missing policy/build evidence, partial coverage, or zero findings as safety.
```

T29 independently replays CR-0336 on the exact A0 Wi-Fi source. The current IPC CLI emits the source-bound syntax candidate at `wifi_device_mgr_stub.cpp:40` with complete parsing for the two-file scope. The same commit publishes manager SA 1120 and contains a receiving `IWifiDevice` surface with permission checks in selected service methods, but exact product selection/effective SA policy, caller token domain, complete operation-to-permission reachability, and target-derived caller comparison remain unknown. CR-0336 remains **PARTIAL/BLOCK** and `not_testable / queued_first_batch`. See [audit report](t29_wifi_ipc_source_audit_20261020.md), [raw CLI report](t29_wifi_ipc_candidate_20261020.json), and [verifier](verify_t29_wifi_ipc_source_audit.py).
