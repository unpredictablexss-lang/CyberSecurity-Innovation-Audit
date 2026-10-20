### T54 — CR-0336 Wi-Fi device-manager IPC independent replay (testing/evidence)

Role: A-line independent IPC test reviewer.
Continuous goal: reproduce A0 source-bound findings with the current production IPC CLI and retain source identity and unresolved authorization evidence.
Scope: CR-0336 `wifi_device_mgr_stub.cpp:40` only. CR-0335 is the separate P2P `copy-range` family and is explicitly excluded.

The frozen source remains `openharmony/communication_wifi` commit `e336c82b3b107d87f68c5e0448cc246b50b53b38`, tree `edd28e23c84d17fa072f8501d7fe3dfbfa55498f`; the A0 candidate blob/SHA-256 still match. A current `ohscanner.interface.ipc` 0.12.12 replay reports `ipc.capability.export` at line 40 and parses both selected files completely. Source review confirms interface-token validation and the returned object path; selected receiver operations enforce `WifiPermissionUtils` checks. Effective target SA policy, product selection, caller principal/token and the complete operation-to-permission path remain unknown. This is not a vulnerability confirmation or safety conclusion.

Disposition stays **PARTIAL/BLOCK**; frozen A0 remains `not_testable / queued_first_batch`. See [T54 audit](t54_wifi_cr0336_current_cli_audit_20261027.md), [current CLI JSON](t54_wifi_cr0336_current_cli_20261027.json), [CLI report](t54_wifi_cr0336_current_cli_20261027.md), and [verifier](verify_t54_wifi_cr0336_audit_20261027.py).
