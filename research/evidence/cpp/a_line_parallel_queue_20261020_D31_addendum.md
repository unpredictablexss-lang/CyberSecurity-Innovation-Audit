# D31 — CR-0335 exact IPC detector replay

Date: 2026-10-22

- The exact frozen A0 source identity is `e336c82b3b107d87f68c5e0448cc246b50b53b38` commit → `edd28e23c84d17fa072f8501d7fe3dfbfa55498f` tree → `1cc8c5c0c0e60a17f49332a7bf7ea1d7d1115b91` candidate blob → SHA-256 `d43aa28a22134dd47c85d17a5e0b017f9fb1d6b2611327c7f92140fbe347fc03`.
- Current production IPC detector `0.12.12` reproduces `ipc.parcel.copy-range` at the queue line 385 on a complete single-file parse. This candidate is supported by exact CLI evidence; D31 did not modify the B-owned detector.
- Source review finds `cfgLen <= 0` and `cfgLen > MAX_LEN (1024)` early returns; `ReadBuffer`, allocation and `memcpy_s` all use `cfgLen`, with copy capacity/count equal. The current candidate message does not reflect these guards. The source excerpt does not establish CWE-125; `ReadBuffer` semantics, product build, callback reachability/authorization and runtime remain unknown. The case remains PARTIAL, not confirmed or safe.
- A prior task-input mismatch is preserved: `edd28...` is the queue commit's tree, not the commit; alternate blob `6106...` hashes to `b23d...`, unlike queue-bound blob `1cc8...` / SHA `d43a...`.
- A0 row remains `not_reproduced / queued_not_reproduced`; no queue file was edited.

Evidence: [D31 analysis](d31_cr0335_wifi_ipc_replay_20261022.md), [machine record](d31_cr0335_wifi_ipc_replay_20261022.json), [exact CLI output](d31_cr0335_wifi_ipc_cli_20261022.md), [replay verifier](verify_d31_cr0335_wifi_ipc_replay.py).
