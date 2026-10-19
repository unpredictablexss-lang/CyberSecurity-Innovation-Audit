# T21 — CR-0335 Wi-Fi source-bound queue audit

Date: 2026-10-20 (Asia/Shanghai)

## Disposition

- A0 identity: `CR-0335`, candidate `ohscanner.interface.ipc:301c45d0f546f9f3`.
- Original and queue states remain exactly `not_reproduced` / `queued_not_reproduced`.
- Source-level IPC path review: **PARTIAL**. The exact copy site is guarded and uses matching source count, destination capacity, and allocation size; this review does not establish an out-of-bounds read. It does not prove product-level reachability, Parcel implementation semantics, effective caller permissions, or runtime behavior.
- No detector, tests, fixtures, scanner conclusion, or A0 status was changed.

## Source identity correction

The task input labeled `edd28e23...` as a commit and supplied blob `6106eb78...` / SHA-256 `b23dc2a3...`. The frozen A0 queue instead binds the candidate to commit `e336c82b3b107d87f68c5e0448cc246b50b53b38`, tree `edd28e23c84d17fa072f8501d7fe3dfbfa55498f`, blob `1cc8c5c0c0e60a17f49332a7bf7ea1d7d1115b91`, and SHA-256 `d43aa28a22134dd47c85d17a5e0b017f9fb1d6b2611327c7f92140fbe347fc03`. The project object mirror confirms `e336...` is a commit, `edd...` is its root tree, `1cc...` is the exact candidate path blob, and `6106...` is a different blob object. The candidate file bytes hash to `d43a...`, not `b23...`. The original queue values and states are preserved; see the machine-checkable record and verifier alongside this addendum.

## Source findings

- Transaction `P2PInterfaceCode::WIFI_CBK_CMD_CFG_CHANGE` is `0x3208`; `InitHandleMap` binds it to `RemoteOnConfigChanged`.
- `OnRemoteRequest` checks the interface token and exception value, then dispatches by code. The reviewed stub does not identify the effective owner/caller boundary or an explicit permission check.
- In `RemoteOnConfigChanged`, `cfgLen <= 0` and `cfgLen > MAX_LEN` are rejected before `ReadBuffer`; `MAX_LEN` is 1024. A `cfgLen`-byte destination is allocated, `ReadBuffer(cfgLen)` must return non-null, and `memcpy_s` uses destination capacity `cfgLen` and source count `cfgLen`. The reviewed operation does not substantiate the queued CWE-125 hypothesis by itself.
- No FD or remote-object payload flow appears in this method/dispatch path.
- A `wifip2pcbkstub_fuzzer` test target directly calls the stub and compiles the same source. This is test-only evidence: no build/run result or product configuration was available, and it does not independently prove a production caller can reach the callback.

## Reproduction

From this checkout, run:

```powershell
python research/evidence/cpp/verify_cr0335_wifi_p2p_source_audit.py --git-dir D:/openHarmonyScanner/openharmony/.repo/project-objects/communication_wifi.git --queue research/deliveries/cpp/a0_triage_20261019/queue.json
python research/deliveries/cpp/a0_triage_20261019/verify_triage.py
python -m scripts.check_change_scope --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp
git diff --check
```

The first verifier checks commit/tree/blob/SHA, candidate line, transaction mapping, fuzz harness source identity, and the preserved queue row. The second verifies the full 345-ID A0 queue against the frozen source package. Both must be rerun in the independent checkout before integration.

## Smallest remaining evidence

1. Confirm which product build/profile includes this callback stub and obtain its build configuration.
2. Trace callback remote-object registration/ownership and the actual allowed caller/permission boundary.
3. If an OOB claim remains, validate `MessageParcel::ReadBuffer` length behavior at the corresponding IPC revision and reproduce against the product-derived target; the reduced source model and fuzzer declaration are not a product reproduction.
