# D31 — CR-0335 exact production IPC replay

Date: 2026-10-22 (Asia/Shanghai)  
Baseline: `0eef782dd1e9d511321041ea75e49b55e1f64ebd`

## Result

The current production `ohscanner.interface.ipc` CLI **reproduces** the A0 candidate on the queue-bound source identity. Detector `0.12.12` / model `oh-ipc-2026.10-v32` emits `ohscanner.interface.ipc:975eebe9b420d417`, rule `ipc.parcel.copy-range`, at `wifi/frameworks/native/src/wifi_p2p_callback_stub.cpp:385`. The one-file scope parses completely (1/1), so this is not a parse-partial zero-result case. A0's original `not_reproduced` / `queued_not_reproduced` states remain unchanged; this D31 replay is new evidence, not an edit to the frozen queue.

Exact queue identity: commit `e336c82b3b107d87f68c5e0448cc246b50b53b38`, root tree `edd28e23c84d17fa072f8501d7fe3dfbfa55498f`, candidate blob `1cc8c5c0c0e60a17f49332a7bf7ea1d7d1115b91`, SHA-256 `d43aa28a22134dd47c85d17a5e0b017f9fb1d6b2611327c7f92140fbe347fc03`.

## Source and rule comparison

`OnRemoteRequest` validates the interface token and exception field, then dispatches `WIFI_CBK_CMD_CFG_CHANGE (0x3208)` through `handleFuncMap` to `RemoteOnConfigChanged`. Before the copy, the handler rejects `cfgLen <= 0` and `cfgLen > MAX_LEN` (`MAX_LEN == 1024`). It calls `ReadBuffer(cfgLen)`, allocates `char[cfgLen]`, and calls `memcpy_s(cfgData, cfgLen, dataBuffer, cfgLen)`. The helper `OnConfigChanged(cfgType, cfgData, cfgLen)` runs after the copy; the IPC adapter leaves that helper's multi-outcome return unresolved.

The emitted diagnostic describes the Parcel-derived length as lacking matched nonnegative/destination-capacity bounds, but both guards are visible on the handler path and allocation capacity, `memcpy_s` destination capacity, and source count are all `cfgLen`. Thus the candidate is detector-reproducible, while the stated CWE-125 mechanism is not established by this source excerpt. Whether `ReadBuffer(cfgLen)` may return less than `cfgLen`, product caller reachability, effective authorization and runtime behavior remain unverified. Do not promote the finding to confirmed or interpret this as a proof the component is safe.

## Provenance mismatch from the previous task input

T21 already identified that an earlier task input confused the root tree `edd28e23...` with a commit and paired it with a different blob/SHA (`6106eb78...` / `b23dc2a3...`). D31 uses the authoritative frozen A0 queue chain `e336...` commit → `edd28...` tree → `1cc8...` path blob → `d43a...` file SHA. The alternate object remains documented as a distinct blob, and no queue identity or status was rewritten.

## Reproduction command

```powershell
python -m src.cli.main ohscan-run `
  --repo-dir D:\openHarmonyScanner\worktrees\source-cr0335-d31-20261022 `
  --repository openharmony/communication_wifi `
  --commit e336c82b3b107d87f68c5e0448cc246b50b53b38 `
  --include wifi/frameworks/native/src/wifi_p2p_callback_stub.cpp `
  --detector ohscanner.interface.ipc `
  --json-out research/evidence/cpp/d31_cr0335_wifi_ipc_cli_20261022.json `
  --md-out research/evidence/cpp/d31_cr0335_wifi_ipc_cli_20261022.md
```

Full machine replay: [CLI JSON](d31_cr0335_wifi_ipc_cli_20261022.json). Source binding and A0 reconciliation: [D31 JSON](d31_cr0335_wifi_ipc_replay_20261022.json). Run the source/replay verifier `verify_d31_cr0335_wifi_ipc_replay.py` with the project object mirror, frozen A0 queue, and CLI JSON. Full A0 preservation is separately checked by `research/deliveries/cpp/a0_triage_20261019/verify_triage.py`.

## Remaining evidence

This candidate remains unconfirmed. To resolve the CWE-125 hypothesis, bind and inspect the matching `MessageParcel::ReadBuffer` implementation and establish its behavior for a truncated parcel at the same product IPC revision. Also obtain the product build/profile and callback remote-object registration/permission context; a fuzzer declaration or direct stub invocation alone does not establish product reachability. No fixed source was provided, so no fixed-control claim is made.
