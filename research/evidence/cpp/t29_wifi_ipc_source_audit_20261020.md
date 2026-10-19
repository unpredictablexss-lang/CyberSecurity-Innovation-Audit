# T29 — CR-0336 Wi-Fi capability export audit

## Disposition

**PARTIAL/BLOCK; candidate reproduced, product authorization boundary unresolved.** The frozen A0 source identity matches the exact `communication_wifi` commit/tree/blob and source SHA-256. A current production M2 replay parsed the two scoped C++ files completely and reproduced one `ipc.capability.export` syntax candidate at `wifi_device_mgr_stub.cpp:40`. The service implementation publishes the device manager as SA 1120, and `GetWifiRemoteInner` returns a mapped `IWifiDevice` remote object. The receiving `WifiDeviceStub` dispatches many interface operations; the associated `WifiDeviceServiceImpl` contains permission checks on operations. This prevents interpreting object export alone as proof of unauthorized sensitive use.

No target product build/profile, effective SA access policy, caller principal/token, operation-by-operation permission map, or authorized-vs-unauthorized target comparison was available. Therefore this audit establishes an export path and an unresolved boundary, not an exploitable vulnerability or a safe result. The original A0 status remains `not_testable`; queue status remains `queued_first_batch`.

## Frozen identity and current CLI

- A0 identity: repository `openharmony/communication_wifi`; commit `e336c82b3b107d87f68c5e0448cc246b50b53b38`; tree `edd28e23c84d17fa072f8501d7fe3dfbfa55498f`.
- Candidate: `wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_sta_sa/wifi_device_mgr_stub.cpp`, line 40; blob `6106eb782ab6ffb605ec6ebff9e47ed5df923375`; 2,088 bytes; SHA-256 `b23dc2a3573232cf9b2c4c682f20062b3a17d29335ec2b69799a8df01fd71793`.
- Supporting service implementation: blob `6764cab322c82d860905316ace540f839816f7bf`; SHA-256 `053b74d3f95dded15ed95f49a2c31d4768e4777bf633066abdb45e326638916b`.
- CLI: `ohscanner.interface.ipc` 0.12.12, profile `light-ast`, build profile `none`, selected scope is the candidate stub plus same-commit service implementation. Both files parsed completely; one syntax candidate at line 40, symbol `WifiDeviceMgrStub::GetWifiRemoteInner`, rule `ipc.capability.export`, severity/confidence unassessed. Snapshot digest: `37bf27f6cbd08cb7aa1b19690b400a6326b86b6c9f2805d68e4a729891b2bacf`.
- Raw M2 report: [t29_wifi_ipc_candidate_20261020.json](t29_wifi_ipc_candidate_20261020.json).

## Independent source review

1. `WifiDeviceMgrStub::OnRemoteRequest` checks the interface token against `GetDescriptor()` and dispatches `WIFI_MGR_GET_DEVICE_SERVICE`. `GetWifiRemoteInner` reads `instId`, calls `GetWifiRemote(instId)`, and writes the returned object to the reply. The call therefore exports an object after token checking, but the token is not itself caller authorization proof.
2. `WifiDeviceMgrServiceImpl` is constructed as `SystemAbility(WIFI_DEVICE_ABILITY_ID, true)`, initializes per-instance `WifiDeviceServiceImpl` objects, stores their remote objects, then calls `Publish(...)`. The same source declares `WIFI_DEVICE_ABILITY_ID` as the identifier published in service profile `1120.json`; that profile names `libwifi_device_ability.z.so`, with distributed=false. The repository profile is source evidence only; no exact product image/configuration was supplied to show this SA is selected for a target build or how effective SA access control is applied.
3. `wifi_device_mgr_proxy.cpp` sends the matching manager transaction. `i_wifi_device.h` and `wifi_device_stub.cpp` define the returned remote interface and its dispatch surface. `wifi_device_service_impl.cpp` contains permission checks for sensitive operations (for example, enable/disable and Wi-Fi information paths). A complete code-to-handler-to-permission map for all exposed operations and the deployed `WifiPermissionUtils` policy was not established here.
4. No target-derived caller identity, token domain, SA policy/manifest, build profile, or two-principal authorized/unauthorized comparison is available. No runtime reproduction was attempted.

## Per-ID status and next evidence

| ID | Static result | Independent conclusion | Queue state |
|---|---|---|---|
| CR-0336 | Candidate reproduced at the exact A0 line; 2/2 scoped files parse complete | Export mechanism present; unauthorized access and sensitive impact not established; `PARTIAL/BLOCK` | `not_testable / queued_first_batch` unchanged |

Minimum next input: exact target product build/configuration and SA policy; allowed caller token/permission mapping; full reachable `IWifiDevice` method-to-permission review; then compare authorized and unauthorized principals against that same build. Preserve the candidate as unresolved until those facts exist.

## Reproduction and verification

```powershell
$env:GIT_DIR = 'D:\openHarmonyScanner\openharmony\.repo\project-objects\communication_wifi.git'
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\openharmony\foundation\communication\wifi --repository openharmony/communication_wifi --commit e336c82b3b107d87f68c5e0448cc246b50b53b38 --include wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_sta_sa/wifi_device_mgr_stub.cpp --include wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_sta_sa/wifi_device_mgr_service_impl.cpp --detector ohscanner.interface.ipc --json-out research/evidence/cpp/t29_wifi_ipc_candidate_20261020.json
Remove-Item Env:GIT_DIR
python research/evidence/cpp/verify_t29_wifi_ipc_source_audit.py --git-dir D:\openHarmonyScanner\openharmony\.repo\project-objects\communication_wifi.git --queue-json research/deliveries/cpp/a0_triage_20261019/queue.json
python research/deliveries/cpp/a0_triage_20261019/verify_triage.py
python scripts/check_change_scope.py --base 2c1535fd8c4fde34eb506725de8a9fbe9cb666b6 --lane cpp
```

The source object mirror is local and read-only in this audit. The current M2 report is bounded to two files: complete syntax parsing does not substitute for macro/build/link, effective permissions, product reachability, or runtime evidence.
