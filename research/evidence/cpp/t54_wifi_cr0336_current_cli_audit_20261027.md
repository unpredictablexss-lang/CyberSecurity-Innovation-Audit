# T54 — CR-0336 Wi-Fi device-manager IPC audit

## Result

**PARTIAL/BLOCK; candidate reproduced, authorization and product reachability unresolved.** This independent replay against the frozen A0 source still reports `ipc.capability.export` at `wifi_device_mgr_stub.cpp:40`. The two explicitly selected C++ files parse completely (2/2). This establishes the static object-export pattern only; it does not establish unauthorized access or a vulnerability. A0 remains `not_testable / queued_first_batch`.

CR-0335 is the distinct Wi-Fi P2P `copy-range` candidate and is out of scope for this audit.

## Exact source identity

| Item | Binding |
|---|---|
| A0 row | CR-0336, candidate `ohscanner.interface.ipc:fc3ec640b7a45ebb` |
| Repository | `openharmony/communication_wifi` |
| Commit / tree | `e336c82b3b107d87f68c5e0448cc246b50b53b38` / `edd28e23c84d17fa072f8501d7fe3dfbfa55498f` |
| Candidate | `wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_sta_sa/wifi_device_mgr_stub.cpp:40`; blob `6106eb782ab6ffb605ec6ebff9e47ed5df923375`; SHA-256 `b23dc2a3573232cf9b2c4c682f20062b3a17d29335ec2b69799a8df01fd71793` |
| Function | `WifiDeviceMgrStub::GetWifiRemoteInner`; source line is `int ret = reply.WriteRemoteObject(obj);` |
| Service implementation | `wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_sta_sa/wifi_device_mgr_service_impl.cpp`; blob `6764cab322c82d860905316ace540f839816f7bf`; SHA-256 `053b74d3f95dded15ed95f49a2c31d4768e4777bf633066abdb45e326638916b` |
| Current replay | `ohscanner.interface.ipc` 0.12.12, `light-ast`, build profile `none`; one `ipc.capability.export` at the bound path/line; 2/2 complete parse |

The CLI JSON is [t54_wifi_cr0336_current_cli_20261027.json](t54_wifi_cr0336_current_cli_20261027.json), with its rendered report at [t54_wifi_cr0336_current_cli_20261027.md](t54_wifi_cr0336_current_cli_20261027.md).

## Source review and limits

`OnRemoteRequest` compares `ReadInterfaceToken()` with `GetDescriptor()` before dispatch. The `WIFI_MGR_GET_DEVICE_SERVICE` handler reads an instance ID, calls `GetWifiRemote(instId)`, and writes the returned remote object. `GetWifiRemote` rejects negative IDs, looks up the instance map under `g_initMutex`, and returns that instance's service object. The service is registered as system ability 1120 and the same source calls `Publish`; the checked-in `1120.json` names `libwifi_device_ability.z.so` and sets `distributed` to false. These are repository-local implementation/configuration facts, not proof that this exact profile is active in a particular product image or what its effective SA access policy is.

The receiving `WifiDeviceStub` dispatches the `IWifiDevice` operations. Its service implementation contains `WifiPermissionUtils` checks on selected sensitive methods (including Wi-Fi information and configuration operations). That evidence makes the export candidate insufficient by itself to conclude unauthorized sensitive use. This audit did not establish a complete transaction-to-handler-to-permission map, target-derived caller identity/token domain, exact product build/profile and effective SA policy, or a same-build comparison of authorized and unauthorized callers. No trusted fixed source or target-derived runtime harness was available.

Therefore this is not a vulnerability confirmation and not a safety conclusion. Preserve `PARTIAL/BLOCK` and original A0 statuses. Minimum next evidence: target product image/build and effective SA policy; caller principal/token and permission mapping; complete reachable operation-to-guard review; then compare authorized and unauthorized principals against that same target.

## Reproduction

```powershell
$env:GIT_DIR = 'D:\openHarmonyScanner\openharmony\.repo\project-objects\communication_wifi.git'
python -m src.cli.main ohscan-run --repo-dir D:\Temp\t54_wifi_cr0336_source_20261027 --repository openharmony/communication_wifi --commit e336c82b3b107d87f68c5e0448cc246b50b53b38 --include wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_sta_sa/wifi_device_mgr_stub.cpp --include wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_sta_sa/wifi_device_mgr_service_impl.cpp --detector ohscanner.interface.ipc --json-out research/evidence/cpp/t54_wifi_cr0336_current_cli_20261027.json --md-out research/evidence/cpp/t54_wifi_cr0336_current_cli_20261027.md
Remove-Item Env:GIT_DIR
python research/evidence/cpp/verify_t54_wifi_cr0336_audit_20261027.py --git-dir D:\openHarmonyScanner\openharmony\.repo\project-objects\communication_wifi.git
python research/deliveries/cpp/a0_triage_20261019/verify_triage.py
python scripts/check_change_scope.py --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp
```

The CLI result uses a selected two-file scope, not a product build. It does not cover macro expansion, linked target configuration, effective runtime authorization, or reachability from a particular caller.
