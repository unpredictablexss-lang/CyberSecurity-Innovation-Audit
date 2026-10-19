# T55 — communication_wifi fuzz Stub IPC candidates CR-0337–CR-0340

## 结论

**PARTIAL/BLOCK；四个 A0 候选均绑定精确 fuzz harness 源码，但不能认定为产品 IPC 漏洞。** 当前 `ohscanner.interface.ipc` 0.12.12 production CLI 对四个文件逐文件运行，全部完整解析，四次均为 0 findings。当前 CLI 明确排除 `test/fuzz/mock` 路径作为产品入口。A0 原状态 `not_testable / paused_pending_evidence` 全部保留。

## 来源身份与逐文件重放

| A0 ID | 文件:行 | blob | SHA-256 | 当前 CLI | 解析 | findings |
|---|---|---|---|---|---|---:|
| CR-0337 | `wifi/test/fuzztest/wifi_sta/wifidevicestub_fuzzer/wifidevicestub_fuzzer.cpp:118` | `988a6424a18cf2d7f24592ccdc667d264921dd3b` | `d86c855dd10f3de73bde744ed047792477eade8aaf8f667345f50e0ac1d01054` | `0.12.12` completed | complete | 0 |
| CR-0338 | `wifi/test/fuzztest/wifi_sta/wifihotspotstub_fuzzer/wifihotspotstub_fuzzer.cpp:73` | `13f3fb531bff0a9be8fdd3a3b16adf9187a2d40e` | `fe1d3be9c326d58d1f41619fa62d754a75e125f133ca9d02dc178968fef885b6` | `0.12.12` completed | complete | 0 |
| CR-0339 | `wifi/test/fuzztest/wifi_sta/wifip2pstub_fuzzer/wifip2pstub_fuzzer.cpp:65` | `9b805531566fe9e62828f63f5f5a1a0736c64116` | `0bf839a6cc92ff07174b53f1c56e22bd2aee412054604431f1769654547351ce` | `0.12.12` completed | complete | 0 |
| CR-0340 | `wifi/test/fuzztest/wifi_sta/wifiscanstub_fuzzer/wifiscanstub_fuzzer.cpp:67` | `a4aeaf1f0be564e983789516004c5792034f0e12` | `2790fa0df0be218bbf9ea5b8f9fb4a463f396835086afff9689ef68bab483441` | `0.12.12` completed | complete | 0 |

所有行绑定到 `e336c82b3b107d87f68c5e0448cc246b50b53b38` / tree `edd28e23c84d17fa072f8501d7fe3dfbfa55498f`。逐文件原始 JSON/Markdown 与哈希写入 [T55 JSON](t55_wifi_fuzz_ipc_audit_20261029.json)。

## GN 与 Stub 关系

`wifi/test/fuzztest/wifi_sta/BUILD.gn` 将四个 target 注册在 `testonly = true` 的 `fuzztest` group 下。四个 harness 都构造或获取真实 Wifi service implementation/Stub，并调用其 `OnRemoteRequest`；各 target 对应 service implementation source set，相关 install-enabled ability 也依赖该 source set。harness 确实驱动生产实现代码，但 fuzz target 本身仍是 testonly，不证明产品中存在同一输入入口、身份或调用授权关系。GN/实现源码均在 JSON 中有 blob 与 SHA-256。

## 判断与后续补证

A0 原候选行落在 fuzz harness 的 `Init()` 包装/转发函数，不等于生产 Stub 的安全边界缺失。production CLI 0 finding 仅表明现规则不把这些 harness 行列为产品 dispatcher，不能作为安全判断；fuzz target 可用于证明对应 Stub 处理器接受这些 Parcel/code 形状。未知项包括产品 profile/build、外部 caller principal、权限门控与真实入口、影响及修复对照。A0 状态和 345 行账本未修改。

## 复跑

```powershell
$env:GIT_DIR='D:\openHarmonyScanner\openharmony\.repo\project-objects\communication_wifi.git'
python -m src.cli.main ohscan-run --repo-dir D:\Temp\t54_wifi_cr0336_source_20261027 --repository openharmony/communication_wifi --commit e336c82b3b107d87f68c5e0448cc246b50b53b38 --include <one A0 path> --detector ohscanner.interface.ipc --json-out <row JSON> --md-out <row Markdown>
Remove-Item Env:GIT_DIR
python research/evidence/cpp/verify_t55_wifi_fuzz_ipc_audit_20261029.py
python research/deliveries/cpp/a0_triage_20261019/verify_triage.py
python scripts/check_change_scope.py --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp
```

CLI selected-file replay is not a product build, authorization proof or runtime test.
