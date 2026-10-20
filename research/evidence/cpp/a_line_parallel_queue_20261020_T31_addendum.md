# T31 — CR-0335 Wi-Fi copy-range 独立复核

日期：2026-10-21（Asia/Shanghai）
Scanner baseline：`0eef782dd1e9d511321041ea75e49b55e1f64ebd`

## 结论

- 按冻结 A0 CSV/JSON 的对象身份复核：commit `e336c82b3b107d87f68c5e0448cc246b50b53b38`，root tree `edd28e23c84d17fa072f8501d7fe3dfbfa55498f`，候选文件 blob `1cc8c5c0c0e60a17f49332a7bf7ea1d7d1115b91`，文件 SHA-256 `d43aa28a22134dd47c85d17a5e0b017f9fb1d6b2611327c7f92140fbe347fc03`。T21 输入中把 tree 当成 commit、并给出不同 blob/SHA 的身份不匹配未被沿用；A0 台账没有改写。
- 使用当前 IPC CLI 独立扫描 queue-bound commit 的目标文件，得到 1 个 `ipc.parcel.copy-range` 候选：诊断 ID `ohscanner.interface.ipc:975eebe9b420d417`，目标 `wifi/frameworks/native/src/wifi_p2p_callback_stub.cpp:385`，函数 `WifiP2pCallbackStub::RemoteOnConfigChanged`。候选行与 A0 blob/SHA 对应。
- 该文件 CLI 解析及 IPC coverage 均为 complete（1/1）。这仅说明此目标文件在本次 light-ast 运行中完整分析，不补足产品构建或跨仓库 IPC 语义证据。
- 候选附近代码先拒绝 `cfgLen <= 0` 与 `cfgLen > MAX_LEN`（1024），再按 `cfgLen` 调用 `ReadBuffer`、分配 `cfgLen` 字节，并以同为 `cfgLen` 的目标容量和源长度调用 `memcpy_s`。因此静态候选复现了，但源码未显示该复制长度失配，不能据此确认 CWE-125；也不能将本次未建立漏洞等同产品安全。
- A0 `original_status=not_reproduced`、`queue_status=queued_not_reproduced` 保持原值。无可信 fixed source；产品 callback remote object 所属/调用者权限、产品构建配置、Parcel 目标版本语义和运行时影响均未证实。最终为 **PARTIAL/BLOCK**。

## 复跑与验证

```powershell
python -m src.cli.main ohscan-run --repo-dir D:/Temp/cr0335_t31_wifi_audit_20261021 --repository openharmony/communication_wifi --commit e336c82b3b107d87f68c5e0448cc246b50b53b38 --include wifi/frameworks/native/src/wifi_p2p_callback_stub.cpp --detector ohscanner.interface.ipc --json-out research/evidence/cpp/t31_cr0335_wifi_p2p_cli_20261021.json --md-out research/evidence/cpp/t31_cr0335_wifi_p2p_cli_20261021.md
python research/evidence/cpp/verify_t31_cr0335_wifi_p2p_audit.py --git-dir D:/openHarmonyScanner/openharmony/.repo/project-objects/communication_wifi.git --queue research/deliveries/cpp/a0_triage_20261019/queue.json --cli-json research/evidence/cpp/t31_cr0335_wifi_p2p_cli_20261021.json
python research/deliveries/cpp/a0_triage_20261019/verify_triage.py
python -m scripts.check_change_scope --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp
git diff --check
```

机器可读审计与 verifier：[`t31_cr0335_wifi_p2p_audit_20261021.json`](t31_cr0335_wifi_p2p_audit_20261021.json)、[`verify_t31_cr0335_wifi_p2p_audit.py`](verify_t31_cr0335_wifi_p2p_audit.py)；原始 CLI 输出：[`t31_cr0335_wifi_p2p_cli_20261021.json`](t31_cr0335_wifi_p2p_cli_20261021.json)。
