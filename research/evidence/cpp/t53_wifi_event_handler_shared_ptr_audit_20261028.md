# T53 — Wi-Fi event handler shared_ptr 独立审计（CR-0317–CR-0334）

## 结论

当前 `ohscan-run` 使用 `ohscanner.cpp.shared_ptr_race` 0.5.1 对 A0 精确源文件运行：1 个文件、386 LOC、完整解析、18 条 finding，与 18 个 A0 行按行号/列号/成员名全部对应。结论为 **PARTIAL/BLOCK**：这证明扫描器在该源码对象上复现了语法候选，不证明存在数据竞争、可利用路径或安全影响，也不证明安全。没有可信漏洞/修复源码对照或目标派生并发 harness。

## 来源绑定与范围

- 仓库：`openharmony/communication_wifi`
- commit/tree：`e336c82b3b107d87f68c5e0448cc246b50b53b38` / `edd28e23c84d17fa072f8501d7fe3dfbfa55498f`
- 目标：`wifi/utils/src/wifi_event_handler.cpp`，blob `859972d51001153749e1f3df5f8fc0bb5f5e3b7a`，SHA-256 `f5b5de6a96ae54bbe3563bc93206fcb625c3f8d19c299d1b6f82fe1df7123f01`，13345 bytes
- CLI：`ohscanner.cpp.shared_ptr_race` 0.5.1，scope 仅目标文件，解析 `complete`，18 findings，snapshot `0647e4b488d71e0cbe2cbabcc363c7a14c5f9cf0761f2594f6b92dc350e85616`，耗时 0.0649s
- 范围明确排除 CR-0335（`ohscanner.interface.ipc` 的另一源行/检测器）。A0 仍为 345 行，所审 18 行均保留 `not_testable / paused_pending_evidence`。

## 源码与构建核验

这 18 个候选都落在非 Lite、非 FFRT 的 `AppExecFwk::EventHandler` 分支。`eventRunner` 和 `eventHandler` 在构造时初始化，析构时先停止 runner 再 reset 两个 shared_ptr；同步/异步投递和任务移除方法直接通过 `eventHandler` 调用，普通分支没有成员锁。类公开 API 的 `ptr` 是 `unique_ptr<WifiEventHandlerImpl>`。Async callbacks 由 EventHandler 投递到其线程；仅凭本文件看不到 producer 与 callback、以及 API 调用与对象析构的真实重叠顺序。

另一 `WIFI_FFRT_ENABLE` 分支用 `eventQurueMutex` 包护构造、析构及队列访问。GN 将目标源文件加入 install-enabled `ohos_shared_library("wifi_utils")`，并根据 `wifi_ffrt_enable` 选择 FFRT 或 EventHandler 分支；精确产品配置/目标镜像未绑定。Pinned callers 包括 `wifi_timer.cpp` 和 state-machine `handler.cpp`，但调用拓扑不能证明同一实例与析构并发。unit test 注册 `wifi_event_handler_test.cpp`，未提供产品派生并发销毁 harness。

因此目前没有足够证据断言存在或不存在实际竞态。应保留原 A0 状态，后续最小补证是绑定产品 profile 的 GN 配置，再追踪同一实例的所有权/析构与所有投递 API 的线程交叠；若仍无法证明，则继续 PARTIAL/BLOCK。

## 每行对照

| A0 ID | 行:列 | 成员 | 当前 finding |
|---|---:|---|---|
| CR-0317 | 242:9 | `eventRunner` | `ohscanner.cpp.shared_ptr_race:a8fc574b326487ef` |
| CR-0318 | 243:13 | `eventRunner` | `ohscanner.cpp.shared_ptr_race:0ada707995ee8b21` |
| CR-0319 | 244:71 | `eventRunner` | `ohscanner.cpp.shared_ptr_race:68b113913f352a0b` |
| CR-0320 | 244:13 | `eventHandler` | `ohscanner.cpp.shared_ptr_race:7bb242c5d65530c7` |
| CR-0321 | 253:13 | `eventRunner` | `ohscanner.cpp.shared_ptr_race:2c9385dbcc7f77b1` |
| CR-0322 | 254:13 | `eventRunner` | `ohscanner.cpp.shared_ptr_race:14edf76841b24085` |
| CR-0323 | 255:13 | `eventRunner` | `ohscanner.cpp.shared_ptr_race:4d69ceeb80b97ea7` |
| CR-0324 | 257:13 | `eventHandler` | `ohscanner.cpp.shared_ptr_race:039671201a20a8a0` |
| CR-0325 | 258:13 | `eventHandler` | `ohscanner.cpp.shared_ptr_race:d57187bc21f696e4` |
| CR-0326 | 263:13 | `eventHandler` | `ohscanner.cpp.shared_ptr_race:427bae4d36662c16` |
| CR-0327 | 267:16 | `eventHandler` | `ohscanner.cpp.shared_ptr_race:0592c5705191914c` |
| CR-0328 | 271:13 | `eventHandler` | `ohscanner.cpp.shared_ptr_race:c639453f79a45ebc` |
| CR-0329 | 275:16 | `eventHandler` | `ohscanner.cpp.shared_ptr_race:89951e84d4d81df2` |
| CR-0330 | 279:13 | `eventHandler` | `ohscanner.cpp.shared_ptr_race:7ffe9742e8b0ed45` |
| CR-0331 | 284:20 | `eventHandler` | `ohscanner.cpp.shared_ptr_race:30386b9a97cdf48c` |
| CR-0332 | 286:16 | `eventHandler` | `ohscanner.cpp.shared_ptr_race:2edbccd59e776a43` |
| CR-0333 | 290:13 | `eventHandler` | `ohscanner.cpp.shared_ptr_race:cf036384f3144508` |
| CR-0334 | 294:9 | `eventHandler` | `ohscanner.cpp.shared_ptr_race:dacb98e342262d1a` |

机器记录：`t53_wifi_event_handler_shared_ptr_audit_20261028.json`；原始 CLI：`t53_wifi_event_handler_cli_20261028.json` 与 `.md`；重放/校验：`verify_t53_wifi_event_handler_audit_20261028.py`。
