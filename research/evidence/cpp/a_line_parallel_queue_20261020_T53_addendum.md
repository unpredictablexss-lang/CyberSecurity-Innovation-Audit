# T53 — Wi-Fi event handler shared_ptr 独立复核（CR-0317–CR-0334）

T53 将 18 条 A0 记录全部绑定到 `openharmony/communication_wifi` commit `e336c82b3b107d87f68c5e0448cc246b50b53b38` / tree `edd28e23c84d17fa072f8501d7fe3dfbfa55498f` 的同一个目标文件对象：`wifi/utils/src/wifi_event_handler.cpp`，blob `859972d51001153749e1f3df5f8fc0bb5f5e3b7a`，SHA-256 `f5b5de6a96ae54bbe3563bc93206fcb625c3f8d19c299d1b6f82fe1df7123f01`。

当前一方 `ohscan-run` / `ohscanner.cpp.shared_ptr_race` 0.5.1 对精确单文件范围解析 complete，386 LOC，复现 18 个候选；所有行号、列号与 `eventRunner` / `eventHandler` 成员均逐条对应 A0。源码核验显示候选行位于普通 EventHandler 条件编译分支：构造期间创建 runner/handler，析构期间停止 runner 并 reset 两者，投递/移除方法通过 `eventHandler` 调用且此分支无显式成员锁。另一个 FFRT 分支通过 `eventQurueMutex` 保护相关操作。GN 将文件加入 install-enabled `wifi_utils` shared library，实际产品配置选择哪个分支未知。异步回调调度与同一实例的调用/析构重叠，不能从该文件及有限调用点证明；单元测试也没有目标派生并发销毁 harness。

判定为 **PARTIAL/BLOCK**：候选命中不是竞态确认；完整解析、没有可绑定的可信漏洞/修复差分、产品 profile 和对象生命周期/线程重叠证据未齐，均不支持 PASS 或安全结论。18 条 A0 均保留 `not_testable / paused_pending_evidence`。CR-0335 是 IPC detector/source-line 案例，本审计明确排除。未修改 detector、tests、fixtures 或 A0 数据。

详见 [审计报告](t53_wifi_event_handler_shared_ptr_audit_20261028.md)、[机器记录](t53_wifi_event_handler_shared_ptr_audit_20261028.json)、[当前 CLI 原始输出](t53_wifi_event_handler_cli_20261028.json) 及 [复跑/验证器](verify_t53_wifi_event_handler_audit_20261028.py)。
