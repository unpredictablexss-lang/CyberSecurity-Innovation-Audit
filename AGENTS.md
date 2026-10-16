# OHScanner project instructions

## 上下文路由

默认只加载本文件和 `docs/项目现状与下一步.md`。不要为了“完整性”批量读取六份文档或 research 证据。

| 任务 | 按需追加 |
|---|---|
| 公共契约、检测器语义、Runner/Catalog | `docs/架构与公共协议.md` |
| 命令、环境、协作、验证与打包 | `docs/开发协作与交付指南.md` |
| Workbench、API、Web/UI 验收 | `docs/面板功能与验收.md` |
| LLM、Agent、R0/R1/R2 与基准实验 | `docs/Agent方案与对照实验.md` |
| 新人入门或项目边界 | `docs/README.md` |

跨领域任务只读取相关专项文档；`docs` 必须保持六份 Markdown，`项目现状与下一步.md` 是唯一当前状态表。详细历史状态在 `research/status/`，证据和方法卡在 `research/`。预算由 `scripts/check_docs_context_budget.py` 强制执行。

## 启动与事实核验

先确认实际 checkout、full SHA、remote、dirty files 和固定目标 Git 对象。分支名、提交消息、README、源码注释和 teammate 分支都不构成实现或来源证明。扫描本地 pinned Git objects，禁止隐式 fetch、checkout 或调用外部扫描器。

## Shared architecture

- CLI 和 Web 共用一套 OpenHarmony 自研内核，不创建第二套扫描器。
- 负责人维护 contracts/runner/catalog、Git/版本服务、API/Worker/storage、CI、统一验证和报告；A 负责 C/C++ Detector，B 负责 IPC/接口 Detector。
- 公共契约变更与算法修复分开提交，并有兼容性测试。第一方诊断输出 source-bound schema v2；legacy v1 只读兼容，不重写历史报告、ID、review 或 EvidenceObligation。
- 生产 Detector 不依赖外部扫描器或历史 verdict。外部工具只由 provider 规范化离线结果；历史对照留在 `research/benchmark`。
- AST/pattern 只是有限程序事实，不证明 ownership、dominance、并发、attacker control 或 CIA impact。

## Evidence gate

- 绑定 repo、full commit/tree/blob/snapshot/source hash、Detector/rule version、scope/profile 和 artifacts；缺项必须显式 unknown。
- 默认 `candidate/unassessed`。partial、failed、未执行、unknown 不是 safe 或 miss。有效局部候选和义务不因整体 blocked 消失；混合、越界或无效证据必须拒绝。
- 升级 `confirmed/reportable` 必须同时具备真实入口/权限边界、可达敏感操作、触发条件、具体 CIA 影响和可审计证据。满足门槛后应升级，不能永久停留在 candidate。
- 优先处理真实安全边界破坏，保留负结果、安全/修复控制、已知误报和限制。Precision/Recall 只能在独立可靠标注数据上计算；模型自评不是真值，不能声称零 FP/FN。

## Competition deliverables

最终交付必须包含准确/完整分析、受支持的 CWE/CVE、可运行可复现 PoC、受影响模块/版本/分支、修复与重验、性能和创新证据、完整报告。允许本地隔离动态验证；禁止攻击线上服务。静态资源受限子进程不是不可信构建或 PoC 沙箱。

## Development and delivery

- 保留 dirty worktree 和生成证据，不覆盖整仓或 teammate 工作。Detector 修改必须有 positive/fixed/safe/unrelated 控制、方法/来源和有意义回归。
- 第三方源码、大二进制、数据库、环境和秘密不入 Git；复用代码要审查许可证和原创性。
- Agent 从有界只读工具开始，不授予无限 Shell、任意联网或未记录 Git 写权限。动态验证只走授权隔离环境。
- 每次 push 前在聊天中说明变更、实际验证、限制和 branch/commits，并更新 `docs/项目现状与下一步.md`。`PROGRAM_STATUS.md` 只是指针。
- 未获用户授权不得标记 Draft Ready 或合并。文档只保留六份当前指南；历史证据放 Git 或 research 资产。
