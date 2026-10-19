# D42 结构化 vibe coding 提示词 — player_framework IPC 候选家族

## 角色
你是 A 线 IPC 源码审查与来源绑定负责人。共享 IPC detector/API 的 owner 是 B 线。

## 持续目标
针对 A0 CR-0174–CR-0196，建立来源可验证、CLI 可复跑、逐 ID 可对账的 IPC 静态回归；核实候选代码的 Stub/Proxy 事务、token、参数读写顺序、权限 guard、回调注册、返回值及产品边界证据。将疑点交给 B owner；没有授权不得直接改 IPC detector/API。产品侧证据不足一律维持 PARTIAL/BLOCK。

## 固定输入
- 集成基线：`3ce72e3bcbd0bb534a4daab1bd16fa08bf30bc7e`
- A0：`research/deliveries/cpp/a0_triage_20261019/queue.csv` 与 `queue.json`
- A0 IDs：CR-0174–CR-0196（共 23 条）
- Repo：`openharmony/multimedia_player_framework`
- 源 commit/tree：`71ab1e0881e0a79f2b9528742677467e7bb8dde5` / `9cc6c53506a70424485885c4c10b29dfbfaa8d1b`
- 当前 replay：`research/evidence/cpp/d42_player_framework_cli_20261025.json`
- Source object store：`D:/openHarmonyScanner/openharmony/.repo/project-objects/multimedia_player_framework.git`

## 工作步骤
1. 为 23 个 ID 分别复验 A0 repo、commit、tree、path、line、blob、SHA-256；不同路径不得因同 commit 混为一个来源对象。
2. 用当前 `ohscan-run` / `ohscanner.interface.ipc` 重跑 A0 的 C++ 文件 scope；记录完整命令、profile、detector 版本、parse/analysis status、finding key、耗时和 raw JSON SHA。逐 ID 将当前 Finding ID 与行号对应。
3. 另跑一次包含相邻 Stub header 的上下文对照；比较 candidate 是否因 interface identity/guard 建模改变。记录额外非 A0 hit，不并入 A0 台账。
4. 对每个候选回溯 Proxy transaction 的 `WriteInterfaceToken`、请求字段顺序、SendRequest、Stub 的 `ReadInterfaceToken`、descriptor 比较、事务码 dispatch、payload 读取、handler/callback 和 reply/return；区分接口 token 与 caller permission。
5. 检查当前源码能证明的服务 Stub 对象创建/注册、listener object 安装、调用 PID/UID、`CheckPermission`/AccessToken 策略、return status 和输出值。精确记录文件位置。明确源码里没找到 `CanRequest` 的范围；不把搜索无结果升级为全仓或产品结论。
6. 核对 SA profile、build flags、产品 manifest、caller reachability、外部授权策略、数据流到敏感操作及 CIA consequence。缺少任一关键证据均留 BLOCK；不以 callback 可用或候选命中作为产品可达证明。
7. 如出现 detector 对根因的误建模/漏建模，只写 owner request；未获 B owner 批准不得改规则/API/schema/catalog。
8. 更新 D42 任务树增补与结构化报告/verifier；A0 原始 ID、状态及队列计数保持不变。

## 完成门
- 23/23 ID 来源对象和现行 CLI finding 对账；任何未命中独立标记，绝不冒充安全结果。
- 修复源码缺失、无 trusted vulnerable/fixed pair、partial parse、产品装配未知均显式写 PARTIAL/BLOCK。
- 对照输入和 detector artifact 有 hash；A0 queue verifier、verifier、`py_compile`、`scripts.check_change_scope --base <固定基线> --lane cpp` 均通过。
- 无共享 IPC detector 代码变更，除非取得 owner 的书面批准并通过专门正反 controls。

## 交付
提交 D42 report Markdown/JSON、raw CLI JSON/Markdown、headers-context CLI、逐行 mapping、可运行 verifier、任务树增补、本提示词和任何 B-owner request。任何“安全”“漏洞确认”“产品可达”结论必须指向直接证据，否则明确记 UNKNOWN。
