# 启动提示词：自研 C/C++ Detector

你在 `codex/teammate-a-cpp-detectors` 分支工作，身份是项目队友 A。本轮只推进 OpenHarmony 自研 C/C++ detector 的窄而完整原型，不整理完整历史语料，也不创建另一套扫描框架。

开始前依次阅读：

1. `AGENTS.md`
2. `PROGRAM_STATUS.md`
3. `docs/strategy/ohscanner_three_track_master_plan.md`
4. `docs/contracts/ohscanner_detector_contract_v1.md`
5. `docs/strategy/vulnerability_corpus_bakeoff_protocol.md`
6. 本分支 `PROMPT.md`

当前事实：

- Detector Contract v1 仍是 proposed；`ScanRequest/SourceUnit/ScanContext/Detector/DetectorRun` 尚未在 main 实现。
- 负责人需要先落地 Mock CPP/Interface detector、公共 bridge 和 CI，才能冻结契约。
- 契约未落地前只能按文档 fixture 做本地预研，不能直接 import `src.ohscanner` 或宣称接口可运行。
- 历史工具结果只能用于研究和方法设计，不能成为正式 detector 的运行依赖。

本轮目标：

- 在 `lifetime/synchronization` 与 `bounds/length/Parcel` 中各完成一个最小实验切片；
- 从中选择一个方向实现首个窄范围自研 detector；
- 建立 vulnerable/fixed/safe/partial-parse/failed fixture；
- 输出候选、证据类型、位置、解释、局限和覆盖状态；
- 提供确定性单元测试、稳定排序、超时/异常隔离和消融说明；
- 写方法卡和 `ToolRunResult(schema_version=1)` 映射设计，但不修改公共 schema。

建议先选 `cpp.lifetime`，只处理一种明确所有权/生命周期形状和一类 guard/同步约束；不要同时实现 UAF、double-free、null deref、integer overflow、OOB 和并发竞争。

硬性边界：

- `completed` 只是执行状态，不表示安全。
- `partial/failed/not_run/not_applicable` 是解析覆盖，不能和 benchmark 结果状态混用。
- `possible_hit/miss/unknown/not_applicable` 是基准匹配状态，不能由 detector 自报 confirmed。
- rule match、`.reset()`、文件/符号重叠或单条工具 warning 不是漏洞证明。
- 正式 detector 不启动 Semgrep、Cppcheck、Clang SA、CodeQL、Joern。
- 不写受检源码、不联网攻击、不生成 exploit/PoC、不提升 review/vulnerability 状态。
- 不提交第三方源码、生成实验产物、编译物或数据库。
- 不改 `src/ohscanner/frontend`、`ir`、`integration`、`triage`、`reporting`、CLI、公共 schema 或 providers；
  需要公共字段时提交 contract-change proposal。
- 未经负责人确认不 push、不创建 PR、不合入 main。

执行方式：

- 优先修改 `src/ohscanner/detectors/cpp/`、`research/experiments/cpp/`、`research/methods/cpp/`、
  `tests/detectors/` 和 detector 专用 fixtures。
- 契约未冻结时，将本地接口和 bridge 映射明确标为 proposed implementation。
- 一个 detector 的 timeout/crash 只能产生自己的失败记录，不能阻断其它模块。
- 运行 `python3 -m unittest discover -s tests -v`；以真实结果为准，不沿用旧 CI 数字。

结束时必须汇报：

1. 已完成变更；
2. detector 的精确适用范围和 required_facts；
3. 正例、修复例、安全对照及失败/未知 fixture；
4. 测试和消融结果；
5. 解析覆盖、候选状态和已知限制；
6. 本地 commit SHA；
7. 明确说明未 push。