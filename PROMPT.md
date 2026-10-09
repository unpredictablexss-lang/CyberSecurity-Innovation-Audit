# 队友 A 任务提示词：自研 C/C++ Detector

## 角色与目标

你是本项目队友 A，负责 OpenHarmony 专用的自研 C/C++ 静态检测算法。当前分支专注于：
**把历史根因研究转化为一个可装入 OHScanner 的、确定性、可解释、可测试的 C/C++ detector**。

不要在本分支整理完整历史语料；数据基线在 `codex/teammate-a-oh-vuln-corpus` 分支维护。也不要另建一套扫描框架、CLI、
Candidate JSON、全局 AST/IR 或结果 schema。

## 当前成果基线

以下只作为已核实的起点，不得把规划写成已实现：

- PR #4 已合入 `main`，已有历史 benchmark、ToolRunResult/ToolDiagnostic、Evidence、人工审查、
  root-cause matrix 和报告基础。
- 4 条历史样本覆盖 `lifetime_uaf`、`concurrency_race`、`null_deref`、`oob_write`，但样本量不足以计算
  Precision/Recall，且 `validated_vulnerability = 0`。
- 本次分支准备时在 WSL Python 3.10 执行 `python -m unittest discover -s tests -v`，151/151 通过；这只验证当前静态基线，不代表 OHScanner detector 已实现。
- `codex/cutils-component-pilot` 是参考试点，不是自动 merge 目标。其中固定
  `openharmony/commonlibrary_c_utils` commit `b807d3dadb7dbb7639fe85b3a5f72da18d318da2`
  的记录不等于真实产品构建或漏洞结论。
- `docs/contracts/ohscanner_detector_contract_v1.md` 当前是 proposed 设计。`ScanRequest`、`SourceUnit`、
  `ScanContext`、`Detector`、`DetectorRun` 尚未在 main 实现，不得直接 import `src.ohscanner` 或声称契约已冻结。
- 负责人先实现统一 Mock 插件和 CI，才冻结契约并接入真实 detector。契约未落地前，可用同构 fixture 预研，
  但必须标明是本地设计实现。

## 算法方向

优先选择两个根因家族进行 M0/M1 核验，再选一个做 M2 首版 detector：

1. 对象生命周期/同步：
   - 类型与所有权绑定；
   - shared/unique/raw pointer 和 reset/release 等语义；
   - guard、锁、并发上下文；
   - 有限生命周期/逃逸/析构顺序事实。
2. 边界/长度/Parcel：
   - 长度、索引、容量之间的范围关系；
   - 检查与使用之间的 guard；
   - Parcel 读写、截断、溢出和分配大小关系；
   - 可达路径上的必要约束。

现有 `.reset()` 规则过宽，不能作为 UAF 证明；Clang 对 `parcel.cpp` 某条未初始化路径的告警也存在约束疑问，
不能直接升级为越界漏洞。算法必须解释为什么结构匹配之外还需要哪些事实。

## 本分支交付物

1. 自研 C/C++ detector 模块：
   - 建议落在 `src/ohscanner/detectors/cpp/`；
   - 明确 `detector_id/version/required_facts`；
   - 明确入口和纯函数边界；
   - 不在正式执行路径调用外部扫描器。
2. 方法卡 `method_card.md`：
   - 方法来源和自主改造点；
   - 适用根因和 OpenHarmony 专用语义；
   - 为什么规则可能有效；
   - 复杂度、失败模式、误报/漏报限制；
   - 第三方基础组件的许可证和 provenance。
3. 契约 fixture：
   - vulnerable 正例；
   - fixed 修复例；
   - 相似安全对照；
   - partial parse、缺 symbol、宏/构建上下文不完整或失败样例；
   - 真实样本必须绑定 repository/commit/file hash/source artifact。
4. 测试与评估：
   - 确定性单元测试；
   - 重复 diagnostic、稳定排序、超时/异常隔离；
   - 开发集与独立 holdout 分开；
   - 消融实验，说明类型、guard、ownership、range 等每类事实的贡献。
5. 结果适配说明：
   - detector 内部对象如何映射到现有 `ToolRunResult(schema_version=1)`；
   - `status=completed` 只说明执行状态，不表示安全；
   - 输出只能是 candidate/possible_hit，不是 confirmed vulnerability；
   - 不自行修改公共 schema，额外事实放内部对象或 sidecar，等待负责人 bridge。

## 首版 Detector 选择

从以下方向中只选一个先做窄而完整：

- `cpp.lifetime`：聚焦一种明确所有权/生命周期形状和一类同步约束；
- `cpp.bounds`：聚焦一种长度/索引/Parcel 范围关系和一类 guard 条件。

不要第一版同时实现 UAF、double-free、null deref、integer overflow、OOB、并发竞争和完整污点分析。
先证明一个 detector 可挂载、可解释、可回放，再扩展根因家族。

## 拟议接口使用规则

可以依据契约文档预研：

~~~text
ScanRequest(target repository/commit/profile/scope/source_hash)
  -> SourceUnit + shared facts + ScanContext
  -> Detector.detect(context, source_units)
  -> DetectorRun
  -> owner-provided validation/provenance/status adapter
  -> ToolRunResult v1
~~~

但必须遵守：

- `completed/failed/blocked` 是执行状态；
- `complete/partial/failed/not_run/not_applicable` 是解析覆盖；
- `possible_hit/miss/unknown/not_applicable` 是 benchmark 根因匹配；
- 三组状态不能混用。
- 需要公共 IR 新字段时写 `contract-change proposal`，不要修改 `ToolRunResult`、providers、CLI 或共享 frontend/IR。
- 输出必须确定性、可单测、可重放；一个 detector 失败不能阻断其它 detector，但必须保留失败原因。

## 允许修改的范围

优先只修改：

- `src/ohscanner/detectors/cpp/`
- `research/experiments/cpp/`
- `research/methods/cpp/`
- `tests/detectors/`
- detector 专用 fixtures

如需修改 `src/ohscanner/frontend`、`ir`、`integration`、`triage`、`reporting`、全局 CLI、公共 schema 或 providers，
不要直接改；提交 contract-change proposal 给负责人。

## 禁止事项

- 不把 rule match、`.reset()`、文件/符号重叠或单条工具 warning 解释为确认漏洞。
- 不把解析失败、未覆盖、未执行写成 safe/miss/zero vulnerabilities。
- 不按漏洞类型启动 Semgrep、Cppcheck、Clang SA、CodeQL 或 Joern 作为正式 detector 运行依赖。
- 不复制第三方规则/代码而不核验许可证、出处、署名和赛题原创性。
- 不写受检源码、不联网主动攻击、不生成 exploit/PoC、不自动提升 review 或 vulnerability 状态。
- 不提交第三方 OpenHarmony 全量源码、编译产物、生成实验结果、数据库或密钥。
- 不用开发集样本冒充独立测试成绩。

## 完成判定

- detector 不依赖外部大扫描器即可在固定 fixture 上运行。
- 正例、修复例、安全对照和失败/未知 fixture 均有明确期望。
- 每个候选带 repository/commit/scope/source、rule_id、evidence_type、位置、解释和局限。
- 没有诊断时不输出“安全”；partial/failed/not_run 保留真实覆盖状态。
- 一个 detector 的 timeout/crash 只产生自己的失败记录，不影响其它模块。
- 测试和报告结果可重复，排序稳定，没有混入其它 commit/scope/run。
- 运行 `python -m unittest discover -s tests -v` 并记录真实结果；CI 未通过时不得写“已验证”。
- 只在本地提交 commit、patch 或交付包。未经负责人确认不 push、不创建 PR、不合入 main。

## 推荐提交拆分

- `cpp: add lifetime detector fixtures and deterministic unit tests`
- `cpp: implement narrow ownership/guard candidate detector`
- `cpp: add bounds/length/Parcel method card and ablation fixtures`
- `cpp: map detector evidence to ToolRunResult v1`
- `tests: enforce detector isolation and coverage-state semantics`