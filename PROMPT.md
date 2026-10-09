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
- 本次分支基于 PR #5 head `c8c5bb1634141c98959758d12f3e41bdd3eaaf6b` 同步后，在 WSL Python 3.10 执行 `python -m unittest discover -s tests -v`，185/185 通过；这只验证当前静态基线，不代表真实 C/C++ detector 已实现。
- `codex/cutils-component-pilot` 是参考试点，不是自动 merge 目标。其中固定
  `openharmony/commonlibrary_c_utils` commit `b807d3dadb7dbb7639fe85b3a5f72da18d318da2`
  的记录不等于真实产品构建或漏洞结论。
- PR #5 head `c8c5bb1634141c98959758d12f3e41bdd3eaaf6b` / `feat/ohscanner-core` 已实现 M0 最小 Python 接口、Mock detector、Registry、Runner 和
  ToolRunResult v1 Bridge，并实现 M1 `ohscan-index` 固定本地 Git commit/tree/blob 的 C/C++ 轻量 AST 索引。
- 可从 `src.ohscanner.contracts` 使用 `ScanRequest/SourceUnit/ScanContext/DetectorFinding/DetectorRun/Detector`；
  以 `src/ohscanner/contracts.py` 的真实字段为准，不再把它描述为尚未实现。
- M0/M1 是可运行原型，但 v1 尚未冻结。PR #5 仍未实现硬超时、独立进程/内存沙箱、budget/cancel、完整类型/CFG/
  数据流、Web/Bridge/permission IR，也不包含真实 C/C++ 漏洞 detector。
- `main` 尚未合并 PR #5；工作分支可以使用当前接口，但任何公共字段变更仍需 contract-change proposal 和负责人评审。

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

## PR #5 当前接口定义

真实字段和校验以 `src/ohscanner/contracts.py` 为准。当前可直接实现的最小接口是：

~~~python
SourceUnit(
    path, language, text, sha256,
    parse_status="not_run", parse_issues=()
)

ScanRequest(
    request_id, repository, commit, snapshot_sha256, target_id,
    profile_id="m0-synthetic", provenance="fixture"
)

ScanContext(request, units, shared_facts={})

DetectorFinding(
    file, line, rule_id, message,
    evidence_type="pattern", column=None,
    candidate_cwe=None, symbol=None
)

DetectorRun(
    detector_id, version, status,
    analyzed_files=(), findings=(), limitations=()
)

Detector.detect(context, units) -> DetectorRun
~~~

`Detector` 还必须声明：

~~~python
detector_id: str                 # 必须以 `ohscanner.` 开头且唯一
version: str
supported_languages: tuple[str, ...]
required_facts: tuple[str, ...]
~~~

接口语义：

1. `SourceUnit.path` 必须是规范的 POSIX 相对路径；拒绝绝对路径、`.`/`..`、反斜杠、空段、盘符和控制字符。
2. `SourceUnit.language` 支持 `c/cpp/js/ts/arkts`；`parse_status` 支持 `complete/partial/failed/not_run`。
3. `SourceUnit.sha256` 必须匹配 `text` 内容；`ScanContext.units` 按 path 排序且不得重复。
4. `ScanRequest.repository` 是使用者声明的 `owner/repository`；`target_id` 必须是
   `current-component:<repository>`。
5. `provenance=fixture` 用于 M0 合成样例；`provenance=git_object` 要求完整 40/64 位 commit SHA 和
   `profile_id=light-ast`。M1 只校验本地 Git 对象身份，不验证官方远端归属。
6. `DetectorRun.status` 只能是 `completed/failed/blocked`。`completed` 必须覆盖所有选中的 supported-language units。
7. finding 必须位于 analyzed scope 和真实源码行范围内。Runner 生成稳定 `diagnostic_id` 和排序，并映射到现有
   `ToolRunResult(schema_version=1)`；severity/confidence 固定为 `unassessed`。
8. Registry 校验 detector ID、版本、语言和 `required_facts`；Runner 在缺失 shared facts 时返回 `blocked`。
9. `required_facts` 含 `ast` 时，任何选中文件不是 `complete` 都返回 `blocked`，不得继续声称分析完成。
10. detector exception 被隔离为该 detector 的 `failed`；目前是同步执行，尚无强制 timeout/memory limit。

M1 Frontend / CLI：

- `frontend.index_sources(sources)` 返回 `(units, ast_summary, coverage_summary)`。
- C/C++ 复用 Tree-sitter 语法索引；JS/TS/ArkTS 只登记文本和 hash，`parse_status=not_run`，不推断 AST/IPC/权限事实。
- `python -m src.cli ohscan-index --repo-dir ... --repository owner/repo --commit <full-sha> ...`
  只读固定 Git tree/blob，不 checkout/fetch，也不运行 detector。
- symlink/submodule、非 UTF-8、超大文件和超范围输入必须跳过或拒绝，并保留原因；不能记为已扫描。

状态边界保持不变：

- `completed/failed/blocked` 是执行状态；
- `complete/partial/failed/not_run/not_applicable` 是解析覆盖；
- `possible_hit/miss/unknown/not_applicable` 是 benchmark 根因匹配。
- 三组状态不能混用；`completed` 和空 finding 都不表示安全。
- 需要 M2+ 的公共 IR、budget/cancel、硬隔离或新 schema 字段时，写 `contract-change proposal`，不要直接修改
  `contracts.py`、`ToolRunResult`、providers、CLI 或共享 frontend/IR。
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