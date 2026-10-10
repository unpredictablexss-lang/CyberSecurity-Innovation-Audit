# OHScanner 自研 Detector Plugin Contract v1（设计稿）

> **开发分支实施说明（2026-10-09）**：在 `feat/ohscanner-core` / PR #5 已有 M0 最小 Python `ScanRequest/SourceUnit/ScanContext/DetectorRun/Detector` 和注册器/Bridge；M1 新增 `ohscan-index`，从本地固定 Git commit 读取源码并对 C/C++ 形成轻量 AST。下文包含 M2+ 仍未实现的目标字段（如 budget/可取消任务、独立进程硬超时、权限/Bridge 的 IR）；因此仍是逐步落地的协议草案，**不能认为全部字段、完整安全沙箱或真实漏洞算法已实现**。现有真实字段以 `src/ohscanner/contracts.py` 为准。

> **分支说明**：上述 M0/M1 基础接口已在 `feat/ohscanner-core` 实现，可按当前 `src/ohscanner/contracts.py` 导入；**它们尚未合入 `main`**。主线已有 `ToolDiagnostic`、`ToolRunResult(schema_version=1)` 及外部工具 Adapter。本文其余更高级字段与服务仍是 proposed，不应误认为代码已具备全部能力。
>
> 目标：让负责人统一完成扫描底座，队友 A、B 各自交付独立 C/C++ 和 Web/ArkTS/IPC 自研检测插件，无需修改 main 的内部公共实现也能集成。契约首次 Mock CI 通过后再冻结；之后如需变更，单开契约 PR。

## 1. 三个边界不能混淆

- **外部实验 Adapter**（现有 `src/providers`）：只把 Semgrep/CodeQL/Clang/Cppcheck/Joern 保存的原生输出转换为描述性结果，**不运行分析**。
- **OHScanner Detector**（拟建 `src/ohscanner/detectors`）：自行执行语法/类型/guard/对象生命周期/输入传播等算法，**正式扫描不按漏洞类型启动上述外部工具**。
- **结果 Bridge**（拟建 `src/ohscanner/integration`）：统一校验目标、快照、检测覆盖及异常，然后桥接到 main 现有的 `ToolRunResult`、Evidence、Review 和报告模块。

~~~text
Pinned ScanRequest + SourceUnits + SharedFacts
                    |
          Detector Registry / Runner
                    |
       CPP detectors      Interface detectors
                    |            |
                    +------------+
                         |
                 DetectorRun (proposed)
                         |
                Contract validation
                         |
          ToolRunResult v1（已存在）
                         |
           Evidence -> Review -> Report
~~~

## 2. 拟冻结的输入契约

### ScanRequest

| 字段 | 最低要求 | 校验规则 |
|---|---|---|
| `request_id` | 非空扫描任务 ID | 唯一、可追踪 |
| `target_id` | 例如 `current-component:openharmony/commonlibrary_c_utils` | 不得混为 historical sample_id |
| `repository` | 官方仓库标识 | 与快照 origin 绑定 |
| `commit` | 完整 commit SHA | 与固定源码一致，扫描中不变 |
| `snapshot_sha256` | 源码清单 SHA-256 | 读取前后校验 |
| `profile_id` | light-full / linux-host / product-build 等 | 不同 TU、宏和依赖配置不能混评 |
| `include_paths` / `exclude_paths` | 仓库相对路径清单 | 禁止绝对路径、`..`、符号链接越界 |
| `language_mode` | cpp/c/js/arkts/mixed | 不靠扩展名宣告解析完整 |
| `budget` | 时间/内存等额度 | 不可无限运行、主动访问网络或修改受检源码 |

### SourceUnit

`path, language, sha256, text/content_ref, parse_status, parse_issues, symbol_index(optional), type_info(optional), cfg(optional), dataflow(optional)`。

`parse_status` 语义为 `complete/partial/failed/not_run`。类型/CFG/跨函数信息没有时应保留未知，不得臆造。由主线负责提供解析事实；A/B 可以提新需求但不可偷偷把其私有 AST 对象变成公共必填字段。

### ScanContext

只读包含 ScanRequest、指定 SourceUnit 列表、共享事实索引、模型版本、取消/截止时间、受控 artifact writer。**不暴露 GitHub token、任意网络客户端、目标源码写入能力、任意 shell runner。**

### Detector（伪代码，不是已存在 API）

~~~python
class Detector(Protocol):
    detector_id: str    # e.g. ohscanner.cpp.lifetime
    version: str
    supported_languages: tuple[str, ...]
    required_facts: tuple[str, ...]

    def detect(
        self, context: ScanContext, units: list[SourceUnit]
    ) -> DetectorRun: ...
~~~

每个 DetectorRun 包含：`diagnostics`、`analyzed_files`、`coverage`、`limitations`、`elapsed_seconds`、`status` 和可选性能信息。运行时统一排序、路径验证和错误隔离。**某一个 detector crash 不得导致其他 detector 的证据消失**，但必须产生失败记录。

## 3. 自研结果复用 main 现有 ToolRunResult v1

现有字段（核实存在）：`schema_version, run_id, tool, tool_version, target_id, commit, scope_files, scope_loc, status, elapsed_seconds, peak_memory_mb, diagnostics, limitations, parsing`。

现有 `ToolDiagnostic` 字段（核实存在）：`diagnostic_id, provider, evidence_type, file, line, column, rule_id, severity, message, candidate_cwe, confidence, symbol`。

映射约定：

| 内部自研字段 | ToolRunResult v1 | 约定 |
|---|---|---|
| detector_id/version | `tool/tool_version` | 自研工具名使用 `ohscanner.cpp.lifetime`、`ohscanner.interface.bridge`，与 semgrep 区分 |
| request | `run_id,target_id,commit` | 由核心生成并校验，不许 Detector 自行冒用别的目标 |
| 已声明的分析范围 | `scope_files/scope_loc` | 具体 analyzed_files 在 sidecar 中保存，保证可核对范围 |
| 执行状态 | `status` | 仅 `completed / failed / blocked` |
| 诊断与初步 CWE | `diagnostics` | 只能写初步候选，未验证的 confidence 为 `unassessed` |
| 解析状态 | `parsing` | 仍按已有的 `file/status` 结构保留真实错误；其他覆盖状态放 sidecar |
| 额外语义事实 | 另存 Evidence/trace sidecar | 不擅自给 ToolDiagnostic dataclass 添加字段 |

证据类型只能使用 `src/benchmark/tool_result.py` 支持的值：
`pattern, syntax, dataflow, control_flow, symbolic, historical, runtime, permission, web_dynamic, human_review, unknown`。没有确定性路径证据不可写 `dataflow` 或 `control_flow`；CodeQL 供应商身份也不等于它的每一条告警都具备数据流证明。

一个示意 `ToolRunResult`（**模拟 fixture，非真实漏洞输出**）：

~~~json
{
  "schema_version": 1,
  "run_id": "contract-fixture:cpp-lifetime-v1",
  "tool": "ohscanner.cpp.lifetime",
  "tool_version": "0.1.0",
  "target_id": "current-component:openharmony/commonlibrary_c_utils",
  "commit": "b807d3dadb7dbb7639fe85b3a5f72da18d318da2",
  "scope_files": 1,
  "scope_loc": 80,
  "status": "completed",
  "elapsed_seconds": 0.01,
  "peak_memory_mb": null,
  "diagnostic_count": 1,
  "diagnostics": [{
    "diagnostic_id": "fixture:cpp-lifetime:001",
    "provider": "ohscanner.cpp.lifetime",
    "evidence_type": "syntax",
    "file": "base/include/example.h",
    "line": 20,
    "column": 5,
    "rule_id": "ohcpp-lifetime-candidate-001",
    "severity": "unassessed",
    "message": "模拟候选：需核对类型与同步上下文，非漏洞结论",
    "candidate_cwe": "CWE-416",
    "confidence": "unassessed",
    "symbol": "Example"
  }],
  "limitations": ["Synthetic fixture only; no real security verdict."],
  "parsing": [{"file": "base/include/example.h", "status": "complete"}],
  "interpretation": "Descriptive scanner evidence only."
}
~~~

**严禁**将示例路径、行号或 candidate_count 当作已扫描 OpenHarmony 的实测事实。现有 `ToolDiagnostic` 没有 `status=confirmed` 字段；候选审查及是否已确认由独立 Review 记录维护。

## 4. 执行状态 / 分析覆盖 / 根因实验评价：三种不同维度

1. **执行**：`completed/failed/blocked`（ToolRunResult）。
2. **解析覆盖**：按文件、语言、配置区分 `complete/partial/failed/not_run/not_applicable`；未实现扩展状态时保存 sidecar，不要修改已有 `parsing.status` 的接受值。
3. **基准根因匹配**：`possible_hit/miss/unknown/not_applicable`（由历史 benchmark 评估器根据固定修复对和真实分析覆盖给出，不由插件自报）。

没有诊断 ≠ 安全；解析 partial、缺头文件、未执行、范围不含 affected symbol ≠ miss。完整 host TU ≠ 完整设备路径/宏配置/模板实例。

## 5. Candidate 关联与审查 Sidecar（拟议）

可选稳定关联键：`SHA256(repo|commit|profile|file|symbol|root_cause_family|normalized_location)`。多个工具警告在同一行不自动等于同一个根因；候选关联需要对象或路径证据。

sidecar 保存 `snapshot_sha256, model_version, detector_id/version, profile_id, analyzed_files, parse_status, artifact_sha256, trace_ref, missing_obligations, review_status, reviewer, input_control, reachability, security_impact, runtime_validation` 等。初次产出时 `runtime_validation=not_run`、`validated_vulnerability=0` 只是**默认起点而非上限**：当运行时验证与 `AGENTS.md` 的 Evidence gate 满足时，升级为 `runtime_validation=validated`、`validated_vulnerability>0`，并在记录上写明证据等级（2026-10-10 政策）。升级仍不靠 Detector 自报——由 Review 记录 + 动态证据驱动。

现有 `src/triage/review_store.py`、`src/core/evidence.py` 可以复用，但字段与数据格式不同，需由核心编写桥接和回归测试。

## 6. 两位队友必须交付的“接入包”

每个 Detector 必须附带：

- 自研 Python 检测模块及明确入口，`detector_id/version/required_facts`；
- `method_card.md`：方法来源、规则为何有效、OpenHarmony 专用约束、自主改造点、限制、第三方许可；
- 正例、修复后版本、安全相似代码、解析不完整/失败 fixture；真实数据必须有固定提交与文件哈希；
- 可复现的单元测试与独立保留集结果，不得把开发时学习的漏洞作为独立测试成绩；
- 运行耗时、解析/编译范围、失败样例、必要的 Evidence 引用；
- `README.md`：负责人无需安装整个研究工具栈就能在 Mock / 固定源码上使用该 Detector。

**不准交付另一套 CLI、另一套 Candidate JSON、另一套统一 AST 基类。** 需要公共 IR 扩展时先提交申请，由负责人维护并测试向后兼容。

## M1.5 补充：按文件 AST 调度与证据义务（已在 Draft PR #5 实现）

> 实际代码优先：`src/ohscanner/runner.py`、`contracts.py`、`facts.py`。此处是对前面“完整 AST 不足时全部 blocked”策略的**修订**，其他仍未实现的长远 Contract 设计不变。

1. 检测器如声明 `required_facts=("ast",)`，缺省 `ast_scope="per_file"`：只在 AST complete 文件运行，partial/failed/not_run 计为未分析，**绝不计为 miss 或 safe**；需全局完整上下文的算法显式声明 `ast_scope="whole_scope"`，遇任一部分解析文件会整体 blocked。
2. `run_all(context, registry)` 保持返回原 `list[ToolRunResult]`，不破坏 M0 API。新增 `run_all_with_coverage(context, registry)` 返回 `(results, sidecar)`，其中 `sidecar["detectors"][detector_id]` 明确列出 `applicable_files`、`analyzed_files`、`unexamined[{file,parse_status,reason}]`、状态 `complete/partial/blocked/failed/not_applicable`。
3. `ToolRunResult.status=completed` 只表示分配的**合格子集**完成，若总适用范围有跳过文件，`limitations` 必须带 `INCOMPLETE COVERAGE`，`parsing` 中同时保留 `analysis_status` 和 `analysis_reason`；整体组件安全性不能由 completed 或 0 diagnostics 推断。
4. `ScanContext.shared_facts["facts_v1"]` 提供语法级 `functions/calls`；`resolved_target=null`、`guards=[]`，不伪造 guard dominance、类型解析、CFG 或对象生命周期。新增 `EvidenceObligation` 和 `DetectorFinding.evidence_obligations`，通过 `run_all_with_coverage` 的 sidecar 输出待证据，**不修改既有 `ToolDiagnostic v1`**。
5. `git_object` 输入坚持本地 Git tree/blob 对象来源并封锁隐式传输。缺少本地 Blob 时应失败且提示用户在扫描之外明确准备对象；详细 Git 2.34 兼容试验见 `docs/testing/ohscanner_m15_offline_and_coverage.md`。
6. 函数级 partial AST 局部分析属于后续研究；尚无严格错误区域/依赖证明前，不允许 partial 文件中的函数默认标 complete。

## 7. M0 统一 Mock 插件验收

负责人先实现：

~~~text
One ScanRequest
   -> MockCppDetector (固定 C/C++ fixture)
   -> MockInterfaceDetector (固定 JS/ArkTS fixture)
   -> 同一个 Registry / Runner / ToolRunResult Bridge
   -> 2 份 ToolRunResult v1 + 统一 JSON/Markdown
~~~

验收用例应覆盖：路径逃逸、错误 commit/目标 ID、解析 partial、detector 超时/异常、重复 diagnostic_id、跨仓库结果混用、结果排序稳定、完全没有有效候选但显示覆盖不足、不同 detector 的失败隔离。

这一步 CI 成功才冻结契约并允许 A/B 的真实检测器集成。之后任何破坏性变更必须提出 contract-v2（含迁移说明），不可悄悄改公共 schema。

## 8. 权限与验收底线

队友默认本地分支开发、交负责人审查 patch 和固定实验结果；主线负责人控制远端 push、PR 与 merge。Detector 不得写第三方源码，也不得对线上真实服务发起主动攻击。PoC 生成与结论升级是本项目**必须的交付能力**，但由独立 PoC 模块（`src/ohscanner/poc/`）与 Review 记录承载，不在 Detector 的单次静态执行里悄悄完成。每个 PR 包含复现命令、正负对照、覆盖、CI、失败/未知和许可证信息。

**本文件是设计契约，而不是现成可运行的实现说明。**
