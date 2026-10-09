# ToolRunResult(schema_version=1) proposed mapping design

> 状态：**proposed mapping design**。Detector Contract v1 尚未冻结。本轮不修改
> `src/benchmark/tool_result.py`、providers、frontend、IR、integration、triage、
> reporting、CLI 或公共 schema。实际映射复用项目所有方维护的
> `src/ohscanner/runner.py`；本文件记录 teammate A detector 的字段约束和
> M2+ contract-change 需求，不创建第二套 bridge。

## 1. 输入和输出边界

输入：

- 当前公共 `ScanRequest`：目标 repository/commit/profile/provenance；
- 当前公共 `SourceUnit`：path/language/text/SHA-256/parse status/issues；
- 当前公共 `ScanContext`；
- `Detector.detect(context, units) -> DetectorRun`。

输出：

- 现有 `ToolRunResult(schema_version=1)`；
- 现有 `ToolDiagnostic`；
- Runner 生成的 `parsing: [{file,status,issues}]`；
- Runner 生成的稳定 diagnostic ID。

不把 detector 的解释、constraints 或状态提升写入未知公共键。

## 2. DetectorRun 到 ToolRunResult

| Detector 字段 | ToolRunResult v1 | 规则 |
|---|---|---|
| `detector_id` | `tool` / `Diagnostic.provider` | `ohscanner.cpp.lifetime`，不冒用外部 provider |
| `version` | `tool_version` | `0.1.0-proposed`，继续标识 v1 未冻结 |
| request identity | `run_id,target_id,commit` | `request_id:detector_id`，不混用其它 run |
| `analyzed_files` | `scope_files,scope_loc` | 只统计 detector 声明已分析 unit，不等于 selected/parse 范围 |
| `status` | `status` | 仅 `completed/failed/blocked`；不表示安全 |
| Runner elapsed | `elapsed_seconds` | 单 detector 调用耗时 |
| `findings[]` | `diagnostics[]` | 仅描述性 candidate 映射 |
| selected `SourceUnit` | `parsing[]` | 保持 `complete/partial/failed/not_run` 和 `parse_issues` |
| `limitations` | `limitations[]` | 与 Runner 固定限制合并 |

`failed`、异常和 cooperative timeout 只影响当前 detector 的结果，不能把其它
detector 的 run 改写为失败或安全。

## 3. DetectorFinding 到 ToolDiagnostic

| DetectorFinding | ToolDiagnostic v1 | 值 |
|---|---|---|
| 无本地 ID | `diagnostic_id` | Runner 用 `file,line,rule_id,message` 稳定哈希生成 |
| `file,line,column` | 同名 | 1-based source location |
| `rule_id` | 同名 | `ohcpp-lifetime-unique-raw-alias-reset-001` |
| `evidence_type` | 同名 | 仅 `syntax`；无 CFG/dataflow proof |
| `message` | 同名 | candidate shape、解释、sync constraint 和非证明边界 |
| `candidate_cwe` | 同名 | `CWE-416` 仅作初步候选 |
| `symbol` | 同名 | raw alias 名称 |
| 无公共字段 | `severity/confidence` | Runner 强制 `unassessed` |

`ToolDiagnostic` 没有 `confirmed` 字段，也不应添加。candidate 是否进入
review、是否具有安全影响、是否运行验证由后续独立流程决定。

## 4. 需要 sidecar 或 contract-change proposal 的事实

当前公共 schema 无法完整承载：

- `source_sha256` 与 finding 的直接绑定；
- `candidate_status="candidate"`、`review_status="unassessed"`、
  `validation_status="not_run"`；
- candidate-level constraints/missing obligations；
- detector-local `failure_kind`；
- cooperative timeout 与 hard timeout 的区别。

本轮把可表达内容压入 `DetectorFinding.message` 和
`DetectorRun.limitations`，不向公共 dataclass 塞未知键。若负责人决定公共化，
应另提 contract-change proposal，包含向后兼容、状态隔离和迁移测试。

## 5. 三种状态维度

1. 执行状态：`completed/failed/blocked`，映射 `ToolRunResult.status`；
2. 解析覆盖：`complete/partial/failed/not_run`，映射 `parsing[]`，不能与
   benchmark 状态混用；
3. benchmark 根因匹配：`possible_hit/miss/unknown/not_applicable`，只能由
   绑定 sample/repository/commit/tool/scope/source artifact 的 evaluator
   计算，detector 不产生也不映射。

`completed` 仅表示 detector 调用完成。`diagnostics=[]` 仍可能有
partial/failed/not_run 覆盖，绝不是安全证明。

## 6. 稳定性、重复与失败隔离

- detector 排序键：`(file,line,column,rule_id,message)`；
- detector 在返回前按 Runner identity `(file,line,rule_id,message)` 折叠重复；
- Runner 再拒绝重复 diagnostic identity，并把异常隔离成该 detector 的
  `failed` record；
- `analyzed_files` 排序且不得超出 selected units；
- Registry 按 detector ID 稳定排序；
- cooperative timeout 只验证当前 detector 可返回 `failed` 而后续 detector
  继续运行。共享 Runner 未实现 hard timeout、独立进程、kill/cancel 或内存
  沙箱，不能把 cooperative test 描述为硬隔离。

## 7. 不做的公共变更

本轮不新增 `ToolRunResult`/`ToolDiagnostic` 字段，不修改 providers，不把
sidecar 未知键传入公共 dataclass，不创建统一 CLI/JSON schema。
