# ToolRunResult(schema_version=1) proposed mapping design

> 状态：detector-local **proposed bridge design/implementation**。Detector Contract v1 尚未冻结；本文件不修改 `src/benchmark/tool_result.py`、providers、frontend、IR、integration、triage、reporting、CLI 或公共 schema。
> 代码位置：`src/ohscanner/detectors/cpp/proposed_toolrun_bridge.py`，只读构造现有 `ToolRunResult` / `ToolDiagnostic`。

## 1. 输入和输出边界

输入：

- detector-local `ProposedScanRequest`：只用于 fixture provenance；
- detector-local `ProposedDetectorRun`：candidate、coverage、limitations；
- 由调用者提供的稳定 `run_id`。

输出：

- 现有 `ToolRunResult(schema_version=1)`；
- 现有 `ToolDiagnostic` 列表；
- 现有 `parsing: [{file,status}]`；
- detector-local explanation/constraints 等额外事实不塞入公共对象，保留 sidecar。

## 2. 字段映射

| Detector-local 字段 | ToolRunResult v1 | 规则 |
|---|---|---|
| `detector_id` | `tool` | `ohscanner.cpp.lifetime`，不冒用外部 provider |
| `version` | `tool_version` | 当前 `0.1.0-proposed`，继续标识契约未冻结 |
| request provenance | `target_id, commit` | 调用者统一生成；detector 不得替换目标 |
| run_id | `run_id` | 必须绑定 request/detector，不混用其它 run |
| `scope_files,scope_loc` | 同名字段 | 指声明送入 unit 的范围，不等于成功解析范围 |
| `status` | `status` | 只允许 `completed/failed/blocked`；不表示安全 |
| `elapsed_seconds` | 同名字段 | 单模块计时 |
| candidate | `diagnostics[]` | 只做描述性候选映射 |
| `coverage[].parse_status` | `parsing[]` | 保持 `complete/partial/failed/not_run`；未把 `not_applicable` 强塞进当前 parsing |
| run/candidate limitations | `limitations[]` | 去重后稳定排序 |
| failure_kind | 仅 sidecar | 当前公共 schema 无此字段，不新增未知键 |

## 3. Diagnostic 映射

| Detector-local | ToolDiagnostic v1 | 值 |
|---|---|---|
| `diagnostic_id` | 同名 | 稳定哈希 ID；bridge 再折叠重复 ID |
| `provider` | 同名 | `ohscanner.cpp.lifetime` |
| `evidence_type` | 同名 | 仅 `syntax`；无 CFG/dataflow proof |
| `file,line,column` | 同名 | 1-based source location |
| `rule_id` | 同名 | `ohcpp-lifetime-unique-raw-alias-reset-001` |
| `severity` | 同名 | `unassessed` |
| `message` | 同名 | 描述 candidate shape，不写漏洞结论 |
| `candidate_cwe` | 同名 | `CWE-416` 仅作初步候选 |
| `confidence` | 同名 | `unassessed` |
| `symbol` | 同名 | raw alias 名称 |

`ToolDiagnostic` 没有 `confirmed` 字段，也不应添加。candidate 是否进入 review、是否具有安全影响、是否运行验证由后续独立流程决定。

## 4. Sidecar 保留字段

以下事实不能在不改公共 schema 的情况下完整进入 `ToolDiagnostic`，应由 owner-provided bridge 保存到 Evidence/trace sidecar：

- `source_sha256`
- `explanation`
- `limitations`
- `constraints`（包括 `sync_scope=...`）
- `missing_obligations`
- `candidate_status="candidate"`
- `review_status="unassessed"`
- `validation_status="not_run"`
- detector-local `failure_kind`
- `analyzed_files` 与每文件 `parse_issues`

建议稳定关联键仍由公共核心按 `repo|commit|profile|file|symbol|root_cause_family|normalized_location` 生成；本 detector 不擅自实现全局去重或 review 状态迁移。

## 5. 三种状态维度

1. 执行状态：`completed/failed/blocked`，映射 `ToolRunResult.status`。
2. 解析覆盖：`complete/partial/failed/not_run/not_applicable`，本轮只把 source unit 实际状态写入 `parsing`/sidecar。
3. benchmark 根因匹配：`possible_hit/miss/unknown/not_applicable`，**不产生、不映射、不自报**，只能由绑定 sample/repo/commit/tool/scope/source artifact 的 benchmark evaluator 后续计算。

`completed` 仅表示 detector 调用完成。`diagnostics=[]` 仍可能有 partial/failed/not_run 覆盖，绝不是安全证明。

## 6. 稳定性、重复与失败隔离

- diagnostic 排序键：`(file,line,column,diagnostic_id,rule_id)`；
- 相同 `diagnostic_id` 在 detector 和 bridge 两层折叠，并在 `limitations` 留痕；
- coverage/analyzed_files 按 `file` 排序；
- 每个 detector job 独立 timeout/catch exception；失败只生成自己的 `failed` run，不删除其它 detector 结果；
- bridge 不把 exception 转成 safe/miss。

## 7. 不做的公共变更

本轮不新增 `ToolRunResult`/`ToolDiagnostic` 字段，不修改 providers，不把 sidecar 未知键传给公共 dataclass，不创建统一 CLI/JSON schema。若负责人未来决定公共化 `failure_kind`、`constraints` 或 candidate status，应另提 contract-change proposal，包含向后兼容和迁移测试。
