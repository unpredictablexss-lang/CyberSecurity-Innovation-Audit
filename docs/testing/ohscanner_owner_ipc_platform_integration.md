# 负责人集成：IPC 单次执行与覆盖/义务保留

日期：2026-10-11。开发分支：`feat/owner-ipc-platform-integration`。
基于核心分支 `e365465`，选择性迁入队友 B 本地固定提交
`52b2cd5fbbb4a40efdf2089fa0a4c67c36b22ef5` 的检测模块、合成测试、方法卡及来源记录。
导入清单与原始字节 hash：`docs/integration/ipc_source_import_20261011.json`。
清单描述迁入前内容；测试断言的负责人调整由本分支 Git diff 记录。

## 实施决策

不新增 run status，不修改历史 `ToolDiagnostic/ToolRunResult v1` schema。
公共 `DetectorFinding` 仅追加可选 consequence 字段，保存到 sidecar，不自动提升漏洞结论。
执行状态、覆盖深度、待证明义务分别记录：

| 数据 | 当前含义 |
|---|---|
| run `completed` | 被调用的检测流程正常结束；不表示整组件语义完整 |
| run `blocked` | 分析前提不足；旧检测器也可能用它表达模型不完整 |
| run `failed` | 检测器返回失败，或异常/无效结果被平台阻断 |
| `scope_files/scope_loc` | 完整分析与部分检查的源码数量/行数之和；不是安全覆盖率 |
| sidecar `analyzed_files` | 显式完整分析的文件；解析不完整不能进入该桶 |
| `partially_inspected_files` | 已做检查，但解析/模型仍不完整，结论未知 |
| `not_analyzed_files` | 完全未分析，或未完成可承认的检查 |
| `coverage_counts` | complete + partial + not_analyzed = applicable_files |
| `files_in_scope_without_a_claiming_detector` | 索引范围内没有插件声明支持的文件，不能从报告消失 |

为了兼容旧侧车消费者，`unexamined` 仍包含所有非完整分析文件；应读取每条
`analysis_status`，或使用新 `not_analyzed_files`，不要把 partial 都理解为从未检查。

**旧消费者迁移**：不再以 blocked → scope=0 判断未执行；以执行状态与上述覆盖字段联合解释。
已有 `run_all` 的返回类型不变。旧检测器未给 `file_outcomes` 时，blocked/failed 自报的
`analyzed_files` 只保守记 partial，不自动提升为完整分析。提供 outcomes 时必须覆盖所有
被分配文件，且检查范围、候选位置及输入 snapshot 必须通过验证。

有效候选的义务不按整体 status 删除；显式 failed run 已完成部分检查时同样可保留。
异常或范围/位置/结果非法则整体拒绝该插件结果，义务也不保留，避免传播无效证据。
没有义务的候选明确保存空列表；平台不伪造 satisfied 证据。

## IPC 正式路径

显式白名单注册 `ohscanner.interface.ipc`，kind=`research_candidate`。
`M2IpcInterfaceDetector` 只调用原解释器一次，把所有有可用 outline 的 complete/partial C/C++
文件一起交给解释器，保留其现有跨文件宏/派发表上下文；failed/not_run/缺 outline 文件
留为 not_analyzed。partial 候选保留原有义务，并增加 unknown 的
`parse_completeness_impact`。没有注册 `.complete-ast` 旁路身份。

```bash
cd /home/audit/openharmony-audit/owner-ipc-platform-20261011
/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit/.venv/bin/python -m src.cli ohscan-run \
  --repo-dir /path/to/component \
  --repository openharmony/component \
  --commit FULL_GIT_COMMIT \
  --include interfaces --include services \
  --detector ohscanner.interface.ipc \
  --json-out outputs/reports/component.json \
  --md-out outputs/reports/component.md
```

`--include` 与原命令一致，是精确路径/前缀，不是 glob，也不会自动排除测试。
五组件对比实验使用 B 已保存的 production plan 中的精确文件路径，避免改变范围。
没有选择性迁入 B 的 audit 双遍驱动、PoC、benchmark 执行器，也没有把本次工作称为完整
接管 B 分支。其旧驱动与本次正式 CLI 的格式不同；后续由队友按新的 sidecar 适配。

## 验证

```bash
/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit/.venv/bin/python -m unittest discover -s tests -q
/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit/.venv/bin/python scripts/verify_owner_ipc_components.py \
  --baseline-dir /home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b
git diff --check
```

第二条是研究复核脚本，需要 B 的 ignored baseline JSON/manifest 和其中记录的本地目标仓库；
不是正式扫描依赖，也不是无输入即可执行的 CI 测试。它调用正式 CLI，比对固定 repo/commit
下 `(file,line,rule_id,source_sha256)` 候选集合，保存命令、覆盖、产物 SHA-256 与新增/消失记录。
同一方法前后比对不等于独立准确率实验。测试与实验实跑数字见 `PROGRAM_STATUS.md` 最新节。

## 未解决与 unknown

- B 提出的 M1–M6 检测语义问题未修改；接口身份误报等仍在，候选不是漏洞。
- 不证明 guard dominance、完整跨仓调用、真实产品构建或可利用性；validated vulnerability=0。
- partial 文件即使错误不在候选行，也不能被认定不影响分析。
- 未实现生产范围自动规划的正式 CLI 参数、通用分片/跨片摘要、硬超时或进程隔离。
- B 本地曾增加公共 v2 源码绑定格式；本集成明确不迁移该不兼容格式，使用 v1 + sidecar
  绑定 repo/完整 commit/snapshot/profile/file/source hash/detector/version/rule。
- 独立 holdout 与 Precision/Recall 未验证；这里只验证工程接入和结果保留。

本分支可提交给负责人审查；不会自动切换 Draft Ready 或合并 main。
