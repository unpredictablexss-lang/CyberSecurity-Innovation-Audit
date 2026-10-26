# 平台线首项交付：源码绑定与自动检测器规划

日期：2026-10-17；分支 `work/platform-20261017`。
共同基线：`6a41dc9b1aa030158e09be6241e2b14341f9256d`。
代码提交：`fbfc20b8804200cd69a893afdfc0a9daada0648f`。
本交付只在平台 allowlist 内修改；负责人/A/B、Catalog/Runner/API/SQLite/Worker/全局路由保持原状。
没有 push、merge 或 Draft Ready。

## 解决什么问题

产品 PRD §十一及技术文档 §6.4 希望普通审计按实际适用规则自动规划。
本轮将该能力实现为可测试的纯服务：固定源码清单 + 调用方提供的已批准 Catalog 元数据 → 确定性检测器尝试计划。
既有平台只暴露检测器级别的语言/版本，不能凭空生成 rule_id、risk_family、CVE 或完整语义能力。
本模块不重新维护检测器注册表，不执行扫描、源码构建、真实模型、网络操作或漏洞升级。

## 已实现接口

- `SourceFile` / `SourceManifest`（src/workbench/sources）：不可变清单，绑定 repository/full commit/tree/snapshot、文件路径/语言/source SHA/可选 blob/parse、include scope、可用事实、未分类/跳过计数及已有的跳过文件原因。
- `manifest_from_context(context, git_tree, inventory, sources=None)`：消费现有 prepare_git_context 的输出，不再读 Git 或解析；核对 snapshot、tree/count/bytes/scope 和可选 blob 内容哈希。fixture 不能冒充固定 Git 来源。
- `metadata_from_detectors(rows, approved_instances)`：只从调用方已经批准并实例化的 Detector 读取 required_facts；拒绝 ID/版本/语言/事实不一致。不会注册新 Detector 或调用 detect。
- `plan_audit(manifest, rows, selected_detector_ids=None)`：None 自动按元数据语言匹配；显式列表只允许其中的适用项，空列表不会退回自动选择。

返回包含 `suggested_detector_ids`、各 Detector planned/skipped/blocked 与理由、未覆盖文件、解析限制、待复核项、版本/来源及 plan_sha256。
`ready` 只表示可提出尝试建议；`ready_with_limitations` 保留缺口；无适用能力是 blocked/unknown，空清单是 empty_scope/unknown。
所有计划的 execution_status=not_run、security_assessment=unknown；没有 candidate_count=0 或安全/确认漏洞的推导。

同一源码、元数据和选择的排列不影响计划；commit/tree/scope/source SHA/规则版本/事实变化会改变计划摘要。
plan_sha256 不是执行缓存身份；使用缓存仍需 engine/parser/build/product/dependency 等单独版本绑定。

## 能直接复现的命令

从本线工作区、使用自己的环境：

```bash
cd /home/audit/ohscanner/worktrees/parallel-platform-20261017
source /home/audit/ohscanner/parallel-20261017/platform/env.sh
.venv-web/bin/python -m unittest tests.test_audit_plan tests.test_source_planning_manifest -v
.venv-web/bin/python -m unittest discover -s tests -q
.venv-web/bin/python -m scripts.check_change_scope --base "$OHSCANNER_BASELINE" --lane platform
.venv-web/bin/python -m research.deliveries.platform.verify_planning \
  --repo-dir /home/audit/openharmony-targets/commonlibrary_c_utils \
  --repository openharmony/commonlibrary_c_utils \
  --commit b807d3dadb7dbb7639fe85b3a5f72da18d318da2 \
  --output /tmp/ohscanner-platform-plan-new.json
```

验证入口复用现有固定对象读取/索引、Catalog 和 approved registry，只将规划 JSON 写到指定新输出位置；不创建数据库或后台任务。
纯 plan_audit 和 manifest_from_context 不承担源码读取；verify_planning 是验证入口，确实调用现有 Git/AST 索引。

## 本轮验收证据

- 新增定向测试 28/28；仓库根测试总计 551，547 passed / 4 skipped，0 failed。
- 四项 skip 延续基线：两项缺少历史材料，两项按设计禁止宿主机运行 Docker PoC；不将它们报成通过。
- 固定 commonlibrary_c_utils：commit b807d3dadb7dbb7639fe85b3a5f72da18d318da2，tree 52b42d41ed091f7dcae37c4ce3a0d95b6fb1f16d，123 源码文件 / 1,567,031 字节。
- 现有索引为 93 complete / 30 partial；105 个 non_source 条目保持未分类/非源码缺口，未猜测其中多少是真正代码。
- 当前共同基线的实际 Catalog 建议 3 项：lifetime 0.3.0、shared_ptr_race 0.4.0、IPC 0.5.0。这是共同基线版本，不是 A/B 最新开发版本。
- 规划状态 ready_with_limitations；改变 Catalog 排列后输出完全相同；独立重新读取固定对象/索引后第二次完整规划也逐字节相同。未运行 Detector，不作任何准确率或漏洞结论。
- 详细命令输出、原始规划和哈希位于 `/home/audit/ohscanner/records/platform-development-20261017/`；精简摘要见 acceptance.json。

| 验收要求 | 当前证据 |
|---|---|
| 空仓/空清单 | 实际 empty Git commit 的空 inventory 适配测试；返回 empty_scope/unknown |
| 混合/未知语言 | C/C++/JS/Rust 输入与真实 JS fixture；无规则文件逐项列出 |
| 无适用规则/显式不适用/空选择/未知 ID | 不启用其他 Detector，不将未知项当安全 |
| partial/failed/not_run | 保留解析缺口，不生成 analyzed_files |
| 元数据/事实缺失或错误 | blocked 或 prerequisite unknown；不会伪造 required_facts |
| 来源/版本变化与重现 | full SHA/tree/snapshot/blob/content/count/scope 校验、稳定摘要与版本失效测试 |
| 已有代码与证据兼容 | 全量回归；生产 result/schema/ID/API/存储没有修改 |
| 无隐式 fetch、源码执行、模型调用 | 既有离线 Git 环境验证，纯函数 subprocess/socket/write 禁用测试，代码路径复查 |
| 团队边界 | baseline policy scope check，无越界文件 |

## 集成人接线申请（未实施）

1. 先审批一个只读规划预览入口（建议 POST /api/v1/audit-plans，路径仅为提案，不是当前端点）。输入仓库 ID、revision、include scope、可选显式 Detector IDs；复用现有登记根目录与同源写请求检查。
2. 使用现有版本服务先冻结 full commit/tree。源码读取/AST 在现有预算和可取消子进程边界内执行，不把全仓解析直接塞进 FastAPI 请求线程。
3. 由公共层提供 approved metadata/instances 和实际 index context，再调用本模块；metadata 缺失、无适用能力、空清单、超限/超时分别返回真实状态。
4. 后续为 scan API 独立增加 automatic 选择语义；保留旧显式 detector_ids 客户端兼容。入队始终保存最终明确 IDs/versions、planner/version、metadata/plan SHA 与固定源码身份；Worker 重新核验来源和版本，漂移应拒绝，不能偷偷使用新规则。
5. UI 只在公共接口验收后隐藏普通用户的检测器选择；展示已计划、跳过、未支持和 unknown，不能把 planned 写成已运行。
6. 接线单独提交并补 API→Worker、版本漂移、预算/取消、旧客户端/历史报告兼容和浏览器回归；不要把本线单元测试当作完成这些链路。

## 仍未实现的边界

- 网页/API/Worker 自动调度尚未接线；当前网页的 Detector 手选不会因本交付自动消失。
- 现有 prepare_git_context 在无受支持 UTF-8 源码时仍抛出异常；本模块支持消费空 inventory，但没有改动该公共读取器或假装端到端空仓索引已修复。
- Git symlink/submodule 在既有 inventory 只有总数，不能制造缺失的路径；oversize/non-UTF8 已有路径/原因完整保留。
- 未认证官方仓库归属，未补全 JS/TS/ArkTS 解析或检测器，也未实现多仓、分片、真实 Agent、PoC 或产品影响确认。
- context_snapshot_checked 表示所消费 context 的摘要/清单一致，不表示重新读取并独立证明 Git tree，或证明完整语义分析。

这些后续工作各自需要集成人/对应线的独立交付，不应通过加空菜单或修改历史结论来声称完成。
