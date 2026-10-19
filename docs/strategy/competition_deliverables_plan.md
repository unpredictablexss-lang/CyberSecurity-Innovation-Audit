# 赛题交付物对齐计划（2026-10-10）

> 性质：**生效中的交付规范**（非历史记录）。本文把赛题要求逐条映射到项目模块与补齐路径。
> 上位约束：`AGENTS.md` 的 **Competition deliverables — must produce** 章节。评分与范围依据：`docs/competition_requirements.md`、`docs/deliverables_checklist.md`、`docs/evaluation_criteria.md`、`docs/architecture_2026.md`。

## 0. 背景：为什么需要这份文档

赛题（第五届中国研究生网络安全创新大赛 · 揭榜挑战 · 第一题：OpenHarmony 开源代码漏洞挖掘）评分九项：准确性、完整性、CVE 准确性、CWE 准确性、**PoC 质量**、**分支影响准确性**、**修复建议质量**、工具性能、技术创新性。误报负向扣分。

项目在 2026-10-09 前后被注入了一整套禁止性条款（"不做 PoC / 不做动态验证 / 不升级结论状态 / 不计算 Precision-Recall"），导致 `validated_vulnerability = 0`、没有任何漏洞报告产出——**交付物与评分表严重脱节**。2026-10-10 起废除这些条款（见 `AGENTS.md`）。本文给出补齐路线。

保留的唯一纪律是**防误报**：结论只上升到证据支撑的高度。误报是负分项，宁可标 `unknown` 也不虚报；但这不等于"不做"。

## 1. 交付物矩阵

| # | 赛题交付件 | 对应评分项 | 现状 | 责任模块 | 补齐路径 |
|---|---|---|---|---|---|
| 1 | 工具源代码 | 准确性/完整性/创新性 | 已有：OHScanner core（漏斗 L0–L8）+ IPC 六家族 Detector | `src/ohscanner/` | 继续；补 Web 家族与跨文件边 |
| 2 | 漏洞描述 + CWE/CVE | CVE/CWE 准确性 | `candidate_cwe` 已有；CVE 映射缺失 | `src/case/`、`src/report/` | 建 CWE→影响 映射表；有公开编号的映射 CVE，新发现走 OH 漏洞披露/奖励流程 |
| 3 | **PoC 可执行代码** | PoC 质量 | **完全空白**（被政策禁止） | **新增** `src/ohscanner/poc/` | per-family 模板 + 隔离环境执行 + 稳定性重放（见 §2） |
| 4 | 影响范围（模块 + 版本分支） | 分支影响准确性 | 部分（仅固定 commit 对） | `src/report/`、跨版本 manifest 扫描 | 跨 tag/manifest 扫描同一根因，输出受影响版本区间与漏洞/修复 commit 边界 |
| 5 | 修复建议/补丁 | 修复建议质量 | 空白 | `src/report/`、patch pattern 库 | 从 12+ 组历史修复对提炼 patch pattern，对新发现输出 diff 建议与理由 |
| 6 | 漏洞分析报告 | 完整性 | 只有 benchmark 汇总（非漏洞报告） | **新增** `src/report/vulnerability_report.py` | 渲染 confirmed 发现为赛题格式报告 |
| 7 | 性能数据 | 工具性能 | ✅ **已完成首轮实测（2026-10-10）** | `scripts/perf_scale_scan.py` + `benchmarks/perf_scale_corpus_2026-10-10.json` | 11 个真实组件 / 9,508 源文件 / 261.8 万行，累计 113.6 s，峰值 RSS 上界 265.7 MB，84 files/s。报告 `docs/testing/ohscanner_performance_scale.md`。后续可补：并行/增量、整树（千万行）规模 |

## 2. PoC 与动态验证（交付件 #3，最高优先级缺口）

**为什么最关键**：PoC 质量是独立评分项，且"发现—PoC—Patch—重验"闭环（`architecture_2026.md` §17 创新点 C）是创新性得分点。项目当前这条链完全断裂。

### 2.1 模块设计 `src/ohscanner/poc/`

- **per-family 模板**：六个 IPC 家族（AUTH-01..04、DATA-01、CAP-01）各一个 PoC 骨架，参数化 entry / guard 缺失点 / 敏感操作。
- **隔离执行**：在本地不可信的临时构建环境里编译并运行目标组件，收集观测。
- **稳定性重放**：同一 PoC 多次运行，记录 `trigger_success` / `stable_reproduced` / `flaky` / `no_trigger`（对齐 `docs/roadmap.md` Milestone 4 的 PoC 状态机）。
- **产物保存**：PoC 源码、编译命令、运行日志、环境指纹（commit + 构建配置 + sanitizer 版本）。

### 2.2 动态验证手段

- ASan / UBSan / TSan（并发类发现必须 TSan）。
- 已有基础：`docs/testing/cjson_allocator_runner_verification.md` 已跑通"sanitizer 触发的受控失败"路径，可作为 harness 起点。
- 已有真值：`docs/targets/c_utils_singleton_uaf_groundtruth.md` 给出用修复前 commit + 多线程 harness + TSan 复现 UAF 的方案。

### 2.3 安全边界（必须写明）

- **允许并要求**：本地隔离环境构建/运行 OpenHarmony 组件、编译运行 PoC、使用 sanitizer。这是赛题要求的"PoC 成功触发"。
- **唯一边界**：不攻击线上真实服务、不向真实设备/网络发送攻击流量。
- **证据分级**：`static_candidate < static_confirmed < dynamic_reproduced < stable_reproduced`。只有达到 `dynamic_reproduced` 及以上才进漏洞报告。

## 3. 当前差距与优先级

```text
P0  建立 src/ohscanner/poc/ 骨架 + 1 个 family 的端到端 PoC（打通闭环）
P1  src/report/vulnerability_report.py：把 confirmed 发现渲染成赛题报告
P2  跨版本影响判定（复用 ipc-research/pairs/ 的 13 组修复对 + 跨 tag 扫描）
P3  从历史修复对提炼 patch pattern，输出修复建议
P4  真实组件性能基准
P5  Web 家族（round1 web_patterns 升级为 AST 版）
```

**P0 是唯一真正卡住"交付物 vs 赛题脱节"的一环**：没有 PoC，其余交付件都只是静态描述，评分表上 PoC/分支影响/修复建议三项直接失分。

## 4. 与现有文档的关系

- `AGENTS.md`：政策真源（deliverables 章节 + Evidence gate）。
- `docs/architecture_2026.md`：目标架构，§17/§18/§19 已按"发现—PoC—Patch—重验"闭环表述，与本计划一致。
- `docs/roadmap.md` Milestone 4：PoC / 动态验证 MVP 的里程碑拆解。
- `docs/evaluation_criteria.md`：评分维度细节与 PoC 状态划分。
- `docs/deliverables_checklist.md`：交付清单核对表。
- 本计划：把上述对齐为**可执行的责任模块 + 补齐顺序**。

## 5. 验收

逐条核对交付件时用以下问题（取自 `architecture_2026.md` §19）：

1. 系统扫了多少代码？覆盖率多少？
2. 为什么这个候选被选中？Source/Sink 在哪？
3. 哪条路径可达？哪个安全检查存在或缺失？
4. **PoC 是否真的触发？动态证据是什么？**
5. 哪些分支/版本受影响？
6. **Patch 为什么能修？修复后原 PoC 是否失败？**
7. 性能数据是多少？

对齐赛题的完成标准 = 上述问题对**至少一个真实 OpenHarmony 组件**都有可复核答案。
