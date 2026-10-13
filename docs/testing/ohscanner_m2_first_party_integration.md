# OHScanner M2：固定 Git 源码上的第一方 Detector 执行入口
> **政策更新 2026-10-10**：本文为历史记录（记录某时点实际做了什么），事实性内容保留原样。文中"不做 PoC / 不做动态验证 / 不升级结论状态 / 不计算 Precision-Recall"等限制已于 2026-10-10 **废除**；当前生效政策见 `AGENTS.md` 的 **Competition deliverables — must produce** 章节：PoC、动态验证、CWE/CVE、影响范围、修复建议、性能数据、漏洞报告均为**必须产出**的交付物。

> 版本：`feat/ohscanner-core` / Draft PR #5。M2 先实现**负责人负责的统一平台执行链**；两位队友实际算法必须通过独立正/负样本、方法卡、来源及代码审查后，才能注册为正式检测器。
> 
> **不要混淆**：`ohscan-index` 仅索引，`ohscan` 仅运行合成 Mock，`ohscan-run` 才使用固定 Git 对象 + 显式登记的第一方插件。当前唯一 catalog 项是 **非安全算法示例** `ohscanner.example.cpp.copy-calls`。它寻找调用表达式，不证明溢出/UAF/权限绕过。

## 1. 代码结构与交付

| 路径 | 责任 |
|---|---|
| `src/ohscanner/detectors/catalog.py` | 负责人管理的**显式审核注册表**，不会解析用户任意模块路径；默认只允许示例插件 |
| `src/ohscanner/detectors/example.py` | 使用 M1 AST 的 C/C++ 调用位置样例，附带 `resolved_callee`、`bounds_proof`、`reachability` 的 `unknown` 义务；不是漏洞检测器 |
| `src/ohscanner/execution.py` | 准备本地 Git 固定源码 `ScanContext`，调用 M1.5 `run_all_with_coverage`，重新核对 commit/tree/blob，写结构化证据报告 |
| `src/cli/main.py` | 新增 `ohscan-run`，要求显式 `--detector`；示例插件须额外 `--allow-example-detectors` |
| `tests/test_ohscanner_m2.py` | 本地临时 Git 仓库中测试候选、状态、来源、未覆盖文件、义务、未审批插件与 CLI |

此模式**不动态加载不可信插件、不启动 CodeQL/Semgrep/Clang 等外部漏洞扫描器**。检测器的 Python 代码仍与 Runner 在同一进程，**没有硬超时、进程资源隔离或沙箱**。只运行代码审查通过的第一方插件。

## 2. Ubuntu 演示（你现在可以跑）

在审计工程根目录：

```bash
git fetch origin
git switch feat/ohscanner-core
git pull --ff-only origin feat/ohscanner-core
source .venv/bin/activate
python -m unittest discover -s tests -p 'test_ohscanner_m2.py' -v
python -m unittest discover -s tests -q

TARGET="$HOME/oh-audit-targets/commonlibrary_c_utils"
COMMIT=b807d3dadb7dbb7639fe85b3a5f72da18d318da2

# 明确授权运行的非安全演示插件；不是正式漏洞检测
python -m src.cli ohscan-run \
  --repo-dir "$TARGET" \
  --repository openharmony/commonlibrary_c_utils \
  --commit "$COMMIT" \
  --detector ohscanner.example.cpp.copy-calls \
  --allow-example-detectors \
  --json-out outputs/reports/cutils_m2_example.json \
  --md-out outputs/reports/cutils_m2_example.md
```

该命令预期读取固定提交的全部允许源码，**不 fetch、不 checkout、不修改被检 Git 工作区**，并按文件将完整 AST 交给示例插件，partial 文件进入 `unexamined`。

报告字段：

- `experiment_kind=first_party_detector_execution`：此时执行了一个第一方实例；它仍可能只是示例插件。
- `commit/git_tree/snapshot_sha256`：固定 Git 来源的三层身份。
- `scope/source_parsing`：被收录 Git 条目、文件和语法覆盖；跳过项不可视为已扫描。
- `detector_runs[]`：原 `ToolRunResult v1`；`status=completed` 仅代表**合格子集运行结束**，不是组件安全结论。
- `detector_coverage.detectors[id].analyzed_files/unexamined`：可精确统计该检测器的执行/未知区域。
- `evidence_obligations`：每条候选需要额外证明的事项，默认 `unknown`，不可转化为确认漏洞。
- `validated_vulnerability=0` 表示没有执行本阶段的运行时漏洞验证；`diagnostic_count=0` 也不表示没有漏洞。
- `status=completed_with_limitations` 表示存在跳过或覆盖缺口。即使状态为 completed，也不可声明已完成正式安全审计。

## 3. 队友 A 的首个 C++ Detector 如何接入

队友 A 的 `codex/teammate-a-cpp-detectors` 分支目前已有 `LifetimeOwnershipGuardDetector` 的源码原型，位于 `src/ohscanner/detectors/cpp/lifetime_detector.py`。

**不要直接把 A 的整个分支 merge 进 `feat/ohscanner-core`**：该分支带有独立研究资产和较早公共文件版本。待代码审查通过后，单独迁移检测器模块、方法卡、正负例和必要测试，再在 `src/ohscanner/detectors/catalog.py` 加入经过确认的工厂映射，例如：

```python
# 仅在对应类与测试经过审核、已存在于当前分支时：
# from .cpp.lifetime_detector import LifetimeOwnershipGuardDetector
# _APPROVED[LifetimeOwnershipGuardDetector.detector_id] = {
#     "factory": LifetimeOwnershipGuardDetector,
#     "kind": "research_candidate",
#     "summary": "Narrow ownership/raw-alias candidate model; not proven UAF",
# }
```

建议队友 A 在开发分支和你的 M1.5 公共接口同步后，明确选择 `required_facts=("ast",)` + `ast_scope="per_file"`（如果确实只在 AST 完整文件执行）。旧原型只要求文本且自行跳过 partial，这样在真实 123 文件输入中可能返回 `blocked`、丢失已分析子集的成功状态；应补严格的正/负/partial 测试，而不是由负责人随意覆盖他的算法语义。

验收前不能把 `ohscanner.example.cpp.copy-calls` 的结果与 A 的研究样本成果混算。

## 4. 队友 B 的接口安全算法怎么接入

B 的 JS/ArkTS 和 IPC 检测器应使用**同一 Detector 协议**，通过 `SourceUnit`/可选 `shared_facts` 输入产生 `DetectorRun`。

对于 C++ 层 IPC 方法可先使用现有 AST `facts_v1`；JS/ETS 当前尚未解析，应把完整语义/Guard/权限关联列为未证实前提。没有对应 Frontend 时不能声称存在调用者身份—权限的完备关系。队友 B 同样须经代码审查、方法卡与回归测试后在同一 `catalog.py` 显式注册。

## 5. M2 平台 Done 与完整 M2 Done

- [x] 第一方 allowlist 和非安全示例插件入口；
- [x] 固定 Git source → 注册器 → `ToolRunResult` → 覆盖/证据 sidecar → JSON/Markdown；
- [x] 输入 commit/blob 二次核验、旧 CLI 兼容和无外部扫描器依赖；
- [x] CI 的 Git fixture、部分解析、候选义务、插件信任边界测试；
- [ ] 用户在 Ubuntu Git 2.34.x 对真实固定 `c_utils` 执行 `ohscan-run` 示例，核对覆盖；
- [ ] 队友 A 实际 Detector 完成单独代码与案例审查，通过 PR/局部挑选接入；
- [ ] 队友 B 实际 Detector 和真实攻击面实验完成审查，通过对应插件接口接入；
- [ ] 真正的检测算法独立修复前/后、安全对照、保留集及消融评测。

所以 **M2 平台底座可先验收，不等于整个 M2 自研检测器研究完成**。

## 6. Git 分支与合并策略

可继续将本 PR #5 保持 Draft，以便目前集中开发。但**不推荐等 M0～M4 全部结束再合并一个超级 PR**；长期积累会导致难以审查和分支漂移，队友也要同步旧接口。最佳节奏是在底座单独审查稳定后合并 core PR，之后 A/B 分别以小 PR 集成，再用独立 PR 添加高级分析与报告。按负责人的明确授权执行 Ready/Merge，不自动合并。


> **2026-10-11 M2-A 追加**：两个来自队友 A 的第一方 C++ 研究候选插件现已登记在 Catalog，可用 `ohscan-run --detector ohscanner.cpp.lifetime --detector ohscanner.cpp.shared_ptr_race` 在固定 Git 提交执行。原文“唯一 Catalog 项是 example”指 M2 初始状态，请以 [M2-A 接入验收文档](ohscanner_m2_a_integration.md) 为准。尚未完成独立保留集、动态确认和比赛交付闭环。
