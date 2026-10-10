# 接口/IPC 线基线决策记录（2026-10-10）

> 性质：**生效中的决策记录（ADR）**。记录接口线为何选本地 v0.1 为基线、round1 为捐赠者。

## 状态

已决定（队长 2026-10-10 拍板）：**本地 v0.1 为基线，`origin/draft/oh-interface-detectors-round1` 作模块捐赠者。**

## 背景

接口/IPC 线存在两套并行成果，均位于 WSL `~/openharmony-audit/CyberSecurity-Innovation-Audit-b`：

| | v0.1（本地） | round1（远端 `draft/oh-interface-detectors-round1`） |
|---|---|---|
| 分支/提交 | `feat/oh-a-interface-detectors` @ `830ef56`（61 提交） | `4271926` |
| 基底 | `feat/ohscanner-core`（真实 Detector 契约） | 较早的公共文件版本，`detector.py` 用 deferred import |
| 算法 | `analysis.py` 603 行：有界析取抽象解释（授权事实 must-intersection、descriptor、owner、上下界、caller_class、状态失效、路径预算 96） | `ipc_repository.py` 28KB：入口/分发器索引 + 权限链 + 宏目录 |
| 研究纵深 | 12 组真实 S2 历史修复对 + Semgrep/Joern/CodeQL/Clang 四工具对照 + 消融 + design freeze + 218 项回归 | 8 个测试文件，模式级 Web 家族 |
| 重叠 | 两套**只在 `src/ohscanner/detectors/interface/detector.py` 一个文件重叠** | |

## 决策

**基线 = v0.1。** 理由：

1. **契约正确性**：v0.1 基于 `feat/ohscanner-core`，使用真实 `DetectorFinding`/`EvidenceObligation`/`RunStatus` 契约；round1 的 `detector.py` 是 deferred import，与已落地契约不匹配。
2. **研究纵深**：v0.1 有 12 组固定 commit 的真实 S2 修复对、四工具离线对照、消融实验和 218 项回归——这是赛题评分（准确性/完整性/创新性）的实证基础，round1 没有。
3. **算法深度**：v0.1 的有界析取状态机比 round1 的模式匹配更深，且已 self-document 其边界。

**round1 = 捐赠者。** 理由：v0.1 自认的两个最大短板，round1 恰好补齐：

| round1 模块 | 补 v0.1 的哪个短板 | 去向 |
|---|---|---|
| `ipc_repository.py` (28KB) | v0.1 缺 transaction→handler 入口/分发器映射 | 抽取 entry 发现逻辑并入 `analysis.py` |
| `cpp_macros.py` | v0.1 因宏/头文件缺失导致 12 组里 7 组 partial→unknown | 作为 `analysis.py` 预处理层 |
| `web_patterns.py` | Web 家族（BridgeInjection/WebUrl/Disclosure/Engine） | 升级为 AST 版并入 `detectors/interface/` |

## 分支处置

- `origin/draft/oh-interface-detectors-round1` **保留不删**——它是捐赠来源，删除会丢失可追溯性。
- 本地 `feat/oh-a-interface-detectors` 重命名为 `feat/interface-ipc-detector`（去掉误导性的 `oh-a` 前缀）后推送为接口线唯一远端基线。

## 迁移原则

1. **`detector.py` 不合并**——以 v0.1 版为准，只从其捐赠模块吸收 entry/macro/web 逻辑。
2. **保留契约**：所有捐赠代码需改造为 v0.1 契约（`DetectorFinding`/`EvidenceObligation`），不引入新的 Finding 类型或 CLI。
3. **回归不退化**：迁移后 218 项测试必须仍全绿；新增能力补新测试。
4. **诚实标注**：捐赠模块的解析覆盖改善需实测重跑 12 组，不能凭推断宣称 partial 转 complete。
