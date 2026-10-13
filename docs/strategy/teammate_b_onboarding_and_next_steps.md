# 接口/IPC 线上手与下一步架构建议（2026-10-10）

> 读者：队长，以及后续接手接口/IPC 线的开发会话。
> 目的：把队友 B 已完成的 v0.1 工作讲清楚（代码在哪、怎么跑、边界在哪），并给出打通"发现 → PoC → 报告"闭环的架构建议。
> 政策前提：见 `AGENTS.md`（PoC/动态验证/漏洞报告是必须交付物）。

## 1. 代码位置与运行

- 仓库：WSL `~/openharmony-audit/CyberSecurity-Innovation-Audit-b`，分支 `feat/interface-ipc-detector`（原 `feat/oh-a-interface-detectors`）。
- 检测器包：`src/ohscanner/detectors/interface/`
  - `detector.py`（41 行）：契约适配器 `IpcInterfaceDetector`，`detector_id = "ohscanner.interface.ipc"`，`version = "0.1.0"`，`ast_scope = "per_file"`。任一单元 `parse_status in (failed, not_run)` 或缺 AST → 返回 `blocked`；任一单元 `parse_status != complete` → 状态 `blocked`（保留已审候选）。
  - `models.py`（54 行）：冻结数据类 `IpcPolicy`，`MODEL_VERSION = "oh-ipc-2026.10-v1"`。内含敏感 API 目录（约 50 个）、能力调用、布尔权限 API、result 权限、caller token/UID API、owner API、parcel 读取、entry 名、`max_call_depth=2`、`max_paths=96`、`expected_permissions` 等。
  - `analysis.py`（603 行）：核心。`Interpreter` —— 有界析取抽象解释。关键类型：`Value`、`State`（`auth`/`descriptor`/`owner`/`lower`/`upper`/`caller_class`/`identity_issues`/`reset`）、`Function`、`Observation`。
- 测试：`tests/detectors/interface/`（8 个文件）。全项目回归：

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit-b
.venv/bin/python -m unittest discover -s tests      # 218 项，约 5.8s
```

- 结果报告：`docs/research/ipc_scanner_v0_1_2026-10-10.md`；方法卡 `research/methods/interface/IPC_METHOD_CARD.md`；执行记录 `research/methods/interface/IMPLEMENTATION_LOG.md`。

## 2. 运行链路（v0.1）

```text
ScanRequest (repo_path, component, full_commit_sha, cpp_scope)
   │
   ├─ 固定 Git tree/blob 读取 → SourceUnit（不可变快照，commit 二次核验）
   │
   ├─ IpcInterfaceDetector.detect(units, ctx)
   │      └─ Interpreter：per_file AST → 有界析取状态机
   │             · if/else 分裂、return 截断、switch case/fallthrough
   │             · 循环零/一次展开、路径预算 96、局部调用摘要深度 2
   │             · 合并时对授权事实取 must-intersection（未授权路径不丢）
   │      └─ Observation(family, rule, file, line, symbol, trace, root_key)
   │
   ├─ DetectorFinding(family, cwe, trace, evidence_obligations[3])
   │      obligations = entry_reachability / callee_and_policy / security_impact
   │
   └─ Bridge → ToolRunResult(schema_version=1) + coverage sidecar
```

接入示例：

```python
from src.ohscanner.runner import DetectorRegistry
from src.ohscanner.execution import run_reviewed_detectors
from src.ohscanner.detectors.interface import IpcInterfaceDetector
registry = DetectorRegistry()
registry.register(IpcInterfaceDetector())
report = run_reviewed_detectors(repo_path, component_name, full_commit_sha, tuple(cpp_scope), registry)
```

## 3. 六家族模型

| 家族 | CWE | Source → Sink | 保护必须成立 | 主要边界 |
|---|---|---|---|---|
| AUTH-01 SA/descriptor 信任边界 | CWE-441 | `OnRemoteRequest` 请求 Parcel → 分发/回调 | 同一请求 Parcel 的 token 与本服务 descriptor 比较，拒绝不匹配路径 | descriptor 只隔离接口，≠ 访问权限；完整 SA 代理跨服务转发链未恢复 |
| AUTH-02 缺失服务端鉴权 | CWE-862 | 审核入口/handler → 敏感 API/设备对象 | 原始调用者权限/受信类别保护到达操作的路径 | 仅客户端 NAPI 校验不算；API→permission 映射需版本化审查 |
| AUTH-03 身份/归属/调用者类别 | CWE-863 | caller token/UID、self、Parcel 派生 ID、owner | UID/token 域匹配；original caller；owner 或特定 caller class | 无全程序别名；**直接按请求 UID 授权是已知安全对照误报** |
| AUTH-04 鉴权路径覆盖 | CWE-863 | 权限结果 → 分支 → 敏感操作 | 拒绝分支真正退出；每个可达敏感 case 受保护 | 循环/复杂条件保守近似；语法路径 ≠ 实际可达攻击路径 |
| DATA-01 Parcel 长度/位置 | CWE-20 | `ReadInt32` 长度 → `memcpy`/`ReadBuffer` | 长度非负且不超同一目标容量；减法前剩余量足够 | 非通用整数分析；乘法/类型溢出/容器生命周期未覆盖 |
| CAP-01 能力导出 | CWE-926 | `WriteRemoteObject`/`WriteFileDescriptor` | 原始调用者授权覆盖导出路径 | 需核对是否公开合法 API、对象权限语义、FD 所有权；≠ 已证实泄漏 |

## 4. 实验资产地图（`~/openharmony-audit/ipc-research`，**6.5 GB，必须留在 Git 外**）

| 目录 | 内容 | 数量 |
|---|---|---|
| `repos/` | 10 个 OpenHarmony 组件源码（communication_ipc、inputmethod_imf、multimedia_camera_framework、multimedia_player_framework、notification_common_event_service、resourceschedule_background_task_mgr、security_access_token、telephony_call_manager、update_updateservice、window_window_manager） | 10 |
| `pairs/` | 历史修复对（漏洞版 + 修复版） | 13 |
| `workspace/` | Joern CPG 工作区 | 28 |
| `artifacts/` | CodeQL DB/SARIF、工具原生日志 | 390 |
| `tools/` | codeql、jdk-21、joern-cli、semgrep | 4 |
| `downloads/` | 被动下载源码 | — |

复现命令见 `docs/research/ipc_scanner_v0_1_2026-10-10.md` §复现与集成。

## 5. 诚实度评估（**不可对外引用的说法**）

已确认的事实：

- 12 组设计集：**仅 5 组两侧文件解析完整**，另 7 组 partial → unknown（保留候选 + blocked）。
- 29 个自编设计场景全符合预期；13 个冻结后生成变体 12 个符合、**1 个安全对照误报**（直接按请求 UID 授权）。变体与设计集**同源**，非独立留出集。
- 四工具对照是**本项目自编公开规则**，非厂商默认能力排行。
- 218 项回归通过；解析压力测试 94 文件 × 3 轮完成。

**不可声称**（`research/methods/interface/IMPLEMENTATION_LOG.md` 已自述）：

- ❌ "12/12 真实漏洞检出率" —— 设计集，且 7 组 unknown。
- ❌ "覆盖大部分历史 IPC 漏洞" —— 39 条清单仅部分确认 IPC 根因。
- ❌ "独立留出集验证" —— S3=0，无独立 holdout。
- ❌ "整体组件安全/全部告警为零" —— fixed 候选为零 ≠ 安全。

## 6. 补齐路线（按依赖排序）

```text
① 解析覆盖：移植 round1 的 cpp_macros.py 宏展开 → 把 7 组 partial 降到 unknown 以下
② 跨文件/入口：移植 round1 的 ipc_repository.py 入口/分发器索引 → 补 transaction→handler 映射
③ 关系域：用 caller/owner/permission 关系域替代名字启发式 → 修直接 UID 安全绑定误报
④ 数值：对最常见长度/减法模式接 SMT 路径可满足性与位宽约束
⑤ 独立留出：从剩余公告复核根因，锁模后盲测，按组件/时间段切分
```

## 7. 架构建议：打通"候选 → 漏洞报告 + PoC"

```text
现状:  源码 → IPC 检测器 → candidate + EvidenceObligation ──▶ (断在这里)
目标:  源码 → IPC 检测器 → candidate
                 ↓ 复核（review_store 已存在）
                 ↓ 证据等级升级（candidate → confirmed，记录等级）
                 ↓ family-specific PoC 生成 + 本地隔离环境触发（ASan/UBSan/TSan）
                 ↓ 影响版本判定（跨 commit/tag manifest 扫描）
                 ↓ 修复建议（从 13 组历史修复对提炼 patch pattern）
                 ──▶ 漏洞报告（src/report/vulnerability_report.py）
```

关键点：

1. **不断链**：candidate 有 `EvidenceObligation`，补齐 obligation 后走 Evidence gate 升级；升级路径需实现（当前只有 candidate 出口）。
2. **PoC 分家族**：六个家族各一个模板，参数化 entry/guard 缺失点/敏感操作，产出可执行源码 + 观测。
3. **影响范围可自动化**：`pairs/` 有 13 组漏洞/修复 commit 对，可作为跨版本判定的种子与真值。
4. **不引入新 Finding 类型/新 CLI**：复用 `ToolRunResult` 契约（见 `docs/contracts/ohscanner_detector_contract_v1.md`）。

## 8. Web 方向下一步

round1 的 `web_patterns.py` 是**词法级**模式（`runJavaScript` 非字面量参数、URL `startsWith` 白名单、`fileAccess(true)`/`mixedMode(MixedMode.All)`）。升级路径：

```text
现状:  词法 token 匹配 → review_patterns(family)
目标:  AST + 约束传播
       controller 实例 → 注册的 proxy 方法 → 源码约束（allowlist/Origin 校验）
                       → native sink（runJavaScript / 文件访问 / 混合模式）
```

- 复用 round1 的家族划分（bridge / url / disclosure / engine），换成 AST 版。
- `WebEngineDetector` 目前恒返回 `blocked`（引擎算法未实现）——补齐或明确移除，不要留空壳。
- 前端源码（.ets/.js/.ts）解析需新增 language binding，属于平台层能力，需向负责人申请。

## 9. 立即可执行的动作

1. 跑一次回归确认基线：`.venv/bin/python -m unittest discover -s tests`（应 218 项 OK）。
2. 移植 `cpp_macros.py`，重跑 12 组，量化解析覆盖改善（目标：partial 组下降）。
3. 建 `src/ohscanner/poc/` 骨架 + 选一个家族（建议 AUTH-02，条件最清晰）打通端到端 PoC。
4. 更新 `PROGRAM_STATUS.md` 记录上述实测事实。
