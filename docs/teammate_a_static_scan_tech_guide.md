# Teammate A 静态扫描技术指南

> 适用分支：`codex/teammate-a-static-module-20261013`  
> 更新日期：2026-10-13  
> 本文整理 A 线 C/C++ 静态扫描模块的职责、数据流、实验边界和复现命令。平台、Web、任务队列、Agent 和动态 PoC 平台不属于 A 线职责。

## 1. 职责边界

| 模块 | 负责方 | A 线职责 |
|---|---|---|
| C/C++ detector | A | 实现和维护 `lifetime`、`shared_ptr_race` 等候选检测器 |
| 静态实验 | A | 外部工具实验、方法卡、Coverage、性能和历史样本分析 |
| Evidence / binding | A | 提供 source hash、artifact hash、patch obligation 和版本影响输入 |
| Core / Catalog / Runner | Core | 统一契约、注册、调度、CLI、CI 和结果桥接 |
| IPC / ArkTS / 权限 | B | 接口、权限、Parcel、IPC detector |
| PoC / TSan / 动态验证 | B / 接口线 | PoC、Harness、Sanitizer 和动态证据 |
| Web / Worker / DB | Core | RepositoryManager、任务队列、SQLite、Web UI |
| Agent | Core / M3 | 受约束工具调用和证据调查编排 |

A 线不建立第二套 CLI、Candidate JSON、PoC 平台或漏洞报告系统。

## 2. 模块数据流

```text
固定 Git Revision
  -> SourceUnit / ScanContext
  -> A 线 C++ Detector
  -> Candidate / Evidence / Coverage
  -> Revision / Version Differential
  -> Review / Report / Performance
```

### 2.1 输入约束

- 必须绑定 repository、完整 commit、scope、profile、source hash。
- Detector 不联网、不 checkout、不写受检源码。
- `partial`、`failed`、`blocked`、`not_run` 不能解释为 safe。
- 空 findings 只能表示未观察到候选形态。

### 2.2 输出约束

- 新鲜输出默认 `candidate/unassessed`。
- `possible_hit` 不是 TP，`miss` 不是 FN。
- `confirmed/reportable` 必须经过独立 Evidence gate 和动态验证。
- `ToolRunResult v1` 保持兼容；扩展信息放入 sidecar。

## 3. 三种审计模式

### Snapshot

对一个冻结的 `repo + commit + scope + profile` 执行 Detector。

### Revision Range

对 baseline 和 endpoint 执行同一 Detector，输出：

- `new`
- `persistent`
- `disappeared`
- `unknown`

该结果描述候选变化，不自动证明漏洞何时引入。

### Cross Version

对多个固定 revision 执行同一 root-instance 分析，输出：

- `possibly_affected`
- `not_present`
- `unknown`

`affected/fixed` 还需要产品构建、补丁和动态证据支持。

## 4. 当前第一方能力

### C/C++

- `ohscanner.cpp.lifetime`：`unique_ptr` owner/raw alias、`reset()`、stale alias 形态，主候选 CWE-416。
- `ohscanner.cpp.shared_ptr_race`：非原子 `shared_ptr` 成员访问和锁上下文不一致，主候选 CWE-362。

### 接口联合能力

- AUTH-01：IPC 描述符/中转边界；
- AUTH-02/03/04：授权缺失、身份/对象归属和 guard 覆盖；
- DATA-01：Parcel copy-range / position-underflow；
- CAP-01：能力导出或敏感能力暴露。

这些能力当前均是 `research_candidate`。详细 CWE 和限制见
`docs/ohscanner_current_vulnerability_subtypes.md`。

## 5. 研究工具与证据

| 工具 | 用途 | 结论边界 |
|---|---|---|
| Clang SA | host TU 静态分析 | 不是产品 GN 构建 |
| CodeQL | 通用 C/C++ security-and-quality | 查询命中不等于漏洞 |
| Infer/Pulse | 锁一致性、内存/资源问题 | 只记录 research candidate |
| Joern | 结构查询和 root-cause slice | partial/failed 必须保持 unknown |
| Semgrep / Cppcheck | 快速 pattern/baseline | 只做候选和对照 |

历史 CVE 样本、source binding 和 patch obligation 只能用于 benchmark 证据，不能直接作为新漏洞结论。

## 6. 复现命令

### Catalog

```bash
python3 - <<'PY'
from src.ohscanner.detectors.catalog import catalog_metadata
import json
print(json.dumps(catalog_metadata(), ensure_ascii=False, indent=2))
PY
```

### Source Binding

```bash
python3 -m scripts.verify_historical_source_bindings
```

### 完整测试

```bash
.venv-web/bin/python -m unittest discover -s tests -q
```

### Workbench 等价性验证

```bash
.venv-web/bin/python -m scripts.verify_workbench \
  --repo-dir /path/to/commonlibrary_c_utils \
  --repository openharmony/commonlibrary_c_utils \
  --commit b807d3dadb7dbb7639fe85b3a5f72da18d318da2 \
  --data-dir /tmp/ohscanner-workbench \
  --include .
```

## 7. 当前限制

- Detector 仍是窄范围结构/语法候选，不具备完整 CFG、跨 TU alias、guard dominance 或线程交错证明。
- host bootstrap 不等于 OpenHarmony 产品构建。
- Joern 全 scope 覆盖未完成。
- 新 CVE 样本不是独立 holdout。
- PoC、TSan 和漏洞报告由接口线/统一验证模块负责；A 线只提供 detector 和证据输入。
- Agent loop、产品级入口证明和 confirmed/reportable 升级仍需 Core/负责人复核。

## 8. 相关文档

- `docs/architecture_2026.md`：九层漏斗和 PoC/证据门槛。
- `docs/contracts/ohscanner_detector_contract_v2.md`：契约 v2。
- `docs/strategy/ohscanner_three_track_master_plan.md`：三线分工。
- `docs/strategy/competition_deliverables_plan.md`：赛题交付要求。
- `docs/testing/static_module_remaining_limits_2026-10-13.md`：本轮工具和实验记录。
- `docs/ohscanner_current_vulnerability_subtypes.md`：当前漏洞子类清单。
