# OHScanner 技术文档索引

> 更新日期：2026-10-13

## 核心架构与约束

- `docs/architecture_2026.md`：L0-L8 漏斗式漏洞挖掘架构。
- `docs/contracts/ohscanner_detector_contract_v2.md`：SourceUnit、ScanContext、DetectorRun、source binding。
- `docs/contracts/ohscanner_detector_contract_v1.md`：历史契约和兼容说明。
- `AGENTS.md`：项目职责、证据门槛、比赛交付边界。

## Teammate A 静态扫描

- `docs/teammate_a_static_scan_tech_guide.md`：A 线职责、数据流、模式、复现命令。
- `docs/ohscanner_current_vulnerability_subtypes.md`：当前可识别候选子类。
- `docs/testing/static_module_remaining_limits_2026-10-13.md`：工具实验、CVE binding、Workbench 验证和限制。
- `src/ohscanner/detectors/cpp/README.md`：C++ detector 实现和边界。

## Benchmark 与实验

- `docs/strategy/vulnerability_corpus_bakeoff_protocol.md`：历史样本、工具对照、MethodCard 和 holdout。
- `docs/strategy/team_parallel_multi_scanner_plan.md`：多工具 benchmark 与 Adapter 边界。
- `docs/testing/historical_benchmark_verification.md`：historical benchmark 复核命令。
- `benchmarks/historical/source_bindings/`：CVE exact source bindings。

## 产品与比赛交付

- `docs/strategy/competition_deliverables_plan.md`：PoC、动态验证、CVE/CWE、影响、修复、性能和报告。
- `docs/competition_requirements.md`：赛题能力拆解。
- `docs/evaluation_criteria.md`：评分维度。
- `docs/testing/ohscanner_owner_ipc_platform_integration.md`：平台和 IPC 集成记录。
- `docs/workbench/README.md`：本地 Web/Worker/SQLite 工作台。
