# OHScanner M0 统一接口与 Mock 检测器验收记录
> **政策更新 2026-10-10**：本文为历史记录（记录某时点实际做了什么），事实性内容保留原样。文中"不做 PoC / 不做动态验证 / 不升级结论状态 / 不计算 Precision-Recall"等限制已于 2026-10-10 **废除**；当前生效政策见 `AGENTS.md` 的 **Competition deliverables — must produce** 章节：PoC、动态验证、CWE/CVE、影响范围、修复建议、性能数据、漏洞报告均为**必须产出**的交付物。

> 状态：`feat/ohscanner-core` 上的第一阶段实现。仅验证自主 Detector **插件接口与数据桥接**；不执行外部工具，不扫描真实 OpenHarmony 组件，不代表发现漏洞。

## 目标与实现范围

新增模块：
- `src/ohscanner/contracts.py`：SourceUnit、ScanRequest、ScanContext、Detector Protocol、DetectorRun 与 DetectorFinding；
- `src/ohscanner/fixture.py`：只读合成样例装载及 SHA-256 漂移核验，拒绝危险路径、符号链接和未知文件；
- `src/ohscanner/runner.py`：DetectorRegistry、模块隔离与 DetectorRun → **现有** ToolRunResult v1 / ToolDiagnostic 的映射；
- `src/ohscanner/mocks.py`：MockCppDetector、MockInterfaceDetector（寻找自建 marker，不判断漏洞）；
- `src/ohscanner/smoke.py`：M0 JSON/Markdown 合成报告；
- `src/cli/main.py`：新增 `ohscan` 命令，仅测试合成 fixture；
- `tests/test_ohscanner_contract.py`：合约、目标绑定、错误隔离、位置范围、漂移与回归测试。

演示命令（从仓库根目录运行）：

```bash
python -m src.cli ohscan \
  --fixture-root tests/fixtures/ohscanner \
  --json-out outputs/reports/ohscanner_m0.json \
  --md-out outputs/reports/ohscanner_m0.md

python -m unittest discover -s tests -v
```

## 安全与结论边界

- 此命令仅允许带测试目录的 M0 fixture，使用 `fixture/ohscanner-core` 与 `synthetic-fixture-v1` 身份，**不核实 OpenHarmony Git commit/tree 关联**，不能拿来做当前组件安全结论；
- Marker 即使在注释中也会被 Mock 检测到，因为它只是检查接口链路。不是候选真实漏洞；
- 输出的 `ToolRunResult.status` 为执行状态；支持范围为空或事实缺失则 `blocked`，并保留 `unknown/not_applicable` 的解释，不宣称无漏洞；
- Detector 异常独立隔离；没有实现硬超时、独立进程或内存沙箱，不能在 M0 上运行不受信任的第三方插件；
- SourceUnit 的解析状态为 `not_run`，没有 AST/CFG/数据流事实；下阶段由正式 Frontend + 固定 Git 快照模块提供；
- `validated_vulnerability=0` 是此报告的固定陈述，不是被检目标的安全度量；
- `src/providers` 的外部扫描器格式归一化和已有 benchmark 不改动。

## 对两位队友的影响

当前 Contract 已有最小 Python 定义，但设计文档里的更高级 `shared_facts`、硬超时、资源配额、真实 Git 快照核验与安全对照实验仍需要分阶段完善。

队友可以参照 MockCppDetector / MockInterfaceDetector 的 `detect(context, units) -> DetectorRun` 与 `src/ohscanner/contracts.py` 开发，但**在第一轮 CI/评审完成前不要把 v1 当作不可更改的最终冻结版本**。提出公共 IR 需求时先与主线负责人协调。

## 验收记录

此文件先随首轮开发提交；**测试结果以该 PR 最新 GitHub Actions 记录为准**，不能使用历史 PR #4 的成功结果代替新代码测试。
