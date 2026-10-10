# M2-A：队友 A 两个 C++ 检测器的第一方接入（2026-10-11）

> 范围：只完成 M2 平台登记、固定 Git 输入、文件级覆盖、候选证据义务和回归。**不将候选升级为漏洞、不给出独立准确率或产品 PoC 结论。**
>
> 算法源码来源：A 分支 `codex/teammate-a-fragment-consolidation-20261010` @ `40c2c66e181836d4f38b8c25978ce225f0eadd49`。迁移的是该提交的**原始不改动**的 `lifetime_detector.py` 和 `shared_ptr_race_detector.py`，其 SHA 可通过 `git rev-parse` / `git hash-object` 对照。原算法的继续开发仍由队友 A 负责；没有将 A 的 component/product 工具整条分支合入 Core。

## 当前已实现

- 显式 Catalog 两个 `kind=research_candidate` 的第一方插件：`ohscanner.cpp.lifetime`（`unique_ptr/get/reset` 的窄词法形状）；`ohscanner.cpp.shared_ptr_race`（共享 `shared_ptr` 的非原子成员访问、CWE-362 候选）。两者不需要 `--allow-example-detectors`，但仍**只输出未验证语法候选**。
- `src/ohscanner/detectors/cpp/m2_adapter.py`：适配器要求 M1 共享 AST **作为完整解析资格条件**，每次将一个可分析 C++ 文件交给队友 A 的原 Detector，保持原始检测逻辑与版本不变。没有重新开发 CFG、类型、锁或生命周期证明。
- 对于 detector 内部无法完全建模的文件，返回 `file_outcomes`，将已完整分析文件、部分检查文件和未分析文件准确分列。ToolRunResult v1 的 `blocked` 仍保持历史 `scope_files=0` 语义；**不要用它估算局部执行量**，改读 `detector_coverage.analyzed_files/partially_inspected_files/unexamined`。局部候选即使整次 blocked 也保留待证据。
- 候选均通过 `EvidenceObligation` sidecar 记录尚未验证的所有权、控制流/并发路径、产品构建上下文和攻击者控制/实际影响。`CWE-362` 是 shared_ptr 的初步根因候选；`CWE-416` 对该规则只能视为潜在后果。
- sidecar 中新增 `source_sha256` 映射和每条有义务候选的 `file/source_sha256/analysis_status`。旧 `ToolDiagnostic v1` 格式保持不变。
- 拷贝 A 的原始合成正/修复/安全/unknown 样例以及测试，保留其 `synthetic development` 属性；**没有复制实验数据作为独立 holdout**。

## Ubuntu / WSL2 运行步骤

在 OHScanner 仓库根目录（需先更新到包含本次代码的核心分支）：

```bash
git fetch origin
git switch feat/ohscanner-core
git pull --ff-only origin feat/ohscanner-core
source .venv/bin/activate

python -m unittest discover -s tests -p 'test_ohscanner_m2_a_integration.py' -v
python -m unittest discover -s tests -q

TARGET="$HOME/oh-audit-targets/commonlibrary_c_utils"
COMMIT=b807d3dadb7dbb7639fe85b3a5f72da18d318da2
python -m src.cli ohscan-run \
  --repo-dir "$TARGET" \
  --repository openharmony/commonlibrary_c_utils \
  --commit "$COMMIT" \
  --detector ohscanner.cpp.lifetime \
  --detector ohscanner.cpp.shared_ptr_race \
  --json-out outputs/reports/cutils_m2_a_candidates.json \
  --md-out outputs/reports/cutils_m2_a_candidates.md
```

这条命令扫描的是**当前指定固定版本、独立于历史漏洞修复前后实验**。历史 `DelayedSingleton` 开发集出现的候选数不应外推到该当前版本，实际候选数量以本机输出为准，不要声称已新发现漏洞。

## 阶段验收与尚缺内容

1. CI 原始算法单元测试、M0/M1/M1.5/M2 旧测试、新的固定 Git 端到端测试必须同时通过。
2. 本地真实 `c_utils` 输出能说明哪些文件完整/部分/未覆盖，并保留全部候选的 CWE 初步类别、来源和未满足的证据。
3. **仍未完成**：独立历史保留集、真实产品 GN/Ninja 构建、C++ 漏洞通用语义解析、自动 PoC、ASan/TSan 与每条候选的联动、影响版本判断、补丁建议和完整比赛报告。它们不是这个 scoped M2 插件集成可宣称的能力。
4. 独立 holdout 未执行前，不得宣称 Precision/Recall、零误报或零漏报。历史 TSan harness 是独立研究证据，不是此次候选检测自动运行的 PoC。
5. **代码授权**：只在开发分支与 Draft PR，未经用户授权不合并 main。A 自研方法卡与历史实验留在 A 分支，本 PR 只登记经过审查的算法模块和确定性测试。
