# OHScanner 队友开发接入指南（M0/M1 实际代码版）

> **阅读对象**：队友 A（C/C++ 内存安全检测）与队友 B（OpenHarmony Web/ArkTS/IPC/权限与接口安全检测）。
>
> **版本状态**：2026-10-09，当前基底为 `feat/ohscanner-core`（Draft PR #5），不是尚未合并此 PR 的 `main`。以下以**实际 Python 代码**为准；`docs/contracts/ohscanner_detector_contract_v1.md` 包含后续规划，未必全部实现。
>
> **核心原则**：外部扫描器只用于**离线实验和技术对照**。队友交付的是**自主检测算法模块**，不是“遇到漏洞类型就运行 Semgrep / CodeQL / Joern”的调度器。静态命中是候选证据，不是已确认漏洞。

## 一、第一眼先看什么（按顺序）

1. `docs/strategy/ohscanner_three_track_master_plan.md`：项目的三线分工、工程目标和验收标准。
2. **本文件**：今天可以实际编写、运行的函数与目录；特别注意“已实现 / 未实现”。
3. `src/ohscanner/contracts.py`：真实的 `SourceUnit`、`ScanContext`、`DetectorFinding`、`DetectorRun`、`Detector`（Protocol）定义。
4. `src/ohscanner/mocks.py`：两个真实可执行的 **Mock 接口实现**（只识别合成标记，不检测漏洞）。
5. `src/ohscanner/runner.py`：`DetectorRegistry.register()` / `run_all()` 的校验与 `ToolRunResult` 桥接。
6. `src/ohscanner/frontend.py` + `src/ohscanner/indexing.py`：M1 当前语法索引与固定 Git 来源；`src/parser/ast.py` 为旧主线已经有的 C/C++ AST 解析器。
7. 各自方向：A 阅读 `docs/strategy/vulnerability_corpus_bakeoff_protocol.md`；B 阅读 `docs/strategy/oh_web_interface_track.md`。

### 实际实现边界

| 能力 | 现状 | 队友应如何使用 |
|---|---|---|
| `Detector.detect(context, units) -> DetectorRun` | M0 已实现的 Protocol | 按签名编写、返回 DetectorRun |
| `DetectorRegistry` / `run_all` | M0 已实现 | 可在测试代码中手工注册；**无自动发现插件机制** |
| `ToolRunResult`（自研 detector 产物为 `schema_version=2`） | 已有 | Runner 转换，队友不应自行修改公共 schema；**契约 v2 已把 source 绑定改为产出物必填**，见 `docs/contracts/ohscanner_detector_contract_v2.md`（v1 payload 仍可加载，标 `unbound`） |
| 完整 Git commit + blob 来源 | M1 已实现 | `prepare_git_context()` 从本地 Git 对象构造上下文 |
| `shared_facts["ast"]` | M1 C/C++ 已实现轻量索引 | 每个路径有 parse_status/functions/calls/variables；**非完整 AST 节点/CFG/类型/路径分析** |
| JS/TS/ETS / ArkTS 解析 | 仅识别源文件，`parse_status=not_run` | B 不得宣称已有 JS/ArkTS AST；需要时申请 Frontend 扩展 |
| 命令行 `ohscan-index` | M1 已实现 | **只做源码索引，没有运行 detector** |
| 命令行 `ohscan` | M0 已实现 | **只运行两个合成 Mock**，不是通用真实扫描入口 |
| 统一运行真实 detector 的生产 CLI | 尚未实现 | 由负责人在 M2 做，队友先编写模块+契约测试 |
| 硬超时/独立进程隔离、正式权限模型 | 尚未实现 | 不运行不受信任插件；异常捕获不等于沙箱 |

## 二、怎么取得正确的代码

在项目仓库目录：

```bash
git fetch origin
git switch -c local/my-detector-work origin/feat/ohscanner-core
# 如果本地已有该工作分支，改用 git switch local/my-detector-work

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -q
```

**注意**：不要用当前 `main`、旧 `codex/cutils-component-pilot` 当作接口实现基线。已有独立工作分支可以在本地合并或 rebase 最新核心分支，但不要强行覆盖本地未提交修改。此处建议本地开发分支，是否推送 GitHub、开 PR 和合并由负责人确认。

## 三、模块代码放哪里

目标目录（**拟建**，无需先创建整棵树）：

```text
src/ohscanner/
  contracts.py              # [负责人] 已有公共协议
  runner.py                 # [负责人] 已有注册器/桥接
  git_source.py             # [负责人] 已有固定 Git 来源
  frontend.py               # [负责人] C/C++ 轻量 AST
  indexing.py               # [负责人] 当前源码索引
  mocks.py                  # [负责人] 可运行样例
  detectors/
    cpp/                    # [队友 A] 自研 C/C++ Detector
    interface/              # [队友 B] 自研 Web/ArkTS/IPC Detector
  models/
    openharmony_cpp/        # [A+负责人审批] OpenHarmony C++ API/所有权模型
    openharmony_web/        # [B+负责人审批] JS-Bridge/IPC/权限模型
research/
  corpus/                   # 历史漏洞公告及固定修复对元数据（尽量分子目录）
  experiments/cpp/          # [A] 外部工具离线实验（不进入正式运行时）
  experiments/interface/    # [B] 外部工具离线实验（不进入正式运行时）
  methods/                  # 分方向 MethodCard 与消融实验
tests/
  detectors/cpp/            # [A] 正例、修复后、安全对照、失败用例
  detectors/interface/      # [B] 对应测试
```

已有 `src/providers/*` 是外部工具**结果适配器**，不是待继承的自研 Detector；`src/benchmark/*` 继续作为离线对照评估工具。队友不要复制另一份 CLI、Runner、全局 Finding/Evidence/ToolRunResult。

## 四、必须遵守的真实 Python 函数签名

核心接口位于 `src/ohscanner/contracts.py`：

```python
class Detector(Protocol):
    detector_id: str
    version: str
    supported_languages: Tuple[str, ...]
    required_facts: Tuple[str, ...]

    def detect(
        self, context: ScanContext, units: Tuple[SourceUnit, ...]
    ) -> DetectorRun:
        ...
```

本版 `SourceUnit` 仅有：`path, language, text, sha256, parse_status, parse_issues`；语言当前支持 `c/cpp/js/ts/arkts`，解析状态为 `complete/partial/failed/not_run`。

`ScanContext` 当前仅有 `request, units, shared_facts`。`ScanRequest` 当前有 `request_id, repository, commit, snapshot_sha256, target_id, profile_id, provenance`。不要使用规划稿里的 `context.budget`、`unit.cfg`、`unit.type_info`、`context.cancel_token` 等尚不存在的字段。

`DetectorFinding` 当前字段：`file, line, rule_id, message, evidence_type='pattern', column=None, candidate_cwe=None, symbol=None`。

`DetectorRun` 当前字段：`detector_id, version, status, analyzed_files, findings, limitations`；status 只能是 `completed / failed / blocked`。

`evidence_type` 最终会在 `ToolDiagnostic` 验证，只能使用当前 `src/benchmark/tool_result.py` 支持的枚举，例如 `pattern/syntax/dataflow/control_flow/symbolic/permission/unknown` 等。没有真实数据流或控制流证明不要自报 `dataflow`、`control_flow`；Severity/Confidence 由 Bridge 暂定 `unassessed`。

**范围契约非常严格：** 当返回 `completed` 时，`analyzed_files` 必须包含 Runner 选给该 Detector 的**全部**对应语言文件；部分分析不能假称 completed，应 `blocked/failed` 并保留原因。目前 Runner 对没有声明 AST 依赖的 Detector 不自动阻拦未解析源文件，队友必须自行降级或说明结果边界；要求完整 AST 的 Detector 写 `required_facts=("ast",)`，当前 Runner 遇到不完整解析会整体 blocked。

## 五、最小可运行的“队友 Detector”模板

> 以下是**接口教学示例**，只能识别合成测试标记；**不是漏洞检测算法**。A 将 `supported_languages` 设为 `("c","cpp")`，B 可先设 `("js","ts","arkts")`。正式算法不应靠字符串出现次数来判真实漏洞。

```python
from typing import Tuple
from src.ohscanner.contracts import (
    DetectorFinding, DetectorRun, ScanContext, SourceUnit
)

class ExampleNativeDetector:
    detector_id = "ohscanner.cpp.example"
    version = "0.1.0"
    supported_languages = ("c", "cpp")
    required_facts = ()

    def detect(
        self, context: ScanContext, units: Tuple[SourceUnit, ...]
    ) -> DetectorRun:
        findings = []
        for unit in units:
            # 自研算法替换这里；这是合成 marker 示例。
            for n, line in enumerate(unit.text.splitlines(), start=1):
                if "OH_TEAM_EXAMPLE_MARKER" in line:
                    findings.append(DetectorFinding(
                        file=unit.path,
                        line=n,
                        rule_id="example.synthetic.marker",
                        message="Synthetic example, not a vulnerability",
                        evidence_type="pattern",
                    ))
        return DetectorRun(
            detector_id=self.detector_id,
            version=self.version,
            status="completed",
            analyzed_files=tuple(unit.path for unit in units),
            findings=tuple(findings),
            limitations=("Only a synthetic API contract example.",),
        )
```

### 不修改平台就能手工注册、运行

以下代码在项目根目录执行。它加载**真正已经有的** M0 fixture 和 Runner；`ExampleNativeDetector` 需放到上面你创建的 Python 模块中并调整 import。为了直接复制运行，可先使用仓库现成的 `MockCppDetector`：

```bash
python - <<'PY'
from pathlib import Path
from src.ohscanner.fixture import load_fixture
from src.ohscanner.runner import DetectorRegistry, run_all
from src.ohscanner.mocks import MockCppDetector, MockInterfaceDetector

context = load_fixture(Path("tests/fixtures/ohscanner"))
registry = DetectorRegistry()
registry.register(MockCppDetector())
registry.register(MockInterfaceDetector())

results = run_all(context, registry)
for result in results:
    print(result.tool, result.status, result.diagnostic_count, result.scope_files)
    assert result.schema_version == 2  # contract v2; v1 payloads still load
    assert all(d.source_binding == "bound" for d in result.diagnostics)
    assert all(d.confidence == "unassessed" for d in result.diagnostics)
PY
```

这里仅示范接入流程。后续队友的 `Detector` 只要通过 `registry.register(YourDetector())` 注册，便可复用当前 `run_all()` 和已有 `ToolRunResult`。

## 六、怎么使用 M1 的真实 Git 源码和 AST

本地已经克隆且拥有目标 SHA 的 Git 仓库时：

```python
from pathlib import Path
from src.ohscanner.indexing import prepare_git_context
from src.ohscanner.runner import DetectorRegistry, run_all

context, tree, inventory, coverage, sources = prepare_git_context(
    repo_dir=Path("/path/to/local/commonlibrary_c_utils"),
    repository="openharmony/commonlibrary_c_utils",
    commit="<替换为本地确实存在的完整 Git commit SHA>",
    includes=(".",),
)
print(context.request.provenance)  # git_object
print(coverage)                    # languages / parsing_status
print(context.shared_facts["ast"]) # C/C++ 轻量索引字典
```

`shared_facts["ast"]` 的真实结构是：

```python
{
    "repo/relative/source.cpp": {
        "parse_status": "complete",      # 也可能 partial / failed
        "functions": [ ... ],            # FunctionDef.__dict__
        "calls": [ ... ],                # CallSite.__dict__
        "variables": [ ... ],            # VariableDecl.__dict__
    }
}
```

**这不是完整 CFG/SSA/符号执行，也不会宏展开或自动找到 IPC caller 关系。** 对 B 的 JS/ArkTS 文件，目前 `parse_status=not_run`，没有该语言 AST 字典；不要将文本索引当成语义覆盖。

如要先看看现有 M1 的完整命令行：

```bash
python -m src.cli ohscan-index \
  --repo-dir /path/to/local/git-repository \
  --repository openharmony/commonlibrary_c_utils \
  --commit <完整Git提交SHA> \
  --json-out outputs/reports/index.json \
  --md-out outputs/reports/index.md
```

这个命令**不运行 Detector**。队友开发时可用 `prepare_git_context()+run_all()` 做自研模块的本地手工集成测试，但在负责人完成生产执行入口、超时隔离和来源附加校验前，不应把这样的试跑作为正式全量漏洞审计结论。

## 七、两位队友具体该做哪些实验、怎么交付？

### 队友 A：C/C++ 安全检测

先从经过核实的历史漏洞修复对入手，选择一类清晰根因（如空指针 guard 或生命周期风险），通过 Semgrep/Cppcheck/Clang/CodeQL/Joern **离线**比较根因区域命中、修复前/后消失情况、安全相似代码误报、编译解析覆盖与成本。

输出 MethodCard：工具哪里做得好、哪里漏报/误报、准备自主实现的语法/数据流/guard/所有权算法、OpenHarmony API 专用约束。第一版只开发**一个**可执行 Detector，再逐步做 Guard 或有限路径增强；不能把 `.reset()` 直接定为 UAF。

### 队友 B：Web / ArkTS / IPC

先确认 OpenHarmony **真实存在的**接口源、JS Bridge / IPC 方法、授权边界和敏感调用。明确调用者身份/权限/入口/guard/sink 的证据。若缺公开高质量漏洞修复对，可用标记为 synthetic 的正负 fixture 开发原型，但不能说检测到了历史真实漏洞。

B 不需要单独造一个平台；需要 JS/ArkTS 解析器、跨语言链接等时按本文件“接口变更申请”提出需求，由负责人决定如何纳入统一 Frontend。可以先对 C++ IPC 方法做检测，或对 JS/ArkTS 源码做**明确标注的语法/文本候选原型**；没有 AST 不得宣称控制流/数据流分析已经完成。

### 共同实验和测试标准

每个 Detector 最少包含：开发集正例、修复后源码、相似安全负例、语法 partial/未解析情形、无对应语言情形、异常或不完整范围情形。样本要有固定 repo/commit/hash；synthetic 要显式标注，不能充当真实公开漏洞。保留测试集不得用于调参。

工具失败/未覆盖记 unknown；`possible_hit` 是源码命中，不是确认漏洞；没有真实且可信完整标签时不报精确 Recall/Precision。

## 八、接入主线的测试合同

队友本地跑：

```bash
python -m unittest discover -s tests -q

# 核对 M0 接口与 M1 Git 固定提交数据是否正常
python -m unittest tests.test_ohscanner_contract tests.test_ohscanner_m1 -v
```

编写自身 `tests/test_xxx_detector.py` 或对应目录测试时必须验证：

- 实例的 `detector_id` 以 `ohscanner.` 开头并唯一、version 为非空；
- `supported_languages`、`required_facts` 为 tuple；
- `DetectorRun.detector_id/version` 与注册器一致，`analyzed_files` 是 Runner 提供文件的真实子集；`completed` 不能跳过已选择的文件；
- 每条 `DetectorFinding.file/line` 对应源码范围、rule_id 非空、evidence_type 为真正存在的证据；
- Guard 保护下的安全负例不能与风险路径不加区分地命中；
- 解析失败、缺 AST、缺对应语言等情况不得解释为安全；
- 完整原始工具实验与自研插件的运行依赖隔离，不得在 `detect()` 中执行第三方大扫描器。

**M0/M1 的 CI 通过不是 A/B 新 detector 的质量保证。** 每个新检测器要有它自己的真实正/负对照、假设、覆盖边界、错误/异常、许可审查与独立测试。

## 九、接口不够怎么办？

发现需要 `ctx.cfg`、`unit.types`、JS/ArkTS AST、跨语言调用边、`budget` 时，**不要自己修改公共 `contracts.py` 或另造一套共享 IR**。

向负责人提交一份小的 Contract Change Request：

```text
标题：需要的公共事实/字段
使用人：A 或 B；Detector ID：
真实源码/测试样例与必要性：
现有 SourceUnit/shared_facts 为什么不能表达：
建议类型、字段及缺失时的状态：
能否作为 shared_facts 中可选数据先试验：
正例、负例、partial/缺失事实测试：
对另一队友的兼容影响：
```

负责人决定修改 v1、旁路 Sidecar 还是留到 v2，并增加契约回归测试。不要两个分支对同一公共文件分别作不可兼容修改。

## 十、每次交付给负责人的清单

```text
[ ] 自研 Detector 类及唯一 detector_id/version
[ ] 使用已有 ScanContext/SourceUnit/DetectorRun 的代码；不新建 CLI/Runner
[ ] 运行所需 shared_facts、语言及解析状态要求
[ ] 正例/修复后/安全对照/partial 或 unknown 回归测试
[ ] 方法卡：历史样本、对照工具和规则版本、选择依据、自研改进
[ ] 来源证据：公开公告、repo+commit、文件 hash、原始实验报告 hash
[ ] 诚实的覆盖范围、耗时和漏报/误报/未覆盖分析
[ ] 第三方代码/规则/数据许可与出处
[ ] 复现命令、单测结果、主线所需扩展请求
[ ] 本地分支 commit/patch（是否远端 push/PR 由负责人决定）
```

首个里程碑不要以“找到几条漏洞”验收，而要以“单个真正自主实现的 Detector 在统一 Runner 下可运行；有正负对照、覆盖证明、方法卡；无需改主线接口”验收。

## 十一、常见误区与工程边界

1. `src/providers` ≠ 自研 Detector；离线工具实验不能搬成线上自动调用。
2. `ohscan-index` ≠ 真实扫描命令；`ohscan` 当前仍只跑 Mock 标记。
3. C/C++ AST 索引 ≠ 完整语义、编译/宏、CFG 或跨函数数据流。
4. 文件语言被识别 ≠ JS/ArkTS 被解析；文件成功读取 ≠ 安全覆盖。
5. `completed` 仅表示该 Detector 声明的执行范围完整，不是代码安全；`blocked` 与 `failed` 不等于 `miss`。
6. `possible_hit` ≠ confirmed vulnerability。所有输出应保留 `candidate/unassessed` 和可核验源码依据。
7. 不要无许可复制第三方工具完整实现或忽略比赛原创性要求。
8. 当前 Python Runner 只有异常隔离，没有硬超时/进程沙箱：只能运行审核过的可信代码。

**最终接入目标**：负责人在 M2 提供正式 `ohscan` 自研运行入口/注册表、Git 来源映射和报告，A/B 的自主 `detect()` 不经大规模迁移即可注册并运行；在它实现之前，以 `Mock + 手工注册 + 单元测试` 为准确落地方法。
