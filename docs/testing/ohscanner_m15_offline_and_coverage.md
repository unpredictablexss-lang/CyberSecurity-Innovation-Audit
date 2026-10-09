# OHScanner M1.5：离线 Git + AST 细粒度调度 + 最小事实接口验收

> 实施位置：`feat/ohscanner-core` / Draft PR #5。
> **代码已提交，GitHub CI 的人工小仓库/partial-clone 回归通过；OpenHarmony 真组件上的新调度和 Ubuntu Git 2.34.x 兼容性仍待本地复测**。
> 这不是一次漏洞检测实验，不得报告检出率、真实漏洞数量或组件整体无漏洞。

## 为什么需要 M1.5

M1 在固定的 `commonlibrary_c_utils` 提交 `b807d3dadb7dbb7639fe85b3a5f72da18d318da2` 上完成了真实源码索引（前次交付 123 C/C++ 文件、93 complete、30 partial）。但：
- 旧 `run_all()` 对 AST 需求采用“全体文件完整，否则全部 blocked”，浪费可分析文件；
- 旧 `git_source._git()` 不显式封锁 Git 对 promisor/partial clone 缺失对象的按需获取；用 `file://` 本地 clone 曾实测触发隐式 `fetch`；
- 基础 AST 索引不提供 guard 支配、对象所有权、准确的调用目标，不能被误当成语义漏洞分析。

## 修复范围与设计边界

### P0：强离线 Git 读取

`src/ohscanner/git_source.py` 的每个子进程都设置：
- `GIT_NO_LAZY_FETCH=1`
- `GIT_ALLOW_PROTOCOL=""`，禁止 `ssh/http/https/file` 等 Git 传输
- `GIT_NO_REPLACE_OBJECTS=1`、`GIT_TERMINAL_PROMPT=0`、`GIT_OPTIONAL_LOCKS=0`
- 额外命令行配置 `-c remote.origin.promisor=false`，与旧历史 benchmark 方式兼容。

`git ls-tree -l` 在缺少本地 Blob 时，不同 Git 版本可能报告大小 `-` 或 `BAD`；两者都转换成 `missing_local_git_object`。缺少本地对象意味着**无法形成完整索引**，程序应失败并要求用户在**索引程序外**、获许可的环境中预先准备完整 Git 对象，不能偷偷把失败变成成功，也不能声称 0 漏洞。

离线限制只约束 OHScanner 索引器的 Git 子进程；用户自行执行的 `git clone/fetch` 是独立明确的资料准备动作。

### P1：允许局部可分析文件继续运行

`src/ohscanner/runner.py` 保留 `run_all(context, registry)` → `list[ToolRunResult]` 的旧接口，并新增：

```python
reports, coverage = run_all_with_coverage(context, registry)
```

当 `detector.required_facts` 包含 `ast`：

- 默认 `ast_scope="per_file"`：只把 `parse_status=complete` 的同语言文件交给 detector；`partial/failed/not_run` 不提供给本次 detector，并在 `coverage["detectors"][id]["unexamined"]` 记录文件与原因。
- 可选 `ast_scope="whole_scope"`：需要整个输入范围都满足完整 AST 的算法可选择**严格全量阻断**，而不是错误地启动。
- `ToolRunResult.scope_files` 只统计 detector 真正报告完整分析的文件；`parsing` 保留所有本次适用文件，并带 `analysis_status` 与 `analysis_reason`。有任一未覆盖文件，limitations 必须出现 `INCOMPLETE COVERAGE`。
- `ToolRunResult.status=completed` 只表示已分配的**合格子集**完成，不表示所有源码均覆盖，更不表示代码安全。组件级覆盖通过 `run_all_with_coverage` 的 sidecar 判断。

**目前粒度为文件级**；同一个 `partial` 文件里哪些函数仍可安全单独分析，还没有严格的错误区域与依赖范围验证，因此仍先视为未覆盖，暂不启用函数级调度。

### P2：最小语法事实与缺少证据

`src/ohscanner/facts.py` 的 `facts_v1` 由主线已有 AST 生成 `FunctionFact`、`CallFact`；只提供函数范围、调用表达式和实参文本。它明确使用 `type_resolution=not_computed`、`resolved_target=null`、`guards=[]`。**没有实现** CFG、Guard 支配、别名/所有权、污点传播或 IPC 身份检查。

`DetectorFinding.evidence_obligations` 可引用 `EvidenceObligation(kind, description, status="unknown")`，并在新的覆盖 sidecar 的 `evidence_obligations` 条目中输出，与 `ToolDiagnostic(schema v1)` 严格分离。例如候选缺少 `guard_dominance` 的检查，算法应记“待证实”，不能自动标记 CWE 已确认。

### P3：报告复现环境

`ohscan-index` 报告新增 `environment`：Python、Git、tree-sitter 及 C/C++ grammar 版本、`light-ast` profile 和明确的 `build_profile=none`、`macro_expansion=false`、`product_manifest_locked=false`。固定对象身份≠完整 GN 产品配置。

## Ubuntu 本地复测（本次请你执行）

在 **CyberSecurity-Innovation-Audit 项目根目录**：

```bash
git fetch origin
git switch feat/ohscanner-core
git pull --ff-only origin feat/ohscanner-core
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
git --version
python -m unittest discover -s tests -p 'test_ohscanner_m15.py' -v
python -m unittest discover -s tests -q
```

其中 `test_promisor_clone_never_fetches_missing_blob` 会在临时目录构建 `file://` 部分克隆，并检查 Git trace 未出现 `fetch origin` / `upload-pack`；不使用外网。**请特别在你的 Ubuntu 22.04 / Git 2.34.x 上保留这项测试的输出**，GitHub Actions 的 Git 版本可能比你本机新。

复查真实组件索引（如果你已有源码目录，不需要再次克隆）：

```bash
TARGET="$HOME/oh-audit-targets/commonlibrary_c_utils"
COMMIT=b807d3dadb7dbb7639fe85b3a5f72da18d318da2
git -C "$TARGET" cat-file -t "$COMMIT" # 应为 commit

python -m src.cli ohscan-index \
  --repo-dir "$TARGET" \
  --repository openharmony/commonlibrary_c_utils \
  --commit "$COMMIT" \
  --json-out outputs/reports/cutils_m15_index.json \
  --md-out outputs/reports/cutils_m15_index.md
```

命令会读取本地固定 Git 对象，不改源码，不调用外部成熟扫描器，也不执行真实 Detector。

### 检验“93 完整文件能跑、30 partial 记录未知”

在上述审计项目根目录继续运行**模拟接口调度检查（不会检测漏洞）**：

```bash
python - <<'PY'
from pathlib import Path
from src.ohscanner.indexing import prepare_git_context
from src.ohscanner.mocks import MockCppDetector
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

TARGET = Path.home() / "oh-audit-targets/commonlibrary_c_utils"
COMMIT = "b807d3dadb7dbb7639fe85b3a5f72da18d318da2"
context, _, inventory, parse_coverage, _ = prepare_git_context(
    TARGET, "openharmony/commonlibrary_c_utils", COMMIT
)

class EligibilityProbe(MockCppDetector):
    detector_id = "ohscanner.mock.ast_eligibility"
    required_facts = ("ast",)
    # No security logic: marker-only Mock used to prove scheduler behavior.

registry = DetectorRegistry()
registry.register(EligibilityProbe())
runs, sidecar = run_all_with_coverage(context, registry)
coverage = sidecar["detectors"][EligibilityProbe.detector_id]
print("parsed:", parse_coverage["parsing_status"])
print("execution status:", runs[0].status)
print("applicable:", coverage["applicable_files"])
print("analyzed:", len(coverage["analyzed_files"]))
print("unexamined:", len(coverage["unexamined"]))
print("sidecar status:", coverage["status"])
print("limits:", [s for s in runs[0].limitations if "INCOMPLETE COVERAGE" in s])
PY
```

以你先前同一 `c_utils` SHA 与同样文件范围为前提，预计可看到 `analyzed=93`、`unexamined=30`；**这是预期对照值，不是本次已复测得出的结论**。失败时请保留错误和版本，不要为凑数字换 commit。

## 项目验收（是否可以结束 M1.5）

- [x] 已有 M1.5 GitHub CI 临时完整 Git、partial clone 反例测试；
- [x] AST 93/30 synthetic 合约测试 + 全局严格模式测试；
- [x] evidence obligations sidecar 与旧 `ToolDiagnostic v1` 分离测试；
- [ ] Ubuntu Git 2.34.x 同类回归通过，确认为无按需 fetch；
- [ ] 真实固定 c_utils 的 `ohscan-index` + Probe 返回可比的 93/30 覆盖清单；
- [ ] M2 前评审是否将本 Draft PR 拆成更小 PR/冻结插件接口。

禁止把测试中的 Mock 命中视为漏洞；在真实自主 Detector 进入之前保持 Draft，不自动合并 main。
