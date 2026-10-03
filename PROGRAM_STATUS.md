# PROGRAM_STATUS.md

> - 项目：CyberSecurity-Innovation-Audit
> - 赛题方向：2026 OpenHarmony 开源代码漏洞挖掘
> - 更新日期：2026-10-04
> - 当前分支：`feat/openharmony-target-onboarding`
> - 已合并 PR：#2（MVP scanner 与目标筛选模板），merge commit `bef61d0caeed7c58b3887abc8b8cbfc33a1b4755`。
> - 当前阶段：真实组件筛选与 cJSON 首条工程闭环；构建、测试和扫描的证据见目标配置与筛选记录。
> 本文用途：给 ChatGPT、Codex、队友和未来自己看的统一进度说明。继续开发前先读本文，避免重复搭环境、误把计划当成已实现功能，或跳过验证步骤。

---

## 0. 当前一句话状态

**MVP scanner 已合并到 main；scan scope、轻量函数上下文与 Clang Static Analyzer baseline runner 已在 Ubuntu 22.04 WSL2 验证。完整回归 18/18 通过。固定提交 cJSON 核心两文件的文本扫描为 2 文件、4,681 行、26 条候选；默认 `clang --analyze` 对两文件均退出 0，解析诊断 0、failed files 0，精确行重合 0。零诊断不证明安全，26 条候选也不是漏洞。原组件运行时验证、完整编译参数对照和大规模性能基准仍未做。**

---

## 1. 已完成的环境与基础设施

### 1.1 开发环境

已完成：

- 安装 Ubuntu 22.04 WSL2。
- 创建普通用户：`audit`。
- 主工作目录：`/home/audit/openharmony-audit`。
- 项目目录：`/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit`。
- 项目文件位于 WSL Linux 文件系统内，不放在 `/mnt/c`，避免性能问题。

曾检查过但未作为主环境：

- Kali WSL2：可用，但不适合作 OpenHarmony 主开发环境。
- Ubuntu 22.04 云服务器：系统合适，但只有约 2 vCPU、2 GB RAM、40 GB 磁盘且无 swap，不适合作编译、静态分析和 fuzz 主机。

### 1.2 工具链

已验证的基础工具：

- Git 2.34.1
- GCC / G++ 11.4.0
- Clang / Clang++ 14.0.0
- CMake 3.22.1
- Ninja 1.10.1
- Python 3.10.12
- pip 22.0.2

Python 虚拟环境：

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
source .venv/bin/activate
```

### 1.3 AddressSanitizer

ASan 已用故意越界测试验证成功，能够输出：

```text
ERROR: AddressSanitizer: heap-buffer-overflow
SUMMARY: AddressSanitizer: heap-buffer-overflow
```

后续可将 ASan 作为内存安全候选的运行时验证证据来源。

### 1.4 GitHub 与分支

已完成：

- GitHub SSH key 配置成功。
- 私有仓库已 clone 到本地。
- PR #2 已合并到 `main`，merge commit 为 `bef61d0caeed7c58b3887abc8b8cbfc33a1b4755`。
- 当前功能分支：`feat/openharmony-target-onboarding`。

基本开发流程：

```text
main（包含已合并的 MVP scanner）
  ↓ 新建功能分支
feat/openharmony-target-onboarding
  ↓ 固定真实组件提交、保存构建与扫描证据
提交并通过 PR 审核
```

---

## 2. 当前 MVP 已实现内容

### 2.1 代码结构

当前核心文件：

```text
src/
├── baseline/
│   ├── __init__.py
│   └── clang_analyzer.py
├── cli/
│   ├── __init__.py
│   ├── __main__.py
│   └── main.py
└── core/
    ├── __init__.py
    ├── context.py
    ├── finding.py
    ├── scanner.py
    └── report.py

samples/
├── vulnerable/demo_overflow.cpp
└── safe/demo_safe_copy.cpp

tests/
├── test_context.py
└── test_scanner.py
```

### 2.2 Finding 数据结构

`src/core/finding.py` 当前保存：

- rule_id
- title
- vulnerability_type
- cwe
- severity
- confidence
- file_path
- line
- function
- function_start_line / function_end_line
- context_start_line / context_end_line
- context_status / context
- evidence
- explanation
- remediation
- status

当前默认：

```text
status = candidate
confidence = unassessed
severity = unassessed
```

不要把 `candidate` 当作“漏洞已确认”；也不要把 provisional CWE 当作最终 CWE。

### 2.3 Scanner 当前能力

`src/core/scanner.py` 当前支持：

- 递归遍历目标目录；
- 识别 `.c`、`.cc`、`.cpp`、`.cxx`、`.h`、`.hpp`、`.hh`；
- 以文本模式查找首批危险调用：`strcpy`、`strcat`、`sprintf`、`gets`、`memcpy`；
- 生成结构化 Finding；
- 记录 scanned_files、scanned_lines、skipped_files、finding_count；
- 跳过 `.git`、`.venv`、`__pycache__`、`.cache` 等目录。
- 支持显式 `--include` / `--exclude` 相对路径范围，并在报告中记录 scope；本地验证见第 11 节。
- 为文本候选附加轻量 top-level 函数与局部上下文；固定 cJSON 核心范围的实测见第 12 节。它不是 AST、CFG 或数据流分析。

重要边界：

```text
危险函数出现 != 已确认漏洞
```

当前尚未分析：

- 参数是否可控；
- 目标缓冲区容量；
- 上游 guard；
- 调用路径可达性；
- 安全影响；
- PoC 是否能触发。

### 2.4 CLI 当前命令

已验证命令：

```bash
python -m src.cli scan samples \
  --json-out outputs/reports/samples_report.json \
  --md-out outputs/reports/samples_report.md
```

实际输出过：

```text
[OK] scanned files: 2
[OK] scanned lines: 28
[OK] skipped source files: 0
[OK] candidate findings: 1
```

`--out` 仍作为 `--json-out` 的兼容别名。

2026-10-04 已验证无参数旧用法及 include/exclude 样例；重叠 include 去重由回归测试覆盖。核心范围命令与结果见第 11 节。

### 2.5 报告输出

已支持：

- JSON 报告；
- Markdown 报告；
- Markdown 明确提示“Text-pattern candidates only. No finding has been validated as a vulnerability.”
- JSON 与 Markdown 均记录 include/exclude scope；核心范围报告的实际字段见第 11 节。

本地生成报告位于 `outputs/reports/`，该目录下的 `.json` 和 `.md` 已被 `.gitignore` 忽略，不应提交。

### 2.6 回归测试

当前 `tests/test_scanner.py` 有 9 个扫描/范围回归测试，`tests/test_context.py` 有 5 个函数上下文测试，`tests/test_clang_baseline.py` 有 4 个 baseline runner 测试；2026-10-04 在 WSL 实跑 18/18 通过。原 4 个扫描测试覆盖以下基础行为：

1. vulnerable / safe 样例区分；
2. 函数名边界与空格调用形式；
3. CLI 写出 JSON 和 Markdown；
4. CLI 对不存在 target 报错。

本轮实际结果为 `Ran 18 tests ... OK`，失败 0；此前 9/9 和 14/14 的阶段结果分别保留在第 11～12 节。运行命令：

```bash
python -m unittest discover -s tests -v
```

---

## 3. 明确没有完成的能力

以下能力**尚未实现**，不要让 Codex 或后续文档误写成已完成：

- 尚未对真实 OpenHarmony 组件完成全套构建、测试与运行时漏洞验证；
- 尚未对 cJSON 核心候选完成原组件运行时验证或漏洞确认；本轮只验证了扫描范围与文本候选的可复现性；
- 尚未接入 AST；已验证的 function context 只是轻量 top-level 语法启发式，不能称为 AST；
- 尚未实现 CFG；
- 尚未实现数据流或污点分析；
- 尚未自动构造 PoC；
- 尚未把 ASan Runner 接入工具；
- 尚未实现 fuzz；
- 尚未实现 CWE 深度根因判断；
- 尚未实现 CVE 关联；
- 尚未实现版本/分支影响分析；
- 尚未实现 Patch 自动验证；
- 尚未实现 LLM 二次研判；
- 尚未实现完整比赛漏洞报告；
- 尚未使用完整 OpenHarmony 编译参数做 Clang 分析，也未完成其他工具对照或真实漏洞确认；已完成的默认参数基线见第 13 节；
- 尚未进行真实准确率、召回率和性能 Benchmark。

当前状态只是：

```text
环境与 GitHub 打通
→ MVP scanner 合并到 main
→ 固定 3 个真实组件提交并完成第一轮筛选
→ cJSON 局部构建、单测、全仓扫描及 10 条初筛
→ scope 功能 9/9 测试通过，cJSON 核心两文件 26 条候选逐项复现
→ function context 完整回归 14/14 通过，固定 cJSON 26 条获启发式函数名
→ Clang baseline 完整回归 18/18 通过，两文件分析退出 0、诊断 0
→ 待做原编译参数对照、人工边界复核和原组件运行时验证
```

---

## 4. 本轮已完成的 Step 1～7

本轮已完成：

1. 确认开发环境、分支、工作区；
2. Finding 增加独立 `status` 字段；
3. Scanner 增加扫描统计；
4. 增加 Markdown 报告生成器；
5. CLI 支持 JSON + Markdown；
6. 增加 safe 对照样例；
7. 完整运行 MVP 回归测试。

这一阶段已经可以冻结为 MVP scanner 阶段。后续不应继续在自建样例上无限扩规则。

---

## 5. 下一阶段目标：真实 OpenHarmony 组件 onboarding

### 5.1 为什么要切换阶段

当前自建样例只证明工程骨架能跑，不能证明工具适合 OpenHarmony。

下一阶段要回答：

- 当前 scanner 在真实 OpenHarmony C/C++ 组件上能不能稳定跑？
- 候选数量是否可控？
- 命中的候选是否主要来自注释、宏、第三方代码或安全封装？
- 能否拿到真实构建命令？
- 能否把一个候选放回原组件中运行验证？

### 5.2 已新增/应使用的文档与配置

本阶段新增/使用：

```text
docs/targets/target_selection.md
config/targets/README.md
config/targets/template.yaml
```

用途：

- `docs/targets/target_selection.md`：记录 3 个候选组件的筛选过程；
- `config/targets/template.yaml`：TargetSnapshot v0 模板；
- `config/targets/<component>.yaml`：未来某个真实主目标的固定配置。

真实 OpenHarmony 源码不要放进本项目仓库。建议放在：

```text
/home/audit/openharmony-targets/<component>/
```

本仓库只保存 URL、commit、构建命令、扫描范围和轻量配置。

---

## 6. 真实组件 onboarding：Step 8～15

## Step 8：最终回归并合并 MVP PR（已完成）

2026-10-03 已运行 4 个回归测试（4/4 通过）及自建样例扫描（2 文件、28 行、1 条 candidate），检查 PR #2 变更范围后合并到 main；本地 main 已同步，并创建 feat/openharmony-target-onboarding 分支。MVP 阶段以合并提交 bef61d0caeed7c58b3887abc8b8cbfc33a1b4755 为基线。
## Step 9：筛选 3 个真实 OpenHarmony C/C++ 候选组件（第一轮完成）

已固定 cJSON、c_utils、lwIP 的 master 提交；cJSON 为首条工程闭环主目标，c_utils 为第一方备选，lwIP 因宿主机构建受阻而暂缓。命令结果与未知项见 [目标筛选记录](docs/targets/target_selection.md)。

目标：找到至少 1 个主目标和 1 个备选目标。

填写：

```text
docs/targets/target_selection.md
```

每个候选至少记录：

- repo / component；
- repo URL；
- branch / tag；
- commit；
- host build 是否可能；
- 是否有 tests；
- 是否有 fuzz target；
- 输入面；
- 依赖重量；
- 是否有历史安全修复；
- 最终 decision。

筛选原则：

- C/C++ 为主；
- 有真实输入处理；
- 有 host build / unit test / fuzz target 更优；
- 依赖不能太重；
- 不需要第一天就上开发板。

止损：对一个候选先花 1～2 小时探测，不能构建或入口不清晰就记录原因换下一个。

---

## Step 10：为主目标建立 TargetSnapshot v0（已完成）

已填写 [cJSON TargetSnapshot](config/targets/third_party_cJSON.yaml)：精确记录独立测试通过和完整构建失败的不同状态，以及真实扫描的分母。

从 `config/targets/template.yaml` 复制：

```bash
cp config/targets/template.yaml config/targets/<component>.yaml
```

最少填入：

```text
repo_url
branch_or_tag
commit
local_path
source_paths
exclude_paths
build.command
test.command
```

在目标仓库中记录：

```bash
git remote -v
git rev-parse HEAD
git status
git log -1 --oneline
```

验收：任何人只看 YAML 就能知道扫的是哪个 repo、哪个 commit、哪些源码路径、如何构建和测试。

---

## Step 11：证明原组件能正常构建和运行（局部完成）

cJSON 的 host cJSON_test 目标构建成功、ctest 1/1 通过；完整测试构建缺少 test_fwk.h，未达到全组件通过条件。原始日志位于本地 Git 忽略目录 outputs/logs/。

在安全分析前先建立正常基线。

必须记录：

- Ubuntu / Clang / GCC 版本；
- 目标 commit；
- 构建命令；
- 测试命令；
- 正常输入；
- 正常返回值；
- 构建耗时；
- 失败日志。

建议：

```bash
/usr/bin/time -v <build command>
```

通过条件：

```text
clean checkout
→ build success
→ original/unit test success
```

如果失败，优先补真实依赖或换组件，不要为了能编译而乱改原组件核心逻辑。

---

## Step 12：真实组件上跑当前 scanner + 成熟工具基线（核心扫描与默认 Clang baseline 已完成）

cJSON 全仓扫描 99 文件、22,377 行、49 条文本候选；其中核心库 26 条，测试代码 22 条，fuzz 代码 1 条。2026-10-04 已按 [scope 验证清单](docs/testing/scan_scope_verification.md) 在 WSL 验证 9 个测试和全部样例命令。固定提交的核心两文件 scoped scan 为 2 文件、4,681 行、26 条候选；JSON 与 Markdown 均记录同一 include/exclude 范围，且 26 条与旧全仓核心命中逐项一致。同两文件的默认参数 Clang Static Analyzer baseline 已运行，结果见第 13 节。

当前 scanner 示例：

```bash
python -m src.cli scan /home/audit/openharmony-targets/<component>/<source-dir> \
  --json-out outputs/reports/<component>_candidate.json \
  --md-out outputs/reports/<component>_candidate.md
```

记录：

- scanned_files；
- scanned_lines；
- skipped_files；
- candidate_count；
- top rule IDs。

成熟工具第一阶段只选 1～2 个：

- clang-tidy；
- Clang Static Analyzer / scan-build；
- 有现成入口时再跑 fuzz。

不要把成熟工具 warning + 我们的 candidate 直接相加为漏洞数。

---

## Step 13：人工审核首批真实候选，建立误报原因字典（首批 10 条已初筛）

核心库 10 条初筛中，5 条 likely_safe、3 条 needs_context、2 条 interesting；没有 validated 漏洞。逐条原因见目标筛选记录。此处的状态仅表示下一步调查优先级。

建议从真实扫描结果中抽 10～30 条，逐条回答：

1. 这是真函数调用，还是注释/宏/声明？
2. 所在函数是什么？
3. 参数是什么？
4. destination 实际大小是什么？
5. length 从哪里来？
6. 调用前是否已有边界检查？
7. 上层调用者是否保证约束？
8. 外部输入是否可控？
9. 路径是否真实可达？
10. 是否有安全影响？

Triage 状态建议：

```text
needs_context
likely_safe
interesting
duplicate
scanner_quality_issue
blocked
```

误报原因建议：

```text
comment_or_macro
constant_safe_length
destination_large_enough
upstream_guard
wrapper_enforces_bound
unreachable_test_code
third_party_code
duplicate_callsite
no_security_impact
unknown
```

这一步会决定下一步到底该做函数上下文、AST、数据流还是验证 harness。

---

## Step 14：函数上下文提取（轻量启发式已实现并在固定目标验证）

当前 Finding 已能携带启发式 top-level 函数名、函数范围和局部源代码窗口；固定 cJSON 两文件的 26 条候选全部解析到函数，六个指定位置的归属正确。更复杂的 C/C++ 结构尚未评估；若要做深层语义审计，仍需要：

```text
candidate line
→ enclosing function
→ function range
→ call location
→ context snippet
→ parser status
```

优先路径：如果目标组件有 `compile_commands.json`，后续用 Clang AST / tooling。

降级路径：如果编译参数不完整，先用 Tree-sitter 或轻量语法解析抽函数边界，并标注 `syntax_only`，不能冒充完整 C++ 语义。

必须补测试：

- 注释里的 `strcpy(...)`；
- `my_strcpy`；
- 跨行调用；
- 宏内调用；
- 同一函数两个候选；
- header/source；
- 解析失败记录 unknown。

---

## Step 15：选择一个候选进入 ASan/UBSan 验证闭环

第一条真实验证链可以先采用：

- 公开历史已知修复前版本；或
- 能明确控制输入的真实组件路径。

验证链：

```text
Candidate
  ↓
确认所在函数和调用约定
  ↓
确认输入和边界条件
  ↓
复用原组件测试 / fuzz 入口
  ↓
构建 sanitizer 版本
  ↓
正常输入对照
  ↓
异常/边界输入
  ↓
保存 ASan/UBSan/行为日志
  ↓
重复执行
  ↓
升级状态或记录反证
```

结果只能是：

```text
validated
refuted
inconclusive
environment_blocked
harness_invalid
```

没有触发不等于一定安全；环境失败也不能当作漏洞不存在。

---

## 7. 当前验证后的工作顺序

scan scope、函数上下文和默认参数 Clang baseline 的本地验证已经完成。下一轮按同一固定提交与核心范围：

1. 取得/核对原 OpenHarmony 编译命令后，判断默认 Clang 分析缺少哪些必要宏与 include 参数；没有依据时不任意加参数。
2. 复核 needs_context / interesting 候选的函数、边界关系、调用链与实际输入条件。
3. 只有存在可控输入与正常输入对照时，才在原组件上做 ASan/UBSan 或行为验证。
4. 并行评估 c_utils 的一个小型第一方子模块，但不要把未知构建状态写成通过。

Clang baseline 的本轮验证结果见第 13 节；本轮没有开始上述下一阶段工作。

---

## 8. 硬性止损规则

1. 不能构建的组件，不作为第一主目标长期死磕。
2. 当前 scanner 再增加新函数名之前，必须说明解决了哪类真实漏检。
3. 没有真实候选驱动，不自研完整 CFG/CPG。
4. PoC/harness 尽量调用原组件代码，不复制核心函数重写一份。
5. Sanitizer crash 必须确认栈帧来自目标组件，而不是 harness 自己。
6. 未触发、环境失败、解析失败都记录为 unknown / inconclusive。
7. 公开历史案例只证明能力，不能当作新发现。
8. 未匹配到 CVE 不能自动标记 0-day。
9. 每次 AI 直接修改 GitHub 远程分支后，本地继续前先 `git pull --ff-only`。
10. 每完成一个稳定小闭环就 commit；不要攒几十个功能后一次性提交。

---

## 9. 给 Codex 的下一轮任务模板

下一轮先读本文件第 11～13 节、三份 docs/testing 验证记录和 docs/targets/target_selection.md。scan scope、轻量 function context 和默认参数 Clang baseline 均已在 WSL 验证；不要重复实现，也不要把候选或 Clang 的零诊断解释为安全结论。后续工作优先核对原编译参数与人工上下文；任何运行时结论需保存可复现证据。未实际运行的工具、构建或 PoC 结果保持 unknown / not_started。

---

## 10. 最重要提醒

**MVP scanner 阶段已经完成。下一步不是把规则表做得更长，而是选定一个可构建、可测试、固定 commit 的真实 OpenHarmony C/C++ 组件，把 `candidate → 上下文 → 原组件运行 → sanitizer/行为证据` 这条链第一次跑通。九层架构继续作为最终方向，但当前两周路线只实现真实案例所需要的纵切面。**


---

## 11. 2026-10-04 scan scope 的 WSL 实测记录

验证环境：Ubuntu 22.04 WSL2，分支 feat/openharmony-target-onboarding，项目提交 ba7144806bfc23c2d449c64883f015d9a5b9cfd1。cJSON 本地源码提交 0c2c9dff82cc85539c8362132d7a5f6bf7d1e748，未改目标源码。按 docs/testing/scan_scope_verification.md 运行；本轮只更新文档，**未修改 scanner、CLI、报告器或测试代码**。

### 已验证

- 执行 python -m unittest discover -s tests -v：**Ran 9 tests，OK；通过 9，失败 0，错误 0**。因此没有失败测试名或失败原因。
- 旧命令扫描 samples：2 文件、28 行、1 条候选；无显式范围时 stdout 显示 include 为 .、exclude 为 (none)，旧用法可继续使用。
- include vulnerable：1 文件、11 行、1 条候选；include safe：1 文件、17 行、0 条候选；exclude safe：1 文件、11 行、1 条候选，均与验证清单相符。
- include ../outside 以退出码 1 拒绝，报 Include path escapes target root；include does-not-exist 也以退出码 1 拒绝，报 Included path does not exist。
- 重叠 include 不重复计数由本轮通过的对应回归测试覆盖；未另对真实仓库运行重叠范围命令。
- 固定提交 cJSON 的核心两文件 scoped scan：**scanned_files 2，scanned_lines 4,681，skipped_files 0，candidate findings 26**。规则分布：memcpy 9、sprintf 11、strcat 1、strcpy 5。
- JSON 报告 outputs/reports/cjson_core_candidate.json 的 scope 实际为：

~~~json
{
  "include_paths": ["cJSON.c", "cJSON_Utils.c"],
  "exclude_paths": []
}
~~~

- Markdown 报告 outputs/reports/cjson_core_candidate.md 的对应字段为 Include scope: cJSON.c, cJSON_Utils.c；Exclude scope: (none)。两种报告范围一致。
- 与此前全仓报告 outputs/reports/cjson_candidate.json 比较，旧报告的核心文件命中也是 26 条；逐项比较文件、行号、rule_id 与 evidence 后，26 条**顺序和内容完全一致**。这复现了旧记录的核心候选数，并非为了得到 26 修改代码或预期结果。

执行核心范围扫描的命令：

~~~bash
python -m src.cli scan /home/audit/openharmony-targets/third_party_cJSON \
  --include cJSON.c --include cJSON_Utils.c \
  --json-out outputs/reports/cjson_core_candidate.json \
  --md-out outputs/reports/cjson_core_candidate.md
~~~

报告在本地 Git 忽略目录 outputs/reports/，不会随提交上传；复现者可运行上述命令重建。

### 未验证

- 没有把 26 条文本候选升级为漏洞；本轮没有原组件 PoC、ASan/UBSan 实验或影响分析。
- 截至本节 scan scope 验证时，尚未运行 clang-tidy、Clang Static Analyzer、CodeQL 或 fuzz；后续 Clang 结果见第 13 节。
- cJSON 完整测试套件仍未通过构建。已知 standalone checkout 缺 test_fwk.h；本轮没有补依赖或重试完整构建。
- 没有测试大规模代码库的耗时、峰值内存、准确率或召回率。

### unknown（需后续证据才能判断）

- 26 条候选的真实安全影响、可控触发条件及受影响 OpenHarmony 版本。
- 三个候选仓库与最终赛方指定代码范围/版本的匹配结论。
- 补齐 test_fwk.h 等依赖后，cJSON 完整套件能否在此环境通过。
- c_utils 的宿主机可构建性和其 fuzztest 的实际运行结果。

当时的下一步是同一核心范围的成熟工具基线；该项已于本文件第 13 节记录。后续仍需人工复核 needs_context / interesting 候选，在有可靠调用路径和正常输入对照后再考虑原组件运行时验证。不要把 26 条候选写成 26 个漏洞。


---

## 12. 2026-10-04 function-context 的 WSL 实测记录

验证环境：Ubuntu 22.04 WSL2；项目基线提交 06b9498，分支 feat/openharmony-target-onboarding；cJSON 源码固定为 0c2c9dff82cc85539c8362132d7a5f6bf7d1e748，工作树干净。执行 docs/testing/function_context_verification.md 的清单。**本轮未修改任何扫描代码、测试或 cJSON 源码；只更新进度与验证说明文档。**

### 已验证

- 完整回归：执行 python -m unittest discover -s tests -v，实际 **Ran 14 tests，OK；通过 14，失败 0，错误 0**。无失败测试、traceback 或代码修复。
- 旧样例扫描：2 文件、28 行、1 条 candidate。第一条 Finding 的 function = bad_copy，function_start_line = 1，function_end_line = 6，context_start_line = 2，context_end_line = 6，context_status = heuristic_top_level_function。context 包含 strcpy(buf, input);。
- 固定 cJSON 核心两文件扫描：scanned_files = 2，scanned_lines = 4681，skipped_files = 0，candidate_findings = 26。与上一轮核心范围报告的 26 条候选按文件、行号、rule_id、evidence 和顺序逐项相同；新增上下文没有改变候选身份或数量。
- context_status 统计：heuristic_top_level_function = 26；resolved = 26，unresolved = 0。本次固定源码没有 unresolved 项；这不是对其他 C/C++ 工程解析率的承诺。
- 六处指定调用的函数归属如下，均为文档预期。expected 与 actual 分列，避免只记录“通过”。

| 位置 | expected | actual | 结果 |
|---|---|---|---|
| cJSON.c:204 | cJSON_strdup | cJSON_strdup | OK |
| cJSON.c:367 | parse_number | parse_number | OK |
| cJSON.c:465 | cJSON_SetValuestring | cJSON_SetValuestring | OK |
| cJSON.c:570 | ensure | ensure | OK |
| cJSON_Utils.c:234 | cJSONUtils_FindPointerFromObjectTo | cJSONUtils_FindPointerFromObjectTo | OK |
| cJSON_Utils.c:245 | cJSONUtils_FindPointerFromObjectTo | cJSONUtils_FindPointerFromObjectTo | OK |

- Markdown 报告 outputs/reports/cjson_core_context.md 有 26 个候选段落；每段均含 Function、Function range、Context status、Context lines、Evidence、Context。开头仍有 “Text-pattern candidates only. No finding has been validated as a vulnerability.”。
- /usr/bin/time -v 对同一固定两文件运行一次：**Elapsed wall clock time 0:00.10；Maximum resident set size 14,556 kB；Exit status 0**。这是单次小目标 sanity check，不能称为最终 Benchmark。
- 本地生成 outputs/reports/cjson_core_context.json、outputs/reports/cjson_core_context.md；这些运行报告按 .gitignore 保留在本机，不上传仓库。

### 未验证

- 截至本节 function-context 验证时，尚未运行 clang-tidy、Clang Static Analyzer、fuzz 或原组件 ASan/UBSan/PoC；后续 Clang 结果见第 13 节，仍未证明任一 candidate 是漏洞。
- 没有对大规模 OpenHarmony 代码库测耗时、峰值内存、准确率或召回率。
- 没有做 AST、CFG、数据流、调用链可达性或完整 C++ 类内函数解析。本轮 26/26 只表示固定 cJSON 核心两文件的启发式函数名被填出。

### unknown（仍需证据）

- 其他仓库、宏、属性、类内定义及损坏源码上启发式函数归属和行范围的可靠性；六处 spot check 不等于验证了其余 20 条的语义正确性。
- 26 条文本候选的可控输入、安全影响、受影响版本及是否存在真实漏洞。
- cJSON 完整测试套件补齐 test_fwk.h 等依赖后能否通过；c_utils 的宿主机构建结果。
- 两周竞赛交付所需的大规模性能、真实准确率和完整漏洞验证链。

结论边界：context_status = heuristic_top_level_function 仅表示轻量启发式匹配到 top-level 函数，**不是 AST 证明，更不是漏洞验证**。下一阶段功能开发未在本轮开始。


---

## 13. 2026-10-04 Clang Static Analyzer baseline 的 WSL 实测记录

验证环境：Ubuntu 22.04 WSL2；项目基线提交 44b4843，分支 feat/openharmony-target-onboarding；cJSON 源码固定为 0c2c9dff82cc85539c8362132d7a5f6bf7d1e748，工作树干净。按 docs/testing/clang_baseline_verification.md 执行。本轮**没有修改 analyzer、CLI、测试或 cJSON 源码**；只更新进度、验证说明和 TargetSnapshot。

### 已验证

- Clang executable path：/usr/bin/clang；版本首行：Ubuntu clang version 14.0.0-1ubuntu1.1。
- 完整回归 python -m unittest discover -s tests -v：**Ran 18 tests，OK；通过 18，失败 0，错误 0**。无失败测试名、traceback 或代码修复。
- 对固定 cJSON 核心两文件运行：

~~~bash
python -m src.cli baseline-clang /home/audit/openharmony-targets/third_party_cJSON \
  --file cJSON.c --file cJSON_Utils.c \
  --json-out outputs/reports/cjson_clang_baseline.json \
  --md-out outputs/reports/cjson_clang_baseline.md
~~~

- 两条实际 analyzer 命令均为 clang --analyze -Xanalyzer -analyzer-output=text -I /home/audit/openharmony-targets/third_party_cJSON 加对应源文件绝对路径；**没有添加 --clang-arg 或伪造编译参数**。cJSON.c exit_code = 0；cJSON_Utils.c exit_code = 0；二者 stderr 均为空。
- JSON 实际：tool = clang-static-analyzer；files = [cJSON.c, cJSON_Utils.c]；file_count = 2；diagnostic_count = 0；failed_files = []；warning = 0、error = 0、note = 0；checker 分布 = {}。首次运行器 elapsed_seconds = 16.684430。
- 与已验证的 26 条核心文本候选按文件名和行号比较：candidate_locations = 26；baseline_warning_error_locations = 0；exact_location_overlap = 0；Clang-only warning/error locations = 0；text-candidate-only locations = 26。这是**描述性位置比较**，不能将 26 条视为误报，也不能把 0 条 Clang 诊断当作安全证明。
- Markdown 报告包含 Target、Clang version、Files、Diagnostics、Failed files、每个文件的 Command、Exit code、Elapsed 和免责声明。由于诊断数为 0，没有逐条诊断的 Checker/Message 行；报告写明 No parsed warning/error diagnostics，JSON 的 diagnostics 为 []。不为满足展示字段而虚构诊断。
- 第二次对同一命令运行 /usr/bin/time -v：运行器自身 elapsed_seconds = 15.727517；外部墙钟 **0:15.96**，Maximum resident set size **179,716 kB**，Exit status **0**。仅为小目标 sanity check，不是最终比赛 Benchmark。
- 原始 JSON/Markdown 运行报告位于本地忽略目录 outputs/reports/，性能复跑报告位于 /tmp/；均不随 Git 提交。

### 未验证

- 未使用完整 OpenHarmony 编译命令、宏定义、include 路径或指定产品配置；当前只是两个独立 C 文件的默认 Clang 分析。
- 未运行 clang-tidy、CodeQL、Joern、fuzz、原组件 ASan/UBSan 或 PoC；未验证任何候选的可利用性。
- 未测大规模扫描耗时/内存、准确率、召回率或影响版本；cJSON 完整测试套件仍缺 test_fwk.h。

### unknown（仍需证据）

- 补齐原 OpenHarmony 编译参数后，Clang 的诊断集合是否变化；零诊断不能推断为“无漏洞”。
- 26 条文本候选的边界条件、真实安全影响和适用版本；Clang 不报告某行不等于该候选必定误报。
- 其他组件上的 analyzer 可构建性、diagnostic 解析覆盖率及性能；本轮只分析固定 cJSON 核心两文件。
- c_utils 的宿主机构建、赛方指定代码范围与最终竞赛报告的实质漏洞证据。

结论边界：Clang baseline 与本项目文本候选是两种独立证据，数量不能相加或当作准确率。下一阶段功能开发未在本轮开始。
