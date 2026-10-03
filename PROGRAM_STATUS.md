# PROGRAM_STATUS.md

> - 项目：CyberSecurity-Innovation-Audit
> - 赛题方向：2026 OpenHarmony 开源代码漏洞挖掘
> - 更新日期：2026-10-03
> - 当前分支：`feat/openharmony-target-onboarding`
> - 已合并 PR：#2（MVP scanner 与目标筛选模板），merge commit `bef61d0caeed7c58b3887abc8b8cbfc33a1b4755`。
> - 当前阶段：真实组件筛选与 cJSON 首条工程闭环；构建、测试和扫描的证据见目标配置与筛选记录。
> 本文用途：给 ChatGPT、Codex、队友和未来自己看的统一进度说明。继续开发前先读本文，避免重复搭环境、误把计划当成已实现功能，或跳过验证步骤。

---

## 0. 当前一句话状态

**MVP scanner 已合并到 main。真实目标第一轮筛选了 cJSON、c_utils、lwIP 三个固定提交；cJSON 的独立宿主机测试 1/1 通过，但完整测试构建缺少 test_fwk.h。当前扫描 cJSON 全仓 99 个源码文件、22,377 行，得到 49 条文本候选，其中核心库 26 条。已人工初筛 10 条，尚无确认漏洞。2026-10-04 已在当前分支加入显式 `--include/--exclude` 扫描范围、scope 报告字段和 5 个新增回归测试，但尚待 Ubuntu WSL/Codex 本地验证。验证通过后先重跑 cJSON 核心文件，再进入成熟静态工具基线和函数上下文分析。**

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
├── cli/
│   ├── __init__.py
│   ├── __main__.py
│   └── main.py
└── core/
    ├── __init__.py
    ├── finding.py
    ├── scanner.py
    └── report.py

samples/
├── vulnerable/demo_overflow.cpp
└── safe/demo_safe_copy.cpp

tests/
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

### 2.5 报告输出

已支持：

- JSON 报告；
- Markdown 报告；
- Markdown 明确提示“Text-pattern candidates only. No finding has been validated as a vulnerability.”

本地生成报告位于 `outputs/reports/`，该目录下的 `.json` 和 `.md` 已被 `.gitignore` 忽略，不应提交。

### 2.6 回归测试

当前 `tests/test_scanner.py` 已有 4 个最小回归测试，覆盖：

1. vulnerable / safe 样例区分；
2. 函数名边界与空格调用形式；
3. CLI 写出 JSON 和 Markdown；
4. CLI 对不存在 target 报错。

运行：

```bash
python -m unittest discover -s tests -v
```

---

## 3. 明确没有完成的能力

以下能力**尚未实现**，不要让 Codex 或后续文档误写成已完成：

- 尚未对真实 OpenHarmony 组件完成全套构建、测试与运行时漏洞验证；
- 尚未用新 `--include/--exclude` 功能完成 cJSON 核心源码的独立扫描统计；该功能代码与测试已写入远程分支，但本地验证仍 pending；
- 尚未接入 AST；
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
- 尚未进行真实准确率、召回率和性能 Benchmark。

当前状态只是：

```text
环境与 GitHub 打通
→ MVP scanner 合并到 main
→ 固定 3 个真实组件提交并完成第一轮筛选
→ cJSON 局部构建、单测、全仓扫描及 10 条初筛
→ 待做核心范围扫描、成熟工具对照和运行时验证
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

## Step 12：真实组件上跑当前 scanner + 成熟工具基线（扫描完成，工具待做）

cJSON 全仓扫描 99 文件、22,377 行、49 条文本候选；其中核心库 26 条，测试代码 22 条，fuzz 代码 1 条。成熟工具尚未运行。2026-10-04 已在当前分支加入可重复的 `--include` / `--exclude` 范围参数，并将 scope 写入 JSON/Markdown；同时新增 5 个 scope 回归测试。该功能尚未在用户 Ubuntu WSL 上实跑验证，因此下一动作是按 `docs/testing/scan_scope_verification.md` 先把测试跑绿，再用 `--include cJSON.c --include cJSON_Utils.c` 复现核心 26 条基线。

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

## Step 14：实现函数上下文提取，而不是立刻自研完整 CFG

当前 Finding 只有单行 evidence，`function` 多数仍无法解析。真实审计需要：

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

## 7. 接下来 2～3 天的实际顺序

### 今天剩余时间

```text
回归测试
→ 合并 PR #2
→ 新建 feat/openharmony-target-onboarding
→ 阅读 docs/targets/target_selection.md
→ 找 3 个候选组件
```

### 下一工作日上半天

```text
clone 主/备选目标
→ 构建探测
→ 运行原始测试
→ 固定第一个 TargetSnapshot
```

### 当前最近一步（2026-10-04）

```text
Codex/WSL 验证 scan scope 9 个回归测试
→ cJSON 核心两文件 scoped scan
→ 对照此前 26 条核心 candidate
→ clang-tidy / Clang Static Analyzer 选择一个成熟工具基线
→ 复核 needs_context / interesting 候选
→ 决定先做函数上下文还是 sanitizer 验证
```

测试计划见 `docs/testing/scan_scope_verification.md`。在 scoped scan 数字可复现之前，不更新正式基线统计。

### 随后一天

根据真实缺口决定：

```text
如果最大缺口是“看不到函数” → 做函数上下文/AST
如果最大缺口是“看不到长度来源” → 做局部数据流
如果已有高价值候选且组件可测试 → 做 sanitizer harness 和验证
```

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

可以直接交给 Codex：

```text
先阅读 PROGRAM_STATUS.md、docs/roadmap.md、docs/targets/target_selection.md、config/targets/template.yaml 和当前分支代码。

当前 Step 1～7 已完成，不要重复实现 MVP 扫描器。

本轮目标不是增加更多危险 API 规则，而是进入真实 OpenHarmony 组件 onboarding。

请完成：
1. 根据 docs/targets/target_selection.md 帮我填 3 个候选组件的调研表，但不要虚构 build/test 成功；
2. 对所有 build/test/fuzz 字段默认写 unknown，等待我在 Ubuntu WSL 本地真实执行；
3. 为选出的主目标生成 config/targets/<component>.yaml 草案；
4. 输出我本地需要执行的 clone、固定 commit、build、test、scan 命令；
5. 不实现完整 AST/CFG/污点；
6. 不把 candidate 称为 vulnerability；
7. 说明哪些结论仍然 unknown。
```

---

## 10. 最重要提醒

**MVP scanner 阶段已经完成。下一步不是把规则表做得更长，而是选定一个可构建、可测试、固定 commit 的真实 OpenHarmony C/C++ 组件，把 `candidate → 上下文 → 原组件运行 → sanitizer/行为证据` 这条链第一次跑通。九层架构继续作为最终方向，但当前两周路线只实现真实案例所需要的纵切面。**


---

## 11. 2026-10-04 ChatGPT 远程代码更新（待 Codex/WSL 验证）

本次直接写入 `feat/openharmony-target-onboarding`：

- `src/core/scanner.py`：增加显式 include/exclude 扫描范围，防止路径逃逸、重叠 include 重复计数，并把 scope 写入 ScanResult。
- `src/cli/main.py`：增加可重复使用的 `--include PATH` 与 `--exclude PATH` 参数。
- `src/core/report.py`：Markdown 报告增加 include/exclude scope。
- `tests/test_scanner.py`：在原 4 个测试基础上新增 5 个 scope 测试，目标总数 9。
- `docs/testing/scan_scope_verification.md`：增加 Codex/WSL 验证清单。

这些提交**尚未由用户本地 Ubuntu WSL 实际执行**，因此不能写成“已验证通过”。

本地下一步：

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
git checkout feat/openharmony-target-onboarding
git pull --ff-only
source .venv/bin/activate
python -m unittest discover -s tests -v
```

预期在实现正确时：

```text
Ran 9 tests
OK
```

随后按 `docs/testing/scan_scope_verification.md` 重跑 samples 和 cJSON 核心两文件。若任何测试或 cJSON 计数不一致，先定位原因，不为了让数字好看而修改预期结果。
