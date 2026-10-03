# PROGRAM_STATUS.md

> 项目：CyberSecurity-Innovation-Audit  
> 赛题方向：2026 OpenHarmony 开源代码漏洞挖掘  
> 更新日期：2026-10-03  
> 当前开发分支：`feat/mvp-scanner`  
> 当前 PR：#2 `feat: add MVP C++ dangerous call scanner`（目标分支：`main`，当前未合并）  
> 本文用途：作为 ChatGPT、Codex 和团队成员的统一进度说明。开始新一轮开发前，应先阅读本文，避免重复搭环境、误判已实现功能或跳过验证步骤。

> **2026-10-03 进度更新：** 下文第 4 节的 Step 1～7 已实施并通过回归测试；第 1 节记录环境历史，第 4 节保留原执行计划。当前可运行能力与限制以第 2、3、7 节为准。状态字段为 `candidate`，而 `confidence` / `severity` 为 `unassessed`；不能用“两个样例一正一负”推断真实项目的准确率。

---

## 1. 今天从零开始完成了什么

### 1.1 开发环境选型

最初检查过两套环境：

- Kali Linux WSL2：可用，但缺少 Git、Clang、CMake 等基础工具，不作为 OpenHarmony 主开发环境。
- 一台 Ubuntu 22.04 云服务器：系统和 x86_64 架构合适，但只有约 2 vCPU、2 GB RAM、40 GB 磁盘且无 swap，不适合作为后续 C/C++ 编译、静态分析、Sanitizer 和 fuzz 的主力环境。

最终决定：

- **主开发环境：Windows 本机上的 Ubuntu 22.04 WSL2**
- Kali WSL 保留作其他安全实验
- 低配置云服务器暂不作为主开发机

本机物理内存约 64 GB，适合 WSL2 开发；为了节省磁盘，当前不做完整 OpenHarmony 全量下载和全量编译，优先走组件级验证路线。

### 1.2 Ubuntu 22.04 WSL2 已安装并可用

已完成：

- 安装 Ubuntu 22.04 WSL2
- 创建普通 Linux 用户：`audit`
- 工作目录位于 Linux 文件系统，而不是 `/mnt/c`：
  - `/home/audit/openharmony-audit`

WSL 启动时曾出现若干 Windows PATH 无法转换的提示，例如旧的 D 盘 Python/PHP 路径。这些提示目前**不阻塞项目开发**，后续如有必要再清理 Windows PATH。

### 1.3 基础开发工具链已安装

当前已验证的核心工具包括：

- Git 2.34.1
- GCC / G++ 11.4.0
- Clang / Clang++ 14.0.0
- CMake 3.22.1
- Ninja 1.10.1
- Python 3.10.12
- pip 22.0.2

此外已创建 Python 虚拟环境：

- 项目根目录下：`.venv/`
- 开发时通过 `source .venv/bin/activate` 启用

### 1.4 AddressSanitizer 已验证成功

已使用一个故意越界的 C++ 测试程序验证：

```bash
clang++ -fsanitize=address -g /tmp/asan_test.cpp -o /tmp/asan_test
/tmp/asan_test
```

当前环境已经能够正常输出类似：

```text
ERROR: AddressSanitizer: heap-buffer-overflow
SUMMARY: AddressSanitizer: heap-buffer-overflow
```

这说明后续可以使用 ASan 作为内存安全候选的运行时验证证据。

> 说明：此前曾尝试安装 `libclang-rt-14-dev`，APT 无法定位该包；但最终实际的 ASan 编译和诊断已经正常工作，因此这不再是当前阻塞项。

### 1.5 GitHub SSH 与本地仓库已打通

已完成：

- 为 Ubuntu WSL 创建 GitHub SSH key
- GitHub SSH 认证成功
- 将私有仓库克隆到本地：

```text
/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit
```

Git 的基本工作流当前采用：

```text
GitHub main
   ↓ clone
本地仓库
   ↓ 创建功能分支
feat/mvp-scanner
   ↓ 开发 / 本地运行 / 验证
git add
   ↓
git commit
   ↓
git push
   ↓
GitHub Pull Request
   ↓
确认成熟后再 merge 到 main
```

### 1.6 当前开发分支与 Pull Request

当前开发分支：

```text
feat/mvp-scanner
```

命名含义：

- `feat`：feature，新功能
- `mvp-scanner`：最小可行扫描器

当前 GitHub PR：

- **PR #2**
- 标题：`feat: add MVP C++ dangerous call scanner`
- base：`main`
- compare/head：`feat/mvp-scanner`
- 当前状态：Open，未合并

后续在本地继续向 `feat/mvp-scanner` 提交并 `git push`，新的 commit 会自动进入 PR #2，无需重复创建 PR。

---

## 2. 当前已经实现的 MVP

### 2.1 当前代码结构

目前已经实际存在并运行过的核心文件：

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

`src/core/finding.py` 当前定义统一 Finding，对候选结果保存：

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

扫描器只设置 `status = candidate`；`confidence = unassessed` 和 `severity = unassessed` 表示尚未做置信度及危害评级。不要把流程状态当成置信度。

### 2.3 第一版 C/C++ 候选扫描器

`src/core/scanner.py` 当前能够：

1. 递归遍历目标目录
2. 识别以下源码后缀：
   - `.c`
   - `.cc`
   - `.cpp`
   - `.cxx`
   - `.h`
   - `.hpp`
   - `.hh`
3. 以文本模式查找第一批危险调用：
   - `strcpy`
   - `strcat`
   - `sprintf`
   - `gets`
   - `memcpy`
4. 命中后生成结构化 Finding，并记录已扫描文件数、行数和跳过的源码路径

**重要边界：**

当前扫描器只是候选生成器。

```text
危险函数出现 != 已确认漏洞
```

目前尚未分析：

- 参数是否真正可控
- 缓冲区实际容量
- 上游是否已有 guard
- 调用路径是否可达
- 是否存在真实安全影响
- PoC 是否可触发

因此当前结果必须继续使用 `candidate` 语义，不能直接写成“真实漏洞”。

### 2.4 CLI 已跑通

当前有效命令：

```bash
python -m src.cli scan samples \
  --json-out outputs/reports/samples_report.json \
  --md-out outputs/reports/samples_report.md
```

已经实际运行成功，输出：

```text
[OK] scanned: ...
[OK] scanned files: 2
[OK] scanned lines: 28
[OK] skipped source files: 0
[OK] candidate findings: 1
[OK] json report: ...
[OK] markdown report: ...
```

示例代码中的：

```cpp
strcpy(buf, input);
```

被识别为 1 个候选 Finding。

### 2.5 JSON 与 Markdown 报告已经跑通

当前报告包含：

- target
- scanned_files
- scanned_lines
- skipped_file_count / skipped_files
- finding_count
- findings[]

每一条 finding 能输出规则、候选 CWE、位置、证据、解释和修复建议等字段。Markdown 明确提示“仅为文本候选”。`--out` 保留为 `--json-out` 的兼容别名。

### 2.6 .gitignore 已配置

项目根目录 `.gitignore` 已加入本地开发相关忽略项，包括：

- `.venv/`
- `__pycache__/`
- Python 编译缓存
- `outputs/reports/*.json`
- `outputs/reports/*.md`
- `outputs/logs/`
- `.tmp/`
- `.cache/`

目的：避免把 Python 虚拟环境、缓存和本地生成报告当作源代码上传到 GitHub。

---

## 3. 当前明确还没有实现的能力

以下内容**不要让 ChatGPT、Codex 或团队成员误认为已经完成**：

- 尚未扫描真实 OpenHarmony 组件
- 尚未接入 AST
- 尚未实现 CFG
- 尚未实现数据流或污点分析
- 尚未做跨函数调用分析
- 尚未自动构造 PoC
- 尚未把 ASan Runner 接入工具
- 尚未实现 fuzz
- 尚未实现 CWE 深度根因判断
- 尚未实现 CVE 关联
- 尚未实现版本/分支影响分析
- 尚未实现 Patch 自动验证
- 尚未实现 LLM 二次研判
- 尚未实现完整比赛漏洞报告
- 尚未进行准确率、召回率和性能 Benchmark

当前状态可以概括为：

```text
环境已打通
    ↓
仓库 / Git 流程已打通
    ↓
第一版文本候选扫描器已跑通
    ↓
已具备候选状态、扫描统计、双报告、正负样例和回归测试
    ↓
下一步验证真实 OpenHarmony 组件与构建配置
```

---

# 4. 本轮已完成：1～7 步详细开发计划

以下保留本轮的执行计划与验收思路。实际实现已通过第 7 步，并补充了自动化回归测试；尚未拉取或扫描真实 OpenHarmony 组件。

## Step 1：确认开发环境、分支和工作区状态

### 目标

每次继续开发前先确认自己在正确仓库、正确虚拟环境、正确分支，避免代码写错目录或提交到 main。

### 执行

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
source .venv/bin/activate

git branch --show-current
git status
```

期望：

```text
feat/mvp-scanner
```

如果不是：

```bash
git checkout feat/mvp-scanner
```

### 验收

- 当前目录是仓库根目录
- Python 虚拟环境已激活
- 当前分支是 `feat/mvp-scanner`
- 工作区中的未提交修改都是本轮有意修改

---

## Step 2：给 Finding 增加独立 status 字段

### 为什么做

原实现曾有：

```text
confidence = candidate
```

但“置信度”和“流程状态”是两个不同概念。

后续需要明确区分：

```text
candidate
    ↓
suspected
    ↓
validated
    ↓
reportable
```

因此新增：

```python
status: str
```

第一版扫描器生成的 Finding 默认：

```text
status = candidate
```

### 修改位置

`src/core/finding.py`

### 验收

JSON Finding 中能够同时看到：

```json
{
  "confidence": "unassessed",
  "status": "candidate"
}
```

原计划示例把 `confidence` 也写成 `candidate`，仍然混淆了两个概念；实际实现已改为 `unassessed`。后续程序分析、运行验证和人工审核可以分别更新状态与置信度。

---

## Step 3：给扫描器增加扫描统计

### 为什么做

比赛后续需要说明：

- 实际扫描多少文件
- 实际扫描多少代码行
- 产生多少候选
- 哪些范围真正被分析

因此 MVP 从现在开始就记录基础 coverage 数据。

### 修改目标

将 `scan_directory()` 从“只返回 Finding 列表”扩展成一个 ScanResult 风格的字典，至少包含：

```text
target
scanned_files
scanned_lines
finding_count
findings
```

### 第一版统计

- `scanned_files`：实际进入扫描器的 C/C++ 源文件数
- `scanned_lines`：读取到的总行数
- `finding_count`：候选 Finding 数

### 验收

CLI 运行后能够看到类似：

```text
[OK] scanned files: 2
[OK] scanned lines: ...
[OK] findings: 1
```

> 注意：当前只是“文本扫描覆盖”，不能把这个数字写成 OpenHarmony 全项目安全覆盖率。

---

## Step 4：增加 Markdown 报告生成器

### 为什么做

JSON 适合程序处理，但不适合团队快速阅读和答辩展示。

新增：

```text
src/core/report.py
```

第一版 Markdown 报告包含：

### Scan Summary

- Target
- Scanned files
- Scanned lines
- Finding count

### 每个 Finding

- Rule ID
- Status
- CWE
- Severity
- Confidence
- File
- Line
- Evidence
- Explanation
- Remediation

### 验收

运行后生成：

```text
outputs/reports/samples_report.md
```

文件能够直接打开阅读，不依赖额外工具。

---

## Step 5：更新 CLI，同时支持 JSON + Markdown

### 当前

目前命令只有：

```bash
python -m src.cli scan TARGET --out REPORT.json
```

### 下一版目标

改为：

```bash
python -m src.cli scan samples \
  --json-out outputs/reports/samples_report.json \
  --md-out outputs/reports/samples_report.md
```

CLI 完成扫描后应同时：

1. 保存机器可读 JSON
2. 保存人可读 Markdown
3. 在终端打印基础扫描统计

### 验收

一次命令生成两个报告，并打印：

```text
[OK] scanned: ...
[OK] scanned files: ...
[OK] scanned lines: ...
[OK] findings: ...
[OK] json report: ...
[OK] markdown report: ...
```

---

## Step 6：增加 safe 对照样例

### 为什么做

不能只准备一个“必然会报”的危险样例。

如果测试集中只有 vulnerable 样例，无法证明扫描器不会见什么都报警。

新增：

```text
samples/safe/demo_safe_copy.cpp
```

第一版安全样例使用有界复制或等价安全写法，并确保当前规则不会把它当成危险调用候选。

### 目标

形成最小正负样本：

```text
samples/
├── vulnerable/
│   └── demo_overflow.cpp
└── safe/
    └── demo_safe_copy.cpp
```

### 验收

扫描整个 `samples/`：

- 扫描文件数：2
- vulnerable 样例产生候选
- safe 样例不产生候选
- 总 Finding 数仍为 1

这只是最小 smoke test，不代表真正的误报率实验。

---

## Step 7：完整运行一次 MVP 回归测试

### 执行目标命令

```bash
python -m src.cli scan samples \
  --json-out outputs/reports/samples_report.json \
  --md-out outputs/reports/samples_report.md
```

然后检查：

```bash
cat outputs/reports/samples_report.json
cat outputs/reports/samples_report.md
```

### 本轮期望

至少满足：

```text
Scanned files: 2
Finding count: 1
```

并确认：

- `demo_overflow.cpp` 的 `strcpy` 被报告
- `demo_safe_copy.cpp` 没被当前危险函数规则报告
- JSON 中存在 `status`
- Markdown 报告能够正常生成
- 没有 Python traceback
- 生成报告不会被 Git 误提交

### 通过 Step 7 后再提交

通过后执行：

```bash
git status
git add src samples
git commit -m "feat: add scan summary and markdown report"
git push
```

因为当前分支已经设置 upstream，后续通常只需要：

```bash
git push
```

新的 commit 会自动加入 PR #2。

---

## 5. 完成 1～7 步之后做什么

上述 1～7 步完成后，先不要马上堆更多危险函数。

下一阶段优先顺序建议：

1. 已为 scanner 增加 4 个最小回归测试；后续要增加真实组件和注释、宏、跨行等边界案例
2. 让规则从 Python 代码常量逐渐变成可配置/可扩展规则
3. 抽取函数上下文，而不是只保存单行
4. 区分“危险 API 出现”和“真实容量约束缺失”
5. 开始寻找一个**真实、可构建、可测试的 OpenHarmony C/C++ 组件**
6. 对真实组件先跑成熟工具基线 + 当前候选扫描器
7. 选择一个候选进入：
   - 上下文分析
   - 原组件构建
   - 合法输入构造
   - ASan/UBSan 验证
   - Finding 状态升级或反证

目标仍然是：

```text
Candidate
   ↓
上下文与约束
   ↓
真实组件运行
   ↓
ASan / UBSan / 行为证据
   ↓
Validated Case
   ↓
版本 / CWE / 修复 / 报告
```

---

## 6. 给 ChatGPT / Codex 的协作约束

后续 AI 在修改仓库前应遵守：

1. **先读本文件，再读当前分支实际代码。**
2. 不把 roadmap / architecture 中的设计目标写成“已经实现”。
3. 当前主分支开发重点是 MVP 纵向闭环，不一次性实现完整九层架构。
4. 当前危险函数规则只生成 Candidate，不允许自动宣称真实漏洞。
5. 每增加一个功能必须有至少一个可运行验证方式。
6. 优先修改 `feat/mvp-scanner`，除非明确决定合并 main 或另开分支。
7. 本地生成的报告、缓存、虚拟环境不得作为源码提交。
8. 后续直接通过 GitHub 修改当前远程分支时，要提醒本地开发者先 `git pull`，避免本地代码落后于远程。
9. 对真实 OpenHarmony 目标，必须固定 repo/commit/build config；不能只写“master 当前代码”。
10. 静态候选、运行时错误、安全影响、正式漏洞四个层次必须分开表述。

---

## 7. 当前一句话状态

> **Ubuntu 22.04 WSL2、GitHub、Python/C++ 工具链与 ASan 已打通；`feat/mvp-scanner` / PR #2 上的文本候选扫描器已具有状态字段、扫描统计、JSON/Markdown 双报告、安全负例和 4 个回归测试。在自建样例上扫描 2 个文件、28 行并产生 1 个候选；真实 OpenHarmony 组件、AST/数据流、PoC、影响版本和真实准确率评估仍未完成。下一步锁定一个可构建组件的 repo/commit/build config，建立成熟工具基线与真实候选验证。**


---

# 8. 2026-10-03 下一阶段决策：从自建样例进入真实 OpenHarmony 组件

> 本节在 Step 1～7 已完成后新增。现在**不要继续机械增加 `strcpy/memcpy` 之类函数名**。MVP 已证明“扫描 → Finding → JSON/Markdown → 回归测试”能够运行，下一阶段必须验证这套框架在真实 OpenHarmony 组件上的可用性，并开始建立真实的构建、上下文和动态证据链。

## 8.1 为什么现在要切换阶段

当前最重要的已知事实是：

```text
2 个自建 C++ 样例
→ 扫描 28 行
→ 1 个 candidate
→ JSON/Markdown 输出正常
→ 4 个回归测试已存在
```

这证明了**工程骨架能运行**，但尚不能证明：

- 对 OpenHarmony 真实代码能稳定扫描；
- 当前规则的候选量是否可控；
- 候选是否主要来自注释、宏、包装函数或第三方代码；
- 能否拿到真实编译参数；
- 能否识别候选所在函数和真实上下文；
- 能否把某个候选放回原组件中构建和运行；
- ASan/UBSan 能否在真实组件路径中产生证据；
- 当前方案能否降低误报，而不只是“搜索危险函数名”。

因此下一阶段的核心问题从：

> “我们的 scanner 能不能跑？”

变成：

> “我们的 scanner 在一个固定版本、真实可构建的 OpenHarmony C/C++ 组件上，能否产生可调查候选，并把至少一个案例推进到上下文或动态验证？”

---

# 9. 下一阶段 Step 8～15

## Step 8：冻结当前 MVP，并结束 `feat/mvp-scanner` 这一开发阶段

### 目标

当前分支的任务已经从“写第一版扫描器”推进到“有状态、有统计、有双报告、有 safe/vulnerable 对照、有自动测试”。这已经达到一个自然的 Git 里程碑。

在进入真实 OpenHarmony 目标前，先做一次最终回归，然后将 PR #2 合并到 `main`。之后的新开发使用新的功能分支，避免一个分支无限承担所有功能。

### 本地最终回归

在 Ubuntu WSL 中：

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
source .venv/bin/activate

python -m unittest discover -s tests -v

python -m src.cli scan samples \
  --json-out outputs/reports/samples_report.json \
  --md-out outputs/reports/samples_report.md

git status
```

期望：

- 4 个回归测试通过；
- 扫描 2 个文件；
- 扫描 28 行；
- skipped source files 为 0；
- candidate findings 为 1；
- `git status` 中没有意外生成文件被跟踪。

### GitHub 操作

在 PR #2 中检查：

- Commits；
- Files changed；
- 是否仍然是 `feat/mvp-scanner → main`；
- 是否存在意外大文件、运行报告或 `.venv`。

确认后可以合并 PR #2。

### 合并后本地同步

```bash
git checkout main
git pull --ff-only

git branch -d feat/mvp-scanner
git checkout -b feat/openharmony-target-onboarding
```

> 如果 PR #2 尚未合并，则不要执行删除旧分支。  
> 新分支名称建议固定为 `feat/openharmony-target-onboarding`。

### 验收

- MVP 已进入 `main`；
- 本地 `main` 与 GitHub 同步；
- 新阶段在独立分支开发；
- 不在 `main` 上直接试验。

---

## Step 9：筛选 3 个真实 OpenHarmony C/C++ 候选组件

### 目标

**先选“能验证的组件”，再写更多分析代码。**

当前不应该直接下载全量 OpenHarmony，也不应该先假设某个组件一定适合。先列 3 个候选，实际探测：

1. 是否是 C/C++ 为主；
2. 是否存在明确输入处理逻辑；
3. 是否有 host build、单元测试或 fuzz target；
4. 是否能在 Ubuntu x86_64 上构建至少一个目标；
5. 是否依赖整个系统镜像/开发板；
6. 是否存在解析、长度、序列化、内存操作等适合首阶段研究的代码；
7. 仓库规模是否适合两周内理解；
8. 是否有公开历史安全修复可作为验证样本。

### 新建目标选择文档

建议新增：

```text
docs/targets/target_selection.md
```

内容使用表格：

```text
repo/component
language
repo URL
candidate commit
host build
existing tests
existing fuzz target
external input surface
dependency weight
historical security fix
estimated difficulty
decision
reason
```

### 选择原则

优先：

- C/C++；
- 解析器、媒体/文件格式、序列化、数据处理、网络/IPC 边界附近组件；
- 有测试入口；
- 能在 host 上构建；
- 依赖相对有限。

暂时避开：

- 必须完整系统镜像才能运行的组件；
- 第一天就必须开发板才能验证的目标；
- 超大仓库但没有可单独构建 target；
- 只有内核/驱动环境才能触发的路径；
- 需要大量自造 stub 才能勉强编译的组件。

### 止损条件

对一个候选最多先花约 1～2 小时做构建探测。

如果出现：

- 大量平台依赖；
- 无测试入口；
- 需要重写大量代码才能 host 编译；
- 依赖链无法快速定位；

则记录失败原因并切换到下一候选，不把一天耗在环境上。

### 验收

至少得到：

- 3 个候选；
- 每个候选都有 repo URL 和构建探测结果；
- 至少 1 个组件进入“主目标”；
- 至少 1 个保留为“备选目标”。

---

## Step 10：为主目标建立 TargetSnapshot v0

### 为什么做

从真实组件开始，任何 Finding 都必须知道它到底属于哪个版本。

不能再使用：

```text
“我扫描了 OpenHarmony 当前代码”
```

这种不可复现描述。

必须固定：

```text
repo + commit + source path + build config + scan scope
```

### 建议新增配置

```text
config/targets/<component>.yaml
```

第一版字段可为：

```yaml
target_id:
project: OpenHarmony
component:
repo_url:
commit:
branch_or_tag:
local_path:
language:
build_mode:
build_command:
test_command:
source_paths:
exclude_paths:
notes:
```

目前可以先手工维护 YAML，不要急着做数据库。

### 真实目标源码放在哪里

**不要把完整 OpenHarmony 目标源码放进本项目 Git 仓库。**

建议：

```text
/home/audit/openharmony-targets/<component>/
```

本项目只保存：

- URL；
- commit SHA；
- 构建命令；
- 配置；
- 小型、许可允许且确有必要的测试资产；
- 我们自己的分析代码。

### 固定版本命令

在目标仓库内记录：

```bash
git remote -v
git rev-parse HEAD
git status
git log -1 --oneline
```

将 commit 写进 target config。

### 验收

任何成员只看 target config，就能知道：

- 扫的是哪个仓库；
- 哪个 commit；
- 哪些路径；
- 用什么命令构建；
- 用什么命令测试。

---

## Step 11：先证明“原组件能正常构建和运行”

### 目标

在安全分析之前，先建立正常基线。

如果原组件自身都无法在当前环境正常构建，那么后面出现的错误无法判断是：

- 漏洞；
- 环境问题；
- 依赖缺失；
- harness 问题；
- 编译配置错误。

### 必须记录

- Ubuntu / Clang / GCC 版本；
- 目标 commit；
- 构建命令；
- 测试命令；
- 正常输入；
- 正常返回值；
- 构建耗时；
- 失败日志。

### 建议使用

```bash
/usr/bin/time -v <build command>
```

第一阶段不用做漂亮 Benchmark，只要开始保存：

- wall time；
- peak RSS；
- exit code。

### 通过条件

至少一个真实 target：

```text
clean checkout
→ build success
→ original/unit test success
```

### 不通过时

不要马上修改原组件代码让它“能编”。

优先：

1. 补真实依赖；
2. 找官方已有 host test；
3. 找已有 fuzz target；
4. 换组件。

---

## Step 12：在真实组件上同时跑“当前 scanner + 成熟工具基线”

### 为什么要双基线

我们的工具当前只是文本 candidate generator。

必须知道它相对于成熟工具到底增加了什么，而不是只展示：

> “我们也能找到 memcpy。”

### 当前 scanner

例如：

```bash
python -m src.cli scan /home/audit/openharmony-targets/<component>/<source-dir> \
  --json-out outputs/reports/<component>_candidate.json \
  --md-out outputs/reports/<component>_candidate.md
```

保存：

- scanned_files；
- scanned_lines；
- skipped_files；
- candidate count。

### 成熟工具基线

第一阶段根据组件实际构建方式，只选择 1～2 个，不同时折腾四套：

- Clang Static Analyzer / `scan-build`；
- clang-tidy；
- 若后续环境合适，再比较 CodeQL C/C++；
- fuzz 有现成入口时单独作为独立发现通道。

### 重要原则

成熟工具的告警和我们的 candidate **不能简单合并后当漏洞数**。

需要记录：

```text
source = mvp_text_rule | clang_analyzer | clang_tidy | fuzz | manual
```

### 验收

得到第一张真实目标扫描表：

```text
target commit
scanned files
scanned LOC
MVP candidate count
baseline warning count
scan time
skipped files
```

---

## Step 13：人工审核第一批真实候选，建立“误报原因字典”

### 目标

先审核少量候选，不追求一口气处理全库。

建议从真实扫描结果中选择前 10～30 条，逐条回答：

1. 这真的是函数调用还是注释/宏/声明？
2. 所在函数是什么？
3. 参数是什么？
4. destination 实际大小是什么？
5. length 从哪里来？
6. 调用前是否已有边界检查？
7. 上层调用者是否保证约束？
8. 外部输入是否可控？
9. 路径是否真实可达？
10. 即使出错，是否具有安全影响？

### 初始审核状态

建议增加 triage 分类：

```text
needs_context
likely_safe
interesting
duplicate
scanner_quality_issue
blocked
```

这不是最终漏洞状态，而是人工调查状态。

### 建立误报原因

例如：

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
```

### 为什么非常重要

下一阶段 AST/数据流功能应该针对**真实遇到的误报原因**开发。

不是：

> “因为架构图有 CFG，所以现在必须写 CFG。”

而是：

> “真实候选中 40% 因无法知道所在函数和 guard，所以先做函数上下文与 guard 抽取。”

这才是问题驱动开发。

### 验收

形成：

- 第一批人工审核记录；
- 真实误报原因 Top-N；
- 至少 1～3 个 `interesting` 或 `needs_context` 候选；
- 明确下一项程序分析能力为什么值得开发。

---

## Step 14：实现“函数上下文提取”，而不是立刻自研完整 CFG

### 这是下一项推荐代码功能

当前 Finding 只有：

```text
单行 evidence
function = None
```

真实审计远远不够。

下一项最有价值的代码能力是：

```text
candidate line
→ 找到 enclosing function
→ 保存函数名
→ 保存函数起止行
→ 保存候选前后上下文
→ 后续 AST / guard / dataflow 使用
```

### 实现策略

按目标组件环境选择：

#### 优先路径：有可靠编译参数

如果组件能生成可靠的编译命令：

```text
compile_commands.json
```

优先使用 Clang AST / tooling 获取：

- FunctionDecl；
- CallExpr；
- 参数；
- 类型；
- 源码范围。

#### 降级路径：编译参数暂时不完整

可使用 Tree-sitter 或其他轻量语法解析做：

- 函数边界；
- 函数名；
- 调用节点；
- 局部结构。

但必须在 Evidence 中标记：

```text
semantic capability = syntax_only
```

不能把语法解析结果说成完整 C++ 语义。

### 必须补的测试

至少增加：

- 注释里的 `strcpy(...)` 不应当作为真实 CallExpr；
- 标识符 `my_strcpy` 不误匹配；
- 跨行调用；
- 宏内调用；
- 同一函数两个候选；
- header 与 source；
- 解析失败时保持 candidate，但显式记录 unknown。

### 验收

至少让真实目标中的 Finding 从：

```json
{
  "function": null,
  "evidence": "memcpy(...)"
}
```

升级成可以表达：

```text
function
function range
call location
context snippet
parser status
```

---

## Step 15：选择一个候选进入 ASan/UBSan 验证闭环

### 第一目标不要直接追“0-day”

第一条真实验证链最好先采用：

- 公开历史已知修复前版本；或
- 我们能够明确控制输入的真实组件路径。

原因是先验证**系统能力**，不是赌第一天就发现新漏洞。

### 验证链

```text
Candidate
  ↓
确认所在函数和真实调用约定
  ↓
确认输入和边界条件
  ↓
尽量复用原组件测试 / fuzz 入口
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

### Sanitizer 构建目标

对可 host 编译的局部组件，可以尝试：

```text
-fsanitize=address,undefined
-fno-omit-frame-pointer
-g
```

但具体编译选项必须接入目标组件真实构建系统，不能为了让 PoC 崩溃而删除原始检查或重写核心逻辑。

### 结果状态

验证后只允许进入以下之一：

```text
validated
refuted
inconclusive
environment_blocked
harness_invalid
```

没有触发 ≠ 一定安全。

### 首条闭环的成功标准

至少有一条案例具备：

- 固定 commit；
- 原组件或足够保真的测试入口；
- 正常输入成功；
- 异常输入有明确 oracle；
- ASan/UBSan 或行为证据；
- 原始日志；
- 另一成员可复现；
- 明确说明哪些安全影响仍未证明。

---

# 10. 下一阶段建议的数据结构增量

在真实组件开始后，不要急着一次性实现完整 VulnerabilityCase。先增加三个很小但关键的数据对象。

## 10.1 TargetSnapshot v0

回答：

> “分析的是哪个真实版本？”

最少包含：

```text
target_id
repo_url
commit
component
build_command
test_command
scan_paths
tool_versions
```

## 10.2 CandidateTriage v0

回答：

> “这条 candidate 人工看过以后是什么情况？”

最少包含：

```text
candidate_id
triage_status
triage_reason
reviewer
notes
next_action
```

## 10.3 RuntimeEvidence v0

回答：

> “运行时到底观察到了什么？”

最少包含：

```text
target_id
candidate_id
build_command
run_command
input_hash
exit_code
sanitizer_type
summary
log_path
outcome
```

三个对象足够支撑下一阶段，不需要现在就上数据库或图数据库。

---

# 11. 未来 2～3 天的实际顺序

建议严格按下面的顺序推进，而不是同时开十个模块。

### 第 1 段：今天剩余时间

```text
回归测试
→ 合并 PR #2
→ 新建 target-onboarding 分支
→ 建 target_selection.md
→ 找 3 个候选组件
```

### 第 2 段：下一工作日上半天

```text
实际 clone 3 个候选中的主/备选
→ 构建探测
→ 跑原始测试
→ 固定第一个 TargetSnapshot
```

### 第 3 段：下一工作日下午

```text
当前 scanner 扫真实目标
→ 成熟工具基线
→ 审核首批 10～30 candidate
→ 统计最常见误报原因
```

### 第 4 段：随后一天

根据真实问题决定：

```text
如果最大缺口是“看不到函数”
→ 做函数上下文 / AST

如果最大缺口是“看不到长度来源”
→ 做局部数据流

如果已有高价值候选且组件可测试
→ 优先做 sanitizer harness 和验证
```

这意味着程序分析技术由真实候选推动，而不是按教材顺序堆功能。

---

# 12. 当前阶段的硬性止损规则

为避免 AI 写代码很快但项目失控，统一采用以下规则：

1. **不能构建的组件，不作为第一主目标长期死磕。**
2. **当前 scanner 再增加新的函数名之前，先说明它解决了哪类真实漏检。**
3. **没有真实候选驱动，不自研完整 CFG/CPG。**
4. **PoC/harness 必须尽量调用原组件代码，不复制核心函数重新写一份。**
5. **Sanitizer crash 必须确认栈帧来自目标组件，而不是 harness 自己。**
6. **未触发、环境失败、解析失败都记录为 unknown/inconclusive，不当作安全。**
7. **公开历史案例只证明能力，不能当成新发现。**
8. **未匹配到 CVE 不能自动标记 0-day。**
9. **每次 AI 直接修改 GitHub 远程分支后，本地继续前先 `git pull --ff-only`。**
10. **至少每完成一个稳定小闭环就 commit；不要攒几十个功能后一次性提交。**

---

# 13. 给 Codex 的下一轮任务模板

可以直接把下面内容交给 Codex，但要求它先读本文件和当前分支代码。

```text
先阅读 PROGRAM_STATUS.md、docs/roadmap.md 和当前分支实际代码。

当前 Step 1～7 已完成，不要重复实现 MVP 扫描器。

本轮目标不是增加更多危险 API 规则，而是进入真实 OpenHarmony 组件 onboarding。

请先完成：
1. 新建 docs/targets/target_selection.md 模板；
2. 设计 config/targets/<component>.yaml 的 TargetSnapshot v0 字段；
3. 不要虚构具体组件已经可构建；
4. 对所有“构建成功/测试成功”字段默认写 unknown，必须等待本地真实命令结果；
5. 不实现完整 AST/CFG/污点；
6. 不把 candidate 称为 vulnerability；
7. 为新增配置解析或数据结构增加最小单元测试；
8. 输出需要我在 Ubuntu WSL 本地执行的探测命令，并明确每条命令要记录什么结果。

完成后告诉我：
- 修改了哪些文件；
- 为什么这样设计；
- 本地需要执行哪些命令；
- 哪些结论仍然 unknown。
```

---

# 14. 当前最重要的一句话

> **MVP scanner 阶段已经完成。下一步不是把规则表做得更长，而是选定一个可构建、可测试、固定 commit 的真实 OpenHarmony C/C++ 组件，把“candidate → 上下文 → 原组件运行 → sanitizer/行为证据”这条链第一次跑通。九层架构继续作为最终方向，但当前两周路线只实现真实案例所需要的那一纵切面。**
