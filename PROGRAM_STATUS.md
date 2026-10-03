# PROGRAM_STATUS.md

> 项目：CyberSecurity-Innovation-Audit  
> 赛题方向：2026 OpenHarmony 开源代码漏洞挖掘  
> 更新日期：2026-10-03  
> 当前开发分支：`feat/mvp-scanner`  
> 当前 PR：#2 `feat: add MVP C++ dangerous call scanner`（目标分支：`main`，当前未合并）  
> 本文用途：作为 ChatGPT、Codex 和团队成员的统一进度说明。开始新一轮开发前，应先阅读本文，避免重复搭环境、误判已实现功能或跳过验证步骤。

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
    └── scanner.py

samples/
└── vulnerable/
    └── demo_overflow.cpp
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

当前 Finding 仍是第一版，下一阶段计划加入独立的 `status` 字段。

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
4. 命中后生成结构化 Finding

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
python -m src.cli scan samples/vulnerable --out outputs/reports/demo_report.json
```

已经实际运行成功，输出：

```text
[OK] scanned: ...
[OK] findings: 1
[OK] report: .../outputs/reports/demo_report.json
```

示例代码中的：

```cpp
strcpy(buf, input);
```

被识别为 1 个候选 Finding。

### 2.5 JSON 报告已经跑通

当前报告包含：

- target
- finding_count
- findings[]

每一条 finding 能输出规则、CWE、风险类别、位置、证据、解释和修复建议等字段。

### 2.6 .gitignore 已配置

项目根目录 `.gitignore` 已加入本地开发相关忽略项，包括：

- `.venv/`
- `__pycache__/`
- Python 编译缓存
- `outputs/reports/*.json`
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
下一步继续完善 MVP 基础闭环
```

---

# 4. 下一阶段：1～7 步详细开发计划

这一轮暂时**不拉完整 OpenHarmony、不做九层架构的全部模块**。先把 MVP 从“能找到一条 strcpy”提升为“具有基本工程形态的候选扫描工具”。

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

当前已有：

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
  "confidence": "candidate",
  "status": "candidate"
}
```

后续程序分析、运行验证和人工审核可以改变 status，而不用混淆 confidence。

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

1. 为 scanner 增加最小自动测试，固定当前行为
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

> **Ubuntu 22.04 WSL2、GitHub、Python/C++ 工具链与 ASan 已打通；第一个 C/C++ 文本候选扫描器已经在自建 vulnerable 样例上成功产生 1 个 JSON Finding；当前正在 `feat/mvp-scanner` / PR #2 上继续完善 MVP，下一步按本文 Step 1～7 增加状态字段、扫描统计、Markdown 报告和安全负例，再进入真实 OpenHarmony 组件。**
