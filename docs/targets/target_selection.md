# OpenHarmony 真实目标组件筛选记录

> 目的：在进入真实 OpenHarmony 源码前，先用统一标准筛选 3 个候选组件，避免一开始就下载/编译全量 OpenHarmony，或把大量时间耗在无法构建、无法验证的目标上。
>
> 当前状态：尚未确认任何真实组件可构建；本文件只是筛选模板和记录表。任何 `build` / `test` / `fuzz` / `validated` 字段，在本地实际命令运行前都必须保持 `unknown`。

---

## 1. 使用原则

当前项目已完成 MVP 文本候选扫描器，但它只在自建 `samples/` 上验证过。下一阶段不是继续堆更多危险函数名，而是选择一个真实、固定 commit、可构建、可测试的 OpenHarmony C/C++ 组件，跑通：

```text
真实 repo + commit
  ↓
原组件构建/测试
  ↓
MVP candidate scan
  ↓
成熟工具基线
  ↓
人工审核候选
  ↓
函数上下文/guard/容量关系
  ↓
ASan/UBSan 或行为验证
  ↓
VulnerabilityCase / 反证 / unknown
```

目标选择优先级：

1. 能在 Ubuntu x86_64 / WSL2 上构建或至少运行 host test；
2. C/C++ 为主，有真实输入处理逻辑；
3. 有现成单测、fuzz target 或可复用测试入口；
4. 依赖不至于必须先编译完整系统镜像；
5. 存在解析、长度、内存复制、序列化、IPC 参数、文件格式等值得审计的代码；
6. 有公开历史修复、commit 或 issue 可作为能力回放样本更好。

暂时不优先：

- 必须开发板或完整镜像才能启动的路径；
- 只能在 ARM 目标环境运行、host 侧完全不可测的组件；
- 仓库巨大但没有清晰 build/test target；
- 需要大量手写 stub 才能“勉强”编译的组件；
- 只有理论攻击面、没有合法输入入口的代码。

---

## 2. 候选组件总表

> 填表时不要凭印象写“能构建”。只有执行过命令并保存日志，才能从 `unknown` 改成 `yes` 或 `no`。

| ID | repo / component | language | repo URL | branch / tag | commit | local path | host build | existing tests | fuzz target | input surface | dependency weight | historical security fix | decision | reason |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| T1 | TBD | C/C++ | TBD | TBD | TBD | TBD | unknown | unknown | unknown | unknown | unknown | unknown | candidate | 待调研 |
| T2 | TBD | C/C++ | TBD | TBD | TBD | TBD | unknown | unknown | unknown | unknown | unknown | unknown | candidate | 待调研 |
| T3 | TBD | C/C++ | TBD | TBD | TBD | TBD | unknown | unknown | unknown | unknown | unknown | unknown | candidate | 待调研 |

---

## 3. 单个候选组件调查卡

复制本节，为每个候选组件建立一张卡。

### Target ID

```text
TBD
```

### 组件基本信息

- repo / component: TBD
- repo URL: TBD
- upstream source: official OpenHarmony / mirror / other
- branch / tag: TBD
- commit: TBD
- local path: `/home/audit/openharmony-targets/<component>`
- language: C/C++ / mixed / unknown
- selected source paths: TBD
- excluded paths: TBD

### 为什么选择它

需要说明：

- 是否处理外部输入；
- 是否有内存/长度/解析/序列化逻辑；
- 是否和赛题重点漏洞类型相关；
- 是否适合两周内完成候选到验证闭环。

### 构建与测试探测

实际命令记录：

```bash
# example only; replace with actual commands
git remote -v
git rev-parse HEAD
git log -1 --oneline

# build command
# test command
```

结果：

- build status: unknown
- test status: unknown
- build log path: TBD
- test log path: TBD
- build time: TBD
- peak memory: TBD
- failure reason if any: TBD

### MVP scanner 结果

命令模板：

```bash
python -m src.cli scan /home/audit/openharmony-targets/<component>/<source-dir> \
  --json-out outputs/reports/<component>_candidate.json \
  --md-out outputs/reports/<component>_candidate.md
```

记录：

- scanned files: TBD
- scanned lines: TBD
- skipped files: TBD
- candidate findings: TBD
- top rule IDs: TBD
- notes: TBD

### 成熟工具基线

第一阶段只选 1～2 个工具，不要同时折腾四套。

- clang-tidy: unknown
- clang static analyzer / scan-build: unknown
- CodeQL: not evaluated
- existing fuzz: unknown

记录：

- tool command: TBD
- warnings count: TBD
- useful warnings: TBD
- logs: TBD

### 人工审核摘要

首批候选建议审核 10～30 条。

| candidate id | location | rule | triage status | reason | next action |
|---|---|---|---|---|---|
| TBD | TBD | TBD | unknown | TBD | TBD |

Triage status 可选：

```text
needs_context
likely_safe
interesting
duplicate
scanner_quality_issue
blocked
```

误报原因可选：

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

### 是否进入下一阶段

- decision: candidate / primary_target / backup_target / rejected
- reason: TBD
- next action: TBD

---

## 4. 本阶段验收标准

完成本文件第一轮调研后，至少应得到：

1. 3 个候选组件；
2. 每个候选有 repo URL、branch/tag、commit 或待确认原因；
3. 每个候选有 host build / test / fuzz 的初步探测结果；
4. 至少 1 个主目标和 1 个备选目标；
5. 不把任何 `unknown` 写成 `yes`；
6. 不把扫描候选写成漏洞；
7. 对失败构建保留日志与失败原因。

下一步不是直接写漏洞报告，而是对主目标建立 `config/targets/<component>.yaml`，再开始真实扫描和人工审核。
