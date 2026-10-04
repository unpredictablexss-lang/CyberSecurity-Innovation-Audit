# Historical 样本候选清单（多根因）

> 目的：把 OpenHarmony 第一方历史安全修复扩展成不同 root-cause group 的 benchmark 样本。
> 已落地样本见 benchmarks/historical/；每条样本先做 metadata（commit/文件/符号/根因），clone 大仓库做 replay 属于后续步骤。

## 已落地样本

| sample_id | 组件 | 根因组 | CWE | CVE | 状态 |
|---|---|---|---|---|---|
| c_utils-singleton-uaf-2026-01 | commonlibrary_c_utils | lifetime_uaf | CWE-416 | - | metadata + 已核实 commit |
| kernel_liteos_a-getgroups-oob-2025-03 | kernel_liteos_a | concurrency_race | CWE-125 | CVE-2025-20042 | metadata（runtime_replay=not_run） |
| communication_dsoftbus_null_deref_001 | communication_dsoftbus | null_deref | CWE-476 | CVE-2025-26690 | metadata + static replay 已验证（0 文本候选，miss） |

## 待扩展候选（来自 OpenHarmony 官方 2025-03 / 2025-07 安全公告）

以下按 root-cause group 分类，优先补足"类型多样性"（整数溢出 / 越界写 / 栈溢出 / 空指针 / double free），避免全是 UAF。

### 整数溢出（CWE-190）
- CVE-2025-0587 arkcompiler_ets_runtime（整数溢出）
- CVE-2025-20024 arkcompiler_ets_runtime（整数溢出）
- CVE-2025-22851 kernel_liteos_a（整数溢出）

### 越界写（CWE-787）
- CVE-2025-23420 / 22835 / 24309 / 23240 arkcompiler_ets_runtime（越界写）

### 栈溢出（CWE-121）
- CVE-2025-23234 / 22897 arkcompiler_ets_runtime（栈溢出）

### 空指针解引用（CWE-476）
- CVE-2025-26690 communication_dsoftbus（空指针）→ 已落地，见 benchmarks/historical/communication_dsoftbus_null_deref.json
- CVE-2025-21084 / 21097 / 22837 arkcompiler_ets_runtime（空指针）

### 类型混淆（CWE-843）
- CVE-2025-27536 arkcompiler_ets_runtime（类型混淆）

### 权限绕过（信息泄露）
- CVE-2025-21098 kernel_liteos_a（权限绕过）

### 内存泄露（CWE-401）
- CVE-2025-20011 communication_dsoftbus（内存泄露）

## 约束与下一步

1. **确定 commit**：公告给出 gitee PR 号；用 gitee `.patch`（`pulls/<id>.patch`）拿到 commit hash，再用 github 镜像 API（`api.github.com/repos/openharmony/<repo>/commits/<sha>`）确定父 commit 为 vulnerable 版本。
2. **clone 大仓库**：kernel_liteos_a / arkcompiler_ets_runtime / communication_dsoftbus 都是大仓库；`run_historical_benchmark` 需要本地 repo 含 vulnerable+fixed 两个 commit。浅 clone 两个 commit 即可（`git fetch --depth 1 <sha>` 两次）。
3. **样本优先级**：communication_dsoftbus 空指针（第一方、相对小、CWE-476 补类型多样性）> kernel_liteos_a 整数溢出（CWE-190）> arkcompiler 越界写（CWE-787）。
4. 样本少时不计算 Precision/Recall；先只报原始命中/overlap 计数。
