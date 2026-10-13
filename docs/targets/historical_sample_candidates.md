# Historical 样本候选清单（多根因）

> 目的：把 OpenHarmony 第一方历史安全修复扩展成不同 root-cause group 的 benchmark 样本。  
> 当前 PR #4 已落地 4 条样本；本文件只维护“已落地”和“后续候选”的状态，不把 historical replay 写成新漏洞发现。

---

## 已落地样本

| sample_id | 组件 | 根因组 | CWE | CVE | 状态 |
|---|---|---|---|---|---|
| `c_utils-singleton-uaf-2026-01` | `commonlibrary_c_utils` | `lifetime_uaf` | CWE-416 | - | metadata + commit / affected symbol 已核实 |
| `kernel_liteos_a-getgroups-oob-2025-03` | `kernel_liteos_a` | `concurrency_race` | CWE-125 | CVE-2025-20042 | metadata + static replay；runtime `not_run` |
| `communication_dsoftbus_null_deref_001` | `communication_dsoftbus` | `null_deref` | CWE-476 | CVE-2025-26690 | metadata + static replay；text scanner miss 记录为盲区 |
| `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02` | `arkcompiler_ets_runtime` | `oob_write` | CWE-787 | CVE-2025-23420 | metadata + static replay；用于检验 oob_write pattern 覆盖 |

当前 7 条样本覆盖 `lifetime_uaf` / `concurrency_race` / `null_deref` /
`oob_write` / `integer_overflow` / `type_confusion` / `permission_bypass`
七类 root-cause group。样本量仍不足以计算正式 Precision / Recall。

---

## 待扩展候选（后续 PR 再做）

以下候选只用于后续扩展 benchmark 类型多样性。进入样本集前必须先确认公开修复提交、父提交、affected file、affected symbol、CWE / root-cause group 与引用来源。

### 整数溢出（CWE-190）

- CVE-2025-0587 arkcompiler_ets_runtime（整数溢出）
- CVE-2025-20024 arkcompiler_ets_runtime（整数溢出）
- CVE-2025-22851 kernel_liteos_a（整数溢出）

### 越界写（CWE-787）

- CVE-2025-22835 / 24309 / 23240 arkcompiler_ets_runtime（越界写）
- CVE-2025-23420 已落地为 `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02`，不要重复加入同一根因组的近似样本。

### 栈溢出（CWE-121）

- CVE-2025-23234 / 22897 arkcompiler_ets_runtime（栈溢出）

### 空指针解引用（CWE-476）

- CVE-2025-26690 communication_dsoftbus 已落地为 `communication_dsoftbus_null_deref_001`
- CVE-2025-21084 / 21097 / 22837 arkcompiler_ets_runtime（空指针）

### 类型混淆（CWE-843）

- CVE-2025-27536 arkcompiler_ets_runtime（类型混淆）

### 权限绕过 / 信息泄露

- CVE-2025-21098 kernel_liteos_a（权限绕过）

### 内存泄露（CWE-401）

- CVE-2025-20011 communication_dsoftbus（内存泄露）

### UAF 候选池

- `kernel_liteos_a` UAF（CVE-2025-24298 / CVE-2025-27128）仍保留在候选池；当前 PR 不做，避免把样本扩展和运行时验证混在一起。

---

## 后续扩展约束

1. **先定 metadata**：公开来源、fixed commit、vulnerable parent、affected file、affected symbol、CWE、root-cause group 必须可追溯。
2. **再做 static replay**：只记录 commit 存在性、direct parent、changed files、symbol presence、candidate overlap。
3. **不做 PoC / exploitability**：本候选清单只服务 benchmark，不服务漏洞触发。
4. **不计算 Precision / Recall**：当前 7 条正样本只能报告 raw hit / miss / unknown / not_applicable。
5. **避免重复根因**：优先补当前缺失的 integer_overflow、type_confusion、permission/information-leak、stack_overflow，而不是继续堆 UAF。

## 2026-10-13 核验记录

CVE-2025-0587、CVE-2025-27536、CVE-2025-21098 已补齐 official advisory、merged
fix commit、vulnerable parent、affected file、vulnerable/fixed Git blob SHA-1、
source SHA-256、affected symbol 与 PR patch SHA-256。对应 manifest 已进入
`benchmarks/historical/`，逐项绑定位于 `benchmarks/historical/source_bindings/`，
可通过 `python -m scripts.verify_historical_source_bindings` 重新核验。

这三组记录是 historical benchmark evidence，不是新漏洞发现；其 patch-obligation
sidecar 在阅读修复后创建，因此标记 `development_participation=true`，不得伪装成
独立 holdout。
