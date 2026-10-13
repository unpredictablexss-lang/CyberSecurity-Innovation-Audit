# 接口线 v0.4：有界宏展开的实测（2026-10-11）

> 本报告回答两个问题，并按数据集 §8.1 的要求把「运行状态 / 分析覆盖 / 结果」分开写，
> 不混成一个数：**（一）移植 `cpp_macros.py` 到底改善了哪些可量化的东西；（二）它有没有
> 改变候选集。** 本报告的分母是**宏调用与文件**，不是漏洞数，**不能反推召回率**。
> `validated_vulnerability = 0`。

## 1. 背景与两个待验证的收益

round1 分支（`draft/oh-interface-detectors-round1`）的 `cpp_macros.py` 是 v0.2 基线唯一没
吸收的部件。决定移植它时，预期它同时改善两件事：

1. **解析覆盖**：宏实参里带语句（`ENGINE_CHECK(cond, return ret, "msg")`）会让 Tree-sitter
   解析失败，展开后函数体可以被正常解析。
2. **假阴性来源「guard 藏在宏里」**：`analysis.normalize_syntax` 能中和带语句的宏实参让文件
   解析过去，但**宏体内部**的 `return` 守卫在解释器眼里不存在。若该守卫是授权检查，
   AUTH-02/AUTH-03 就会报告一条**源码其实守住了**的未授权路径——这是**假阳性**方向，
   赛题对误报负向扣分。

本报告的价值主要在于**如实报告第二个收益在本语料上落空**，并把它与「被我们自己的拒绝
语义挡住」这一竞争解释**分开测量**。

## 2. 运行状态

- 语料：`~/openharmony-audit/perf-corpus` 10 个真实组件，只取生产代码
  （排除 `/test/` `/unittest/` `/fuzztest/`），共 **5,270** 个 C/C++ 单元。
- 工具：`research/experiments/interface/ipc/measure_macro_expansion.py`，纯本地静态分析，
  无网络、无目标执行、不导入任何外部扫描器或历史标签。
- 产物：`outputs/reports/macro_expansion.json` / `.md`（生成物，不入库）。
- 10 个组件全部跑完并产出报告，无失败、无 blocked。

## 3. 分析覆盖

### 3.1 逐组件

| 组件 | 单元 | 应用展开的文件 | 展开调用 | 其中带控制流 | **引入 modelled guard** | 完整解析 before→after | 丢弃的展开 | 候选 off/on |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| communication_ipc | 253 | 53 | 1,009 | 406 | **0** | 161 → 167 | 3 | 11 / 11 |
| inputmethod_imf | 408 | 19 | 550 | 242 | **0** | 357 → 362 | 2 | 4 / 4 |
| multimedia_camera_framework | 1,105 | 300 | 3,532 | 2,146 | **0** | 955 → 972 | 0 | 9 / 9 |
| multimedia_player_framework | 920 | 15 | 102 | 0 | **0** | 734 → 734 | 3 | 23 / 23 |
| notification_common_event_service | 137 | 10 | 58 | 5 | **0** | 121 → 121 | 0 | 0 / 0 |
| resourceschedule_background_task_mgr | 188 | 6 | 63 | 52 | **0** | 162 → 163 | 0 | 2 / 2 |
| security_access_token | 545 | 172 | 6,126 | 376 | **0** | 496 → 496 | 14 | 20 / 20 |
| telephony_call_manager | 393 | 5 | 88 | 0 | **0** | 324 → 324 | 0 | 2 / 2 |
| update_updateservice | 218 | 53 | 448 | 180 | **0** | 195 → 196 | 0 | 2 / 2 |
| window_window_manager | 1,103 | 158 | 740 | 238 | **0** | 879 → 932 | 7 | 15 / 15 |
| **合计** | **5,270** | **791** | **12,716** | **3,645** | **0** | **4,384 → 4,467** | **29** | **88 / 88** |

「引入 modelled guard」的定义：该次展开产生的文本里出现
`IpcPolicy.boolean_permissions | result_permissions` 中的任一被调函数名
（`CheckPermission` / `VerifyPermission` / `CheckCallerPermission` / `VerifyAccessToken` /
`VerifyNativeToken`）。这是**唯一**能让一次展开改变候选集的条件。

### 3.2 收益 ①：解析覆盖确实改善，但幅度小

完整解析 **4,384 → 4,467（+83，+1.9%）**。改善集中在 `window_window_manager`（+53）与
`multimedia_camera_framework`（+17）。

**覆盖单调不减**，这是被实测逼出来的设计约束：一个在 A 上下文成立的宏在 B 上下文可能是
胡话，实测有 14 个文件（`security_access_token`）展开后反而解析不动。因此解释器里加了一道
闸门——**展开若把一个原本可解析的文件变成 partial，该次展开被丢弃**
（`expansion_worsened_the_parse`，全语料 29 次）。所以 `complete_parses` 只可能不降。

### 3.3 拒绝分布（诚实边界的一部分）

被拒绝的理由（宏原样保留）：`variadic_stringify_or_token_paste` 占绝对多数
（全语料 91,189 次），其余为 `ambiguous_definition_variants`（9,736，同一宏在多个文件里
定义不同）、`conditional_definition_requires_build_profile`（4,248）。

整文件回退（致命）65 次：`expansion_worsened_the_parse` 29（即上表的「丢弃」列）、
`raw_string_tokenization_not_supported` 13、`source_local_undef_not_supported` 23。

目录预算为 400 源 / 6 MB，`inputmethod_imf`、`multimedia_camera_framework`、
`multimedia_player_framework`、`security_access_token`、`window_window_manager` 5 个组件
因此**截断**（目录里只有前 400 个源文件，头文件优先）。未被编入目录的宏只是保持不展开，
退化为展开前的行为。

## 4. 收益 ②：候选集增量**恰好为 0**，且原因可测

10 个组件逐个以 `IpcPolicy(expand_macros=False)` 与 `=True` 各跑一遍完整解释器：
**88 → 88**，**没有任何一条规则计数变化**（`by_rule` 为空）。

归因不是推测，是同一个脚本直接数的：12,716 次展开里 **0 次**引入 modelled guard。

### 4.1 竞争解释：「是不是被我们自己的拒绝语义挡住了？」

这是必须排除的解释，因为 `variadic_stringify_or_token_paste` 是最高频的拒绝理由，而
OpenHarmony 自己的错误检查宏**恰恰是变参的**。如果被拒绝的定义里提到了 modelled guard
被调函数，那么收益可能只是**藏在拒绝后面**而非不存在。

实测（报告中 `refusal_cost` 一节）：

> **被拒绝的宏定义 314 个，其中提到 modelled guard 被调函数的：0 个。**

逐个组件：50 / 10 / 33 / 10 / 14 / 31 / 34 / 3 / 39 / 90，全部为 0。

所以结论是**语料里真的没有**「宏里藏授权 guard」这个模式，而不是它藏在我们拒绝的宏里。
反过来说，OpenHarmony 的变参宏是**日志与错误码检查**（`CHECK_AND_RETURN` 一类），其守卫
条件是**错误码**而不是**权限**——这对 `IpcPolicy` 不构成授权事实，因此展开与否不改变
候选。这也解释了 3,645 次「带控制流」的展开为什么一次都没落到 modelled guard 上：
宏里的 `return` 是真的，但它是错误处理，不是授权。

## 5. 与入口索引（v0.2）的正交性：实测 10/10 零变化

移植时留下一处**未被修掉**的隐患，本报告把它测掉了：`analysis.py` 解析的是**展开后**文本，
而 `entry_index.py` 解析的是**原始**文本。如果某个宏展开改了类名或 dispatcher 的 owner
（例如 `#define Stub FooStub` 这类对象宏），两份解析就会不一致，而 analyses 侧可能
**静默丢掉一个由分发派生的 root**。

探针 `research/experiments/interface/ipc/probe_entry_index_expansion.py` 在 10 个组件上
同时建两份 `EntryIndex` 并比对 `root_bindings()` 与分发边：

| 组件 | root before→after | 丢了 | 分发边 before→after | 丢了 |
|---|---:|---:|---:|---:|
| communication_ipc | 19 → 19 | 0 | 19 → 19 | 0 |
| inputmethod_imf | 0 → 0 | 0 | 0 → 0 | 0 |
| multimedia_camera_framework | 7 → 7 | 0 | 8 → 8 | 0 |
| multimedia_player_framework | 36 → 36 | 0 | 145 → 145 | 0 |
| notification_common_event_service | 0 → 0 | 0 | 0 → 0 | 0 |
| resourceschedule_background_task_mgr | 0 → 0 | 0 | 0 → 0 | 0 |
| security_access_token | 12 → 12 | 0 | 12 → 12 | 0 |
| telephony_call_manager | 0 → 0 | 0 | 3 → 3 | 0 |
| update_updateservice | 20 → 20 | 0 | 22 → 22 | 0 |
| window_window_manager | 497 → 497 | 0 | 497 → 497 | 0 |

**10 个组件、0 增 0 减。**（表中的绝对数是该索引 `root_bindings()` 的条数，用于**自身
前后对比**；它与 §22 报告的入口覆盖口径不同，不要并排引用。）展开最多的
`security_access_token`（186 个文件）与 root 最多的 `window_window_manager`（497 条）
都零变化。**该隐患在本语料上为空集**——不是说它不存在，只是在本语料上没有触发；
它仍是设计上耦合 `analysis` 与 `entry_index` 的一处已知点。

## 6. 结论

| 预期收益 | 是否兑现 | 证据 |
|---|---|---|
| ① 解析覆盖 | **兑现，但小** | 完整解析 +83（+1.9%），单调不减，29 次为保护解析而丢弃 |
| ② 关掉「宏里藏 guard」假阴性 | **本语料未兑现** | 12,716 次展开中 0 次引入 modelled guard；314 个被拒绝定义中 0 个提到 modelled guard；候选集 88 → 88 零变化 |

**保留这个模块的理由不是「它找到了东西」，**而是：

1. 它把一类**会让源码已守住的路径被误报为未守卫**的假阳性变成结构性不可能。测试
   （`tests/test_ipc_macros.py::IntegrationTests`）证明机制在模式出现时有效：关闭时报
   `ipc.auth.missing`、开启不报、**去掉宏的控制组仍然报**（否则一个「干脆不再报告」的
   实现也能通过前一条）。
2. 它让私有解析覆盖**单调不减**（有闸门保证，不是靠运气）。
3. 拒绝语义是**显式且可数的**：什么没展开、为什么没展开，都进报告而不是被默认为「没有」。

**本轮没有产生任何新候选，也没有删掉任何旧候选**（88 → 88 逐组件核对）。
`validated_vulnerability` 仍为 0。

## 7. 复现

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit-b
# 全量 10 组件：解析覆盖 + 展开计数 + 拒绝成本 + 候选增量（约 6 分钟）
.venv/bin/python research/experiments/interface/ipc/measure_macro_expansion.py \
    --json outputs/reports/macro_expansion.json \
    --md   outputs/reports/macro_expansion.md
# 与入口索引的正交性探针
.venv/bin/python research/experiments/interface/ipc/probe_entry_index_expansion.py
# 语义与集成测试
.venv/bin/python -m unittest tests.test_ipc_macros -v
```

## 8. 未做到与未证明

- `#include` **从不跟随**：目录是「本次扫描看得见的源码」里收集的 `#define`，不是
  include 解析。头文件在预算内优先编入，但预算外与仓库外的头文件不参与。
- **条件定义只记录不选择**：`#ifdef FEATURE` 下的定义按条件拒绝，不假设 FEATURE 已开。
  唯一例外是包含卫（`#ifndef FOO_H` / `#define FOO_H`），它是语法模式可证的、不选择任何
  东西，因此不记为构建条件——否则几乎每个头文件宏都会被拒。
- **变参 / 字符串化 / token 粘连 / 冲突定义变体一律拒绝**，不猜。变参类占拒绝的绝大多数。
- **宏体内部的守卫若调用不在 `IpcPolicy.boolean_permissions | result_permissions` 内**
  （例如 `IsCallerValid`、`IsPermissionGranted`），展开后依旧不构成授权事实。那部分不确定性
  走既有的 `dispatch_binding` 义务，**不假装已解决**。
- 本报告的全部数字是**静态分析产物**，不含动态验证；没有任何一条候选因此升级。
- 语料是 10 个组件，不是全仓；10/10 的零变化是**语料事实**，不是普遍保证。

## 9. 相关

- 代码：`src/ohscanner/detectors/interface/cpp_macros.py`（round1 移植，含两处刻意偏离）
- 集成：`src/ohscanner/detectors/interface/analysis.py`、`models.py`、`detector.py`
- 测试：`tests/test_ipc_macros.py`（23 项）
- 前序：`docs/research/ipc_scanner_v0_2_entry_coverage_2026-10-10.md`、
  `docs/research/ipc_scanner_v0_1_2026-10-10.md`
- 方法卡：`research/methods/interface/IPC_METHOD_CARD.md`（v0.4 一节）
