# IPC 扫描器 v0.2：源码派生的入口/分发索引与实测覆盖（2026-10-10）

> 政策前提：见 `AGENTS.md` 的 **Competition deliverables — must produce** 章节。本文是**实测记录**，不是方案。
> 代码：`src/ohscanner/detectors/interface/entry_index.py`（新增）、`analysis.py`、`detector.py`。
> 度量：`research/experiments/interface/ipc/measure_entry_coverage.py`；原始 JSON 在 `outputs/reports/`（Git 忽略，可复跑）。
> **全文只回答「检测器够到哪些入口、还差在哪」；不构成漏洞、可达性、可利用性或分支影响结论；`validated_vulnerability` 恒为 0。**

## 0. 一句话结论

v0.1 的入口发现是**硬编码名字白名单**。v0.2 换成**源码派生的分发索引**（按签名识别 dispatcher，从函数指针表 / `switch` / `if` 恢复 code→handler 绑定，含跨文件 handler 与源码可证的服务委托一跳）。

在 10 个真实组件的**生产代码**上：入口 root 从**旧谓词 109** 提升到**源码派生 690**；历史 S2 修复对（按**历史修订**建索引，验收口径）58 条「样本×修订」记录中，**未触达 0 条**，其中 **33 条由源码派生的绑定支撑**、25 条仍**只能靠 `models.py` 里手写的名字**。

## 1. 运行状态

语料 `~/openharmony-audit/perf-corpus`（`--depth=1` 完整 blob，Git 外），已排除 `/test/`、`/unittest/`、`/fuzztest/`。

| 组件 | 固定提交 | 生产源文件 | 索引内 partial |
|---|---|---:|---:|
| communication_ipc | `bbb92dbb2f52` | 253 | 98 |
| inputmethod_imf | `7777cba9eb19` | 408 | 76 |
| multimedia_camera_framework | `085a5d0e2dc1` | 1105 | 173 |
| multimedia_player_framework | `9f9a285ff489` | 920 | 342 |
| notification_common_event_service | `aaaaf6d10aa8` | 137 | 16 |
| resourceschedule_background_task_mgr | `cff2ff475e38` | 188 | 26 |
| security_access_token | `17d88bfb36be` | 545 | 56 |
| telephony_call_manager | `6638d1b37f27` | 393 | 69 |
| update_updateservice | `e4942a33cc5e` | 218 | 31 |
| window_window_manager | `8b0d8fe1b973` | 1103 | 269 |
| **合计** | | **5270** | **1156** |

数据集 §3 的三处当代锚点与上表提交**逐字符一致**（`update_updateservice@e4942a33…`、`multimedia_player_framework@9f9a285ff489…`、`communication_ipc@bbb92dbb2f52…`），说明该语料就是数据集锚定的同一版本。

## 2. 分析覆盖（入口发现）

两个数字用**同一个** root 收集函数测出，唯一差别是入口索引开关，因此可比：「旧谓词」= v0.1 的 `OnRemoteRequest` / `*Inner` in `*Stub` / `models.py::service_entries`；「源码分发 root」= v0.2 的派生入口。

| 组件 | dispatcher（按签名） | 分发绑定 | 源码分发 root | 旧谓词 root | 未解析事务 |
|---|---:|---:|---:|---:|---:|
| communication_ipc | 35 | 19 | 26 | 7 | 0 |
| inputmethod_imf | 1 | 0 | 1 | 1 | 0 |
| multimedia_camera_framework | 4 | 7 | 11 | 4 | 0 |
| multimedia_player_framework | 31 | 37 | 64 | 29 | 62 |
| notification_common_event_service | 0 | 0 | 0 | 0 | 0 |
| resourceschedule_background_task_mgr | 0 | 0 | 1 | 1 | 0 |
| security_access_token | 12 | 12 | 27 | 18 | 0 |
| telephony_call_manager | 13 | 0 | 17 | 17 | 10 |
| update_updateservice | 2 | 20 | 22 | 2 | 0 |
| window_window_manager | 37 | 497 | 521 | 30 | 0 |
| **合计** | **135** | **592** | **690** | **109** | **72** |

恢复出的分发形状：`map_callable` 610、`switch_case_return` 506、`map_member_ptr` 155、`switch_case_call` 70、`if_code_return` 1；其中 12 条带预处理条件上下文。

**必须说清的边界**：

- 「按签名识别」覆盖 `OnRemoteRequest` / `OnRemoteMessageRequest` / `ProcessRemoteRequest` / **`IPCObjectStub::SendRequest`**。最后一个类名不含 `Stub`、函数名不叫 `OnRemoteRequest`，**只按名字必然漏**——它承载 B 思路 §6 的 `GET_PID_UID` 链。
- 入口被找到**不等于可达**。`IPCObjectStub::SendRequest` 里 `GET_PID_UID`、`GET_SESSION_NAME_PID_UID` 等分支位于 `#ifndef CONFIG_IPC_SINGLE` 内；索引只记录该条件（`conditional` 字段），不判定其在某个构建下是否可达。
- **分发器级 guard 不在 `IpcPolicy` 内**。`update_updateservice` 的 `UpdateServiceStub::OnRemoteRequest` 在分发前调用 `IsCallerValid()` 与 `IsPermissionGranted(code)`；把 handler 直接立为 root 会丢掉这一跳。处理方式是**改判而非抑制**：这类入口产生的候选归入 `AUTH-04 / ipc.auth.guard-coverage`（覆盖未证明），并附 `dispatch_binding` 义务，不报成 `AUTH-02`（缺授权）。

## 3. 根因相交：历史 S2 修复对的符号是否被触达

记录符号来自各样本的 **vulnerable/fixed 修订**，因此正确的验收口径是按**历史修订**建索引（源码取自 `~/openharmony-audit/ipc-research/pairs/<id>/`）。比对为类名精确（`Class::Method`，容忍命名空间前缀）——只比方法名会把无关类误判为同一符号。

### 3.1 历史修订（验收口径）

**58 条「样本×修订」记录：源码派生 33、仅靠硬编码白名单 25、未触达 0。**

即：历史样本的入口覆盖里，**43%（25/58）完全没有源码证据支撑，只因为 `models.py` 里写死了那个名字**。典型：

- `background-470` 的 `BgContinuousTaskMgr::RequestBackgroundRunningForInner`——签名是 `(const sptr<ContinuousTaskParamForInner>&)`，既不是 parcel 形状也不是 stub 成员，其 dispatcher 是 **IDL 生成物、不在仓库内**，源码里找不到任何入口证据；
- `cve-2025-26691` 的 `CallManagerService::{StartRtt,StopRtt,GetImsConfig,SetImsConfig,GetImsFeatureValue,SetImsFeatureValue,SetCameraZoom}`——全部来自 `service_entries` 手写清单；
- `cve-2022-38700` 的 `HCameraService::CreateCameraDevice`、`cve-2024-0285` 的 `HitraceInvoker::TraceServerReceieve`——同样只在 `models.py` 里。

**`TraceServerReceieve` 在 `communication_ipc` 现行代码里根本不存在**（`transport_entries` 是个失效条目）；`security_access_token` 的 `PrivacyManagerStub::*Inner` 在 HEAD 只存在于测试文件。手工白名单会随代码演进静默失效，这正是 v0.2 要替换它的原因。

### 3.2 当代 HEAD（参考，不是验收口径）

29 条记录符号：源码派生 10、仅靠硬编码白名单 6、未触达 13。未触达的多数**并非检测器缺陷**，而是历史符号已不在现行代码中（`DisplayManagerStub`、`PlatformCallbackStub` 在 HEAD 完全不存在；`PrivacyManagerStub::*Inner` 只剩测试）。此节仅用于观察符号是否还在 HEAD 里。

## 4. 端到端候选增量（检测器级，同一语料）

`run_reviewed_detectors` 跑真实组件，只切换入口索引开关：

| 组件 | 旧谓词 | 源码分发入口 | 说明 |
|---|---:|---:|---|
| update_updateservice | 0 | **2** | `DoUpdateStub`（code 5）、`FactoryResetStub`（code 18），均归 AUTH-04 |
| communication_ipc | 18 | **25** | +2 AUTH-02、+5 CAP-01 |
| telephony_call_manager | 2 | **3** | +1 AUTH-02 |
| security_access_token | 20 | 20 | 新 root 未落在策略内敏感调用上 |
| multimedia_camera_framework | 9 | 9 | 同上 |
| notification_common_event_service | 0 | 0 | 组件内无 dispatcher 源码（IDL 生成） |

增量不大是**如实结论**：入口覆盖提升主要在「能看见」上，而不是「多报」上。另外 `multimedia_player_framework` 有 **62 条事务码未解析**（case 值来自未在语料内的枚举/宏），属于明确的覆盖缺口。

**服务委托边**（`DelayedSingleton<T>::GetInstance()->Method` 等）已实现并按源码可证的接收者解析：`telephony_call_manager` 唯一绑定 452 处、camera 137、updateservice 28——但**在当前测得的组件上候选增量为 0**。对象宏别名（`#define X DelayedSingleton<T>::GetInstance()`）全语料仅 1 处，因此该边实际只靠显式 `GetInstance()` 形式起作用。

## 5. 顺带修掉的三个真缺陷（都会让 v0.1 在真实组件上失真）

1. **`required_facts = ()` 让一个 `.ts` 文件废掉整个组件。** runner 因而不按语言过滤，检测器把 `not_run` 的 ArkTS 声明文件当成失败 → 整体返回 `blocked` 且 **findings 为空**。真实 OpenHarmony 组件几乎必带 ArkTS 声明，所以 v0.1 在真实组件上**从来拿不到任何 findings**。已限定在该检测器声明的语言内。
2. **`ENGINE_CHECK(cond, return ret, "msg")` 让函数解析失败。** 宏实参里嵌 `return` 语句，Tree-sitter 报 ERROR，`analysis.py` 随即丢弃整个函数。已加等长的私有规范化（把该实参替换为 `0` 并补空格、保留换行与全部字节偏移）；全语料 2662 个 partial 文件中因此可救回 **281 个（10.6%）**。代价：宏内提前返回不进 CFG，已记为限制。
3. **`(this->*(iter->second))(...)` 让 dispatcher 自己解析失败。** 原规范化只认 `(this->*IDENT)`，认不出目标是表达式；连**旧谓词都立不起 `UpdateServiceStub::OnRemoteRequest` 这个 root**（实测旧谓词 root 从 1 变 2）。已按两种写法分别处理，均保持字节偏移不变。

另修 `entry_index._ALIAS_PATTERNS` 的 `^::?` 锚定错误（`::?` 是「必须有第一个冒号」），它使对象宏别名表**恒为空**。

## 6. 仍未做到（如实列出）

- **3/10 组件的 dispatcher 源码不在仓库内**（`notification_common_event_service`、`resourceschedule_background_task_mgr`、`inputmethod_imf` 的部分入口）：IDL 生成。这类组件的入口**无法从源码发现**，只能沿用弱证据（见 §3.1 的 25 条）。
- **72 条事务码未解析**（`multimedia_player_framework` 62、`telephony_call_manager` 10）：case 值来自语料内未定义的枚举/宏，记为 `unresolved`，不静默丢。
- **成员函数指针的目标无法从 AST 恢复**：`->*` 在 Tree-sitter 里是 ERROR，索引靠「干净的 `map.find(code)` 节点 + 函数体字节级 `->*` 引用」确认分发，属于私有语法模型，不是编译器语义。
- **没有宏展开、重载解析或虚调用证明**；虚接口实现只以 `virtual_override` 弱档记录，多候选即标 `ambiguous_virtual_override` 不绑定。
- **本报告的分母是「入口数」，不是「漏洞数」**，不能反推召回率或检出率。

## 7. 复现

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit-b
.venv/bin/python -m unittest discover -s tests -q      # 236 tests（218 既有 + 18 新增）

.venv/bin/python research/experiments/interface/ipc/measure_entry_coverage.py \
  --json outputs/reports/entry_coverage.json \
  --md   outputs/reports/entry_coverage.md
```

历史修订验收需要 `~/openharmony-audit/ipc-research/pairs/`（Git 外）；缺失时该节标为不可用，不会静默跳过。
