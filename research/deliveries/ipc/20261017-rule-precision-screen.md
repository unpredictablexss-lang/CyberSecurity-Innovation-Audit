# 交付项 11：把 AUTH-01 的精度筛查原样套在每一条会响的规则上

> 交付项 10 §6 只筛了 `ipc.relay.descriptor-boundary` 一条规则，而且当时只用
> `symbol` 与 `message` 里的 `path=`，所以判决必须另读 pinned blob。本项把同一套模式
> 无条件套到**全部 6 条会响的规则**上，并把"读过的那一版源码"变成候选自带的字段。

## 0. 一句话结论

179 条候选全部过同一套筛查：**23 行命中 4 种模式（12.9%）**。逐行读源后，
**12 行可用报告自身字段判定为"输出缺陷"**——8 行把**校验调用本身**当成"未被校验的
handler"（message 点名的 handler 就是 `EnforceInterfaceToken` / `CheckPermission` /
`EnforceInterceToken` / `CheckCurrentDescriptor`），1 行在自己的 `path=` 里记下了它声称
缺失的那次校验，1 行记下了它声称缺失的那两个上下界，1 行（宏写法）与 1 行（同文件一跳）
在 pinned 源码里确有校验而 `path=()` 为空。`ipc.auth.missing` 21 条**零命中**。
剩下 11 行分属 plausible（3）/ 构建配置依赖（4）/ 覆盖陈述（1）/ 不自明为错（2）/ unknown（1）。

本项**没有**改检测器、**没有**改任何候选、**没有**删除任何负结果、
**0 条 confirmed**、`validated_vulnerability` 仍为 0。

## 1. 为什么同一套模式能套到所有规则上

两条报告自身的事实：

1. **`path=` 的格式统一**：11 条规则的每条候选，`message` 都带
   `path=((line, 'cond'), ...)`，空时为 `path=()`。179 条候选里共 591 条 path 条件，
   形状实测见 §3.2。所以不依赖任何规则专有语法的模式可以统一适用。
2. **每条候选都带结构化 `excerpt`**：`{start_line, end_line, blob_oid, lines:[{number,
   text, candidate}]}`——**报告产出所用那一版**上的源码窗口。本项把 179 条的
   `excerpt.blob_oid` 逐条与 `git rev-parse <commit>:<path>` 比对：
   **179 条全部相等，0 条不符，0 条未能比对**。于是"读的是报告自己钉住的那一版"
   是被核对过的，不是假设的。

5 条沉默规则（caller-class / identity-domain / service-identity / request-identity /
position-underflow）没有候选可筛，故本项的覆盖是 **6/11 条规则、179/179 条候选**。

## 2. 四种模式（判据只用报告自身字段）

| 模式 | 判据 | 是 / 不是 |
|---|---|---|
| `empty_path` | `message` 声称有路径，却记 `path=()` | **不是**误报数，是分流信号（§4） |
| `line_is_guard` | 被标记行的**原文**是一次校验调用——原文取自候选自己的 `excerpt`，不查符号表 | 不需要第二个查找 |
| `enforced_path` | 记下来的 path 里有一条**点了校验调用名字**且成立的条件 | 规则自己记下"边界被强制过" |
| `bound_recorded` | path 里出现了 `message` 声称缺失的那个比较，且操作数就是它点名的那个 | — |

`ENFORCE = /(Check|Enforce|Verify|Validate)[A-Za-z]*(Descriptor|InterfaceToken|Token|Permission)/`
逐字抄自 `auth01_precision_probe.py`，两条筛查不会各自漂移。

`bound_recorded` 的判据是"点名操作数"：**早先版本搜整条 message，而 "boundary" 里含 "bound"**，
于是两条 path 里记着 `uid < 0 => False` 的 AUTH-01 行误命中了一个关于拷贝长度的模式。
改为 `BOUND_CLAIM = /copy length (\w+) lacks .*bound/`，并要求那个比较发生在**被点名的
操作数**上，该类误命中归零。

**模式命中不是判决。** 每一行都对着它自己的 pinned `excerpt` 读，一行的判决只写它那一行。

## 3. 全量结果

### 3.1 6 条会响的规则

| 规则 | 候选 | 零模式 | 命中模式 -> 条数 | 命中合计 |
|---|---:|---:|---|---:|
| `ipc.relay.descriptor-boundary` (AUTH-01) | 103 | 90 | `empty_path` 4；`empty_path`/`line_is_guard` 4；`line_is_guard` 4；`enforced_path` 1 | **13** |
| `ipc.capability.export` (CAP-01) | 44 | 38 | `empty_path` 2；`enforced_path` 4 | **6** |
| `ipc.auth.missing` (AUTH-02) | 21 | **21** | （无） | **0** |
| `ipc.auth.guard-coverage` (AUTH-04) | 8 | 7 | `empty_path` 1 | **1** |
| `ipc.auth.object-owner` (AUTH-03) | 2 | 0 | `enforced_path` 2 | **2** |
| `ipc.parcel.copy-range` (DATA-01) | 1 | 0 | `bound_recorded` 1 | **1** |
| **合计** | **179** | **156** | | **23** |

条数是行数，不是候选数：一条候选可同时命中两个模式（4 行 AUTH-01 同时
`empty_path` 与 `line_is_guard`）。

### 3.2 591 条 path 条件的形状（回答"`path=()` 是不是记录器漏了"）

| 形状 | 条数 | 例子 |
|---|---:|---|
| 其他（含比较、`switch entry`、`preproc #ifdef` 等） | 571 | `descriptor != token => False` |
| 调用 | 20 | `CheckGetSAPermission(systemAbilityId) => True` |
| **宏形标识符** | **0** | — |

记录器**会**把字面 `if` 写的描述符比较记进 path，例如同一组件的两条同形状站点：

```
'descriptor != token => False'
'token.compare(IConnectCallback::GetDescriptor()) != 0 => False'
```

而 `pasteboard_disposable_observer_stub.cpp:48` 上面 36/41/45 三行守卫写成宏
`PASTEBOARD_CHECK_AND_RETURN_RET_LOGE(...)`，该行的 `path=()` 就是空的。
591 条里 0 条宏形条件，与"路径记录器不记宏中介的守卫"一致——**这是相容，不是证明**。

## 4. `empty_path` 的口径修正

交付项 10 §6 把 `empty_path` 仅当分流信号，理由当时是"读到的前几行 `path=()` 都准确"。
本项把**全部 11 行**读完：**10 行准确，1 行不准确**。

| 规则 | 行 | `path=()` 是否准确 | 依据 |
|---|---|---:|---|
| AUTH-01 | `system_ability_load_callback_stub.cpp:36`、`system_process_status_change_stub.cpp:39`、`system_ability_status_change_stub.cpp:46`、`system_ability_manager_stub.cpp:222` | 准确 | 守卫是该函数的第一个分支 |
| AUTH-01 | `ohos.rpc.rpc.impl.cpp:231`、`raw_parcel_callback_stub.cpp:44`、`iesim_service_callback_stub.cpp:219` | 准确 | 被标记函数体内 231 行之前没有 `if`（202 行的 `if` 在另一个函数里） |
| AUTH-01 | `pasteboard_disposable_observer_stub.cpp:48` | **不准确** | 36/41/45 三行是宏写的守卫 |
| CAP-01 | `ability_manager_stub.cpp:2851`、`wifi_device_mgr_stub.cpp:40` | 准确 | 直线代码，`WriteRemoteObject` 之前无分支 |
| AUTH-04 | `update_service_stub.cpp:228` | 准确 | handler 是直线代码 |

所以 `empty_path` 仍是分流信号，但它**确实会把 1 行真实误报掩盖成"路径为空"**——
交付项 10 若把这 11 行一律记成"准确"，就会漏掉 `pasteboard:48`。

## 5. 23 行的逐条读源结论

### 5.1 8 行：被标记行**就是**校验调用（`line_is_guard`）

message 的模板是 "…reaches a locally resolved handler without interface-descriptor
validation: **X**"，这 8 行的 X 是：

| 组件 | 文件:行 | message 点名的 handler | `empty_path` |
|---|---|---:|:--:|
| `ability_dmsfwk` | `distributed_sched_stub.cpp:266` | `DistributedSchedStub::EnforceInterfaceToken` | |
| `multimedia_player_framework` | `recorder_service_stub.cpp:215` | `RecorderServiceStub::CheckPermission` | |
| `multimedia_player_framework` | `recorder_service_stub.cpp:218` | `RecorderServiceStub::CheckPermission` | |
| `systemabilitymgr_samgr` | `system_ability_load_callback_stub.cpp:36` | `SystemAbilityLoadCallbackStub::EnforceInterceToken` | ✓ |
| `systemabilitymgr_samgr` | `system_process_status_change_stub.cpp:39` | `SystemProcessStatusChangeStub::EnforceInterceToken` | ✓ |
| `systemabilitymgr_samgr` | `system_ability_status_change_stub.cpp:46` | `SystemAbilityStatusChangeStub::EnforceInterceToken` | ✓ |
| `systemabilitymgr_samgr` | `system_ability_manager_stub.cpp:222` | `SystemAbilityManagerStub::EnforceInterceToken` | ✓ |
| `telephony_core_service` | `raw_parcel_callback_stub.cpp:31` | `RawParcelCallbackStub::CheckCurrentDescriptor` | |

**断言缺失的东西，就是被点名的那个 handler。** 这 8 行不必读 blob 也能判：报告的
`symbol` 字段与自己的 `message` 互相矛盾。本项仍把 8 行的 pinned 原文取进了证据 JSON。

### 5.2 1 行：规则自己的 path 记下了它声称缺失的那次校验

`ability_dmsfwk/distributed_sched_stub.cpp:271`，被标记行是
`return (this->*func)(data, reply);`，`path=((264,'iter != funcsMap.end() => True'),
(266,'EnforceInterfaceToken(data) => True'), (270,'func != nullptr => True'))`，
而 message 是 "Unresolved member-pointer IPC dispatch lacks interface-descriptor
validation; callee remains unknown"。**message 的第一个分句被它自己的 path 反证。**

值得注意的是同一处边界的**两侧各被命中一次**：`:266`（守卫行本身）落进 §5.1 的误identify，
`:271`（守卫之后的派发）落进本条的自我反证。

### 5.3 1 行：规则自己的 path 记下了它声称缺失的上下界

`communication_wifi/wifi_p2p_callback_stub.cpp:385`。message 称
"copy length cfgLen lacks matched nonnegative/destination-capacity bounds"，
而 `path=((365,'cfgLen <= 0 => False'), (369,'cfgLen > 1024 => False'),
(375,'dataBuffer == nullptr => False'), (381,'cfgData == nullptr => False'))`
——**正是它声称缺失的那两个界，而且点名的操作数就是 `cfgLen`**。

### 5.4 1 行：同文件一跳之外的守卫

`telephony_core_service/raw_parcel_callback_stub.cpp:44`，被标记行是
`Transfer(nullptr, data);`（在 `OnRemoteRequest` 里）。`writer == nullptr` 时 `Transfer`
走 else 分支。**而** `:31` 那条候选的 path 恰好记着 `writer => False`，其后就是
`if (!CheckCurrentDescriptor(data))`——校验在**同一文件、被调用者的第一层**。
`:44` 的 message 说 "Entry=…Transfer … without interface-descriptor validation"，与源码不符。

`:44` 与 `:31` 是同一处边界的两个站点，两条都错，错法相反：一条把守卫记进了 path
却把**守卫行**标成未校验 handler，另一条跳不进被调用者。

### 5.5 1 行：宏写法让 `path=()` 掩盖了守卫

`distributeddatamgr_pasteboard/pasteboard_disposable_observer_stub.cpp:48`，被标记行是
`return (this->*memberFunc)(data, reply);`。同一函数 34–38 行的原文是：

```cpp
std::u16string myDescriptor = PasteboardDisposableObserverStub::GetDescriptor();
std::u16string remoteDescriptor = data.ReadInterfaceToken();
PASTEBOARD_CHECK_AND_RETURN_RET_LOGE(myDescriptor == remoteDescriptor,
    static_cast<int32_t>(PasteboardError::CHECK_DESCRIPTOR_ERROR), PASTEBOARD_MODULE_SERVICE,
    "invalid descriptor, code=%{public}u", code);
```

**描述符校验在位**，只是写成宏，于是没有进 `path=`，于是 `empty_path` 与
"without interface-descriptor validation" 同时成立。这一行的 pinned `excerpt`
（9 行窗口）不含 34–38 行，本项另取了同一 blob 的更宽窗口（±55 行）。

### 5.6 1 行：在 C++ 帧上成立，但校验可能在 JS 层（**未决**）

`communication_ipc/ohos.rpc.rpc.impl.cpp:231`：`ANIRemoteObject::OnRemoteRequest`
（219–236 行）调到 `callOnRemoteMessageRequest`，**C++ 帧里没有任何描述符校验**。
这是 ANI/ArkTS 桥，JS 层是否校验不在本检测器的语言范围内（与既有的 ArkTS/JS 前端
阻塞项同一处）。记 **unknown**：不记误报，也不记成立。

### 5.7 1 行：在 C++ 帧上成立（**plausible**）

`telephony_core_service/iesim_service_callback_stub.cpp:219`：
`OnRemoteRequest` 整个函数体两行，直接
`return OnEsimServiceCallback(static_cast<EsimServiceCallback>(code), data);`；
该 stub 文件里没有 `ReadInterfaceToken`/`EnforceInterfaceToken`，`path=()` 准确。
message 自己写的是 "…without a matched interface-descriptor guard; relay/exposure
still requires review"——**在被标记帧上成立**；但"该回调接口能否被非属主 caller 触达"
不由本证据给出。

### 5.8 6 行 CAP-01

**4 行 `enforced_path`**（`systemabilitymgr_samgr/system_ability_manager_stub.cpp`
387/474/591/629）：被标记行都是紧随门禁的 `ret = reply.WriteRemoteObject(remoteObject);`，
path 里记着 `CheckGetSAPermission(...) => True` 或 `CheckGetRemoteSAPermission(...) => True`。
读 pinned blob（blob `1f8bb91464df550d7d5b9d622a6303f7474d5b78`）：`CheckGetSAPermission`
是 SELinux `GetServiceCheck(GetCallingSid(), …)`，**且在 `#else`（`!WITH_SELINUX`）
分支下 `return true`**。所以"这条路径缺调用方授权"的强弱**依赖构建配置**：
不是自明误报，也不能记成已成立。

**2 行 `empty_path`**（`ability_ability_runtime/ability_manager_stub.cpp:2851`、
`communication_wifi/wifi_device_mgr_stub.cpp:40`）：两个函数体都是 4 行以内的直线代码，
`reply.WriteRemoteObject(...)` 之前没有任何分支，`path=()` **准确**。两条都**不含**
`dispatcher-guard-observed` 字样（对比 §5.9）。在被标记帧上 claim 成立；
dispatcher 层是否有授权，本帧不能判定。记 **plausible**。

### 5.9 1 行 AUTH-04：这是覆盖陈述，不是缺陷断言

`update_updateservice/update_service_stub.cpp:228`，message 自带限定：
"…has no matched caller authorization on this path, **but the dispatcher performs an
authorization call before dispatch; its dominance over this transaction is not
established**"，并带 `[dispatch=map_member_ptr codes=5 dispatcher-guard-observed]`。
`path=()` 准确。这一行不该按误报读，也不该按缺陷读。

### 5.10 2 行 AUTH-03：不自明为错

`resourceschedule_background_task_mgr/bg_continuous_task_mgr.cpp:907/909`，
message "Background-task target UID is not bound to calling UID"，
path 记着 `CheckPermissionForInner(taskParam, callingUid) => True`。
读 pinned blob：该守卫只在 `AUDIO_PLAYBACK` 分支上把 `callingUid` 绑到
`taskParam->uid_`；另一分支是行内注释（blob 第 900 行）说明的
`g_innerApiReqBgRunningConfig` 白名单。**不是自明误报，也不成立。** 与交付项 10 一致。

## 6. 23 行的分类，以及这些数字**不是**什么

| 类别 | 行数 | 含义 |
|---|---:|---|
| 输出缺陷（报告自身字段即反证） | **12** | §5.1 8 + §5.2 1 + §5.3 1 + §5.4 1 + §5.5 1 |
| plausible（被标记帧上成立，机制不由该帧决定） | 3 | §5.7 1 + §5.8 的后 2 行 |
| 构建配置依赖 | 4 | §5.8 的前 4 行 |
| 覆盖陈述（不是缺陷断言） | 1 | §5.9 |
| 不自明为错 | 2 | §5.10 |
| unknown | 1 | §5.6 |
| **confirmed** | **0** | — |

口径提醒：

- **12/179 = 6.7%** 是"报告自身字段与自己的 message 相矛盾"的行占全部候选的比例；
  **12/23 = 52%** 是它占命中筛查行的比例。两者都不是"语料漏洞率"。
- 这 12 行是**检测器输出**的缺陷，不是被测组件的缺陷；也不构成"其余 167 条成立"的推论。
- **撤销一条静态候选不等于证明该组件安全**；本项一条候选都没撤（见 §1 的"没有改任何候选"）。
- 5 条沉默规则的"0 候选"是覆盖陈述，不是安全结论。

## 7. 未验证 / 阻塞 / 下一项

- **未验证**：§5.6 的 JS 层、§5.7/§5.8 的 dispatcher 层——都需要读本检测器语言范围外
  或本帧之外的代码；本项不推定。
- **未验证**：`ipc.auth.missing` 21 条零命中，只说明它没有命中这 4 种模式；
  **零命中不等于这 21 条都对**。要判它需要另一套模式（本项没有构造）。
- **阻塞**：ArkTS/JS 前端（`detector.py:74`）。
- **下一项（需 integrator 决定，不在本 lane 权限内）**：
  - §5.1 的 8 行成因是**守卫调用被当成 handler**，修它要动
    `src/ohscanner/detectors/interface/analysis.py`（共享面，需单独提出）；
  - 同理 §5.4 的**一跳**与 §5.5 的**宏中介守卫**都在同一处；
  - 本项只做测量与记录，不擅自扩大范围。
- **本次未做**：无 PoC、无动态验证、无 push / PR / merge / Draft Ready。

## 8. 证据与文件清单

| 文件 | 说明 | sha256 |
|---|---|---|
| `research/deliveries/ipc/rule_precision_screen.py` | 筛查脚本 | `13b73e6aa01c451d05e80480e91eba1fc977f3f564783ad1f4ae74f4281bc361` |
| `research/evidence/interface/ipc/rule_precision_screen_20261017/rule_precision_screen.json` | 全量结果（含 23 行的 pinned 窗口与 §3.2 的形状普查） | `5fd1b2f5e63a27166a23982c8b57865afa98b171bb5ba7e7cbf9bcb634b6b096` |

证据 JSON 的字段：`rows`（23 行：component / rule_id / file / line / symbol / modes /
path_items / excerpt / excerpt_blob_oid）、`per_rule`、`blob_checked`=179、
`blob_mismatch`=0、`blob_unchecked`=0、`cond_shapes`（`path_conditions`=591、
`candidates_with_empty_path`=11、`buckets`、每类至多 5 个 `examples`）。

§3 的两张表由**同一次运行**产出，脚本 sha256 见上表。

输入（只读，未修改）：

- 报告：`/home/audit/wtmp/ipc-audit`（30 个组件）、`/home/audit/wtmp/ipc-audit-bline`（12 个组件）；
  由检测器 `CyberSecurity-Innovation-Audit-b` @ `635b3e0449c552f0ccc25118850d245962845568`
  （`0.8.0` / `oh-ipc-2026.10-v6`）产出。
- 语料（浅克隆、SHA 固定、只读，**无隐式 fetch**）：
  `/home/audit/openharmony-audit/perf-corpus`、`/home/audit/corpus-ipc-widen`、
  `/home/audit/corpus-ipc-shape`、`/home/audit/openharmony-audit/gitcode-corpus`、
  `/home/audit/corpus-ipc-bline`。

## 9. 复现

```bash
cd /home/audit/ohscanner/worktrees/parallel-ipc-20261017
python3 -I research/deliveries/ipc/rule_precision_screen.py \
  --json research/evidence/interface/ipc/rule_precision_screen_20261017/rule_precision_screen.json
```

脚本只读报告与语料 git 对象，不需要检测器环境、不写任何语料、不做隐式 fetch。
输出应与 §3.1 的表逐字一致（`blob_checked`=179 / `blob_mismatch`=0 / `blob_unchecked`=0）。
