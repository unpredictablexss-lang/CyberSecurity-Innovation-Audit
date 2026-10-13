# 首批代表性候选核查：41 条逐条判定 + 五个误报机制（2026-10-11）

- 输入：五组件审计（schema v2）的 **41 条候选**，全部 `evidence_type = syntax`、`severity = unassessed`、
  `confidence = unassessed`、`validated_vulnerability = 0`。
- 产出：**逐条判定 + 可复现的误报机制**，用于指导算法改进，**不是**新的漏洞结论。
- 三个数分开报：**测试 375 项 OK**（其中组件审计 45 项）/ **候选 41 条** / **确认漏洞 0 条**。
- 判定分布：**likely false positive 37 条、plausible but unproven 4 条、确认 0 条**。

## 0. 一句话结论

41 条候选里没有一条能走到证据门（缺入口可达性、缺攻击者控制、缺影响），而**其中 37 条的误报原因已经定位到具体代码行**，集中在**四个可修的谓词/锚点缺陷**和**三类可修的解析缺陷**上；另有 **4 条值得继续跟**（都卡在同一件事：跨仓/运行时才能确定的能力面）。

## 1. 方法

- 所有源码在 **pinned commit 上读取**（`git show <commit>:<path>`），不看 worktree；跨文件符号用 `git grep -n <sym> <commit>`。
- 逐条核查：候选行原文 → 从 IPC 入口到该行的**完整路径** → 路径上的每个检查（file:line + 效果）→
  检查是否**支配**该行 → 谓词的真实语义 → 外层预处理条件 → 判定。
- **关键机制我不接受推断**：用真检测器跑对照实验，观察解释器自己的状态（见 §4.1 的探针）。
- 组件与 commit：

  | 组件 | commit | 候选 |
  |---|---|---:|
  | `openharmony/security_access_token` | `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` | 20 |
  | `openharmony/window_window_manager` | `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` | 15 |
  | `openharmony/communication_dsoftbus` | `652f88e0261ce4d0610f73cc451c26b84d2597af` | 4 |
  | `openharmony/update_updateservice` | `e4942a33cc5ed29040e5c720bea3b2a8e4a79221` | 2 |

## 2. 逐条判定

### 2.1 `security_access_token`（20 条，全部 likely false positive）

| 行 | 规则 | 候选行 | 路径上真实存在的检查 | 判定 |
|---|---|---|---|---|
| `accesstoken_callback_stubs.cpp:78/81/84` | AUTH-01 | switch 内三个 `XxxInner(data, reply)` | **:69-73** `ReadInterfaceToken() != ITokenSyncCallback::GetDescriptor()` → `return ERROR_IPC_REQUEST_FAIL` | FP（**M1**） |
| 同上 `:103/116/131` | AUTH-01 | `this->Get/Delete/UpdateRemoteHapTokenInfo(...)` | 同上 + **:94/109/122** `IsAccessTokenCalling()`（`:136-140` 判 `GetCallingUid()==ACCESSTOKEN_UID(3020)`） | FP（M1） |
| `on_permission_used_record_callback_stub.cpp:45/54` | AUTH-01 | `OnQueried(...)` | **:34-37** 描述符校验 → `ERROR_IPC_REQUEST_FAIL`；授权在请求侧 `privacy_manager_service.cpp:494-498`（`IsSystemAppCalling` + `VerifyPermission(PERMISSION_USED_STATS)`） | FP（M1） |
| `token_sync_manager_stub.cpp:48/51/54` | AUTH-01 | switch 内三个 `XxxInner(data, reply)` | **:37-40** `IsLocalCalling()`；**:41-44** `!= ITokenSyncManager::GetDescriptor()` | FP（M1） |
| `token_sync_manager_stub.cpp:83/110/127` | AUTH-01 | **`IsRootCalling`（授权谓词本身）** | 同上 | FP（**M3**：把 guard 函数当成了 handler） |
| `token_sync_manager_stub.cpp:104/121/136` | AUTH-02 | `Get/Delete/UpdateRemoteHapTokenInfo` | **:83/110/127** `!IsRootCalling() && !IsNativeProcessCalling()` → `ERR_IDENTITY_CHECK_FAILED` | FP（M3） |
| `token_sync_manager_stub.cpp:104/121/136` | AUTH-01 | 同上 | 同上 | FP（M1） |

**同一组件内的自证**：`accesstoken_callback_stubs.cpp` 用 `IsAccessTokenCalling()`（**在**模型词表内，`analysis.py:600`
把它映射为 `("auth","<caller-service-role>",True)`），所以该文件**没有**产生 AUTH-02；
`token_sync_manager_stub.cpp` 用 `IsRootCalling()`/`IsNativeProcessCalling()`（**不在**词表内），同一位置的同一类检查就变成了 3 条 AUTH-02。
**"有检查但没被识别"不是"没有检查"**，这是可修复的词表问题，不是真实缺失授权。

单测与 fuzz 佐证拒绝行为确实存在：
`accesstoken_kit_coverage_test.cpp:659`（错误 descriptor → `ERROR_IPC_REQUEST_FAIL`）、`:698`（uid≠3020 → 拒绝）；
`token_sync_service_test.cpp:1386/1402`（`setuid(1234)` → `ERR_IDENTITY_CHECK_FAILED`）；
`privacy_kit_test.cpp:3390`（错误 descriptor → 非 0 返回）。

### 2.2 `window_window_manager`（15 条：13 FP + 2 待查）

| 行 | 规则 | 路径上的检查 | 判定 |
|---|---|---|---|
| `screen_session_manager_stub.cpp:42` | AUTH-01 | 入口 `:38-44` 只是转调，**描述符校验在同文件 `OnRemoteRequestInner:50`** | FP（**M2**） |
| `screen_session_manager_stub.cpp:738` | AUTH-02 | 实现侧 `screen_session_manager.cpp:10917` `!IsSystemCalling() && !IsShellCall()` | FP（**M6**） |
| `screen_session_manager_stub.cpp:1778` | CAP-01 | **整条路径（stub:1776-1778 → `GetRenderSession` :3200 → `screen_session.cpp:1007`）无调用者检查** | **plausible but unproven** |
| `session_stage_stub.cpp:1252` | CAP-01 | 实现侧 `window_session_impl.cpp:5064` `IsSystemCalling()` → 失败则不导出 | FP（M6） |
| `session_stub.cpp:592` | CAP-01 | 实现侧 `session.cpp:1687` 无检查；但导出的是**调用方自身会话**的 renderSession | **plausible but unproven** |
| `scene_session_manager_stub.cpp:371/373/421/462` | CAP-01 | 实现侧 `CheckSystemWindowPermission` / `CheckSessionPropertyOnRecovery`（`scene_session_manager.cpp:5838/6015`） | FP（M6） |
| `scene_session_manager_stub.cpp:1208/1226` | CAP-01 | 实现侧 `IsSACalling()`（`:12971` / `:12985`） | FP（M6） |
| `scene_session_manager_stub.cpp:2944` | CAP-01 | 实现侧 `IsSystemCalling()`（`:4783`） | FP（M6） |
| `session_manager_service_stub.cpp:37/41` | CAP-01 | 导出 SSM 句柄，**SA 的设计入口**；SSM 对象逐方法自检 | FP（设计） |
| `window_manager_stub.cpp:389` | CAP-01 | 服务侧 `window_manager_service.cpp:1608` `IsSystemCalling()\|\|IsStartByHdcd()` → 失败使 `finishedCallback` 保持 `nullptr`，导出分支根本不会执行 | FP（M6） |

### 2.3 `communication_dsoftbus`（4 条：2 FP + 2 待查）

| 行 | 规则 | 检查 | 判定 |
|---|---|---|---|
| `softbus_server_stub.cpp:2174/2191` | CAP-01 | 同文件 dispatcher：`:391` 描述符校验 + **`:403` `CheckPermission(code)`**，四个导出 code 在 `:294-297` 均登记了权限 | FP（**M4**） |
| `bus_center_ex_obj_stub.cpp:56` | AUTH-01 | stub **不校验描述符**，直接 `dlsym` 到插件 `OnRemoteRequestByDlsym`；`OpenSoftbusPluginSo` 加载**固定路径** `/system/lib64/libdsoftbus_server_plugin.z.so`（无调用者可影响输入）；插件**不在本仓库**、无构建目标 | **plausible but unproven** |
| `trans_spec_object_stub.cpp:62` | AUTH-01 | 同上；插件的 `TransSpecObject` 在本仓库把全部方法实现为 `SOFTBUS_NOT_IMPLEMENT` | **plausible but unproven** |

可达性由导出侧界定：`SoftBusServerStub` dispatcher 有 token + 权限双闸门，**对象自身的 `OnRemoteRequest` 不再校验**——
即"取句柄时授权一次"。是否足够取决于插件内部的每调用校验，**本仓库无法证明**。

### 2.4 `update_updateservice`（2 条：判定为 FP，但检测器是诚实的）

两条都不该按"误报"草率处理——**报告自己写明了理由**：

```
AUTH-04 candidate: Sensitive modeled call Upgrade has no matched caller authorization on this path,
but the dispatcher performs an authorization call before dispatch; its dominance over this transaction
is not established. Entry=UpdateServiceStub::DoUpdateStub [dispatch=map_member_ptr codes=5
dispatcher-guard-observed]
```

- `dispatch=map_member_ptr`：入口索引**已经**把 `DoUpdateStub` 通过 `requestFuncMap_` 绑定到 dispatcher；
- `dispatcher-guard-observed`：**已经看到** dispatcher 里有鉴权调用；
- 仍然出候选，是因为"该 guard 是否支配这条业务路径"没被证明。

我实测确认支配关系**成立**：`update_service_stub.cpp:421-426` 的
`if (!IsCallerValid()) return ...; if (!IsPermissionGranted(code)) return ...;` 位于**唯一派发点 `:432`** 之前，
且派发是 `map.find` + 成员函数指针（不是 `switch`），表内每个 code 都必然先过这两道闸门。
`IsCallerValid`（`:370-389`）判 HAP→必须系统应用 / NATIVE→uid∈{0,3057} / 其余 → false；
`IsPermissionGranted`（`:391-404`）按 code 取 `ohos.permission.UPDATE_SYSTEM`，`FACTORY_RESET` 取专用权限 `ohos.permission.FACTORY_RESET`。

→ **判定：FP（实际后果），机制 M5（守卫支配性未证明）**。正确的下一步是**证明支配性**，而不是删掉候选。

## 3. 四个待继续跟进的线索（都不是漏洞结论）

| 线索 | 为什么还留着 | 需要什么才能推进 |
|---|---|---|
| `screen_session_manager_stub.cpp:1778`（CAP-01） | 唯一一条**导出前路径上找不到任何调用者检查**的能力导出；导出的是 `GetRenderSession(screenId)` 的渲染会话对象 | 确认 `renderSession_`（RSRenderService 渲染会话）被第三方持有后能做什么——`foundation/graphics` 跨仓，本仓库看不到 |
| `session_stub.cpp:592`（CAP-01） | 无显式检查，但导出对象是调用方自身会话的 renderSession | 运行时确认该句柄是否授予超出该 surface 的能力 |
| `bus_center_ex_obj_stub.cpp:56` / `trans_spec_object_stub.cpp:62`（AUTH-01） | stub 确实不校验描述符，且**绕过了 `IRemoteStub<T>` 的默认校验**；对象拿到后可跨 code 直达插件 | 插件 `libdsoftbus_server_plugin.z.so` 的源码或目标镜像（本仓库无）；或运行时用 fuzz 目标观测 |

## 4. 五个误报机制（附代码位置与对照实验）

### M1 描述符校验被限定条件挡掉（**已用对照实验证实**）

`analysis.py:582-585`：

```python
if name == "GetDescriptor":
    if "::" in callee and callee.rsplit("::",1)[0] != fn.owner:
        return UNKNOWN            # 限定名不是"本类" -> 不认这个描述符校验
    return Value("descriptor_expected", fn.owner)
```

规则的原意是对的（防止把"拿别的接口的描述符做比较"当成校验），但**身份判据用错了对象**：
真实 OpenHarmony 里 stub 实现接口、描述符声明在**接口类**上，于是
`TokenSyncCallbackStub::OnRemoteRequest` 写的是 `ITokenSyncCallback::GetDescriptor()`——
限定名 `ITokenSyncCallback` **永远不等于** `fn.owner = TokenSyncCallbackStub` → 返回 `UNKNOWN` → 描述符集合为空 → AUTH-01 触发。

- **量**：`security_access_token` 有 **12** 处描述符比较，其中 **9 处是接口限定形式**；`communication_dsoftbus` 有 1 处
  （`ISoftBusClient::GetDescriptor()`）。`window_window_manager`（28 处）与 `update_updateservice`（2 处）用的是**非限定**
  `GetDescriptor()`，所以那条规则在它们身上**没有**误报——这正是"同一个 bug 只在一部分组件上显形"的原因。
- **构造 28 个 fixture 用的是非限定形式**（`tests/fixtures/ipc/*.cpp:5` 全是 `!= GetDescriptor()`），所以 29 个设计场景
  全部通过，而真实代码的常见形式从未被测到。这是"在实验室里自洽、在真实代码上失效"的典型。
- **对照实验**（`research/experiments/interface/ipc/review_descriptor_rule.py`，只改这一处判据，别的不动）：

  ```
  as shipped                     candidates=6  AUTH-01=6
  GetDescriptor qualifier relaxed candidates=0  AUTH-01=0
  ```

- **可行的修法**：接口身份**可从源码派生**——基类模板实参即接口：
  `class TokenSyncCallbackStub : public IRemoteStub<ITokenSyncCallback>`（`accesstoken_callback_stubs.h:39`）、
  `OnPermissionUsedRecordCallbackStub : public IRemoteStub<OnPermissionUsedRecordCallback>`（`on_permission_used_record_callback_stub.h:27`）、
  `ScreenSessionManagerStub : public IRemoteStub<IScreenSessionManager>`、
  `WindowManagerStub : public IRemoteStub<IWindowManager>`、`SessionStageStub : public IRemoteStub<ISessionStage>`。
  注意第二条：接口名没有 `I` 前缀、且是**另一个文件**的声明——所以**按名字猜 `FooStub→IFoo` 会失败**，必须用基类实参。
  该映射应当来自入口索引（它已经跨文件建 class/base 图），且**必须记录比对的到底是哪个接口**，
  这样"拿别的接口的描述符做比较"仍然作为更强的发现保留下来，不会被这次修正一起抹掉。

### M2 描述符校验被委托给内层入口（**已复现**）

`screen_session_manager_stub.cpp:38-44` 的 `OnRemoteRequest` 只加锁并转调，真正的校验在
同一文件的 `OnRemoteRequestInner:50`（`if (data.ReadInterfaceToken() != GetDescriptor()) return ERR_TRANSACTION_FAILED;`）。
候选报在**第 42 行的转调本身**，此时 root 层的描述符集合为空。探针输出：

```
--- AUTH-01 emit at line 42
    fn  : ScreenSessionManagerStub::OnRemoteRequest
    root: ScreenSessionManagerStub::OnRemoteRequest
    text: OnRemoteRequestInner(code, data, reply, option)
    descriptor state: []
```

→ 修法与 M1 无关：需要在"入口转调入口"的形状上把内层的检查**上提**（或在报候选前先解析被转调的同名内层入口）。

### M3 授权谓词词表只认固定名字（**已用同一组件内的对照证实**）

`models.py:130-135` 只登记了
`boolean_permissions = {CheckPermission, VerifyPermission, CheckCallerPermission}`、
`result_permissions = {VerifyAccessToken, VerifyNativeToken}`、`trusted_uids = {0, ROOT_UID, SYSTEM_UID, 1000}`，
`analysis.py:596-601` 另外硬编码了 `IsSystemAppCalling`/`CheckCallerIsSystemApp`/`IsPrivilegedCalling`/`IsAccessTokenCalling`。
**项目自定义的谓词一律不可见**：`IsRootCalling`、`IsNativeProcessCalling`、`IsCallerValid`、
`IsPermissionGranted`、`IsSystemCalling`、`IsSACalling`、`IsLocalCalling`、`IsShellCall` 全部不在表内。

两个方向都出问题：
1. **漏报式误报**（把"有检查"读成"没检查"）→ AUTH-02/AUTH-04/CAP-01，见 §2 中 M3/M5/M6 各行；
2. **反向误报**：AUTH-01 还把 **guard 函数自己**当成了 handler——
   `token_sync_manager_stub.cpp:83/110/127` 的候选文本是
   `IPC entry reaches a locally resolved handler without interface-descriptor validation: TokenSyncManagerStub::IsRootCalling`
   ——被"到达"的"handler"其实是授权谓词。`analysis.py:617-619` 对入口 root 内**任何**可本地解析的调用都发候选，
   缺少"这是不是分发目标"的判据。

**可行的修法**（两条都要）：① 把"返回 bool 且名字/参数形态像鉴权"的**本地**函数纳入谓词解析，
并在结论里记录**它的判据**（例如 `GetCallingUid() == ROOT_UID`），使结论可复核；
② 给 AUTH-01 加"分发目标"判据（来自入口索引的 dispatch 绑定），谓词调用不是分发目标。

### M4 识别得到的权限函数，用项目错误码判成败时不被识别

`softbus_server_stub.cpp:403` 的 `CheckPermission(code)` **在**词表内（`boolean_permissions`），
但调用点写的是 `if (ret != SOFTBUS_OK) return ret;`，而 `SOFTBUS_OK` 是**另一个文件里的枚举成员**：

```
interfaces/kits/common/softbus_error_code.h:1788:    SOFTBUS_OK = 0,
```

谓词识别（`analysis.py:672`）只在 `cv.key ∈ {"0","PERMISSION_GRANTED","AccessTokenKit::PERMISSION_GRANTED","true"}`
（或 `terminal(cv.key)=="PERMISSION_GRANTED"`）时判成功，`"SOFTBUS_OK"` 不在其中 → 不产生 auth 谓词 → 导出行 CAP-01。
同理 `update_updateservice` 用 `CALL_RESULT_TO_IPC_RESULT(INT_APP_NOT_GRANTED)` 包装返回值。

→ 修法：需要一个**有界的跨文件常量表**（枚举/`#define` 的整数值），或至少承认"与某个 `*_OK`/`*_SUCCESS` 常量不等即失败"这一形状。

### M5 dispatcher 守卫的支配性未证明（**检测器自述诚实**）

见 §2.4。`dispatcher-guard-observed` 已经记下了守卫存在，缺的是**支配性证明**。
对 `map_member_ptr` 这一形态，支配性是**可判定**的：守卫与派发在同一个基本块序列里，
派发是表查找后的唯一调用点（`update_service_stub.cpp:415-432`），不存在旁路分支、`switch` 贯穿或"只有一条分支带检查"。
→ 修法：给 `map_member_ptr` / `switch` 两种分发形态各写支配性判据并**分别记录**（"守卫支配"vs"守卫存在但支配性未知"），
不要用一个布尔把两种处境合并。

### M6 守卫在实现类里，而实现类在另一个翻译单元（单文件分析的固有边界）

`window_manager_stub.cpp:389` 的守卫在 `window_manager_service.cpp:1608`；
`session_stage_stub.cpp:1252` 的在 `window_session_impl.cpp:5064`；
`scene_session_manager_stub.cpp:1208` 的在 `scene_session_manager.cpp:12971`。
这不是 bug 而是 **file-local 语义**：本链路不做跨文件数据流。可做的改善是**受限的一跳**：
入口索引已有 dispatch 绑定，可对"stub 方法 → 同名实现方法"做一次受控解析并记录来源（与 alias 表同样的保守策略）。

## 5. 部分解析的真实成因（实测，不是推测）

用项目自己的解析器（`src/parser/ast.py` 的 `_CPP_PARSER`）在 pinned blob 上复现，**ERROR 节点逐行**：

| 文件 | `has_error` | ERROR 行与文本 | 成因 |
|---|---|---|---|
| `dsoftbus/core/frame/standard/init/src/softbus_server_stub.cpp` | True（4） | 416 `this->*`；599 `SCNd64`；756、1161 `PRIu32` | **成员函数指针调用** + **格式宏字符串拼接** |
| `wwm/window_scene/screen_session_manager/src/zidl/screen_session_manager_stub.cpp` | True（2） | 581、630 `PRIu64` | 格式宏字符串拼接 |
| `update/services/engine/src/update_service_stub.cpp` | True（20） | 78/99/114/133/148/175/193/211/**229**/247/261/276… 全部为 `ret` | **`ENGINE_CHECK(cond, return ret, "...")`：把 `return` 当宏实参** |

三点结论：

1. **不是 `#if` 嵌套造成的**。这三个文件里 `grep '^#'` 只有 `#include`（update 另有 2 个 `#define`），
   没有预处理嵌套被误解析。
2. **是三类机械形状**：格式宏拼接（`PRIu64/PRIu32/SCNd64`）、成员函数指针调用 `(this->*f)(...)`、语句关键字作宏实参。
   三者在预处理/规范化阶段**可修**：定义格式宏为字符串字面量、把 `(this->*` 形态在解析前规范化、
   或在 `normalize_syntax` 里把宏实参中的 `return` 包成占位表达式。
3. **本批候选没有被 partial 隐藏掉守卫**：上述 ERROR 行（416/599/756/1161、581/630、78…276）与
   本批候选行（2174/2191、42、228/336）**不在同一处**，且 `update_service_stub.cpp` 的候选锚点是
   `dispatch=map_member_ptr`——说明入口索引在部分解析下**仍然**恢复出了分发绑定与 dispatcher 守卫。
   即：partial 影响的是**覆盖口径与义务来源**（进不了 `complete-ast` 那遍），**不是**本批候选的成因。

## 6. 对算法改进的建议（按性价比排序）

1. **M1 修 `GetDescriptor` 的接口身份判据**（用基类 `IRemoteStub<I>` 实参，不用名字猜；同时记录被比对的接口）。
   预期直接消掉 20 条里的绝大部分，且**提高**准确率（当前它把"有校验"读成"没校验"）。
   需要补：正例（接口限定 → 不再报）、反例（比对**别的**接口 → 仍然报）、以及非限定形式的既有 28 个 fixture 不回归。
2. **M5 给 dispatcher 守卫写支配性判据**，并区分"支配"与"存在但支配未知"。
3. **M3 扩展谓词解析到项目本地辅助函数**，并把谓词的判据写进结论；同时给 AUTH-01 加"分发目标"判据，
   消除"把 guard 函数当 handler"这类反向误报。
4. **解析规范化**（格式宏、`(this->*`、宏实参里的 `return`）——这条同时提升**覆盖**与**证据深度**，
   是 `parse_completeness_impact` 义务的可落地答案。
5. **M4 有界跨文件常量表**（枚举/`#define` 整数值），让 `!= SOFTBUS_OK` 这类判定可用。
6. **M6 受限一跳实现解析**（stub 方法 → 同名实现方法）。

**不建议现在做的**：把 AUTH-01 的限定判据简单删掉（会把"比对了错误接口"这一更强的发现一起抹掉）；
把 M5 的候选直接丢弃（现在它至少诚实地说"支配性未证明"）。

## 7. 本报告明确没做的事

- **没有修改任何检测器规则**：本文只给证据与修法。规则改动会改变候选集合，应与它的正/反例一起单独落地并复跑五组件。
- **没有把任何候选升级**：41 条仍是 `evidence_type=syntax`、`validated_vulnerability=0`。
- **没有宣称漏洞**：`plausible but unproven` 的四条**必须**跨仓或运行时才能推进，静态到此为止。
- **没有跑构建/运行时验证**：可行性已按组件列出（`security_access_token` 有 `test/unittest` 与 fuzz；
  `window_window_manager` 有 `window_scene/test/unittest`、`wmserver/test/unittest`、dms fuzz；
  `communication_dsoftbus` 有 `tests/core/frame/fuzztest/softbusserverstub_fuzzer` 与
  `tests/core/transmission/fuzztest/transbroadcast_fuzzer`；`update_updateservice` **无** `services/engine/test`，
  现有 fuzzer 用 `SetSelfTokenID` 私授权限令牌，不适合验证"未授权被拒"）。

## 8. 复现命令

四个复核脚本已入库到 `research/experiments/interface/ipc/`，均须**从仓库根目录**运行（它们按 `os.getcwd()`
导入 `src.ohscanner`），并按本机语料路径读取 pinned blob。

```bash
cd <B 仓库>

# 判定所用的 pinned 读取方式
git -C <repo> show <commit>:<path>

# M1 对照实验：只改 GetDescriptor 的限定判据，别的不动
.venv/bin/python -I research/experiments/interface/ipc/review_descriptor_rule.py
#   as shipped                     candidates=6  AUTH-01=6
#   GetDescriptor qualifier relaxed candidates=0  AUTH-01=0

# M1 的量：接口限定 vs 非限定描述符比较的分布
.venv/bin/python -I research/experiments/interface/ipc/review_descriptor_shapes.py

# M2：入口转调内层入口时 root 层描述符集合为空（探针打印解释器状态）
.venv/bin/python -I research/experiments/interface/ipc/review_delegated_descriptor.py

# §5 解析成因：用项目自己的 parser 列出每个文件的 ERROR 行与文本
.venv/bin/python -I research/experiments/interface/ipc/review_parse_causes.py
```
