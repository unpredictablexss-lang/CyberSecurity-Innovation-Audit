# IPC 候选深审：`security_access_token` 3 条 + `update_updateservice` 2 条（2026-10-15）

> 队友 B 提交。范围只有一件事：把**当前检测器版本下仅剩的 5 条未逐条复核的候选**判完，
> 使五组件 23 条候选全部有复核记录。**不改任何规则、不改公共契约、不做动态验证。**
> 检测器 `ohscanner.interface.ipc` **0.5.0**，模型 `oh-ipc-2026.10-v3`。

## 0. 一句话结论

5 条全部判为 **likely false positive**：**0 条 confirmed，0 条升级，0 条删除，0 条新立**。
`validated_vulnerability` 仍为 **0**。

判据不是「本地没搜到限制」，而是在**固定提交的源码里逐行读出了守卫、读出了它的失败分支会返回、
读出了它支配那条被报告的效果调用**——同时检测器**自己的 limitations 列表**记着「这个守卫的取值没解析出来」。
两处机制归属：

| 候选组 | 条数 | 机制 | 一句话 |
|---|---:|---|---|
| `security_access_token` AUTH-02 | 3 | **M3** | 授权谓词是本地 helper（`IsRootCalling`），helper 的布尔取值未被解析成 auth 事实 → 路径上「没有授权」是**解析结论**，不是源码事实 |
| `update_updateservice` AUTH-04 | 2 | **M5** | 检测器**看见了** dispatcher 守卫并如实标注支配性未证明；手工按 pinned 源码读，守卫确实支配 |

两者的共同点值得写下来：**这两批候选都是「检测器自己已经说出了不确定性」的那种**。
AUTH-04 的消息里直接写着 `dispatcher-guard-observed`；AUTH-02 的守卫 helper 名字就躺在 `limitations` 里。
它们不是被忽略的守卫，而是**已知未解析**的守卫。

## 1. 绑定与读取纪律

| 组件 | repository | commit | 文件 | blob oid | sha256 | 行数 |
|---|---|---|---|---|---|---:|
| security_access_token | `openharmony/security_access_token` | `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` | `services/tokensyncmanager/src/service/token_sync_manager_stub.cpp` | `6b32d5dcc0e0b98c858a374d95640deb06ec94b0` | `c775adcc16da96412cfbef3ae5beb44f967fc58d6279901e55388a8004636ae1` | 142 |
| update_updateservice | `openharmony/update_updateservice` | `e4942a33cc5ed29040e5c720bea3b2a8e4a79221` | `services/engine/src/update_service_stub.cpp` | `51ab923c63520965b13c95cab7c1674d799c93e9` | `9f0076ef97d099258e38f55568dee05d8926d5ee686336c43af3b8a268765768` | 435 |
| （语义核验）communication_ipc | `openharmony/communication_ipc` | `bbb92dbb2f52aca54ab268307c9476ac1802f3ff` | `ipc/native/src/core/framework/source/ipc_skeleton.cpp` | `5e3bf5f6296a6879bf18c4ce82ad203146df9d99` | — | — |

- 两个 commit 与 `outputs/reports/*.manifest.json` 记录的 commit 逐字一致；两个 perf-corpus 克隆的
  `HEAD` 等于该 commit 且 `status --porcelain` 为空。
- **即便如此，本次全部内容从 `git show <commit>:<path>` 读出，没有把工作树当证据**——这条读法规则
  是 v0.13 由 dsoftbus 那轮定的（工作树与 run 声称的修订可以互不为祖先）。
- 行号一律是 pinned blob 的行号。

## 2. `security_access_token`：3 条 AUTH-02

三条都落在同一个文件、同一个 stub、同一道门后面：

| # | 位置 | 被报的效果调用 | 消息给的后果 |
|---|---|---|---|
| 1 | `token_sync_manager_stub.cpp:104` | `GetRemoteHapTokenInfo` | `information_disclosure CWE-200` |
| 2 | `token_sync_manager_stub.cpp:121` | `DeleteRemoteHapTokenInfo` | `unauthorized_effect` |
| 3 | `token_sync_manager_stub.cpp:136` | `UpdateRemoteHapTokenInfo` | `unauthorized_effect` |

### 2.1 入口与两道门（pinned 正文）

```cpp
// token_sync_manager_stub.cpp:33-60
int32_t TokenSyncManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    ...
    if (!IPCSkeleton::IsLocalCalling()) {                    // :37
        return ERROR_IPC_REQUEST_FAIL;                        // :39
    }
    std::u16string descriptor = data.ReadInterfaceToken();    // :41
    if (descriptor != ITokenSyncManager::GetDescriptor()) {   // :42
        return ERROR_IPC_REQUEST_FAIL;                        // :44
    }
    switch (code) {                                           // :46
        case ...GET_REMOTE_HAP_TOKEN_INFO:   GetRemoteHapTokenInfoInner(data, reply);    break;  // :47-48
        case ...DELETE_REMOTE_HAP_TOKEN_INFO: DeleteRemoteHapTokenInfoInner(data, reply); break; // :50-51
        case ...UPDATE_REMOTE_HAP_TOKEN_INFO: UpdateRemoteHapTokenInfoInner(data, reply); break; // :53-54
        default: return IPCObjectStub::OnRemoteRequest(code, data, reply, option);       // :57
    }
    return NO_ERROR;
}
```

每个 handler 的第一条语句都是同一道身份门，**失败分支写错误码并 `return`**：

```cpp
// :81-106（Delete/Update 的 :108-123 / :125-139 同形）
void TokenSyncManagerStub::GetRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsRootCalling() && !IsNativeProcessCalling()) {      // :83
        reply.WriteInt32(ERR_IDENTITY_CHECK_FAILED);
        return;                                                // :86
    }
    ... data.ReadString(deviceID) ... data.ReadUint32(tokenID) ...
    int result = this->GetRemoteHapTokenInfo(deviceID, tokenID);   // :104  ← 被报告的效果
}
```

守卫自身的取值来源（同一 blob）：

```cpp
// :70-79
bool TokenSyncManagerStub::IsRootCalling() const
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    int callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ROOT_UID;            // ROOT_UID = 0，定义在 :29
#else
    return false;
#endif
}

// :62-68
bool TokenSyncManagerStub::IsNativeProcessCalling() const
{
    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    uint32_t type = (reinterpret_cast<AccessTokenIDInner*>(&tokenCaller))->type;
    return type == TOKEN_NATIVE;
}
```

**支配关系**：`GetRemoteHapTokenInfoInner` 的全文中，`:83` 之后到 `:104` 之间没有任何分支可以绕过该门；
`:104` 是 `:83` 之后的**唯一**效果调用。`DeleteRemoteHapTokenInfoInner`（`:110` → `:121`）、
`UpdateRemoteHapTokenInfoInner`（`:127` → `:136`）同形。且 `:46` 的 `switch` 是唯一派发点
（default 交给基类，不回落到这三个 handler）。

### 2.2 为什么是 false positive 而不是「未决」

被报告的命题是「这条结构化路径上**没有**被识别的调用者授权」。按 pinned 源码，命题不成立：

1. 授权**存在**且是**身份域**检查（root UID 或 TOKEN_NATIVE 进程），不是缺失；
2. 它**支配**被报告的效果调用，失败分支**返回**（写 `ERR_IDENTITY_CHECK_FAILED`）；
3. 描述符检查（`:42`）也被检测器**正确识别**了——候选 1 的路径轨迹里就有
   `(42, 'descriptor != ITokenSyncManager::GetDescriptor() => False')`，即 **M1 在这个文件上是生效的**。

所以「没有授权」是**解析结论**，不是源码事实。M1 已经把该文件 17 条 AUTH-01 的观测收掉了；
剩下这 3 条 AUTH-02 是 **M3 的残渣**——10-11 的复核报告 §2.1 已把该组件 20 条全部判为
likely false positive，本轮的结论与之**独立地一致**，但依据从"逐条人工判断"细化成了"守卫 + 支配 + 失败分支返回"三件可复核的事。

### 2.3 检测器自己怎么说：`limitations` 里就有守卫的名字

对 `security_access_token` 跑当前检测器，`limitations` 共 **249** 条，其中 16 条是
`Unresolved multi-outcome helper return:`，**包括守卫本身**：

```
Unresolved multi-outcome helper return: TokenSyncManagerStub::IsRootCalling        ← 身份门
Unresolved multi-outcome helper return: TokenSyncManagerStub::GetRemoteHapTokenInfoInner
Unresolved multi-outcome helper return: TokenSyncManagerStub::DeleteRemoteHapTokenInfoInner
Unresolved multi-outcome helper return: TokenSyncManagerStub::UpdateRemoteHapTokenInfoInner
```

对照引擎侧的两处事实：

- `analysis.py:527-532` 的 `authorized()` **对这三个调用名有专门分支**：
  `GetRemoteHapTokenInfo` / `DeleteRemoteHapTokenInfo` / `UpdateRemoteHapTokenInfo` 被判为
  「`state.auth` 非空 **或** `state.caller_class` 含 `TOKEN_NATIVE`」——也就是说，
  **引擎本来就把「native 进程身份」当作这三个调用的授权模型**。
- `analysis.py:881-882`：`GetCallingUid()` 与 `trusted_uids`（`{"0","ROOT_UID","SYSTEM_UID","1000"}`，
  `models.py:135`）比较**会**产生 auth 事实。

所以这不是「这个概念无法建模」，而是**事实没有走到路径上**：`IsRootCalling` 在
`#ifndef/#else` 下有两个 `return`（一个布尔表达式、一个字面 `false`），helper 摘要
（`analysis.py:824-834`）要求所有 return 一致或恰好是 true/false 字面量，于是给出 `UNKNOWN` 并记下 limitation。
`IsNativeProcessCalling` 的 token 类型是 reinterpret_cast 后的位域，取值同样未解析。

> 本节的**已验证部分**是：limitations 里有这几条、`authorized()` 有那个专门分支、`:881` 能建模 trusted-uid。
> **未验证部分**是每一条 limitation 的内部成因（例如 `IsPermissionGranted` 只有一个 `return` 却也被列入）。
> 这里不把成因当结论；M3 的修复方案按 `AGENTS.md` 需要单独提交并配正/固定/安全对照，本轮**不做**。

### 2.4 记录在案、但不写成漏洞的观察

以下两点不在任何候选的消息里，是读源码时看到的**策略性**观察，记为观察，**不升级、不新立候选**：

1. `IsNativeProcessCalling()` 只比对调用者 token 的**类型**是 `TOKEN_NATIVE`，不比对是**哪一个** native 进程。
   即：任何 native SA 都过这道门。（root 路径另受 `ROOT_UID` 约束。）
2. `ATM_BUILD_VARIANT_USER_ENABLE` 构建下 `IsRootCalling()` 恒为 `false`（`:76-78`），
   此时只有 native 进程能过。两种构建下都**有**检查，只是通过的集合不同。

这两点说明「守卫存在且支配」成立；它们**不**说明这道门的策略是否足够严——那是策略评审的题目，
不是本候选报告的题目。按证据门，本轮不把它写成 finding。

### 2.5 一条顺手查出的负结果：`IsLocalCalling()` 不是「同进程」判据

调查中我先把 `:37` 的 `if (!IPCSkeleton::IsLocalCalling())` 读成「跨进程调用一律拒绝」，
并据此准备写「远端调用者根本到不了这三个事务」。**这是错的**，按 pinned 源码更正：

```cpp
// communication_ipc @ bbb92dbb, ipc/native/src/core/framework/source/ipc_skeleton.cpp:258-265
bool IPCSkeleton::IsLocalCalling()
{
    IRemoteInvoker *invoker = IPCThreadSkeleton::GetActiveInvoker();
    if (invoker != nullptr) { return invoker->IsLocalCalling(); }
    return true;
}

// ipc/native/src/core/invoker/source/binder_invoker.cpp:1714-1717
bool BinderInvoker::IsLocalCalling() { return true; }

// ipc/native/src/core/dbinder/source/dbinder_databus_invoker.cpp:802-805
bool DBinderDatabusInvoker::IsLocalCalling() { return false; }
```

即 `IsLocalCalling()` 的真实语义是**「不是 dbinder / databus 的跨设备调用」**，
在 binder 路径上**恒为 true**。所以 `:37` **不**构成对同设备跨进程调用者的门。
写出这条，是因为「`IsLocalCalling` = 同进程」是一个很容易犯、且会**放大**结论的误读——
如果按误读去写，sat 这三条会被描述成"远端不可达"，那是一个**没有源码支撑的更强断言**。
**记录为负结果，保留，不删。**

## 3. `update_updateservice`：2 条 AUTH-04

| # | 位置 | 效果调用 | code | 消息给的后果 |
|---|---|---|---:|---|
| 1 | `update_service_stub.cpp:228` | `service->Upgrade` | 5 (`UPGRADE`) | `unauthorized_effect` |
| 2 | `update_service_stub.cpp:336` | `service->FactoryReset` | 18 (`FACTORY_RESET`) | `unauthorized_effect` |

### 3.1 dispatcher 与两级守卫（pinned 正文）

```cpp
// update_service_stub.cpp:406-433
int32_t UpdateServiceStub::OnRemoteRequest(uint32_t code,
    MessageParcel& data, MessageParcel& reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {                     // :409
        return CALL_RESULT_TO_IPC_RESULT(INT_CALL_IPC_ERR);                  // :411
    }
    auto iter = requestFuncMap_.find(code);                                  // :415
    if (iter == requestFuncMap_.end()) {                                     // :416
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);     // :418
    }
    if (!IsCallerValid()) {                                                  // :421
        return CALL_RESULT_TO_IPC_RESULT(INT_NOT_SYSTEM_APP);                 // :422
    }
    if (!IsPermissionGranted(code)) {                                        // :425
        ...
        return CALL_RESULT_TO_IPC_RESULT(INT_APP_NOT_GRANTED);                // :430
    }
    return CALL_RESULT_TO_IPC_RESULT((this->*(iter->second))(this, data, reply, option));  // :432 唯一派发点
}
```

两级的正文：

```cpp
// :370-389  IsCallerValid —— 按调用者类别判
//   TOKEN_HAP    → TokenIdKit::IsSystemAppByFullTokenID(...)  只允许系统应用
//   TOKEN_NATIVE → uid == ROOT_UID(0) || uid == EDM_UID(3057)
//   default      → false

// :391-404  IsPermissionGranted(code) —— 按 code 查权限
//   permission = "ohos.permission.UPDATE_SYSTEM"
//   if (code == CAST_UINT(UpdaterSaInterfaceCode::FACTORY_RESET)) permission = "ohos.permission.FACTORY_RESET";
//   AccessTokenKit::VerifyAccessToken(callerToken, permission) == PERMISSION_GRANTED
```

**支配关系**：`:432` 是唯一派发点；到 `:432` 之前，`:409` / `:416` / `:421` / `:425` 四个分支**各自 return**，
没有任何路径能绕过 `:421` 或 `:425` 抵达 `:432`。`:415` 的 `map.find` + `:432` 的成员函数指针调用是唯一一跳，
不存在 `switch` 贯穿或旁路分支。

### 3.2 code 绑定核验

`requestFuncMap_` 在构造函数 `:43-66` 初始化；`:48` 绑 `UPGRADE → DoUpdateStub`，
`:63` 绑 `FACTORY_RESET → FactoryResetStub`。枚举 `UpdaterSaInterfaceCode`（`interfaces/inner_api/include/updater_sa_ipc_interface_code.h:22-43`）
从 `CHECK_VERSION = 1` 起顺序递增，故 `UPGRADE = 5`、`FACTORY_RESET = 18`——
与检测器消息里的 `codes=5` / `codes=18` 一致，因此 `:425` 对这两个事务分别要求
`ohos.permission.UPDATE_SYSTEM` 与 `ohos.permission.FACTORY_RESET`。

### 3.3 判定：likely false positive，机制 M5

被报告的命题是 AUTH-04 的：「dispatcher 在派发前做了授权调用，但它对**这个事务**的支配性未建立」。
按 pinned 源码，支配性**成立**（3.1），所以该候选在安全问题上不成立 → likely false positive。

**这与 FP 的通常含义有一处重要区别，必须写清楚**：这里检测器**没有**把「有守卫」说成「无守卫」。
它 `:421`/`:425` 两个调用都**看见**了，消息里写着 `dispatcher-guard-observed`，
并且**如实**说「支配性未证明」。所以：

- 对**候选**：FP（守卫确实支配）。
- 对**规则**：M5 缺陷**未修复**。10-11 复核报告 §5 记的处置是「按派发形态证明支配性，
  并把『支配』与『存在但支配未知』分开记录——**不是**删掉候选」，本轮维持该处置。

`limitations` 侧的对应证据（`update_updateservice` 共 92 条，2 条是未解析 helper）：

```
Unresolved multi-outcome helper return: UpdateServiceStub::IsCallerValid
Unresolved multi-outcome helper return: UpdateServiceStub::IsPermissionGranted
```

即两级守卫的取值都没被解析出来——与 10-11 卡片记的 M4（`CheckPermission` 用项目错误码判成败）
是同一族问题的另一处表现，但这里的直接原因是 helper 取值未解析，不是错误码常量跨文件。

## 4. 机制归属与计数（不重复折算）

| 机制 | 现象 | 本轮证据 |
|---|---|---|
| **M3** | 授权谓词是本地 helper，其布尔取值未解析成 auth 事实 | limitations 含 `IsRootCalling`；`analysis.py:530-531` 已有 native 身份分支；`:881-882` 可建模 trusted-uid |
| **M5** | dispatcher 守卫支配性未证明 | `:421`/`:425` 两级守卫 + `:432` 唯一派发点，逐行支配 |
| **M1（正向）** | 描述符身份已正确识别 | 候选 1 路径轨迹的 `(42, ... => False)` |
| **M4**（相关但不同） | 本组件两处未解析 helper 的成因不是错误码常量 | limitations 直指 helper 名 |

**计数口径**：

- 这 5 条是**独立候选**，不共用机制、不重复计数：sat 3 条是同一 stub 的三条路径（同一道门，
  但三条独立的事务与效果调用），update 2 条是两条独立事务。**不合并、不打折**。
- 本报告**不产生**新候选、不删除旧候选、不改变任何候选的计数。五组件合计仍为 **23**。
- 本报告的 5 条 **不计入 Precision/Recall**：语料仍无独立 holdout
  （`research/corpus/interface/ipc/verified_pairs.jsonl` 12 条全为 `split=design`，S3 = 0）。

## 5. 五组件复核覆盖率（本轮之后）

| 组件 | 候选 | 复核状态 |
|---|---:|---|
| window_window_manager | 14 | 2026-10-15 已复核（6 FP / 2 外部依赖 / 6 plausible / 0 confirmed） |
| communication_dsoftbus | 4 | 2026-10-14 已复核（2 FP / 2 外部依赖） |
| security_access_token | 3 | **本轮已复核**（3 likely false positive） |
| update_updateservice | 2 | **本轮已复核**（2 likely false positive） |
| distributeddatamgr_kv_store | 0 | 无候选 |
| **合计** | **23** | **23/23 有复核记录** |

合计判定：likely false positive **13**、unresolved external dependency **6**、plausible but unproven **6**、
**confirmed 0**。`validated_vulnerability` 仍为 **0**，未升级、未删除任何候选或负结果。

> 口径提醒：这 23 条里被删掉的从来没有过——本报告 0 删除。上表的「likely false positive 13」
> 是**候选级**判定，不能外推成「这两个组件是安全的」：`completed` 不是 safe，空 findings 不是安全证明，
> 本报告只覆盖被报告的那 5 条路径。

## 6. 仍未证明 / 仍需外部证据

- sat 3 条：**这道门是否是充分的授权策略**（native 进程的粒度、`TOKEN_NATIVE` 是否覆盖了不该覆盖的进程）
  ——本仓库内无可判定证据，属策略评审，**未判**。
- update 2 条：支配性已按源码证明，但**派发形态的支配性证明尚未成为规则**（M5），
  同类形态在别的组件上仍会照旧产出候选。
- 全部 5 条：`evidence_type = syntax`，可达性、攻击者控制、具体影响三格均未填。
- 独立 holdout 仍不存在，Precision/Recall 仍不可宣称。

## 7. 复现命令

```sh
# 固定版本（两个克隆的 HEAD 与报告 commit 一致）
git -C ~/openharmony-audit/perf-corpus/security_access_token rev-parse HEAD
git -C ~/openharmony-audit/perf-corpus/update_updateservice rev-parse HEAD

# 逐条读 pinned blob（不要读工作树）
git -C ~/openharmony-audit/perf-corpus/security_access_token \
    show 17d88bfb36bea6c9370ba919ac41a22d16dd66b3:services/tokensyncmanager/src/service/token_sync_manager_stub.cpp | sha256sum
git -C ~/openharmony-audit/perf-corpus/update_updateservice \
    show e4942a33cc5ed29040e5c720bea3b2a8e4a79221:services/engine/src/update_service_stub.cpp | sha256sum

# 当前版本下的候选与 limitations（本报告的数据来源）
.venv/bin/python research/experiments/interface/ipc/measure_consequences.py \
    --json outputs/reports/consequence_dimension_v050.json \
    --md   outputs/reports/consequence_dimension_v050.md
```

预期：两个 `sha256sum` 分别等于 §1 表格里的值；
`consequence_dimension_v050.json` 中 `security_access_token` 3 条、`update_updateservice` 2 条，
`totals.findings = 72`、`validated_vulnerability = 0`。
