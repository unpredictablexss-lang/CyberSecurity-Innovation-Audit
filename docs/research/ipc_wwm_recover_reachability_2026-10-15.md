# WWM 恢复路径可达性调查（候选 7/8）

> 审计对象：`openharmony/window_window_manager` @ `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
> 候选锚点：`window_scene/session_manager/src/zidl/scene_session_manager_stub.cpp:421`、`:462`
> 前序记录：`docs/research/ipc_wwm_deep_review_2026-10-15.md`（14 条候选逐条判定）
> 本轮范围：**只**回答一个问题，不改检测规则、公共契约、A/B 其他代码，不新增检测能力。
> 唯一安全边界：不得攻击线上真实服务；动态验证只在本地隔离环境进行。

**唯一问题**：普通应用是否能控制恢复请求中的 `persistentId`、`isPersistentRecover_` 及相关 property，
并通过真实可达的服务接口触发取回或接管其他会话？

**一句话结论（两层，互不替代）**：

1. **子假设层——已证伪**：「通过调用者给出的 `persistentId` 取回并接管已有会话」这一具体机制，
   被固定提交内的服务端逻辑证伪（`:3751` 早退、只增不删的 id 集合、id 不一致即擦除，见 §7.A）。
   记为 **refuted / likely false positive**，负结果与原始候选记录**保留**。
2. **整体层——仍未判定**：恢复事务**仍会新建会话**，且相较创建路径**少了** `CheckModalSubWindowPermission`、
   `CheckSubWindowCallingProcess`（父进程比对）与 sub-window 层级上限；普通应用是否可达、
   身份字段（`bundleName_` 等）能造成什么下游影响**都还没有证据**。整体 finding **维持未决**，
   **不升** `confirmed`/`reportable`，**也不**定为 false positive（见 §7.B）。

计数口径：`:421` 与 `:462` 是**同一条共享机制**的两次触发点，按一条记录、**不重复计为两个独立漏洞**，
本轮结论**不折算进 Precision/准确率**（§7.C）。

---

## 1. 版本绑定与证据来源

所有源码读取均通过 `git show <commit>:<path>`（pinned blob），**不使用**工作树。
仓库：`/home/audit/openharmony-audit/perf-corpus/window_window_manager`
commit `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`，tree `24e60146ba2fe4af3aaef20b306a1e306df44617`。

| 文件 | blob SHA-1 | blob sha256 | 行数 |
|---|---|---|---|
| `window_scene/session_manager/src/zidl/scene_session_manager_stub.cpp` | `5d2ee611ab17e59905b4e8caffbf83708a5536b0` | `c8a84dffa0347c7116f4bfac211a7b17d06c5e530cdb3cfcb90a0fe54ba2e1b5` | 3220 |
| `window_scene/session_manager/src/zidl/scene_session_manager_proxy.cpp` | `e13cfa5514d442bc5cc83fd9b04ac1dbe3eab05c` | `d4a21abe23d4648d526de20bd529a16b80fa7c21da6ef0cb8009f317770045cd` | 5138 |
| `window_scene/session_manager/src/scene_session_manager.cpp` | `a8302de35899b1691e6f9523ef81a22ba763af38` | `2bc2ba8e66c3e32a9abb64f169cc8c04baa16ded090cb56d7e7aec73cb7313fd` | 22767 |
| `window_scene/session/host/src/session.cpp` | `39489182a4c8ee3822f1e5c2408bbe9468bdce05` | `5e8c0f2fdd3199055a5f920d8613c06e5e7d63c31dcc6ed041a3d8c0bfaaee0b` | 6619 |
| `window_scene/session/host/src/scene_session.cpp` | `80dde41f9ae41c937a708e33338061220b06a433` | `8fd279888b98416fb7ff2935df1034bde28b2640975f92c203b8628b2da843b6` | 11871 |
| `window_scene/session/host/src/sub_session.cpp` | `55bd69d600480a9b53e60b8653972834f953df0a` | `91793975536bbbf68508b39c9a689705f7b3fa3c6da1e40b9577897f95e04e17` | 711 |
| `window_scene/common/src/window_session_property.cpp` | `a4c01ed820d51f9ffcc8b497195f6cb32c2aff27` | `384306e9fda50bb7c3c20d786310aa2d756d0cc1f3383778b1fc4162d489e6dc` | 3372 |
| `window_scene/interfaces/include/ws_common.h` | `723ea1a1c7c305dd46804efb70279bff9812199f` | `c2a0489c1ae2f44937e4fc93b6e0daed674cec62ed37055dcb1d2d447699fb63` | 1856 |
| `utils/include/window_helper.h` | `3b20e566845180958123aec40149150849377647` | `0f5a19c8c6533705dbf9df5bf072d44f90951b62867a1a54c16465480ce7fca7` | 888 |
| `wm/src/window_scene_session_impl.cpp` | `6368061efc5ed5501c48480a1b0dfa4af26714df` | `e57664e34b84fca85639c5e9c725b5ae556ab1700d9fc7c5201c6e8caca1f4b7` | 10383 |
| `wm/src/window_adapter.cpp` | `9cd587cfcf58cb9787a2d4311a277cbd6fa363a5` | `ea6d55fb0ba26ea3f13bddddb603bbba712b9051f879f7f0eba5fe13e88f976c` | 1872 |
| `sa_profile/4606.json` | `58cd27ad45b26baaed097f322caca54b0edd3fae` | `48c2388e6f83537902858dd0d126e6a6e7f91309a03892f4880e99279d7f2cfb` | 13 |

复现命令见 §9。行号一律指上述 pinned blob 内的行号。

---

## 2. 两个 IPC case 的 parcel 字段与输入可控性（核查 1）

入口（`scene_session_manager_stub.cpp`）：`OnRemoteRequest:30-39` → 描述符检查 `:34` → `switch (code) :44`
→ `TRANS_ID_RECOVER_AND_CONNECT_SPECIFIC_SESSION :47-48` / `TRANS_ID_RECOVER_AND_RECONNECT_SCENE_SESSION :49-50`。

两个 handler 的读取序列完全一致（`:385-424` / `:426-465`），字段来源：

| 字段 | 读取位置 | 来源 | 调用者可控 |
|---|---|---|---|
| `sessionStage` | `:388-389` / `:429-430` | `data.ReadRemoteObject()` + `iface_cast<ISessionStage>` | 是（自带代理对象） |
| `eventChannel` | `:390-391` / `:431-432` | 同上 | 是 |
| `surfaceNode` | `:392` / `:433` | `RSSurfaceNode::Unmarshalling(data)` | 是 |
| `hasProperty` | `:397-401` / `:438-442` | `ReadBool`，失败即 `ERR_TRANSACTION_FAILED` | 是 |
| `property` | `:402-407` / `:443-448` | `ReadStrongParcelable<WindowSessionProperty>()` | 是（整块 parcelable） |
| `token` | `:409-414` / `:450-455` | 仅当 `property->GetTokenState()` 才读一个 remote object | 是 |
| `persistentId` | `window_session_property.cpp:1676` `parcel.WriteInt32(persistentId_)` | `WindowSessionProperty::persistentId_`，随 property 序列化 | **是** |
| `isPersistentRecover_` | — | `SessionInfo` 的成员，**不在** property 的 SessionInfo 往返字段里 | **否** |

关键三点：

1. **`isPersistentRecover_` 不是调用者可给的字段。** `WindowSessionProperty.cpp` 全文没有
   `isPersistentRecover`（`git grep` 为空）；`MarshallingSessionInfo:1338-1369` /
   `UnmarshallingSessionInfo:1372-1436` 只往返 `bundleName_`、`moduleName_`、`abilityName_`、
   `currentRotation_`、`appIndex_`、`continueState`、`want`、`isFollowParentMultiScreenPolicy`、
   四个键盘注册布尔、`isReceiveDragEventEnabled_`、`isSeparationTouchEnabled_` —— **不含
   `persistentId_` 与 `isPersistentRecover_`**。默认值：`isPersistentRecover_ = false`
   （`ws_common.h:468`）、`persistentId_ = INVALID_SESSION_ID`（`ws_common.h:483`，而
   `INVALID_SESSION_ID = 0`，`ws_common.h:51`）。
2. **服务端在查表之前强制置位。** 两条路径都在 task 内先调
   `sessionRecoverStateChangeFunc_(SessionRecoverState::SESSION_START_RECONNECT, property)`
   （`:6043` / `:6193`）→ `OnSessionRecoverStateChange:704-713` → `RecoverSessionInfo:5949-5977`，
   其中 `:5956 sessionInfo.persistentId_ = property->GetPersistentId();`、
   **`:5963 sessionInfo.isPersistentRecover_ = true;`**（`property->EditSessionInfo()` 返回引用，
   写回同一 `sessionInfo_`）。
3. 读取失败路径不发散：任一 `ReadRemoteObject`/`Unmarshalling` 返回空 → `ERR_INVALID_DATA`；
   `hasProperty=false` 时 `property == nullptr` → `CheckSessionPropertyOnRecovery` 首行
   （`:6013-6016`）返回 `WS_ERROR_NULLPTR` → 事务在创建会话之前结束。

---

## 3. 服务端判定链：守卫、支配性与实际效果（核查 2、3）

### 3.1 唯一守卫

`CheckSessionPropertyOnRecovery:6010-6026`：

```
:6013  if (property == nullptr) → WS_ERROR_NULLPTR
:6017  if (!CheckSystemWindowPermission(property)) → WS_ERROR_NOT_SYSTEM_APP
:6021  if (!isSpecificSession && property->GetPersistentId() > 0 && !IsNeedRecover(...)) → WS_ERROR_INVALID_PARAM
```

- `CheckSystemWindowPermission:5838-5916`：`IsUIExtensionWindow` → false（`:5841-5844`）；
  **非系统窗口类型直接 true（`:5845-5848`）**；`DIALOG`/`PIP`/`SELECTION` 也直接 true
  （`:5864-5868`，注释 "some system types could be created by normal app"）；其余系统类型才落到
  `IsSystemCalling()` / `IsStartByHdcd()` / 具体权限（`:5875-5915`）。
- `IsNeedRecover:6000-6008` 只判「`persistentId` 是否在 `alivePersistentIds_` 里」；该列表由
  `SetAlivePersistentIds:5993-5998` 写入，唯一调用点是 WMS 侧 napi
  `js_scene_session_manager.cpp:4432`。

**候选 7 与候选 8 的守卫不对称（重要）**：

| | 候选 7 `:421`（specific） | 候选 8 `:462`（scene） |
|---|---|---|
| 传入 `isSpecificSession` | `true`（`:6032`） | `false`（`:6178`） |
| `IsNeedRecover` 成员检查 | **跳过**（`:6021` 短路） | 要求 `id > 0` 且在 `alivePersistentIds_` |
| `recoveringFinished_` 窗口门 | **无**（`:6039` 只查回调非空） | 有（`:6185 if (recoveringFinished_ \|\| ...)`） |
| `recoverSceneSessionFunc_` 非空检查 | 无 | 有（`:6189-6192`） |
| 是否可能创建主窗口会话 | 否（property 非空 → 见 §3.3） | 是（`:6195` 传 `nullptr`） |

`recoveringFinished_` 只出现在 `scene_session_manager.cpp:6081`（置 true）、`:6113`、`:6185`，
故候选 7 既不受恢复窗口约束、也不受"该 id 应该被恢复"约束。

### 3.2 「取回活会话」这条线索不成立

`GetSceneSessionBySessionInfo:3749-3793` 的第一件事：

```
:3751  if (sessionInfo.isPersistentRecover_) { ...; return nullptr; }
:3756  if (sessionInfo.persistentId_ != INVALID_SESSION_ID) { GetSceneSession(id) ... return session; }
```

由于 §2.2 的 `isPersistentRecover_ = true` 在两次查表之前就已置位（`:6043→6044→6046`、
`:6193→6194→6195`），**`:3756-3762`「按调用者给的 id 返回任意活会话」这一分支在两条候选路径上
不可达**；两条路径必然落到 `CreateSceneSession`（`RequestSceneSession:3832-3845`）。
前序记录中「按调用者 id 取回任意活会话、不比对属主」的描述对本组候选**不成立**，此处更正。

补充：`HandleCreateAndConnectSpecificSession`（候选 4 家族）构造的 `SessionInfo info`（`:5388-5394`）
根本不写 `persistentId_` → 默认 0 → 也不走 `:3756`。该分支实际只被「主窗口启动」类调用者（SCB 侧）
使用，不属本轮范围。

### 3.3 新建会话的实际效果与 id 采纳

- 会话类型由 `CreateSceneSession:3438-3475` 按 `sessionInfo.isSystem_`（parcel 不可控，恒 false）、
  `property == nullptr && IsMainWindow`（MainSession）、`property != nullptr && IsSubWindow`
  （SubSession）、`WINDOW_TYPE_INPUT_METHOD_FLOAT`、`IsSystemWindow` 分派；否则 "Invalid window type"
  → `sceneSession == nullptr` → `:6047-6050` / `:6196-6199` 报错返回。
  **候选 7 的 property 恒非空** → 无法创建 MainSession，只能建 sub / IME / 系统类型会话。
- id 采纳：`SceneSession::SceneSession:192-196` → `GeneratePersistentId(false, info.persistentId_)`
  （`session.cpp:5216-5247`）：

  ```
  :5219  if (persistentId != INVALID_SESSION_ID && !g_persistentIdSet.count(persistentId)) {
  :5220      g_persistentIdSet.insert(persistentId); persistentId_ = persistentId; return;
  ```
  `g_persistentIdSet`（`session.cpp:54`）**只增不删**（全仓仅 `:5220`、`:5244` 两处 insert，
  无 erase），且 `SceneSessionManager::EraseSceneSessionMapById` 不清它。因此**活着的会话、以及
  本进程曾用过的任何 id，都无法被调用者的值占用**；id 不一致时
  `:6053-6061` / `:6202-6208` 走 `EraseSceneSessionMapById` + `SESSION_NOT_RECONNECT` 错误返回。
- 绑定效果：`SceneSession::Reconnect:281-299` → `Session::Reconnect:1853-1887`：
  `:1868 sessionStage_ = sessionStage;`、`:1869 SetSurfaceNode`、`:1870 windowEventChannel_ = ...`、
  `:1871 abilityToken_ = token;`、`:1872 SetSessionPropertyForReconnect(property)`（→
  `session.cpp:4715 property_->CopyFrom(property)`，整块覆盖）、`:1873 persistentId_ = property->GetPersistentId();`、
  `:1874 SetCallingPid(pid);`、`:1875 callingUid_ = uid;`（pid/uid 来自
  `IPCSkeleton::GetCallingRealPid/Uid`，`:6036-6037` / `:6182-6183`，即**调用者自己的真实身份**）。
  该路径**不调用** `CheckPidIfMatched` / `CheckIdentityTokenIfMatched`——这两者只出现在
  `scene_session.cpp:531`、`:634`、`:837`（另一批方法），`ConnectInner:211-266` 也只在主窗口分支
  检查 identityToken（`:226-231`）。

### 3.4 与创建路径的守卫差（对照证据）

| 守卫 | 创建路径 `CreateAndConnectSpecificSession:5272-5439` | 恢复路径（候选 7/8） |
|---|---|---|
| `CheckSystemWindowPermission` | `:5278` | 有（经 `:6017`） |
| `CheckModalSubWindowPermission:5818-5836` | `:5278` | **无** |
| `CheckSubWindowCallingProcess:5918-5947`（父窗口须同进程：`:5937-5942` 比对 `GetCallingRealPid()` 与 `parentSession->GetCallingPid()`） | `:5287` | **无** |
| sub-window 层级上限 `:5295-5300` | 有 | **无** |
| `SessionPermission::IsSystemCalling()` 相关分支 `:5313-5332` | 有 | 无（仅 `CheckSystemWindowPermission` 内部按类型用） |

即：恢复路径缺了「子窗口父进程比对」和「modal 子窗口」两道检查。**这是本组候选唯一的守卫缺口**，
且仅影响"以调用者自选身份新建一个会话"，不触及任何已存在会话。

### 3.5 DIALOG 父会话绑定：跨会话父子关系，但**不是**恢复路径独有

`InitSceneSession:3971` 对 `property->GetPersistentId() != 0` 之外的 DIALOG 调用
`UpdateParentSessionForDialog:2590-2613`：

```
:2597  auto parentPersistentId = property->GetParentPersistentId();
:2600  auto parentSession = GetSceneSession(parentPersistentId);      // 无属主/uid/token 比对
:2606  parentSession->BindDialogSessionTarget(sceneSession);
:2607  parentSession->BindDialogToParentSession(sceneSession);        // session.cpp:2884-2896，push 进父的 dialogVec_
:2608  sceneSession->SetParentSession(parentSession);                 // 调用者的会话持有受害者会话指针
```

`RequestSceneSession` 同时被创建路径（`:5396`）与恢复路径（`:6046`/`:6195`）使用，而
`CheckSubWindowCallingProcess` 对 DIALOG 提前返回 `WS_OK`（`:5922-5924`，`IsSubWindow` 只覆盖
`[APP_SUB_WINDOW_BASE, APP_SUB_WINDOW_END)`，`window_helper.h:63-66`）——**该跨会话绑定在创建路径上
同样无属主校验**。因此它属于恢复路径与创建路径**共有**的机制，按「同一机制不重复计数」原则，
本轮不把它记作候选 7/8 的独立漏洞，只作为影响面待查项记录（消费方在 `SceneSession` /
scene board 侧，需要跨仓证据）。

---

## 4. 可达性：普通应用能不能发这两个事务（核查 4）

### 4.1 应用侧入口是**系统恢复事件**驱动的回调，不是可随时调用的 API

```
wm/src/window_scene_session_impl.cpp:1129-1167  RegisterSessionRecoverListener(bool isSpecificSession)
  :1145-1165  callbackFunc = [..]{ ... isSpecificSession ? RecoverAndConnectSpecificSession()
                                                          : RecoverAndReconnectSceneSession() ... }
  :1166       WindowAdapter::RegisterSessionRecoverCallbackFunc(GetPersistentId(), callbackFunc)
wm/src/window_adapter.cpp:615-621           存入 sessionRecoverCallbackFuncMap_[persistentId]
wm/src/window_adapter.cpp:690-714           HandleRecoverCallback(...) 遍历并执行
wm/src/window_adapter.cpp:850 / 887-896     RegisterRecoverCallback() → SessionManager::GetInstance(userId_)
                                            .RegisterWindowManagerRecoverCallbackFunc(...)
```

即回调由**本进程的 SessionManager（系统恢复通知）**统一触发，单次执行；应用侧没有暴露
「用指定 property 发起恢复」的公开 API。`RegisterSessionRecoverCallbackFunc` 全仓只有 `:1166`
一个调用点，`sessionRecoverCallbackFuncMap_` 只被 `HandleRecoverCallback:714` 消费。

### 4.2 innerkit 里的 `Window::Recover()` **不**到达这两个事务（负结果）

`interfaces/innerkits/wm/window.h:3295/3303/4572/4581/4593` 的 `Recover()` 系列（注释：ACE 恢复按钮 /
JsWindow 调用）实现为 `WindowSceneSessionImpl::Recover:4996/5002/5081/5087/5147/5153` →
`ExecuteRecover:5105-5140`，其效果是 `hostSession->OnSessionEvent(SessionEvent::EVENT_RECOVER, ...)`
+ `SetWindowMode(WINDOW_MODE_FLOATING)`（取消最小化），**与 `TRANS_ID_RECOVER_*` 事务无关**。
「接口存在」不等于「普通应用可到达候选路径」。

### 4.3 代理层与 stub 层都没有权限检查

- `SceneSessionManagerProxy::RecoverAndConnectSpecificSession:155-211` 与
  `RecoverAndReconnectSceneSession:212-...`：只有 `WriteInterfaceToken` / 序列化 / `SendRequest`，
  无任何权限判断；全文件中唯一的权限调用在 `:3677`（另一个方法）。
- `scene_session_manager_stub.cpp`：`SessionPermission` / `VerifyCallingPermission` / `IsSystemCalling` /
  `IsSACalling` / `GetCallingUid` / `GetCallingRealPid` 在**整个文件**中一次都不出现
  （`git grep` 为空），即 WMS 的 stub 层不做逐方法权限判定，判定全部落在 impl 内。
- 服务注册：`sa_profile/4606.json` 无 `permission` 字段（13 行全文见 §1 哈希）。

### 4.4 应用侧类与库的暴露面

- `WindowSceneSessionImpl` / `WindowAdapter` 定义在 `wm/`（应用进程内库 `libwm`），头文件
  `wm/include/window_scene_session_impl.h:659-660` 声明了这两个方法，但 `wm/include/` **不在**
  `interfaces/innerkits/wm/` 的公开头清单里。
- `WindowSessionProperty` 编译进 `libwindow_scene_common.so`（`window_scene/common/BUILD.gn` 的
  `ohos_shared_library("window_scene_common")`，源含 `src/window_session_property.cpp`），其
  `innerapi_tags = [ "platformsdk_indirect" ]`——**间接平台 SDK**，非普通三方 SDK 直接可链。

### 4.5 仓库内结论（诚实边界）

- 本仓库内**找不到**任何阻止普通应用发送这两个事务的检查：stub 无权限、proxy 无权限、SA 无
  `permission` 字段、impl 只做 `CheckSessionPropertyOnRecovery`。
- 但**同样证明不了**普通应用可达：发事务需要 (a) 取得 WMS 的 `ISceneSessionManager` 远程对象
  （`SAMGR::GetSystemAbility(4606)` 的访问控制策略在 samgr/access_token 仓），(b) 构造
  `WindowSessionProperty` 的 parcel 或拿到 `libwindow_scene_common.so` 的符号。两者都在本仓之外。
- 因此**不写成 confirmed，也不因"本地没搜到限制"就断言"没有限制"**；记为 unresolved external
  dependency（见 §6、§8）。

### 4.6 napi/JS 面：已检索（核查 4 的补录）

- **两个候选事务在 JS/napi 层没有任何绑定**（负结果）：
  `git grep "RecoverAndConnectSpecificSession\|RecoverAndReconnectSceneSession" -- interfaces/kits/napi/`
  → 空；`git grep "sceneSessionManager" -- "*.d.ts" "*.ts"` → 空。
- 与恢复相关的**唯一** JS 面是 `notifySessionRecoverStatus`：绑定 `js_scene_session_manager.cpp:268-269`，
  实现 `OnNotifySessionRecoverStatus:4400-4437`，要求恰好 2 个参数（`:4405 argc != ARGC_TWO`，
  `ARGC_TWO = 2`）；`isRecovering == false` 时调 `NotifyRecoveringFinished()` +
  `UpdateRecoveredSessionInfo(ids)`（`:4429-4430`），否则调 `SetAlivePersistentIds(ids)`（`:4432`）。
  该函数体内**没有任何权限检查**。
- **这一点直接关系到候选 8 的窗口**：候选 8 的两道门 `IsNeedRecover(alivePersistentIds_)`（`:6021`）
  与 `recoveringFinished_`（`:6185`）的数据来源正是上面这两个 JS 调用。
  `SetAlivePersistentIds` 声明于 `window_scene/session_manager/include/scene_session_manager.h:305`、
  实现于 `scene_session_manager.cpp:5993-5999`（`alivePersistentIds_` 成员 `:1646`），
  **全仓唯一调用端是 `:4432` 这一个 napi**，无其他写入端；
  该 napi 所在模块注册为 `nm_modname = "sceneSessionManager"`、
  `nm_filename = "libscenesessionmanager_napi.so/sceneSessionManager.js"`
  （`scene_session_manager_module.cpp`，经 `interfaces/kits/napi/BUILD.gn:19` 汇总），
  **由哪个进程加载、是否要求系统身份，在仓外**（§8 项 5）。
- 应用侧唯一与「恢复」同名的 JS API 是 `window.recover`（绑定 `js_window.cpp:12338` →
  `JsWindow::Recover:208` → `OnRecover:2060`），其最终效果（`window_impl.cpp:2744-2766`）只是
  取消最小化 / 归一化窗口模式，**不触达 `TRANS_ID_RECOVER_*`**——与 §4.2 的 innerkit 结论互相印证。

---

## 5. 合法恢复流程所需的输入 vs 候选路径允许的输入（核查 5）

| 项 | 合法流程（应用重启恢复） | 候选路径允许 | 差异 |
|---|---|---|---|
| `property` 来源 | 应用自己的 `property_`（`window_scene_session_impl.cpp:638` / `:688` 传 `property_`） | 调用者自备的任意 `WindowSessionProperty` parcel | 身份字段可自选 |
| `persistentId` | 服务端在创建会话时分配、经 property 回传，恢复时原样带回 | 任意 `int32`；**仅当未被本进程用过**才被采纳（`:5219`），否则报错 | 不能抢占在用的 id |
| `bundleName_/abilityName_/moduleName_` | 应用自身的 HAP 身份（`:667-669` 由 `AbilityContext` 填充） | parcel 可任填，服务端**不**与调用者 UID 比对 | **可冒名** |
| `isPersistentRecover_` | 服务端置 true（`:5963`） | 不可控 | 无差异 |
| 会话复用 | 不复用：`isPersistentRecover_=true` → 新建（`:3751`） | 同左 | 无差异 |
| 额外检查 | 创建路径有 modal 子窗口 / 父进程比对（§3.4） | 恢复路径无 | **守卫缺失** |

---

## 6. 同提交内的旁路校验、代理层、权限声明、服务注册（核查 6）

| 位置 | 结果 |
|---|---|
| `scene_session_manager_stub.cpp` 全文 | 无任何权限/uid/pid/token 检查（`git grep` 为空） |
| `SceneSessionManagerProxy` 两个恢复方法 | 无权限检查（`:155-211`、`:212-...`） |
| `CheckSessionPropertyOnRecovery` | 唯一守卫；候选 7 连 `IsNeedRecover` 都跳过（`:6021`） |
| `recoveringFinished_` | 只保护候选 8（`:6185`），候选 7 无 |
| `alivePersistentIds_` 的写入端 | 唯一写入端是 napi `js_scene_session_manager.cpp:4432`（无权限检查），setter 在 `scene_session_manager.cpp:5993-5999`；加载方/身份要求见 §4.6、§8 项 5 |
| `sa_profile/4606.json` | 无 `permission` 字段 |
| `CheckSubWindowCallingProcess` / `CheckModalSubWindowPermission` | 只挂在创建路径（`:5287`/`:5278`），恢复路径不调用 |
| `UpdateParentSessionForDialog` | 无属主校验，但创建路径同样无（§3.5，不重复计数） |

---

## 7. 判定

判定分两层，**各自有独立的结论对象与计数口径，不能互相代替、也不能合并成一句话**：

| 层 | 结论对象 | 判定 | 计数口径 |
|---|---|---|---|
| **7.A** | 「通过调用者给出的 `persistentId` **取回并接管已有会话**」这一**子假设** | **refuted / likely false positive** | 子假设被删项，**候选记录不减**（负结果保留，见下） |
| **7.B** | 候选 7/8 作为一条 finding 的**整体安全结论** | **未决（plausible but unproven）** | 仍是**同一条**共享机制记录，**不另立**新漏洞、**不重复计数** |

**7.A 只否掉一个子假设，不等于候选整体误报。** 读 §7.A 时不要把它的结论外推到整体 finding。

### 7.A 子假设「取回并接管已有会话」：本仓内证伪 → refuted / likely false positive

三条 in-repo 事实各自独立地否掉了「取回或接管其他会话」：

| # | 事实 | 位置 | 否掉了什么 |
|---|---|---|---|
| 1 | 服务端在查表**之前**把 `isPersistentRecover_` 强制置 true | `scene_session_manager.cpp:5963` | 复用分支 `:3756-3762` 不可达 → `GetSceneSessionBySessionInfo:3751` 必返 nullptr |
| 2 | id 采纳规则：仅当调用者的 `persistentId` **不在**只增不删的 `g_persistentIdSet` 才采纳 | `session.cpp:5219`（成员 `:54`，仅 `:5220`/`:5244` 插入） | 活会话、以及本进程用过的 id，都无法被调用者占用 |
| 3 | id 不一致时服务端擦除新建的会话并返回 `SESSION_NOT_RECONNECT` | `:6052-6061`、`:6202-6208` | 猜测/碰撞 id 得不到任何已有会话对象 |

`CheckSessionPropertyOnRecovery:6010-6026` 之外的路径都不改变这一结论（§3.1–§3.3）。
写回调用者的 `ISession`（`:421`/`:462`）是**它自己刚建的那一个**会话对象。

> **子假设判定：refuted / likely false positive。** 这是仓库内可证伪的负结果
> （三条锚点行 + 固定提交 `8b0d8fe1`），**不是**「本地没搜到限制」的推测。
> 负结果与原始候选记录**保留、不删除**；detector 规则本身不在本轮修改范围。
> **本判定不外推为候选整体的结论** —— 整体仍未决，见 §7.B。
> （更正对象：本报告 §3.2 与前序 `PROGRAM_STATUS.md` §37 中该条线索。）

### 7.B 整体 finding：未决（plausible but unproven），承载"尚未判定的 broader capability / ownership 风险"

7.A 只删掉了「接管已有会话」这一条路径。这两条事务**仍然**（§5、§3.4）：

- 以调用者**自备的** `WindowSessionProperty` 新建一个 sub-window / 系统类型会话；
- 身份字段 `bundleName_`/`abilityName_`/`moduleName_` 任填，服务端不与调用者 UID 比对（**可冒名**）；
- 该路径**缺**创建路径上的 `CheckModalSubWindowPermission`（`:5278`）、
  `CheckSubWindowCallingProcess`（`:5287`，父窗口同进程比对 `:5937-5942`）、sub-window 层级上限
  （`:5295-5300`）；`Session::Reconnect:1874-1875` 会把 pid/uid 改写成调用者的真实身份；
- 叠加 §3.5 的跨会话 DIALOG 父子绑定（`UpdateParentSessionForDialog:2590-2613`，无属主校验）。

这是**尚未判定的 broader capability / ownership 风险**，判定它需要两个条件，而**两者都缺证据**：
(a) 普通应用能否取得 `ISceneSessionManager` 远程对象并发这两个事务（§4.5、§8 项 1–3）；
(b) 「新建一个冒名会话 + 跨会话 DIALOG 父子绑定」对下游（scene board / AMS）造成的具体
C/I/A 影响（§3.5，消费者在仓外）。

> **整体判定：未决（plausible but unproven）。** 既不升 `confirmed`/`reportable`，
> **也**不因 7.A 而定为 false positive；也不因本地未搜到限制就断言无限制。
> 缺证据的两项记为 **unresolved external dependency**（指向缺失的**外部证据**，
> **不是**一条已经成立的新漏洞）。对外部证据的优先次序见 §8.1。

### 7.C 计数与关系口径

- `:421` 与 `:462` **同属一条共享机制**（`CheckSessionPropertyOnRecovery` / `RequestSceneSession` /
  `Session::Reconnect`），按**一条记录**计：**不重复计为两个独立漏洞**。
- 7.A 删除的是**子假设**，**不减少候选计数**；7.B 的残余风险是**同一条记录**里尚未判定的部分，
  **不另立一条候选**。因此本轮结论不产出、也**不折算进** Precision/准确率。
- 两者的守卫差（候选 7 无 `IsNeedRecover`、无 `recoveringFinished_`；候选 8 两者皆有，§3.1）
  **不改变 7.A 的结论**——被跳过的 `IsNeedRecover` 只影响"恢复窗口"的时序约束，
  不构成对已有会话的取回能力；它是 7.B 未决部分的一个加重条件，不是独立发现。

---

## 8. unknown 与缺失证据（进入受控运行时验证所需条件）

证明/否证可达性所缺的外部证据：

1. **SAMGR 访问控制**：普通应用能否 `GetSystemAbility(4606)` 拿到 WMS 对象（`sa_profile` 无
   `permission` 字段，但 samgr 侧可能有基于 `access_token`/SA 白名单的策略）——在 samgr/安全子系统仓之外，本仓无法回答。
2. **库可用性**：普通 app 进程能否加载并调用 `libwindow_scene_common.so`（`platformsdk_indirect`）
   与 `libwm`(z).so 中的 `WindowAdapter`/`WindowSceneSessionImpl` 符号——取决于 SDK 暴露与
   设备 SELinux 域策略（本仓外）。
3. **描述符/parcel 构造可行性**：`OnRemoteRequest:34` 只比对 `GetDescriptor()`；
   该字符串可从设备的 `libwms.z.so` 提取，但「提取+手搓 parcel」的可行性需运行时验证。
4. **napi/JS 面**：**本轮已检索完毕**（§4.6）——两个事务无 JS 绑定；唯一相关 JS 面
   `notifySessionRecoverStatus` 无权限检查但**不在本仓 `*.d.ts` 声明清单内**，其调用方
   （scene board 的 JS）在仓外。仍需外部证据的是：普通应用能否 `import` 该模块
   （`@ohos.sceneSessionManager` 是否为公开 SDK 面）。
5. **`alivePersistentIds_` 的写入端权限**：`js_scene_session_manager.cpp:4432` 所在 napi 由
   `libscenesessionmanager_napi.so`（`scene_session_manager_module.cpp`）提供，**由哪个进程加载、
   是否要求系统身份在仓外**（决定候选 8 的恢复窗口能否被非系统调用者"造出来"）。

运行时验证还缺：完整 OpenHarmony 构建产物（`out/`）、可运行 WMS/SCB 的设备或模拟器、
一个普通（非系统）应用样本、以及可复现的恢复窗口（重启/进程恢复）时序。
**本轮不做动态验证**（用户本轮明确要求不扩大范围）。

### 8.1 是否建议进入受控运行时验证 —— 当前不建议

**当前不为候选 7/8 立项做 PoC 或受控运行时验证。** 理由：7.A 的三条证伪事实都是**源码级确定性
结论**（早退分支 / 只增不删的 id 集合 / 显式擦除+错误码），运行时验证只能**重复确认同一个负结果**；
真正待答的是 7.B 的 broader capability / ownership 风险，而它缺的是**宿主机访问控制与下游影响
证据**（§8 项 1–5），属于**取证与跨仓审计**问题，不是"跑一遍 PoC"能补的。

**重新评估的门槛**（三条同时给出证据后，再讨论是否进运行时）：
(i) 普通应用能取回 SA 4606 的远程对象；(ii) 普通应用能调用这两个恢复事务；(iii) 由此造成**具体的
越权影响**。在此之前保持 unresolved / unknown，不扩大漏洞结论、不启动 PoC。

**下一步研究优先级**（均为**只读**、绑定固定版本仓库与 SHA）：
1. SAMGR 对 SA 4606 的访问控制（`samgr` / `access_token` / 安全子系统仓）；
2. 普通应用可用的库/API 边界（`libwindow_scene_common.so` 的 `platformsdk_indirect`、
   `libscenesessionmanager_napi.so` 的加载身份、SDK 面）；
3. 下游 scene board / AMS 对**新建冒名会话**与**跨会话 DIALOG 绑定**的处理与后果。
   逐条记录所查仓库、commit/blob SHA 与源码位置；若仍不能证明可达性或具体影响，
   **保持 unresolved/unknown 并停止**。

---

## 9. 复现与负结果

读取均使用 `git -C <repo> show <commit>:<path>`（证据脚本 `/home/audit/wtmp/w38_c1..c27.sh`、
`w38_hashes.sh`，均在仓库之外，不入库）。判定所依据的负结果：

- `git grep isPersistentRecover window_scene/common/src/window_session_property.cpp` → 空
  （`isPersistentRecover_` 不是 property 字段）。
- `git grep "SessionPermission\|VerifyCallingPermission\|IsSystemCalling\|IsSACalling\|GetCallingUid\|GetCallingRealPid"
  -- scene_session_manager_stub.cpp` → 空（stub 无逐方法权限检查；同目录 `scene_session_manager.cpp`
  有 40+ 处 `IsSystemCalling()`，说明判定落在 impl 内而非 stub 内）。
- `git grep g_persistentIdSet` → 6 处，仅 insert，无 erase（id 不可抢占的依据）。
- `Window::Recover()` 系列不触达 `TRANS_ID_RECOVER_*`（§4.2）；JS `window.recover` 同样不触达（§4.6）。
- `git grep "RecoverAndConnectSpecificSession\|RecoverAndReconnectSceneSession" -- interfaces/kits/napi/`
  → 空（两个事务无 JS 绑定）。
- `git grep sceneSessionManager -- "*.d.ts" "*.ts"` → 空（该模块不在本仓声明式 API 清单内）。
- `git grep SetAlivePersistentIds` → 唯一非测试调用端是 `js_scene_session_manager.cpp:4432`（§4.6）。
- `RegisterSessionRecoverStateChangeListener` 的调用点是 `SceneSessionManager::Init()`（定义 `:548`，
  调用 `:591`）→ 该回调在服务初始化时注册、生命周期内恒非空，故候选 7 在 `:6039` 的
  `sessionRecoverStateChangeFunc_ != nullptr` **不构成恢复窗口门**（§3.1 守卫差表的依据）。
- 前序记录中「`GetSceneSessionBySessionInfo:3756-3762` 按调用者 id 取回任意活会话」对本组候选
  **不成立**（`:3751` 早退，§3.2）——该负结果保留，用于纠正后续引用，并已据此更正
  `PROGRAM_STATUS.md` §37 的对应表述。
