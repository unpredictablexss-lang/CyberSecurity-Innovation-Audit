# window_window_manager 十四条候选深审：守卫证据、对象归属与外部实现缺口（2026-10-15）

- 输入：当前检测器（`ohscanner.interface.ipc@0.5.0` + 模型 `oh-ipc-2026.10-v3`）对
  `openharmony/window_window_manager` @ `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` 的 **14 条候选**。
- 产出：每条候选的**入口、描述符/权限守卫、派发/对象导出点、守卫支配性、跨文件/跨仓边界与判定依据**；
  **不是**新的漏洞结论。
- 判定分布：**likely false positive 6 条**、**unresolved external dependency 2 条**、
  **plausible but unproven 6 条**、**confirmed 0 条**；`validated_vulnerability` 仍为 **0**。
- **不据此计算 Precision / 准确率**：误报 6 与证据边界 2 **分列**，两者都**不**进入准确率分子/分母
  （理由见 §2、§7.2；独立 holdout 仍不存在）。

## 0. 一句话结论

14 条里 **6 条**的守卫就在实现体里、且支配对象导出点（可复核，属检测器词表问题 M3）；
**2 条**（12/13）确实没有授权码，但它导出的对象**正是客户端库自己的入口对象**，其语义边界
（`sa_profile` 无 `permission` 字段意味着什么、`WINDOW_MANAGER_SERVICE_ID` 的数值与归属）
**在本仓库之外**，本仓库既不能证明也不能否证；
剩下 **6 条**（2/4/5/6/7/8）是同一类问题——**对象归属**：导出对象属于"调用者自己的进程/自己已经持有的会话对象"，
但**没有任何一处把调用者的 uid/pid/bundle 与会话对象的属主做过比较**。
其中 **7/8**（恢复路径）是本组证据最强的一条，链条完整到"攻击者自选 persistentId 取回活会话对象"，
但**仍未过证据门**（可达性与影响未证），本报告只把它记成一条**线索**，不写成漏洞。

## 1. 版本绑定（先做这一步，否则行号会指错地方）

| 项 | 值 |
|---|---|
| 审计声明并使用的 commit | `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` |
| `git_tree` | `24e60146ba2fe4af3aaef20b306a1e306df44617` |
| 本地 `perf-corpus/window_window_manager` 工作树 HEAD | **同一 commit** |
| 六个候选文件的 `source_sha256` vs pinned blob vs 工作树 | **三者一致**（前缀见 §3 表） |

与 dsoftbus 那轮不同，本轮**没有**版本偏移陷阱：候选自带的 `source_sha256`、pinned commit 的 blob、
工作树三者相同，且该 clone 的 HEAD 就是声明 commit。**但引文仍一律** `git -C <repo> show <commit>:<path>`，
不读工作树——规则不因"这次恰好一致"而放松。工具侧绑定方式与 dsoftbus 报告一致
（`audit.py` 用 `git ls-tree -r -z -l <commit>` 建计划、`cat-file blob <oid>` 取原文，
`git_source.py:67` 先 `rev-parse --verify <commit>^{commit}`）。

本轮 14 条分布在 6 个 stub 文件上；其中 **10 条的宿主文件 `file_parse_status=partial`**，
4 条 `complete`（3/12/13/14）。文件级：`source_files_audited=1112`，解析 complete 811 / partial 268。

## 2. 判定口径（四类互斥，禁止互相折算）

| 判定 | 含义 | 本组计数 |
|---|---|---|
| **likely false positive** | 路径上**存在**支配导出点的授权/所有权守卫，守卫内容可复核 | 6 |
| **unresolved external dependency** | 本仓库内的事实已查清（含"确实没有守卫"），但**判定所需的语义在本仓库之外** | 2 |
| **plausible but unproven** | 有**具体**风险线索（守卫缺失点可指认），但利用条件或影响未证 | 6 |
| **confirmed** | 证据门全部满足 + 可复现证据 | **0** |

两处纪律（沿用本项目既有规则并在此重申）：

- **不把"仓库里没找到调用者"写成"没有调用者"**；本组 6 条 plausible 的可达性都写到"未证"为止。
- **不把"外部没有实现"当成漏洞，也不当成安全**；12/13 归 `unresolved external dependency` 而不是 FP，
  也不升级为漏洞。

## 3. 十四条逐条判定表

| # | 家族/锚点 | 入口与描述符守卫 | 实现侧守卫（是否支配导出点） | 导出对象与归属 | 判定 |
|---|---|---|---|---|---|
| 1 | AUTH-02 `screen_session_manager_stub.cpp:738`（sha `404969d1…`, partial） | `OnRemoteRequestInner` `:50` 描述符；switch `:55` | **有，支配**：`:10918` `!IsSystemCalling&&!IsShellCall` → `DM_ERROR_NOT_SYSTEM_APP`；`:10933` `CheckSavePermission` (`:10894-10912`) | PixelMap 截图，无对象 | **FP** |
| 2 | CAP-01 `screen_session_manager_stub.cpp:1778`（同文件, partial） | 同上 `:50` | **无**：case `:1775-1779` 无检查；`GetRenderSession` `:3200-3208` 无检查；同文件唯一在桩内检查是 `:2026` `ProcSetPrimaryDisplaySystemDpi` | `IRemoteObject` 渲染会话令牌（调用者自选 `screenId`） | **plausible** |
| 3 | CAP-01 `session_stage_stub.cpp:1252`（sha `1b66a137…`, complete） | `:95`，描述符 `:98`；case `:199-200` | **有，支配**：`WindowSessionImpl::GetUIContentRemoteObj` `wm/src/window_session_impl.cpp:5062-5075`，`:5064` `!IsSystemCalling` 先返回 | 桩属**应用进程**（`WindowSessionImpl : public virtual SessionStageStub`，`wm/include/window_session_impl.h:93`），导出的是**该应用自己的** UIContent | **FP**（边界方向与假设相反） |
| 4 | CAP-01 `session_stub.cpp:592`（sha `22026ae7…`, partial） | `:121`，描述符 `:124` → `ProcessRemoteRequest:132`，switch `:135`，case `:136` | **无所有权检查**：`SceneSession::ConnectInner :226-231` 仅主窗比 `identityToken`；`Session::ConnectInner session.cpp:1687-1736` 只查状态/空指针后 `:1710/:1715/:1718/:1719` 写入 | `renderSession` = `ScreenSessionManagerClient::GetInstance().GetRenderSessionToken()`（`scene_session.cpp:253`，**无条件赋值**） | **plausible** |
| 5 | CAP-01 `scene_session_manager_stub.cpp:371`（sha `c8a84dff…`, partial） | `:30-38`，描述符 `:34`，switch `:44` | 创建路径 `:5272-5439`：`:5278` `CheckSystemWindowPermission\|\|CheckModalSubWindowPermission`（非系统窗型 `:5845-5848` **直接 true**）、`:5287` `CheckSubWindowCallingProcess`（仅子窗、pid 相等）；`:5313` 只用于 `shouldBlock` | `sceneSession->AsObject()`：**本次调用创建/匹配到的**会话对象 | **plausible**（较弱） |
| 6 | CAP-01 同文件 `:373` | 同 5 | 同 5 | `renderSession` = `:5421` 进程内 SSM 客户端令牌 | **plausible**（较弱） |
| 7 | CAP-01 同文件 `:421` | `:30-38`，描述符 `:34` | `CheckSessionPropertyOnRecovery:6010-6026`：`CheckSystemWindowPermission`（非系统窗型 true）+ *特定会话变体跳过* `IsNeedRecover`；`IsNeedRecover:6000-6008` 只查 `alivePersistentIds_` 成员资格 | 会话对象（`session = sceneSession`）+ `renderSession` | **plausible（本组最强）** |
| 8 | CAP-01 同文件 `:462` | 同 7 | 同 7（非特定变体多一层 `IsNeedRecover`） | 同 7 | **plausible（本组最强）** |
| 9 | CAP-01 同文件 `:1208` | `:30-38`，描述符 `:34` | **有，支配**：`:12969-12982` `!IsSACalling` → `WS_ERROR_INVALID_PERMISSION` | 被查会话的 UIContent remote obj | **FP** |
| 10 | CAP-01 同文件 `:1226` | 同 9 | **有，支配**：`:12984-12991` 同一守卫 | root UIContent remote obj | **FP** |
| 11 | CAP-01 同文件 `:2944` | 同 9 | **有，支配**：`:4779-4791` `!IsSystemCalling` → `WM_ERROR_NOT_SYSTEM_APP` | UIEffectController | **FP** |
| 12 | CAP-01 `session_manager_service_stub.cpp:37`（sha `c0d8b870…`, complete） | `:29` 描述符（全文件唯一检查） | **桩内与实现体内都没有**：`SessionManagerService::GetSceneSessionManager` `session_manager_service.cpp:73-81` 只加锁返回缓存 `AsObject()` | **`SceneSessionManager` SA 对象本身**（即客户端库自己的深层入口） | **external dependency** |
| 13 | CAP-01 同文件 `:41` | 同 12 | 同 12（`:83-90` Lite 变体） | `SceneSessionManagerLite` SA 对象 | **external dependency** |
| 14 | CAP-01 `window_manager_stub.cpp:389`（sha `fc598e1e…`, complete） | `:36` 描述符 | **有，支配**：`window_manager_service.cpp:1608` `!IsSystemCalling&&!IsStartByHdcd` 即 `return`，`finishCallback` 保持 nullptr → 只写 `false`，`:389` 不执行 | `RSWindowAnimationFinishedCallback`（接口定义不在本仓库） | **FP** + 对象类型外部 |

### 3.1 FP 的机制归属（为什么它们会进候选集）

5 条 FP 的宿主文件是 `partial` 解析，但**误报不是解析造成的**，而是**谓词词表**：

- 1：守卫写成 `CheckSavePermission(isUserSave)`（`screen_session_manager.cpp:10933`），真值来自
  `Permission::CheckCallingPermission(CUSTOM_SCREEN_CAPTURE_PERMISSION)` / `SCREEN_CAPTURE_PERMISSION` /
  `CUSTOM_SCREEN_RECORDING_PERMISSION`（`:10902-10910`）——**跨一层非内联函数的名权限校验**，
  未进入 auth 谓词（M3），并且是同文件一跳委派（M6）。
  附注：`:10918` 这一道对 `errorCode != nullptr` 有短路（调用者传 nullptr 可跳过），
  但 `:10933` **无条件**执行，`else` 分支 `:10949` 返回 `nullptr` + `DM_ERROR_NO_PERMISSION`，所以支配性不受影响。
- 3/9/10/11：守卫是 `SessionPermission::IsSystemCalling()` / `IsSACalling()` 的**否定形式早退**，
  且位于**另一个 TU 的实现体**（`wm/src/window_session_impl.cpp`、同文件 `:12969/:12984`、`:4779`）——
  导出点在 stub 里、守卫在实现里，两者不同文件（M6 的"跨文件委派"反向：检测器只看了 stub 那一侧）。
- 14：守卫在 `WindowManagerService::MinimizeWindowsByLauncher`，且**支配关系靠"失败时不构造对象"**实现
  （`finishCallback` 保持 nullptr，走 `:383` 的空分支），不是同一函数内的 if-return —— 这种
  **"守卫通过空值传播支配导出点"**的形态，静态词表更难跟。

**这四条不是要放宽或收紧规则的理由，而是说明 CAP-01 需要一个"对象归属/守卫跨 TU 传播"的义务**（§7）。

## 4. 两条重点候选的证据链与剩余缺口

### 4.1 候选 2 — `screen_session_manager_stub.cpp:1778`（CAP-01，调用者自选 `screenId` 取渲染会话令牌）

```text
[SSM 桩 @ pinned, sha 404969d1…]
client transact(TRANS_ID_GET_RENDER_SESSION)
 └─ ScreenSessionManagerStub::OnRemoteRequestInner        :50   描述符闸门（唯一）
     switch :55
       case TRANS_ID_GET_RENDER_SESSION:                  :1775-1779
           ScreenId screenId = data.ReadUint64();          ← 调用者自选
           sptr<IRemoteObject> renderSession = GetRenderSession(screenId);
           reply.WriteRemoteObject(renderSession);         ← 导出点（本候选锚点 :1778）
 └─ ScreenSessionManager::GetRenderSession                :3200-3208   ← 无任何守卫
 └─ ScreenSession::GetRenderSession                      screen_session.cpp:1007-1010  { return renderSession_; }
      renderSession_ 来源：:72 由 config.renderSession 初始化，并交给
      RSAdapterUtil::InitRSUIDirector(rsUIDirector_, renderSession_)（:180/:189/:216/:242）
      实现体：rs_adapter.cpp:495 rsUIDirector = RSUIDirector::Create(connectToRenderToken, rsUiContext)
```

**能证明的（本仓库内）**

1. 派发路径上**只有描述符校验**；`:1778` 所在 `case` 与 `GetRenderSession` 实现**都没有**权限/所有权检查。
2. 同文件**存在**同形态的检查先例：`ProcSetPrimaryDisplaySystemDpi` `:2026-2031`
   （`if (!SessionPermission::IsSystemCalling()) { … return; }`）——说明"该加而未加"而不是"这个 SA 从不加"。
   （：这是**对照**，不是判定依据；"别处有"不等于"此处必须有"。）
3. 导出对象的**归属**是 `ScreenSession::renderSession_`，而 `screenId` 由调用者指定 →
   调用者拿到的是**它自己选定的那块屏幕**的令牌，不是"它自己窗口的"。

**必须依赖外部/运行时的（本仓库不能判）**

1. `RSUIDirector` / 渲染会话令牌的**接口能力**：真实实现在 foundation/graphics（Rosen）；
   本仓库只有测试 mock（`window_scene/test/dms_unittest/mock/rs/ui/rs_ui_director.h`）。
   **"拿到这个令牌能做什么"是影响判定的全部依据，而它在仓库外。**
2. SA 4607 是否可被非系统调用者取得句柄：`sa_profile/4607.json`、
   `sa_profile/scene_board/4607.json` **无 `permission` 字段**，但"框架如何消费该字段"在本仓库外。
3. 反向事实（削弱"令牌即高危"的直觉，必须记录）：WMS **自己**在正常创建窗口时就把同一种令牌交给应用
   （`scene_session_manager.cpp:5421`、`scene.host/scene_session.cpp:253`）→
   **"应用持有渲染令牌"是设计如此**；本候选的增量是"**任意 screenId**"，不是"有没有令牌"。

→ **判定 `plausible but unproven`**。上限由影响判定（外部）与可达性（未证）共同决定，不是分析深度不够。
   `file_parse_status=partial` 使其证据等级低于同报告另外 4 条 CAP-01。

### 4.2 候选 4 — `session_stub.cpp:592`（CAP-01，`Connect` 的渲染会话回写）

调用方向必须先定死：`SessionStub` 由 **WMS 进程**实现（`session.h:197 class Session : public SessionStub`，
`SceneSession : public Session`），调用者是**应用进程**（`wm/src/window_session_impl.cpp:861`
`hostSession->Connect(iSessionStage, …)`）。

```text
client transact(TRANS_ID_CONNECT)
 └─ SessionStub::OnRemoteRequest                     :121  描述符 :124（唯一）
     └─ ProcessRemoteRequest                         :132  switch :135
         case TRANS_ID_CONNECT → HandleConnect       :136
 └─ SessionStub::HandleConnect                       :545-666
     读：sessionStage(548) eventChannel(550) surfaceNodeId(552) property(565) token(575, 仅当 GetTokenState)
         identityToken(582)
     WSError errCode = Connect(...)                  :589
     reply.WriteParcelable(&systemConfig)            :591
     reply.WriteRemoteObject(renderSession)          :592   ← 导出点（本候选锚点）
     ... property 字段回写 ... reply.WriteUint32(errCode) :663  ← errCode 最后才写，且从不据此分支
 └─ SceneSession::Connect                            scene_session.cpp:268-279
      pid = IPCSkeleton::GetCallingRealPid(); uid = IPCSkeleton::GetCallingUid();   :275-276
 └─ SceneSession::ConnectInner                       :211-266（PostSyncTask 内）
      :226-231  仅当 IsMainWindow 才比 identityToken → CheckIdentityTokenIfMatched(:10279-10288)
      :251-252  落到 Session::ConnectInner
      :253      renderSession = ScreenSessionManagerClient::GetInstance().GetRenderSessionToken();  ← 无条件
      :254      RSUIContextContainer::SetRenderSession(renderSession);
 └─ Session::ConnectInner                            session.cpp:1687-1736
      :1693 property 空检  :1700 会话状态须为 DISCONNECT  :1706 stage/channel 空检
      :1710 sessionStage_ = sessionStage;   :1711 sessionStage_->SetCurrentRotation(...)
      :1712 windowEventChannel_ = eventChannel;  :1715 abilityToken_ = token;
      :1717 InitSessionPropertyWhenConnect(property);  :1718 SetCallingPid(pid);  :1719 callingUid_ = uid;
```

**对提问的直接回答（sessionStage / token / property / identityToken 如何参与身份校验）**

| 参数 | 是否参与身份/所有权校验 | 证据 |
|---|---|---|
| `sessionStage` | **不参与**：被直接接管（`sessionStage_ = sessionStage`，随后被调用） | `session.cpp:1710-1711` |
| `token`（abilityToken） | **不参与**：只存（`abilityToken_ = token`）；仅在 `property->GetTokenState()` 为真时读取，非空判空 | `session.cpp:1715`；`session_stub.cpp:574-580` |
| `property` | **不参与**：只做空检 + `InitSessionPropertyWhenConnect` + SceneSession 层若干字段回写 | `session.cpp:1693/1717`；`scene_session.cpp:232-249` |
| `identityToken` | **仅主窗**比一次，且**空值即通过**；失败返回 `WS_OK`（静默不动，但桩仍照常回写） | `scene_session.cpp:226-231`、`:10279-10288` |

**最关键的三条事实**

1. **Connect 路径上没有所有权检查**：`pid`/`uid` 取自 `IPCSkeleton`（真实调用者），但只被**写入**会话
   （`SetCallingPid`/`callingUid_`），**从不与属主比较**。本仓库**存在**这样的比较函数
   （`SceneSession::CheckPidIfMatched` `:10290-10298`，比 `GetCallingPid()`），**但它只被
   Foreground/Background/Disconnect 使用，Connect 用不到** —— 这是一条可复核的"守卫存在但未施加"。
2. **`renderSession` 是无条件赋值的**（`scene_session.cpp:253`，在 `if (ret != WS_OK)` 之前）→
   即使 `ConnectInner` 失败（如会话状态不是 DISCONNECT），回复里**仍然**带一个渲染会话令牌。
3. `identityToken` 的弱比较（**任一侧为空即视为匹配**）是**独立**的一条观察；
   本报告**不**把它判成漏洞（它是否可被利用取决于 `clientIdentityToken_` 的赋值时机，未在本轮验证）。

**剩余缺口（为什么是 plausible 而不是 confirmed）**

- **能否拿到别人的 `ISession` 对象** ——这正是候选 5/6/7/8 的同一个问题，见 §5，未证。
  若只能对自己的会话调用 `Connect`，本候选回落到"导出自己进程的令牌"，无越权。
- **渲染令牌与 `Ace::UIContent` 的能力语义**在 foundation/graphics、foundation/arkui 之外（同 §4.1）。
- 本候选 `file_parse_status=partial`。

→ **判定 `plausible but unproven`**；"返回的 renderSession 是否属于发起连接的会话"的**当前证据上限**是：
  它由 `ScreenSessionManagerClient`（**进程内**客户端）取回，因此**属于调用者进程当前屏幕会话**，
  而**不**是按被调用的那个会话对象逐个授权的——语义上"属于会话"这一层并未由本仓库的代码保证。

## 5. 本组证据最强的一条线索：候选 7/8 的恢复路径（**仍是线索，不是漏洞**）

候选 5–8 共用一条"对象归属"链路。5/6（创建路径）相对弱：`:5388-5394` 由**服务端**重建 `SessionInfo`，
**没有把调用者给的 `persistentId_` 带进来**（默认 `INVALID_SESSION_ID`），所以按 id 取回既有会话这条路在创建路径上关闭。
**7/8（恢复路径）不同**：

```text
[SceneSessionManagerStub @ pinned, sha c8a84dff…]
TRANS_ID_RECOVER_AND_CONNECT_SPECIFIC_SESSION  → HandleRecoverAndConnectSpecificSession   :385-…
TRANS_ID_RECOVER_AND_RECONNECT_SCENE_SESSION   → HandleRecoverAndReconnectSceneSession    :~415-…
  （读 sessionStage/eventChannel/surfaceNode/property，token 仅当 property->GetTokenState()；桩内无权限检查）

 └─ SceneSessionManager::RecoverAndConnectSpecificSession        :6028-6075   （另一条 :6174-6221）
     :6032  CheckSessionPropertyOnRecovery(property, isSpecific)
              :6017  CheckSystemWindowPermission(property)  → 非系统窗型一律 true（:5845-5848）
              :6021  仅非特定变体才查 IsNeedRecover → :6000-6008 只查 alivePersistentIds_ 成员资格（不是属主）
     :6044  SessionInfo info = property->GetSessionInfo();      ← persistentId_ 来自调用者
     :6046  sceneSession = RequestSceneSession(info, property);
              └─ :3832  GetSceneSessionBySessionInfo(info)
                   :3751  isPersistentRecover_ 为真 → nullptr（走新建）
                   :3756-3762  persistentId_ 有效 → GetSceneSession(persistentId_)
                                → 返回 **任意同 id 的活会话**（仅要求 !isRemoving_），**不与属主比较**
     :6052-6053  事后等值检查 persistentId == info.persistentId_
     :6062  sceneSession->Reconnect(sessionStage, eventChannel, surfaceNode, property, token, pid, uid)
              └─ Session::Reconnect  session.cpp:1853-1887
                   :1868 sessionStage_ = sessionStage;    ← 接管调用者的 stage
                   :1870 windowEventChannel_ = eventChannel;
                   :1871 abilityToken_ = token;
                   :1872 SetSessionPropertyForReconnect(property)   → property_->CopyFrom(property)（:4715）
                   :1873 persistentId_ = property->GetPersistentId();
                   :1874 SetCallingPid(pid);  :1875 callingUid_ = uid;   ← 把调用者的 pid/uid 写进被接管会话
     :6071/:6217  session = sceneSession;   → 桩回写会话对象 + 渲染会话令牌
```

**为什么它比其他 12 条更接近证据门**（全部可在 pinned 上复核）：

- **按 id 取对象，且不比对属主**：`GetSceneSessionBySessionInfo:3756-3762`；
- **恢复路径的守卫不覆盖所有权**：`CheckSessionPropertyOnRecovery` 只做窗型检查；
  `IsNeedRecover` 只查 `alivePersistentIds_`（**特定会话变体连这一层都跳过**，`:6021` 的 `!isSpecificSession`）；
- **接管动作会改写会话属主字段**（`:1874-1875`）——一旦此路可走，后续所有以
  `GetCallingPid()` 为准的判断（例如 `:6749`、`:5937`、`CheckPidIfMatched`）都会**接受**新的 pid；
- **`persistentId` 的取值空间小且可预测**（`Session::GeneratePersistentId` `session.cpp:5216-5247`：
  自增计数取低 30 位；且**若调用者给的 id 未被占用就直接采纳**）；
- 客户端侧确实有到这两个事务的**库内路径**：`SessionManager::GetSceneSessionManagerProxy`
  （`session_manager.cpp:221/:278`，经 `WINDOW_MANAGER_SERVICE_ID` 取 SA）→
  `SceneSessionManagerProxy::RecoverAnd…`（`:155/:212`）→
  `WindowSceneSessionImpl::RecoverAnd…`（`wm/src/window_session_impl.cpp:608/:658`，
  由 `:1160-1161` 回调触发）。

**缺口（这就是它不能升级的原因）**：

1. **`entry_controlled` 未论证**：库内那条路径用的是**应用自己的 `property_`**（`:637-638`、`:687-688`），
   所以"经公开 API 换个 persistentId"不成立；要换成别人的 id，调用者必须**自备 property/自行构造该事务**。
   "第三方应用能做到"在本仓库内**只有可行性论证，没有证据**（`sa_profile` 无 `permission` 字段、
   fuzz 观测面 `test/fuzztest/window_scene/screensessionmanager_fuzzer/screensessionmanager_fuzzer.cpp:44`
   是旁证，不是证明）。
2. **本仓库外是否还有一层校验**未查（AMS/token 侧、`MockSessionManagerService` 之外的用户校验等）。
3. **影响未证**：拿到被接管会话对象 + 渲染令牌后能做什么，仍需运行时证据；
   本仓库只能证明"门开着"，证明不了"门后是金库"。
4. `isPersistentRecover_` 是**parcel 可控**字段（`window_session_property.cpp:1676/:2019` 编解码、
   `js_scene_utils.cpp:518` 可由 JS 设置、默认 false 见 `ws_common.h:468`），
   它决定走"按 id 复用活会话"还是"按 id 新建"；这条分支对本线索的走向是决定性的，值得下一轮单独钉。

→ 记录为 **`plausible but unproven`（本组最强）**，**不**升级、**不**写成漏洞。
   候选集**不按严重度排序**这件事本身应写进方法卡（§7.3）。

## 6. 本仓库无法判定的边界（外部依赖清单）

| 外部对象/语义 | 本仓库中的形态 | 影响的候选 |
|---|---|---|
| `RSUIDirector` / 渲染会话令牌（`IRenderSession` 全树不存在） | 仅测试 mock（`test/dms_unittest/mock/rs/ui/rs_ui_director.h`）；真实实现在 foundation/graphics | 2、4、6、7、8 |
| `Ace::UIContent`（`ui_content.h`） | 外部 include，无本仓库定义 | 3、9、10 |
| `RSIWindowAnimationFinishedCallback` / `RSWindowAnimationFinishedCallback` | 只有 `<rs_window_animation_finished_callback.h>` include，无类定义 | 14 |
| `WINDOW_MANAGER_SERVICE_ID` 的**数值与归属** | 全树无定义，只被使用 | 12、13（及 5–11 的可达性） |
| `sa_profile` 的 `permission` 字段语义 | 4606 / 4607 / scene_board 4607 **均无该字段**；消费方在框架侧 | 全部 |
| 运行时调用者身份/令牌是否通过 | 源码不可判 | 全部 |
| `IsSystemCalling()`/`IsSACalling()` 底层 access-token 行为 | 本仓库只到 `IPCSkeleton`/`AccessTokenKit` 调用点 | 1、3、9、10、11、14 |

**覆盖缺口**：14 条中 10 条的宿主文件解析为 `partial`（1/2/4/5/6/7/8/9/10/11），
文件级 partial 268 / complete 811（占总选中文件约 24.9%）。本报告的判定**不**建立在"partial 文件里的守卫都找到了"这一假设上；
对 partial 文件，只有**直接读到的**守卫才计入 FP 依据。

## 7. 对检测器/流程的建议（本轮**不改**任何规则）

1. **新增义务类型 `object_ownership`（或在 CAP-01 上扩展）**：CAP-01 现在的判据是
   "导出点附近没有识别到授权谓词"。本组 6 条 FP 说明还差两件事：
   (a) **守卫跨 TU 传播**（导出在 stub、守卫在实现体；`wm/` 与 `window_scene/` 不同目录）；
   (b) **对象归属**（导出对象是调用者自己的，还是可被调用者选定的）。建议把
   "调用者能否影响被导出对象的身份"（如 `persistentId`/`screenId`/窗口句柄来自 parcel）作为一条**可记录的事实**，
   而不是让它继续体现为 severity 相同的候选。**这是契约变更，须单独落地并带正例/反例/无关对照。**
2. **误报与证据边界继续分列**（沿用 dsoftbus 报告的 §3.2）：本组 6 FP + 2 external dependency
   **不**用于计算 Precision；把证据边界计作误报会低估准确率，把误报计作边界会高估。
3. **候选集当前不按严重度/归属风险分层**：本组 14 条里证据最强的 7/8 与最弱的 6 在报告里平权。
   建议报告侧增加一个**仅由已记录事实推导**的分层字段（不改判定），供人工排序用。
4. **复核流程固化（本轮再次适用）**：候选 → `source_sha256` → pinned commit → `git show <commit>:<path>` → 才谈行号。
   本轮虽三处一致，流程仍照做；工作树不可作为证据来源。

## 8. 复现命令

```bash
R=/home/audit/openharmony-audit/perf-corpus/window_window_manager
C=8b0d8fe1b973d865904c942c286b3d2a3b9b08e7

# 版本绑定：工作树 HEAD == 声明 commit；六个候选文件的 sha256 三者一致
git -C $R rev-parse HEAD

# 候选 1（AUTH-02）守卫链
git -C $R show $C:window_scene/screen_session_manager/src/zidl/screen_session_manager_stub.cpp | sed -n '46,56p;733,743p'
git -C $R show $C:window_scene/screen_session_manager/src/screen_session_manager.cpp | sed -n '10894,10953p'

# 候选 2（CAP-01，重点）
git -C $R show $C:window_scene/screen_session_manager/src/zidl/screen_session_manager_stub.cpp | sed -n '1775,1780p;2026,2031p'
git -C $R show $C:window_scene/screen_session_manager/src/screen_session_manager.cpp | sed -n '3200,3208p'
git -C $R show $C:window_scene/session/screen/src/screen_session.cpp | sed -n '1007,1010p'

# 候选 3（SessionStageStub：桩在应用进程，守卫在实现体）
git -C $R show $C:window_scene/session/container/src/zidl/session_stage_stub.cpp | sed -n '95,106p;1247,1255p'
git -C $R show $C:wm/src/window_session_impl.cpp | sed -n '5062,5075p'

# 候选 4（ISession::Connect，重点）
git -C $R show $C:window_scene/session/host/src/zidl/session_stub.cpp | sed -n '121,140p;545,596p'
git -C $R show $C:window_scene/session/host/src/scene_session.cpp | sed -n '211,266p;10279,10300p'
git -C $R show $C:window_scene/session/host/src/session.cpp | sed -n '1687,1736p'

# 候选 5–8（SceneSessionManager：创建/恢复两条路径）
git -C $R show $C:window_scene/session_manager/src/zidl/scene_session_manager_stub.cpp | sed -n '30,44p;327,362p;385,412p;371,373p;421p;462p'
git -C $R show $C:window_scene/session_manager/src/scene_session_manager.cpp | sed -n '3749,3793p;3828,3902p;5272,5440p;5838,5947p;6000,6026p;6028,6075p;6174,6221p'
git -C $R show $C:window_scene/session/host/src/session.cpp | sed -n '1853,1887p;4713,4728p;5216,5247p'

# 候选 9/10/11（同文件，实现体守卫）
git -C $R show $C:window_scene/session_manager/src/scene_session_manager.cpp | sed -n '12969,12991p;4779,4791p'

# 候选 12/13（session_manager_service：桩与实现体都没有守卫）
git -C $R show $C:window_scene/session_manager_service/src/session_manager_service_stub.cpp
git -C $R show $C:window_scene/session_manager_service/src/session_manager_service.cpp | sed -n '73,91p'
git -C $R show $C:sa_profile/4606.json; git -C $R show $C:sa_profile/4607.json

# 候选 14（WindowManagerStub：由空值传播实现的支配）
git -C $R show $C:wmserver/src/zidl/window_manager_stub.cpp | sed -n '32,39p;370,396p'
git -C $R show $C:wmserver/src/window_manager_service.cpp | sed -n '1605,1616p'

# 候选报告本体（含 source_sha256 / plan_sha256 / 计数）
python3 -c "import json;d=json.load(open('/home/audit/wtmp/rescan/window_window_manager.json'));print(d['commit'],d['git_tree'],d['plan_sha256']);print(d['counts'])"
```

## 9. 本报告明确没做的事

- **没有修改任何检测器规则或契约**：§7 全是建议；`object_ownership` 是**新契约**，须单独落地并带正/反例与无关对照。
- **没有升级任何候选**：14 条仍是 `evidence_type=syntax`，`validated_vulnerability=0`，`confirmed=0`。
- **没有删除任何负结果**：6 条 FP 全部保留并给出可复核的守卫位置。
- **没有把外部缺口判成漏洞，也没有判成安全**：12/13 记为证据边界。
- **没有跑动态验证**：本组结论全部静态。7/8 这条线索若要推进，路径是
  "先钉住 `isPersistentRecover_` 分支 + 可达性论证"，再考虑本地隔离环境的运行时复现。
- **没有宣称 Precision/Recall**：独立 holdout 仍不存在（`research/corpus/interface/ipc/verified_pairs.jsonl`
  12 条全为 `split=design`）。
