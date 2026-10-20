# AAFWK AbilityManager 能力导出与 caller-token 关联复核

复核日期：2026-10-19
固定源码：openharmony/aafwk_standard @ 834a566b1372268c7bbb0c40362322f812ca6efc；tree c3744c8c230573a4bcdb76bf49493a1ea61c72d1。
Detector 0.12.12；本报告核对三条解析升级后的 CAP-01 观察，并结合 AppMgr 的 GetAbilityRecordsByProcessID 候选追踪一个源码内可见的 capability-flow 假设。所有 raw candidates 仍是 unassessed；本报告不确认漏洞。

## 结果概览

| 候选键 | 锚点 | 复核结果 |
|---|---|---|
| ffa8b04cd4d24ee0 | AbilityManagerStub::AcquireDataAbilityInner，ability_manager_stub.cpp:294 | 找到 URI、目标可见性、静态配置权限及 callerToken 存在性校验；但 callerToken 是否属于实际 IPC caller 未证。保留 unknown，不按单纯缺少服务端策略作 FP |
| bf2d852588d4bd33 | AbilityManagerStub::GetWantSenderInner，:583 | AbilityManagerService/PendingWantManager 用实际 callingUid、目标 bundle uid 与 APL 约束普通 app 的跨 bundle 请求；新建 PendingWantRecord 记录 callerUid。likely false positive：局部 stub 未显示的集中策略 |
| 85d6d48234cb309d | AbilityManagerStub::GetTopAbilityTokenInner，:1260 | 服务端 GetTopAbility 直接返回 WMS 当前 focus token，没有本地 caller check。SA/系统能力入口和 returned token 的可用操作仍未验证；保留 candidate/unknown |
| 8d6ff9efe6b81247 | AppMgrStub::HandleGetAbilityRecordsByProcessID，app_mgr_stub.cpp:359 | 前一份 AppMgr 复核已证实请求提供 PID，服务端按该 PID 返回 Ability token 集合；与 AcquireDataAbility 的 callerToken 参数形成待验证的两跳能力关联 |

## AcquireDataAbility：有目标授权，但 caller token 的主体绑定未闭合

Stub 从 parcel 读 URI、tryBind 和 callerToken，调用 AbilityManagerService::AcquireDataAbility 后把返回的 IAbilityScheduler 写入 reply。

Service（ability_manager_service.cpp:1873）对非系统 UID 要求 VerificationAllToken(callerToken)；验证 URI scheme/path，解析目标 Ability，执行 CheckDataAbilityRequest（包含目标可见性检查）及 CheckStaticCfgPermission，之后才由 DataAbilityManager::Acquire 返回 scheduler。故原规则描述的“没有任何 authorization”不完整，至少目标策略在服务端统一实施。

但 VerificationAllToken（service :3128）查 token 是否存在于所有 mission/data/connect manager 的 live records；当前实现看起来没有将该 token 的 owner UID 与 IPCSkeleton::GetCallingUid() 比较。DataAbilityManager::Acquire（data_ability_manager.cpp:45）随后通过 Token::GetAbilityRecordByToken(client) 解析此 token，并将它作为 client 加入 DataAbilityRecord。目标静态权限检查使用 IPC caller 的 AccessToken；token 参数则参与客户端身份/生命周期关联。

因此不能将该候选简单判作误报。待查的具体问题是：未授权调用者是否可能得到其他应用的 live Ability token，或把任意有效他人 token 作为 callerToken，进而改变服务端记录的 client 身份；AppMgr 的 GetAbilityRecordsByProcessID 又是否能提供这种 token。两条路径都需要产品级 SA reachability 和 token 操作后果证据。

## GetWantSender：有跨文件 caller/target 身份策略

Stub 调用 GetWantSender 后把 IWantSender remote object 写入 reply。服务端 AbilityManagerService::GetWantSender（:1468）读取 IPCSkeleton::GetCallingUid()，解析指定 bundle 的 uid 与 privilege level，再调用 PendingWantManager。

PendingWantManager::GetWantSender（pending_want_manager.cpp:44）对非 SA、非 system-basic/core 目标检查 callingUid == target uid；跨 bundle 请求被拒绝。通过后创建 PendingWantRecord，并将 callerUid 写到记录中（:62 之后的创建路径）。这直接解释了 AUTH/CAP 模型只在 stub-local 查看返回对象、却看不到服务端策略时产生的候选。

对这条“缺少 caller authorization”的候选，当前应归为 likely false positive / centralized caller-target policy observed。它不代表所有 WantSender 操作安全；每个后续 Send/Cancel 操作及 PendingWantRecord 的授权仍需按独立规则判断。

## GetTopAbilityToken：目前仍为 unknown

Stub 直接把 GetTopAbility 返回的 token 写入 reply。固定实现（ability_manager_service.cpp:4085）仅调用 WMS GetFocusWindow，没有本地调用者权限判断。它是能力导出；候选的源代码路径完整，不因没有 sanitizer 或外部报告而删掉。

但此快照没有闭合 AppMgr/AbilityManager SA 的产品 access policy，也没有证明普通 app 能到达事务 1124；同时也未验证 focus token 对持有者可执行哪些操作、下游是否另有 owner 检查。维持 candidate/unassessed，后续优先核对 SA 可达性与 token 后续接口，避免把“导出 token”直接写成越权结论。

## 跨候选能力链：只记假设，不合并原始候选

源码支持如下静态连接：

1. AppMgr GetAbilityRecordsByProcessID(pid) 返回该运行记录的 Ability remote tokens。
2. AbilityManager AcquireDataAbility(uri, tryBind, callerToken) 接受 callerToken；服务端的 VerificationAllToken 确认它属于某个 live Ability，而非明显比较 token UID 与当前 IPC UID。
3. DataAbilityManager 将该 token 作为 client 关联到目标 DataAbilityRecord，并返回 IAbilityScheduler。

这是一个值得用产品/运行时证据验证的 caller-identity/capability 链，不是已证利用链。其前提包括普通调用者可否到达 AppMgr SA、能否查询任意 PID、token 是否可序列化/重用、Acquire 的目标权限如何限制影响，以及 returned scheduler 的权限边界。缺少任何一项都应维持 unknown。两条 CAP-01 与 AUTH-02 候选仍保留为各自独立观察，不合并成一个 finding。

## 对检测器的改进方向

本组样本要求 B 线区分“目标政策存在”和“请求身份绑定成立”：
- 对跨文件 policy helper 建精确路径摘要，要求唯一调用关系和拒绝分支先于能力产生。
- 对 callerToken、callingUid、targetUid 与 token-record owner 单独建身份域；确认 token 存在不能替代 owner == IPC caller。
- 对 WriteRemoteObject / returned binder 增加能力来源、接收方、后续使用与 owner-check obligation；缺产品 SA 策略或后续接口证据时，保留候选/unknown。
- 增加正/反例：同 UID 的 WantSender、跨 UID 被拒绝、有效同进程 callerToken、无效 token、其他 app 的 live token、获取他人 Ability token 后作为 Acquire callerToken、focus token 对照。先做固定源码/模拟协议验证，真实设备链另行授权与隔离。
- 不以三条候选数减少作为准确率提升，逐条记录原始候选、关联链、人工分类与固定证据。

## 范围与验证限制

本轮只做固定源码静态复核，不改 scanner、候选 JSON、团队 B 源仓或 A 线。没有构建 OpenHarmony 产品、没有设备 PoC、没有 Harness 运行。八仓归一化报告中的全量单测为 727 tests OK、36 skipped；本轮没有代码改动，未重跑测试。B scanner validated_vulnerability/confirmed 仍为 0。

建议在取得 SA ACL 与测试设备后，先验证 GetAbilityRecordsByProcessID 的调用权限和目标 PID 范围；只有确实能取得跨应用 token 时，再在隔离设备上验证 AcquireDataAbility 的 callerToken 主体关联。



## 固定源码文件哈希

所有文件均来自 commit 834a566b1372268c7bbb0c40362322f812ca6efc。Git blob 与内容 SHA-256：

| 文件 | Git blob | 内容 SHA-256 |
|---|---|---|
| services/abilitymgr/src/ability_manager_stub.cpp | 9d9d65813728e6d6da0716f93813e63228f3a3fd | 182fc1f0f1d52a3c543b3dd360871334af41d41a3189782eee37af0e6f9e6d4c |
| services/abilitymgr/src/ability_manager_service.cpp | 92db77f364c30ead75d060748a092847c64539d2 | d49042ecc16a55eddcc158dc64cae0c8918310ce9e126afab0d0c54ce2694669 |
| services/abilitymgr/src/data_ability_manager.cpp | 4f2e0b6ad7e236288d2adc7ab2e37612affcaf3a | 7afacfb22ed8791c41f107d550bd8856d89b730dc366887272d67850246b1b65 |
| services/abilitymgr/src/pending_want_manager.cpp | c84d8a780ae36df645bddf121d6a985bac142164 | 083473f5652405a5192a365da9ad512ce315e029643d9ffb97c43c397a913666 |
