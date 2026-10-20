# AAFWK AppMgr CAP-01 跨服务边界复核

复核日期：2026-10-19
固定组件：openharmony/aafwk_standard @ 834a566b1372268c7bbb0c40362322f812ca6efc；tree c3744c8c230573a4bcdb76bf49493a1ea61c72d1。
检测器：B 线 ohscanner.interface.ipc 0.12.12；规则 ipc.capability.export。
两条观察均在成员函数指针语法归一化后由 partial 变为 complete，候选键保持不变。

## 结论

这两条候选都不能按“已找到服务端授权”降为 false positive。

- HandleGetAmsMgr 调用 AppMgrService::GetAmsMgr，当前固定实现直接返回 amsMgrScheduler_，未见调用者权限检查；stub 随后把该 remote object 写入 reply。
- HandleGetAbilityRecordsByProcessID 接受请求中的 pid，调用服务端后端取得对应运行记录，并把记录中的 Ability token remote objects 写入 reply。该路径没有调用同文件存在的 VerifyProcessPermission helper，也没有看到针对调用者与 PID 所属进程的比较。

固定仓内的 sa_profile/501.xml 定义 AppMgr 组件 systemability，但没有 permission 节点。仓内服务注册与配置证据说明存在系统服务入口，不足以证明普通应用在具体产品构建上可调用 GetSystemAbility 或成功使用这个接口；SAMGR/AccessToken 的系统访问策略、产品签名与实际句柄获取仍未绑定。因此两条目前的结论是 **source-local capability export observed; product reachability and impact unknown**。保留 candidate/unassessed，不标 confirmed。

第二条是这两条里优先级更高的待查路径：它由请求端提供 pid，返回一组跨进程 Ability token。要判断安全影响，必须弄清调用者能否指定任意运行中进程、这些 token 实际授予哪些能力、其他服务端是否另有访问限制。源码当前证据支持进一步调查，不支持已经发生越权的断言。

## 逐条证据

| 候选键 | 路径与本地检查 | 当前复核 |
|---|---|---|
| 458097b74283dce6 | AppMgrStub::HandleGetAmsMgr（app_mgr_stub.cpp:158）调用 GetAmsMgr，非空时 reply.WriteRemoteObject(amsMgr->AsObject())；AppMgrService::GetAmsMgr（app_mgr_service.cpp:264）直接 return amsMgrScheduler_ | 未发现本地 caller guard；返回能力的下游接口授权与 SA 句柄获取策略尚未查清。保留候选 |
| 8d6ff9efe6b81247 | HandleGetAbilityRecordsByProcessID（app_mgr_stub.cpp:354）读取 parcel pid，调用 GetAbilityRecordsByProcessID，并序列化每个 token；AppMgrService（app_mgr_service.cpp:411）仅检查 IsReady 后委托；Inner（app_mgr_service_inner.cpp:2166）按给定 pid 查 record，枚举 Ability remote token | 未发现本地 caller/PID owner guard；VerifyProcessPermission（Inner :2179）存在但该路径未调用。访问可达性和 token 能力后果未证明。保留候选并优先查证 |

## 证据边界

已验证：
- AppMgrStub 的两条远程分派处理函数将 remote object/token 写入 caller reply。
- GetAmsMgr 当前实现没有应用服务层检查。
- GetAbilityRecordsByProcessID 当前实现没有调用 VerifyProcessPermission，也未将 IPCSkeleton::GetCallingPid() 与请求 pid 比较；它根据传入 pid 查找运行记录并返回该记录 Ability token。
- sa_profile/501.xml 内容没有 permission 声明；AppMgrService 使用 APP_MGR_SERVICE_ID 注册。
- 候选源文件为 complete；这只表示该源文件语法解析完整，不代表全产品调用链闭合。

unknown：
- 普通 app 是否能在目标设备的系统策略下获取 SA 501 remote object 并使用相关事务。
- 501.xml 在目标产品构建中的实际装载方式、SA ACL、访问控制与权限策略。
- IAMS/AmsMgr 返回对象的各个操作是否针对调用者另有权限要求；获得对象是否等于获得可滥用能力。
- 任意应用能否通过该接口取得其他进程的 Ability token；token 暴露后可能执行什么操作，实际影响边界是什么。
- 请求 PID 的攻击者控制与目标选择在公开 API / 运行时部署下的可达性。

## 下一步验证建议

1. 固定同一 OpenHarmony 产品构建的 SA profile、SAMGR/access-token 访问策略和 AppMgr 注册配置，确认外部调用者获取 SA 501 的前置条件。单独看到 XML 无 permission 节点不等于全局匿名可调用。
2. 对 GetAmsMgr 返回的 IAMS/AmsMgr 接口逐方法映射权限检查，验证 capability possession 是否被下游约束。
3. 对 GetAbilityRecordsByProcessID 做授权测试矩阵：自身 PID、同 UID 进程、不同普通应用 UID、系统 UID、无效 PID；仅在隔离测试设备和测试应用上运行。记录返回 token 是否可被跨 caller 使用，以及其允许的具体操作。
4. 将入口身份、外部 SA policy、请求 pid 与 calling pid、返回 token 能力分成独立证据义务；缺一项时保持 unknown。
5. 在外部 reachability 与 token capability 没有证据之前，不升为 confirmed，也不把其他调用者方法上的 VerifyProcessPermission 当成本路径守卫。

## 固定源绑定

| 文件 | Git blob | 内容 SHA-256 |
|---|---|---|
| interfaces/innerkits/app_manager/src/appmgr/app_mgr_stub.cpp | 62301fe0ec1b8b829261395fce6c6bcb2e170341 | bd5cec80057f1df5a2d6e19048daa25eeaa3d9b7b47f5bdf577578993310fa6d |
| services/appmgr/src/app_mgr_service.cpp | ca2af94755d99aba7524bc96c9eccf17848cde7b | 7a24f28ea0718c9b080ac18ed0babf876b99a2c4adf9dde66673e76ff8147e6e |
| services/appmgr/src/app_mgr_service_inner.cpp | 18a724c51b08462246e9fe0bfd14133c4f9d5e1a | 05390c53aa4827bb9df5a3e68bd3cda01b6ef4c36822e611cde0b48bb97af88b |
| sa_profile/501.xml | 0f8bd438e5071ea33dcd4aec51a00c7fec1b506d | 60cc2788bc2f2d5fbe46aebb7f746c39dabc71556c01ff2f9168fa33923c560a |

哈希由固定 commit 的 git show <commit>:<path> 计算。本轮没有修改 detector、测试、目标源码或队友工作树；没有运行产品构建/设备动态验证。此报告只补充两条人工复核，不改写原候选输出。
