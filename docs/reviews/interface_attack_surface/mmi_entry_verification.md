# MMI IPC Entry 核验与原索引修订

2026-10-09；源码固定 commit 2468d204d3f276c373841e057af35985296c8421。
主线项目 main 基线 dcd9629f50a34545d75abc92c0a16c79723197db。
本页是人工源码结构核验，不是运行时测试、真实漏洞标注或完整调用图。
所有源文件下载自 GitHub 官方 openharmony/multimodalinput_input Git blob API，12 份文件字节长度与 blob/SHA-256 通过离线校验，清单见 research/corpus/interface/mmi_source_manifest.json。

## 已确认的源码事实
| 事实 | 仓库相对文件 / 行 | 范围与局限 |
|---|---|---|
| MMIService 继承 SystemAbility、MultimodalInputConnectStub | service/module_loader/include/mmi_service.h:40 | 类声明关系，不证明任意应用可达 |
| ALLOC_SOCKET_FD = 0 | service/connect_manager/include/i_multimodal_input_connect.h:32 | 固定版本枚举值 |
| OnRemoteRequest 检查 interface descriptor | service/connect_manager/src/multimodal_input_connect_stub.cpp:36–47 | descriptor 不等于调用者权限认证 |
| 分发 ALLOC_SOCKET_FD 到 StubHandleAllocSocketFd | 同文件:50、89–92 | map 成员函数指针路径；源码级关系已确认 |
| ReadParcelable<ConnectReqParcel> | 同文件:105 | 读取请求对象，CHKPR 宏语义未展开 |
| moduleId/clientName 来自 Parcel | service/connect_manager/src/multimodal_input_connect_def_parcel.cpp:31–45 | 字段属于入站 parcel；攻击者能力/范围尚未验证 |
| GetTokenType 读取 IPCSkeleton::GetCallingTokenID | service/permission_helper/src/permission_helper.cpp:95–110 | token 类型分类不等于 VerifyAccessToken 权限检查 |
| handler 调用 AllocSocketFd 并回写 FD | stub.cpp:110–124 | 成功路径写 reply；异常和宏路径不声称完整解析 |
| AllocSocketFd 使用 GetCallingUid/Pid，PostSyncTask 绑定 AddSocketPairInfo | service/module_loader/src/mmi_service.cpp:342–370 | 身份来自调用上下文，不是 parcel 的 uid；任务切换语义仍需核对 |
| AddSocketPairInfo 创建 socketpair、UDSSession 并 AddSession | service/module_loader/src/uds_server.cpp:94–164 | 资源操作已确认，是否必须保护及具体安全影响仍为 unknown |

## 核心修订：INPUT_MONITORING 不属于已核验的 AllocSocketFd 检查链

现有三个已读函数 StubHandleAllocSocketFd、MMIService::AllocSocketFd、UDSServer::AddSocketPairInfo 中，没有直接 CheckMonitor/VerifyAccessToken 调用。
这只说明这些已读函数的源码事实，不能推论整个资源协议无权限控制，更不能判为漏洞。

INPUT_MONITORING 的可见链位于另一条路径：
StubAddInputHandler（stub.cpp:347；MONITOR 分支:362–365）
→ PermissionHelper::CheckMonitor（permission_helper.cpp:49–63）
→ CheckMonitorPermission（:82–93）
→ VerifyAccessToken(tokenId, "ohos.permission.INPUT_MONITORING")（:84–85）。
CheckMonitor 中 token 来自 IPCSkeleton::GetCallingTokenID；HAP/NATIVE 进入权限验证，SHELL 返回 true。需要后续核验平台身份语义，不能直接判 shell 分支为越权。

另一结构对照是 StubAddInputEventFilter（stub.cpp:131–150）：CheckPermission(APL_SYSTEM_CORE) 失败后源码显式 return，然后读取 remote object 并调用 AddInputEventFilter。它是人工结构研究对照，不是“已证明全路径安全”的真实负样本。

## 当前结论与缺口
Entry 的源码分发关系可从 pending 升为 source_confirmed。Source 字段读取可标 source_confirmed；用户权限、可控性和系统入口可达性仍 unknown。
原文中“运行证据”未提供原始日志，本次未引用为已核验 runtime 证据。
源码 blob 是历史固定版本，不代表最新 OpenHarmony 产品。未建立公开公告或 vulnerable/fixed pair，样本级别仅结构研究，无 S2 阳性标签。
尚缺：设备/产品 manifest、SA 暴露策略、proxy 与 caller 权限语义、宏和 TU 解析覆盖、helper 完整语义、socket 后续消息授权、官方权限需求、真实修复对。
validated_vulnerability=0；runtime_validation=not_run。

## 来源
每条链接及 SHA 在 manifest 中。入口源码：
https://github.com/openharmony/multimodalinput_input/blob/2468d204d3f276c373841e057af35985296c8421/service/connect_manager/src/multimodal_input_connect_stub.cpp
权限 helper：
https://github.com/openharmony/multimodalinput_input/blob/2468d204d3f276c373841e057af35985296c8421/service/permission_helper/src/permission_helper.cpp
