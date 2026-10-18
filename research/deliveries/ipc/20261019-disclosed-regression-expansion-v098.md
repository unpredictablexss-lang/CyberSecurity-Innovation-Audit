# B线公开漏洞回归增量

## 实验结果

CVE-2025-26691（telephony_call_manager）：c751a0dc4c67b40430291d983df60efbb68b5caa → 911c6c99872e3a6a421747815bc8c1f6b201db26。单文件 services/call_manager_service/src/call_manager_service.cpp，complete，AUTH-02 候选 7→0。候选位于 StartRtt、StopRtt、SetCameraZoom、GetImsConfig、SetImsConfig、GetImsFeatureValue、SetImsFeatureValue。修复提交增加 caller/system-app 与权限检查。

CVE-2025-26693（security_access_token）：89953b22ba58654beda0ff3154125d6779550e2b → 31ed3b9f31b029b0ae4dec48a9f95b6356f924c0。单文件 services/accesstokenmanager/main/cpp/src/service/accesstoken_manager_stub.cpp，partial，候选 4→2。其中 GetReqPermissionsInner 的 AUTH-02 与 DATA-04 候选消失；修复后仍有一条 AUTH-03 和一条入口描述符候选。权限修复包括 GetTokenType/IsSystemAppCalling 与 VerifyAccessToken(GET_SENSITIVE_PERMISSIONS)。

CVE-2023-25176（pasteboard TLV 越界读）：693a188bb719f547724638ac39888353aca7db81 → 9408af4fe6e85f70fc46427b7ba779e683a12ec3。framework/tlv/tlv_object.h partial，0→0。官方修复要求 head.len == sizeof(T)。根因属于一般 TLV/vector 读取，超出当前 IPC Parcel 规则范围，记为未覆盖/unknown，不作为安全负结果。

CVE-2024-39775（netmanager 权限拦截返回码）：eb00c2b458c26c10ab4e7ea5f7af0c529be0f6b7 → 7d0c987f0cd4134040935384d50e17f226507463。services/netstatsmanager/src/stub/net_stats_service_stub.cpp partial，0→0。补丁把权限失败分支的外层返回值从 success 改成拒绝；检测器目前没有建模这个返回码语义，且须人工核对实际安全影响。

本轮新增两个固定修复对上的源码回归匹配，加上先前四个正例，累计六个公开修复对的静态回归记录。CVE 样本是公开补丁回归而非盲测，不能作为 Precision/Recall。所有 finding 仍 unassessed，validated_vulnerability=0；未运行组件构建、PoC 或设备验证。CVE-2025-26691 两侧 complete；另三组均 partial，候选消失和未命中须保留解析限制。

重点改进建议：
1. 优先修 AUTH-03 对局部 callingTokenID + GetTokenType(TOKEN_HAP) + IsSystemAppCalling() 组合守卫的识别，覆盖拒绝/放行正反例，再重跑 CVE-2025-26693 和五组件固定集。
2. 研究 CVE-2024-39775 前，先跟踪 Binder transport 返回码和 reply payload 的消费语义；确认安全影响再设计独立规则。
3. 将 CVE-2023-25176 交给通用内存安全检测线，若 B 要纳入，明确 TLV 来源、长度与类型宽度、读取 sink，不做宽泛 len/sizeof 匹配。
4. 回归样本不冒充盲测；检测逻辑冻结后另建独立 holdout。

验证：674 tests passed, 36 skipped。扫描 JSON/Markdown 和哈希见同目录 manifest.json。


负责人确认口径：CVE-2025-26691 与 CVE-2025-26693 可在“披露漏洞回归台账”中标为 confirmed（公开披露根因与固定源码补丁的静态回归匹配已完成）；后续 Agent/运行时验证仍待执行。此 confirmed 不改写扫描器原始 finding 的 severity，也不把运行器 validated_vulnerability 从 0 改成 1。
