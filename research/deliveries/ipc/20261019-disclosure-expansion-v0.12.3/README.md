# B 线已披露漏洞回放增量（detector 0.12.3）

日期：2026-10-19
分支：`work/ipc-20261017`
检测器基线：`b8adb2a2908b8e8c3757878b1b1fae7e5a781d74`（`ohscanner.interface.ipc 0.12.3`）
范围：只读固定 Git 对象，仅扫描披露修复涉及的源码文件；不是独立 holdout。

## 结论

本轮共重放五个官方披露样本，分别记录静态修复对匹配、部分匹配和明确漏检：

| CVE | 组件 | 当前版修复前 → 修复后 | 结论 |
|---|---|---:|---|
| CVE-2024-39612 | `resourceschedule_background_task_mgr` | **2 → 0** | 新增的 AUTH-03 UID/owner 静态修复对匹配。 |
| CVE-2025-26691 | `telephony_call_manager` | **7 → 0** | 当前版复验：AUTH-02 权限候选与修复差分一致，文件 complete。 |
| CVE-2025-26693 | `security_access_token` | **4 → 1** | 部分匹配：AUTH-03/AUTH-02/DATA-04 消失；AUTH-01 描述符观察保留，目标文件 partial。 |
| CVE-2025-27563 | `security_access_token` | **6 → 3** | 部分匹配：三个 caller-class 候选消失；修复后仍有 AUTH-02/AUTH-04 unknown，目标文件 partial。 |
| CVE-2024-38382 | `ability_ability_runtime` | **2 → 2** | 未命中根因；两条 CAP-01 是前后相同的无关观察。 |

本轮新增了 **1 个此前没有进入当前版本回归集的 CVE 修复对（39612）**；同时用 v0.12.3 重验了两个已有披露样本（26691、26693）。可以把 39612 和 26691 记为“确认：静态回归与公开补丁机制相匹配”；这是回归台账结论，不等于确认产品可利用性。所有原始 finding severity 仍为 `unassessed`，所有报告 `validated_vulnerability=0`。没有新增/修改 detector 规则，也没有使用 CVE 或方法名特判。

## CVE-2024-39612：UID 所有权绑定

官方 2024 年 9 月公告将该问题列为后台任务管理权限绕过。vulnerable commit 为 `4a0b86b5506c103406cad2d81aefad634dbdcdeb`，修复提交 `0a6e90e327d1f0d22addd1dad468125edec7c830` 是其直接子提交。补丁在 `services/continuous_task/src/bg_continuous_task_mgr.cpp` 中读取 `IPCSkeleton::GetCallingUid()`，若与 `taskParam->uid_` 不一致则拒绝，然后才按 `isStart_` 进入 start/stop 分支。

当前版在修复前的 `RequestBackgroundRunningForInner` 两个分支分别产生 AUTH-03 `ipc.auth.object-owner` 候选（行 530、532）；修复后候选为 0。两侧文件均为 `partial`，错误节点在较早的第 142、144 行，目标函数本身进入解释器。因此这是有补丁差分和调用者/任务 UID 比较代码支撑的静态回归匹配，仍不是运行时可利用性证明。

- vulnerable commit/tree：`4a0b86b5506c103406cad2d81aefad634dbdcdeb` / `1dba2f8c644f83cd56cb142c16eecfe700f53e96`
- fixed commit/tree：`0a6e90e327d1f0d22addd1dad468125edec7c830` / `aae4cf509b10315c90c593f3d24e335f6cc0bf0e`
- 固定文件：`services/continuous_task/src/bg_continuous_task_mgr.cpp`

## CVE-2025-26691：电话服务权限匹配

当前版重放固定提交 `c751a0dc4c67b40430291d983df60efbb68b5caa` 与修复提交 `911c6c99872e3a6a421747815bc8c1f6b201db26`，单文件 `services/call_manager_service/src/call_manager_service.cpp` 从 7 条 AUTH-02 降到 0，文件两侧均为 complete。候选对应多个电话服务敏感操作缺少识别出的调用者授权；公开修复将错误的 `PLACE_CALL` 权限常量换成对应读写电话状态权限。当前 detector 能观察这些权限检查的添加/变化，但本次不等于验证各 API 的完整权限策略或设备影响。

- 官方修复前 commit：`c751a0dc4c67b40430291d983df60efbb68b5caa`
- 修复后 commit：`911c6c99872e3a6a421747815bc8c1f6b201db26`

## CVE-2025-26693：身份检查部分匹配

当前版在 `security_access_token` 的固定漏洞前提交 `89953b22ba58654beda0ff3154125d6779550e2b` 与修复提交 `31ed3b9f31b029b0ae4dec48a9f95b6356f924c0` 上重跑 `accesstoken_manager_stub.cpp`，诊断数 4→1。`GetReqPermissionsInner` 上的 AUTH-03、AUTH-02、DATA-04 与补丁增加的 HAP/system-app 和敏感权限校验相对应；修复后保留的单条 AUTH-01 描述符候选与该漏洞方法无关。两侧文件均 partial，故作为部分回归匹配，而非全文件安全结论。

## CVE-2025-27563：部分匹配，保留 unknown

当前版在固定漏洞前提交 `85ead8f16d070dd66e4ea906b1246018d747ec7b` 与修复提交 `e232d8ed63b53ba883265972872695bb5aab756a` 上重跑 `privacy_manager_stub.cpp`，诊断数 6→3。补丁对应的三个 caller-class 候选消失；修复后 `RemovePermissionUsedRecordsInner` 仍有 AUTH-02/AUTH-04，身份来源与角色链尚不能完整归约。两侧文件都是 partial，保留现有义务，不把计数下降解释为整条披露已完全识别。

## CVE-2024-38382：明确漏检

修复将 `IsSACall()` 检查加入 `AppMgrServiceInner::GetAppRunningStateByBundleName`。在修复前 `fd8cd59c2f98c9b5365ee422f58bd82064fe2359` 与修复提交 `f2898e72966a8fcc59ecebc3cdea8d9aab063b1d` 的固定三文件范围上，当前版均只报两条相同、与目标方法无关的 CAP-01：`HandleGetAmsMgr` 和 `HandleGetAbilityRecordsByProcessID`。没有候选绑定到披露修复点；范围为 1 complete、2 partial。

这支持继续优先做**泛化跨文件委托链与守卫归属分析**。此前只加函数名的反事实修改前后都会增加同一候选，故这里不再做单函数特判。

## 复现、证据和限制

每份 JSON 绑定完整 commit、Git tree、固定 snapshot 和 declared scope；配套 `manifest.json` 记录报告 SHA-256，`SHA256SUMS` 可校验归档完整性。目标对象先在本地 Git 仓库准备，扫描阶段不联网更新源码。

- 官方公告：[OpenHarmony 2024 年 9 月安全公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2024/2024-09.md)、[OpenHarmony 2025 年 6 月安全公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2025/2025-06.md)。
- 未构建 OpenHarmony、未运行设备/产品 PoC、未做 Agent 动态验证。
- 本批公开修复对用于回归开发，不是独立 holdout；不能据此报告 Precision、Recall 或整体准确率。
- `0` 候选不证明安全；partial/跨文件路径继续为 unknown。

下一步优先把 CVE-2024-39612 固定为 AUTH-03 owner-binding 回归，再为跨文件委托/守卫开发正例、修复例、安全例和无关例，以解决 CVE-2024-38382 这类漏检，不继续扩充函数名列表。
