# B 线已披露漏洞回放增量（detector 0.12.3）

日期：2026-10-19
分支：`work/ipc-20261017`
检测器基线：`b8adb2a2908b8e8c3757878b1b1fae7e5a781d74`（`ohscanner.interface.ipc 0.12.3`）
范围：只读固定 Git 对象，对每个样本仅扫描披露修复涉及的源码文件。不是独立 holdout。

## 结论

本轮补充回放三个官方披露样本，结果分为三类：

| CVE | 组件 | 当前版修复前 → 修复后 | 本轮判断 |
|---|---|---:|---|
| CVE-2024-39612 | `resourceschedule_background_task_mgr` | **2 → 0** | 新增静态修复对匹配。两条候选落在 start/stop 两个分支，均由“任务参数 UID 与真实调用者 UID 不一致”机制触发；官方补丁在分支分流之前增加 UID 绑定检查。 |
| CVE-2025-27563 | `security_access_token` | **6 → 3** | 部分匹配，复验了既有结果。三个 caller-class 候选随补丁消失；修复后仍有同方法 AUTH-02/AUTH-04 unknown，不能称整条披露已完全收敛。 |
| CVE-2024-38382 | `ability_ability_runtime` | **2 → 2** | 明确未命中根因。前后两条均是与披露修复路径无关的 CAP-01 候选；修复前后都没有发现目标方法的 SA 权限边界。 |

所以本轮**只新增 1 个静态修复对匹配样本**；另有 1 个部分匹配复测和 1 个未命中边界。没有新增或修改检测规则，没有把 CVE 名称、函数名加入规则。三组共 8 份原始 JSON/Markdown 报告均记录 `validated_vulnerability=0`，finding severity 保持 `unassessed`。

## CVE-2024-39612：UID 所有权绑定

官方 2024 年 9 月公告将该问题列为后台任务管理权限绕过。固定的 vulnerable commit 是 `4a0b86b5506c103406cad2d81aefad634dbdcdeb`，官方修复提交是 `0a6e90e327d1f0d22addd1dad468125edec7c830`，为前者的直接子提交。修复改动 `services/continuous_task/src/bg_continuous_task_mgr.cpp`：读取 `IPCSkeleton::GetCallingUid()`，若与 `taskParam->uid_` 不一致则拒绝，然后才按 `isStart_` 进入 start/stop 分支。

当前版在修复前的 `RequestBackgroundRunningForInner` 两个分支分别产生 AUTH-03 `ipc.auth.object-owner` 候选（行 530、532）；修复后该候选集为 0。目标文件两侧均为 `partial`，但错误节点位于文件较早位置（第 142、144 行），目标函数本身进入解释器；因此这是有源码差分支撑的高置信静态回归匹配，仍不是运行时可利用性证明。

固定对象与范围：

- 仓库：`openharmony/resourceschedule_background_task_mgr`
- vulnerable commit/tree：`4a0b86b5506c103406cad2d81aefad634dbdcdeb` / `1dba2f8c644f83cd56cb142c16eecfe700f53e96`
- fixed commit/tree：`0a6e90e327d1f0d22addd1dad468125edec7c830` / `aae4cf509b10315c90c593f3d24e335f6cc0bf0e`
- 文件：`services/continuous_task/src/bg_continuous_task_mgr.cpp`
- 报告：`CVE-2024-39612-vulnerable.*`、`CVE-2024-39612-fixed.*`

## CVE-2025-27563：部分吸收，保留 unknown

同一检测器在固定漏洞前提交 `85ead8f16d070dd66e4ea906b1246018d747ec7b` 与修复提交 `e232d8ed63b53ba883265972872695bb5aab756a` 上重跑 `privacy_manager_stub.cpp`，诊断数 6→3。补丁对应的三个 caller-class 候选消失；修复后 `RemovePermissionUsedRecordsInner` 仍有 AUTH-02/AUTH-04，身份来源与角色链尚不能完整归约。两侧文件都是 partial。保留现有义务，不以诊断数下降推断整条 CVE 已被完整识别。

## CVE-2024-38382：明确漏检

官方修复把 `IsSACall()` 检查加入 `AppMgrServiceInner::GetAppRunningStateByBundleName`。在固定三文件范围、修复前 `fd8cd59c2f98c9b5365ee422f58bd82064fe2359` 与修复提交 `f2898e72966a8fcc59ecebc3cdea8d9aab063b1d` 上，当前版均只报相同的两条无关 CAP-01：`HandleGetAmsMgr` 和 `HandleGetAbilityRecordsByProcessID`。没有候选与目标敏感方法绑定。范围解析为 1 complete、2 partial。

本结果支持继续优先开发**泛化的跨文件委托链与守卫归属分析**。此前的函数名特判反事实实验前后都会出同一条候选，故本轮不重复做该特判，也不将 CVE 计入匹配样本。

## 复现、证据和限制

每份 JSON 绑定完整 commit、Git tree、固定 snapshot 和 declared scope；配套 `manifest.json` 为报告记录 SHA-256，`SHA256SUMS` 可校验归档完整性。扫描器未联网更新目标仓库，所有对象先在本地 Git 仓库中准备好后再扫描。

- 官方公告：[2024 年 9 月安全公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2024/2024-09.md)、[2025 年 6 月安全公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2025/2025-06.md)。
- 未构建 OpenHarmony、未运行设备/产品 PoC，也没有 Agent 动态验证。
- 本批是公开修复对回归集，不是独立 holdout；不能据此报告 Precision、Recall 或整体准确率。
- `0` 候选不证明安全；partial/跨文件路径仍应标为 unknown。

下一步先把 CVE-2024-39612 作为新增的 AUTH-03 owner-binding 回归固定下来；然后建立跨文件委托/守卫的正例、修复例、安全例和无关例，目标是解决 CVE-2024-38382 这类真实漏检，而不是继续加 API 名称规则。
