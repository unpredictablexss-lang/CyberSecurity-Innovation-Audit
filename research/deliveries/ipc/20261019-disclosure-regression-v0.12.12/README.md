# B 线公开披露回归：固定修复对（0.12.12 / v32）

日期：2026-10-19。代码工作树：/home/audit/ohscanner/worktrees/parallel-ipc-20261017，分支 work/ipc-20261017，基线 HEAD 2fee193dd2d8a1849ac31e0683baef8c9a59d9c3。本次检测器改动尚未提交。

本目录收录八组已公开披露漏洞的固定 Git 修复对回放。报告是原始 CLI 输出；这些披露样本是回归样本，不是独立 holdout。

## 固定修复对

| CVE | 固定范围与报告差分 | 解析/证据限制 |
|---|---|---|
| CVE-2024-12082 | ability_ability_runtime，6 个 AppMgr stub/service 文件；总诊断 7→4。新 caller-class 契约在 GetBundleNameByPid 的 AUTH-03 与两个 DATA-04 reply sink 上产生 3 条候选，官方固定端三条消失；4 条无关候选保留。 | 两端 1 complete / 5 partial，completed_with_limitations。 |
| CVE-2024-38382 | ability_ability_runtime，7 个 AppMgr stub/service 文件；总诊断 7→5。GetAppRunningStateByBundleName 的 AUTH-02 与 DATA-04 目标候选，在加入 IsSACall 检查后消失；5 条其他候选保留。 | 两端 1 complete / 6 partial，completed_with_limitations。 |
| CVE-2024-39775 | communication_netmanager_base，services/netstatsmanager/src/stub/net_stats_service_stub.cpp；使用披露修复的直接父子提交，总诊断 2→0。共享 CheckNetManagerAvailable helper 的两个权限拒绝候选随固定补丁消失。 | 单文件 partial，completed_with_limitations。供应商公告把 4.1 修复链接到 PR #2403；共享 CheckNetManagerAvailable helper 的拒绝状态差异与补丁吻合；源码证据支持“权限拦截失败返回状态不正确”，但不能单独证明公告所述 OOB read/信息泄露后果。 |
| CVE-2023-25176 | distributeddatamgr_pasteboard，framework/tlv/tlv_object.h；总诊断 1→0，DATA-05 ipc.tlv.fixed-width-length 随固定补丁消失。 | 两端单文件 partial，completed_with_limitations；这是现有规则复验，不是本轮新增规则。 |
| CVE-2022-42463 | communication_dsoftbus，两文件范围；总诊断 1→1。AUTH-06 修复前识别到缺少拒绝式白名单；修复端保留前缀比较候选，理由明确为 strncmp 前缀匹配及 peer/session 注册策略未知。 | 两端 2 个文件均 partial，completed_with_limitations；候选保留不等于修复无效或漏洞确认。 |
| CVE-2025-27247 | distributeddatamgr_pasteboard，四文件范围；总诊断 4→3，目标 AUTH-02 privileged-app-bypass 候选消失。 | 两端 4 个文件均 partial；3 条残留候选不是本 CVE 的补丁差分。 |
| CVE-2025-25212 | distributeddatamgr_pasteboard，同四文件范围；总诊断 3→2，目标 RESOURCE-01 unbounded-observer-registration 候选消失。 | 两端 4 个文件均 partial；2 条残留候选不代表已验证漏洞。 |
| CVE-2025-27563 | security_access_token，两文件范围；总诊断 3→0。三个 AUTH-03 caller-class 候选在三个隐私权限方法上随固定端消失。 | 两端文件均 partial；仅是静态补丁差分回归，validated_vulnerability=0。 |

## CVE-2024-39775 补丁语义复核

正确固定对为修复提交 b99cb78281915a9a2587aca981fa69c969ba8f93 的直接父提交 c172839fd6354d9bff189c8b1ade2cf621f4b24f 到修复提交。共享 CheckNetManagerAvailable helper 的两个权限拒绝分支写入 reply 错误码后却返回 NETMANAGER_SUCCESS；修复将其改为返回拒绝码。当前 0.12.12 在正确固定对上得到 2→0，候选落在 helper 的 IsSystemCaller 与 CheckPermission 拒绝分支，文件解析为 partial。

上轮用 eb00…→7d0c… 的扫描不是这条披露补丁的直接前后版本，旧 10→8 数据已从本包 CVE 根因证据中剔除。官方公告/NVD 将影响描述为越界读信息泄露；当前源码回归只确认权限拒绝返回状态与修复差异相符，没有证明一条触发越界读取的具体数据流。故本项按“静态补丁机制部分匹配”记录，不宣称 OOB 根因已被检测器吸收。PR #2403 标题为修复权限拦截失败问题。

## 本轮新增代码

本轮新写入的是 CVE-2024-12082 所需的仓库+限定方法 caller-class 契约与对应敏感引用输出建模。代码把 GetBundleNameByPid 的 <sa-caller> 约束和 GetAppRunningRecordByPid 前置效果限定在 ability_ability_runtime，并把两个被审阅的输出参数映射到 reply sink。测试覆盖正确 SA gate、无 gate、过晚 gate、错误角色和跨仓不继承。检测器版本为 0.12.12，模型版本为 oh-ipc-2026.10-v32。

CVE-2024-38382、CVE-2024-39775、CVE-2023-25176、CVE-2025-27247、CVE-2025-25212 与 CVE-2025-27563 是当前代码对既有机制的复验，没有因 CVE 字符串加入新规则。CVE-2024-39775 只命中权限拒绝返回差分，不足以证明 OOB read 根因；需要找到公告所指越界读取的源码/调用链证据后再增加相应检测能力。

## 解释边界

八组报告中的 validated_vulnerability 均为 0。已公开的 CVE 可在披露台账标记为外部已确认；OHScanner 的静态 finding 仍是 candidate/unassessed，等待人工或 Agent 核查。所有报告至少包含 partial 解析；没有产品构建、设备 PoC、Harness 或 Agent 验证，不支持完整覆盖、可达性、影响或 Precision/Recall 结论。

## 文件和外部依据

- CVE-2024-12082-{vulnerable,fixed}.{json,md}
- CVE-2024-38382-{vulnerable,fixed}.{json,md}
- CVE-2024-39775-{vulnerable,fixed}.{json,md}
- CVE-2023-25176-{vulnerable,fixed}.{json,md}
- CVE-2022-42463-{vulnerable,fixed}.{json,md}
- CVE-2025-27247-{vulnerable,fixed}.{json,md}
- CVE-2025-25212-{vulnerable,fixed}.{json,md}
- CVE-2025-27563-{vulnerable,fixed}.{json,md}
- manifest.json：固定 commit/tree、范围文件、计数和状态。
- SHA256SUMS：本目录报告与文档校验值。
- OpenHarmony 2024-09 公告：https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2024/2024-09.md
- 4.1 修复 PR #2403：https://gitee.com/openharmony/communication_netmanager_base/pulls/2403

未推送 GitHub；未修改 A 线或队友 B 源仓。
