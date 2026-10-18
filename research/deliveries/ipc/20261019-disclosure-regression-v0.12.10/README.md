# B 线披露修复对回归（2026-10-19，Detector 0.12.10）

本目录以当前仓库提交和 Detector 0.12.10 重放三组固定公开修复对。使用同一固定范围扫描易受影响与修复端；这是静态源码补丁差分证据，不是产品运行时确认，也不是 Precision/Recall 评估。

| 披露 | 仓库 | 易受影响 → 修复提交 | 诊断总量 | 根因相关差分 | 覆盖 |
|---|---|---|---:|---|---|
| CVE-2025-26691 | openharmony/telephony_call_manager | 911c6c99872e3a6a421747815bc8c1f6b201db26 → 6018446d576b84d8893f8f7ad5d46353236fb8e0 | 9→0 | 9 个操作的权限错配触发 AUTH-02，修复端消失 | 1/1 complete |
| CVE-2024-38382 | openharmony/ability_ability_runtime | fd8cd59c2f98c9b5365ee422f58bd82064fe2359 → f2898e72966a8fcc59ecebc3cdea8d9aab063b1d | 4→2 | 目标 AUTH-02、DATA-04 消失；留下 2 条共有 CAP-01 | 1 complete / 6 partial |
| CVE-2025-26693 | openharmony/security_access_token | 89953b22ba58654beda0ff3154125d6779550e2b → 31ed3b9f31b029b0ae4dec48a9f95b6356f924c0 | 4→1 | GetReqPermissionsInner 的权限/身份候选随补丁消失；保留 1 条与根因无关的描述符候选 | 两侧 partial |

## 本轮规则改进

0.12.9 中从 CVE-2025-26691 固定修复差异整理的九条权限契约原先只绑定完整类/方法名，没有绑定仓库。0.12.10 将其改为 repository + fully-qualified method + expected permission 三元组，只对 openharmony/telephony_call_manager 生效。新增同名跨仓负例验证：同名 CallManagerService::GetImsConfig 在其他仓库不会继承该产品契约。通用本地测试策略的 expected_permissions 仍可单独传入。

版本标识：Detector 0.12.10，model oh-ipc-2026.10-v30。全量测试：715 OK，36 skipped。此前写成 v31 是文档错误；v31 从 0.12.11 开始。源代码改动和该次回放分别记录，旧的 0.12.9 报告保持不可变。

## 结论边界与历史更正

- CVE-2025-26691 使用真正包含九处权限替换的固定父子提交。旧记录 c751a0dc... → 911c6c99... 不包含该修复差异，不能作为此 CVE 的根因回归。
- CVE-2024-38382 的目标候选此前记为漏检；当前版本已观察到目标 AUTH-02 与 DATA-04 的修复差分。但 6/7 源文件 partial，不能据此宣称完整跨文件覆盖。
- CVE-2025-26693 的 4→1 是部分匹配：目标方法候选消失，残留描述符观察不等于目标根因仍存在；文件仍为 partial。
- 三组报告的 validated_vulnerability 均为 0；无产品构建、设备 PoC、动态 Harness 或 Agent 验证。公开披露历史可单独登记为已披露，不改写扫描 finding 的 candidate/unassessed。
- 三组报告生成时的仓库范围代码改动随后原样提交为 8d7dab93829bf3d4115cb2c3fffd147c66003823；该提交包含 Detector 0.12.10 / model v30 实现与回归测试。

- Repository is a caller-declared identity, not cryptographic origin verification. This scope reduces accidental cross-repository contract reuse, but does not authenticate the source remote.
