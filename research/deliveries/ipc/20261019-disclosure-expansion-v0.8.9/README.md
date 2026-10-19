# B线公开披露修复对扩展复验（Detector 0.8.9）

日期：2026-10-19；分支：`feat/interface-ipc-detector`；扫描器：`ohscanner.interface.ipc@0.8.9` / `oh-ipc-2026.10-v15`。

## 结果

| CVE | 机制 | 候选差分 | 解析状态 | 结论 |
|---|---|---:|---|---|
| CVE-2025-27563 | security_access_token 服务账号与方法级调用者类别边界 | 3 → 0 | 两端 2 个文件 partial，run blocked | 当前 AUTH-03 服务账号模型与三处补丁边界相符；新增一组披露修复对回归，不是产品确认 |
| CVE-2025-27247 | pasteboard 默认输入法授权绕过 | 2 → 2 | 两端 4 个文件 partial，run blocked | 当前只保留通用 GetPasteData 授权/数据流候选，没有识别补丁移除的默认 IME grant；未吸收 |
| CVE-2025-25212 | pasteboard 观察者资源增长限制 | 2 → 2 | 两端 4 个文件 partial，run blocked | 当前没有识别 AddObserver 聚合上限修复；未吸收 |

CVE-2025-27563 漏洞端三个 AUTH-03 锚点为 `RemovePermissionUsedRecordsInner:195`、`IsAllowedUsingPermissionInner:306`、`SetMutePolicyInner:457`，均在修复端消失。模型把 `ACCESSTOKEN_UID=3020` 限定于 `RemovePermissionUsedRecords`，不是对该 UID 的全局信任。报告仍保留调用可达性、策略语义和影响义务。

CVE-2025-27247 两端共同保留 PasteboardServiceStub::OnGetPasteData:162 的 AUTH-02 和 DATA-04 候选。补丁从 `PasteboardService::VerifyPermission` 的授权表达式移除了默认 IME 例外，B 当前版未对这项变化形成差分。

CVE-2025-25212 两端同样保留上述两条通用候选，未产生资源增长候选。补丁增加按用户/PID 聚合的观察者上限与清理行为，当前版未覆盖这一机制。

## 固定 Git 身份

CVE-2025-27563：`openharmony/security_access_token`，vulnerable `85ead8f16d070dd66e4ea906b1246018d747ec7b` / tree `10a6185050ce6c8615bc941f8f31f38837ddc43e`；fixed `e232d8ed63b53ba883265972872695bb5aab756a` / tree `a737217e2472ad655ee1e6e2272ad75bfa14121f`；scope 为 privacy_manager_stub.h/.cpp。

CVE-2025-27247：`openharmony/distributeddatamgr_pasteboard`，vulnerable `59360e6d675a1d6c553e1aeb3a5e265aa3591045` / tree `7d5623dfc108b7deb07c323deb4aa43508dbe776`；fixed `f27fb584ee3dd14ec38b66d64e50cd7e70325bca` / tree `1fc6df6efc5a5f9c9b072a570c6486f62c0478cd`；scope 为服务头/实现与 ZIDL stub 头/实现四文件。

CVE-2025-25212：同仓库，vulnerable `d91a9b38fc801a269dc684c0c9735dc68ddbb0b8`；fixed `836cf6990579451d6521e9177d749660b07ad34e`；同组件四文件。JSON 绑定两端 tree、blob 与 source SHA-256。

## 验证边界

三组均由 B 线隔离 Git pair replay 执行。所有报告的 `validated_vulnerability=0`；公开披露事实与工具 finding 验证状态分开。27563 的差分不证明产品可达或动态影响；两个 pasteboard 修复对因全部文件 partial、运行 blocked，不能判为安全，也不能把 2→2 当成完整漏报结论。

本包是披露样本回归，不是独立 holdout，不用于 Precision/Recall。未构建组件、未运行 PoC/Harness 或 Agent。官方公告：[OpenHarmony 2025年6月安全公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2025/2025-06.md)。复现脚本：`research/experiments/interface/ipc/replay_pinned_git_pair_isolated.py`。产物哈希见 `SHA256SUMS`。
