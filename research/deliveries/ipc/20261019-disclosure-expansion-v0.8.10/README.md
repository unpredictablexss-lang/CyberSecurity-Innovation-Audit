# B线披露机制扩展（Detector 0.8.10）

日期：2026-10-19\
分支：`feat/interface-ipc-detector`\
Detector：`ohscanner.interface.ipc@0.8.10` / model `oh-ipc-2026.10-v16`

## 本轮吸收

从已审查的集成线实现中，选择性移入两项源代码模型，没有搬入公共 Runner/协议或无关变化。

1. **默认应用授权例外**：新规则 `ipc.auth.privileged-app-bypass`，隶属 AUTH-02。仅当唯一 `OnGetPasteData → GetPasteData → VerifyPermission` 路径能绑定，且 `IsDefaultIME` 结果进入 `isGrant`，才报授权策略候选；扫描同时可指出 allowlist 为空时 helper 返回 true 的源码事实。规则不把名字或 CVE 编号作为结论。
2. **观察者无界注册**：新规则 `ipc.resource.unbounded-observer-registration`，归入 RESOURCE-01 / CWE-400。候选需看到 IPC `On*Observer → SubscribeObserver → AddObserver` 以及 observer 参数流向容器插入。只识别明确的计数 + 上限 + 插入前早退形状；没有路径、统计或产品影响证明时保留义务。

## 固定披露对复验

| CVE | vuln→fixed 总候选 | 目标规则差分 | 覆盖 |
|---|---:|---|---|
| CVE-2025-27247 | 4 → 3 | `ipc.auth.privileged-app-bypass` 1 → 0；通用 AUTH-02、DATA-04 与 observer 候选留存 | 四文件均 partial，run blocked |
| CVE-2025-25212 | 3 → 2 | `ipc.resource.unbounded-observer-registration` 1 → 0；两条通用候选留存 | 四文件均 partial，run blocked |
| CVE-2025-27563 | 3 → 0 | AUTH-03 三条方法级候选消失，作为旁路回归保持 | 两文件均 partial，run blocked |

27247 的候选锚点为 `PasteboardService::VerifyPermission` 中 `IsDefaultIME` 参与权限 grant，并能把路径回溯到 `PasteboardServiceStub::OnGetPasteData`。25212 的候选锚点为 `PasteboardService::AddObserver` 的 observer 容器插入，并追到 stub 的订阅入口。固定修复端相应特定候选消失，而无关通用候选保持。

## 固定 Git 来源

- CVE-2025-27247，`openharmony/distributeddatamgr_pasteboard`：`59360e6d675a1d6c553e1aeb3a5e265aa3591045` → `f27fb584ee3dd14ec38b66d64e50cd7e70325bca`；四文件范围见 JSON。
- CVE-2025-25212，同仓库：`d91a9b38fc801a269dc684c0c9735dc68ddbb0b8` → `836cf6990579451d6521e9177d749660b07ad34e`；四文件范围见 JSON。
- CVE-2025-27563，`openharmony/security_access_token`：`85ead8f16d070dd66e4ea906b1246018d747ec7b` → `e232d8ed63b53ba883265972872695bb5aab756a`；privacy_manager_stub.h/.cpp。

每份 JSON 都固定 commit/tree、纳入文件的 blob 与 SHA-256、scope、检测器与证据义务。复现脚本为 `research/experiments/interface/ipc/replay_pinned_git_pair_isolated.py`。

## 验收边界

本轮三组任务都被标记为 `blocked`，扫描文件均 partial。前两项的差分支持“规则与公开补丁机制相符”，但不证明完整覆盖、普通应用可达、产品可利用或产品影响；候选仍是 `candidate/unassessed`，所有原始报告 `validated_vulnerability=0`。CVE 的公开披露状态可登记为已披露，不能把扫描器候选的验证状态自动改成 confirmed。样本为开发回归，不是独立 holdout，不用于 Precision/Recall。

新增 18 项特定机制正/修复/安全对照测试，另通过 family matrix；全量测试结果与源码状态见 B 仓 `PROGRAM_STATUS.md` §71。没有构建组件、运行 PoC/Harness 或 Agent。官方公告：[OpenHarmony 2025年6月安全公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2025/2025-06.md)。
