# B 线披露 CVE 历史样本的当前版复测（0.12.12 / v32）

复测日期：2026-10-19。代码基线 2fee193dd2d8a1849ac31e0683baef8c9a59d9c3，检测器 ohscanner.interface.ipc 0.12.12，模型 oh-ipc-2026.10-v32。所有输入固定到已披露漏洞与修复提交；本目录报告由当前 CLI 生成。

## 结果

| CVE | 固定范围 | 当前版漏洞端→修复端 | 观察到的补丁差分 | 覆盖限制 |
|---|---|---:|---|---|
| CVE-2023-0035 | dsoftbus softbus_client_stub.cpp | 1→0 | AUTH relay descriptor-boundary 候选消失 | 两端 partial |
| CVE-2023-0036 | inputmethod platform_callback_stub.cpp | 1→0 | AUTH relay descriptor-boundary 候选消失 | 两端 complete |
| CVE-2024-39612 | background task bg_continuous_task_mgr.cpp | 2→0 | 两条 AUTH object-owner 候选消失 | 两端 partial |
| CVE-2025-26691 | telephony call manager 头文件与实现文件 | 9→0 | 9 条 AUTH-02 permission-contract 候选消失 | 每端 1 complete / 1 partial |
| CVE-2025-26693 | access token accesstoken_manager_stub.cpp | 4→1 | AUTH-02/AUTH-03/DATA-04 目标候选消失；AUTH-01 descriptor-boundary 候选仍在 | 两端 partial |

五组报告的 validated_vulnerability 均为 **0**。这些结果说明当前静态规则在固定源码修复对上观察到了与补丁相符的候选差异；它们不证明产品可达、可利用、影响成立，也不是独立 holdout 或 Precision/Recall 测量。CVE-2025-26693 修复端保留的 AUTH-01 需单独复核，不能因为与该 CVE 根因无关就删掉。

CVE-2025-26691 使用原始专项 manifest 中校正后的端点：漏洞端 911c6c99872e3a6a421747815bc8c1f6b201db26，修复端 6018446d576b84d8893f8f7ad5d46353236fb8e0。其余四组的端点与历史固定对报告一致；每一端的完整 commit/tree/snapshot、scope、解析状态、候选明细均记录于 manifest.json 和原始 JSON/Markdown 中。

## 文件

- CVE-*-vulnerable.json|md、CVE-*-fixed.json|md：当前 CLI 原始报告。
- manifest.json：固定对象、范围、覆盖、目标候选差分与保留候选摘要。
- SHA256SUMS：本目录报告和 manifest 的校验和。
- 全部已披露 CVE 清单见父级的 20261019-B线已披露CVE集成清单.md。

本轮只补齐隔离审计缓存中的固定 Git 对象并执行只读扫描；未修改 A 线或队友 B 源仓，没有产品构建、Harness 或设备运行时验证，也没有推送 GitHub。
