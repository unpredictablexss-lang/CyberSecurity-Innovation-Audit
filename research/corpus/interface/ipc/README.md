# IPC corpus evidence levels
> **政策更新 2026-10-10**：本文为历史记录（记录某时点实际做了什么），事实性内容保留原样。文中"不做 PoC / 不做动态验证 / 不升级结论状态 / 不计算 Precision-Recall"等限制已于 2026-10-10 **废除**；当前生效政策见 `AGENTS.md` 的 **Competition deliverables — must produce** 章节：PoC、动态验证、CWE/CVE、影响范围、修复建议、性能数据、漏洞报告均为**必须产出**的交付物。

`advisories.jsonl`：39 条用户清单记录，官方固定公告匹配后为 S1。初始子类与 IPC 相关性仍属 provisional。
`verified_pairs.jsonl`：12 个去重的 S2 静态根因，所有样本 split=design。标签由本次代码/补丁审阅生成，不是独立人工双人标注。
`pending_pairs.jsonl`：1 个混合补丁 S1，禁止正样本计分。
`generated_holdout.json`：13 个与设计控制同源的生成变体，非独立历史验证集；freeze 在生成/评估之前。
`design_freeze.json`：检测代码内容哈希；`model_sources.json`：API 模型来源。

S0=检索线索；S1=官方公告与补丁引用匹配；S2=固定源码与补丁根因复核；S3=实际产品运行验证。本次 S3=0，所有 validated_vulnerability=0。零告警、解析成功或官方 ID 命中都不能自动升级证据。

目标源文件不入仓库。运行 `research/experiments/interface/ipc/acquire_sources.py` 后，用 `validate_corpus.py` 检验 98 个文件、Git blob、固定提交和 frozen detector。重型素材在 WSL `~/openharmony-audit/ipc-research`。完整结果与限制见 docs/research/ipc_scanner_v0_1_2026-10-10.md。
