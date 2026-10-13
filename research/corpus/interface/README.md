# Interface historical advisory seeds
> **政策更新 2026-10-10**：本文为历史记录（记录某时点实际做了什么），事实性内容保留原样。文中"不做 PoC / 不做动态验证 / 不升级结论状态 / 不计算 Precision-Recall"等限制已于 2026-10-10 **废除**；当前生效政策见 `AGENTS.md` 的 **Competition deliverables — must produce** 章节：PoC、动态验证、CWE/CVE、影响范围、修复建议、性能数据、漏洞报告均为**必须产出**的交付物。

`official_advisory_seeds_2026-10-09.json` is a **purposively selected S0 advisory index**, not a runnable benchmark manifest. It contains 17 official records, including authorization and path/file access leads. Independent root-cause count is unknown; no record has been upgraded to S2/S3.

Sources are pinned to `openharmony/security` commit `ceaf1b4fbe38e46cd18bfcffd7353516bdc34227`. Each record carries an advisory path, line, Git-blob-content SHA-256, row SHA-256 and the advisory's fix reference URLs. Hashes refer to bytes read from Git objects, not Windows checkout line endings. Target code revisions, affected symbols, CWE and analysis profiles remain unverified.

Do not pass this file to the existing historical benchmark loader or use its records as a Precision/Recall denominator. They are leads for investigation. Review patch semantics, fix ancestry, affected source snapshots, source licenses, safe controls and build/parse scope before promotion under `docs/strategy/vulnerability_corpus_bakeoff_protocol.md`.

`CVE-2024-21816` and `CVE-2024-39612` refer to the same background-task PR. Keep both advisory records, but investigate their event identity before counting independent cases. Backports, related fixes and renamed repositories also need review.

All records are `unassigned_advisory_seen`, `benchmark_eligible=false`, with runtime `not_run`. They are neither unseen holdout cases nor newly discovered vulnerabilities. The summaries are research notes; original official descriptions and affected-version details remain at the pinned source URLs.

See [the B research plan](../../../docs/strategy/teammate_b_detection_research_plan_2026-10-09.md) for detector priorities, algorithms and evaluation design. No third-party target source or scanner implementation is included.
