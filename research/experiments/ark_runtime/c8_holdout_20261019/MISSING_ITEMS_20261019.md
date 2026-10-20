# AC-HOLDOUT-04 missing items and continuous slices

本文件只补充 pinned artifact 的缺失项，不生成第三份 holdout packet，不覆盖 `origin/codex/c-line-ark-runtime-replay-20261019` 已有内容。

## Missing items

| ID | 优先级 | 缺失项 | 完成门 |
|---|---:|---|---|
| M01 | 1 | 0.7.0 双规则 freeze manifest | 绑定 0.7.0、两个 rule ID、8 个 source SHA-256、model digest、profile、AnalysisBudget |
| M02 | 1 | freeze manifest digest 唯一绑定 | `0b8b...` 与 `852d...` 的语义/规范化差异被解释并可重放，或新 manifest 直接绑定 exact bytes |
| M03 | 1 | frozen implementation 自洽 | 6/6 implementation SHA-256 与 pinned path bytes 相同，或增加独立 immutable implementation snapshot |
| M04 | 1 | 独立 truth | 至少两名独立 reviewer 完成真正 unseen holdout；作者/开发者不作为 truth authority |
| M05 | 2 | reviewer metadata/timing 扩展 | reviewer_id、reviewed_at、confidence、active/paused seconds、unknown reason、evidence 完整 |
| M06 | 2 | 分歧裁决账本 | 保留所有分歧，记录 adjudicator、basis、status；未决项保持 unknown |
| M07 | 2 | 0.7.0 replay 性能账本 | exact argv/env、coverage/partial/unknown、wall/RSS/Token/cost；未测项显式 unknown |
| M08 | 3 | 历史 Git objects | 缺 commit/tree/creator object 时继续 blocked/unknown，不转成 safe/miss |

## 后续持续切片

1. S1：在不改远端 packet 的前提下增加 0.7.0 freeze overlay，解决 M01-M03。
2. S2：发布 reviewer metadata/timing extension，启动两名独立 reviewer；prediction 文件保持封存。
3. S3：标签冻结后运行分歧裁决；只有 reliable non-model truth 与完整 prediction 同时满足，才进入指标计算候选。
4. S4：补 Ark Runtime repository-scale performance，分别报告 wall/RSS/Token/cost、coverage/partial/unknown。
5. S5：增加跨版本、多仓 unseen variants；parent/fix/safe family 隔离，禁止同根因泄漏到开发调参集。

## Reviewer timing contract

- `active_seconds` 只累计实际阅读/标注时间。
- `paused_seconds` 记录明确暂停区间；`timing_status` 只能为 `not_started/active/paused/completed/unknown`。
- 时间缺失必须写 `unknown`，不得用 wall time 代填人工 active time。
- 每个 reviewer 独立填写；分歧不得在标签冻结前互相查看或协商。

## Metric gate

`eligible_for_metrics=false`。当前不得计算 Precision/Recall，不得声称零 FP/FN，不得升级产品 CIA/CVE/confirmed。只有独立可靠 truth、完整 prediction、稳定 root-cause identity 与 coverage/unknown 账本全部满足后，才可在新输出中重新评估该 gate。
