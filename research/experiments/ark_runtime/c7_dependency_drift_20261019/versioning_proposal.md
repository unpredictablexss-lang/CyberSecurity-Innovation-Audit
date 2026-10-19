# 版本化建议
1. 冻结 model 0.6.2 历史语义，不静默追认 a65a2853 漂移对象。
2. 语义闭合前只允许 0.7.0-drift-review.1 证据候选，不注册生产语义。
3. 18 项全部证明 equivalent 才发布 0.6.3；任一 modeled function/type/macro/effect 变化则发布 0.7.0 并重建 effect summaries。
4. 部分闭合时拆分 model generations；等价行兼容绑定，漂移/unknown 行 fail closed。
5. C7-DEP-018 在 manifest owner 裁决前保留独立 obligation。
6. 每项需 commit/tree/blob/source SHA、model/rule version、scope/profile、artifact hashes 及 positive/fixed/safe/unrelated 控制；unknown 不得升级。