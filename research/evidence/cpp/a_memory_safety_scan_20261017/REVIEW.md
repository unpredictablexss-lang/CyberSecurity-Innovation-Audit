# A memory-safety review and evidence boundaries

更新：2026-10-17。本包由队友 A 在本地 pinned OpenHarmony Git objects 上执行。候选默认 `candidate/unassessed`，`validated_vulnerability=0`。

## Coverage and performance

- 5 个既有固定组件 scope manifests，4983 个 selected source files、51551827 bytes。
- 精确 commit/tree/snapshot/source SHA、scope manifest SHA、profile `light-ast` 已写入各组件 JSON。
- A-BOF-01/A-INT-01/A-RES-01 总 wall 61.046s，进程峰值 RSS 282476 KiB；这是本地固定范围成本，不是全 OpenHarmony 容量认证。
- 当前为 26 条 lexical candidates / 17 个 detector-rule-symbol groups：bounds/integer 16 条、resource lifetime 10 条（8 UAF、2 double-free）。分组不是漏洞或根因计数。

## Historical capability replay

5 个历史样本中 3 个对当前 A 规则适用：vulnerable 3/3 `possible_hit`，fixed 2/3 `miss`、1/3 保留 residual candidate；另 2 个 kernel race/user-kernel case 明确 `not_applicable`。这个小集合不是产品 Precision/Recall 或全局 Recall。

- CVE-2025-26690 null dereference：vulnerable 5 -> fixed 0。
- CVE-2025-23420 sort OOB：vulnerable 5 -> fixed 0。
- c_utils historical UAF：vulnerable 2 -> fixed residual 3，说明 shared_ptr mixed synchronization 仍是 unknown/误报边界。

## Old/new comparison

相对 `ea7d13a69852d5e639e090671b040f7dcd32eebc`：candidates 16 -> 26（+10），lexical groups 10 -> 17（+7），wall 52.078s -> 61.046s。该 delta 只表示新增 resource lifetime 覆盖，不是准确率提升。

## Reviewed false-positive and scope limitations

- `kvstoremock/**` 被 scope planner 的 `mock` 段规则漏排除，不能作为生产组件证据。
- resource lifetime 不拼接 `if/else/goto/label` 跨段状态，避免互斥释放误报；代价是跨路径 UAF/double-free 保持 unknown。
- `strnlen` + 上界 guard、宏-only、placement-new、窄整数提升等形状已固定为安全对照。
- `MAX_KEY_PATH + 1` 等宏值未知保持 unknown，不按宏值臆测溢出。
- 任何没有真实入口/权限、触发、产品构建、可达敏感操作、CIA 影响和独立复核的候选都不能升级 confirmed/reportable。

## Metrics boundary

没有足够大的独立可靠人工 truth/holdout，因此不计算产品 Precision、Recall、F1、FP/FN，也不声称零误报/漏报。历史 capability counts 和候选分组仅用于能力验证与复核组织。
