# A memory-safety review and evidence boundaries

更新：2026-10-17。本包由队友 A 在本地 pinned OpenHarmony Git objects 上执行。候选默认 `candidate/unassessed`，`validated_vulnerability=0`。

## Coverage and performance

- 5 个既有固定组件 scope manifests，4983 个 selected source files、51551827 bytes。
- 精确 commit/tree/snapshot/source SHA、scope manifest SHA、profile `light-ast` 已写入各组件 JSON。
- A-BOF-01/A-INT-01 总 wall 52.4s（每组件 1.0-20.5s），进程峰值 RSS 282800 KiB；这是本地固定范围成本，不是全 OpenHarmony 容量认证。
- `bounds` 没有产生候选；其局部容量/索引覆盖仍因 partial parse、别名和宏上下文而 blocked/unknown。

## Candidate review

当前快照为 16 条 lexical candidates / 11 个 detector-rule-symbol groups；不是 16 个漏洞。代表性高价值候选：

| 组 | 固定位置 | 观察 | 当前结论 |
|---|---|---|---|
| A-INT-01-A | `communication_dsoftbus` `nstackx_file_list.c:269` | `userDataLength + 1` 进入 `calloc`，随后按同一长度 `memcpy_s` | 需追请求来源、长度上限、入口权限、分配/复制失败路径；保持 candidate |
| A-INT-01-B | `communication_dsoftbus` `nstackx_common.c:165,198` | 网络/发现数据 `size + 1` 进入 `calloc` | 需证明 `size` 可达 `SIZE_MAX`、触发和 CIA；保持 candidate |
| A-INT-01-C | `distributeddatamgr_kv_store` `dbm_kv_store.c:928,964` | DB value `len + KV_SUM_BLOCK_SIZE` 进入 `malloc` | 需核对 `unsigned int len`、上层限制、产品构建和可利用性；保持 candidate |
| A-INT-01-D | `nstackx_util.c:153`、`security_access_token` `soft_bus_channel.cpp` | `len + 1`/`sendlen + 1` 形状 | 可能是复制/分配长度，需逐条补上下文；保持 candidate |

## Reviewed false-positive and scope limitations

- `kvstoremock/**` 被 scope planner 的 `mock` 段规则漏排除；这些不是生产组件证据，不能计入产品候选。
- `keyLen + 1` / `valueLen + 1` 的 `strnlen` + `keyLen >= MAX_KEY_LEN` 守卫形状已作为已审阅安全对照回归，当前版本不再报告。
- `MAX_KEY_PATH + 1`、`PATH_MAX + 1` 等宏值未知表达式保持 unknown，不按宏值臆测溢出。
- placement-new 的 `pos + offset` 不是 allocation size，已修正；窄 `uint16_t + 1` 整数提升形状不告警。
- 任何没有真实入口/权限、触发条件、产品构建、可达敏感操作、CIA 影响和独立复核的候选都不能升级 confirmed/reportable。

## Metrics boundary

没有独立可靠人工 truth/holdout，因此不计算 Precision、Recall、F1、FP/FN，也不声称零误报/漏报。候选分组仅用于去重和复核组织，不是根因或漏洞计数。
