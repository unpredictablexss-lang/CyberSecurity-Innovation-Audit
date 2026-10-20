# Known-case scanner coverage matrix

状态：`candidate/unassessed`。本矩阵逐条核对原文 `research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md` 的“OHScanner C线真实源码复放补记”中 8 项 Ark Runtime 机制，仅说明 scanner 规则/适用性/证据覆盖，不升级产品结论，不计算准确率。

原文身份：remote `origin/codex/c-line-ark-runtime-20261018` = `e4e0761501a83ac25cc67d04c527eefe9f4a1b50`，tree `307ac8237263db793028e0bf34a82a85f60821a5`，path `research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`，blob `dbedea677c8dc70c1b0066c7bc52df27bcff06ea`，SHA-256 `732b17b4adba11f1fefb93940859d951e03d35a69987b77a61f9a785eefe1240`。

| 原文行 | 机制 | local 7af / 715e298 | remote e4e0761 | 集成判定 | 合流门 |
|---|---|---|---|---|---|
| 202 | CVE-2025-24304 / TypedArray Map result type origin | `ark.runtime.typedarray-store-type-origin` 存在，但 0.7.0 selector 以 Filter/CopyWithin/Set/With 为边界，不含 Map；没有 e4e release-pin replay | v0.8.10 source-independent selector 与证据覆盖 Map 根因 1→0；固定侧 Filter/With/ToReversed 仍为同族 candidate，文件 partial | `covered_candidate_partial` | 合并 TypeOrigin 语义后重跑同一 Map pair 与三残留；不得把 Map 1→0 当家族 safe |
| 203 | IBS5YG / TypedArray Filter result type origin | TypeOrigin 与 C3 反例修复存在；缺少 e4e 的 glue-aware `LoadHClass`、双参 builder 和 `api_overload_evidence` 扩展 | v0.8.10 精确 !11196 parent/fix 1→0；a65/master 的 0 伴随 unresolved/partial | `covered_candidate_partial` | 先修复 e4e focused TypeOrigin failures，再绑定完整 include/macro/profile 并复跑 |
| 204 | I7KZJ7 / TypedArray buffer byte-length multiplication | 无对应 size-overflow 机制 | `ark.runtime.typedarray-buffer-size-multiplication-overflow` / `size_overflow.py` 已接入，root-specific 1→0；full TU 仍 partial，安全影响未闭合 | `covered_candidate_partial` | 保留为结构候选；补全编译事实和独立同机制 pair |
| 205 | IC7B8Q / TypedArray Map allocation exception | `exception_guard.py` 建模 `NewTypedArray -> LoadHClass`，caller 含 Filter/Map；历史 parent/fix 测试因 Ark Git store 缺失而 skip | allocation-exception rule 与 !11684 证据覆盖 parent 2 candidates -> fix 0；整 TU partial | `covered_candidate_partial` | 合并 exception-guard 修复并恢复 pinned Ark store 后执行 exact replay |
| 206 | IAO7GO / Reflect.apply exception propagation | 无 compiler NativeInlineLowering exception-flow 规则 | e4e 虽有 runtime/callback/call-info exception 规则，但 ledger 明确 compiler IR lowering 不在 selector；parent/fix 0 是 0 applicable 的漏覆盖 | `missing_uncovered` | 新增独立 compiler exception-lowering 模型与 source-disjoint holdout；当前不得记 pass |
| 207 | I7W51D / TypedArray length narrowing | 无窄化规则 | size-overflow 仅覆盖乘法；narrowing 0→0 是规则缺失，ledger 明确未 admitted | `missing_uncovered` | 单列 signed→unsigned/narrowing 语义，不得复用乘法规则宣称覆盖 |
| 208 | IB8BCA / DataView index width and bounds | 无 DataView/Atomics 边界模型 | e4e 仍无对应规则；0→0 伴随 blocked/partial | `missing_uncovered` | 新增 DataView/Atomics range/index invariant 与独立正/修复/安全控制 |
| 209-215 | IAO7E8 / TypedArray Filter receiver type guard | 无 receiver-guard 规则 | `ark.runtime.typedarray-receiver-type-guard` / `receiver_guard.py`；!9063 parent/fix 1→0，LastIndexOf 仅 safe sibling，不是盲留出 | `covered_candidate_partial` | 合入 receiver guard 后补 source-disjoint TypedArray 非 Filter pair 和动态/产品边界 |

## 必须保留的缺口

- `IAO7GO`：compiler IR exception lowering 未覆盖。
- `I7W51D`：length narrowing 未覆盖。
- `IB8BCA`：DataView/Atomics index-width/bounds 未覆盖。
- e4e focused Ark 运行仍有 6 个 TypeOrigin failures；在失败清零或逐项裁决前，TypeOrigin 行均不能作为完整合流验收。
- 原文 remote 文件不是本地 strict reconciliation 的 root input `源码漏洞审查记录_20261018.md`。strict 输入门仍为 `blocked_missing_input`；本矩阵不是替代输入导入。
