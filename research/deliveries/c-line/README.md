# C 线 Ark Runtime 覆盖台账交接

更新时间：2026-10-19（Asia/Shanghai）

机器可读覆盖台账：`ark-runtime-coverage-ledger-20261019.json`。本目录为 C 线交付位置；C8 实验目录 `research/experiments/ark_runtime/c8_20261018/` 保存逐次扫描、源码身份、候选审查和可重放报告。每轮交付须从最新实验状态同步更新本目录的台账和 checkpoint。

## 当前闭环

目标根因：TypedArray 新建结果的运行时类型与 indexed read/write 所用 type token 来源不一致。生产 CLI v0.8.10 在官方 OpenHarmony 5.0.2 manifest pin → Map 修复提交配对及 5.0.3 !11279 回移配对中，Map 方法候选均为 1→0；总候选均为 4→3。修复侧 Filter、With、ToReversed 仍有同家族候选，未判定为误报或漏洞，故广义家族固定版验收未通过。

官方 CVE-2025-24304 公告确认 Ark Runtime 越界写及受影响版本；官方 !11279 说明 !11130 Map 修复作为漏洞修复回移到 5.0.3。该 CVE 与 !11130 的一对一对应是强推断，仍无直接 source link。静态命中保持 candidate。组件动态复现、产品构建/产品影响均未完成。

## 当前基线与阻塞

- 扫描器工作树 HEAD：`73231e6a8d4ea239033dd322aae8936770438b20`；保留共享工作树其他线的未提交改动。
- TypeOrigin 规则经生产 `ohscan-run` 执行；本轮 C8 单测：29 passed、2 skipped。
- 可用 C1 rk3568 GN profile 锁定 Ark Runtime `a65a2853ccae13da167d9aa4720ab8b11ec16656`，目标文件 hash 与 5.0.2 pair 不同，不能作为精确编译/宏展开证据。
- 需解决精确源码 profile/依赖、Filter/With/ToReversed 残余候选，以及 exact Ark Runtime 动态构建与测试。

## 下一步可执行操作

取得或重建 Ark Runtime `8b615647dc4af6f4b572fca50bfbd4d1b91ecad4` 与 `2654cd98e39479b343ee11abf3a65b74e8e9d957` 对应的 rk3568 编译 action 和依赖闭包；对两版目标 TU 预处理并记录宏展开；构建精确版本 Ark Runtime 后运行上游 `typedarraymap` 回归以及 species 场景，逐项判定修复树的 Filter、With、ToReversed 候选。

详细基线、失败记录、完整哈希、生产复放报告、控制样本和分层证据见实验目录中的 `checkpoint.json`、`coverage_ledger.json`、`v502_map_source_identity.json`、`v502_residual_candidates_triage.json` 及 `reports/`。

### 本轮更新（2026-10-19）

新增 IBS5YG / PR !11196 TypedArray Filter 精确父子提交复放。正确父提交为 `2ea501258ab4155826b64f01b499b43d1911e0e2`，修复为 `919e4fbb011f610427e788889083fa8e28d2f951`；生产 `ohscan-run` 得到 1→0 candidate。两边均 blocked/partial，不能作为完整安全结论。上游回归源码已确认，未构建、未运行。之前 `857ff17` 报告保留为非配对观察。

当前 master `d1a58d...` 已进入 source-independent semantic detector；0 告警仍伴随 partial/blocked 分析和 unresolved TypeOrigin，不能解释为安全。尚缺完整安全/无关控制、独立同机制正例、精确构建 profile 和动态回归。详见交接台账与 checkpoint。

### TypeOrigin 模型与适用性文案更新（2026-10-19）

生产规则补充了经 a65 头文件/声明核验的 `LoadHClass(glue, object)`、两参数 builder 构造和 `GetCurrentGlobalEnv()` 形式，并新增正确结果来源与错配来源的回归。精确 !11196 父/修复仍为 1→0。a65 与官方 master 均无 candidate，但实际进入语义分析后仍是 partial/blocked，存在 unresolved TypeOrigin 观察；0 不能当成安全结果。

旧限制文案误称 exact-binding adapter；实际 Catalog 使用 source-identity-independent 语义 detector。已更正文案、添加回归，并更新之前的解释。聚焦套件：72 passed、4 skipped。本轮核实 a65 的 `CallStubBuilder` 七参数构造、`IsTypedArray(glue, obj)`、`IsJsCOWArray(glue, obj)` 和 `IsFastTypedArray(type)` 都只构造图操作；补入有源码身份的签名语义。对新建且未逃逸的 TypedArray，跨未知 callback 保留其 HClass/type 样本；源对象 token 仍失效，结果传入 callback 后仍为 unknown。

六个固定提交的生产复放：!11196 parent/fix 为 1→0 TypeOrigin candidate；a65/master 为 0/0。直接语义侧车显示 Filter 在 parent 为 candidate，在 fix/a65/master 为 matched；Map、With、CopyWithin、Set 的已分析路径也为 matched。独立历史 !11684 safe pair 的 TypeOrigin 路径均 matched；parent 仍有两条独立的 exception-guard candidate，fix 为 0。所有 CLI/直接分析仍 partial/blocked，故控制结果不是完整安全认证，也不是盲留出集。下一步筛选未触碰的官方历史漏洞正例和修复对；找不到时记录具体历史搜索边界并转向另一个有证据的根因家族。


### !9063 TypedArray Filter receiver type guard replay (2026-10-19)

New rule `ark.runtime.typedarray-receiver-type-guard` traces the same GateRef receiver through its HClass type and `IsFastTypeArray` success edge, then checks generated-graph dominance of `GetViewedArrayBuffer`. The exact PR !9063 first-parent/fix pair produced a root-specific production `ohscan-run` delta of 1→0. The full file remains blocked/partial; three TypeOrigin candidates persist on both sides. Five focused receiver tests passed. Neighboring `LastIndexOf` guarded by `IsTypedArray(thisValue)` matched on both revisions; this safe sibling is not a blind holdout. No runtime build/test or product binding/impact evidence is available.

See `../experiments/ark_runtime/c8_20261018/typeguard_ia7e8_source_identity_20261019.json`, the matching `reports/typeguard-v0810-ia7e8-{parent,fix}.json`, and the delivered review copy `OHScanner_G盘源码漏洞审查记录_20261018.md`. The C8 checkpoint names the next executable operation: bind exact product compile actions and include/macro closure, then replay a Filter-external history variant.

### Generated callback `Branch(...)` control-flow update (2026-10-19)

Production detector v0.8.12 now admits CamelCase `Branch(...)` into the generated CFG only when selected source proves its three-argument signature, true/false edge mapping, unambiguous fully qualified inheritance to `StubBuilder`, and no local macro/derived override. Exact I9K03B parent/fix scan at the same five-file scope is 2→1; the fixed non-stable path remains an unresolved candidate. The separately pinned 2024-05-21 OpenHarmony 4.1 source produces two FindIndex candidates and exercises the new alias, but it was used during implementation and is not a holdout. Old e4 five-file replay was not applicable, so no valid before/after comparator exists for that expanded scope. Focused suites: 44 passed/2 skipped; full Ark Runtime suite: 150 passed/11 skipped/7 failed (six existing C3 expectation failures and one C4 manifest expectation failure). No build profile, macro expansion, dynamic reproduction, independent real safe control, holdout, or product impact is established. Exact source/report identities and the next history search are in `ark-runtime-coverage-ledger-20261019.json`, `ark-runtime-checkpoint-20261019.json`, and `../experiments/ark_runtime/c8_20261018/branch_control_contract_i9k03b_20261019.json`.


### Pinned local-history search result (2026-10-19)

Searched the locally pinned Ark Runtime history database without fetching during scans: 31 `Branch(` source-history commits, 16 snapshots containing the scoped callback/exception markers, and 27 complete parsed function candidates. The candidates are textual/control-flow leads only; this pass did not establish an independently disclosed exception-propagation vulnerability pair or a safe/unrelated labelled holdout. No new finding or safety verdict is inferred. Search artifacts: `../experiments/ark_runtime/c8_20261018/branch_source_history_search_20261019.txt`, `branch_source_history_candidate_matrix_20261019.json`, and `branch_function_history_candidates_20261019.json`.

Next executable step: bind one candidate to an official issue/patch and exact parent/fix source identities before replay; if none is supported by the pinned refs, record the bounded search as no-match and move to the existing exact !9063 build-profile/include-macro closure task.
