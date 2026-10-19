### D40 — faultloggerd CR-0119–CR-0160 shared_ptr_race 源码回放

输入：冻结的 42 条 A0 候选及其精确 faultloggerd 对象；当前 `shared_ptr_race` 规则 0.5.1。

D40 对 A0 中 11 个唯一文件重跑 CLI：11/11 完整解析，2,498 LOC，11 条 syntax candidate；42 条 A0 行里 10 条与 finding 行精确对应，其余位置没有当前行级 finding。来源 commit/tree 为 `50c7dffc057a32987d5eeb7626c20e1b3717c77b` / `8b54f17921ba15ff306bcbef280078003a7b1055`，逐项 blob/SHA 与 replay 定位见 [D40 报告](d40_faultloggerd_sharedptr_20261024.md)、[raw CLI](d40_faultloggerd_sharedptr_20261024.json) 和 [逐 ID 映射](d40_faultloggerd_sharedptr_replay_20261024.json)。

未证明生产级同一 shared_ptr wrapper 的跨线程未同步读写根因，故无 detector 修改。`LocalThreadContextMix` singleton 的 `maps_` signal/collect 生命周期存在未闭合的并发序列化问题，但 A0 `SetMaps` 在生产源码中无调用；不把这个不确定性结论转为 race 或安全结论。所有 42 条继续 `not_testable / paused_pending_evidence`，A0 345 行状态未变。运行 [D40 verifier](verify_d40_faultloggerd_sharedptr_20261024.py) 可复核来源、raw replay、逐行映射及队列状态。

**持续目标：** 继续查明 `LocalThreadContextMix` collect/release 调用串行化与 process-dump 对象任务生命周期；只有获取具体生产调用/构建和同对象并发证据后再决定 detector 规则变化。否则保持 PARTIAL/BLOCK，补证到达前不声称安全。
