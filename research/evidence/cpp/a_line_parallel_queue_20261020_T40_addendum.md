# T40 独立测试线任务树增补：faultloggerd shared_ptr_race

基线 `c5c7ea0989c91b884f96ecd1527aad57a7f3a635`。T40 在独立 worktree 上审计 A0 `CR-0119–CR-0160`，未修改 detector、tests、fixtures 或 A0。

## 结果

- 42 个 ID 均绑定 `openharmony/hiviewdfx_faultloggerd` commit `50c7dffc057a32987d5eeb7626c20e1b3717c77b`、tree `8b54f17921ba15ff306bcbef280078003a7b1055`。共 11 个源文件；逐 ID path/line/blob/SHA 在 `t40_faultloggerd_sharedptr_audit_20261024.json`。
- 当前 `ohscanner.cpp.shared_ptr_race` 0.5.1 对声明的 11 个文件执行 CLI，11/11 parse complete、2,498 LOC、11 findings。10 条 finding 精确映射 42 个 A0 行；另外 32 行没有当前精确 finding。还有 `tools/process_dump/dfx_process.h:74` 一条 CLI finding，不属于本组 42 个 ID。该差异是来源/模型核查结果，不能按 zero finding 解释为安全，也不能将finding计数当作竞态数。
- `CR-0124` 的 A0 行在 `stack_printer.cpp:127`，实际是 `Impl()` 空构造函数；当前 CLI 无该行 finding。另有同文件 `SetUnwindInfo` 无锁写 `maps_`/`unwinder_`、若干读点未锁的独立线索，但没有证明同一实例被并发重配置/读取。
- `CR-0143` 所涉 `LocalThreadContextMix::maps_` 属于函数静态 singleton。已确认生产能力写点：`LiteProcessDumper::Unwind` 调 `SetMaps`（`lite_process_dumper.cpp:362`）、`MinidumpDumper::UnwindProcess` 调 `SetMaps`（`minidump_dumper.cpp:514`）；`LocalUnwinder::DoUnwindLocalByOtherTid` 调 `CollectThreadContext` 并在路径结束时 `ReleaseCollectThreadContext`（`local_unwinder.cpp:176–181`）。赋值点未受同一 `mtx_` 保护，但产品配置与服务级序列化/并行调用拓扑未固定，尚未证明同一对象上的并发冲突。
- 其余候选分布于 FpBacktrace 初始化、共享指针构造/持有及 Unwinder/进程转储状态访问。源码没有足够证据证明同一 pointee 或 shared_ptr member 发生并发读写。BUILD 文件将关联源列入 production-capable targets，不是 `testonly` fuzz target；GN 配置本身不证明目标镜像纳入或真实运行时可达。

## 状态与后续动作

所有 42 条维持 A0 原值 `not_testable / paused_pending_evidence`，本任务结论统一 `PARTIAL`。下一项取证应固定目标产品配置和 faultloggerd 服务请求调度，确认 Lite/Minidump dump 与 LocalUnwinder 调用能否重叠；另需确认 StackPrinter 对象是否跨线程共享并允许并发调用。只有确认具体同对象冲突后，才进入受限动态复现或 detector 评估。

可复验材料：

- `t40_faultloggerd_sharedptr_cli_20261024.json` 和 `.md`：当前 CLI 原始复跑。
- `t40_faultloggerd_sharedptr_audit_20261024.json` 和 `.md`：逐 ID 来源、finding 映射、构建与源码审计。
- `verify_t40_faultloggerd_sharedptr_audit_20261024.py`：核对 345 行 A0 台账、42 个 ID、来源 blob/SHA、CLI 及映射。

独立持续目标：持续复核 A0 中可绑定的 `shared_ptr_race` 候选，补齐真实产品线程/对象生命周期证据；未证明时保留 `PARTIAL/BLOCK`，不将静态告警升级为 race 或漏洞。
