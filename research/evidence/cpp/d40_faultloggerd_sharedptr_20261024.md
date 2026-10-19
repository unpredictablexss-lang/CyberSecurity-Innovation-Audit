# D40 — faultloggerd shared_ptr_race 源码复核

## 范围与来源

A0 CR-0119–CR-0160 共 42 行，均绑定 `openharmony/hiviewdfx_faultloggerd` commit `50c7dffc057a32987d5eeb7626c20e1b3717c77b`、tree `8b54f17921ba15ff306bcbef280078003a7b1055`。候选分布于 11 个文件；每条记录的 blob 与 SHA-256 在 [逐 ID 机器映射](d40_faultloggerd_sharedptr_replay_20261024.json) 中保存。精确源码对象目录为本地 `openharmony/.repo/project-objects/hiviewdfx_faultloggerd.git`。

当前 `ohscanner.cpp.shared_ptr_race` 0.5.1 CLI 对这 11 个 A0 文件重跑：11/11 完整解析、2,498 LOC、11 条候选。42 个 A0 行中 10 行与当前 finding 行精确对应；其余 32 行当前未在该行报 finding。这个差异记录的是候选观察覆盖，不是 root-cause 准确率或 race 结论。命令模板：

```powershell
python -m src.cli.main ohscan-run --repo-dir <faultloggerd exact checkout> --repository openharmony/hiviewdfx_faultloggerd --commit 50c7dffc057a32987d5eeb7626c20e1b3717c77b --detector ohscanner.cpp.shared_ptr_race --include <11 exact A0 paths> --json-out research/evidence/cpp/d40_faultloggerd_sharedptr_20261024.json
```

## 根因与并发上下文审查

本次不修改 detector：目前没有来源证明的生产级同一 `shared_ptr` wrapper 并发未同步读写 root 漏检。所有 A0 行仍为 `not_testable / paused_pending_evidence`，分类 `PARTIAL`；这不表示安全，也不把语法候选认作 race。

- **CR-0119–0123, `FpBacktraceImpl::maps_`:** `Init()` 创建 maps 并在 `CreateInstance()` 返回对象前完成初始化；代码中未见发布后的 `maps_` 重写。`SymbolicAddress()` 用 `mutex_` 保护 frame cache。返回实例是否被并发共享没有被绑定证据证明。
- **CR-0124–0142, unwinder/parser:** 多数是构造函数持有的内存/映射 shared_ptr 或其成员读取。当前精确行 CLI 未复现这些 A0 行。片段没有证明同一个 wrapper 被并发写入。
- **CR-0143, `LocalThreadContextMix::SetMaps`:** 类是进程内 singleton，内联 setter 不加锁；本组件 production 源码中未找到该 setter 调用（引用在单元测试）。生产 `CollectThreadContext()` 在发信号前设置 `maps_`，`ReleaseCollectThreadContext()` 在等待结束后持锁清理，信号回调路径读取它。并发进入 collect/release 的调用序列化及信号路径完整生命周期仍未知，不能据此确认或排除竞争，保留为补证项。
- **CR-0157–0160, `keyRegs_`、`keyThread_`、`regs_`:** setter 及读取存在于 process-dump 对象；写入在初始化/请求组装阶段，之后在格式化或提交路径读取。当前组件源码未证明同一对象有并发读写，也未证明产品任务/构建路径排除了它。

报告限制：扫描只覆盖这 11 个候选文件；未绑定产品构建清单、外部调用线程模型或目标运行时 harness，也没有可信 fixed source。完整解析仅表示语法解析完成。

## 持续结构化 vibe coding 提示词

- **角色：** A 线 C/C++ `shared_ptr_race` 开发负责人。
- **持续目标：** 只对来源证明的生产级同一 wrapper 未同步并发 root 漏检优化规则；保持语法候选、并发根因、产品可达性和安全影响各自证据边界。
- **输入：** 本报告、精确 commit/tree/blob/SHA、原始 CLI JSON、CR-0119–CR-0160 的来源映射、现有 `shared_ptr_race` 方法卡。
- **步骤：** 交叉引用每个对象的 shared_ptr 读写、锁/原子/条件变量、线程/信号/task 创建与完成顺序；先确认生产入口和构建目标，再判断同对象并发访问；只有重放证明了产品 root 漏检才改 detector，并补 vulnerable/fixed/safe/unrelated/renamed/partial controls；交由独立测试线复验。
- **完成门：** 独立 CLI 重放绑定精确源码；适用 root 有同对象并发未同步读写的来源证据，修复/安全对照按可用性通过；其他项明确 PARTIAL/BLOCK；A0 状态不被篡改且范围检查通过。
- **边界：** 不从 `shared_ptr` 语法推断 data race；不按 CVE、仓库、符号名或哈希硬编码；不伪造 fixed source，不修改 A0 状态或公共 API/Catalog。

验证器：`python research/evidence/cpp/verify_d40_faultloggerd_sharedptr_20261024.py --source-git-dir <faultloggerd object database>`。原始 CLI 输出：[d40_faultloggerd_sharedptr_20261024.json](d40_faultloggerd_sharedptr_20261024.json)；逐 ID 来源与定位：[d40_faultloggerd_sharedptr_replay_20261024.json](d40_faultloggerd_sharedptr_replay_20261024.json)。
