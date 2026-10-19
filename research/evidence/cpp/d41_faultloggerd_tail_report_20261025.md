# D41 — faultloggerd `shared_ptr_race` CR-0161–CR-0173

## 范围和来源

D41 只审查 A0 尾段 CR-0161–CR-0173，共 13 条，精确绑定到 `openharmony/hiviewdfx_faultloggerd` commit `50c7dffc057a32987d5eeb7626c20e1b3717c77b`、tree `8b54f17921ba15ff306bcbef280078003a7b1055`。4 个候选文件是 `tools/process_dump/dfx_process.h`、`tools/process_dump/dfx_thread.h`、`tools/process_dump/minidump_parser/include/minidump_parser.h` 和 `tools/process_dump/minidump_parser/include/minidump_stream.h`。逐 ID blob 与 SHA-256、对象身份及当前 finding 映射保存在 [机器可读复放记录](d41_faultloggerd_tail_replay_20261025.json)。

D40 的队列范围是 CR-0119–CR-0160；它曾把 `dfx_process.h:74` 的 finding 记为额外的队列外发现。D41 现在将 CR-0161 绑定到该行，未把 D40 的 42 行审计范围扩写成整个 faultloggerd family。

## 当前 CLI 回放

在固定对象 checkout 上按四个文件运行当前生产 `ohscanner.cpp.shared_ptr_race` CLI 0.5.1：4/4 文件解析完整，874 LOC，DetectorRun `completed`，输出 7 个 syntax diagnostics。13 条 A0 位置中，4 条与当前 finding 精确同位置：CR-0161、0162、0163、0169；另外 9 条无同位置 finding。7 个 finding 中其余 3 个为该 scope 内的额外候选。此计数只表示静态规则对这些行的观察，不表示 race 的命中率或漏洞结论。

精确命令见 replay JSON 的 `cli.command`。原始 CLI JSON 与 Markdown 是 [JSON](d41_faultloggerd_tail_cli_20261025.json) 和 [Markdown](d41_faultloggerd_tail_cli_20261025.md)。

| A0 ID | 文件:行 | 当前同位置 finding | 复核摘要 |
|---|---|---:|---|
| CR-0161 | `dfx_process.h:74` | 是 | `regs_` 的 const shared_ptr 引用 getter；存在初始化写入和多个读取者，但没有本地对象锁。调用时序/对象发布排除并发的证据缺失。 |
| CR-0162 | `dfx_thread.h:64` | 是 | `stackBuf_` setter；process-dump 路径中写入发生在 dump 组装阶段，字段无本地锁。 |
| CR-0163 | `dfx_thread.h:69` | 是 | `stackBuf_` getter；调用点在之后的序列化路径，未证明与写入跨线程重叠。 |
| CR-0164 | `dfx_thread.h:87` | 否 | `processInfo_` getter；该行返回的 shared_ptr 副本本身不能证明 wrapper 并发写入。 |
| CR-0165 | `minidump_parser.h:50` | 否 | `GetSubject()` 返回 shared_ptr 副本。 |
| CR-0166 | `minidump_parser.h:86` | 否 | 私有构造函数初始化 `streamMap_`；为对象构造路径。 |
| CR-0167 | `minidump_parser.h:88` | 否 | 私有构造函数初始化 `minidumpSubject_`；为对象构造路径。 |
| CR-0168 | `minidump_parser.h:90` | 否 | nested `MinidumpStreamInfo::stream_` 成员声明。 |
| CR-0169 | `minidump_stream.h:76` | 是 | `SetContextARM64()` 写 `arm64Context_`；`Read()` 建立 context，访问器随后读取，成员没有局部互斥量。跨线程/重入排除证据缺失。 |
| CR-0170 | `minidump_stream.h:162` | 否 | `MinidumpMemoryRegion` 区域/缓存相关声明。 |
| CR-0171 | `minidump_stream.h:259` | 否 | stream 类型的字段/接口声明。 |
| CR-0172 | `minidump_stream.h:353` | 否 | thread-name 列表 getter 返回容器引用。 |
| CR-0173 | `minidump_stream.h:403` | 否 | `GetThreads()` 返回 shared vector 副本；未证明 wrapper 写入并发。 |

## 调用关系、锁与线程边界

- `DfxProcess::SetFaultThreadRegisters()` 在 `registers.cpp` 和 dump 构造路径写入；reporter、maps、memory-near-register 等路径读取。header 对 `regs_` 没有 mutex/atomic。`SetKeyThread()` 与 `GetKeyThread()` 也没有本地锁。绑定源码只展示每个 process dump 对象的配置、生成和报告阶段，没有证明实例是否可能并发发布，也没有产品任务调度证据。
- `DfxThread::SetThreadStackBuffer()` 和 `GetThreadStackBuffer()` 在 `minidump_dumper.cpp` 分别位于堆栈缓冲区准备和输出阶段。当前源码没有同对象成员锁；阶段上的先后关系来自局部调用流程，不能外推到所有线程/重入入口。
- `MinidumpContext::Read()` 重置并设置 `arm64Context_`，`GetContextARM64()` 与 PC/SP/Print 读取它。实现没有该成员的 mutex；read/parse 的常见调用顺序可见，但不能据此断言所有产品调用均串行。
- `MinidumpParser::InjectStream()` 使用 `unique_lock(streamMapMutex_)` 修改 `streamMap_` 项。该锁只证明此 map 写入受锁保护；不能证明其他独立对象字段都有同样保护。`minidump_parser` GN target 在 `!ohos_lite` 条件下是 source set，`processdump` 是 install-enabled executable；这只证明组件构建目标存在，不绑定具体产品 manifest。
- 抽查限定在 A0 精确对象和有直接关联的实现/BUILD 文件。未绑定产品配置、运行时线程模型、攻击入口、根因利用条件或可信修复源；没有从 syntax-only 结果确认或排除 data race。

## 结论和状态

本轮没有发现来源充分证明的生产级同一 wrapper 未同步并发 root 漏检，因此不改 detector。解析完整不等于项目级调用图、线程模型或产品配置完整。13 条均保持 A0 原状态 `not_testable / paused_pending_evidence`，分类 PARTIAL；不计为安全或 race 已确认。A0 的 345 条总量及状态均未改变。

## 持续结构化 vibe coding 提示词

**角色：** A 线 C/C++ `shared_ptr_race` 开发负责人。

**持续目标：** 只在来源证明存在生产级同一 shared_ptr wrapper 未同步并发访问时改进 detector；区分语法候选、对象数据流、锁与线程事实和产品安全结论。

**输入：** A0 CR-0161–CR-0173，固定 faultloggerd commit/tree/blob/SHA，D41 CLI JSON，相关实现和 GN target 身份，以及 D40 明确限定的 CR-0119–CR-0160 范围。

**步骤：** 先逐 ID 复核源码身份与当前 CLI；逐一追踪 setter/getter、对象所有权、所有调用者、GN target、mutex/atomic 和 task/thread 生命周期；核实同一对象是否可能并发读写；只有确认生产级 root 漏检才提出规则改动，并由独立测试线使用正例、修复/安全/无关/partial controls 复验。

**完成门：** 精确 CLI 和独立 source verifier 通过；适用 root 有真实同对象未同步并发证据；修复/安全对照按实际可用性复验；A0 不变；范围检查通过。缺产品配置、线程调度或可信修复的项继续 PARTIAL/BLOCK 并列出最小缺项。

**边界：** 不把 shared_ptr 语法候选当作 data race；不按仓库、符号名、CVE 或 hash 硬编码；不改 A0 状态、Catalog、API 或公共 schema；不将完整语法解析写成并发/产品结论。

验证命令：

```powershell
python research/evidence/cpp/verify_d41_faultloggerd_tail_20261025.py --source-repo D:\openHarmonyScanner\tmp\a-d40-faultloggerd-source-20261024
python -m scripts.check_change_scope --base 1ebe2d809719cc7b445fe6e723c452e0634c8dd3 --lane cpp
```
