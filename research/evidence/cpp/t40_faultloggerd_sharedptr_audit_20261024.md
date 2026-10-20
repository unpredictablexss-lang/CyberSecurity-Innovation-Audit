# T40 独立审计：faultloggerd shared_ptr_race CR-0119–CR-0160

- 整合基线：`c5c7ea0989c91b884f96ecd1527aad57a7f3a635`；审计提交：`50c7dffc057a32987d5eeb7626c20e1b3717c77b`，tree `8b54f17921ba15ff306bcbef280078003a7b1055`。
- 范围：42 个 A0 ID，覆盖 11 个源码文件；文件 blob/SHA、BUILD blob/SHA 和逐 ID 证据见同名 JSON。
- 当前 CLI：`ohscanner.cpp.shared_ptr_race 0.5.1`，profile `light-ast`，completed；解析 {'complete': 11}，11 条 diagnostics，10/42 个 A0 行精确对应 finding。另有 `tools/process_dump/dfx_process.h:74` finding 不属于这 42 个 A0 ID。
- 结论：全部保留 `PARTIAL / not_testable / paused_pending_evidence`。Finding 是 shared_ptr 语法候选，不等同同一对象并发读写、真实竞态或漏洞。A0 原队列未修改。

## 逐 ID 对账

| A0 ID | 源文件:行 | A0 行摘要 | 当前 CLI 精确 finding | 结论 |
|---|---|---|---|---|
| CR-0119 | `interfaces/innerkits/backtrace/fp_backtrace.cpp:80` | `maps_ = DfxMaps::Create(0, false);` | `ohscanner.cpp.shared_ptr_race:825a4e514c81aaec` | PARTIAL |
| CR-0120 | `interfaces/innerkits/backtrace/fp_backtrace.cpp:81` | `if (maps_ == nullptr) {` | `ohscanner.cpp.shared_ptr_race:43071211c68328f4` | PARTIAL |
| CR-0121 | `interfaces/innerkits/backtrace/fp_backtrace.cpp:85` | `maps_->GetStackRange(mainStackBegin_, mainStackEnd_);` | `ohscanner.cpp.shared_ptr_race:072aad444b4c0cad` | PARTIAL |
| CR-0122 | `interfaces/innerkits/backtrace/fp_backtrace.cpp:86` | `maps_->GetStaticArkRange(staticArkBegin_, staticArkEnd_);` | `ohscanner.cpp.shared_ptr_race:08e55eb42d49c393` | PARTIAL |
| CR-0123 | `interfaces/innerkits/backtrace/fp_backtrace.cpp:92` | `if (!maps_ \|\| startFp == nullptr \|\| pcArray == nullptr \|\| size == 0) {` | `ohscanner.cpp.shared_ptr_race:3113990f32f9e532` | PARTIAL |
| CR-0124 | `interfaces/innerkits/stack_printer/src/stack_printer.cpp:127` | `Impl() : root_(nullptr)` | 无（不是 safe 结论） | PARTIAL |
| CR-0125 | `interfaces/innerkits/unwinder/include/dfx_accessors.h:85` | `DfxAccessorsCustomize(std::shared_ptr<UnwindAccessors> accessors) : accessors_(accessors) {}` | 无（不是 safe 结论） | PARTIAL |
| CR-0126 | `interfaces/innerkits/unwinder/include/dfx_elf_parser.h:46` | `ElfParser(const std::shared_ptr<DfxMmap>& mmap) : mmap_(mmap) {}` | 无（不是 safe 结论） | PARTIAL |
| CR-0127 | `interfaces/innerkits/unwinder/include/dwarf_cfa_instructions.h:31` | `DwarfCfaInstructions(std::shared_ptr<DfxMemory> memory) : memory_(memory) {};` | 无（不是 safe 结论） | PARTIAL |
| CR-0128 | `interfaces/innerkits/unwinder/include/dwarf_op.h:40` | `DwarfOp(std::shared_ptr<DfxMemory> memory) : memory_(memory) {};` | 无（不是 safe 结论） | PARTIAL |
| CR-0129 | `interfaces/innerkits/unwinder/include/dwarf_op.h:85` | `memory_->Read<uintptr_t>(addr, &val);` | 无（不是 safe 结论） | PARTIAL |
| CR-0130 | `interfaces/innerkits/unwinder/include/dwarf_op.h:98` | `memory_->Read<uint8_t>(exprPtr, &operand, true);` | 无（不是 safe 结论） | PARTIAL |
| CR-0131 | `interfaces/innerkits/unwinder/include/dwarf_op.h:102` | `memory_->Read<uint8_t>(addr, &u8, true);` | 无（不是 safe 结论） | PARTIAL |
| CR-0132 | `interfaces/innerkits/unwinder/include/dwarf_op.h:108` | `memory_->Read<uint16_t>(addr, &u16, true);` | 无（不是 safe 结论） | PARTIAL |
| CR-0133 | `interfaces/innerkits/unwinder/include/dwarf_op.h:115` | `memory_->Read<uint32_t>(addr, &u32, true);` | 无（不是 safe 结论） | PARTIAL |
| CR-0134 | `interfaces/innerkits/unwinder/include/dwarf_op.h:124` | `memory_->Read<uint64_t>(addr, &u64, true);` | 无（不是 safe 结论） | PARTIAL |
| CR-0135 | `interfaces/innerkits/unwinder/include/dwarf_op.h:165` | `memory_->Read<uint8_t>(exprPtr, &reg, true);` | 无（不是 safe 结论） | PARTIAL |
| CR-0136 | `interfaces/innerkits/unwinder/include/dwarf_op.h:307` | `stack_[0] += memory_->ReadUleb128(exprPtr);` | 无（不是 safe 结论） | PARTIAL |
| CR-0137 | `interfaces/innerkits/unwinder/include/dwarf_op.h:350` | `memory_->Read<int16_t>(exprPtr, &offset, true);` | 无（不是 safe 结论） | PARTIAL |
| CR-0138 | `interfaces/innerkits/unwinder/include/dwarf_op.h:362` | `memory_->Read<int16_t>(exprPtr, &offset, true);` | 无（不是 safe 结论） | PARTIAL |
| CR-0139 | `interfaces/innerkits/unwinder/include/dwarf_op.h:443` | `auto reg = static_cast<uint32_t>(memory_->ReadUleb128(exprPtr));` | 无（不是 safe 结论） | PARTIAL |
| CR-0140 | `interfaces/innerkits/unwinder/include/dwarf_op.h:460` | `auto value = static_cast<SignedType>(memory_->ReadSleb128(exprPtr));` | 无（不是 safe 结论） | PARTIAL |
| CR-0141 | `interfaces/innerkits/unwinder/include/dwarf_op.h:467` | `auto reg = static_cast<uint32_t>(memory_->ReadUleb128(exprPtr));` | 无（不是 safe 结论） | PARTIAL |
| CR-0142 | `interfaces/innerkits/unwinder/include/dwarf_op.h:473` | `auto value = static_cast<SignedType>(memory_->ReadSleb128(exprPtr));` | 无（不是 safe 结论） | PARTIAL |
| CR-0143 | `interfaces/innerkits/unwinder/include/thread_context.h:105` | `void SetMaps(std::shared_ptr<DfxMaps> maps) { maps_ = maps; }` | `ohscanner.cpp.shared_ptr_race:9e6a516877c1c8d1` | PARTIAL |
| CR-0144 | `interfaces/innerkits/unwinder/include/unwind_entry_parser.h:29` | `explicit UnwindEntryParser(const std::shared_ptr<DfxMemory>& memory) : memory_(memory) {}` | 无（不是 safe 结论） | PARTIAL |
| CR-0145 | `interfaces/innerkits/unwinder_refactor/include/unwinder_base.h:82` | `state_->regs = regs;` | 无（不是 safe 结论） | PARTIAL |
| CR-0146 | `interfaces/innerkits/unwinder_refactor/include/unwinder_base.h:83` | `state_->firstFrameSp = regs->GetSp();` | 无（不是 safe 结论） | PARTIAL |
| CR-0147 | `interfaces/innerkits/unwinder_refactor/include/unwinder_base.h:91` | `state_->maps = maps;` | 无（不是 safe 结论） | PARTIAL |
| CR-0148 | `interfaces/innerkits/unwinder_refactor/include/unwinder_base.h:96` | `return state_->regs;` | 无（不是 safe 结论） | PARTIAL |
| CR-0149 | `interfaces/innerkits/unwinder_refactor/include/unwinder_base.h:101` | `return state_->maps;` | 无（不是 safe 结论） | PARTIAL |
| CR-0150 | `interfaces/innerkits/unwinder_refactor/include/unwinder_base.h:106` | `return state_->lastErrorData.GetCode();` | 无（不是 safe 结论） | PARTIAL |
| CR-0151 | `interfaces/innerkits/unwinder_refactor/include/unwinder_base.h:111` | `return state_->lastErrorData.GetAddr();` | 无（不是 safe 结论） | PARTIAL |
| CR-0152 | `interfaces/innerkits/unwinder_refactor/include/unwinder_base.h:208` | `return state_->jitCache;` | 无（不是 safe 结论） | PARTIAL |
| CR-0153 | `interfaces/innerkits/unwinder_refactor/include/unwinder_base.h:248` | `: state_(state),` | 无（不是 safe 结论） | PARTIAL |
| CR-0154 | `interfaces/innerkits/unwinder_refactor/include/unwinder_base.h:249` | `frameMgr_(*state_),` | 无（不是 safe 结论） | PARTIAL |
| CR-0155 | `interfaces/innerkits/unwinder_refactor/include/unwinder_base.h:250` | `mixedStack_(*state_),` | 无（不是 safe 结论） | PARTIAL |
| CR-0156 | `interfaces/innerkits/unwinder_refactor/include/unwinder_base.h:251` | `unwindCore_(*state_, frameMgr_, mixedStack_)` | 无（不是 safe 结论） | PARTIAL |
| CR-0157 | `tools/process_dump/coredump/coredump_note_segment_writer.h:103` | `keyRegs_ =  regs;` | `ohscanner.cpp.shared_ptr_race:30c5704b904e3cff` | PARTIAL |
| CR-0158 | `tools/process_dump/dfx_process.h:55` | `return keyThread_;` | `ohscanner.cpp.shared_ptr_race:e8bc5bf3de23df86` | PARTIAL |
| CR-0159 | `tools/process_dump/dfx_process.h:60` | `keyThread_ = keyThread;` | `ohscanner.cpp.shared_ptr_race:b95bbc62436d4be7` | PARTIAL |
| CR-0160 | `tools/process_dump/dfx_process.h:69` | `regs_ = regs;` | `ohscanner.cpp.shared_ptr_race:93f311701435a067` | PARTIAL |

## 源码并发与构建边界

- **FpBacktraceImpl `maps_`（CR-0119–0123）**：`Init()` 建立并写入，`CreateInstance()` 初始化成功后才返回对象；之后 `BacktraceFromFp` 读取，`SymbolicAddress` 在 `mutex_` 下读并操作缓存。没有发现对象发布后的第二次 maps_ 写入。对象生命周期/外部调用线程契约未绑定，因此不据此判安全或竞态。
- **StackPrinter（CR-0124）**：A0 行 127 是空构造函数初始化列表，当前 CLI 无精确 finding，属于 A0 source/model mismatch。同文件的 `SetUnwindInfo` 对 `unwinder_`/`maps_` 无锁赋值；`GetFullStack`/`GetTreeStack` 有无锁读取，`GetHeaviestStack` 的初始空值读取也在锁外。这是单独的潜在线索，但当前没有证明调用者共享同一对象并重叠调用。
- **DfxAccessors / ElfParser / Dwarf / UnwindEntryParser（CR-0125–0142）**：队列行对应构造初始化或通过已持有对象读取；shared_ptr 的复制/持有本身不证明 pointee 并发访问。未在这些行证明同一 shared_ptr member 有并发赋值和读取。
- **LocalThreadContextMix `maps_`（CR-0143）**：它是函数静态 singleton。写入点包括 `CollectThreadContext`、`SetMaps`、`ReleaseCollectThreadContext`；读取点包括 `GetMapByPc`、`FindUnwindTable`、`AccessMem`、`GetMaps`。`SetMaps` 的生产能力调用见 `LiteProcessDumper::Unwind` 和 `MinidumpDumper::UnwindProcess`；`Collect/Release` 来自 `LocalUnwinder::DoUnwindLocalByOtherTid`。`SetMaps`/`Collect` 赋值不在 `mtx_` 临界区；Collect 信号/条件变量交接及 Release 持锁清理也必须结合整体调用序列判断。共享 singleton 与未锁写入是真实源码事实；是否有产品服务并行调用/与读操作重叠仍未由固定产品配置和调用拓扑证明，故只列 follow-up，不升级为 race。
- **UnwinderSharedState（CR-0145–0156）**：内部组件共享一个状态对象，`SetRegs`/`SetMaps` 与 getters 访问 regs/maps；这些行无锁。但同一 Unwinder 对象的跨线程访问契约未建立，组件共享不等于线程并发。
- **CoredumpThread / DfxProcess（CR-0157–0160）**：`CoredumpThread::Init` 设置 regs，DfxProcess setters/getters 暴露 keyThread_/regs_。已检查进程转储调用点；尚无同一个实例跨线程并发读写的证据。
- `BUILD.gn` 将相关源列入 production-capable `ohos_shared_library`、unwinder 和 process-dump targets；这些目标不是 `testonly` fuzz target。构建声明不能证明所选产品镜像启用目标，也不能建立运行时可达性或调用并发。本次没有构建产品或运行 TSan。

## 限制与下一步

当前 11 个 CLI 文件均 parse complete，但范围只有 2,498 LOC，profile 为 light-ast；这不代表完整组件语义覆盖。最值得继续取证的是 LocalThreadContextMix singleton 的产品服务序列化与并发 dump 调用，以及 StackPrinter 实例是否会被并发重配/读取。缺这些证据前，不改 detector、不将零结果或候选数解释成 precision/recall、安全或漏洞确认。

复验：`python research/evidence/cpp/t40_faultloggerd_sharedptr_audit_20261024.py` 生成逐 ID JSON；`python research/evidence/cpp/verify_t40_faultloggerd_sharedptr_audit_20261024.py` 校验来源身份、42 行映射、A0 状态和 CLI 报告。
