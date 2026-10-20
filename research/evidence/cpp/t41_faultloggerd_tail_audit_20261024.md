# T41 独立审计：faultloggerd shared_ptr_race CR-0161–CR-0173

- 基线：`1ebe2d809719cc7b445fe6e723c452e0634c8dd3`；输入源：`50c7dffc057a32987d5eeb7626c20e1b3717c77b` / tree `8b54f17921ba15ff306bcbef280078003a7b1055`。
- 当前 CLI：`ohscanner.cpp.shared_ptr_race 0.5.1`，`light-ast`，4 个目标头文件、完整解析 4/4，7 条诊断；13 个 A0 行中 4/13 精确匹配 finding。完整逐行映射、blob/SHA 和 CLI ID 见同名 JSON。
- `tools/process_dump/dfx_process.h:74`（CR-0161）是 T40 的额外行 finding，本轮确认它确属新增 A0 尾部行。T40 的 `SetMaps` 调用方证据仅涉及 `LocalThreadContextMix::maps_`（CR-0143）；不适用于 DfxProcess、DfxThread 或 minidump parser 对象。
- `dfx_process.h` 的 getter/setter 与 `dfx_thread.h` 的 stack buffer / ProcessInfo getter 只表明成员读写接口；已见生产调用集中在 processdump 的请求初始化和 minidump 处理路径。没有证据证明同一个对象同时跨线程调用这些方法，类本身也没有针对 shared_ptr 成员的锁。
- minidump parser 对象经 `processdump` 的 `minidump_parser` source_set 消费，属于 production-capable 构建路径。`MinidumpParser::streamMapMutex_` 保护 stream map 操作，但并不自动保护其他 `MinidumpStream` 子类的 vector/ref 成员访问。此片段未建立同一流对象并发 Read 与 getter 的重叠。
- 无可信固定版或产品级线程/入口证据；不将完整语法解析、无精确 finding 或 production-capable BUILD 声明解释为安全或漏洞确认。13 项均保留 `PARTIAL` 和 A0 原状态。

## 逐项回放

| ID | Source line | CLI exact finding | Status |
|---|---|---:|---|
| CR-0161 | `tools/process_dump/dfx_process.h:74` | yes | PARTIAL |
| CR-0162 | `tools/process_dump/dfx_thread.h:64` | yes | PARTIAL |
| CR-0163 | `tools/process_dump/dfx_thread.h:69` | yes | PARTIAL |
| CR-0164 | `tools/process_dump/dfx_thread.h:87` | no | PARTIAL |
| CR-0165 | `tools/process_dump/minidump_parser/include/minidump_parser.h:50` | no | PARTIAL |
| CR-0166 | `tools/process_dump/minidump_parser/include/minidump_parser.h:86` | no | PARTIAL |
| CR-0167 | `tools/process_dump/minidump_parser/include/minidump_parser.h:88` | no | PARTIAL |
| CR-0168 | `tools/process_dump/minidump_parser/include/minidump_parser.h:90` | no | PARTIAL |
| CR-0169 | `tools/process_dump/minidump_parser/include/minidump_stream.h:76` | yes | PARTIAL |
| CR-0170 | `tools/process_dump/minidump_parser/include/minidump_stream.h:162` | no | PARTIAL |
| CR-0171 | `tools/process_dump/minidump_parser/include/minidump_stream.h:259` | no | PARTIAL |
| CR-0172 | `tools/process_dump/minidump_parser/include/minidump_stream.h:353` | no | PARTIAL |
| CR-0173 | `tools/process_dump/minidump_parser/include/minidump_stream.h:403` | no | PARTIAL |

## 构建与对象上下文

- `tools/process_dump/BUILD.gn` 将 `processdump_sources` 纳入 `ohos_executable("processdump")` 且 `install_enable = true`；其依赖包含 `minidump_parser:minidump_parser`。
- `tools/process_dump/minidump_parser/BUILD.gn` 定义 `ohos_source_set("minidump_parser")`，由 processdump 依赖。BUILD 只能证明 production-capable target 收录，不证明具体产品 manifest、安装状态或入口可达性。
- `DfxProcess::regs_`（CR-0161）、`DfxThread::stackBuf_`（CR-0162/0163）、`DfxThread::processInfo_`（CR-0164）和 minidump stream/parser shared_ptr（CR-0165–0173）均是不同对象/成员。没有将 T40 LocalThreadContextMix singleton 的 SetMaps 并发结论外推到这些对象。
- CR-0165–0168 为 subject/stream map 相关初始化或 getter；CR-0169 为 `MinidumpContext::SetContextARM64` 内部赋值；CR-0170/0172 返回 vector 引用，CR-0171 返回 vector 拷贝，CR-0173 返回 owned vector shared_ptr。并发安全还取决于实例发布后 Read/访问是否重叠；现有固定证据不足以判定。

## 来源与复验

- 精确 scope 文件、BUILD 文件、调用上下文文件均记录 Git blob、SHA-256 和字节数于 JSON。
- 当前 CLI 原始输出：`t41_faultloggerd_tail_cli_20261024.json`。
- 运行：`python research/evidence/cpp/t41_faultloggerd_tail_audit_20261024.py`；验证：`python research/evidence/cpp/verify_t41_faultloggerd_tail_audit_20261024.py`。
