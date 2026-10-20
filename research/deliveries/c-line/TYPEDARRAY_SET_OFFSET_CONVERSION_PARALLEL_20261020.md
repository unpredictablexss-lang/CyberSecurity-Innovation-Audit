# TypedArray.set offset 转换可达性：开发/独立测试切片（2026-10-20）

## 触发依据与身份

当前 C 收尾代码基线：`4e1268a980fd103326c7dbaa6ca2e78d2ba43e69`，tree `0495b0db7d05f02e2ce4e48149f7571c8bdd8023`。Ark Runtime 输入源码：`openharmony/arkcompiler/ets_runtime@a65a2853ccae13da167d9aa4720ab8b11ec16656`，tree `8781f036a3e7e04d8e0b34970d5f623b42875016`。

已有条件性 `TypedArray.set(arrayLike, offset)` 源码候选使用 `targetOffset = 2^64 - 2048` 计算 unsigned range-sum wrap。新发现的可核实边界是实际实现调用 `ToInteger` 并将 double 转 `uint64_t`；必须独立证明该输入可由 JS Number 表达、且转换处于合法范围。Ark Runtime 构建尝试在依赖检查处停止：当前 checkout 缺 Node.js 14.21.1、Linux Python 预置和 Hvigor；因此不记为 runtime 结果。

## C-DEV-SET-OFFSET-CONVERSION-20261020

```yaml
role: 精确源码转换路径开发/分析负责人
code_sha: 4e1268a980fd103326c7dbaa6ca2e78d2ba43e69
source_repo: openharmony/arkcompiler_ets_runtime
source_commit: a65a2853ccae13da167d9aa4720ab8b11ec16656
objective: 证明或推翻候选 offset 经真实 JS Number → ToInteger → double→uint64_t 路径的可达性，并复核之后 unsigned 算术。
steps:
  - 绑定 BuiltinsTypedArray::Set 和 ToInteger 实现的完整源码对象身份
  - 分析 2^64-2048 的 binary64 可表示性与 uint64_t cast 范围
  - 跟踪负数、+Infinity、2^64 和邻近可表示值等边界控制
  - 用最小隔离计算复核 unsigned addition、byte index narrowing 和 range check
  - 写 source-only 报告，明确不等同于 Ark VM 执行
deliverable: research/deliveries/c-line/typedarray_set_offset_conversion_developer_20261020.md (194495c845240aab728e8480ac62c6a9dd488130); correction research/deliveries/c-line/typedarray_set_offset_conversion_correction_20261020.md (28eb558366f8bf224ccdb593f67635e7dc07afae)
feedback: 独立测试线发现初版对循环写入仍在 TypedArray view 内的推论不成立；开发线用非零 targetByteOffset 反例更正，反馈已由测试线复核
stop: 不修改生产 detector，不称为 runtime PoC 或产品影响；runtime/build 未执行时保持 not_run/unknown
```

## C-TEST-SET-OFFSET-CONVERSION-20261020

```yaml
role: 独立转换可达性反证/测试负责人
code_sha: 4e1268a980fd103326c7dbaa6ca2e78d2ba43e69
source_commit: a65a2853ccae13da167d9aa4720ab8b11ec16656
objective: 独立复现/挑战开发报告中的 JS Number 可达性、binary64 邻值、uint64_t 转换和 unsigned wrap 计算。
steps:
  - 自行读取精确 pinned source 与 ToInteger 实现，不先复用开发推理
  - 在独立 temp 中用 Python/C++ 计算可复现的正例与边界控制
  - 审阅开发报告，逐项回传源码行、身份或算术差异
  - 若发现反例，要求开发线修订后再复核报告
deliverable: research/deliveries/c-line/typedarray_set_offset_conversion_independent_20261020.md (edf0cb0c48dce15f722b34caa167e82a88de3474)
stop: 不改生产代码，不将微型计算称作 Ark Runtime 执行；runtime 保持 not_run，product 保持 unknown
```

## 持续目标

本切片仅回答 offset 转换可达性与源代码算术链。开发线先提交证据，独立测试线在同一 scanner/source SHA 上挑战；矛盾经开发修订后由测试线复查。反馈闭环现已完成：`2^64-2048` 可达；array-like 路径存在一个可复算的源码级 view-boundary candidate：offset=`2^64-2048`、srcLen=4096、目标 Uint8Array byteOffset=4096/length=4096 时，长度检查回绕后通过，循环写 `[0x800,0x1800)`，其中 2048 字节在目标 view 前，但全在 8 KiB backing ArrayBuffer 内。开发初版的“循环写入仍在 view 内”结论已更正并经独立测试复核。Ark Runtime/JS PoC/build/profile 未执行，保持 `not_run`；产品适用性及影响保持 `unknown`。不把该源码候选升级为 backing-store OOB 或产品确认。

## 当前状态

| 任务 | 状态 | 结果 |
|---|---|---|
| C-DEV-SET-OFFSET-CONVERSION-20261020 | completed_with_correction | 初版转换结论成立；view 范围推论经 correction commit `28eb558` 更正 |
| C-TEST-SET-OFFSET-CONVERSION-20261020 | completed | 同一 scanner SHA/tree 独立复算确认 correction 算术；未运行 Ark Runtime |

## 收尾运行时构建尝试

随后启动了有界开发/独立测试子任务。开发线固定同一 scanner SHA 和 Ark source commit，在私有 WSL OverlayFS 输出目录中尝试 `rk3568 / ark_js_host_linux_tools_packages`；源码以只读绑定挂载，官方预编译包已核验哈希。构建在 HB `[LOAD] Checking all build args...` 等待 Kali/WSL 9p 读取时停滞，未启动 GN/Ninja/clang；为结束本轮，构建进程被显式 TERM 停止，返回码 1 不能解释为自然构建失败。

- 开发记录：`stage_20261020/C_LINE_ARK_RUNTIME_BUILD_ATTEMPT_20261020.md`（`5e2e92a1a`）
- 独立验收：`typedarray_set_offset_runtime_acceptance_addendum_20261020.md`（`429ee4d2a514061a36fe51a1fc296f316ae54b09`）
- 产物检查：没有 `ark_js_vm` 或 `es2abc`；候选 witness、offset 0 控制、offset 4097 RangeError 控制均 `not_run`
- 收尾状态：源码级 view-boundary candidate 保留；backing-store OOB、运行时行为和产品影响未确认。不要继续重复相同构建路线；仅在出现新的可用工具链/构建环境或其他具体证据后再开任务。

证据提交：开发 `194495c845240aab728e8480ac62c6a9dd488130`，更正 `28eb558366f8bf224ccdb593f67635e7dc07afae`，独立测试 `edf0cb0c48dce15f722b34caa167e82a88de3474`。下一切片应以新的 source/runtime/build 证据为触发点，避免重复审计已闭环的算术；当前 runtime 依赖缺失已记录，不作为本源码结论的阻塞项。
