# TypedArray.set 超大 offset 转换与 view-boundary 独立复验

日期：2026-10-20（Asia/Shanghai）  
用途：独立挑战开发线关于 `TypedArray.set(arrayLike, offset)` 超大 offset 的可达性、整数回绕和后续写循环结论。仅新增本报告；不改 scanner 或 Ark 生产代码。

## 结论

- `targetOffset = 2^64 - 2048` 可由 binary64 精确表示。固定源码中的 `ToInteger → TruncateDouble` 保留该有限整数，后续 `double → uint64_t` 转换在该值上有定义。因此 offset 转换是 **reachable（源码级）**。
- 开发线更正报告里的非零 `targetByteOffset` 算例经独立复算成立。它证明长度检查可在 `uint64_t` 回绕后通过，且 array-like 写循环可写到目标 TypedArray view 起点之前的同一 backing buffer 区域；该算例不证明写越过 backing ArrayBuffer 边界。
- 最初开发报告关于“只要循环执行，索引就已经处于目标 TypedArray view 范围内”的概括被更正报告中的非零 byteOffset 算例反例推翻。更正 commit `28eb558366f8bf224ccdb593f67635e7dc07afae` 已补入算例。独立复验未发现该算例的算术错误。
- Ark Runtime/JS PoC 未运行；产品 build/profile、产品入口可达性及影响仍为 **not_run / unknown**。保留源码级 **candidate**，不升格为产品确认或内存越界结论。

## 基线与来源身份

OHScanner 目标代码基线：

- 仓库：`D:\openHarmonyScanner\worktrees\c-mainline-test-closeout-20261020`
- 被测代码 commit：`4e1268a980fd103326c7dbaa6ca2e78d2ba43e69`
- 被测代码 tree：`0495b0db7d05f02e2ce4e48149f7571c8bdd8023`
- `4e` 中 `src/ohscanner/detectors/ark_runtime/arraylike_set_bounds.py`：Git blob `4f48c90ee516227d7f0818e8f95dfa47ffb2c071`
- `4e` 中 `src/ohscanner/detectors/ark_runtime/model.py`：Git blob `8cf730b595377c25eca041b1762a1a744b59d1c9`
- 当前测试分支 HEAD 为 `0b7ab8baf1e09e151dd88a0694da62cb49e1f906`；执行 `git diff --exit-code 4e... HEAD -- src/ohscanner tests` 返回 0，证明当前分支的 scanner 与 tests 树和目标 SHA `4e` 一致。该测试分支已有报告提交不纳入被测代码树。

Ark 源基线：

- 仓库：`openharmony/arkcompiler_ets_runtime`；本地 checkout 路径 `D:\openHarmonyScanner\openharmony\arkcompiler\ets_runtime`
- `.git/HEAD` 内容：`a65a2853ccae13da167d9aa4720ab8b11ec16656`
- 目标 OHScanner 模型在该 commit 上固定的文件 blob 与 SHA-256：

| 文件 | Git blob | SHA-256 |
|---|---|---|
| `ecmascript/builtins/builtins_typedarray.cpp` | `0fc27c213e1ea80d93e1e3807eec11baf2634832` | `14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c` |
| `ecmascript/builtins/builtins_arraybuffer.cpp` | `2aa22c58803df690a5a2b326451e02297dc5e2f6` | `4d388d997313cf7c900f1f0d54fbe826266845665424e32cc9dd4cdbaa62dcc9` |
| `ecmascript/builtins/builtins_typedarray.h` | `b291181c949c7038b7030a216f5bdc0e7474a1c2` | `651d426c00c1d8bc6503c1d717decf42b28c61c57336e9418ad422604a6a1be7` |

| 转换语义依赖文件 | 当前 checkout 计算的 Git blob | SHA-256 |
|---|---|---|
| `ecmascript/js_tagged_value.cpp` | `cc2900c2a5a2fdec4321d6f1f619cf2f2f8dbf4d` | `22ad153b0e5a3a9fa4ea45fc0b5feed83504f124684d44c67dffe39d057e53a4` |
| `ecmascript/base/number_helper.cpp` | `afc0ad3513725bf6606256755cb37285f4b97aa8` | `bd0ec62661f7f75236204d4fd3b11874c43981cb8e20245cdb8db45adc076634` |

SHA-256 按本地文件原始字节计算；Git blob OID 按 `SHA1("blob <length>\0" + bytes)` 计算。Ark checkout 的 `.git/config` 和 `.git/objects` 在当前 Windows 环境不可访问，所以无法独立取得 Ark tree OID、验证 checkout clean 状态或用本地对象库确认所有非模型绑定文件；公开远端 fetch 本轮也因 GitHub 443 连接失败未完成。报告因此记录可读的 commit 标识及各相关文件的 blob/SHA-256，并将 Ark tree/clean 状态保留为未知，不声称其已独立验证。

## 源码调用链

1. 固定源码 `builtins_typedarray.cpp:1156-1179` 对非 tagged-int offset 调 `JSTaggedValue::ToInteger`，拒绝小于 0 与正无穷，然后将 `rawTargetOffset` 转为 `uint64_t`。
2. `js_tagged_value.cpp:204-210` 的 `ToInteger` 调 `ToNumber` 后返回 `NumberHelper::TruncateDouble` 结果。`number_helper.cpp:804-820` 对有限非零值按符号调用 `floor`/`ceil`；此处不先转 `int64_t`。`2^64 - 2048` 保持不变；NaN 转 0；无穷保持无穷，正无穷被调用点拒绝，负无穷因小于 0 被拒绝。
3. array-like 分支 `builtins_typedarray.cpp:1223-1276` 将 `ToLength` 结果转为 `uint64_t`，以 `srcLen + targetOffset > targetLength` 检查长度，之后计算并窄化 byte index 与 `limit`，再以 `targetByteIndex < limit` 驱动写循环。
4. `builtins_arraybuffer.cpp` 中 `SetValueInBuffer` 取得 backing buffer 的数据指针并把 byte index 传给底层写路径；本次算例的地址落在 backing buffer 内，但部分地址在 TypedArray view 范围外。

## 独立复算：非零 byteOffset 见证

取 `x = 2^64 - 2048 = 0xfffffffffffff800`，构造 8192-byte backing buffer、byteOffset 为 4096、length 为 4096 的 Uint8Array；array-like source 的 length 为 4096，并提供可读索引 `0..4095`。这些值仅描述源码级输入，不曾提交给 Ark VM。

```js
const backing = new ArrayBuffer(8192);
const sibling = new Uint8Array(backing, 0, 4096);
const target = new Uint8Array(backing, 4096, 4096);
const source = { length: 4096 /* 且提供索引 0..4095 */ };
target.set(source, 18446744073709549568);
```

按源码整数宽度逐步计算：

1. `ToInteger(x)` 保留 `x`，且 `x < UINT64_MAX`，所以 `uint64_t(x) = x`。
2. `srcLen + targetOffset = 4096 + (2^64 - 2048) ≡ 2048 (mod 2^64)`。`targetLength=4096`，所以长度条件 `2048 > 4096` 为假。
3. 第一项 ASSERT 与 byte index 赋值使用相同 uint64 乘加。`(x * 1 + 4096) mod 2^64 = 2048`，故 ASSERT 检查 `2048 <= UINT32_MAX` 通过，窄化后 `targetByteIndex = 0x0800`。
4. 第二项 ASSERT 检查 `1 * 4096 + 2048 = 6144 <= UINT32_MAX`，通过；`limit = uint32(2048 + 4096) = 6144 = 0x1800`。
5. 循环从 `0x0800` 到 `0x17ff` 写 4096 个 Uint8 元素。目标 view 覆盖 backing 偏移 `[0x1000,0x2000)`；前 2048 个写地址 `[0x0800,0x1000)` 落在目标 view 之前，并落在 `sibling` 的索引 `[2048,4096)`。全部写地址仍位于 8192-byte backing buffer `[0,0x2000)`。

因此该见证不要求关闭 `ASSERT`；与零 byteOffset 的边界算例不同，第一项 ASSERT 的 uint64 无符号乘加自身回绕到 2048。写入越过目标 TypedArray view 边界，但没有越过 ArrayBuffer backing 边界。视图外写能否在目标产品配置中按此源码执行仍需 runtime/build 复验。

## 微型算术核对

在系统临时目录运行 Python 3，使用 binary64 `math.nextafter` 找到 `2^64` 前一个浮点值，并用整数模运算复算 uint64/uint32 结果。结果为：

```text
offset_double=18446744073709549568
offset_integer=18446744073709549568
2^64_as_double=18446744073709551616
src_len=4294968320 (ToLength cap=9007199254740991)
(offset + src_len) mod 2^64=4294966272; target_length=4294967295; range_guard=False
target_byte_index_uint32=4294965248; limit_uint32=4294966272; loop_iterations=1024
last_written_byte_index=4294966271; backing_byte_length=4294967295; in_bounds=True
```

这组零 byteOffset 算例用于核对宽整数与窄化算术；它需要近 4 GiB 目标且第一项 ASSERT 不通过，不作为可运行见证。非零 byteOffset 算例才是能通过两项 ASSERT、并跨出目标 view 的源码级见证。Python 微型检查不是 C++ 编译器证明，也不代表 Ark Runtime 执行。

对非零 byteOffset 见证的独立 Python 复算输出：

```text
x=18446744073709549568; srcLen=4096; uint64_sum=2048; guard=False
assert1_uint64_add=2048; targetByteIndex=0x0800
assert2_uint64_sum=6144; limit=0x1800; iterations=4096
write_range=[0x0800,0x1800); view=[0x1000,0x2000); backing=[0,0x2000)
before_view_bytes=2048; backing_oob=False
```

## 对开发线结果的独立审阅

- 认可开发报告关于 `ToInteger` 保留该 offset，以及 uint64 长度和后续 uint32 byte-index 运算的基本追踪。
- 原开发报告中“若循环区间越过 uint32 尾部，元素索引也已位于足够大的目标 TypedArray 范围内”的推断忽略了非零 `targetByteOffset`。开发线 correction `typedarray_set_offset_conversion_correction_20261020.md` 与提交 `28eb558366f8bf224ccdb593f67635e7dc07afae` 修正该点；本报告独立复算确认其新见证的整数、ASSERT、循环区间与 view/backing 区分均成立。
- 当前证据支持 view-boundary 写入 **candidate**；本算例不支持 backing-store OOB。没有实际运行 Ark VM、构建目标 runtime 或验证产品入口，因此 runtime 保持 **not_run**，产品适用性/影响保持 **unknown**。

## 状态与限制

- offset 转换与 array-like 的 view 前置写：**reachable / candidate，source-level only**。
- backing ArrayBuffer 边界越界：**本算例不支持；未穷尽其他形状**。
- binary64 和整数窄化算术：**Python micro-check performed**。
- Ark Runtime 执行、Ark JS PoC、目标 build/profile：**not_run**。
- 产品部署、产品入口可达性和影响：**unknown**。
- 未运行 scanner 测试或 Ark Runtime 测试；本轮产物为固定 SHA 的源码复核与算术微检。
