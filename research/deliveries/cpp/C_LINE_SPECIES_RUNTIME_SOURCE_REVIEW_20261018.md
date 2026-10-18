# C 线 TypedArray species 运行时源码复核（2026-10-18）

状态：**实现路径已从官方源码复核；实际运行时结果仍 unknown**。本记录不是漏洞确认，也没有把源代码预期冒充为执行结果。

## 对象与文件

产品配置候选及其 OpenHarmony manifest/runtime pin 见同目录 `C1_ARK_RUNTIME_BUILD_PROFILE_20261018.md`（runtime commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`）。本次阅读该 checkout 的：

| 路径 | 所见内容 |
|---|---|
| `openharmony/arkcompiler/ets_runtime/ecmascript/base/typed_array_helper.cpp`，`TypedArraySpeciesCreate` | 在 species protector 未失效、prototype accessor 未变、对象没有自定义 constructor 且传入单个参数为整数时，按 exemplar 的 TypedArray 类型执行快速分配；否则读取 constructor、执行 `SlowSpeciesConstructor` 并 `TypedArrayCreate`。随后检查结果与 exemplar 的 BigInt/Number `ContentType` 一致，不一致则抛 TypeError。 |
| `openharmony/arkcompiler/ets_runtime/ecmascript/base/tests/typed_array_helper_test.cpp`，`TypedArraySpeciesCreate` 单测 | 构造默认 Int16Array，并检查默认 species 创建长度为 6；不覆盖自定义 species、跨 Number TypedArray 类型或异常路径。 |
| `openharmony/arkcompiler/ets_runtime/test/moduletest/typedarray2/typedarray2.js`，`Test TypedArray species` | 检查 Int8Array/Uint8Array 的默认 `constructor[Symbol.species]`；不调用 Filter/CopyWithin/Set/With，也不验证 species 返回不同元素类型。 |

## 产品 pin 中的 Filter 源码反证

目标文件 `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` 的本地 SHA-256 为 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`，与 C1 manifest 记录一致；其 Git blob 为 `68fb3b0adc4f9062889a861be51b7be90362e37a`。在该精确目标源码的 `BuiltinsTypedArrayStubBuilder::Filter`（约 1542–1563 行），创建结果后先检查 `HasPendingException`，成功边才执行 `GetObjectType(LoadHClass(glue, newArray))`，随后将 `newArrayType` 传给 `StoreTypedArrayElement`。因此，历史 parent 中“从源类型 token 写入可能由 species 创建的目标数组”的候选模式没有出现在当前产品 pin 的 Filter 快速路径；这里读取的是目标新数组的实际 HClass 类型，且读取在异常检查之后。

该 stub 仅在快速 TypedArray、无自定义 constructor、species accessor 未改变等门控后进入；其他情况走 `slowPath`。C++ `BuiltinsTypedArray::Filter` 慢路径源码先调用 `TypedArrayHelper::TypedArraySpeciesCreate`，然后对结果执行 `FastSetPropertyByValue`。慢路径 helper 的当前 checkout 文本表现为：仅在 species protector 未失效、accessor 未改变、无自定义 constructor 且单参数为整数时按 exemplar 默认类型快分配；否则走 `SlowSpeciesConstructor`/`TypedArrayCreate`，并校验 Number/BigInt `ContentType`。慢路径文件尚未以其自身 blob OID 绑定到 C1 build，因此上述描述是 checkout 源码证据，不能单独当作该产品构建的完整闭包。

同一精确目标 blob 中其他方法的局部读法：

| 方法 | 目标/类型关系 | 当前 source-level 结论 |
|---|---|---|
| `CopyWithin` | 仅写回 `thisValue`，并以该对象的 `jsType` 调用 store；没有 species 结果对象。 | 未见历史 Filter 型 source/destination identity 分离；构建与运行未验证。 |
| `Filter` | species creator 可能返回目标类型不同的数组；成功 guard 后读取 `newArray` 的 HClass 类型，并用它写入。 | 未复现历史候选模式；最直接 source-level 反证。 |
| `Set` | 写入接收者 `thisValue`；异类型 source 按 source HClass 读取，store 按 destination HClass 处理。 | 源、目标类型显式分开；未见由 species 创建目标的路径。 |
| `With` | 调用 `NewTypedArraySameType`，异常 guard 后复制，再以来源 `jsType` 写入。 | 声明了 same-type creator 关系；creator 实际语义、宏及动态行为未在产品构建中复核。 |

这个结果是针对既定 historical candidate 的**当前目标源码反证**，不等于已证明整产品安全：构建是否包含该 blob、active defines/宏、实际运行时是否进入优化 stub、用户自定义 species 的行为、其他方法及其他历史版本都未动态验证。

本地 checkout 字节 SHA-256（用于该副本完整性复核；在相应 Git blob OID 复核完成前，不单独作为 commit 归属证明）：

| 路径 | SHA-256 |
|---|---|
| `ecmascript/base/typed_array_helper.cpp` | `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d` |
| `ecmascript/base/tests/typed_array_helper_test.cpp` | `ba7798bb753eebc2838cbc5d6bc3aa76aec1bab4270c4a28e24c272dbc3b714f` |
| `test/moduletest/typedarray2/typedarray2.js` | `65cc26c0cb5f9837d0baa35f97a1b4fdb8e060517a25629411e7b112db5716c6` |

因此，官方实现明确存在“默认类型快速路径”与“动态 species 构造路径”的分叉，并会拒绝 Number/BigInt ContentType 不一致；但这些源码和现有测试**没有证明**目标漏洞中的 store 类型选择、具体 TypedArray species 行为、产品构建是否启用该调用路径，也没有证明可达性或安全影响。

## 可复现的运行时验证仍缺什么

当前 checkout 没有可用的 `out` 构建产物或可定位的 Ark runtime 可执行文件；本轮没有成功编译或执行 JS 测试。产品构建复核记录也缺少匹配该 manifest 的原始 compile command、`args.gn`、宏/头文件闭包和工具链 provenance，故不能以开发机自行构建替代产品构建证据。

已新增可移植的行为控制脚本 `research/deliveries/cpp/typedarray_species_behavior_control.js`（SHA-256 `ffe045c4fa7f6250eed2cf875df875181139e80d15b8245707880cc19a10da0f`）。该脚本在参考 Node `v22.14.0` 上通过，stdout 为 `{"engine":"v22.14.0","status":"passed","controls":["default_filter_same_type","filter_cross_number_type","number_bigint_content_type_rejected","species_error_propagation_and_prior_callback_effects","set_copywithin_with_no_species_lookup"]}`。五组断言覆盖默认同类型、合法 Number 元素类型转换、Number/BigInt 拒绝、species 构造错误与回调副作用顺序，以及 Set/CopyWithin/With 不访问 `@@species`。这是 ECMAScript 参考行为控制，**不计入 Ark Runtime 产品运行证据**。

拿到同一 manifest build 的可执行文件与启动/测试命令后，应在该 build 上重新运行上述脚本并补充以下**行为控制**，记录完整 stdout/退出码和 binary/source pin：

1. 默认 `Int8Array.prototype.filter`：结果构造器及元素类型保持默认行为。
2. 自定义 `Symbol.species` 返回 `Uint16Array`：验证结果类型、逐元素写入值及是否触发异常；分别执行 Filter、CopyWithin、Set、With 的可适用场景。
3. BigInt/Number ContentType 不兼容 species：验证抛出 TypeError。
4. species getter/constructor 重入并抛异常：验证异常传播、部分副作用和任何后续类型读取/写入顺序。
5. 原型 species accessor 未变、变更后恢复、以及自定义 constructor 的对照，覆盖 protector 快速/慢速分支。

对照的期望须以此 pin 的 Ark Runtime 规范实现及独立代码评审确定；仅出现 TypeError 或结果类型不同不自动构成漏洞。随后还需将触发路径绑定到产品入口/攻击者输入，证明影响并评估安全后果。

## 当前结论

- 固定产品目标源码：Filter 当前目标 blob 与 pin 一致，source-level 写入使用 creator 结果的 HClass 类型；未复现历史 candidate 的 source-token 写入模式。慢路径依赖闭包仍未完整绑定。
- 实际运行：`unknown`，没有产品二进制或本地执行结果。
- 漏洞与影响：未确认；无入口、攻击者控制及安全后果证据。
- Public Runner admission：继续 `blocked`，`execution_enabled=false`。
