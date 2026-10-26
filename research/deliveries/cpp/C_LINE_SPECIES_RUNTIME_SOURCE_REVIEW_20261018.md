# C 线 TypedArray species 运行时源码复核（2026-10-18）

状态：**官方源码路径已复核；2026-10-19 补充了当前 C1 ARM32 目标构建与 QEMU 运行证据**。本记录不是漏洞确认；运行证据仅限所列 commit、目标对象和 VM，不代表完整产品镜像或设备。

## 对象与文件

产品配置候选及其 OpenHarmony manifest/runtime pin 见同目录 `C1_ARK_RUNTIME_BUILD_PROFILE_20261018.md`（runtime commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`）。本次阅读该 checkout 的：

| 路径 | 所见内容 |
|---|---|
| `openharmony/arkcompiler/ets_runtime/ecmascript/base/typed_array_helper.cpp`，`TypedArraySpeciesCreate` | 在 species protector 未失效、prototype accessor 未变、对象没有自定义 constructor 且传入单个参数为整数时，按 exemplar 的 TypedArray 类型执行快速分配；否则读取 constructor、执行 `SlowSpeciesConstructor` 并 `TypedArrayCreate`。随后检查结果与 exemplar 的 BigInt/Number `ContentType` 一致，不一致则抛 TypeError。 |
| `openharmony/arkcompiler/ets_runtime/ecmascript/base/tests/typed_array_helper_test.cpp`，`TypedArraySpeciesCreate` 单测 | 构造默认 Int16Array，并检查默认 species 创建长度为 6；不覆盖自定义 species、跨 Number TypedArray 类型或异常路径。 |
| `openharmony/arkcompiler/ets_runtime/test/moduletest/typedarray2/typedarray2.js`，`Test TypedArray species` | 检查 Int8Array/Uint8Array 的默认 `constructor[Symbol.species]`；不调用 Filter/CopyWithin/Set/With，也不验证 species 返回不同元素类型。 |

## 产品 pin 中的 Filter 源码反证

目标文件 `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` 的本地 SHA-256 为 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`，与 C1 manifest 记录一致；其 Git blob 为 `68fb3b0adc4f9062889a861be51b7be90362e37a`。在该精确目标源码的 `BuiltinsTypedArrayStubBuilder::Filter`（约 1542–1563 行），创建结果后先检查 `HasPendingException`，成功边才执行 `GetObjectType(LoadHClass(glue, newArray))`，随后将 `newArrayType` 传给 `StoreTypedArrayElement`。因此，历史 parent 中“从源类型 token 写入可能由 species 创建的目标数组”的候选模式没有出现在当前产品 pin 的 Filter 快速路径；这里读取的是目标新数组的实际 HClass 类型，且读取在异常检查之后。

该 stub 仅在快速 TypedArray、无自定义 constructor、species accessor 未改变等门控后进入；其他情况走 `slowPath`。C++ `BuiltinsTypedArray::Filter` 慢路径源码先调用 `TypedArrayHelper::TypedArraySpeciesCreate`，然后对结果执行 `FastSetPropertyByValue`。慢路径 helper 的当前 checkout 文本表现为：仅在 species protector 未失效、accessor 未改变、无自定义 constructor 且单参数为整数时按 exemplar 默认类型快分配；否则走 `SlowSpeciesConstructor`/`TypedArrayCreate`，并校验 Number/BigInt `ContentType`。该 helper 与 runtime sink 链的 C1 commit/blob 身份已由新增 31 项 source-only manifest 核对，详见下节；它仍不是产品构建依赖闭包证明。

## C1 pin 的跨文件 source binding 补充

新增 [C1 TypedArray sink binding manifest](C_LINE_C1_SINK_BINDING_20261019.json) 和只读重验脚本 `verify_c1_typedarray_sink_bindings.py`。它们固定 C1 runtime commit `a65a2853ccae13da167d9aa4720ab8b11ec16656` / tree `8781f036a3e7e04d8e0b34970d5f623b42875016`，对 sink/runtime 源链、根与 compiler BUILD 配置、`js_runtime_config.gni` 以及方法注册、继承、creator API、IR/TypedArray 类型声明共 33 个文件重算 Git blob SHA-1 和字节 SHA-256；当前 Git 对象和本地 checkout 均为 33/33 匹配，manifest 有相邻 SHA-256 sidecar。固定 `builtins_call_signature_list.h` 将 `CopyWithin`、`Filter`、`With` 和 `Set` 映射到 TypedArray stub IDs；目标头文件通过宏生成方法声明，且 `BuiltinsTypedArrayStubBuilder` 继承 `BuiltinsStubBuilder`。精确类型头文件给出 `GateRef`、`Label`/`Variable`、`DataViewType`、`JSTypedArray` 声明，creator 头文件声明 `NewTypedArraySameType`。这是源级声明与注册复核，没有观察编译器预处理展开、C++ 类型/重载解析或完整活动 include 闭包。

固定 C1 `ecmascript/compiler/BUILD.gn` 在 `libark_jsoptimizer_sources` 列入 TypedArray builder（第 86 行），`libark_jsoptimizer_set` 使用该列表（第 292–294 行），`ark_stub_compiler` 依赖该 source set（第 531–535 行）；同文件 `gen_stub_file` 调用 host `ark_stub_compiler` 并产生 `stub.an`（第 666–753 行）。根 `BUILD.gn` 的 `ark_js_packages` 声明将 `ecmascript/compiler:stub.an` 与 `:libark_jsruntime` 放入 package deps（第 93–101 行）；另将 `libark_jsoptimizer` 条件性加入 arm64、OHOS、非 clang 9.0.3 构建（第 109–115 行）。host-tools package 也有独立的 host-tool deps（第 159–169 行）。这些固定 GN 对象描述了源码到 stub artifact/package 的静态图路径及动态库条件；它们不解析条件结果，也不证明完整 HiHope 镜像包含该目标。2026-10-19 的隔离 C1 profile 后续补齐了 `product_ohos_arm32` 目标编译命令、Clang/宏/include、512 项 Ninja 依赖闭包和目标 `.o`；另有同 C1 runtime 源快照构建的 ARM32 `ark_js_vm` 在 QEMU 下运行。该 profile 的状态仍为 partial，完整产品镜像与设备运行未验证。精确构建及执行记录见 `research/experiments/ark_runtime/c1_product_gn_20261019/profile.json` 和 `runtime_behavior/runtime_behavior_record.json`。

在这组精确 C1 源码对象中，`NewObjectStubBuilder::NewTypedArray` 在回调后再次检查 species protector，失效时进入 `TypedArraySpeciesCreate`；`Filter` 成功检查 pending exception 后，从结果对象 HClass 取得 `newArrayType`，并以该 token 调用 `StoreTypedArrayElement`。该 store 检查结果数组索引范围，再把数组、索引、值和类型传给 `SetTypedArrayPropertyByIndex`；后续 runtime helper 按传入类型计算字节宽度。因此，C1 固定源码中，历史 parent 的源类型 token 已替换为结果类型 token，未见本次复核的类型宽度错配路径。隔离 C1 ARM32 目标对象及同源码 VM 后续已在 2026-10-19 构建/运行；其有限范围和未验证项见下方更新。

同一精确目标 blob 中其他方法的局部读法：

| 方法 | 目标/类型关系 | 当前 source/runtime 结论 |
|---|---|---|
| `CopyWithin` | 仅写回 `thisValue`，并以该对象的 `jsType` 调用 store；没有 species 结果对象。 | 当前 C1 QEMU 单方法控制未读取 species；历史版本与完整产品镜像未验证。 |
| `Filter` | species creator 可能返回目标类型不同的数组；成功 guard 后读取 `newArray` 的 HClass 类型，并用它写入。 | 当前 C1 VM 对 subclass `@@species` 有语义偏差 candidate；失效 protector 后会读取 species。编译 sink 用结果类型，未见类型宽度错配；无安全影响证据。 |
| `Set` | 写入接收者 `thisValue`；异类型 source 按 source HClass 读取，store 按 destination HClass 处理。 | 当前 C1 QEMU 单方法控制未读取 species；历史版本与完整产品镜像未验证。 |
| `With` | 调用 `NewTypedArraySameType`，异常 guard 后复制，再以来源 `jsType` 写入。 | 当前 C1 QEMU 单方法控制未读取 species，返回 intrinsic `Int8Array`；历史版本与完整产品镜像未验证。 |

这个结果是针对既定 historical candidate 的**当前目标源码反证**，不等于已证明整产品安全：构建是否包含该 blob、active defines/宏、实际运行时是否进入优化 stub、用户自定义 species 的行为、其他方法及其他历史版本都未动态验证。

本地 checkout 字节 SHA-256（用于该副本完整性复核；在相应 Git blob OID 复核完成前，不单独作为 commit 归属证明）：

| 路径 | SHA-256 |
|---|---|
| `ecmascript/base/typed_array_helper.cpp` | `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d` |
| `ecmascript/base/tests/typed_array_helper_test.cpp` | `ba7798bb753eebc2838cbc5d6bc3aa76aec1bab4270c4a28e24c272dbc3b714f` |
| `test/moduletest/typedarray2/typedarray2.js` | `65cc26c0cb5f9837d0baa35f97a1b4fdb8e060517a25629411e7b112db5716c6` |

因此，官方实现明确存在“默认类型快速路径”与“动态 species 构造路径”的分叉，并会拒绝 Number/BigInt ContentType 不一致；但这些源码和现有测试**没有证明**目标漏洞中的 store 类型选择、具体 TypedArray species 行为、产品构建是否启用该调用路径，也没有证明可达性或安全影响。

## 2026-10-19 C1 构建与运行结果

固定 runtime commit `a65a2853ccae13da167d9aa4720ab8b11ec16656` 的 ARM32 产品编译目标生成了 TypedArray builder `.o`（SHA-256 `865a1639c3f73f24f7235400228d0bd341930aa903231cd2c4ff21de25f220d5`，512 项 Ninja 依赖）；同一 C1 源快照构建的 `ark_js_vm`（SHA-256 `c6b51a8036fc40415da3c02a7bb1e1b732f9e7fe094fca33ce5f29ad19c9c4c5`）在 QEMU ARM32 下复现 subclass `@@species` 被 `Filter` 忽略。当前 C1 运行时是 **candidate semantic divergence**。同进程 protector 扰动控制显示，定义 `%TypedArray%[Symbol.species]` 后 getter 被调用且结果转为 `Uint16Array`，支持 fast-path/protector 根因；独立 callback/Set/CopyWithin/With 控制均有隔离结果。证据仍不等于完整产品镜像或设备执行。

**产品安全结论评估：不提升为产品安全漏洞。** 现有编译 AST 显示当前 C1 `Filter` 在异常 guard 后读取结果数组 HClass 类型并将其传入 store；运行时观察到的是 subclass species 结果类型不符合预期的 API 语义偏差，没有观察到越界、类型宽度错配、内存破坏、权限边界绕过或其他安全影响。没有把 JS/Ark VM 的可执行输入等同于真实产品入口/攻击者控制证明。历史 parent/fix 仍未在对应构建配置下编译运行，完整产品镜像、设备入口与影响范围仍未知。

## 仍未验证的运行时范围

2026-10-18 初稿时没有可用的 `out` 构建产物，故当时运行状态记为 unknown。后续隔离 C1 构建补充了当前目标编译和 QEMU VM 运行证据；它不提供历史 parent/fix 的 `args.gn`/编译命令，也不提供完整设备镜像，因此不能回填历史配置或取代产品入口验证。

已新增可移植的行为控制脚本 `research/deliveries/cpp/typedarray_species_behavior_control.js`（SHA-256 `e48a8ee209f3fa90cc0aa51a8c2c1b440d625a00232975a67b81d17695299e0e`）。该脚本在参考 Node `v22.14.0` 上通过，stdout 为 `{"engine":"v22.14.0","status":"passed","controls":["default_filter_same_type","filter_cross_number_type","number_bigint_content_type_rejected","species_error_propagation_and_prior_callback_effects","callback_changes_own_species_before_result_creation","shared_typedarray_species_mutation_observed:Uint8Array","set_copywithin_with_no_species_lookup"],"source_specific_mutation_observation":"Uint8Array"}`。共享 `%TypedArray%` species mutation 控制会断言结果类型为 `Uint8Array`、值为 `[0x34]`，并断言回调恰好执行一次。七项控制覆盖默认类型、跨 Number 类型 species、Number/BigInt 拒绝、异常与回调副作用、回调中修改 own species、回调中修改共享 `%TypedArray%` constructor species，以及 Set/CopyWithin/With 不访问 `@@species`。这是 ECMAScript 参考行为控制，**不计入 Ark Runtime 产品运行证据**。

拿到同一 manifest build 的可执行文件与启动/测试命令后，应在该 build 上重新运行上述脚本并补充以下**行为控制**，记录完整 stdout/退出码和 binary/source pin：

1. 默认 `Int8Array.prototype.filter`：结果构造器及元素类型保持默认行为。
2. 自定义 `Symbol.species` 返回 `Uint16Array`：验证结果类型、逐元素写入值及是否触发异常；分别执行 Filter、CopyWithin、Set、With 的可适用场景。
3. BigInt/Number ContentType 不兼容 species：验证抛出 TypeError。
4. species getter/constructor 重入并抛异常：验证异常传播、部分副作用和任何后续类型读取/写入顺序。
5. 原型 species accessor 未变、变更后恢复、以及自定义 constructor 的对照，覆盖 protector 快速/慢速分支。

对照的期望须以此 pin 的 Ark Runtime 规范实现及独立代码评审确定；仅出现 TypeError 或结果类型不同不自动构成漏洞。随后还需将触发路径绑定到产品入口/攻击者输入，证明影响并评估安全后果。

## 当前结论

- 固定产品目标源码：Filter 当前目标 blob 与 pin 一致，source-level 写入使用 creator 结果的 HClass 类型；未复现历史 candidate 的 source-token 写入模式。慢路径依赖闭包仍未完整绑定。
- 当前 C1 实际运行：QEMU 范围观察到 species 语义 candidate；完整产品镜像/设备与应用入口仍未验证。
- 历史 parent/fix 实际运行：`unknown`；没有对应构建配置和 runtime 对照。
- 产品安全漏洞与影响：不支持升级；未观察到安全影响，也没有入口/攻击者控制证据。
- Public Runner admission：继续 `blocked`，`execution_enabled=false`。
