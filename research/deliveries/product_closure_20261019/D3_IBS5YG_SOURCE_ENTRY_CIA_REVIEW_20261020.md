# IBS5YG D3 源码入口与影响边界审查（2026-10-20）

## 结论

审查对象是官方 Ark Runtime 的 IBS5YG parent/fix 源码对，范围仅为静态代码证据。parent 源码支持一个窄的 TypedArray Filter 越界写候选：若 callback 能在输出数组创建前为 Int32Array receiver 安装 constructor/species，且 species 返回长度恰为保留元素数的 Uint8Array，则 parent 的复制循环可能以源 Int32 类型向较窄目标写入。该机制在源码层可达，但目标产品是否包含 parent、实际优化 stub 是否运行、越界写能否在目标构建触及对象边界、攻击入口和安全影响均未证实；不构成产品漏洞结论。

## 候选入口与调用链

1. 候选入口是 `BuiltinsTypedArrayStubBuilder::Filter` 的 fast Filter 实现（parent 行 1414–1500）。它捕获 receiver 的 `arrayType`，逐项调用用户 callback，然后才通过 `NewTypedArray` 建立输出数组，再遍历保留项写入输出。
2. callback 在输出创建前执行 JavaScript。若它给 receiver 添加 `constructor`，`JSHClass::AddPropertyTransition` 设置 HClass 的 `HasConstructor` 标志；后续 `NewTypedArray` 检查可转入 `TypedArraySpeciesCreate` 慢路径。
3. `TypedArraySpeciesCreate` 要求结果是 TypedArray、长度至少为请求长度且 ContentType 一致；静态检查到的条件未要求元素类型一致。因此 Number ContentType 的 Int32Array receiver 可在候选情景中取得 Uint8Array species 结果。
4. parent Filter 复制时把捕获的源 `arrayType` 传给 `StoreTypedArrayElement`。调用链为 runtime stub `SetTypeArrayPropertyByIndex` → `JSTypedArray::FastSetPropertyByIndex` → `FastSetValueInBuffer`/`SetValueInBuffer`。后者按传入类型计算宽度/偏移并执行存储。固定提交改为从目标 `newArray` 的 HClass 读取类型后再写。

上述是代码路径分析，不证明该候选会通过具体版本的编译器优化、实际调度到该 fast stub，或目标二进制保留相同路径。

## 输入、触发与权限边界

- 候选输入：Int32Array receiver；Filter callback 对每个元素返回 truthy；callback 在执行中安装/改写 receiver 的 `constructor[Symbol.species]`；species 构造器返回 Uint8Array。
- 窄触发条件：species 返回长度恰等于 Filter 保留项数。示例保留 3 项，末项 index 2：源 Int32 宽度导致偏移 8、写入范围 `[8,12)`；目标 Uint8Array 逻辑 backing 长度为 3。所检查的 ByteArray 布局按 8 字节对齐后仍比该写入终点短 4 字节。返回更长的 species 结果可能避免该边界情景；它不是任意长度都成立的无条件结论。
- 权限边界：现有源码证明 callback 可执行用户 JavaScript、species 可调用构造器；没有证据证明目标产品中不可信脚本可到达此 API，也没有证据证明执行上下文、权限/隔离域或调用者身份。不得把“JavaScript 可控”扩展成“远程攻击者可控”。
- 入口状态：产品调用入口未知。没有产品 API、应用/组件调用链、脚本来源策略、IPC/权限配置或远程输入链证据。

## 敏感操作与 CIA 证据定位

| 操作/主张 | 静态证据位置 | 可支持结论与边界 |
|---|---|---|
| callback 后创建输出并复制元素 | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`, `Filter`, parent 行 1444–1500 | 用户 callback 与输出创建顺序、parent 源类型写回；不能证明实际产品运行路径 |
| species 接受跨元素类型结果 | `ecmascript/base/typed_array_helper.cpp`, `TypedArraySpeciesCreate`/`TypedArrayCreate`, 行 970–1055 | 类型类别、最小长度和 ContentType 检查；不能证明 callback/species 情景在产品中到达 |
| index 检查及按传入类型算偏移 | `ecmascript/js_typed_array.cpp`, `FastSetPropertyByIndex`, 行 713–748；`ecmascript/builtins/builtins_arraybuffer.cpp`, 行 711–769 | 候选写偏移与写宽度来源；缺少动态边界/ASan 验证 |
| TypedArray backing 与对象分配范围 | `ecmascript/base/typed_array_helper.cpp`, 行 194–235；`ecmascript/byte_array.h`, 行 30–72；`ecmascript/compiler/new_object_stub_builder.cpp`, 行 2555–2571 | 支持 n=3 的静态尺寸算术；实际对象布局、构建宏、分配路径仍需目标构建验证 |

CIA 评估：C（机密性）未知；I（完整性）源码机制提示可能的内存越界写候选，但对进程数据/控制流影响未知；A（可用性）可能受内存破坏影响但未复现，状态未知。没有可支持的产品级 CIA 结论、严重度或可利用性结论。

## 上游来源、产品适用性与不可证项

L2 记录的 parent `2ea501258ab4155826b64f01b499b43d1911e0e2` 与 fix `919e4fbb011f610427e788889083fa8e28d2f951` 的 commit/tree/blob/source SHA、parent ancestry 已与官方 Gitee API/Git 内容比对；fix PR !11196 合并。该核验确认上游源码身份与修复差异，不确认本地 bare store 的历史 custody，也不绑定任何产品。

以下仍不可证：目标 release/build、locked manifest 与 Ark Runtime component commit；GN target/action/args、compiler/linker/sysroot、include/generated-input closure、预处理 TU/macro log、最终 binary/image 映射；具体产品是否编入并执行候选 stub/helper 路径；回调触发时的真实优化/慢路径选择；实际 backing allocation 越界与 sanitizer 结果；不可信调用者/远程入口、权限边界和 CIA 影响；fixed 产品的同配置回归结果。L2 引用的 fixed regression `test/aottest/typedarrayfilter/typedarrayfilter.ts` 在 Filter 前改原型且只打印 `success`，不检查边界，也未运行，不能证明本窄 callback 内改 species 路径。

因此：上游 source-level candidate 可保留给第二层复核；产品适用性与安全影响继续 BLOCKED/UNKNOWN。不得将 Sort host-tools 产物或其他 case profile 作为 IBS5YG 产品证据。

## 可复算证据索引

- 本报告依据 `research/deliveries/product_closure_20261019/IBS5YG_L2_REVIEW_20261020.json`，SHA-256 `6cd30adf91bf4a46f67ee5a7bf8294af760e594cff09368db5d13b12829392a7`。
- L2 中 parent `builtins_typedarray_stub_builder.cpp` SHA-256：`847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422`；fixed 同文件 SHA-256：`8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e`。
- 关键依赖 SHA-256：`typed_array_helper.cpp` `0704698674d39389525de7ccca0941138fc0bb4a84d3acdf0f14544a119558a3`；`js_typed_array.cpp` `e0fa7cb24aae9e3da6ac0bf6ea06972c9419dda83a6647cf3e62d9595997342f`；`builtins_arraybuffer.cpp` `ccf5281e92af41022b25be409f7e69c5bb269a1ad2e32b4d01f9c73c57d42f08`；`byte_array.h` `d089cc14c93cd28f357b014b90d4a2a0797f1a5279de1714b20d6370e2d7e85b`；`new_object_stub_builder.cpp` `3fd7e99e957fb5b7793cb7c36c01b370208c05645aa93551da6abeecaf2e7198`。
- 当前 owner checkout 的任务树 `research/deliveries/product_closure_20261019/task_tree.json` SHA-256 `1861a62e864949e506ec935db8ecd1313fecefe4130995bcd72c66d2970fbb84`。它记录 PC-1 为 0/16 profile complete；个案画像仍需目标产品输入。

静态审查只读取现有材料；未运行 PoC、编译、测试或设备操作，未修改产品代码、计划或任务树。
