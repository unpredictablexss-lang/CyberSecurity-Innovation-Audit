# IBS5YG 第二层静态候选审查（2026-10-20）

## 范围与结论

只读审查已固定的官方 Ark Runtime parent `2ea501258ab4155826b64f01b499b43d1911e0e2` 与 fixed `919e4fbb011f610427e788889083fa8e28d2f951` 源码，以及 fixed 回归输入。未编译、未运行测试或 PoC。候选为有明确边界条件的静态越界写机制；运行时可达性与产品适用性仍未证明。

| 层次 | 判断 | 依据与限制 |
|---|---|---|
| Source mechanism | **支持，窄条件候选** | parent `Filter` 在回调后构造结果；species 创建接受长度至少为请求长度且 ContentType 相同的 TypedArray，不要求相同元素类型。复制循环却将源 `arrayType` 传给写入。三元素 `Int32Array` 过滤结果若由 species 返回恰好 `Uint8Array(3)`，末项按 Int32 宽度写入相对 byte offset 8 的 `[8,12)`。对应 3 字节 ByteArray 的数据区后，8 字节对齐对象总长为 24 字节（数据起点偏移 16）；该写范围越过对象末端 4 字节。源码路径中可见的 detached/index 检查未按目标元素宽度校验字节范围。 |
| Runtime reachability | **未知** | 需要证明目标构建实际生成并执行此 fast `Filter` stub，回调造成的自有 `constructor`/species 变更能进入该 helper/store 序列，且实际分配布局与该内联 ByteArray 路径相同。仅有静态控制流和源码算术，不足以证明运行时越界。 |
| Product applicability | **阻塞 / 未知** | 没有目标产品版本、组件绑定、构建配置/预处理 TU 或 shipped binary 映射；攻击者入口、触发控制和安全影响也未建立。不得据此给出产品漏洞或严重性结论。 |

## 反例优先核查

- **元素类型约束**：species 返回值必须是有效 TypedArray；ContentType 必须一致。`Int32Array`→`Uint8Array` 都是 Number ContentType，满足该检查；`BigInt64Array`→数值数组会被 ContentType 检查拒绝。因此候选只覆盖同 ContentType、不同元素宽度的组合。
- **结果长度**：`TypedArrayCreate` 对单个 Number 参数仅要求返回数组长度 `>= requested`。恰好长度 3 是窄候选；若返回 `Uint8Array(m)`，末个源类型写入结束于偏移 12，只有当该目标 backing storage 小于 12 字节时才越过逻辑数据区。足够长的结果（例如 `m>=12`）会反驳此具体越界实例，但不自动排除其他长度/类型组合。
- **写入边界**：`FastSetPropertyByIndex` 的 index 上界使用目标数组长度，但 element size 与 store type 来自传入 `jsType`；随后 `FastSetValueInBuffer` 做 detached 检查并按该 type 写入，没有显式传入 backing byte length。这个调用链支持候选，但静态查看单一 helper 仍不能排除更上层未审阅的保护或不同实际 dispatch。
- **分配及对齐**：目标恰为 `Uint8Array(3)` 时，ByteArray 的数据长度为 3，分配按对象对齐 8 字节。数据起点是对象内偏移 16；有效对象末尾为偏移 24。Int32 第三个元素的写范围对应对象绝对偏移 `[24,28)`。这不是靠“allocator 可能有 padding”推断；如果目标不是该 on-heap ByteArray 分配分支，以上对象边界计算不适用，须按实际 allocator/buffer 单独验证。
- **回调及 species**：parent `Filter` 入场时先检查 `HasConstructor`，之后才调用用户 callback，回调完成后才执行 `NewTypedArray`。所以静态候选要求回调期间给接收者安装 constructor/species；在调用 `Filter` 前已安装 constructor 的场景会被入口检查送往 slow path，不等同于该 fast-stub候选。

## Fixed callsite / test 对照

fixed 实现从已分配的 `newArray` HClass 读取 `newArrayType`，并将其用于每次 `StoreTypedArrayElement`；parent 则传源 `arrayType`。这直接修正了跨类型结果的写入类型来源。

官方 fixed 测试 `test/aottest/typedarrayfilter/typedarrayfilter.ts` 在调用 `Filter` **之前**将 `Float32Array(3924)` 的 `__proto__` 改成 `Uint8ClampedArray(3594)` 实例，然后执行 `a.filter(Array, a)`，最后只打印 `success`。它没有断言结果类型、长度、值、边界或 sanitizer 结果，也没有证明执行候选所需的 callback 内 constructor 变更序列，更没有识别实际 Filter stub。预先改 prototype 可能令入场 guard 选择慢路径。因此该测试是相关的跨类型 species 回归输入，不是 parent 越界的动态证明，也不能作为精确候选 fast-path 的可达性证据。

## 可推翻候选的反证

以下任一项若以同一 parent 源身份和目标执行路径证实，都将推翻或实质收窄本候选：

1. 完整 guard/control-flow 证明 callback 后不可能修改接收者 constructor/species，或这种修改必定退出当前 fast stub、使复制循环不执行。
2. 同一 `NewTypedArray` 路径实际强制结果元素类型与源一致，或某个已遗漏的校验拒绝 Number ContentType 内的跨类型 species。
3. 目标 `FastSetValueInBuffer` 或其实际下游对 computed byte range 做有效的目标 backing-store 边界检查，且失败时不会写内存。
4. 对选定 3→3 例，在精确 parent build/dispatch 中证实分配容量至少 28 字节（对象起始计）或写入实际使用 Uint8 宽度/被拦截；需留存构建身份、路径和可复核运行证据。
5. 同产品精确源/构建映射证明该 parent stub/helper 未包含、不可调用，或部署版本已含等效 fixed 修复。这会推翻产品适用性，但不推翻历史 parent 的静态机制。

## 审查边界

本报告复核了既有 IBS5YG 静态候选，不验证外部对象获取链、不重新构建官方仓库，也不评估产品攻击面。源码来源、commit 与固定测试身份见同目录 `research/deliveries/product_closure_20261019/IBS5YG_L2_REVIEW_20261020.json` 中记录；本报告仅将机制结论表述为 source-level candidate。
