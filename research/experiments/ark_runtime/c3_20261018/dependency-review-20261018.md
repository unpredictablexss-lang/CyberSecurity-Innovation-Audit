# C3 模型依赖语义复核（2026-10-18）

## 结论

C3 快照 `openharmony/arkcompiler_ets_runtime@a65a2853ccae13da167d9aa4720ab8b11ec16656` 的 19 条模型依赖中，18 条内容改变，1 条 `profiler_operation.h` blob 未变。对照旧模型提交 `a0e30483ab3e4aead67ecfb5c708489915e447f9`（异常路径依赖另见 `c758818dbfd0b146a908d43d21f6ca1706c33783`、`81ca57487d04ea30cd11c271e86494a4e130f43e`），逐对确认了 commit:path 的实际 blob，并检查了文件级函数上下文差异。

多处变化落在模型依赖的语义边界：类型/对象谓词、IR 加载和分支包装、循环/异常控制流、TypedArray creator 与 allocation、wrapper 及 caller/sink。旧、新源码不能按文本相似推为等价。表内改变的依赖均保持 `unknown/blocked`。未确认漏洞，也不把旧结论迁移到新快照。

## 身份和重放边界

| 项 | 固定值 |
|---|---|
| 新源码仓库 / commit / tree | `openharmony/arkcompiler_ets_runtime` / `a65a2853ccae13da167d9aa4720ab8b11ec16656` / `8781f036a3e7e04d8e0b34970d5f623b42875016` |
| C3 snapshot SHA-256 | `7f1c19c5ba21a311fba7f018df8fff077c6c9a60ee81c3ce348bb5b0a9f017d2` |
| 新目标文件 | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` / blob `68fb3b0adc4f9062889a861be51b7be90362e37a` / SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c` |
| 旧 effect/type 依赖版本 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` |
| 旧 exception guard 依赖版本 | `c758818dbfd0b146a908d43d21f6ca1706c33783`、`81ca57487d04ea30cd11c271e86494a4e130f43e` |
| C3 比较清单 SHA-256 | `c920f31bc6fe4c05d0d64b210b26dacc8b01d277aeb86ca552ddf52ce83f8d2d` (`model_dependency_comparison.json`) |
| Detector model | `0.6.3`; `RuntimeTypeModel.digest` = `79e69842146939fd1d278b10165bc4b1c468cf26676b56c04eaf09bf9c7f82e6` |
| C3 admission | blocked; model digest includes the exact C3 manifest digest and blocked-snapshot state |

旧 commit IDs 在复核前不在本地 component object store。按用户要求，从该组件配置的 GitHub mirror fetch 了四个精确 commit（未更新分支）；gitcode remote 本次 fetch 因远端响应格式失败。随后所有表列的 old/new `commit:path` blob 均与比较清单中的 SHA-1 一致。历史 C1 parent/fix Runner 重放和 exception guard parent/fix 测试在获取对象后运行通过；这只证明已有历史绑定能重放，不代表 `a65a…` 依赖已获语义准入。

## 19 条依赖差异表

所有新端都固定为 `a65a2853ccae13da167d9aa4720ab8b11ec16656:<path>`。`unknown/blocked` 表示保留源码差异事实，但没有把其含义缩减为与旧规则等价；它不表示安全或漏洞已确认。第 18、19 行是同一路径/blob 在两个独立 exception-guard commits 下的两个模型依赖，按原比较清单保留为两行。

| # / kind | 旧 commit:path @ blob → 新 commit:path @ blob | 检查到的代码区间 / 符号 | 对规则前提的判断 |
|---|---|---|---|
| 1 effect | `a0e30483…447f9:ecmascript/compiler/stub_builder.h` @ `b784eb08…a6a9cd` → `a65a2853…16656` @ `9e2fbd3e…944515` | `StubBuilder` IR wrapper declarations；`LoopOptions`、`IR_WHILE`、`IR_BREAK`/`IR_CONTINUE`（函数上下文 diff 新区间约 126–1666） | 循环及控制流构造 API 有新增/改动；effect 与 dominance 假设需按调用点重审。**unknown/blocked** |
| 2 effect | `a0e30483…447f9:ecmascript/compiler/stub_builder-inl.h` @ `8658e6ee…42abd0` → `a65a2853…16656` @ `c0521ab7…95373c` | `Alloca`、`Return`、`Bind`、`CallRuntime`、`CallStub` 和 typed predicate wrappers（新 hunk 60–1006） | wrapper 的参数/实现差异可能改变调用效果和值身份传播；不由名字相同证明纯度。**unknown/blocked** |
| 3 effect | `a0e30483…447f9:ecmascript/compiler/stub_builder.cpp` @ `8aae4bfa…5151c2` → `a65a2853…16656` @ `c630a620…8e6c4` | `Jump`、`Branch`、`LoopBegin`、`CheckSuspend`、`LoopEnd`（新 hunk 55、83、148、186、222）；循环 safepoint/control flow | 生成图边与循环/挂起点语义改变，可能改变异常路径和 sink 可达性。**unknown/blocked** |
| 4 effect | `a0e30483…447f9:ecmascript/compiler/hcr_circuit_builder.h` @ `176dd0a5…6380d` → `a65a2853…16656` @ `e66c414a…68cd11` | `CircuitBuilder::IsSpecial`、`IsJSHClass`（新 commit 行 25–37） | 类型 predicate 所读值、入参和 IR 生成语义不能据符号名推定相同。**unknown/blocked** |
| 5 effect | `a0e30483…447f9:ecmascript/compiler/mcr_circuit_builder.h` @ `631911de…6a6f884` → `a65a2853…16656` @ `297a46c0…61f743` | `CircuitBuilder::TaggedObjectIsTypedArray`（新 commit 行 399 起）及同组 tagged-type predicates | TypedArray 类型身份/分类模型直接相关；需要核对输入 tag、wrapper 和返回值语义。**unknown/blocked** |
| 6 effect | `a0e30483…447f9:ecmascript/compiler/lcr_circuit_builder.cpp` @ `af4d27bc…0ffb56` → `a65a2853…16656` @ `a6df4cba…ad1b24c` | `ReadSp`、`Alloca`、`StoreWithoutBarrier`、`Load`（新 hunk 63–302） | load/store/allocation 的 IR 包装改变，可能影响 creator 结果和类型读取。**unknown/blocked** |
| 7 effect | `a0e30483…447f9:ecmascript/compiler/circuit_builder.cpp` @ `b4bf452c…330cb` → `a65a2853…16656` @ `225f0938…4fcffb6` | `Arguments`、`IsJsCOWArray`、`GetObjectType`、`StoreHClass`、`HasConstructorByHClass`（新 hunk 29–715） | 类型读取、对象 HClass 写入和 wrapper 实现有变化；规则的类型身份假设需重审。**unknown/blocked** |
| 8 effect | `a0e30483…447f9:ecmascript/compiler/new_object_stub_builder.h` @ `f411d72c…e438ac` → `a65a2853…16656` @ `ecdf871b…950cb0` | `NewTypedArray`、`NewTypedArraySameType`、相关 allocation helper declarations（hunk 32–194） | creator/overload surface 有变化，不能将旧 arity/返回值和新建对象语义直接沿用。**unknown/blocked** |
| 9 effect | `a0e30483…447f9:ecmascript/compiler/builtins/builtins_stubs.cpp` @ `715c5d65…970143` → `a65a2853…16656` @ `f9c026f6…759f3b` | `GetCallArg2`、`ArrayConstructor`、`MapConstructor` 和 builtin wrappers（新 hunk 160–646） | caller argument 与包装调用路径发生变化；是否可达模型 caller/sink 未完成闭环。**unknown/blocked** |
| 10 effect | `a0e30483…447f9:ecmascript/compiler/builtins/builtins_array_stub_builder.h` @ `88e13156…3c34c6a` → `a65a2853…16656` @ `c9b5a66c…fb8232` | array builtin declarations / wrapper signatures（hunk 27–226） | caller surface/signature 有变化；未证明对 TypedArray caller 无影响。**unknown/blocked** |
| 11 effect | `a0e30483…447f9:ecmascript/compiler/call_stub_builder.h` @ `f1f44f46…7c24f7` → `a65a2853…16656` @ `d1fb1b9e…2ef6aa` | `CallCoStubBuilder`、`CallStubBuilder` wrapper declarations（hunk 112–273） | 调用边界及 wrapper 事实可能变化；不能按方法名相似认定 effect 不变。**unknown/blocked** |
| 12 effect | `a0e30483…447f9:ecmascript/compiler/profiler_operation.h` @ `e68a2db4…f93651` → `a65a2853…16656` @ 同 blob `e68a2db4…f93651` | 完整文件 blob 字节相同 | 此依赖无内容漂移；它单独不能证明其他 18 项的前提成立。**unchanged** |
| 13 effect | `a0e30483…447f9:ecmascript/base/typed_array_helper-inl.h` @ `3adadba4…bc41` → `a65a2853…16656` @ `172fa188…8e1cf` | `TypedArrayHelper::GetSizeFromType`（旧/新函数上下文约 482 行） | 类型→元素宽度映射直接影响 allocation size/layout；语义尚未判为相同。**unknown/blocked** |
| 14 effect | `a0e30483…447f9:ecmascript/base/typed_array_helper.cpp` @ `17f4b8f5…394dc` → `a65a2853…16656` @ `bcb422fe…b0b21` | `AllocateTypedArrayBuffer`、`CreateFromTypedArray`、`ValidateTypedArray`、`SortCompare`（新 hunk 31–1180） | allocator、copy/source-type 和 validation 路径均有改动，影响 creator、类型身份及异常路径假设。**unknown/blocked** |
| 15 effect | `a0e30483…447f9:ecmascript/stubs/runtime_stubs.cpp` @ `c7ce18a7…9b17af8` → `a65a2853…16656` @ `14dc0635…3224d6c` | `TypedArrayCreateSameType`（新 hunk 306 起）及 runtime wrappers | runtime creator/wrapper 变更可能影响返回对象身份和副作用。**unknown/blocked** |
| 16 effect | `a0e30483…447f9:ecmascript/js_typed_array.cpp` @ `892e376d…4b39bb` → `a65a2853…16656` @ `098c2a22…03bbd7` | `DefineOwnProperty`、`OwnPropertyKeys`、`FastGetPropertyByIndex`、`FastSetPropertyByIndex`（新 hunk 71–847） | caller/sink 周边的属性读写与类型转换路径改变，未能证明模型 sink 的运行语义不变。**unknown/blocked** |
| 17 type | `a0e30483…447f9:ecmascript/compiler/new_object_stub_builder.cpp` @ `757b8d05…4245e` → `a65a2853…16656` @ `991ac5ac…15b69` | `NewTypedArray` 新 hunk 2843–2911；`NewTypedArraySameType` 2912–2970；`NewTypedArrayFromCtor` 3092 起 | `HasConstructor`/HClass loads 改用 glue wrappers；`contentType` 从 `INT32` load/store 改为 `INT8`/`LoadPrimitive`；young-space `StoreHClass` 与 SameType HClass fast guard 改变。creator、allocation layout 和类型身份前提均未获证明。**unknown/blocked** |
| 18 exception guard | `c758818d…6c33783:ecmascript/compiler/new_object_stub_builder.cpp` @ `05dda56d…94b52a` → `a65a2853…16656` @ `991ac5ac…15b69` | `NewTypedArray`/`NewTypedArraySameType` allocation 与 result-HClass 读取；同上新 hunk 2843–2970 | 模型的 `NewTypedArray(4)` → `LoadHClass` exception-path 前提受 allocation、wrapper 和 HClass 变化影响。**unknown/blocked** |
| 19 exception guard | `81ca5748…0f43e:ecmascript/compiler/new_object_stub_builder.cpp` @ `05dda56d…94b52a` → `a65a2853…16656` @ `991ac5ac…15b69` | 与第 18 行相同的文件区间；这是另一条精确旧 commit 绑定 | 独立历史 binding 保留；当前依赖事实相同但不能将前一行审查自动复用为另一 commit 的源码证明。**unknown/blocked** |

表格中的短 blob 展示只为可读性；完整值见 C3 比较清单。可复核命令（均为只读 diff；`old` 按行取对应 commit）：

以下精确映射表给出每条记录的完整 commit/path/blob，行号与上表一一对应：

| # | old commit | path | old blob | new commit | new blob |
|---|---|---|---|---|---|
| 1 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/stub_builder.h` | `b784eb0812c27f11c1bfd8673cda4bf884a6a9cd` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `9e2fbd3ede1da91133dcd936018285e597944515` |
| 2 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/stub_builder-inl.h` | `8658e6ee729c3b171639772ad3a1ada06442abd0` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `c0521ab7a55cd63850736c2db8a290115965373c` |
| 3 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/stub_builder.cpp` | `8aae4bfa151e8b8dbd58d03a5cd881f3315151c2` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `c630a6200215705843d11c0dd86c565709e8c6c4` |
| 4 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/hcr_circuit_builder.h` | `176dd0a5ee320f814049c2b671119515c746380d` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `e66c414a7a739284b474c234e6f90bae0368cd11` |
| 5 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/mcr_circuit_builder.h` | `631911dec663addd62533d6a6808ffe699a6f884` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `297a46c06349c0ed7e881ee4475291a41361f743` |
| 6 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/lcr_circuit_builder.cpp` | `af4d27bcd46ea0a4a2980a805dd7de77970ffb56` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `a6df4cba87c9a49f09a292648e7ea7d7cad1b24c` |
| 7 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/circuit_builder.cpp` | `b4bf452cac6bdeb820b78334be98cb3dc11330cb` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `225f09385632bfc2a6ff20bbdf2bfd8694fcffb6` |
| 8 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/new_object_stub_builder.h` | `f411d72cbca7915e56b9d851beeb57b788e438ac` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `ecdf871b20e884e013ce0f26877ef404e4950cb0` |
| 9 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/builtins/builtins_stubs.cpp` | `715c5d65164369bc93a82aa4a6cc1d19b7970143` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `f9c026f6b732cf090aca9df620c4d79bf7597f3b` |
| 10 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/builtins/builtins_array_stub_builder.h` | `88e131561f756db9bd9e57b3078df22ac3c34c6a` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `c9b5a66c12c657533047286ec79406a639fb8232` |
| 11 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/call_stub_builder.h` | `f1f44f44679a9a6d648c8dd0182864d4af7c24f7` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `d1fb1b9ef28ff8c928a6e8dfdd9aed67e42ef6aa` |
| 12 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/profiler_operation.h` | `e68a2db48f222945629adb637cd50be8a0f93651` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `e68a2db48f222945629adb637cd50be8a0f93651` |
| 13 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/base/typed_array_helper-inl.h` | `3adadba4324927a18ff715efa99b2aa9cd15bc41` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `172fa188b64ed23d0714c4f4cd0ef66bcbb8e1cf` |
| 14 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/base/typed_array_helper.cpp` | `17f4b8f50ea126eb646ef011e9b7fa7e461394dc` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `bcb422fe67f4e670adcca31fffd4da7e2b3b0b21` |
| 15 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/stubs/runtime_stubs.cpp` | `c7ce18a76e25289ee7274354fd85950fa9b17af8` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `14dc06350881b1fa0fdabeeb8465ae9063224d6c` |
| 16 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/js_typed_array.cpp` | `892e376de57c08c768831936503a8e4dac4b39bb` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `098c2a22cae3152af3a59063dda25e145f03bbd7` |
| 17 | `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/new_object_stub_builder.cpp` | `757b8d050d306d349822600deacb295c7a54245e` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` |
| 18 | `c758818dbfd0b146a908d43d21f6ca1706c33783` | `ecmascript/compiler/new_object_stub_builder.cpp` | `05dda56de74949f07a241942be6465beaf94b52a` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` |
| 19 | `81ca57487d04ea30cd11c271e86494a4e130f43e` | `ecmascript/compiler/new_object_stub_builder.cpp` | `05dda56de74949f07a241942be6465beaf94b52a` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` |

```bash
git -C /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime rev-parse <old-commit>:<path>
git -C /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime rev-parse a65a2853ccae13da167d9aa4720ab8b11ec16656:<path>
git -C /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime diff --function-context <old-commit> a65a2853ccae13da167d9aa4720ab8b11ec16656 -- <path>
```

## Detector 主目标文件的差异（不计入 19 个 supporting blobs）

`a0e30483…447f9` 的目标 blob 是 `95f54f2875f401afe3167c62f8c1e7799782be8c`；exception-guard 的旧目标 blob 分别是 `857ad416bc102fcd5d462e9702d2ba7c51f29b6d`（`c758…`）和 `3b9de9d915d767d7a67316145451da2446162884`（`81ca…`）。这三条 exact commit:path 均对比新 commit `a65a…`、blob `68fb3b0…`。旧/新函数上下文差异包括 `StoreTypedArrayElement`（旧约 113 行、新 92 行开始）以及新加入的 `StoreTypedArrayElementFromStoreIC`（新约 120 行）；caller `Filter` 中 `NewTypedArray` 和 sink 调用点也随行号移动（旧约 1372/1478/1499，新约 1436/1542/1563）。由于这些变化作用于模型的 sink、creator 和 caller 事实，目标文件本身也不能为 `a65a…` 解锁。

| 旧目标绑定 commit | path | 旧 blob | 新 commit | 新 blob |
|---|---|---|---|---|
| `830e85b40240677039719fcbf14f721ad3b19050` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `054451b1be4f39254d56a1683cc9d1c1b5e55018` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `68fb3b0adc4f9062889a861be51b7be90362e37a` |
| `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `95f54f2875f401afe3167c62f8c1e7799782be8c` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `68fb3b0adc4f9062889a861be51b7be90362e37a` |
| `c758818dbfd0b146a908d43d21f6ca1706c33783` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `857ad416bc102fcd5d462e9702d2ba7c51f29b6d` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `68fb3b0adc4f9062889a861be51b7be90362e37a` |
| `81ca57487d04ea30cd11c271e86494a4e130f43e` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `3b9de9d915d767d7a67316145451da2446162884` | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `68fb3b0adc4f9062889a861be51b7be90362e37a` |

## 控制样例与回归映射

以下是模型机制的合成/历史控制，不是对新 upstream 语义的证明，也不替代独立真值集：

| 语义维度 | 正例 | 修复/安全例 | 无关/unknown 例 |
|---|---|---|---|
| type identity / alias | `test_C03_renamed_variables_still_form_candidate`、`test_same_type_creator_and_exact_buffer_copy_preserve_origin` | `test_C04_target_type_has_same_identity`、`test_C05_local_object_alias_preserves_identity`、`test_C06_token_copy_preserves_origin` | `test_C08_other_owner_is_not_a_modelled_call`、`test_wrong_namespace_owner_is_not_bound` |
| creator / allocation identity | `test_missing_exception_guard_is_candidate`、`test_species_creation_invalidates_current_type_but_not_token_origin` | `test_exception_return_before_use_suppresses_candidate`、`test_same_type_creator_requires_token_from_its_exact_exemplar` | `test_reassigned_creator_helper_loses_its_proven_owner`、`test_global_creator_type_homonym_is_not_a_reviewed_builder` |
| effect / wrapper | `test_unknown_runtime_call_still_invalidates_same_type_relation`、`test_missing_exception_guard_is_candidate` | `test_copywithin_reviewed_reads_preserve_same_object_type`、`test_verified_by_value_call_does_not_refresh_old_token` | `test_unmodeled_effect_fails_closed_as_unknown`、`test_nested_call_in_expression_fails_closed_as_unknown`、`test_sensitive_read_requires_exact_wrapper_expression` |
| caller / sink | `test_other_reviewed_owner_function_uses_actual_symbol`、历史 exact parent Runner 重放 | `test_exact_parent_and_fixed_source_through_registered_adapter` | `test_wrong_sink_arity_stays_unknown`、`test_overload_with_wrong_signature_cannot_replace_modelled_caller` |
| snapshot admission | exact C1 parent/fix tests通过；历史绑定条目未删除 | fixed parent/fix 不产生规则候选 | `test_c3_snapshot_with_unreviewed_dependencies_is_blocked_before_analysis`、`test_bound_current_component_is_explicitly_selected_but_partial_stays_unknown` |

控制覆盖证明的是旧 model 对其合成机制的预期行为和新 gate 的拒绝行为；18 条依赖是否改变某个具体前提仍保持 unknown。因此 C3 当前版本没有正例候选输出，也没有被解释为安全/修复。
